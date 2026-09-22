//! Linux backend: `AF_PACKET` raw socket via libc directly.

use super::CaptureBackend;
use crate::domain::{Frame, LinkType, MacAddr};
use crate::error::{Error, Result};
use crate::parse;
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::Duration;

/// Linux `ETH_P_ALL` — capture every protocol.
const ETH_P_ALL: u16 = 0x0003;

#[derive(Clone)]
pub struct AfPacketConfig {
    pub interface: String,
    pub promiscuous: bool,
    pub read_timeout: Duration,
    pub buffer_size: usize,
}

impl AfPacketConfig {
    pub fn new(interface: impl Into<String>) -> Self {
        Self {
            interface: interface.into(),
            promiscuous: true,
            read_timeout: Duration::from_millis(250),
            buffer_size: 4 * 1024 * 1024,
        }
    }
    pub fn promiscuous(mut self, yes: bool) -> Self { self.promiscuous = yes; self }
    pub fn read_timeout(mut self, d: Duration) -> Self { self.read_timeout = d; self }
    pub fn buffer_size(mut self, n: usize) -> Self { self.buffer_size = n; self }
}

pub struct AfPacketCapture {
    fd: OwnedFd,
    buffer: Vec<u8>,
    link_type: LinkType,
    config: AfPacketConfig,
    iface_mac: Option<MacAddr>,
}

impl AfPacketCapture {
    pub fn open(config: AfPacketConfig) -> Result<Self> {
        // ---- 1. Create the socket -------------------------------------
        // The protocol is passed in *network byte order*.
        let protocol_be = (ETH_P_ALL).to_be() as libc::c_int;

        let fd_raw = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                protocol_be,
            )
        };
        if fd_raw < 0 {
            let err = std::io::Error::last_os_error();
            return Err(match err.raw_os_error() {
                Some(libc::EPERM) | Some(libc::EACCES) => Error::PermissionDenied,
                _ => Error::Capture(format!("socket(AF_PACKET): {err}")),
            });
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd_raw) };

        // ---- 2. Bind to the interface ---------------------------------
        let ifindex = if_nametoindex(&config.interface)?;
        let addr = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as libc::c_ushort,
            sll_protocol: protocol_be as libc::c_ushort,
            sll_ifindex: ifindex as libc::c_int,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(Error::Capture(format!(
                "bind({}): {}",
                config.interface,
                std::io::Error::last_os_error()
            )));
        }

        // ---- 3. Promiscuous mode (best effort) ------------------------
        if config.promiscuous {
            let mreq = libc::packet_mreq {
                mr_ifindex: ifindex as libc::c_int,
                mr_type: libc::PACKET_MR_PROMISC as libc::c_ushort,
                mr_alen: 0,
                mr_address: [0; 8],
            };
            let _ = unsafe {
                libc::setsockopt(
                    fd.as_raw_fd(),
                    libc::SOL_PACKET,
                    libc::PACKET_ADD_MEMBERSHIP,
                    &mreq as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::packet_mreq>() as libc::socklen_t,
                )
            };
        }

        // ---- 4. Enlarge the kernel receive buffer ---------------------
        let bufsize = config.buffer_size as libc::c_int;
        let _ = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &bufsize as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };

        // ---- 5. Read timeout (SO_RCVTIMEO) ----------------------------
        let tv = libc::timeval {
            tv_sec: config.read_timeout.as_secs() as _,
            tv_usec: config.read_timeout.subsec_micros() as _,
        };
        let _ = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };

        let link_type = LinkType::Ethernet;
        let iface_mac = super::stats::mac_of(&config.interface);

        Ok(Self {
            fd,
            buffer: vec![0u8; 65536],
            link_type,
            config,
            iface_mac,
        })
    }
}

impl CaptureBackend for AfPacketCapture {
    fn name(&self) -> &str { "af_packet" }
    fn link_type(&self) -> LinkType { self.link_type }
    fn interface(&self) -> &str { &self.config.interface }

    fn read_batch(&mut self, sink: &mut dyn FnMut(Frame)) -> Result<usize> {
        let mut total = 0usize;
        loop {
            let n = unsafe {
                libc::recvfrom(
                    self.fd.as_raw_fd(),
                    self.buffer.as_mut_ptr() as *mut libc::c_void,
                    self.buffer.len(),
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };

            if n < 0 {
                let err = std::io::Error::last_os_error();
                match err.raw_os_error() {
                    Some(libc::EAGAIN) | Some(libc::EINTR) => break,
                    Some(libc::ENOBUFS) => continue,
                    _ => return Err(Error::Capture(format!("recvfrom: {err}"))),
                }
            }

            let n = n as usize;
            if n == 0 { break; }

            if let Ok(Some(mut frame)) =
                parse::decode(&self.buffer[..n], self.link_type, n as u32)
            {
                if let Some(macs) = frame.macs {
                    frame.direction = super::stats::classify_direction(
                        macs.src, macs.dst, self.iface_mac,
                    );
                }
                sink(frame);
            }
            total += n;
        }
        Ok(total)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn if_nametoindex(name: &str) -> Result<u32> {
    let cstr = CString::new(name)
        .map_err(|_| Error::Config("interface name contains NUL".into()))?;
    let idx = unsafe { libc::if_nametoindex(cstr.as_ptr()) };
    if idx == 0 {
        Err(Error::NoSuchInterface(name.to_string()))
    } else {
        Ok(idx)
    }
}
