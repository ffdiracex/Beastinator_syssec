//! FreeBSD backend: `/dev/bpf` via raw ioctl + read(2).

use super::CaptureBackend;
use crate::domain::{Frame, LinkType, MacAddr, MacPair};
use crate::error::{Error, Result};
use crate::parse;
use std::ffi::CString;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};

#[repr(C)]
#[derive(Copy, Clone, Default)]
struct BpfHdr {
	bh_tstamp: libc::timeval,
	bh_caplen: u32,
	bh_datalen: u32,
	bh_hdrlen: u16,
}

const BIOCSETIF:     libc::c_ulong = 0x8020426c;
const BIOCPROMISC:   libc::c_ulong = 0x20004269;
const BIOCIMMEDIATE: libc::c_ulong = 0x80044270;
const BIOCSBLEN:     libc::c_ulong = 0xc0044266;
const BIOCGBLEN:     libc::c_ulong = 0x40044266;
const BIOCGDLT:      libc::c_ulong = 0x4004426a;
const BIOCSRTIMEOUT: libc::c_ulong = 0x8010426d;
const REQUESTED_BUFFER: libc::c_int = 4 * 1024 * 1024;

#[derive(Clone)]
pub struct BpfConfig {
    pub interface: String,
    pub promiscuous: bool,
    pub immediate: bool,
    pub read_timeout: std::time::Duration,
}

impl BpfConfig {
    pub fn new(interface: impl Into<String>) -> Self {
        Self {
            interface: interface.into(),
            promiscuous: true,
            immediate: true,
            read_timeout: std::time::Duration::from_millis(250),
        }
    }
    pub fn promiscuous(mut self, yes: bool) -> Self { self.promiscuous = yes; self }
    pub fn immediate(mut self, yes: bool) -> Self { self.immediate = yes; self }
    pub fn read_timeout(mut self, d: std::time::Duration) -> Self { self.read_timeout = d; self }
}

pub struct BpfCapture {
    fd: OwnedFd,
    buffer: Vec<u8>,
    link_type: LinkType,
    config: BpfConfig,
    iface_mac: Option<MacAddr>,
}

impl BpfCapture {
    pub fn open(config: BpfConfig) -> Result<Self> {
        let fd = open_bpf_device()?;
        let raw = fd.as_raw_fd();

        let mut buf_len: libc::c_int = REQUESTED_BUFFER;
        ioctl_ptr(raw, BIOCSBLEN, &mut buf_len as *mut _ as *mut libc::c_void)
            .map_err(|e| Error::Capture(format!("BIOCSBLEN: {e}")))?;

        let ifname = CString::new(config.interface.clone())
            .map_err(|_| Error::Capture("interface name contains NUL".into()))?;
        let mut ifreq: [libc::c_char; 16] = [0; 16];
        for (i, b) in ifname.as_bytes().iter().take(15).enumerate() {
            ifreq[i] = *b as libc::c_char;
        }
        ioctl_ptr(raw, BIOCSETIF, ifreq.as_mut_ptr() as *mut libc::c_void)
            .map_err(|e| Error::Capture(format!("BIOCSETIF({}): {e}", config.interface)))?;

        if config.immediate {
            let one: libc::c_int = 1;
            ioctl_ptr(raw, BIOCIMMEDIATE, &one as *const _ as *mut libc::c_void)
                .map_err(|e| Error::Capture(format!("BIOCIMMEDIATE: {e}")))?;
        }

        let mut tv = libc::timeval {
            tv_sec: config.read_timeout.as_secs() as _,
            tv_usec: config.read_timeout.subsec_micros() as _,
        };
        let _ = ioctl_ptr(raw, BIOCSRTIMEOUT, &mut tv as *mut _ as *mut libc::c_void);

        if config.promiscuous {
            let _ = ioctl_ptr(raw, BIOCPROMISC, std::ptr::null_mut());
        }

        let mut dlt: libc::c_uint = 0;
        ioctl_ptr(raw, BIOCGDLT, &mut dlt as *mut _ as *mut libc::c_void)
            .map_err(|e| Error::Capture(format!("BIOCGDLT: {e}")))?;
        let link_type = LinkType::from_dlt(dlt);

        let mut blen: libc::c_int = 0;
        ioctl_ptr(raw, BIOCGBLEN, &mut blen as *mut _ as *mut libc::c_void)
            .map_err(|e| Error::Capture(format!("BIOCGBLEN: {e}")))?;
        let buffer = vec![0u8; blen.max(4096) as usize];

        let iface_mac = super::stats::mac_of(&config.interface);

        Ok(Self { fd, buffer, link_type, config, iface_mac })
    }
}

impl CaptureBackend for BpfCapture {
    fn name(&self) -> &str { "bpf" }
    fn link_type(&self) -> LinkType { self.link_type }
    fn interface(&self) -> &str { &self.config.interface }

    fn read_batch(&mut self, sink: &mut dyn FnMut(Frame)) -> Result<usize> {
        let n = unsafe {
            libc::read(
                self.fd.as_raw_fd(),
                self.buffer.as_mut_ptr() as *mut libc::c_void,
                self.buffer.len(),
            )
        };
        if n < 0 {
            let errno = std::io::Error::last_os_error();
            if matches!(errno.raw_os_error(), Some(libc::EAGAIN | libc::EINTR)) {
                return Ok(0);
            }
            return Err(Error::Capture(errno.to_string()));
        }
        let n = n as usize;
        if n == 0 { return Ok(0); }

        let mut offset = 0usize;
        while offset + std::mem::size_of::<BpfHdr>() <= n {
            let hdr: BpfHdr = unsafe {
                std::ptr::read_unaligned(self.buffer.as_ptr().add(offset) as *const BpfHdr)
            };
            let hdr_len = hdr.bh_hdrlen as usize;
            let caplen = hdr.bh_caplen as usize;
            if hdr_len == 0 || caplen == 0 { break; }
            let start = offset + hdr_len;
            let end = start + caplen;
            if end > n { break; }

            if let Ok(Some(mut frame)) =
                parse::decode(&self.buffer[start..end], self.link_type, hdr.bh_datalen)
            {
                if let Some(macs) = frame.macs {
                    frame.direction = super::stats::classify_direction(
                        macs.src, macs.dst, self.iface_mac,
                    );
                }
                sink(frame);
            }

            offset += (hdr_len + caplen + 3) & !3;
        }
        Ok(n)
    }
}

fn open_bpf_device() -> Result<OwnedFd> {
    let candidates = ["/dev/bpf", "/dev/bpf0", "/dev/bpf1", "/dev/bpf2"];
    let mut last_err = None;
    for path in candidates {
        let p = CString::new(path).unwrap();
        let fd = unsafe { libc::open(p.as_ptr(), libc::O_RDWR) };
        if fd >= 0 { return Ok(unsafe { OwnedFd::from_raw_fd(fd) }); }
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::EACCES) {
            return Err(Error::PermissionDenied);
        }
        last_err = Some(e);
    }
    Err(Error::Capture(match last_err {
        Some(e) => format!("cannot open any /dev/bpf*: {e}"),
        None => "no /dev/bpf* nodes exist".into(),
    }))
}

#[inline]
fn ioctl_ptr(fd: RawFd, req: libc::c_ulong, arg: *mut libc::c_void) -> std::io::Result<()> {
    let r = unsafe { libc::ioctl(fd, req as _, arg) };
    if r < 0 { Err(std::io::Error::last_os_error()) } else { Ok(()) }
}

#[allow(dead_code)]
pub type Unused = (MacPair,);
