//! Cross-platform interface statistics and helpers.

use crate::domain::{Counters, IfStats, MacAddr, Direction};
use crate::error::{Error, Result};

// ---------------------------------------------------------------------------
// List interfaces
// ---------------------------------------------------------------------------

#[cfg(target_os = "freebsd")]
pub fn list_interfaces() -> Result<Vec<String>> {
    let out = std::process::Command::new("ifconfig").arg("-l").output()?;
    let text = String::from_utf8_lossy(&out.stdout);
    Ok(text.split_whitespace().map(String::from).collect())
}

#[cfg(target_os = "linux")]
pub fn list_interfaces() -> Result<Vec<String>> {
    // /sys/class/net has one directory per interface, in a stable order.
    let mut out = Vec::new();
    for entry in std::fs::read_dir("/sys/class/net")? {
        let e = entry?;
        if let Some(name) = e.file_name().to_str() {
            out.push(name.to_string());
        }
    }
    out.sort();
    Ok(out)
}

// ---------------------------------------------------------------------------
// Interface stats
// ---------------------------------------------------------------------------

#[cfg(target_os = "freebsd")]
pub fn if_stats(name: &str) -> Result<IfStats> {
    // (unchanged from the previous FreeBSD-only version; kept verbatim)
    use std::ffi::CString;
    #[repr(C)]
    #[derive(Copy, Clone, Default, Debug)]
    struct IfData {
        ifi_type: u8, ifi_physical: u8, ifi_addrlen: u8, ifi_hdrlen: u8,
        ifi_link_state: u8, ifi_vhid: u8, _pad0: [u8; 2],
        ifi_mtu: u32, ifi_metric: u32, ifi_baudrate: u64,
        ifi_ipackets: u64, ifi_ierrors: u64, ifi_opackets: u64, ifi_oerrors: u64,
        ifi_collisions: u64, ifi_ibytes: u64, ifi_obytes: u64,
        ifi_imcasts: u64, ifi_omcasts: u64, ifi_iqdrops: u64, ifi_oqdrops: u64,
        ifi_noproto: u64, ifi_hwassist: u64, ifi_epoch: i64, _extra: [u8; 32],
    }

    let count_oid = CString::new("net.link.generic.system.ifcount").unwrap();
    let mut count: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::size_t;
    let r = unsafe {
        libc::sysctlbyname(
            count_oid.as_ptr(),
            &mut count as *mut _ as *mut libc::c_void,
            &mut len, std::ptr::null_mut(), 0,
        )
    };
    if r != 0 {
        return Err(Error::Sysctl {
            oid: "net.link.generic.system.ifcount".into(),
            errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
        });
    }

    for idx in 1..=count {
        let name_oid = CString::new(format!("net.link.generic.ifdata.{idx}.name")).unwrap();
        let mut name_buf = [0u8; 32];
        let mut name_len = name_buf.len() as libc::size_t;
        let r = unsafe {
            libc::sysctlbyname(
                name_oid.as_ptr(),
                name_buf.as_mut_ptr() as *mut libc::c_void,
                &mut name_len, std::ptr::null_mut(), 0,
            )
        };
        if r != 0 { continue; }
        let this_name = std::str::from_utf8(&name_buf[..name_len.saturating_sub(1)])
            .unwrap_or("").trim_end_matches('\0');
        if this_name != name { continue; }

        let oid = CString::new(format!("net.link.generic.ifdata.{idx}.general")).unwrap();
        let mut buf = vec![0u8; std::mem::size_of::<IfData>().max(256)];
        let mut buf_len = buf.len() as libc::size_t;
        let r = unsafe {
            libc::sysctlbyname(
                oid.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_void,
                &mut buf_len, std::ptr::null_mut(), 0,
            )
        };
        if r != 0 { continue; }
        let data: IfData = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const IfData) };

        let flags = read_bsd_flags(name).unwrap_or(0);

        return Ok(IfStats {
            name: name.to_string(),
            mtu: data.ifi_mtu,
            baudrate: data.ifi_baudrate,
            rx: Counters { bytes: data.ifi_ibytes, packets: data.ifi_ipackets },
            tx: Counters { bytes: data.ifi_obytes, packets: data.ifi_opackets },
            rx_errors: data.ifi_ierrors,
            tx_errors: data.ifi_oerrors,
            rx_drops: data.ifi_iqdrops,
            tx_drops: data.ifi_oqdrops,
            collisions: data.ifi_collisions,
            multicast: data.ifi_imcasts + data.ifi_omcasts,
            flags,
        });
    }
    Err(Error::NoSuchInterface(name.to_string()))
}

#[cfg(target_os = "freebsd")]
fn read_bsd_flags(name: &str) -> Option<u32> {
    // We pull the flags out of the same ifdata record but the struct
    // layout beyond ifi_epoch is version-dependent; a quick shell-out
    // is safer and only happens once per snapshot.
    let out = std::process::Command::new("ifconfig")
        .arg(name).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    // Look for the flags=0x... token.
    let idx = text.find("flags=")?;
    let tail = &text[idx + 6..];
    let hex = tail.split_whitespace().next()?;
    u32::from_str_radix(hex.trim_start_matches("0x"), 16).ok()
}

#[cfg(target_os = "linux")]
pub fn if_stats(name: &str) -> Result<IfStats> {
    use std::fs;

    let base = format!("/sys/class/net/{name}");
    if !std::path::Path::new(&base).exists() {
        return Err(Error::NoSuchInterface(name.to_string()));
    }

    let read_u64 = |file: &str| -> u64 {
        fs::read_to_string(format!("{base}/statistics/{file}"))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0)
    };
    let read_str = |file: &str| -> Option<String> {
        fs::read_to_string(format!("{base}/{file}")).ok().map(|s| s.trim().to_string())
    };

    let mtu = read_str("mtu").and_then(|s| s.parse().ok()).unwrap_or(0);
    // `speed` is in Mbps; 0 or -1 mean "unknown" (virtual/wireless/lo).
    let speed_mbps: i64 = read_str("speed").and_then(|s| s.parse().ok()).unwrap_or(-1);
    let baudrate = if speed_mbps > 0 { (speed_mbps as u64) * 1_000_000 } else { 0 };

    // flags in /sys/class/net/<if>/flags is the Linux IFF_* bitmask.
    let flags = read_str("flags")
        .and_then(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .unwrap_or(0);

    Ok(IfStats {
        name: name.to_string(),
        mtu,
        baudrate,
        rx: Counters {
            bytes: read_u64("rx_bytes"),
            packets: read_u64("rx_packets"),
        },
        tx: Counters {
            bytes: read_u64("tx_bytes"),
            packets: read_u64("tx_packets"),
        },
        rx_errors: read_u64("rx_errors"),
        tx_errors: read_u64("tx_errors"),
        rx_drops: read_u64("rx_dropped"),
        tx_drops: read_u64("tx_dropped"),
        collisions: read_u64("collisions"),
        multicast: read_u64("multicast"),
        flags,
    })
}

// ---------------------------------------------------------------------------
// MAC discovery
// ---------------------------------------------------------------------------

/// Read the interface's own MAC address (used for direction classification).
#[cfg(target_os = "freebsd")]
pub fn mac_of(iface: &str) -> Option<MacAddr> {
    let out = std::process::Command::new("ifconfig").arg(iface).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    // Look for the first `ether XX:XX:...` token.
    let idx = text.find("ether ")?;
    let rest = &text[idx + 6..];
    let mac_str = rest.split_whitespace().next()?;
    parse_mac(mac_str)
}

#[cfg(target_os = "linux")]
pub fn mac_of(iface: &str) -> Option<MacAddr> {
    let addr = std::fs::read_to_string(format!("/sys/class/net/{iface}/address")).ok()?;
    parse_mac(addr.trim())
}

fn parse_mac(s: &str) -> Option<MacAddr> {
    let parts: Vec<u8> = s.split(':')
        .map(|p| u8::from_str_radix(p, 16).ok())
        .collect::<Option<Vec<_>>>()?;
    if parts.len() != 6 { return None; }
    Some(MacAddr([parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]]))
}

// ---------------------------------------------------------------------------
// Direction classification
// ---------------------------------------------------------------------------

/// A BPF/AF_PACKET frame does not tell us whether it was received or
/// transmitted. If we know the interface's MAC, we can infer it: a frame
/// whose source MAC equals ours is our own transmission.
pub fn classify_direction(
    src: MacAddr,
    dst: MacAddr,
    iface_mac: Option<MacAddr>,
) -> Direction {
    if let Some(mac) = iface_mac {
        if src == mac && dst != MacAddr::BROADCAST {
            Direction::Tx
        } else {
            Direction::Rx
        }
    } else {
        Direction::Rx
    }
}

#[derive(Copy, Clone, Debug)]
pub struct MacContext { pub iface_mac: Option<MacAddr> }

impl MacContext {
    pub fn direction(&self, pair: crate::domain::MacPair) -> Direction {
        classify_direction(pair.src, pair.dst, self.iface_mac)
    }
}
