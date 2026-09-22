//! Domain model — strongly-typed, no naked primitives across module
//! boundaries.

use smallvec::SmallVec;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::Add;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// MAC address
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize)]
#[repr(transparent)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    pub const BROADCAST: Self = Self([0xff; 6]);
    pub const ZERO: Self = Self([0; 6]);

    pub const fn is_broadcast(self) -> bool {
        matches!(self.0, [0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
    }
    pub const fn is_multicast(self) -> bool { self.0[0] & 0x01 != 0 }
    pub const fn is_locally_administered(self) -> bool { self.0[0] & 0x02 != 0 }
    pub const fn oui(self) -> [u8; 3] { [self.0[0], self.0[1], self.0[2]] }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

// ---------------------------------------------------------------------------
// Link type
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum LinkType { Ethernet, Loopback, Other(u32) }

impl LinkType {
    pub const fn from_dlt(dlt: u32) -> Self {
        match dlt {
            1 => Self::Ethernet,
            0 => Self::Loopback,
            other => Self::Other(other),
        }
    }
    pub const fn header_len(self) -> usize {
        match self { Self::Ethernet => 14, Self::Loopback => 4, Self::Other(_) => 0 }
    }
}

// ---------------------------------------------------------------------------
// L4 protocol
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum L4Proto { Tcp, Udp, Icmp, IcmpV6, Igmp, Other(u8), Unknown }

impl L4Proto {
    pub const fn from_ip_proto(n: u8) -> Self {
        match n {
            6 => Self::Tcp, 17 => Self::Udp, 1 => Self::Icmp,
            58 => Self::IcmpV6, 2 => Self::Igmp, other => Self::Other(other),
        }
    }
    pub const fn name(self) -> &'static str {
        match self {
            Self::Tcp => "TCP", Self::Udp => "UDP", Self::Icmp => "ICMP",
            Self::IcmpV6 => "ICMP6", Self::Igmp => "IGMP", Self::Other(_) => "L4",
            Self::Unknown => "?",
        }
    }
    pub const fn all() -> &'static [L4Proto] {
        &[Self::Tcp, Self::Udp, Self::Icmp, Self::IcmpV6, Self::Igmp, Self::Unknown]
    }
}

impl fmt::Display for L4Proto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Other(n) => write!(f, "IP/{n}"),
            other => f.write_str(other.name()),
        }
    }
}

// ---------------------------------------------------------------------------
// L3 protocol
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum L3Proto { Ipv4, Ipv6, Arp, Other(u16) }

impl L3Proto {
    pub const fn from_ethertype(et: u16) -> Self {
        match et {
            0x0800 => Self::Ipv4, 0x86dd => Self::Ipv6, 0x0806 => Self::Arp,
            other => Self::Other(other),
        }
    }
    pub const fn name(self) -> &'static str {
        match self { Self::Ipv4 => "IPv4", Self::Ipv6 => "IPv6", Self::Arp => "ARP",
                     Self::Other(_) => "L3" }
    }
}

// ---------------------------------------------------------------------------
// Direction
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Direction { Rx, Tx }

impl Direction {
    pub const fn arrow(self) -> char { match self { Self::Rx => '↓', Self::Tx => '↑' } }
    pub const fn label(self) -> &'static str { match self { Self::Rx => "RX", Self::Tx => "TX" } }
}

// ---------------------------------------------------------------------------
// Endpoint pair
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FlowKey {
    pub proto: L4Proto,
    pub src: IpAddr,
    pub src_port: u16,
    pub dst: IpAddr,
    pub dst_port: u16,
}

impl FlowKey {
    pub fn canonical(&self) -> Self {
        if (self.src, self.src_port) <= (self.dst, self.dst_port) {
            *self
        } else {
            Self {
                proto: self.proto,
                src: self.dst, src_port: self.dst_port,
                dst: self.src, dst_port: self.src_port,
            }
        }
    }
}

impl fmt::Display for FlowKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}:{} ⇄ {}:{}",
               self.proto, self.src, self.src_port, self.dst, self.dst_port)
    }
}

// ---------------------------------------------------------------------------
// MAC pair (for L2 top talkers)
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MacPair { pub src: MacAddr, pub dst: MacAddr }

// ---------------------------------------------------------------------------
// Byte counters with arithmetic
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct Counters {
    pub bytes: u64,
    pub packets: u64,
}

impl Counters {
    pub const ZERO: Self = Self { bytes: 0, packets: 0 };

    pub const fn from_packet(len: u64) -> Self {
        Self { bytes: len, packets: 1 }
    }

    pub fn rate_per_sec(self, window: Duration) -> f64 {
        let secs = window.as_secs_f64().max(1e-9);
        self.bytes as f64 / secs
    }

    pub fn packets_per_sec(self, window: Duration) -> f64 {
        let secs = window.as_secs_f64().max(1e-9);
        self.packets as f64 / secs
    }
}

impl Add for Counters {
    type Output = Self;
    fn add(self, o: Self) -> Self {
        Self { bytes: self.bytes + o.bytes, packets: self.packets + o.packets }
    }
}

// ---------------------------------------------------------------------------
// Frame — the captured observation
// ---------------------------------------------------------------------------

pub type PeerList = SmallVec<[IpAddr; 8]>;

#[derive(Clone, Debug)]
pub struct Frame {
    pub captured_at: Instant,
    pub wire_len: u32,
    pub cap_len: u32,
    pub direction: Direction,
    pub l3: L3Proto,
    pub l4: L4Proto,
    pub macs: Option<MacPair>,
    pub flow: Option<FlowKey>,
    pub tcp_flags: TcpFlags,
    pub app: AppHint,
}

// ---------------------------------------------------------------------------
// TCP flags
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct TcpFlags(pub u8);

impl TcpFlags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;

    pub const fn has(self, flag: u8) -> bool { self.0 & flag != 0 }
    pub const fn is_syn(self) -> bool { self.has(Self::SYN) && !self.has(Self::ACK) }
    pub const fn is_synack(self) -> bool { self.has(Self::SYN) && self.has(Self::ACK) }
    pub const fn is_fin(self) -> bool { self.has(Self::FIN) }
    pub const fn is_rst(self) -> bool { self.has(Self::RST) }
}

impl fmt::Display for TcpFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = String::with_capacity(6);
        if self.has(Self::SYN) { s.push('S'); }
        if self.has(Self::ACK) { s.push('A'); }
        if self.has(Self::FIN) { s.push('F'); }
        if self.has(Self::RST) { s.push('R'); }
        if self.has(Self::PSH) { s.push('P'); }
        if self.has(Self::URG) { s.push('U'); }
        f.write_str(if s.is_empty() { "-" } else { &s })
    }
}

// ---------------------------------------------------------------------------
// Application hint — a lightweight, port-based classifier
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AppHint {
    Http, Https, Ssh, Dns, Smtp, Imap, Pop3, Ntp, Mdns, Dhcp,
    Quic, Tls,
    #[default]
    Unknown,
}

impl AppHint {
    pub const fn from_ports(src: u16, dst: u16) -> Self {
        let p = if src < dst { src } else { dst };
        match p {
            80 => Self::Http, 443 => Self::Https, 22 => Self::Ssh,
            53 => Self::Dns, 25 | 587 => Self::Smtp,
            143 => Self::Imap, 110 => Self::Pop3, 123 => Self::Ntp,
            5353 => Self::Mdns, 67 | 68 => Self::Dhcp,
            _ => Self::Unknown,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Http => "HTTP", Self::Https => "HTTPS", Self::Ssh => "SSH",
            Self::Dns => "DNS", Self::Smtp => "SMTP", Self::Imap => "IMAP",
            Self::Pop3 => "POP3", Self::Ntp => "NTP", Self::Mdns => "mDNS",
            Self::Dhcp => "DHCP", Self::Quic => "QUIC", Self::Tls => "TLS",
            Self::Unknown => "—",
        }
    }
}

// ---------------------------------------------------------------------------
// Interface stats
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct IfStats {
    pub name: String,
    pub mtu: u32,
    pub baudrate: u64,
    pub rx: Counters,
    pub tx: Counters,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_drops: u64,
    pub tx_drops: u64,
    pub collisions: u64,
    pub multicast: u64,
    pub flags: u32,
}

impl IfStats {
    pub fn is_up(&self) -> bool { self.flags & 0x1 != 0 }
    pub fn is_running(&self) -> bool { self.flags & 0x40 != 0 }
    pub fn is_promisc(&self) -> bool { self.flags & 0x100 != 0 }

    pub fn utilization(&self) -> Option<f64> {
        if self.baudrate == 0 { return None; }
        let bits = (self.rx.bytes + self.tx.bytes) * 8;
        Some(bits as f64 / self.baudrate as f64)
    }
}

// ---------------------------------------------------------------------------
// Convenience re-exports
// ---------------------------------------------------------------------------

pub use std::net::Ipv4Addr as V4;
pub use std::net::Ipv6Addr as V6;

#[allow(dead_code)]
pub const fn wildcard_v4() -> IpAddr { IpAddr::V4(Ipv4Addr::UNSPECIFIED) }
#[allow(dead_code)]
pub const fn wildcard_v6() -> IpAddr { IpAddr::V6(Ipv6Addr::UNSPECIFIED) }
