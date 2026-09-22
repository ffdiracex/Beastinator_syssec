//! Zero-copy frame decoding.

use crate::domain::{
    AppHint, Direction, FlowKey, Frame, L3Proto, L4Proto, LinkType,
    MacAddr, MacPair, TcpFlags,
};
use etherparse::{Ethernet2Header, NetSlice, SlicedPacket, TransportSlice, TcpSlice};
use std::time::Instant;

#[derive(Debug)]
pub enum ParseError {
    TooShort(usize),
    UnsupportedLinkType(LinkType),
    L3(&'static str),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort(n) => write!(f, "frame too short: {n}"),
            Self::UnsupportedLinkType(t) => write!(f, "unsupported link type: {t:?}"),
            Self::L3(s) => write!(f, "L3 parse: {s}"),
        }
    }
}

/// Decode a captured frame.
pub fn decode(
    payload: &[u8],
    link_type: LinkType,
    wire_len: u32,
) -> Result<Option<Frame>, ParseError> {
    if payload.is_empty() { return Ok(None); }

    let (l3, macs, l4, flow, tcp_flags, app, l3_payload_len) = match link_type {
        LinkType::Ethernet => decode_ethernet(payload)?,
        LinkType::Loopback => decode_loopback(payload)?,
        LinkType::Other(t) => return Err(ParseError::UnsupportedLinkType(LinkType::Other(t))),
    };

    Ok(Some(Frame {
        captured_at: Instant::now(),
        wire_len,
        cap_len: l3_payload_len as u32,
        direction: Direction::Rx, // caller overrides via MAC context
        l3,
        l4,
        macs,
        flow,
        tcp_flags,
        app,
    }))
}

type Decoded = (L3Proto, Option<MacPair>, L4Proto, Option<FlowKey>, TcpFlags, AppHint, usize);

fn decode_ethernet(payload: &[u8]) -> Result<Decoded, ParseError> {
    if payload.len() < 14 { return Err(ParseError::TooShort(payload.len())); }

    // etherparse 0.15: from_slice returns (header, remaining_payload).
    let (eth, _rest) = Ethernet2Header::from_slice(payload)
        .map_err(|_| ParseError::TooShort(payload.len()))?;

    let macs = Some(MacPair {
        src: MacAddr(eth.source),
        dst: MacAddr(eth.destination),
    });
    let l3 = L3Proto::from_ethertype(eth.ether_type.0);

    // Skip the Ethernet header and hand the raw IP payload to the L3
    // decoder. We could use `_rest` but it's cleaner to slice here so
    // decode_l3's contract stays "give me the L3 payload."
    let after_eth = &payload[14..];
    let (l4, flow, tcp_flags, app, l3_len) = decode_l3(after_eth, l3)?;
    Ok((l3, macs, l4, flow, tcp_flags, app, l3_len))
}

fn decode_loopback(payload: &[u8]) -> Result<Decoded, ParseError> {
    if payload.len() < 4 { return Err(ParseError::TooShort(payload.len())); }
    let family = u32::from_ne_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let l3 = match family {
        2 => L3Proto::Ipv4,
        30 => L3Proto::Ipv6,
        _ => return Ok((L3Proto::Other(0), None, L4Proto::Unknown,
                        None, TcpFlags::default(), AppHint::Unknown, 0)),
    };
    let after = &payload[4..];
    let (l4, flow, tcp_flags, app, l3_len) = decode_l3(after, l3)?;
    Ok((l3, None, l4, flow, tcp_flags, app, l3_len))
}

fn decode_l3(
    payload: &[u8],
    _hint: L3Proto,
) -> Result<(L4Proto, Option<FlowKey>, TcpFlags, AppHint, usize), ParseError> {
    // In 0.15, use from_ip for the L3 payload (we already stripped
    // Ethernet above).
    let sliced = SlicedPacket::from_ip(payload)
        .map_err(|_| ParseError::L3("not IP"))?;

    let (src_ip, dst_ip) = match &sliced.net {
        Some(NetSlice::Ipv4(v4)) => {
            let h = v4.header();
            (std::net::IpAddr::V4(h.source_addr()), std::net::IpAddr::V4(h.destination_addr()))
        }
        Some(NetSlice::Ipv6(v6)) => {
            let h = v6.header();
            (std::net::IpAddr::V6(h.source_addr()), std::net::IpAddr::V6(h.destination_addr()))
        }
        None => {
            return Ok((L4Proto::Unknown, None, TcpFlags::default(), AppHint::Unknown, 0));
        }
    };

    let (l4, ports, tcp_flags) = match &sliced.transport {
        Some(TransportSlice::Tcp(tcp)) => (
            L4Proto::Tcp,
            Some((tcp.source_port(), tcp.destination_port())),
            extract_tcp_flags(tcp),
        ),
        Some(TransportSlice::Udp(udp)) => (
            L4Proto::Udp,
            Some((udp.source_port(), udp.destination_port())),
            TcpFlags::default(),
        ),
        Some(TransportSlice::Icmpv4(_)) => (L4Proto::Icmp, None, TcpFlags::default()),
        Some(TransportSlice::Icmpv6(_)) => (L4Proto::IcmpV6, None, TcpFlags::default()),
        None => (L4Proto::Unknown, None, TcpFlags::default()),
    };

    let (flow, app) = match ports {
        Some((sp, dp)) => (
            Some(FlowKey { proto: l4, src: src_ip, src_port: sp, dst: dst_ip, dst_port: dp }),
            AppHint::from_ports(sp, dp),
        ),
        None => (None, AppHint::Unknown),
    };

    Ok((l4, flow, tcp_flags, app, payload.len()))
}

/// etherparse 0.15 exposes TCP flags as individual booleans on the
/// `TcpHeaderSlice` (accessible via `TcpSlice::header()`), not as a
/// `TcpFlags` struct with a `.flags()` method. We read them directly.
fn extract_tcp_flags(tcp: &TcpSlice<'_>) -> TcpFlags {
    let mut out = 0u8;
    if tcp.fin() { out |= TcpFlags::FIN; }
    if tcp.syn() { out |= TcpFlags::SYN; }
    if tcp.rst() { out |= TcpFlags::RST; }
    if tcp.psh() { out |= TcpFlags::PSH; }
    if tcp.ack() { out |= TcpFlags::ACK; }
    if tcp.urg() { out |= TcpFlags::URG; }
    TcpFlags(out)
}
