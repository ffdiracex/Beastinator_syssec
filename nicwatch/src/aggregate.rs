//! Rolling aggregation of frames into per-interface and per-flow views.

use crate::domain::{
    AppHint, Counters, Direction, FlowKey, Frame, IfStats, L3Proto, L4Proto, MacAddr,
};
use dashmap::DashMap;
use parking_lot::Mutex;
use std::array;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::ops::Add;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Generic sliding window
// ---------------------------------------------------------------------------

pub struct SlidingWindow<T, const CAP: usize> {
    buf: [Option<(Instant, T)>; CAP],
    head: usize,
    len: usize,
    window: Duration,
}

impl<T: Copy + Default + Add<Output = T>, const CAP: usize> SlidingWindow<T, CAP> {
    pub fn new(window: Duration) -> Self {
        Self { buf: array::from_fn(|_| None), head: 0, len: 0, window }
    }

    pub fn push(&mut self, v: T, at: Instant) {
        if self.len == CAP {
            self.buf[self.head] = None;
            self.head = (self.head + 1) % CAP;
            self.len -= 1;
        }
        let idx = (self.head + self.len) % CAP;
        self.buf[idx] = Some((at, v));
        self.len += 1;
        self.evict(at);
    }

    pub fn sum(&self) -> T {
        let mut acc = T::default();
        for i in 0..self.len {
            let idx = (self.head + i) % CAP;
            if let Some((_, v)) = &self.buf[idx] {
                acc = acc + *v;
            }
        }
        acc
    }

    pub fn len(&self) -> usize { self.len }
    pub fn is_empty(&self) -> bool { self.len == 0 }
    pub fn window(&self) -> Duration { self.window }

    fn evict(&mut self, now: Instant) {
        let Some(cutoff) = now.checked_sub(self.window) else { return };
        while self.len > 0 {
            match &self.buf[self.head] {
                Some((t, _)) if *t < cutoff => {
                    self.buf[self.head] = None;
                    self.head = (self.head + 1) % CAP;
                    self.len -= 1;
                }
                _ => break,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Per-interface rolling view
// ---------------------------------------------------------------------------

pub struct IfaceWindow {
    pub rx: SlidingWindow<Counters, 512>,
    pub tx: SlidingWindow<Counters, 512>,
    pub totals_rx: Counters,
    pub totals_tx: Counters,
    pub l3_rx: [u64; 4],
    pub l3_tx: [u64; 4],
    pub l4_rx: [u64; 8],
    pub l4_tx: [u64; 8],
    pub app_rx: [u64; 12],
    pub app_tx: [u64; 12],
    pub syn: u64,
    pub fin: u64,
    pub rst: u64,
    pub syn_rx: u64,
    pub syn_tx: u64,
    pub rst_rx: u64,
    pub rst_tx: u64,
    pub errors: IfStats,
    pub iface_mac: Option<MacAddr>,
    pub link_type: crate::domain::LinkType,
    pub window: Duration,
}

impl IfaceWindow {
    pub fn new(window: Duration) -> Self {
        Self {
            rx: SlidingWindow::new(window),
            tx: SlidingWindow::new(window),
            totals_rx: Counters::ZERO,
            totals_tx: Counters::ZERO,
            l3_rx: [0; 4],
            l3_tx: [0; 4],
            l4_rx: [0; 8],
            l4_tx: [0; 8],
            app_rx: [0; 12],
            app_tx: [0; 12],
            syn: 0, fin: 0, rst: 0,
            syn_rx: 0, syn_tx: 0, rst_rx: 0, rst_tx: 0,
            errors: IfStats::default(),
            iface_mac: None,
            link_type: crate::domain::LinkType::Ethernet,
            window,
        }
    }

    pub fn ingest(&mut self, frame: &Frame) {
        let n = Counters::from_packet(frame.cap_len as u64);
        let at = frame.captured_at;
        match frame.direction {
            Direction::Rx => {
                self.rx.push(n, at);
                self.totals_rx = self.totals_rx + n;
                self.l3_rx[l3_idx(frame.l3)] += 1;
                self.l4_rx[l4_idx(frame.l4)] += 1;
                self.app_rx[app_idx(frame.app)] += 1;
                if frame.tcp_flags.is_syn() { self.syn_rx += 1; }
                if frame.tcp_flags.is_rst() { self.rst_rx += 1; }
            }
            Direction::Tx => {
                self.tx.push(n, at);
                self.totals_tx = self.totals_tx + n;
                self.l3_tx[l3_idx(frame.l3)] += 1;
                self.l4_tx[l4_idx(frame.l4)] += 1;
                self.app_tx[app_idx(frame.app)] += 1;
                if frame.tcp_flags.is_syn() { self.syn_tx += 1; }
                if frame.tcp_flags.is_rst() { self.rst_tx += 1; }
            }
        }
        if frame.tcp_flags.is_syn() { self.syn += 1; }
        if frame.tcp_flags.is_fin() { self.fin += 1; }
        if frame.tcp_flags.is_rst() { self.rst += 1; }
    }
}

fn l3_idx(p: L3Proto) -> usize {
    match p {
        L3Proto::Ipv4 => 0, L3Proto::Ipv6 => 1, L3Proto::Arp => 2, L3Proto::Other(_) => 3,
    }
}

fn l4_idx(p: L4Proto) -> usize {
    match p {
        L4Proto::Tcp => 0, L4Proto::Udp => 1, L4Proto::Icmp => 2,
        L4Proto::IcmpV6 => 3, L4Proto::Igmp => 4, L4Proto::Other(_) => 5,
        L4Proto::Unknown => 6,
    }
}

fn app_idx(a: AppHint) -> usize {
    match a {
        AppHint::Http => 0, AppHint::Https => 1, AppHint::Ssh => 2,
        AppHint::Dns => 3, AppHint::Smtp => 4, AppHint::Imap => 5,
        AppHint::Pop3 => 6, AppHint::Ntp => 7, AppHint::Mdns => 8,
        AppHint::Dhcp => 9, AppHint::Quic => 10, AppHint::Tls => 11,
        AppHint::Unknown => 0,
    }
}

// ---------------------------------------------------------------------------
// Flow and host tables
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default)]
pub struct FlowEntry {
    pub direction: Option<Direction>,
    pub bytes_rx: u64,
    pub bytes_tx: u64,
    pub packets: u64,
    pub first_seen: Option<Instant>,
    pub last_seen: Option<Instant>,
    pub tcp_flags_seen: u8,
    pub app: AppHint,
}

impl FlowEntry {
    fn observe(&mut self, frame: &Frame) {
        self.packets += 1;
        match frame.direction {
            Direction::Rx => self.bytes_rx += frame.cap_len as u64,
            Direction::Tx => self.bytes_tx += frame.cap_len as u64,
        }
        self.last_seen = Some(frame.captured_at);
        self.first_seen.get_or_insert(frame.captured_at);
        self.direction.get_or_insert(frame.direction);
        self.tcp_flags_seen |= frame.tcp_flags.0;
        if frame.app != AppHint::Unknown { self.app = frame.app; }
    }

    pub fn total_bytes(&self) -> u64 { self.bytes_rx + self.bytes_tx }
}

#[derive(Clone, Debug, Default)]
pub struct HostEntry {
    pub mac: Option<MacAddr>,
    pub bytes_rx: u64,
    pub bytes_tx: u64,
    pub packets: u64,
    pub flows: u64,
    pub first_seen: Option<Instant>,
    pub last_seen: Option<Instant>,
}

impl HostEntry {
    fn observe(&mut self, frame: &Frame, mac: Option<MacAddr>) {
        self.packets += 1;
        match frame.direction {
            Direction::Rx => self.bytes_rx += frame.cap_len as u64,
            Direction::Tx => self.bytes_tx += frame.cap_len as u64,
        }
        self.last_seen = Some(frame.captured_at);
        self.first_seen.get_or_insert(frame.captured_at);
        if self.mac.is_none() { self.mac = mac; }
    }
    pub fn total_bytes(&self) -> u64 { self.bytes_rx + self.bytes_tx }
}

// ---------------------------------------------------------------------------
// The aggregator
// ---------------------------------------------------------------------------

pub struct Aggregator {
    iface: Mutex<IfaceWindow>,
    flows: DashMap<FlowKey, Mutex<FlowEntry>>,
    hosts: DashMap<IpAddr, Mutex<HostEntry>>,
    macs: DashMap<MacAddr, Mutex<HostEntry>>,
    recent: Mutex<VecDeque<Frame>>,
    recent_cap: usize,
}

impl Aggregator {
    pub fn new(window: Duration, recent_cap: usize) -> Self {
        Self {
            iface: Mutex::new(IfaceWindow::new(window)),
            flows: DashMap::new(),
            hosts: DashMap::new(),
            macs: DashMap::new(),
            recent: Mutex::new(VecDeque::with_capacity(recent_cap)),
            recent_cap,
        }
    }

    pub fn ingest(&self, frame: Frame) {
        self.iface.lock().ingest(&frame);

        if let Some(flow) = frame.flow {
            let key = flow.canonical();
            self.flows
                .entry(key)
                .or_insert_with(|| Mutex::new(FlowEntry::default()))
                .lock()
                .observe(&frame);

            if let Some(macs) = frame.macs {
                self.hosts
                    .entry(flow.src)
                    .or_insert_with(|| Mutex::new(HostEntry::default()))
                    .lock()
                    .observe(&frame, Some(macs.src));
                self.hosts
                    .entry(flow.dst)
                    .or_insert_with(|| Mutex::new(HostEntry::default()))
                    .lock()
                    .observe(&frame, Some(macs.dst));
            }
        }

        if let Some(macs) = frame.macs {
            self.macs
                .entry(macs.src)
                .or_insert_with(|| Mutex::new(HostEntry::default()))
                .lock()
                .observe(&frame, Some(macs.src));
            self.macs
                .entry(macs.dst)
                .or_insert_with(|| Mutex::new(HostEntry::default()))
                .lock()
                .observe(&frame, Some(macs.dst));
        }

        let mut q = self.recent.lock();
        if q.len() == self.recent_cap { q.pop_front(); }
        q.push_back(frame);
    }

    pub fn snapshot(&self) -> Snapshot {
        let iface = self.iface.lock();
        let iface_view = IfaceView {
            rx_rate: iface.rx.sum().rate_per_sec(iface.window),
            tx_rate: iface.tx.sum().rate_per_sec(iface.window),
            rx_pps: iface.rx.sum().packets_per_sec(iface.window),
            tx_pps: iface.tx.sum().packets_per_sec(iface.window),
            rx_total: iface.totals_rx,
            tx_total: iface.totals_tx,
            l3_rx: iface.l3_rx,
            l3_tx: iface.l3_tx,
            l4_rx: iface.l4_rx,
            l4_tx: iface.l4_tx,
            app_rx: iface.app_rx,
            app_tx: iface.app_tx,
            syn: iface.syn, fin: iface.fin, rst: iface.rst,
            syn_rx: iface.syn_rx, syn_tx: iface.syn_tx,
            rst_rx: iface.rst_rx, rst_tx: iface.rst_tx,
            errors: iface.errors.clone(),
            iface_mac: iface.iface_mac,
            link_type: iface.link_type,
            window: iface.window,
        };
        drop(iface);

        let mut flows: Vec<(FlowKey, FlowEntry)> = self.flows.iter()
            .map(|e| (*e.key(), e.value().lock().clone()))
            .collect();
        flows.sort_by(|a, b| b.1.total_bytes().cmp(&a.1.total_bytes()));

        let mut hosts: Vec<(IpAddr, HostEntry)> = self.hosts.iter()
            .map(|e| (*e.key(), e.value().lock().clone()))
            .collect();
        hosts.sort_by(|a, b| b.1.total_bytes().cmp(&a.1.total_bytes()));

        let mut macs: Vec<(MacAddr, HostEntry)> = self.macs.iter()
            .map(|e| (*e.key(), e.value().lock().clone()))
            .collect();
        macs.sort_by(|a, b| b.1.total_bytes().cmp(&a.1.total_bytes()));

        let recent: Vec<Frame> = self.recent.lock().iter().cloned().collect();

        Snapshot {
            iface: iface_view,
            flows,
            hosts,
            macs,
            recent,
            generated_at: Instant::now(),
        }
    }
}

// ---------------------------------------------------------------------------
// Snapshot
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct IfaceView {
    pub rx_rate: f64,
    pub tx_rate: f64,
    pub rx_pps: f64,
    pub tx_pps: f64,
    pub rx_total: Counters,
    pub tx_total: Counters,
    pub l3_rx: [u64; 4],
    pub l3_tx: [u64; 4],
    pub l4_rx: [u64; 8],
    pub l4_tx: [u64; 8],
    pub app_rx: [u64; 12],
    pub app_tx: [u64; 12],
    pub syn: u64, pub fin: u64, pub rst: u64,
    pub syn_rx: u64, pub syn_tx: u64,
    pub rst_rx: u64, pub rst_tx: u64,
    pub errors: IfStats,
    pub iface_mac: Option<MacAddr>,
    pub link_type: crate::domain::LinkType,
    pub window: Duration,
}

#[derive(Clone)]
pub struct Snapshot {
    pub iface: IfaceView,
    pub flows: Vec<(FlowKey, FlowEntry)>,
    pub hosts: Vec<(IpAddr, HostEntry)>,
    pub macs: Vec<(MacAddr, HostEntry)>,
    pub recent: Vec<Frame>,
    pub generated_at: Instant,
}

impl Snapshot {
    pub fn top_flows(&self, n: usize) -> &[(FlowKey, FlowEntry)] {
        &self.flows[..n.min(self.flows.len())]
    }
    pub fn top_hosts(&self, n: usize) -> &[(IpAddr, HostEntry)] {
        &self.hosts[..n.min(self.hosts.len())]
    }
    pub fn top_macs(&self, n: usize) -> &[(MacAddr, HostEntry)] {
        &self.macs[..n.min(self.macs.len())]
    }
    pub fn recent_frames(&self, n: usize) -> impl Iterator<Item = &Frame> {
        self.recent.iter().rev().take(n)
    }
    pub fn total_packets(&self) -> u64 {
        self.iface.rx_total.packets + self.iface.tx_total.packets
    }
}
