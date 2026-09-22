//! Frame sources, platform-neutral.

use super::open_default;
use crate::domain::{
    AppHint, Direction, FlowKey, Frame, L3Proto, L4Proto, MacAddr, MacPair, TcpFlags,
};
use crate::error::Result;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

pub type FrameTx = mpsc::Sender<Frame>;
pub type FrameRx = mpsc::Receiver<Frame>;

pub trait FrameSource: Send + 'static {
    fn name(&self) -> String;

    /// Consume the source and start delivering frames to `tx`.
    ///
    /// The receiver is `Box<Self>` rather than `self` so that a
    /// `Box<dyn FrameSource>` can be started without moving the
    /// (unsized) `dyn` value out of the box.
    fn start(self: Box<Self>, tx: FrameTx) -> Result<()>;
}

// ---------------------------------------------------------------------------
// LiveSource — uses whichever backend the platform provides
// ---------------------------------------------------------------------------

pub struct LiveSource {
    interface: String,
    promiscuous: bool,
}

impl LiveSource {
    pub fn new(interface: impl Into<String>, promiscuous: bool) -> Self {
        Self { interface: interface.into(), promiscuous }
    }
}

impl FrameSource for LiveSource {
    fn name(&self) -> String {
        format!("capture:{}", self.interface)
    }

    fn start(self: Box<Self>, tx: FrameTx) -> Result<()> {
        let interface = self.interface.clone();
        let promiscuous = self.promiscuous;

        std::thread::Builder::new()
            .name(format!("capture-{}", interface))
            .spawn(move || {
                let mut backend = match open_default(&interface, promiscuous) {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::error!(error = ?e, "capture open failed");
                        return;
                    }
                };
                tracing::info!(
                    backend = backend.name(),
                    interface = backend.interface(),
                    "capture started"
                );

                loop {
                    let mut sent = 0usize;
                    let res = backend.read_batch(&mut |frame| {
                        if tx.try_send(frame).is_ok() {
                            sent += 1;
                        }
                    });
                    if let Err(e) = res {
                        tracing::warn!(error = ?e, "capture read error");
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    if tx.is_closed() { break; }
                    if sent == 0 {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
            })
            .map_err(crate::error::Error::Io)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// SyntheticSource — deterministic traffic for tests / demos
// ---------------------------------------------------------------------------

pub struct SyntheticSource {
    rate: Duration,
    burst: usize,
    scenario: Scenario,
}

#[derive(Copy, Clone, Debug)]
pub enum Scenario { Mixed, HttpFlood, PortScan, Idle }

impl SyntheticSource {
    pub const fn new(scenario: Scenario) -> Self {
        Self { rate: Duration::from_millis(50), burst: 20, scenario }
    }
}

impl FrameSource for SyntheticSource {
    fn name(&self) -> String { "synthetic".into() }

    fn start(self: Box<Self>, tx: FrameTx) -> Result<()> {
        use std::net::{IpAddr, Ipv4Addr};

        // Move the fields we need out of the box.
        let SyntheticSource { rate, burst, scenario } = *self;

        std::thread::Builder::new()
            .name("synthetic".into())
            .spawn(move || {
                let mut seq: u32 = 0;
                loop {
                    if tx.is_closed() { break; }
                    for _ in 0..burst {
                        seq = seq.wrapping_add(1);
                        let frame = match scenario {
                            Scenario::Idle => continue,
                            Scenario::HttpFlood => build_http_frame(seq),
                            Scenario::PortScan => build_scan_frame(seq),
                            Scenario::Mixed => {
                                if seq % 7 == 0 { build_scan_frame(seq) }
                                else { build_http_frame(seq) }
                            }
                        };
                        let _ = tx.try_send(frame);
                    }
                    std::thread::sleep(rate);
                    let _ = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
                }
            })
            .map_err(crate::error::Error::Io)?;
        Ok(())
    }
}

fn build_http_frame(seq: u32) -> Frame {
    use std::net::{IpAddr, Ipv4Addr};
    let src: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
    let dst: IpAddr = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
    let flow = FlowKey {
        proto: L4Proto::Tcp, src, src_port: 40_000 + (seq as u16 % 500),
        dst, dst_port: 443,
    };
    Frame {
        captured_at: std::time::Instant::now(),
        wire_len: 1500, cap_len: 1500,
        direction: if seq % 3 == 0 { Direction::Rx } else { Direction::Tx },
        l3: L3Proto::Ipv4,
        l4: L4Proto::Tcp,
        macs: Some(MacPair {
            src: MacAddr([0xaa, 0xbb, 0xcc, 0x00, 0x11, 0x22]),
            dst: MacAddr([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
        }),
        flow: Some(flow),
        tcp_flags: TcpFlags(TcpFlags::ACK | TcpFlags::PSH),
        app: AppHint::Https,
    }
}

fn build_scan_frame(seq: u32) -> Frame {
    use std::net::{IpAddr, Ipv4Addr};
    let src: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42));
    let dst: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
    let flow = FlowKey {
        proto: L4Proto::Tcp, src, src_port: 50_000,
        dst, dst_port: 1 + (seq as u16 % 2000),
    };
    Frame {
        captured_at: std::time::Instant::now(),
        wire_len: 60, cap_len: 60,
        direction: Direction::Rx,
        l3: L3Proto::Ipv4,
        l4: L4Proto::Tcp,
        macs: None,
        flow: Some(flow),
        tcp_flags: TcpFlags(TcpFlags::SYN),
        app: AppHint::Unknown,
    }
}

pub fn channel(capacity: usize) -> (FrameTx, FrameRx) {
    mpsc::channel(capacity)
}

pub fn spawn<S: FrameSource>(source: S, capacity: usize) -> Result<FrameRx> {
    let (tx, rx) = channel(capacity);
    Box::new(source).start(tx)?;
    Ok(rx)
}

#[allow(dead_code)]
pub type SharedTx = Arc<FrameTx>;
