//! The runtime: capture thread, aggregation task, snapshot broadcaster.

use crate::aggregate::{Aggregator, IfaceView, Snapshot};
use crate::capture::source::FrameSource;
use crate::domain::LinkType;
use crate::error::Result;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

pub struct PipelineConfig {
    pub window: Duration,
    pub recent_cap: usize,
    pub snapshot_interval: Duration,
    pub channel_capacity: usize,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            window: Duration::from_secs(5),
            recent_cap: 4096,
            snapshot_interval: Duration::from_millis(250),
            channel_capacity: 16_384,
        }
    }
}

pub struct Pipeline {
    pub source: Box<dyn FrameSource>,
    pub config: PipelineConfig,
}

impl Pipeline {
    pub fn new(source: Box<dyn FrameSource>, config: PipelineConfig) -> Self {
        Self { source, config }
    }

    /// Start the pipeline. Returns a receiver for snapshots and the
    /// background tasks driving it.
    pub async fn start(
        self,
        cancel: CancellationToken,
    ) -> Result<(watch::Receiver<Snapshot>, Vec<JoinHandle<()>>)> {
        // Destructure so we own each field independently. `source` is
        // `Box<dyn FrameSource>` which can't be moved out of `self`
        // while `self` is still partially borrowed.
        let Pipeline { source, config } = self;

        let (tx, mut rx) = crate::capture::source::channel(config.channel_capacity);
        source.start(tx)?;

        let aggregator = Arc::new(Aggregator::new(config.window, config.recent_cap));

        let initial = Snapshot {
            iface: IfaceView {
                rx_rate: 0.0,
                tx_rate: 0.0,
                rx_pps: 0.0,
                tx_pps: 0.0,
                rx_total: Default::default(),
                tx_total: Default::default(),
                l3_rx: [0; 4],
                l3_tx: [0; 4],
                l4_rx: [0; 8],
                l4_tx: [0; 8],
                app_rx: [0; 12],
                app_tx: [0; 12],
                syn: 0,
                fin: 0,
                rst: 0,
                syn_rx: 0,
                syn_tx: 0,
                rst_rx: 0,
                rst_tx: 0,
		errors: Default::default(),
                iface_mac: None,
                link_type: LinkType::Ethernet,
                window: config.window,
            },
            flows: Vec::new(),
            hosts: Vec::new(),
            macs: Vec::new(),
            recent: Vec::new(),
            generated_at: Instant::now(),
        };

        let (snap_tx, snap_rx) = watch::channel(initial);

        // --- Ingest task ----------------------------------------------------
        let agg = aggregator.clone();
        let cancel_ingest = cancel.clone();
        let ingest = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel_ingest.cancelled() => break,
                    maybe = rx.recv() => {
                        match maybe {
                            Some(frame) => agg.ingest(frame),
                            None => break,
                        }
                    }
                }
            }
        });

        // --- Snapshot task --------------------------------------------------
        let agg2 = aggregator.clone();
        let interval = config.snapshot_interval;
        let cancel_snap = cancel.clone();
        let snap = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = cancel_snap.cancelled() => break,
                    _ = ticker.tick() => {
                        let s = agg2.snapshot();
                        let _ = snap_tx.send(s);
                    }
                }
            }
        });

        Ok((snap_rx, vec![ingest, snap]))
    }
}
