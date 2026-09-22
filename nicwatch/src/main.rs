use anyhow::Context;
use clap::{Parser, ValueEnum};
use nicwatch::capture::source::{FrameSource, LiveSource, Scenario, SyntheticSource};
use nicwatch::capture::{list_interfaces, open_default};
use nicwatch::pipeline::{Pipeline, PipelineConfig};
use nicwatch::ui::app;
use nicwatch::ui::theme::Theme;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "nicwatch", version,
          about = "A top-like live network interface monitor for FreeBSD and Linux")]
struct Cli {
    /// Interface to monitor (e.g. em0 on FreeBSD, eth0 on Linux). Omit to autodetect.
    #[arg(short, long)]
    interface: Option<String>,

    /// Sliding window for rate calculation
    #[arg(short, long, default_value = "5s", value_parser = humantime::parse_duration)]
    window: Duration,

    /// Snapshot refresh interval
    #[arg(long, default_value = "250ms", value_parser = humantime::parse_duration)]
    refresh: Duration,

    /// Number of recent packets kept for the Live tab
    #[arg(long, default_value_t = 4096)]
    recent: usize,

    /// Do not put the NIC into promiscuous mode
    #[arg(long)]
    no_promisc: bool,

    /// Use synthetic traffic (for demos / tests)
    #[arg(long, value_enum)]
    synthetic: Option<SyntheticMode>,

    /// List interfaces and exit
    #[arg(long)]
    list: bool,

    /// Print the resolved capture backend and exit (useful for CI)
    #[arg(long)]
    probe: bool,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum SyntheticMode { Mixed, Http, Scan, Idle }

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_tracing();

    if cli.list {
        let ifaces = list_interfaces().context("ifconfig -l")?;
        for i in ifaces { println!("{i}"); }
        return Ok(());
    }

    let iface = cli.interface.clone().unwrap_or_else(autodetect_interface);

    if cli.probe {
        let backend = open_default(&iface, !cli.no_promisc)?;
        println!(
            "backend={} interface={} link_type={:?}",
            backend.name(), backend.interface(), backend.link_type(),
        );
        return Ok(());
    }

    let cancel = CancellationToken::new();
    let source: Box<dyn FrameSource> = match cli.synthetic {
        Some(SyntheticMode::Mixed) => Box::new(SyntheticSource::new(Scenario::Mixed)),
        Some(SyntheticMode::Http)  => Box::new(SyntheticSource::new(Scenario::HttpFlood)),
        Some(SyntheticMode::Scan)  => Box::new(SyntheticSource::new(Scenario::PortScan)),
        Some(SyntheticMode::Idle)  => Box::new(SyntheticSource::new(Scenario::Idle)),
        None => Box::new(LiveSource::new(&iface, !cli.no_promisc)),
    };

    let pipeline = Pipeline::new(
        source,
        PipelineConfig {
            window: cli.window,
            recent_cap: cli.recent,
            snapshot_interval: cli.refresh,
            ..Default::default()
        },
    );

    let (snap_rx, tasks) = pipeline.start(cancel.clone()).await?;
    let ui_handle = app::run(iface, snap_rx, Theme::default()).await;
    cancel.cancel();
    for t in tasks { let _ = t.await; }
    ui_handle?;
    Ok(())
}

/// Pick a sensible default interface.
///
/// FreeBSD: first non-`lo` interface from `ifconfig -l`.
/// Linux: first non-`lo` interface from `/sys/class/net`, preferring
///        physical names (`eth*`, `en*`, `wlan*`) over virtual ones.
fn autodetect_interface() -> String {
    let list = list_interfaces().unwrap_or_default();

    #[cfg(target_os = "freebsd")]
    {
        list.into_iter()
            .find(|n| !n.starts_with("lo") && !n.starts_with("pflog"))
            .unwrap_or_else(|| "lo0".into())
    }
    #[cfg(target_os = "linux")]
    {
        let prefer = |n: &String| -> u8 {
            if n.starts_with("eth") || n.starts_with("en") { 0 }
            else if n.starts_with("wlan") || n.starts_with("wl") { 1 }
            else if n == "lo" { 3 }
            else { 2 }
        };
        list.into_iter()
            .filter(|n| n != "lo")
            .min_by_key(prefer)
            .unwrap_or_else(|| "lo".into())
    }
    #[cfg(not(any(target_os = "freebsd", target_os = "linux")))]
    {
        let _ = list;
        "lo".into()
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("nicwatch=info,warn"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .without_time()
        .with_writer(std::io::stderr)
        .init();
}
