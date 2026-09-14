mod colors;
mod syssec;
mod parser;
mod netinspect;
mod checks;
mod freebsd;
mod report;

use colors::*;
use syssec::*;

fn usage(prog: &str) {
    println!("Usage: {} [OPTIONS]", prog);
    println!();
    println!("Options:");
    println!("  -v, --verbose     Verbose output (per-item checks)");
    println!("  -q, --quiet       Quiet mode");
    println!("  -o, --output FILE Save HTML report to FILE");
    println!("  -c, --critical    Show only critical issues");
    println!("  -n, --network     Network only");
    println!("  -N, --no-network  Skip network checks");
    println!("  -h, --help        Show this help");
    println!();
    println!("Examples:");
    println!("  doas {}                    # Standard scan", prog);
    println!("  doas {} -v                 # Verbose per-item output", prog);
    println!("  doas {} -o report.html     # Save HTML report", prog);
    println!("  doas {} -c                 # Show critical only", prog);
    println!("  doas {} -n                 # network only", prog);
    println!("  doas {} -N                 # skip network", prog);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let prog = args.get(0).cloned().unwrap_or_else(|| "syssec".into());

    let mut verbose = false;
    let mut quiet = false;
    let mut critical_only = false;
    let mut only_network = false;
    let mut skip_network = false;
    let mut output: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-v" | "--verbose" => verbose = true,
            "-q" | "--quiet"   => { quiet = true; set_quiet(true); }
            "-o" | "--output"  => {
                if i + 1 < args.len() { i += 1; output = Some(args[i].clone()); }
            }
            "-c" | "--critical" => critical_only = true,
            "-n" | "--network"  => only_network = true,
            "-N" | "--no-network" => skip_network = true,
            "-h" | "--help" => { usage(&prog); return; }
            other => {
                eprintln!("Unknown option: {}", other);
                usage(&prog);
                std::process::exit(1);
            }
        }
        i += 1;
    }

    if verbose { set_log_level(LogLevel::Debug); }
    else if quiet { set_log_level(LogLevel::Error); }

    if !quiet && !critical_only {
        report::print_banner();
    }

    if unsafe { libc::geteuid() } != 0 {
        syssec_log!(LogLevel::Warning, "Not running as root - some checks will be limited");
    }

    let mut s = Syssec::new(verbose);

    // network-only mode
    if only_network {
        checks::syssec_check_network_deep(&mut s);
        if !quiet { report::print_summary(&s); }
        std::process::exit(if s.failures > 0 { 1 } else { 0 });
    }

    checks::syssec_scan(&mut s, skip_network);

    if critical_only {
        report::print_critical(&s);
    } else if verbose {
        report::print_summary(&s);
        report::print_results(&s);
        report::print_recommendations(&s);
    } else if !quiet {
        report::print_summary(&s);
        report::print_recommendations(&s);
    }

    if let Some(path) = output {
        match report::save_report(&s, &path) {
            Ok(_) => {
                if !quiet {
                    println!("{}Report saved to: {}{}", GREEN, path, RESET);
                }
            }
            Err(e) => {
                syssec_log!(LogLevel::Error, "Cannot write report: {}", e);
            }
        }
    }

    std::process::exit(if s.failures > 0 { 1 } else { 0 });
}