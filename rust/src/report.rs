//! Banner, summary, results, critical, recommendations, HTML save.

use crate::colors::*;
use crate::syssec::*;
use std::fs::File;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn print_banner() {
    println!("{}", CYAN);
    println!("╔═══════════════════════════════════════════════════════════════╗");
    println!("║    SYSSEC/Beastinator - Security Scanner                      ║");
    println!("║                FreeBSD Security Audit                         ║");
    println!("║                    Version {:<8}                              ║", SYSSEC_VERSION);
    println!("╚═══════════════════════════════════════════════════════════════╝");
    println!("{}", RESET);
}

pub fn print_summary(s: &Syssec) {
    println!();
    println!("{}═══════════════════════════════════════════════════════════════", BOLD);
    println!("                    SCAN SUMMARY");
    println!("═══════════════════════════════════════════════════════════════{}", RESET);
    println!();
    println!("  Hostname:   {}", s.hostname);
    println!("  Kernel:     {}", s.os_release);
    println!("  Timestamp:  {}", ctime(s.timestamp));
    println!();
    println!("  {}✓ Passed:{}   {}", GREEN, RESET, s.passed);
    println!("  {}⚠ Warnings:{} {}", YELLOW, RESET, s.warnings);
    println!("  {}✗ Failed:{}   {}", RED, RESET, s.failures);
    println!("  {}Total:{}      {}", BOLD, RESET, s.results.len());
    println!();

    if s.failures > 0 {
        println!("{}{}", RED, BOLD);
        println!("  ⚠ {} CRITICAL issues found - address immediately!", s.failures);
        println!("{}", RESET);
    } else if s.warnings > 0 {
        println!("{}  ⚠ {} warnings found - review recommendations{}", YELLOW, s.warnings, RESET);
    } else {
        println!("{}  ✓ All checks passed{}", GREEN, RESET);
    }
    println!();
}

pub fn print_results(s: &Syssec) {
    println!("{}═══════════════════════════════════════════════════════════════", BOLD);
    println!("                    DETAILED RESULTS");
    println!("═══════════════════════════════════════════════════════════════{}", RESET);

    let mut last_category = "";
    for r in &s.results {
        if r.category != last_category {
            println!("\n{}[{}]{}", BOLD, r.category, RESET);
            last_category = &r.category;
        }
        let (color, symbol) = match r.status {
            Status::Pass => (GREEN, "✓"),
            Status::Warn => (YELLOW, "⚠"),
            Status::Fail => (RED, "✗"),
            Status::Unknown => (BLUE, "?"),
        };
        println!("  {}{} {:<25}{} {}",
                 color, symbol, r.name, RESET, r.description);
        if !r.recommendation.is_empty() &&
            (r.status == Status::Fail || r.status == Status::Warn) {
            println!("     {}→ {}{}", DIM, r.recommendation, RESET);
        }
    }
    println!();
}

pub fn print_critical(s: &Syssec) {
    println!("\n{}═══ CRITICAL ISSUES ═══{}\n", BOLD, RESET);
    let mut found = 0;
    for r in &s.results {
        if r.status == Status::Fail && r.severity == Severity::Critical {
            println!("{}  [CRITICAL] {}{}", RED, r.name, RESET);
            println!("    {}", r.description);
            if !r.recommendation.is_empty() {
                println!("    {}→ {}{}", YELLOW, r.recommendation, RESET);
            }
            println!();
            found += 1;
        }
    }
    if found == 0 {
        println!("{}  No critical issues found{}", GREEN, RESET);
    }
}

pub fn print_recommendations(s: &Syssec) {
    println!("\n{}═══ RECOMMENDATIONS ═══{}\n", BOLD, RESET);
    let mut found = 0;
    for r in &s.results {
        if r.status != Status::Pass && !r.recommendation.is_empty() {
            let color = if r.status == Status::Fail { RED } else { YELLOW };
            println!("  {}[{}]{} {}", color,
                     if r.status == Status::Fail { "FAIL" } else { "WARN" },
                     RESET, r.name);
            println!("    → {}", r.recommendation);
            found += 1;
        }
    }
    if found == 0 {
        println!("{}  No recommendations - system looks good{}", GREEN, RESET);
    }
    println!();
}

fn ctime(secs: i64) -> String {
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let t: libc::time_t = secs as libc::time_t;
    unsafe { libc::localtime_r(&t, &mut tm); }
    let days = ["Sun","Mon","Tue","Wed","Thu","Fri","Sat"];
    let months = ["Jan","Feb","Mar","Apr","May","Jun",
        "Jul","Aug","Sep","Oct","Nov","Dec"];
    let dw = days.get(tm.tm_wday as usize).copied().unwrap_or("?");
    let mo = months.get(tm.tm_mon as usize).copied().unwrap_or("?");
    format!("{} {} {:>2} {:02}:{:02}:{:02} {}",
            dw, mo, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, tm.tm_year + 1900)
}

pub fn save_report(s: &Syssec, path: &str) -> std::io::Result<()> {
    let mut f = File::create(path)?;

    writeln!(f, "<!DOCTYPE html>\n<html>\n<head>\n<meta charset=\"UTF-8\">")?;
    writeln!(f, "<title>SYSSEC Report - {}</title>", s.hostname)?;
    writeln!(f, "<style>")?;
    writeln!(f, "body {{ font-family: monospace; margin: 40px; background: #f5f5f5; }}")?;
    writeln!(f, ".container {{ max-width: 1000px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}")?;
    writeln!(f, "h1 {{ color: #333; border-bottom: 3px solid #4CAF50; padding-bottom: 10px; }}")?;
    writeln!(f, "h2 {{ color: #555; border-bottom: 1px solid #ddd; padding-bottom: 5px; margin-top: 30px; }}")?;
    writeln!(f, ".summary {{ display: flex; gap: 20px; margin: 20px 0; }}")?;
    writeln!(f, ".summary-item {{ padding: 15px 25px; border-radius: 6px; }}")?;
    writeln!(f, ".pass {{ background: #d4edda; color: #155724; }}")?;
    writeln!(f, ".warn {{ background: #fff3cd; color: #856404; }}")?;
    writeln!(f, ".fail {{ background: #f8d7da; color: #721c24; }}")?;
    writeln!(f, ".check {{ margin: 10px 0; padding: 12px; border-left: 4px solid #ddd; background: #fafafa; border-radius: 4px; }}")?;
    writeln!(f, ".check.pass {{ border-left-color: #4CAF50; }}")?;
    writeln!(f, ".check.warn {{ border-left-color: #FF9800; }}")?;
    writeln!(f, ".check.fail {{ border-left-color: #f44336; }}")?;
    writeln!(f, ".rec {{ background: #fff8e1; padding: 8px 12px; margin-top: 8px; border-radius: 4px; font-size: 0.9em; }}")?;
    writeln!(f, "</style>\n</head>\n<body>\n<div class=\"container\">")?;

    writeln!(f, "<h1>SYSSEC Security Report</h1>")?;
    writeln!(f, "<p><strong>Hostname:</strong> {}</p>", s.hostname)?;
    writeln!(f, "<p><strong>Kernel:</strong> {}</p>", s.os_release)?;
    writeln!(f, "<p><strong>Timestamp:</strong> {}</p>", ctime(s.timestamp))?;

    writeln!(f, "<div class=\"summary\">")?;
    writeln!(f, "<div class=\"summary-item pass\"><strong>✓ Passed:</strong> {}</div>", s.passed)?;
    writeln!(f, "<div class=\"summary-item warn\"><strong>⚠ Warnings:</strong> {}</div>", s.warnings)?;
    writeln!(f, "<div class=\"summary-item fail\"><strong>✗ Failed:</strong> {}</div>", s.failures)?;
    writeln!(f, "<div class=\"summary-item\"><strong>Total:</strong> {}</div>", s.results.len())?;
    writeln!(f, "</div>")?;

    let mut last_category = String::new();
    for r in &s.results {
        if r.category != last_category {
            if !last_category.is_empty() { writeln!(f, "</div>")?; }
            writeln!(f, "<h2>{}</h2>\n<div>", r.category)?;
            last_category = r.category.clone();
        }
        let (cls, symbol) = match r.status {
            Status::Pass => ("pass", "✓"),
            Status::Warn => ("warn", "⚠"),
            Status::Fail => ("fail", "✗"),
            _ => ("pass", "?"),
        };
        writeln!(f, "<div class=\"check {}\">", cls)?;
        writeln!(f, "<strong>{} {}</strong><br>", symbol, r.name)?;
        writeln!(f, "{}", r.description)?;
        if !r.recommendation.is_empty() && r.status != Status::Pass {
            writeln!(f, "<div class=\"rec\">→ {}</div>", r.recommendation)?;
        }
        writeln!(f, "</div>")?;
    }
    if !last_category.is_empty() { writeln!(f, "</div>")?; }
    writeln!(f, "</div>\n</body>\n</html>")?;
    Ok(())
}