//! Network Inspector

use std::ops::RangeBounds;
use crate::colors::*;
use crate::syssec::*;
use std::process::Command;

pub const NET_MAX_CONNECTIONS: usize = 2048;
pub const NET_MAX_UNIQUE_IPS: usize = 512;
pub const NET_MAX_PORTS: usize = 1024;
pub const NET_MAX_SNAPSHOTS: usize = 16;
pub const NET_MAX_ALERTS: usize = 256;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Proto { Tcp, Udp, Tcp6, Udp6, Unknown }

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum State {
    Listen, Established, TimeWait, CloseWait, SynSent,
    SynRecv, FinWait1, FinWait2, LastAck, Closed, Unknown
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Suspicion {
    None, HighPort, UnknownProc, ExternalConn, UnusualPort, ManyConns,
    BindAll, RootProc, DynamicDns, Blacklisted,
}

#[derive(Clone, Default)]
pub struct Connection {
    pub proto: ProtoOpt,
    pub state: StateOpt,
    pub local_addr: String,
    pub local_port: i32,
    pub local_is_wildcard: bool,
    pub remote_addr: String,
    pub remote_port: i32,
    pub remote_is_public: bool,
    pub pid: i32,
    pub process: String,
    pub first_seen: i64,
    pub last_seen: i64,
    pub seen_count: i32,
    pub suspicion: SuspOpt,
    pub suspicion_reason: String,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ProtoOpt(pub Proto);
impl Default for ProtoOpt { fn default() -> Self { ProtoOpt(Proto::Unknown)}}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct StateOpt(pub State);
impl Default for StateOpt { fn default() -> Self { StateOpt(State::Unknown)}}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SuspOpt(pub Suspicion);
impl Default for SuspOpt { fn default() -> Self { SuspOpt(Suspicion::None)}}

#[derive(Clone, Default)]
pub struct IpEntry {
    pub addr: String,
    pub is_public: bool,
    pub is_local: bool,
    pub connection_count: i32,
    pub listen_count: i32,
    pub ports: Vec<i32>,
    pub first_seen: i64,
    pub last_seen: i64,
    pub suspicion: SuspOpt,
}

#[derive(Clone, Default)]
pub struct PortEntry {
    pub port: i32,
    pub proto: ProtoOpt,
    pub listeners: i32,
    pub established: i32,
    pub process: String,
    pub pid: i32,
    pub is_well_known: bool,
    pub is_suspicious: bool,
}

#[derive(Default)]
pub struct Snapshot {
    pub timestamp: i64,
    pub connections: Vec<Connection>,
    pub ips: Vec<IpEntry>,
    pub ports: Vec<PortEntry>,
}

#[derive(Clone, Default)]
pub struct Alert {
    pub timestamp: i64,
    pub kind: SuspOpt,
    pub message: String,
    pub local: String,
    pub remote: String,
    pub port: i32,
    pub pid: i32,
    pub process: String,
}

pub struct Netinspect {
    pub current: Snapshot,
    pub snapshots: Vec<Snapshot>,
    pub snapshot_index: i32,
    pub alerts: Vec<Alert>,
    pub total_connections: i32,
    pub total_listeners: i32,
    pub total_established: i32,
    pub total_public_ips: i32,
    pub total_local_ips: i32,
    pub suspicious_count: i32,
    pub verbose: bool,
}

impl Netinspect {
    pub fn new(verbose: bool) -> Self {
        Netinspect {
            current: Snapshot::default(),
            snapshots: Vec::new(),
            snapshot_index: 0,
            alerts: Vec::new(),
            total_connections: 0,
            total_listeners: 0,
            total_established: 0,
            total_public_ips: 0,
            total_local_ips: 0,
            suspicious_count: 0,
            verbose,
        }
    }
}

//string mappings
pub fn state_string(s: State) -> &'static str {
    match s {
        State::Listen => "LISTEN",
        State::Established => "ESTABLISHED",
        State::TimeWait => "TIME_WAIT",
        State::SynSent => "SYN_SENT",
        State::SynRecv => "SYN_RECV",
        State::FinWait1 => "FIN_WAIT1",
        State::FinWait2 => "FIN_WAIT2",
        State::LastAck => "LAST_ACK",
        State::Closed => "CLOSED",
        State::Unknown => "UNKNOWN",
        _ => "WARN: _=> CAUGHT ERR 204"
    }
}

pub fn proto_string(p: Proto) -> &'static str {
    match p {
        Proto::Tcp => "tcp4",
        Proto::Udp => "udp4",
        Proto::Tcp6 => "tcp6",
        Proto::Udp6 => "udp6",
        Proto::Unknown => "?",
    }
}

pub fn suspicion_string(s: Suspicion) -> &'static str {
    match s {
        Suspicion::None => "none",
        Suspicion::HighPort => "highport",
        Suspicion::UnknownProc => "unknownproc",
        Suspicion::ExternalConn => "externalconn",
        Suspicion::UnusualPort => "unusualport",
        Suspicion::ManyConns => "manyconns",
        Suspicion::BindAll => "bindall",
        Suspicion::RootProc => "rootproc",
        Suspicion::DynamicDns => "dynamicdns",
        Suspicion::Blacklisted => "blacklisted",
    }
}

// determine whether an IP is public or NOT
fn is_public_ip(addr: &str) -> bool {
    if addr.is_empty() { return false; }
    if addr.contains(':'){
        if addr.starts_with("::1") || addr.starts_with("fe80:") || addr.starts_with("fc00:") || addr.starts_with("fd") {
            return false;
        }
        return true;
    }

    let parts: Vec<&str> = addr.split('.').collect();
    if parts.len() != 4 { return false; }
    let (a,b) = match (parts[0].parse::<u32>(), parts[1].parse::<u32>()) {
        (Ok(a), Ok(b)) => (a, b),
        _ => return false,
    };

    if a == 10 { return false; }
    if a == 172 && (16..=31).contains(&b) { return false; }
    if a == 192 && b == 168 { return false; }
    if a == 127 { return false; }
    if a == 167 && b == 254 { return false; }
    if a == 0 { return false; }
    if (224..=239).contains(&a) { return false; }
    if a >= 240 { return false; }
    true
}

fn is_well_known_port(p: i32) -> bool { p > 0 && p < 1024 }

fn is_suspicious_port(p: i32) -> bool {
    matches!(p, 4444 | 4445 | 5555 | 6666 | 6667 | 6668 | 7777 | 8888 | 9999 | 1337 |
        31337 | 31338 | 12345 | 54321 | 11111 | 22222 | 33333 )
}

fn parse_state(s: &str) -> State {
    match s.to_ascii_uppercase().as_str() {
        "LISTEN" => State::Listen,
        "ESTABLISHED" => State::Established,
        "TIME_WAIT" => State::TimeWait,
        "CLOSE_WAIT" => State::CloseWait,
        "SYN_SENT" => State::SynSent,
        "SYN_RECV" => State::SynRecv,
        "FIN_WAIT1" => State::FinWait1,
        "FIN_WAIT2" => State::FinWait2,
        "LAST_ACK" => State::LastAck,
        "CLOSED" => State::Closed,
        _ => State::Unknown,
    }
}

fn split_endpoint(src: &str) -> (String, i32) {
    if src.is_empty() { return (String::new(), 0); }

    let Some(idx) = src.rfind(':') else {
        return (src.to_string(), 0);
    };

    let mut addr = src[..idx].to_string();
    let port = src[idx + 1..].parse::<i32>().unwrap_or(0);

    if addr.starts_with('[') {
        addr = addr[1..].to_string();
        if let Some(end) = addr.find(']') { addr.truncate(end); }
    }
    (addr, port)
}

fn parse_sockstat_line(line: &str) -> Option<Connection> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 7 { return None; }

    let proto_s = fields[4];
    let local_s = fields[5];
    let remote_s = fields[6];
    let state_s = fields.get(7).copied().unwrap_or("");

    let pid = fields[2].parse::<i32>().unwrap_or(0);
    let command = fields[1].to_string();

    let proto = match proto_s {
        "tcp4" => Proto::Tcp,
        "udp4" => Proto::Udp,
        "tcp6" => Proto::Tcp6,
        "udp6" => Proto::Udp6,
        _ => Proto::Unknown,
    };

    let (local_addr, local_port) = split_endpoint(local_s);
    let (remote_addr, remote_port) = split_endpoint(remote_s);
    let local_is_wildcard =
        local_addr == "*" || local_addr == "0.0.0.0" || local_addr == "::" || local_addr.is_empty();

    let now = now();
    Some(Connection {
        proto: ProtoOpt(proto),
        state: StateOpt(parse_state(state_s)),
        local_addr,
        local_port,
        local_is_wildcard,
        remote_addr: remote_addr.clone(),
        remote_port,
        remote_is_public: is_public_ip(&remote_addr),
        pid,
        process: command,
        first_seen: now,
        last_seen: now,
        seen_count: 1,
        suspicion: SuspOpt(Suspicion::None),
        suspicion_reason: String::new(),
    })
}

pub fn netinspect_scan(ni: &mut Netinspect) -> i32 {
    ni.current = Snapshot::default();
    ni.current.timestamp = now();

    for flag in ["-4", "-6"] {
        let out = Command::new("sockstat").arg(flag).output();
        let Ok(out) = out else { continue };
        if !out.status.success() { continue; }
        let text = String::from_utf8_lossy(&out.stdout);
        let mut lines = text.lines();
        lines.next(); //header
        for line in lines {
            if ni.current.connections.len() >= NET_MAX_CONNECTIONS { break; }
            if let Some(c) = parse_sockstat_line(line) {
                ni.current.connections.push(c);
            }
        }
    }

    for c in &ni.current.connections {
        match c.state.0 {
            State::Listen => ni.total_listeners += 1,
            State::Established => ni.total_established += 1,
            _ => {}
        }
    }
    ni.total_connections = ni.current.connections.len() as i32;
    0
}

//aggregation

fn find_or_add_ip<'a>(snap: &'a mut Snapshot, addr: &str) -> Option<usize> {
    if addr.is_empty() { return None; }
    for (i,ip) in snap.ips.iter().enumerate() {
        if ip.addr == addr { return Some(i); }
    }

    if snap.ips.len() >= NET_MAX_UNIQUE_IPS { return None; }
    let is_public = is_public_ip(addr);
    let now = now();
    snap.ips.push(IpEntry {
        addr: addr.to_string(),
        is_public,
        is_local: !is_public,
        first_seen: now,
        last_seen: now,
        ..Default::default()
    });
    Some(snap.ips.len() -1 )
}

pub fn netinspect_aggregate_ips(ni: &mut Netinspect) {
    // borrow the current snapshot
    ni.current.ips.clear();

    //we need to work with local copies to appease the borrow checker
    let conns: Vec<Connection> = ni.current.connections.clone();
    let mut ips: Vec<IpEntry> = Vec::new();

    for c in &conns {
        if c.local_is_wildcard { continue; }

        //local
        if !c.local_addr.is_empty() {
            let idx = match ips.iter().position(| ip| ip.addr == c.local_addr) {
                Some(i) => Some(i),
                None => {
                    if ips.len() < NET_MAX_UNIQUE_IPS {
                        let is_public = is_public_ip(&c.local_addr);
                        let now = now();
                        ips.push(IpEntry {
                            addr: c.local_addr.clone(),
                            is_public,
                            is_local: !is_public,
                            first_seen: now,
                            last_seen: now,
                            ..Default::default()
                        });
                        Some(ips.len() -1 )
                    } else { None }
                }
            };
            if let Some(i) = idx {
                ips[i].connection_count += 1;
                ips[i].last_seen = now();
                if c.state.0 == State::Listen { ips[i].listen_count += 1; }
                if !ips[i].ports.contains(&c.local_port) &&
                    ips[i].ports.len() < NET_MAX_PORTS {
                    ips[i].ports.push(c.local_port);
                }
            }
        }

        //remote
        if !c.remote_addr.is_empty() && c.remote_addr != "*" && c.remote_addr != "0.0.0.0" {
            let idx = match ips.iter().position(| ip | ip.addr == c.remote_addr) {
                Some(i) => Some(i),
                None => {
                    if ips.len() < NET_MAX_UNIQUE_IPS {
                        let is_public = is_public_ip(&c.remote_addr);
                        let now = now();
                        ips.push(IpEntry {
                            addr: c.remote_addr.clone(),
                            is_public,
                            is_local: !is_public,
                            first_seen: now,
                            last_seen: now,
                            ..Default::default()
                        });
                        Some(ips.len() -1 )
                    } else { None }
                }
            };
            if let Some(i) = idx {
                ips[i].connection_count += 1;
                ips[i].last_seen = now();
            }
        }
    }

    ni.total_public_ips = 0;
    ni.total_local_ips = 0;
    for ip in &ips {
        if ip.is_public { ni.total_public_ips += 1; } else { ni.total_local_ips += 1; }
    }
    ni.current.ips = ips;
}

pub fn netinspect_aggregate_ports(ni: &mut Netinspect) {
    ni.current.ports.clear();
    let conns: Vec<Connection> = ni.current.connections.clone();
    let mut ports: Vec<PortEntry> = Vec::new();

    for c in &conns {
        if c.local_port <= 0 { continue; }
        let idx = match ports.iter().position(| p | p.port == c.local_port && p.proto.0 == c.proto.0)
        {
            Some(i) => Some(i),
            None => {
                if ports.len() < NET_MAX_PORTS {
                    ports.push(PortEntry {
                        port: c.local_port,
                        proto: c.proto,
                        is_well_known: is_well_known_port(c.local_port),
                        is_suspicious: is_suspicious_port(c.local_port),
                        ..Default::default()
                    });
                    Some(ports.len() -1 )
                } else { None }
            }
        };
        if let Some(i) = idx {
            if c.state.0 == State::Listen { ports[i].listeners += 1; }
            if c.state.0 == State::Established { ports[i].established += 1; }
            if ports[i].process.is_empty() && !c.process.is_empty() {
                ports[i].process = c.process.clone();
                ports[i].pid = c.pid;
            }
        }
    }
    ni.current.ports = ports;
}

fn analyze_connection(c: &mut Connection) {
    if c.state.0 == State::Listen && is_suspicious_port(c.local_port) {
        c.suspicion = SuspOpt(Suspicion::UnusualPort);
        c.suspicion_reason = format!("Listener on known malware/backdoor port {}", c.local_port);
        return;
    }
    if c.state.0 == State::Listen && c.local_is_wildcard &&
        !is_well_known_port(c.local_port) && c.local_port > 10000 && c.local_port < 49152 {
        c.suspicion = SuspOpt(Suspicion::HighPort);
        c.suspicion_reason = format!("Listening on high port {} bound to all interfaces", c.local_port);
        return;
    }
    if c.state.0 == State::Established && c.remote_is_public {
        let safe = ["sshd","httpd","nginx","apache","sendmail","postfix",
            "dovecot","ntpd","chrome","firefox"];
        let is_safe = safe.iter().any(|s| s.eq_ignore_ascii_case(&c.process));
        if !is_safe && !c.process.is_empty() {
            c.suspicion = SuspOpt(Suspicion::ExternalConn);
            c.suspicion_reason = format!(
                "Connection to public IP {}:{} from unknown process {}",
                c.remote_addr, c.remote_port, c.process);
        }
    }
}

pub fn netinspect_analyze(ni: &mut Netinspect) {
    ni.suspicious_count = 0;
    ni.alerts.clear();

    // Analyze connections
    let now_ = now();
    let mut alerts = Vec::new();
    for c in ni.current.connections.iter_mut() {
        analyze_connection(c);
        if c.suspicion.0 != Suspicion::None {
            ni.suspicious_count += 1;
            if alerts.len() < NET_MAX_ALERTS {
                alerts.push(Alert {
                    timestamp: now_,
                    kind: c.suspicion,
                    message: c.suspicion_reason.clone(),
                    local: format!("{}:{}", c.local_addr, c.local_port),
                    remote: format!("{}:{}", c.remote_addr, c.remote_port),
                    port: c.local_port,
                    pid: c.pid,
                    process: c.process.clone(),
                });
            }
        }
    }
    ni.alerts = alerts;

    // Analyze IPs
    for ip in ni.current.ips.iter_mut() {
        if ip.connection_count > 50 {
            ip.suspicion = SuspOpt(Suspicion::ManyConns);
        }
    }
}

pub fn netinspect_diff_snapshots(ni: &Netinspect) {
    if ni.snapshots.len() < 2 { return; }
    let prev_idx = ((ni.snapshot_index - 1 + NET_MAX_SNAPSHOTS as i32) as usize)
        % NET_MAX_SNAPSHOTS;
    let prev = &ni.snapshots[prev_idx];
    let curr = &ni.current;

    println!("{}  Snapshot Diff {}", BOLD, RESET);
    println!("  Previous: {} connections", prev.connections.len());
    println!("  Current:  {} connections", curr.connections.len());

    let mut new_conns = 0;
    for c in &curr.connections {
        let found = prev.connections.iter().any(|p| {
            c.local_port == p.local_port &&
                c.remote_port == p.remote_port &&
                c.remote_addr == p.remote_addr
        });
        if !found { new_conns += 1; }
    }

    if new_conns > 0 {
        println!("  {} {} new connections since last snapshot{}",
                 YELLOW, new_conns, RESET);
    } else {
        println!("  {} No new connections{}", GREEN, RESET);
    }
}

pub fn netinspect_print_connections(ni: &Netinspect) {
    let snap = &ni.current;
    println!("\n{}   Live Connections ({})  {}\n",
             BOLD, snap.connections.len(), RESET);
    if snap.connections.is_empty() {
        println!("  No active connections");
        return;
    }
    println!("  {:<10} {:<15} {:<22} {:<22} {:<8} {}",
             "PROTO", "STATE", "LOCAL", "REMOTE", "PID", "PROCESS");
    println!("  {:<10} {:<15} {:<22} {:<22} {:<8} {}",
             "-----", "-----", "-----", "------", "---", "-------");

    for c in &snap.connections {
        let color = if c.suspicion.0 != Suspicion::None { RED } else { RESET };
        println!("  {}{:<10} {:<15} {:<22} {:<22} {:<8} {}{}",
                 color,
                 proto_string(c.proto.0),
                 state_string(c.state.0),
                 format!("{}:{}", c.local_addr, c.local_port),
                 format!("{}:{}", c.remote_addr, c.remote_port),
                 c.pid,
                 c.process,
                 RESET);
        if c.suspicion.0 != Suspicion::None {
            println!("   {} {}{}", RED, c.suspicion_reason, RESET);
        }
    }
}

pub fn netinspect_print_ips(ni: &Netinspect) {
    let snap = &ni.current;
    println!("\n{}   Unique IPs ({})  {}\n", BOLD, snap.ips.len(), RESET);
    println!("  {:<40} {:<10} {:<8} {:<8} {}",
             "ADDRESS", "TYPE", "CONNS", "LISTENS", "PORTS");
    println!("  {:<40} {:<10} {:<8} {:<8} {}",
             "-------", "----", "-----", "-------", "-----");
    for ip in &snap.ips {
        let ty = if ip.is_public { "PUBLIC" } else { "LOCAL" };
        let color = if ip.is_public { YELLOW } else { GREEN };
        let mut ports = String::new();
        for (p, port) in ip.ports.iter().take(5).enumerate() {
            if p > 0 { ports.push(','); }
            ports.push_str(&port.to_string());
        }
        if ip.ports.len() > 5 { ports.push_str("..."); }
        println!("  {}{:<40} {:<10} {:<8} {:<8} {}{}",
                 color, ip.addr, ty, ip.connection_count, ip.listen_count, ports, RESET);
    }
}

pub fn netinspect_print_ports(ni: &Netinspect) {
    let snap = &ni.current;
    println!("\n{}  Port Map ({})  {}\n", BOLD, snap.ports.len(), RESET);
    println!("  {:<8} {:<8} {:<8} {:<10} {:<8} {}",
             "PORT", "PROTO", "LISTEN", "ESTAB", "PID", "PROCESS");
    println!("  {:<8} {:<8} {:<8} {:<10} {:<8} {}",
             "----", "-----", "------", "-----", "---", "-------");
    for p in &snap.ports {
        let color = if p.is_suspicious { RED }
        else if !p.is_well_known && p.listeners > 0 { YELLOW }
        else { RESET };
        println!("  {}{:<8} {:<8} {:<8} {:<10} {:<8} {}{}",
                 color, p.port, proto_string(p.proto.0),
                 p.listeners, p.established, p.pid, p.process, RESET);
    }
}

pub fn netinspect_print_alerts(ni: &Netinspect) {
    println!("\n{}  Network Alerts ({})  {}\n",
             BOLD, ni.alerts.len(), RESET);
    if ni.alerts.is_empty() {
        println!("  {}✓ No suspicious network activity{}", GREEN, RESET);
        return;
    }
    for a in &ni.alerts {
        println!("  {}[{}]{}{}[{}]{}",
                 DIM,
                 format_time(a.timestamp),
                 DIM,
                 RESET,
                 suspicion_string(a.kind.0),
                 RESET);
        println!("     {}", a.message);
        println!("     Local:  {}", a.local);
        println!("     Remote: {}", a.remote);
        println!("     PID:    {} ({})", a.pid, a.process);
        println!();
    }
}

fn format_time(secs: i64) -> String {
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let t: libc::time_t = secs as libc::time_t;
    unsafe { libc::localtime_r(&t, &mut tm); }
    format!("{:02}:{:02}:{:02}", tm.tm_hour, tm.tm_min, tm.tm_sec)
}

pub fn netinspect_print_summary(ni: &Netinspect) {
    println!("\n{}   Network Inspector Summary   {}", BOLD, RESET);
    println!("  Total connections:    {}", ni.total_connections);
    println!("  Total listeners:      {}", ni.total_listeners);
    println!("  Total established:    {}", ni.total_established);
    println!("  Unique local IPs:     {}", ni.total_local_ips);
    println!("  Unique public IPs:    {}", ni.total_public_ips);
    println!("  Unique ports:         {}", ni.current.ports.len());
    if ni.suspicious_count > 0 {
        println!("  {}Suspicious items:    {}{}", RED, ni.suspicious_count, RESET);
    } else {
        println!("  {}✓ No suspicious items{}", GREEN, RESET);
    }
}

pub fn netinspect_print_full(ni: &Netinspect) {
    println!("\n{}   Network Inspector Full   {}", BOLD, RESET);
    netinspect_print_summary(ni);
    netinspect_print_connections(ni);
    netinspect_print_ips(ni);
    netinspect_print_ports(ni);
    netinspect_print_alerts(ni);
    netinspect_diff_snapshots(ni);
}

pub fn netinspect_report(ni: &Netinspect, s: &mut Syssec) {
    let summary = format!("{} connections, {} listeners, {} established",
                          ni.total_connections, ni.total_listeners, ni.total_established);
    s.add_result("Network-Deep", "Connection Summary", &summary,
                 Severity::Info, Status::Pass, None);

    let ips = format!("{} local, {} public", ni.total_local_ips, ni.total_public_ips);
    s.add_result("Network-Deep", "Unique IPs", &ips,
                 Severity::Info, Status::Pass, None);

    if !ni.alerts.is_empty() {
        let buf = format!("{} suspicious items detected", ni.alerts.len());
        s.add_result("Network-Deep", "Suspicious Activity", &buf,
                     Severity::Warning, Status::Warn,
                     Some("Review network alerts for details"));

        for a in ni.alerts.iter().take(10) {
            if matches!(a.kind.0, Suspicion::UnusualPort | Suspicion::Blacklisted) {
                s.add_result("Network-Deep", suspicion_string(a.kind.0),
                             &a.message, Severity::Critical, Status::Fail,
                             Some("Investigate immediately"));
            }
        }
    } else {
        s.add_result("Network-Deep", "Network Analysis",
                     "No suspicious network activity",
                     Severity::Info, Status::Pass, None);
    }
}