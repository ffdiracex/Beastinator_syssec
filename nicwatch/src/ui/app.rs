//! The ratatui application: layout, event loop, key bindings.

use crate::aggregate::Snapshot;
use crate::domain::{Direction, L4Proto};
use crate::ui::theme::Theme;
use crate::ui::widgets::{
    humanize_bytes, humanize_count, humanize_rate, panel,
};
use crossterm::event::{Event, EventStream, KeyCode, KeyEvent, KeyModifiers};
use futures::StreamExt;
use ratatui::{
    layout::{Constraint, Direction as LayoutDir, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Cell, Paragraph, Row, Table, TableState, Tabs, Wrap},
    Frame,
};
use std::collections::VecDeque;

// ---------------------------------------------------------------------------
// Tabs
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Tab { Overview, Flows, Hosts, Protocols, Live }

impl Tab {
    pub const ALL: [Tab; 5] = [Tab::Overview, Tab::Flows, Tab::Hosts, Tab::Protocols, Tab::Live];

    pub const fn title(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Flows => "Flows",
            Self::Hosts => "Hosts",
            Self::Protocols => "Protocols",
            Self::Live => "Live",
        }
    }
    fn index(self) -> usize { Self::ALL.iter().position(|t| *t == self).unwrap_or(0) }
    fn next(self) -> Self { Self::ALL[(self.index() + 1) % Self::ALL.len()] }
    fn prev(self) -> Self { Self::ALL[(self.index() + Self::ALL.len() - 1) % Self::ALL.len()] }
}

// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------

pub struct App {
    pub theme: Theme,
    pub iface: String,
    pub tab: Tab,
    pub paused: bool,
    pub should_quit: bool,
    pub snapshot: Option<Snapshot>,
    pub rx_history: VecDeque<u64>,
    pub tx_history: VecDeque<u64>,
    pub flow_table: TableState,
    pub host_table: TableState,
    pub mac_table: TableState,
    pub live_offset: usize,
    pub sort_mode: SortMode,
    pub show_help: bool,
    pub status: String,
    pub last_error: Option<String>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SortMode { Bytes, Packets, Name }

impl SortMode {
    fn next(self) -> Self {
        match self { Self::Bytes => Self::Packets, Self::Packets => Self::Name, Self::Name => Self::Bytes }
    }
    fn label(self) -> &'static str {
        match self { Self::Bytes => "bytes", Self::Packets => "packets", Self::Name => "name" }
    }
}

impl App {
    pub fn new(iface: String, theme: Theme) -> Self {
        Self {
            theme,
            iface,
            tab: Tab::Overview,
            paused: false,
            should_quit: false,
            snapshot: None,
            rx_history: VecDeque::with_capacity(120),
            tx_history: VecDeque::with_capacity(120),
            flow_table: TableState::default(),
            host_table: TableState::default(),
            mac_table: TableState::default(),
            live_offset: 0,
            sort_mode: SortMode::Bytes,
            show_help: false,
            status: String::new(),
            last_error: None,
        }
    }

    pub fn update(&mut self, snap: Snapshot) {
        let rx = snap.iface.rx_rate as u64;
        let tx = snap.iface.tx_rate as u64;
        push_hist(&mut self.rx_history, rx);
        push_hist(&mut self.tx_history, tx);
        self.snapshot = Some(snap);
    }

    pub fn on_key(&mut self, key: KeyEvent) {
        if self.show_help {
            self.show_help = false;
            return;
        }
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => self.should_quit = true,
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.should_quit = true;
            }
            KeyCode::Char(' ') => self.paused = !self.paused,
            KeyCode::Char('?') | KeyCode::Char('h') => self.show_help = true,
            KeyCode::Char('s') => {
                self.sort_mode = self.sort_mode.next();
                self.status = format!("sort by {}", self.sort_mode.label());
            }
            KeyCode::Tab | KeyCode::Char('l') => self.tab = self.tab.next(),
            KeyCode::BackTab | KeyCode::Char('H') => self.tab = self.tab.prev(),
            KeyCode::Char('1') => self.tab = Tab::Overview,
            KeyCode::Char('2') => self.tab = Tab::Flows,
            KeyCode::Char('3') => self.tab = Tab::Hosts,
            KeyCode::Char('4') => self.tab = Tab::Protocols,
            KeyCode::Char('5') => self.tab = Tab::Live,
            KeyCode::Down | KeyCode::Char('j') => self.scroll_down(),
            KeyCode::Up | KeyCode::Char('k') => self.scroll_up(),
            KeyCode::PageDown => self.scroll_down_by(10),
            KeyCode::PageUp => self.scroll_up_by(10),
            _ => {}
        }
    }

    fn scroll_down(&mut self) { self.scroll_down_by(1); }
    fn scroll_up(&mut self) { self.scroll_up_by(1); }

    fn scroll_down_by(&mut self, n: usize) {
        match self.tab {
            Tab::Flows => select_next(&mut self.flow_table, n,
                self.snapshot.as_ref().map(|s| s.flows.len()).unwrap_or(0)),
            Tab::Hosts => select_next(&mut self.host_table, n,
                self.snapshot.as_ref().map(|s| s.hosts.len()).unwrap_or(0)),
            Tab::Live => self.live_offset = self.live_offset.saturating_add(n),
            _ => {}
        }
    }

    fn scroll_up_by(&mut self, n: usize) {
        match self.tab {
            Tab::Flows => select_prev(&mut self.flow_table, n),
            Tab::Hosts => select_prev(&mut self.host_table, n),
            Tab::Live => self.live_offset = self.live_offset.saturating_sub(n),
            _ => {}
        }
    }
}

fn push_hist(q: &mut VecDeque<u64>, v: u64) {
    const CAP: usize = 120;
    if q.len() == CAP { q.pop_front(); }
    q.push_back(v);
}

fn select_next(state: &mut TableState, n: usize, len: usize) {
    if len == 0 { return; }
    let i = state.selected().unwrap_or(0).saturating_add(n).min(len - 1);
    state.select(Some(i));
}

fn select_prev(state: &mut TableState, n: usize) {
    let i = state.selected().unwrap_or(0).saturating_sub(n);
    state.select(Some(i));
}

// ---------------------------------------------------------------------------
// Render dispatch
// ---------------------------------------------------------------------------

impl App {
    pub fn render(&mut self, frame: &mut Frame) {
        let area = frame.area();
        let chunks = Layout::default()
            .direction(LayoutDir::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(0),
                Constraint::Length(1),
            ])
            .split(area);

        self.render_header(frame, chunks[0]);
        self.render_body(frame, chunks[1]);
        self.render_footer(frame, chunks[2]);

        if self.show_help {
            self.render_help(frame, area);
        }
    }

    fn render_header(&self, frame: &mut Frame, area: Rect) {
        let tabs: Vec<Line> = Tab::ALL.iter()
            .map(|t| Line::from(format!(" {} ", t.title())))
            .collect();
        let tabs_widget = Tabs::new(tabs)
            .select(self.tab.index())
            .style(self.theme.label())
            .highlight_style(
                Style::default().fg(self.theme.accent).add_modifier(Modifier::BOLD),
            )
            .divider(Span::styled("·", self.theme.label()));
        let title = format!(" nicwatch · {} ", self.iface);
        let block = panel(&title, &self.theme);
        let inner = block.inner(area);
        frame.render_widget(block, area);
        frame.render_widget(tabs_widget, inner);
    }

    fn render_footer(&self, frame: &mut Frame, area: Rect) {
        let left = if self.paused { "⏸ PAUSED" } else { "▶ live" };
        let sort = format!("sort:{}", self.sort_mode.label());
        let msg = if let Some(e) = &self.last_error { format!("  ⚠ {e}") }
                  else if !self.status.is_empty() { format!("  {}", self.status) }
                  else { String::new() };
        let line = Line::from(vec![
            Span::styled(format!(" {left} "), self.theme.warn()),
            Span::styled(format!(" {sort} "), self.theme.label()),
            Span::styled(msg, self.theme.danger()),
            Span::styled("  · ? help · q quit", self.theme.label()),
        ]);
        frame.render_widget(Paragraph::new(line), area);
    }

    fn render_body(&self, frame: &mut Frame, area: Rect) {
        match self.tab {
            Tab::Overview => self.render_overview(frame, area),
            Tab::Flows => self.render_flows(frame, area),
            Tab::Hosts => self.render_hosts(frame, area),
            Tab::Protocols => self.render_protocols(frame, area),
            Tab::Live => self.render_live(frame, area),
        }
    }

    // ---- Overview ---------------------------------------------------------

    fn render_overview(&self, frame: &mut Frame, area: Rect) {
        let Some(snap) = &self.snapshot else {
            frame.render_widget(Paragraph::new("waiting for first frame…"), area);
            return;
        };
        let rows = Layout::default()
            .direction(LayoutDir::Vertical)
            .constraints([
                Constraint::Length(7),
                Constraint::Min(8),
                Constraint::Length(8),
            ])
            .split(area);

        // --- Rate gauges ---
        let rate_area = rows[0];
        let cols = Layout::default()
            .direction(LayoutDir::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(rate_area);

        let rx_block = panel("RX", &self.theme);
        let rx_inner = rx_block.inner(cols[0]);
        frame.render_widget(rx_block, cols[0]);
        let rx_line = Line::from(vec![
            Span::styled("  ", self.theme.value()),
            Span::styled(humanize_rate(snap.iface.rx_rate),
                         self.theme.rx().add_modifier(Modifier::BOLD)),
            Span::styled(format!("   {} pps",
                                 humanize_count(snap.iface.rx_pps as u64)),
                         self.theme.label()),
        ]);
        frame.render_widget(Paragraph::new(rx_line), rx_inner);

        let tx_block = panel("TX", &self.theme);
        let tx_inner = tx_block.inner(cols[1]);
        frame.render_widget(tx_block, cols[1]);
        let tx_line = Line::from(vec![
            Span::styled("  ", self.theme.value()),
            Span::styled(humanize_rate(snap.iface.tx_rate),
                         self.theme.tx().add_modifier(Modifier::BOLD)),
            Span::styled(format!("   {} pps",
                                 humanize_count(snap.iface.tx_pps as u64)),
                         self.theme.label()),
        ]);
        frame.render_widget(Paragraph::new(tx_line), tx_inner);

        // --- History sparklines ---
        let hist_area = rows[1];
        let hist_block = panel("history", &self.theme);
        let hist_inner = hist_block.inner(hist_area);
        frame.render_widget(hist_block, hist_area);

        let split = Layout::default()
            .direction(LayoutDir::Vertical)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(hist_inner);

        let rx_data: Vec<u64> = self.rx_history.iter().copied().collect();
        let tx_data: Vec<u64> = self.tx_history.iter().copied().collect();
        let max = rx_data.iter().chain(tx_data.iter()).copied().max().unwrap_or(1).max(1);
        frame.render_widget(
            ratatui::widgets::Sparkline::default()
                .data(&rx_data).max(max)
                .style(Style::default().fg(self.theme.rx)),
            split[0],
        );
        frame.render_widget(
            ratatui::widgets::Sparkline::default()
                .data(&tx_data).max(max)
                .style(Style::default().fg(self.theme.tx)),
            split[1],
        );

        // --- Kernel / lifetime counters ---
        let kern_area = rows[2];
        let kern_block = panel("totals", &self.theme);
        let kern_inner = kern_block.inner(kern_area);
        frame.render_widget(kern_block, kern_area);
        let cols = Layout::default()
            .direction(LayoutDir::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(kern_inner);

        let rx_span = vec![
            Line::from(vec![
                Span::styled("  bytes      ", self.theme.label()),
                Span::styled(humanize_bytes(snap.iface.rx_total.bytes), self.theme.rx()),
            ]),
            Line::from(vec![
                Span::styled("  packets    ", self.theme.label()),
                Span::styled(humanize_count(snap.iface.rx_total.packets), self.theme.rx()),
            ]),
            Line::from(vec![
                Span::styled("  errors     ", self.theme.label()),
                Span::styled(
                    snap.iface.errors.rx_errors.to_string(),
                    if snap.iface.errors.rx_errors > 0 { self.theme.warn() }
                    else { self.theme.value() },
                ),
            ]),
            Line::from(vec![
                Span::styled("  drops      ", self.theme.label()),
                Span::styled(
                    snap.iface.errors.rx_drops.to_string(),
                    if snap.iface.errors.rx_drops > 0 { self.theme.warn() }
                    else { self.theme.value() },
                ),
            ]),
        ];
        frame.render_widget(Paragraph::new(rx_span), cols[0]);

        let tx_span = vec![
            Line::from(vec![
                Span::styled("  bytes      ", self.theme.label()),
                Span::styled(humanize_bytes(snap.iface.tx_total.bytes), self.theme.tx()),
            ]),
            Line::from(vec![
                Span::styled("  packets    ", self.theme.label()),
                Span::styled(humanize_count(snap.iface.tx_total.packets), self.theme.tx()),
            ]),
            Line::from(vec![
                Span::styled("  errors     ", self.theme.label()),
                Span::styled(
                    snap.iface.errors.tx_errors.to_string(),
                    if snap.iface.errors.tx_errors > 0 { self.theme.warn() }
                    else { self.theme.value() },
                ),
            ]),
            Line::from(vec![
                Span::styled("  collisions ", self.theme.label()),
                Span::styled(
                    snap.iface.errors.collisions.to_string(),
                    if snap.iface.errors.collisions > 0 { self.theme.warn() }
                    else { self.theme.value() },
                ),
            ]),
        ];
        frame.render_widget(Paragraph::new(tx_span), cols[1]);
    }

    // ---- Flows ------------------------------------------------------------

    fn render_flows(&self, frame: &mut Frame, area: Rect) {
        let Some(snap) = &self.snapshot else {
            frame.render_widget(Paragraph::new("waiting for first frame…"), area);
            return;
        };
        let header = Row::new(vec![
            Cell::from("Proto"), Cell::from("Source"), Cell::from("Destination"),
            Cell::from("RX"), Cell::from("TX"), Cell::from("Pkts"), Cell::from("Flags"),
            Cell::from("App"), Cell::from("Age"),
        ])
        .style(self.theme.title())
        .height(1);

        let now = std::time::Instant::now();
        let rows: Vec<Row> = snap.top_flows(500).iter().map(|(key, entry)| {
            let src = format!("{}:{}", key.src, key.src_port);
            let dst = format!("{}:{}", key.dst, key.dst_port);
            let age = entry.first_seen
                .map(|t| now.saturating_duration_since(t))
                .map(fmt_dur)
                .unwrap_or_default();
            Row::new(vec![
                Cell::from(key.proto.to_string())
                    .style(Style::default().fg(proto_color(key.proto))),
                Cell::from(src),
                Cell::from(dst),
                Cell::from(humanize_bytes(entry.bytes_rx)).style(self.theme.rx()),
                Cell::from(humanize_bytes(entry.bytes_tx)).style(self.theme.tx()),
                Cell::from(humanize_count(entry.packets)),
                Cell::from(fmt_flags(entry.tcp_flags_seen)),
                Cell::from(entry.app.name()),
                Cell::from(age).style(self.theme.label()),
            ])
        }).collect();
	let title = format!("Flows (top {})", rows.len());
        let block = panel(&title, &self.theme);
        let widths = [
            Constraint::Length(6), Constraint::Min(20), Constraint::Min(20),
            Constraint::Length(10), Constraint::Length(10), Constraint::Length(8),
            Constraint::Length(7), Constraint::Length(7), Constraint::Length(10),
        ];
        let table = Table::new(rows, widths)
            .header(header)
            .block(block)
            .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
            .highlight_symbol("▶ ");

        let mut state = self.flow_table.clone();
        frame.render_stateful_widget(table, area, &mut state);
    }

    // ---- Hosts ------------------------------------------------------------

    fn render_hosts(&self, frame: &mut Frame, area: Rect) {
        let Some(snap) = &self.snapshot else {
            frame.render_widget(Paragraph::new("waiting…"), area);
            return;
        };
        let header = Row::new(vec![
            Cell::from("Address"), Cell::from("MAC"), Cell::from("RX"), Cell::from("TX"),
            Cell::from("Pkts"), Cell::from("Age"),
        ])
        .style(self.theme.title());

        let now = std::time::Instant::now();
        let rows: Vec<Row> = snap.top_hosts(500).iter().map(|(ip, h)| {
            let mac = h.mac.map(|m| m.to_string()).unwrap_or_else(|| "—".into());
            let age = h.first_seen.map(|t| now.saturating_duration_since(t))
                .map(fmt_dur).unwrap_or_default();
            Row::new(vec![
                Cell::from(ip.to_string()),
                Cell::from(mac).style(self.theme.label()),
                Cell::from(humanize_bytes(h.bytes_rx)).style(self.theme.rx()),
                Cell::from(humanize_bytes(h.bytes_tx)).style(self.theme.tx()),
                Cell::from(humanize_count(h.packets)),
                Cell::from(age).style(self.theme.label()),
            ])
        }).collect();
	let title = format!("Hosts ({})", rows.len());
        let block = panel(&title, &self.theme);
        let widths = [
            Constraint::Min(18), Constraint::Length(18),
            Constraint::Length(12), Constraint::Length(12),
            Constraint::Length(10), Constraint::Length(10),
        ];
        let table = Table::new(rows, widths).header(header).block(block)
            .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
            .highlight_symbol("▶ ");
        let mut state = self.host_table.clone();
        frame.render_stateful_widget(table, area, &mut state);
    }

    // ---- Protocols --------------------------------------------------------

    fn render_protocols(&self, frame: &mut Frame, area: Rect) {
        let Some(snap) = &self.snapshot else {
            frame.render_widget(Paragraph::new("waiting…"), area);
            return;
        };
        let rows = Layout::default()
            .direction(LayoutDir::Vertical)
            .constraints([
                Constraint::Length(9),
                Constraint::Length(9),
                Constraint::Min(6),
            ])
            .split(area);

        // L3
        let l3_block = panel("L3", &self.theme);
        let l3_inner = l3_block.inner(rows[0]);
        frame.render_widget(l3_block, rows[0]);
        let l3_names = ["IPv4", "IPv6", "ARP", "Other"];
        let total_rx: u64 = snap.iface.l3_rx.iter().sum::<u64>().max(1);
        let total_tx: u64 = snap.iface.l3_tx.iter().sum::<u64>().max(1);
        let mut l3_lines = vec![];
        for (i, name) in l3_names.iter().enumerate() {
            let rx = snap.iface.l3_rx[i];
            let tx = snap.iface.l3_tx[i];
            if rx == 0 && tx == 0 { continue; }
            l3_lines.push(Line::from(vec![
                Span::styled(format!("  {name:<8}"), self.theme.value()),
                Span::styled(format!("rx {:<8}  ", humanize_count(rx)), self.theme.rx()),
                Span::styled(format!("{:>5.1}%", 100.0 * rx as f64 / total_rx as f64),
                             self.theme.label()),
                Span::styled("   ", self.theme.label()),
                Span::styled(format!("tx {:<8}  ", humanize_count(tx)), self.theme.tx()),
                Span::styled(format!("{:>5.1}%", 100.0 * tx as f64 / total_tx as f64),
                             self.theme.label()),
            ]));
        }
        if l3_lines.is_empty() { l3_lines.push(Line::from("  (no traffic)")); }
        frame.render_widget(Paragraph::new(l3_lines), l3_inner);

        // L4
        let l4_block = panel("L4", &self.theme);
        let l4_inner = l4_block.inner(rows[1]);
        frame.render_widget(l4_block, rows[1]);
        let l4_protos = [
            L4Proto::Tcp, L4Proto::Udp, L4Proto::Icmp, L4Proto::IcmpV6,
            L4Proto::Igmp, L4Proto::Other(0), L4Proto::Unknown,
        ];
        let total_rx_l4: u64 = snap.iface.l4_rx.iter().sum::<u64>().max(1);
        let total_tx_l4: u64 = snap.iface.l4_tx.iter().sum::<u64>().max(1);
        let mut l4_lines = vec![];
        for (i, p) in l4_protos.iter().enumerate() {
            let rx = snap.iface.l4_rx[i];
            let tx = snap.iface.l4_tx[i];
            if rx == 0 && tx == 0 { continue; }
            l4_lines.push(Line::from(vec![
                Span::styled(format!("  {:<8}", p.to_string()),
                             Style::default().fg(proto_color(*p))),
                Span::styled(format!("rx {:<8}  ", humanize_count(rx)), self.theme.rx()),
                Span::styled(format!("{:>5.1}%", 100.0 * rx as f64 / total_rx_l4 as f64),
                             self.theme.label()),
                Span::styled("   ", self.theme.label()),
                Span::styled(format!("tx {:<8}  ", humanize_count(tx)), self.theme.tx()),
                Span::styled(format!("{:>5.1}%", 100.0 * tx as f64 / total_tx_l4 as f64),
                             self.theme.label()),
            ]));
        }
        if l4_lines.is_empty() { l4_lines.push(Line::from("  (no traffic)")); }
        frame.render_widget(Paragraph::new(l4_lines), l4_inner);

        // Application
        let app_block = panel("Applications", &self.theme);
        let app_inner = app_block.inner(rows[2]);
        frame.render_widget(app_block, rows[2]);
        use crate::domain::AppHint;
        let apps = [
            AppHint::Http, AppHint::Https, AppHint::Ssh, AppHint::Dns,
            AppHint::Smtp, AppHint::Ntp, AppHint::Mdns, AppHint::Dhcp,
        ];
        let mut app_lines = vec![];
        for (i, a) in apps.iter().enumerate() {
            let rx = snap.iface.app_rx[i];
            let tx = snap.iface.app_tx[i];
            if rx == 0 && tx == 0 { continue; }
            app_lines.push(Line::from(format!(
                "  {:<8} rx {:<10} tx {:<10}",
                a.name(), humanize_count(rx), humanize_count(tx),
            )));
        }
        if app_lines.is_empty() { app_lines.push(Line::from("  (no recognisable apps)")); }
        frame.render_widget(Paragraph::new(app_lines), app_inner);
    }

    // ---- Live -------------------------------------------------------------

    fn render_live(&self, frame: &mut Frame, area: Rect) {
        let Some(snap) = &self.snapshot else {
            frame.render_widget(Paragraph::new("waiting…"), area);
            return;
        };
        let block = panel("Live packets (newest first)", &self.theme);
        let inner = block.inner(area);
        frame.render_widget(block, area);

        let mut lines = Vec::new();
        for f in snap.recent_frames(inner.height as usize + self.live_offset) {
            let (arrow, style) = match f.direction {
                Direction::Rx => ("↓", self.theme.rx()),
                Direction::Tx => ("↑", self.theme.tx()),
            };
            let flow = f.flow.map(|fl| format!(
                "{} {}:{} → {}:{}",
                fl.proto, fl.src, fl.src_port, fl.dst, fl.dst_port,
            )).unwrap_or_else(|| format!("{} non-IP", f.l3.name()));
            let time = chrono_like(f.captured_at);
            let line = Line::from(vec![
                Span::styled(format!(" {arrow} "), style.add_modifier(Modifier::BOLD)),
                Span::styled(format!("{:>10} ", time), self.theme.label()),
                Span::styled(format!("{:>7} ", humanize_bytes(f.cap_len as u64)), style),
                Span::styled(format!("{:<6} ", f.l4.name()),
                             Style::default().fg(proto_color(f.l4))),
                Span::styled(format!("{:>5} ", f.tcp_flags.to_string()), self.theme.label()),
                Span::styled(flow, self.theme.value()),
                Span::styled(format!("   {}", f.app.name()), self.theme.dim_style()),
            ]);
            lines.push(line);
            if lines.len() >= inner.height as usize { break; }
        }
        if lines.is_empty() {
            lines.push(Line::from("  (no packets yet)"));
        }
        frame.render_widget(Paragraph::new(lines), inner);
    }

    // ---- Help -------------------------------------------------------------

    fn render_help(&self, frame: &mut Frame, area: Rect) {
        use ratatui::widgets::Clear;
        let popup = centered_rect(60, 60, area);
        frame.render_widget(Clear, popup);
        let block = panel("Help", &self.theme);
        let inner = block.inner(popup);
        frame.render_widget(block, popup);
        let text = vec![
            Line::from(vec![Span::styled("q / Ctrl-C ", self.theme.accent_style()),
                            Span::raw("quit")]),
            Line::from(vec![Span::styled("space     ", self.theme.accent_style()),
                            Span::raw("pause / resume")]),
            Line::from(vec![Span::styled("1..5      ", self.theme.accent_style()),
                            Span::raw("switch tab")]),
            Line::from(vec![Span::styled("Tab / ⇧Tab", self.theme.accent_style()),
                            Span::raw("next / prev tab")]),
            Line::from(vec![Span::styled("j / k     ", self.theme.accent_style()),
                            Span::raw("scroll down / up")]),
            Line::from(vec![Span::styled("s         ", self.theme.accent_style()),
                            Span::raw("cycle sort mode")]),
            Line::from(vec![Span::styled("? / h     ", self.theme.accent_style()),
                            Span::raw("toggle this help")]),
        ];
        frame.render_widget(Paragraph::new(text).wrap(Wrap { trim: false }), inner);
    }
}

fn fmt_dur(d: std::time::Duration) -> String {
    let s = d.as_secs();
    if s < 60 { format!("{s}s") }
    else if s < 3600 { format!("{}m{:02}s", s / 60, s % 60) }
    else { format!("{}h{:02}m", s / 3600, (s % 3600) / 60) }
}

fn chrono_like(t: std::time::Instant) -> String {
    let elapsed = t.elapsed();
    let secs = elapsed.as_secs();
    format!("{:>4}.{:03}", secs, elapsed.subsec_millis())
}

fn fmt_flags(mask: u8) -> String {
    use crate::domain::TcpFlags as F;
    let mut s = String::new();
    if mask & F::SYN != 0 { s.push('S'); }
    if mask & F::ACK != 0 { s.push('A'); }
    if mask & F::FIN != 0 { s.push('F'); }
    if mask & F::RST != 0 { s.push('R'); }
    if mask & F::PSH != 0 { s.push('P'); }
    if mask & F::URG != 0 { s.push('U'); }
    if s.is_empty() { "—".into() } else { s }
}

fn proto_color(p: L4Proto) -> Color {
    match p {
        L4Proto::Tcp => Color::Cyan,
        L4Proto::Udp => Color::Blue,
        L4Proto::Icmp | L4Proto::IcmpV6 => Color::Yellow,
        L4Proto::Igmp => Color::Magenta,
        _ => Color::Gray,
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(LayoutDir::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);
    Layout::default()
        .direction(LayoutDir::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

// ---------------------------------------------------------------------------
// Event loop
// ---------------------------------------------------------------------------

pub async fn run(
    iface: String,
    mut snap_rx: tokio::sync::watch::Receiver<Snapshot>,
    theme: Theme,
) -> anyhow::Result<()> {
    use crossterm::terminal::{
        disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
    };
    use crossterm::execute;
    use std::io::stdout;

    enable_raw_mode()?;
    let mut out = stdout();
    execute!(out, EnterAlternateScreen, crossterm::cursor::Hide)?;
    let backend = ratatui::backend::CrosstermBackend::new(out);
    let mut terminal = ratatui::Terminal::new(backend)?;

    let mut app = App::new(iface, theme);
    let mut events = EventStream::new();
    let mut redraw_tick = tokio::time::interval(std::time::Duration::from_millis(250));

    let result = loop {
        tokio::select! {
            _ = redraw_tick.tick() => {
                if !app.paused {
                    let latest = snap_rx.borrow().clone();
                    app.update(latest);
                }
                terminal.draw(|f| app.render(f))?;
                if app.should_quit { break Ok(()); }
            }
            maybe_ev = events.next() => {
                match maybe_ev {
                    Some(Ok(Event::Key(k))) => {
                        app.on_key(k);
                        if app.should_quit { break Ok(()); }
                    }
                    Some(Ok(Event::Resize(_, _))) => {
                        terminal.draw(|f| app.render(f))?;
                    }
                    Some(Err(e)) => break Err(anyhow::Error::from(e)),
                    None => break Ok(()),
                    _ => {}
                }
            }
        }
    };

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        crossterm::cursor::Show
    )?;
    terminal.show_cursor()?;
    result
}
