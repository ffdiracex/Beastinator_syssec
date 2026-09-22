//! Reusable widgets.

use crate::ui::theme::Theme;
use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Paragraph, Sparkline, Widget},
};

// ---------------------------------------------------------------------------
// Human-readable byte formatting
// ---------------------------------------------------------------------------

pub fn humanize_bytes(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "K", "M", "G", "T", "P"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 { format!("{}{}", bytes, UNITS[0]) }
    else if v < 10.0 { format!("{v:.2}{}", UNITS[i]) }
    else if v < 100.0 { format!("{v:.1}{}", UNITS[i]) }
    else { format!("{v:.0}{}", UNITS[i]) }
}

pub fn humanize_rate(bytes_per_sec: f64) -> String {
    format!("{}/s", humanize_bytes(bytes_per_sec.max(0.0) as u64))
}

pub fn humanize_count(n: u64) -> String {
    if n < 1_000 { n.to_string() }
    else if n < 1_000_000 { format!("{:.1}k", n as f64 / 1e3) }
    else if n < 1_000_000_000 { format!("{:.1}M", n as f64 / 1e6) }
    else { format!("{:.1}G", n as f64 / 1e9) }
}

// ---------------------------------------------------------------------------
// Bar
// ---------------------------------------------------------------------------

pub struct Bar {
    pub value: f64,
    pub max: f64,
    pub style: Style,
    pub symbol: char,
}

impl Bar {
    pub fn new(value: f64, max: f64) -> Self {
        Self { value, max, style: Style::default(), symbol: '█' }
    }
    pub fn style(mut self, s: Style) -> Self { self.style = s; self }
    pub fn symbol(mut self, c: char) -> Self { self.symbol = c; self }
}

impl Widget for Bar {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.width == 0 { return; }
        let ratio = if self.max > 0.0 { (self.value / self.max).clamp(0.0, 1.0) } else { 0.0 };
        let filled = (ratio * area.width as f64).round() as u16;
        let mut line = String::with_capacity(area.width as usize);
        for i in 0..area.width {
            line.push(if i < filled { self.symbol } else { ' ' });
        }
        Paragraph::new(Line::from(Span::styled(line, self.style))).render(area, buf);
    }
}

// ---------------------------------------------------------------------------
// Dual RX/TX bar
// ---------------------------------------------------------------------------

pub struct DualBar {
    pub rx: f64,
    pub tx: f64,
    pub max: f64,
    pub rx_style: Style,
    pub tx_style: Style,
}

impl Widget for DualBar {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.width == 0 { return; }
        let half = area.width / 2;
        let rx_ratio = if self.max > 0.0 { (self.rx / self.max).clamp(0.0, 1.0) } else { 0.0 };
        let tx_ratio = if self.max > 0.0 { (self.tx / self.max).clamp(0.0, 1.0) } else { 0.0 };
        let rx_fill = (rx_ratio * half as f64).round() as u16;
        let tx_fill = (tx_ratio * half as f64).round() as u16;

        let mut spans: Vec<Span> = Vec::new();
        let tx_str = " ".repeat((half - tx_fill) as usize) + &"█".repeat(tx_fill as usize);
        spans.push(Span::styled(tx_str, self.tx_style));
        spans.push(Span::raw("│"));
        let rx_str = "█".repeat(rx_fill as usize) + &" ".repeat((half - rx_fill) as usize);
        spans.push(Span::styled(rx_str, self.rx_style));
        Paragraph::new(Line::from(spans)).render(area, buf);
    }
}

// ---------------------------------------------------------------------------
// Sparkline history
// ---------------------------------------------------------------------------

pub struct History {
    pub data: Vec<u64>,
}

impl History {
    pub fn new(data: Vec<u64>) -> Self { Self { data } }
    pub fn push(&mut self, v: u64) {
        const CAP: usize = 120;
        if self.data.len() == CAP { self.data.remove(0); }
        self.data.push(v);
    }
}

impl Widget for History {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let spark = Sparkline::default()
            .data(&self.data)
            .style(Style::default().fg(Color::Cyan));
        spark.render(area, buf);
    }
}

// ---------------------------------------------------------------------------
// Panel helper
// ---------------------------------------------------------------------------

pub fn panel<'a>(title: &'a str, theme: &Theme) -> Block<'a> {
    Block::default()
        .title(Span::styled(format!(" {title} "), theme.title()))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(theme.dim))
}

// ---------------------------------------------------------------------------
// Percent bar
// ---------------------------------------------------------------------------

pub struct PercentBar {
    pub percent: f64,
    pub theme: Theme,
}

impl Widget for PercentBar {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.width == 0 { return; }
        let ratio = (self.percent / 100.0).clamp(0.0, 1.0);
        let filled = (ratio * area.width as f64).round() as u16;
        let style = if self.percent >= 90.0 { self.theme.danger() }
            else if self.percent >= 70.0 { self.theme.warn() }
            else { self.theme.rx() };
        let mut line = String::with_capacity(area.width as usize);
        for i in 0..area.width {
            line.push(if i < filled { '█' } else { '░' });
        }
        Paragraph::new(Line::from(Span::styled(line, style))).render(area, buf);
    }
}

// ---------------------------------------------------------------------------
// Key-value row
// ---------------------------------------------------------------------------

pub struct Kv<'a> {
    pub label: &'a str,
    pub value: String,
    pub label_width: u16,
    pub theme: Theme,
    pub value_style: Option<Style>,
}

impl<'a> Widget for Kv<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let line = Line::from(vec![
            Span::styled(
                format!("{:<w$}", self.label, w = self.label_width as usize),
                self.theme.label(),
            ),
            Span::styled(self.value, self.value_style.unwrap_or_else(|| self.theme.value())),
        ]);
        Paragraph::new(line).render(area, buf);
    }
}

// ---------------------------------------------------------------------------
// Section rule
// ---------------------------------------------------------------------------

#[allow(dead_code)]
pub struct Rule;

impl Widget for Rule {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let s: String = "─".repeat(area.width as usize);
        Paragraph::new(Span::styled(s, Style::default().add_modifier(Modifier::DIM)))
            .render(area, buf);
    }
}
