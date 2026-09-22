//! Colour palette and semantic style helpers.

use ratatui::style::{Color, Modifier, Style};

#[derive(Clone, Copy, Debug)]
pub struct Theme {
    pub bg: Color,
    pub fg: Color,
    pub dim: Color,
    pub accent: Color,
    pub rx: Color,
    pub tx: Color,
    pub warn: Color,
    pub danger: Color,
    pub ok: Color,
}

impl Default for Theme {
    fn default() -> Self {
        Self {
            bg: Color::Reset,
            fg: Color::White,
            dim: Color::DarkGray,
            accent: Color::Cyan,
            rx: Color::Green,
            tx: Color::Magenta,
            warn: Color::Yellow,
            danger: Color::Red,
            ok: Color::LightGreen,
        }
    }
}

impl Theme {
    pub fn title(&self) -> Style {
        Style::default().fg(self.accent).add_modifier(Modifier::BOLD)
    }
    pub fn accent_style(&self) -> Style {
        Style::default().fg(self.accent).add_modifier(Modifier::BOLD)
    }
    pub fn label(&self) -> Style { Style::default().fg(self.dim) }
    pub fn value(&self) -> Style { Style::default().fg(self.fg) }
    pub fn rx(&self) -> Style { Style::default().fg(self.rx) }
    pub fn tx(&self) -> Style { Style::default().fg(self.tx) }
    pub fn warn(&self) -> Style { Style::default().fg(self.warn) }
    pub fn danger(&self) -> Style { Style::default().fg(self.danger) }
    pub fn dim_style(&self) -> Style { Style::default().fg(self.dim) }

    pub fn rate_style(&self, bytes_per_sec: f64) -> Style {
        let s = Style::default();
        if bytes_per_sec < 100_000.0 { s.fg(self.dim) }
        else if bytes_per_sec < 10_000_000.0 { s.fg(self.fg) }
        else if bytes_per_sec < 100_000_000.0 { s.fg(self.warn) }
        else { s.fg(self.danger).add_modifier(Modifier::BOLD) }
    }
}
