use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use eazyconnect_client::NodeEvent;
use eazyconnect_core::{DiscoveredMaster, PeerIdentity, DEFAULT_DISCOVERY_PORT};
use eazyconnect_hw::SystemHardwareReport;
use egui::{Color32, Pos2, Rect, Sense, Stroke, TextureHandle, Vec2};

use crate::theme::ThemePalette;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppScreen {
    Onboarding,
    Chat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsSection {
    Account,
    Theme,
    Connection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Online,
    Reconnecting { attempt: u32 },
}

#[derive(Debug, Clone)]
pub struct ChatMessage {
    pub sender: String,
    pub text: String,
    pub timestamp: String,
    pub outgoing: bool,
}

#[derive(Debug, Clone, Default)]
pub struct PeerConversation {
    pub messages: Vec<ChatMessage>,
    pub paired: bool,
    pub pairing_in_flight: bool,
    pub safety_code: Option<String>,
    pub unread: u32,
}

#[derive(Debug)]
pub enum UiEvent {
    DiscoveryDone(Vec<DiscoveredMaster>),
    HardwareChecked(SystemHardwareReport),
    AutoConnectOk {
        master_url: String,
        tls_pin_hex: Option<String>,
        client_id: String,
        token: Option<(String, String)>,
        peers: Vec<PeerIdentity>,
    },
    AutoConnectFailed(String),
    LoginOk {
        username: String,
        role: String,
        token: String,
        master_url: String,
    },
    UserCreated(String),
    Notice {
        msg: String,
        is_error: bool,
    },
    NodeEvent(NodeEvent),
    DisconnectedCleanly,
}

/// Normalizes user-entered server addresses (`192.168.1.10`, `192.168.1.10:8000`, `https://...`).
pub fn normalize_server_url(raw: &str, insecure_http: bool) -> String {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return String::new();
    }
    let has_scheme = trimmed.starts_with("https://")
        || trimmed.starts_with("http://")
        || trimmed.starts_with("wss://")
        || trimmed.starts_with("ws://");
    let with_scheme = if has_scheme {
        trimmed
            .replacen("wss://", "https://", 1)
            .replacen("ws://", "http://", 1)
    } else if insecure_http {
        format!("http://{trimmed}")
    } else {
        format!("https://{trimmed}")
    };

    if let Some((scheme, rest)) = with_scheme.split_once("://") {
        let authority = rest.split('/').next().unwrap_or(rest);
        let has_port = if let Some(idx) = authority.rfind(']') {
            authority[idx..].contains(':')
        } else {
            authority.contains(':')
        };
        if has_port {
            with_scheme
        } else {
            format!("{scheme}://{authority}:8000")
        }
    } else {
        with_scheme
    }
}

/// Builds a unicast UDP 37020 probe address if `url` points to a direct IPv4 host.
pub fn discovery_target_for_server(url: &str) -> Option<SocketAddr> {
    let rest = url
        .split_once("://")
        .map(|(_, r)| r)
        .unwrap_or(url);
    let authority = rest.split('/').next()?;
    let host = if let Some(stripped) = authority.strip_prefix('[') {
        stripped.split(']').next()?
    } else {
        authority.split(':').next()?
    };
    let ip: IpAddr = host.parse().ok()?;
    Some(SocketAddr::new(ip, DEFAULT_DISCOVERY_PORT))
}

pub fn broadcast_discovery_target() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), DEFAULT_DISCOVERY_PORT)
}

pub fn initials_for(name: &str) -> String {
    let parts: Vec<&str> = name
        .split(|c: char| !c.is_alphanumeric())
        .filter(|s| !s.is_empty())
        .collect();
    if parts.len() >= 2 {
        let a = parts[0].chars().next().unwrap_or('?');
        let b = parts[1].chars().next().unwrap_or('?');
        format!("{}{}", a.to_ascii_uppercase(), b.to_ascii_uppercase())
    } else {
        let mut chars = name.chars().filter(|c| c.is_alphanumeric());
        let a = chars.next().unwrap_or('?').to_ascii_uppercase();
        let b = chars.next().map(|c| c.to_ascii_uppercase());
        match b {
            Some(c) => format!("{a}{c}"),
            None => a.to_string(),
        }
    }
}

pub fn avatar_color_for(id: &str) -> Color32 {
    const PALETTE: &[Color32] = &[
        Color32::from_rgb(88, 101, 242),  // Blurple
        Color32::from_rgb(35, 165, 90),   // Green
        Color32::from_rgb(235, 69, 158),  // Fuchsia
        Color32::from_rgb(240, 178, 50),  // Gold
        Color32::from_rgb(0, 168, 252),   // Cyan
        Color32::from_rgb(230, 126, 34),  // Orange
    ];
    let hash = id
        .bytes()
        .fold(0usize, |acc, b| acc.wrapping_mul(31).wrapping_add(usize::from(b)));
    PALETTE[hash % PALETTE.len()]
}

pub fn format_time_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mins_today = (secs / 60) % (24 * 60);
    format!("{:02}:{:02}", mins_today / 60, mins_today % 60)
}

/// Draws a circular Discord-style avatar with optional image texture and bottom-right status dot.
pub fn paint_avatar(
    ui: &mut egui::Ui,
    size: f32,
    id_seed: &str,
    display_name: &str,
    status_dot: Option<Color32>,
    ring_bg: Color32,
    tex: Option<&TextureHandle>,
) -> egui::Response {
    let (rect, resp) = ui.allocate_exact_size(Vec2::splat(size), Sense::click());
    let painter = ui.painter();
    let center = rect.center();
    let radius = size * 0.5;

    if let Some(handle) = tex {
        painter.image(
            handle.id(),
            rect,
            Rect::from_min_max(Pos2::new(0.0, 0.0), Pos2::new(1.0, 1.0)),
            Color32::WHITE,
        );
        // Circular mask edge ring blends rectangular thumbnails neatly into the Discord chrome.
        painter.circle_stroke(center, radius, Stroke::new(2.0, ring_bg));
    } else {
        painter.circle_filled(center, radius, avatar_color_for(id_seed));
        let label = initials_for(if display_name.is_empty() {
            id_seed
        } else {
            display_name
        });
        painter.text(
            center,
            egui::Align2::CENTER_CENTER,
            label,
            egui::FontId::proportional((size * 0.38).max(10.0)),
            Color32::WHITE,
        );
    }

    if let Some(dot_color) = status_dot {
        let dot_r = (size * 0.17).clamp(4.0, 7.0);
        let dot_center = Pos2::new(rect.right() - dot_r * 0.85, rect.bottom() - dot_r * 0.85);
        painter.circle_filled(dot_center, dot_r + 2.0, ring_bg);
        painter.circle_filled(dot_center, dot_r, dot_color);
    }
    resp
}

pub fn status_pill(ui: &mut egui::Ui, pal: &ThemePalette, label: &str, color: Color32) {
    egui::Frame::new()
        .fill(Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 28))
        .stroke(Stroke::new(1.0, color))
        .corner_radius(egui::CornerRadius::same(10))
        .inner_margin(egui::Margin::symmetric(8, 3))
        .show(ui, |ui| {
            ui.label(
                egui::RichText::new(label)
                    .size(11.5)
                    .strong()
                    .color(if pal.is_dark { color } else { pal.text_primary }),
            );
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_server_url_adds_defaults_cleanly() {
        assert_eq!(
            normalize_server_url("192.168.1.50", false),
            "https://192.168.1.50:8000"
        );
        assert_eq!(
            normalize_server_url("10.188.97.223:8443/", false),
            "https://10.188.97.223:8443"
        );
        assert_eq!(
            normalize_server_url("wss://relay.local:9000", false),
            "https://relay.local:9000"
        );
        assert_eq!(
            normalize_server_url("127.0.0.1:8080", true),
            "http://127.0.0.1:8080"
        );
    }

    #[test]
    fn test_discovery_target_extracts_unicast_ip() {
        let addr = discovery_target_for_server("https://10.188.97.223:8000").unwrap();
        assert_eq!(addr.to_string(), "10.188.97.223:37020");
        assert!(discovery_target_for_server("https://master.local:8000").is_none());
    }

    #[test]
    fn test_initials_for_formats_names() {
        assert_eq!(initials_for("Alice Bob"), "AB");
        assert_eq!(initials_for("hami"), "HA");
        assert_eq!(initials_for("x"), "X");
    }
}
