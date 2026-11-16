use std::collections::BTreeMap;

use eazyconnect_client::{DiagnosticReport, NodeEvent, SyncRunSummary};
use eazyconnect_core::{
    DiscoveredMaster, EazyMeshProfile, HealthResponse, PeerIdentity, ServerFileEntry,
};
use eazyconnect_hw::SystemHardwareReport;
use egui::{Color32, CornerRadius, Frame, Margin, RichText, Stroke};

pub const BG_CANVAS: Color32 = Color32::from_rgb(13, 18, 30);
pub const BG_PANEL: Color32 = Color32::from_rgb(18, 25, 41);
pub const BG_CARD: Color32 = Color32::from_rgb(24, 33, 53);
pub const BG_INPUT: Color32 = Color32::from_rgb(15, 21, 36);
pub const BORDER_SUBTLE: Color32 = Color32::from_rgb(45, 59, 89);

pub const ACCENT_CYAN: Color32 = Color32::from_rgb(56, 189, 248);
pub const ACCENT_EMERALD: Color32 = Color32::from_rgb(16, 185, 129);
pub const ACCENT_AMBER: Color32 = Color32::from_rgb(245, 158, 11);
pub const ACCENT_ROSE: Color32 = Color32::from_rgb(244, 63, 94);
pub const TEXT_PRIMARY: Color32 = Color32::from_rgb(241, 245, 249);
pub const TEXT_MUTED: Color32 = Color32::from_rgb(148, 163, 184);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveTab {
    Connect,
    Files,
    Chat,
    Hardware,
    Diagnostics,
    Profile,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayStatus {
    Disconnected,
    Connecting,
    Online,
    Reconnecting { attempt: u32, reason: String },
}

#[derive(Debug, Clone)]
pub struct PendingOffer {
    pub pair_id: String,
    pub from: String,
    pub profile: EazyMeshProfile,
    pub has_psk: bool,
}

#[derive(Debug, Clone)]
pub struct PairedPeerInfo {
    pub safety_fingerprint: String,
    pub epoch: u64,
}

#[derive(Debug, Clone)]
pub struct ChatLine {
    pub badge: String,
    pub badge_color: Color32,
    pub body: String,
}

#[derive(Debug)]
pub enum UiEvent {
    DiscoveryDone(Result<Vec<DiscoveredMaster>, String>),
    HealthDone(Result<HealthResponse, String>),
    EnrollDone {
        client_id: String,
        role: String,
        token: String,
        master_url: String,
        tls_pin_hex: Option<String>,
    },
    LoginDone {
        username: String,
        role: String,
        token: String,
        master_url: String,
    },
    UserCreated(String),
    ActionError(String),
    UploadDone(ServerFileEntry),
    SyncDone(SyncRunSummary),
    FilesListed {
        owner: String,
        files: Vec<ServerFileEntry>,
    },
    DownloadDone {
        remote: String,
        dest: String,
        bytes: usize,
        e2e: bool,
    },
    DeleteDone(String),
    HardwareDone(SystemHardwareReport),
    SerialDone(Result<Vec<u8>, String>),
    DiagDone(Result<(DiagnosticReport, Option<String>), String>),
    RelayConnected(Vec<PeerIdentity>),
    RelayConnectFailed(String),
    RelayNodeEvent(NodeEvent),
    RelayInfo(String),
    RelayStopped,
}

pub fn card_frame() -> Frame {
    Frame::new()
        .fill(BG_CARD)
        .stroke(Stroke::new(1.0, BORDER_SUBTLE))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::same(14))
}

pub fn section_heading(ui: &mut egui::Ui, title: &str, subtitle: &str) {
    ui.label(
        RichText::new(title)
            .size(16.0)
            .strong()
            .color(TEXT_PRIMARY),
    );
    if !subtitle.is_empty() {
        ui.label(RichText::new(subtitle).size(12.0).color(TEXT_MUTED));
    }
    ui.add_space(6.0);
}

pub fn status_pill(ui: &mut egui::Ui, label: &str, color: Color32) {
    Frame::new()
        .fill(Color32::from_rgba_unmultiplied(
            color.r(),
            color.g(),
            color.b(),
            28,
        ))
        .stroke(Stroke::new(1.0, color))
        .corner_radius(CornerRadius::same(6))
        .inner_margin(Margin::symmetric(8, 3))
        .show(ui, |ui| {
            ui.label(RichText::new(label).size(11.5).strong().color(color));
        });
}

pub fn format_bytes(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    let b = bytes as f64;
    if b >= GB {
        format!("{:.2} GiB", b / GB)
    } else if b >= MB {
        format!("{:.2} MiB", b / MB)
    } else if b >= KB {
        format!("{:.1} KiB", b / KB)
    } else {
        format!("{bytes} B")
    }
}

/// Applies a selected discovered master onto mutable connection strings (URL + SHA-256 pin).
pub fn apply_discovered_master(
    master: &DiscoveredMaster,
    selected_url: &str,
    master_url: &mut String,
    tls_pin_hex: &mut String,
    insecure_http: &mut bool,
) {
    *master_url = selected_url.to_string();
    *insecure_http = !master.https;
    if let Some(ref pin) = master.tls_cert_sha256_hex {
        *tls_pin_hex = pin.clone();
    }
}

pub fn profile_label(profile: EazyMeshProfile) -> &'static str {
    match profile {
        EazyMeshProfile::Standard => "Standard (100 cubes)",
        EazyMeshProfile::Compact => "Compact (40 cubes)",
        EazyMeshProfile::HighCapacity => "HighCapacity (160 cubes)",
    }
}

pub fn sort_paired_label(paired: &BTreeMap<String, PairedPeerInfo>, peer: &str) -> Option<String> {
    paired
        .get(peer)
        .map(|p| format!("{} @e{}", p.safety_fingerprint, p.epoch))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes_scales_cleanly() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1536), "1.5 KiB");
        assert_eq!(format_bytes(2 * 1024 * 1024), "2.00 MiB");
    }

    #[test]
    fn test_apply_discovered_master_updates_url_pin_and_tls_flag() {
        let m = DiscoveredMaster {
            url: "https://100.64.0.10:8000".to_string(),
            host: "100.64.0.10".to_string(),
            port: 8000,
            https: true,
            source_ip: "100.64.0.10".to_string(),
            tls_cert_sha256_hex: Some("ab".repeat(32)),
            master_ed25519_pub_hex: "cd".repeat(32),
            signature_valid: true,
            alternate_urls: vec!["https://192.168.1.50:8000".to_string()],
        };
        let mut url = String::new();
        let mut pin = String::new();
        let mut insecure = true;
        apply_discovered_master(
            &m,
            "https://192.168.1.50:8000",
            &mut url,
            &mut pin,
            &mut insecure,
        );
        assert_eq!(url, "https://192.168.1.50:8000");
        assert_eq!(pin, "ab".repeat(32));
        assert!(!insecure);
    }
}
