use std::future::Future;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::time::{Duration, Instant};

use eazyconnect_client::{build_http_client_from_cfg, MasterHttpClient};
use eazyconnect_core::{ClientConfig, NetworkDevice, NetworkSnapshot, RelayTrafficEvent};
use egui::{Frame, Margin, RichText, Stroke, Ui};
use tokio::runtime::Runtime;

use crate::state::format_bytes;
use crate::theme::ThemePalette;
use crate::widgets::{field, primary_btn, secondary_btn};

const REFRESH_INTERVAL: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Default, PartialEq, Eq)]
pub struct NetworkTarget {
    pub url: String,
    pub ca: Option<PathBuf>,
    pub allow_http: bool,
}

struct Session {
    client: MasterHttpClient,
    token: String,
    username: String,
    expires_unix: u64,
}

enum Update {
    SignIn(Result<Session, String>),
    Snapshot(Result<NetworkSnapshot, String>),
    DeviceAccess {
        device: String,
        blocked: bool,
        result: Result<(), String>,
    },
}

#[derive(Default)]
pub struct NetworkPanel {
    target: NetworkTarget,
    username: String,
    password: String,
    tls_pin: String,
    session: Option<Session>,
    pending: Option<Receiver<Update>>,
    snapshot: Option<NetworkSnapshot>,
    updated_at: Option<Instant>,
    next_refresh: Option<Instant>,
    snapshot_error: Option<String>,
    notice: Option<(String, bool)>,
    search: String,
    confirmation: Option<String>,
}

impl NetworkPanel {
    pub fn set_target(&mut self, target: NetworkTarget) {
        if self.target != target {
            *self = Self {
                target,
                ..Self::default()
            };
        }
    }

    fn sign_out(&mut self) {
        self.session = None;
        self.pending = None;
        self.snapshot = None;
        self.updated_at = None;
        self.next_refresh = None;
        self.snapshot_error = None;
        self.notice = None;
        self.confirmation = None;
        self.search.clear();
        self.password.clear();
    }

    fn start(
        &mut self,
        ui: &Ui,
        rt: &Runtime,
        task: impl Future<Output = Update> + Send + 'static,
    ) {
        let (tx, rx) = mpsc::channel();
        let ctx = ui.ctx().clone();
        self.pending = Some(rx);
        rt.spawn(async move {
            let _ = tx.send(task.await);
            ctx.request_repaint();
        });
    }

    fn sign_in(&mut self, ui: &Ui, rt: &Runtime) {
        let NetworkTarget {
            url,
            ca,
            allow_http,
        } = &self.target;
        let pin = self.tls_pin.trim();
        let client = build_http_client_from_cfg(
            Some(url),
            (!pin.is_empty()).then_some(pin),
            ca.as_deref(),
            *allow_http,
            &ClientConfig::default(),
        );
        let client = match client {
            Ok((client, _, _)) => client,
            Err(error) => {
                self.notice = Some((error, true));
                return;
            }
        };
        self.notice = None;
        let username = self.username.trim().to_owned();
        let password = std::mem::take(&mut self.password);
        self.start(ui, rt, async move {
            let result = request(client.login_password(&username, &password)).await;
            Update::SignIn(result.and_then(|auth| {
                if auth.role == "admin" {
                    Ok(Session {
                        client,
                        token: auth.token,
                        username,
                        expires_unix: auth.expires_unix,
                    })
                } else {
                    Err("Sign in with a master administrator account.".into())
                }
            }))
        });
    }

    fn refresh(&mut self, ui: &Ui, rt: &Runtime) {
        let Some(session) = &self.session else { return };
        let client = session.client.clone();
        let token = session.token.clone();
        self.start(ui, rt, async move {
            Update::Snapshot(request(client.network_snapshot(&token)).await)
        });
    }

    fn set_access(&mut self, ui: &Ui, rt: &Runtime, device: String, blocked: bool) {
        let Some(session) = &self.session else { return };
        let client = session.client.clone();
        let token = session.token.clone();
        self.notice = None;
        self.start(ui, rt, async move {
            let result = request(client.set_device_blocked(&token, &device, blocked)).await;
            Update::DeviceAccess {
                device,
                blocked,
                result,
            }
        });
    }

    fn poll(&mut self) {
        if self.session.as_ref().is_some_and(|session| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .is_ok_and(|now| now.as_secs() >= session.expires_unix)
        }) {
            self.sign_out();
            self.notice = Some(("Session expired. Sign in again.".into(), true));
            return;
        }
        let Some(pending) = &self.pending else { return };
        let update = match pending.try_recv() {
            Ok(update) => update,
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Disconnected) => {
                self.pending = None;
                self.notice = Some(("The request ended early. Try again.".into(), true));
                self.next_refresh = None;
                return;
            }
        };
        self.pending = None;
        let error = match update {
            Update::SignIn(Ok(session)) => {
                self.session = Some(session);
                return;
            }
            Update::SignIn(Err(error)) => {
                self.notice = Some((format!("Sign-in failed. {error}"), true));
                return;
            }
            Update::Snapshot(result) => {
                self.next_refresh = Some(Instant::now() + REFRESH_INTERVAL);
                match result {
                    Ok(snapshot) => {
                        self.snapshot = Some(snapshot);
                        self.updated_at = Some(Instant::now());
                        self.snapshot_error = None;
                        return;
                    }
                    Err(error) => error,
                }
            }
            Update::DeviceAccess {
                device,
                blocked,
                result,
            } => {
                self.next_refresh = None;
                match result {
                    Ok(()) => {
                        self.snapshot_error = Some("Fetching current device access.".into());
                        let action = if blocked { "Blocked" } else { "Unblocked" };
                        self.notice = Some((format!("{action} {device}."), false));
                        return;
                    }
                    Err(error) if !access_denied(&error) => {
                        self.snapshot_error = Some("Fetching current device access.".into());
                        self.notice =
                            Some((format!("Could not confirm the change. {error}"), true));
                        return;
                    }
                    Err(error) => error,
                }
            }
        };
        if access_denied(&error) {
            self.sign_out();
            self.notice = Some(("Administrator access ended. Sign in again.".into(), true));
        } else {
            self.snapshot_error = Some(error);
        }
    }

    pub fn show(&mut self, ui: &mut Ui, pal: &ThemePalette, rt: &Runtime) {
        self.poll();
        let now = Instant::now();
        if self.session.is_some()
            && self.pending.is_none()
            && self.confirmation.is_none()
            && self.next_refresh.is_none_or(|next| now >= next)
        {
            self.refresh(ui, rt);
        }
        if self.session.is_some() {
            ui.ctx().request_repaint_after(Duration::from_secs(1));
        }

        egui::ScrollArea::vertical()
            .id_salt("network")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new("Network").size(28.0).strong());
                    if let Some(session) = &self.session {
                        ui.label(RichText::new(&session.username).color(pal.text_muted));
                        if secondary_btn(ui, pal, "Sign out", 36.0).clicked() {
                            self.sign_out();
                        }
                    }
                });
                if !self.target.url.is_empty() {
                    ui.label(
                        RichText::new(&self.target.url)
                            .monospace()
                            .color(pal.text_muted),
                    );
                }
                ui.add_space(12.0);
                if let Some((message, error)) = &self.notice {
                    ui.colored_label(if *error { pal.danger } else { pal.online }, message);
                    ui.add_space(8.0);
                }
                if self.session.is_none() {
                    self.show_sign_in(ui, pal, rt);
                } else {
                    self.show_dashboard(ui, pal, rt);
                }
            });
        self.show_confirmation(ui, pal, rt);
    }

    fn show_sign_in(&mut self, ui: &mut Ui, pal: &ThemePalette, rt: &Runtime) {
        if self.target.url.is_empty() {
            ui.label("Set a master server address in Connection settings, then return here.");
            return;
        }
        card(pal).show(ui, |ui| {
            ui.set_max_width(420.0);
            ui.label(RichText::new("Administrator sign-in").size(19.0).strong());
            ui.label("Monitor the master relay and manage device access.");
            if self.target.url.starts_with("http://") {
                ui.colored_label(pal.idle, "HTTP sends credentials without TLS.");
            }
            let pending = self.pending.is_some();
            let submit = ui.add_enabled_ui(!pending, |ui| {
                ui.add_space(12.0);
                field(ui, "Username", &mut self.username, "admin", false);
                ui.add_space(4.0);
                let password = field(ui, "Password", &mut self.password, "", true);
                if self.target.url.starts_with("https://") {
                    ui.add_space(4.0);
                    field(
                        ui,
                        "Server TLS pin (self-signed certificates)",
                        &mut self.tls_pin,
                        "SHA-256 pin printed by the master",
                        false,
                    );
                }
                ui.add_space(8.0);
                let complete = !self.username.trim().is_empty() && !self.password.is_empty();
                let clicked = ui.add_enabled_ui(complete, |ui| {
                    primary_btn(
                        ui,
                        pal,
                        if pending { "Signing in…" } else { "Sign in" },
                        112.0,
                        40.0,
                    )
                    .clicked()
                });
                complete
                    && (clicked.inner
                        || (password.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))))
            });
            if !pending && submit.inner {
                self.sign_in(ui, rt);
            }
        });
    }

    fn show_dashboard(&mut self, ui: &mut Ui, pal: &ThemePalette, rt: &Runtime) {
        let pending = self.pending.is_some();
        let status = match (&self.snapshot_error, self.updated_at) {
            (Some(_), Some(at)) => format!("Last update {}s ago", at.elapsed().as_secs()),
            (Some(_), None) => "Master status unavailable".into(),
            (None, Some(at)) => format!("Live · Updated {}s ago", at.elapsed().as_secs()),
            (None, None) => "Loading master status…".into(),
        };
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled_ui(!pending, |ui| secondary_btn(ui, pal, "Refresh", 36.0))
                .inner
                .clicked()
            {
                self.refresh(ui, rt);
            }
            ui.label(status);
        });
        if let Some(error) = &self.snapshot_error {
            ui.colored_label(pal.idle, error);
        }
        let Some(snapshot) = &self.snapshot else {
            return;
        };
        ui.add_space(10.0);
        show_metrics(ui, pal, snapshot);
        ui.add_space(16.0);
        let can_manage = !pending && self.snapshot_error.is_none();
        ui.label(RichText::new("Devices").size(20.0).strong());
        if let Some(action) = show_devices(ui, pal, &snapshot.devices, &mut self.search, can_manage)
        {
            if action.blocked {
                self.set_access(ui, rt, action.client_id, false);
                return;
            }
            self.confirmation = Some(action.client_id);
        }
        ui.add_space(16.0);
        show_activity(ui, pal, &snapshot.relay.recent_frames);
    }

    fn show_confirmation(&mut self, ui: &Ui, pal: &ThemePalette, rt: &Runtime) {
        let Some(device) = self.confirmation.clone() else {
            return;
        };
        let response = egui::Modal::new(egui::Id::unique("block_device")).show(ui.ctx(), |ui| {
            ui.set_max_width(300.0);
            ui.heading("Block device?");
            ui.label(RichText::new(&device).monospace());
            ui.label("This disconnects the device and prevents it from reconnecting until you unblock it.");
            ui.add_space(8.0);
            ui.horizontal_wrapped(|ui| {
                let cancel = secondary_btn(ui, pal, "Cancel", 36.0).clicked();
                let block = primary_btn(ui, pal, "Block device", 100.0, 36.0).clicked();
                (cancel, block)
            }).inner
        });
        let (cancel, block) = response.inner;
        if cancel || block || response.should_close() {
            self.confirmation = None;
        }
        if block {
            self.set_access(ui, rt, device, true);
        }
    }
}

async fn request<T>(task: impl Future<Output = Result<T, String>>) -> Result<T, String> {
    tokio::time::timeout(REQUEST_TIMEOUT, task)
        .await
        .map_err(|_| "The master did not respond within 15 seconds.".to_string())?
}

fn access_denied(error: &str) -> bool {
    error.starts_with("HTTP 401:") || error.starts_with("HTTP 403:")
}

fn card(pal: &ThemePalette) -> Frame {
    Frame::new()
        .fill(pal.card_bg)
        .stroke(Stroke::new(1.0, pal.border))
        .corner_radius(10)
        .inner_margin(Margin::same(14))
}

fn show_metrics(ui: &mut Ui, pal: &ThemePalette, snapshot: &NetworkSnapshot) {
    let uptime = snapshot.uptime_seconds;
    let uptime_text = format!(
        "{}d {:02}h {:02}m",
        uptime / 86_400,
        (uptime / 3_600) % 24,
        (uptime / 60) % 60
    );
    let metrics = [
        (
            "Online / enrolled",
            format!(
                "{} / {}",
                snapshot.relay.online_peers.len(),
                snapshot.devices.len()
            ),
        ),
        (
            "Relay frames",
            snapshot.relay.total_routed_frames.to_string(),
        ),
        ("Master uptime", uptime_text),
    ];
    let narrow = ui.available_width() < 510.0;
    let width = if narrow {
        ui.available_width()
    } else {
        (ui.available_width() - 16.0) / 3.0
    };
    ui.horizontal_wrapped(|ui| {
        for (label, value) in metrics {
            card(pal).show(ui, |ui| {
                ui.set_width((width - 30.0).max(120.0));
                ui.label(RichText::new(label).color(pal.text_muted));
                ui.label(RichText::new(value).size(24.0).strong());
            });
        }
    });
}

fn show_devices(
    ui: &mut Ui,
    pal: &ThemePalette,
    devices: &[NetworkDevice],
    search: &mut String,
    can_manage: bool,
) -> Option<NetworkDevice> {
    if devices.is_empty() {
        ui.label("No devices have enrolled.");
        return None;
    }
    field(ui, "Find a device", search, "Device ID", false);
    let query = search.trim().to_ascii_lowercase();
    let matches: Vec<_> = devices
        .iter()
        .filter(|device| device.client_id.to_ascii_lowercase().contains(&query))
        .collect();
    if matches.is_empty() {
        ui.label("No devices match your search.");
        return None;
    }
    ui.add_space(6.0);
    let mut action = None;
    egui::ScrollArea::vertical()
        .id_salt("device_list")
        .max_height(294.0)
        .show_rows(ui, 44.0, matches.len(), |ui, rows| {
            for &device in &matches[rows] {
                ui.push_id(&device.client_id, |ui| {
                    ui.horizontal(|ui| {
                        let (state, color, label) = if device.blocked {
                            ("Blocked", pal.danger, "Unblock")
                        } else if device.online {
                            ("Online", pal.online, "Block")
                        } else {
                            ("Offline", pal.text_muted, "Block")
                        };
                        let name_width = (ui.available_width() - 190.0).max(68.0);
                        ui.add_sized(
                            [name_width, 44.0],
                            egui::Label::new(RichText::new(&device.client_id).monospace())
                                .truncate(),
                        )
                        .on_hover_text(&device.client_id);
                        ui.add_sized(
                            [72.0, 44.0],
                            egui::Label::new(RichText::new(state).color(color)),
                        );
                        if ui
                            .add_enabled_ui(can_manage, |ui| secondary_btn(ui, pal, label, 36.0))
                            .inner
                            .clicked()
                        {
                            action = Some(device.clone());
                        }
                    });
                });
            }
        });
    action
}

fn show_activity(ui: &mut Ui, pal: &ThemePalette, events: &[RelayTrafficEvent]) {
    ui.label(RichText::new("Recent relay activity").size(20.0).strong());
    if events.is_empty() {
        ui.label("No relay activity has been recorded.");
        return;
    }
    egui::ScrollArea::vertical()
        .id_salt("network_activity")
        .max_height(238.0)
        .show(ui, |ui| {
            for event in events.iter().rev() {
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new(format!("#{}  {}", event.seq, event.frame_type)).strong(),
                    );
                    ui.label(
                        RichText::new(format!("{} → {}", event.from, event.to))
                            .color(pal.text_muted),
                    );
                    if let Some(bytes) = event.wire_total_bytes {
                        ui.label(RichText::new(format_bytes(bytes as u64)).monospace());
                    }
                });
                ui.separator();
            }
        });
}
