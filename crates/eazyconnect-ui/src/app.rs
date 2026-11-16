use std::collections::BTreeMap;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use eazyconnect_client::{
    build_http_client_from_cfg, default_sync_manifest_path, load_bearer_token,
    load_or_create_vault_key, run_diagnostics, sync_folder_to_master, EazyNode,
    NodeConnectOptions, NodeEvent, SyncRunSummary,
};
use eazyconnect_core::{
    decrypt_file_from_vault, discover_masters, encrypt_file_for_vault, load_client_config,
    save_client_config, ClientConfig, CreateUserRequest, DiscoveredMaster, EazyAppMessage,
    EazyMeshProfile, PeerIdentity, ServerFileEntry, DEFAULT_DISCOVERY_PORT,
};
use eazyconnect_hw::{
    collect_hardware_report, send_serial_command, DeviceIdentity, SystemHardwareReport,
};
use egui::{Color32, RichText};
use tokio::runtime::Runtime;
use tokio::sync::Mutex as TokioMutex;

use crate::state::{
    apply_discovered_master, card_frame, format_bytes, profile_label, section_heading,
    sort_paired_label, status_pill, ActiveTab, ChatLine, PairedPeerInfo, PendingOffer, RelayStatus,
    UiEvent, ACCENT_AMBER, ACCENT_CYAN, ACCENT_EMERALD, ACCENT_ROSE, BG_CANVAS, BG_PANEL,
    TEXT_MUTED, TEXT_PRIMARY,
};

pub struct EazyUiApp {
    rt: Arc<Runtime>,
    config_path: Option<PathBuf>,
    keystore_dir: Option<PathBuf>,
    events_tx: mpsc::Sender<UiEvent>,
    events_rx: mpsc::Receiver<UiEvent>,

    active_tab: ActiveTab,
    status_banner: Option<(String, Color32)>,
    busy_label: Option<String>,

    // Persisted client configuration & credentials
    master_url: String,
    tls_pin_hex: String,
    tls_ca_pem_path: String,
    insecure_http: bool,
    client_id: String,
    invite_code: String,
    username: String,
    password: String,
    new_user_name: String,
    new_user_pass: String,
    new_user_admin: bool,
    has_sealed_token: bool,
    loaded_cfg: ClientConfig,

    // Discovery
    discovery_target: String,
    discovered_masters: Vec<DiscoveredMaster>,

    // Files & E2E Vault
    upload_local_path: String,
    upload_remote_path: String,
    files_e2e: bool,
    vault_key_hex: String,
    sync_folder_path: String,
    last_sync_summary: String,
    owner_filter: String,
    remote_files: Vec<ServerFileEntry>,

    // CubeHash E2E Relay Chat
    relay_status: RelayStatus,
    active_node: Arc<TokioMutex<Option<EazyNode>>>,
    online_peers: Vec<PeerIdentity>,
    selected_peer: String,
    pair_profile: EazyMeshProfile,
    chat_psk: String,
    pending_offers: Vec<PendingOffer>,
    paired_peers: BTreeMap<String, PairedPeerInfo>,
    chat_input: String,
    chat_lines: Vec<ChatLine>,

    // Hardware & Serial
    hardware: Option<SystemHardwareReport>,
    serial_port: String,
    serial_baud: String,
    serial_payload: String,
    serial_hex_mode: bool,
    serial_output: String,

    // Diagnostics & Profile
    diag_json: String,
    profile_name: String,
    profile_photo: String,
    profile_lang: String,
}

impl EazyUiApp {
    pub fn new(
        rt: Arc<Runtime>,
        config_path: Option<PathBuf>,
        keystore_dir: Option<PathBuf>,
        ctx: &egui::Context,
    ) -> Self {
        let (events_tx, events_rx) = mpsc::channel();
        let cfg = load_client_config(config_path.as_deref()).unwrap_or_default();
        let client_id = cfg
            .client_id
            .clone()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(eazyconnect_hw::hostname);
        let has_sealed_token = cfg.sealed_token_hex.is_some();

        let mut app = Self {
            rt,
            config_path,
            keystore_dir,
            events_tx,
            events_rx,
            active_tab: ActiveTab::Connect,
            status_banner: Some((
                "Ready — select or discover a Master server to begin.".to_string(),
                ACCENT_CYAN,
            )),
            busy_label: None,
            master_url: cfg.master.clone().unwrap_or_default(),
            tls_pin_hex: cfg.tls_pin_hex.clone().unwrap_or_default(),
            tls_ca_pem_path: cfg.tls_ca_pem_path.clone().unwrap_or_default(),
            insecure_http: !cfg.verify,
            client_id,
            invite_code: String::new(),
            username: cfg.username.clone().unwrap_or_default(),
            password: String::new(),
            new_user_name: String::new(),
            new_user_pass: String::new(),
            new_user_admin: false,
            has_sealed_token,
            discovery_target: format!("255.255.255.255:{DEFAULT_DISCOVERY_PORT}"),
            discovered_masters: Vec::new(),
            upload_local_path: String::new(),
            upload_remote_path: String::new(),
            files_e2e: true,
            vault_key_hex: String::new(),
            sync_folder_path: String::new(),
            last_sync_summary: String::new(),
            owner_filter: String::new(),
            remote_files: Vec::new(),
            relay_status: RelayStatus::Disconnected,
            active_node: Arc::new(TokioMutex::new(None)),
            online_peers: Vec::new(),
            selected_peer: String::new(),
            pair_profile: EazyMeshProfile::Standard,
            chat_psk: String::new(),
            pending_offers: Vec::new(),
            paired_peers: BTreeMap::new(),
            chat_input: String::new(),
            chat_lines: Vec::new(),
            hardware: None,
            serial_port: String::new(),
            serial_baud: "115200".to_string(),
            serial_payload: "AT+INFO?\n".to_string(),
            serial_hex_mode: false,
            serial_output: String::new(),
            diag_json: String::new(),
            profile_name: cfg.profile.name.clone(),
            profile_photo: cfg.profile.photo.clone(),
            profile_lang: if cfg.profile.language.is_empty() {
                "en".to_string()
            } else {
                cfg.profile.language.clone()
            },
            loaded_cfg: cfg,
        };

        app.spawn_refresh_hardware(ctx);
        app
    }

    fn current_cfg_snapshot(&self) -> ClientConfig {
        let mut cfg = self.loaded_cfg.clone();
        cfg.master = (!self.master_url.trim().is_empty()).then(|| self.master_url.trim().to_string());
        cfg.tls_pin_hex = (!self.tls_pin_hex.trim().is_empty()).then(|| self.tls_pin_hex.trim().to_string());
        cfg.tls_ca_pem_path =
            (!self.tls_ca_pem_path.trim().is_empty()).then(|| self.tls_ca_pem_path.trim().to_string());
        cfg.verify = !self.insecure_http;
        cfg.client_id = (!self.client_id.trim().is_empty()).then(|| self.client_id.trim().to_string());
        cfg.username = (!self.username.trim().is_empty()).then(|| self.username.trim().to_string());
        cfg.profile.name = self.profile_name.trim().to_string();
        cfg.profile.photo = self.profile_photo.trim().to_string();
        cfg.profile.language = if self.profile_lang == "fa" {
            "fa".to_string()
        } else {
            "en".to_string()
        };
        cfg
    }

    fn persist_current_cfg(&mut self) -> Result<PathBuf, String> {
        let snap = self.current_cfg_snapshot();
        let saved = save_client_config(&snap, self.config_path.as_deref())?;
        self.loaded_cfg = snap;
        self.has_sealed_token = self.loaded_cfg.sealed_token_hex.is_some();
        Ok(saved)
    }

    fn set_banner(&mut self, msg: impl Into<String>, color: Color32) {
        self.status_banner = Some((msg.into(), color));
    }

    fn poll_async_events(&mut self) {
        while let Ok(ev) = self.events_rx.try_recv() {
            match ev {
                UiEvent::DiscoveryDone(res) => {
                    self.busy_label = None;
                    match res {
                        Ok(list) => {
                            let count = list.len();
                            self.discovered_masters = list;
                            if count == 0 {
                                self.set_banner(
                                    "No Masters replied to UDP discovery (check firewall / target IP).",
                                    ACCENT_AMBER,
                                );
                            } else {
                                self.set_banner(
                                    format!("Discovered {count} Master(s) via signed UDP 37020."),
                                    ACCENT_EMERALD,
                                );
                            }
                        }
                        Err(e) => self.set_banner(format!("Discovery failed: {e}"), ACCENT_ROSE),
                    }
                }
                UiEvent::HealthDone(res) => {
                    self.busy_label = None;
                    match res {
                        Ok(h) => self.set_banner(
                            format!(
                                "Health OK: v{} | devices={} | online_ws_peers={} | key={}..",
                                h.version,
                                h.device_count,
                                h.online_ws_peers,
                                &h.master_ed25519_pub_hex[..16.min(h.master_ed25519_pub_hex.len())]
                            ),
                            ACCENT_EMERALD,
                        ),
                        Err(e) => self.set_banner(format!("Health check failed: {e}"), ACCENT_ROSE),
                    }
                }
                UiEvent::EnrollDone {
                    client_id,
                    role,
                    token,
                    master_url,
                    tls_pin_hex,
                } => {
                    self.busy_label = None;
                    self.loaded_cfg.master = Some(master_url);
                    self.loaded_cfg.client_id = Some(client_id.clone());
                    self.loaded_cfg.role = Some(role);
                    self.loaded_cfg.verify = !self.insecure_http;
                    if let Some(pin) = tls_pin_hex {
                        self.loaded_cfg.tls_pin_hex = Some(pin);
                    }
                    match self
                        .loaded_cfg
                        .set_token(&client_id, &token)
                        .and_then(|_| save_client_config(&self.loaded_cfg, self.config_path.as_deref()))
                    {
                        Ok(path) => {
                            self.has_sealed_token = true;
                            self.set_banner(
                                format!("Enrolled '{client_id}' and sealed token in {}", path.display()),
                                ACCENT_EMERALD,
                            );
                        }
                        Err(e) => self.set_banner(format!("Failed to save sealed token: {e}"), ACCENT_ROSE),
                    }
                }
                UiEvent::LoginDone {
                    username,
                    role,
                    token,
                    master_url,
                } => {
                    self.busy_label = None;
                    let cid = eazyconnect_client::resolve_client_id(
                        Some(&self.client_id),
                        &self.loaded_cfg,
                    );
                    self.loaded_cfg.master = Some(master_url);
                    self.loaded_cfg.username = Some(username.clone());
                    self.loaded_cfg.role = Some(role.clone());
                    self.loaded_cfg.client_id = Some(cid.clone());
                    match self
                        .loaded_cfg
                        .set_token(&cid, &token)
                        .and_then(|_| save_client_config(&self.loaded_cfg, self.config_path.as_deref()))
                    {
                        Ok(_) => {
                            self.has_sealed_token = true;
                            self.password.clear();
                            self.set_banner(
                                format!("Logged in as '{username}' (role={role}); token sealed via DPAPI."),
                                ACCENT_EMERALD,
                            );
                        }
                        Err(e) => self.set_banner(format!("Token save failed: {e}"), ACCENT_ROSE),
                    }
                }
                UiEvent::UserCreated(msg) => {
                    self.busy_label = None;
                    self.new_user_pass.clear();
                    self.set_banner(msg, ACCENT_EMERALD);
                }
                UiEvent::ActionError(e) => {
                    self.busy_label = None;
                    self.set_banner(e, ACCENT_ROSE);
                }
                UiEvent::UploadDone(entry) => {
                    self.busy_label = None;
                    self.set_banner(
                        format!(
                            "Uploaded '{}' ({}, e2e={}, blake3={}..)",
                            entry.filename,
                            format_bytes(entry.size_bytes),
                            entry.e2e_encrypted,
                            &entry.blake3_hex[..16.min(entry.blake3_hex.len())]
                        ),
                        ACCENT_EMERALD,
                    );
                }
                UiEvent::SyncDone(summary) => {
                    self.busy_label = None;
                    self.last_sync_summary = format!(
                        "Synced {} file(s) from {} ({} tracked, e2e={}): {}",
                        summary.uploaded_count,
                        summary.scanned_folder,
                        summary.total_manifest_entries,
                        summary.e2e_encrypted,
                        if summary.uploaded_files.is_empty() {
                            "none changed".to_string()
                        } else {
                            summary.uploaded_files.join(", ")
                        }
                    );
                    self.set_banner(self.last_sync_summary.clone(), ACCENT_EMERALD);
                }
                UiEvent::FilesListed { owner, files } => {
                    self.busy_label = None;
                    let count = files.len();
                    self.remote_files = files;
                    self.set_banner(format!("Listed {count} file(s) for '{owner}'."), ACCENT_CYAN);
                }
                UiEvent::DownloadDone {
                    remote,
                    dest,
                    bytes,
                    e2e,
                } => {
                    self.busy_label = None;
                    self.set_banner(
                        format!(
                            "Downloaded '{remote}' -> {dest} ({}, e2e_decrypted={e2e})",
                            format_bytes(bytes as u64)
                        ),
                        ACCENT_EMERALD,
                    );
                }
                UiEvent::DeleteDone(rel) => {
                    self.busy_label = None;
                    self.remote_files.retain(|f| f.filename != rel);
                    self.set_banner(format!("Deleted '{rel}' from Master."), ACCENT_AMBER);
                }
                UiEvent::HardwareDone(rep) => {
                    if self.serial_port.is_empty() {
                        if let Some(first) = rep.serial_ports.first() {
                            self.serial_port = first.port_name.clone();
                        }
                    }
                    self.hardware = Some(rep);
                }
                UiEvent::SerialDone(res) => {
                    self.busy_label = None;
                    match res {
                        Ok(reply) => {
                            let utf8 = String::from_utf8_lossy(&reply);
                            let hex_s = hex::encode(&reply);
                            self.serial_output = format!("UTF-8: {utf8}\nHEX:   {hex_s}");
                            self.set_banner("Serial command completed.", ACCENT_EMERALD);
                        }
                        Err(e) => {
                            self.serial_output = format!("Error: {e}");
                            self.set_banner(format!("Serial error: {e}"), ACCENT_ROSE);
                        }
                    }
                }
                UiEvent::DiagDone(res) => {
                    self.busy_label = None;
                    match res {
                        Ok((rep, upload_msg)) => {
                            self.hardware = Some(rep.hardware.clone());
                            self.diag_json = serde_json::to_string_pretty(&rep)
                                .unwrap_or_else(|e| e.to_string());
                            let msg = match upload_msg {
                                Some(u) => format!("Diagnostics finished & uploaded ({u})."),
                                None => "Diagnostics completed locally.".to_string(),
                            };
                            self.set_banner(msg, ACCENT_EMERALD);
                        }
                        Err(e) => self.set_banner(format!("Diagnostics failed: {e}"), ACCENT_ROSE),
                    }
                }
                UiEvent::RelayConnected(peers) => {
                    self.relay_status = RelayStatus::Online;
                    self.online_peers = peers;
                    self.set_banner("Connected to CubeHash WSS blind relay.", ACCENT_EMERALD);
                }
                UiEvent::RelayConnectFailed(e) => {
                    self.relay_status = RelayStatus::Disconnected;
                    self.set_banner(format!("Relay connect failed: {e}"), ACCENT_ROSE);
                }
                UiEvent::RelayInfo(line) => {
                    self.chat_lines.push(ChatLine {
                        badge: "INFO".to_string(),
                        badge_color: ACCENT_CYAN,
                        body: line,
                    });
                }
                UiEvent::RelayStopped => {
                    self.relay_status = RelayStatus::Disconnected;
                    self.online_peers.clear();
                    self.set_banner("Disconnected from WSS relay.", ACCENT_AMBER);
                }
                UiEvent::RelayNodeEvent(nev) => self.handle_node_event(nev),
            }
        }
    }

    fn handle_node_event(&mut self, nev: NodeEvent) {
        match nev {
            NodeEvent::Registered { online_peers, .. }
            | NodeEvent::PeerListUpdated { online_peers } => {
                self.online_peers = online_peers;
            }
            NodeEvent::IncomingPairOffer {
                pair_id,
                from,
                profile,
                has_psk,
            } => {
                self.pending_offers.push(PendingOffer {
                    pair_id: pair_id.clone(),
                    from: from.clone(),
                    profile,
                    has_psk,
                });
                self.chat_lines.push(ChatLine {
                    badge: "PAIR?".to_string(),
                    badge_color: ACCENT_AMBER,
                    body: format!(
                        "Incoming PairOffer from '{from}' ({}, has_psk={has_psk})",
                        profile_label(profile)
                    ),
                });
            }
            NodeEvent::Paired {
                peer,
                safety_fingerprint,
                epoch,
            } => {
                self.pending_offers.retain(|o| o.from != peer);
                self.paired_peers.insert(
                    peer.clone(),
                    PairedPeerInfo {
                        safety_fingerprint: safety_fingerprint.clone(),
                        epoch,
                    },
                );
                if self.selected_peer.is_empty() {
                    self.selected_peer = peer.clone();
                }
                self.chat_lines.push(ChatLine {
                    badge: "PAIRED".to_string(),
                    badge_color: ACCENT_EMERALD,
                    body: format!(
                        "CubeHash E2E paired with '{peer}' | safety={safety_fingerprint} | epoch={epoch}"
                    ),
                });
            }
            NodeEvent::MessageReceived {
                from,
                msg,
                healed_bits,
                epoch,
                ..
            } => {
                let text = match msg {
                    EazyAppMessage::ChatText { text } => {
                        format!("[{from} @e{epoch} healed={healed_bits}b] {text}")
                    }
                    EazyAppMessage::FileShared {
                        filename,
                        size_bytes,
                        e2e,
                        ..
                    } => {
                        format!("[file {from}] {filename} ({}B, e2e={e2e})", size_bytes)
                    }
                    EazyAppMessage::SerialData { port, data } => {
                        format!("[serial {port} from {from}] {}", String::from_utf8_lossy(&data))
                    }
                    EazyAppMessage::HardwareProbeResponse { report } => format!(
                        "[hwprobe from {from}] host={} os={} tpm={} adapters={} vpns={}",
                        report.hostname,
                        report.os,
                        report.tpm2_cng_available,
                        report.network_adapters.len(),
                        report.vpn_adapters_detected.len()
                    ),
                    other => format!("[{from} @e{epoch}] {other:?}"),
                };
                self.chat_lines.push(ChatLine {
                    badge: "RX".to_string(),
                    badge_color: ACCENT_CYAN,
                    body: text,
                });
            }
            NodeEvent::DeliveryAcked { from, msg_id } => {
                self.chat_lines.push(ChatLine {
                    badge: "ACK".to_string(),
                    badge_color: ACCENT_EMERALD,
                    body: format!("DeliveryAck from '{from}' for {msg_id}"),
                });
            }
            NodeEvent::HoneyDecoyTriggered {
                from,
                plausible_preview,
                ..
            } => {
                self.chat_lines.push(ChatLine {
                    badge: "DECOY".to_string(),
                    badge_color: ACCENT_ROSE,
                    body: format!(
                        "Zero-oracle Honey DTE decoy against tampered packet from '{from}': {plausible_preview}"
                    ),
                });
            }
            NodeEvent::EpochHopped { peer, new_epoch } => {
                if let Some(entry) = self.paired_peers.get_mut(&peer) {
                    entry.epoch = new_epoch;
                }
                self.chat_lines.push(ChatLine {
                    badge: "HOP".to_string(),
                    badge_color: ACCENT_CYAN,
                    body: format!("X25519 epoch hopped with '{peer}' -> epoch {new_epoch}"),
                });
            }
            NodeEvent::Reconnecting { reason, attempt } => {
                self.relay_status = RelayStatus::Reconnecting {
                    attempt,
                    reason: reason.clone(),
                };
                self.chat_lines.push(ChatLine {
                    badge: "RECONN".to_string(),
                    badge_color: ACCENT_AMBER,
                    body: format!("Reconnecting (#{attempt}): {reason}"),
                });
            }
            NodeEvent::Reconnected => {
                self.relay_status = RelayStatus::Online;
                self.chat_lines.push(ChatLine {
                    badge: "ONLINE".to_string(),
                    badge_color: ACCENT_EMERALD,
                    body: "Reconnected to relay; CubeHash E2E sessions preserved.".to_string(),
                });
            }
            NodeEvent::RelayError { code, detail, .. } => {
                self.chat_lines.push(ChatLine {
                    badge: "ERR".to_string(),
                    badge_color: ACCENT_ROSE,
                    body: format!("[{code}] {detail}"),
                });
            }
            NodeEvent::Disconnected { reason } => {
                self.relay_status = RelayStatus::Disconnected;
                self.chat_lines.push(ChatLine {
                    badge: "DISC".to_string(),
                    badge_color: ACCENT_AMBER,
                    body: reason,
                });
            }
        }
    }

    // --- Background Task Launchers ------------------------------------------

    fn spawn_discover(&mut self, ctx: &egui::Context) {
        let Ok(target) = self.discovery_target.trim().parse::<SocketAddr>() else {
            self.set_banner("Invalid discovery address (expected ip:port).", ACCENT_ROSE);
            return;
        };
        self.busy_label = Some("Discovering Masters via UDP 37020...".to_string());
        let tx = self.events_tx.clone();
        let ctx = ctx.clone();
        self.rt.spawn(async move {
            let res = discover_masters(target, Duration::from_millis(1600)).await;
            let _ = tx.send(UiEvent::DiscoveryDone(res));
            ctx.request_repaint();
        });
    }

    fn spawn_health(&mut self, ctx: &egui::Context) {
        let cfg = self.current_cfg_snapshot();
        let client = match build_http_client_from_cfg(None, None, None, self.insecure_http, &cfg) {
            Ok((c, _, _)) => c,
            Err(e) => {
                self.set_banner(e, ACCENT_ROSE);
                return;
            }
        };
        self.busy_label = Some("Checking Master health...".to_string());
        let tx = self.events_tx.clone();
        let ctx = ctx.clone();
        self.rt.spawn(async move {
            let res = client.health().await;
            let _ = tx.send(UiEvent::HealthDone(res));
            ctx.request_repaint();
        });
    }

    fn spawn_enroll(&mut self, ctx: &egui::Context) {
        let cfg = self.current_cfg_snapshot();
        let cid = eazyconnect_client::resolve_client_id(Some(&self.client_id), &cfg);
        let ks = self.keystore_dir.clone();
        let (client, url, _) =
            match build_http_client_from_cfg(None, None, None, self.insecure_http, &cfg) {
                Ok(v) => v,
                Err(e) => {
                    self.set_banner(e, ACCENT_ROSE);
                    return;
                }
            };
        let invite = (!self.invite_code.trim().is_empty()).then(|| self.invite_code.trim().to_string());
        let pin = cfg.tls_pin_hex.clone();

        self.busy_label = Some(format!("Enrolling '{cid}'..."));
        let tx = self.events_tx.clone();
        let ctx = ctx.clone();
        self.rt.spawn(async move {
            let res = async {
                let id = DeviceIdentity::load_or_create(&cid, ks.as_deref(), None)?;
                client.enroll_device(&id, invite.as_deref()).await
            }
            .await;
            match res {
                Ok(tok) => {
                    let _ = tx.send(UiEvent::EnrollDone {
                        client_id: tok.client_id,
                        role: tok.role,
                        token: tok.token,
                        master_url: url,
                        tls_pin_hex: pin,
                    });
                }
                Err(e) => {
                    let _ = tx.send(UiEvent::ActionError(format!("Enroll failed: {e}")));
                }
            }
            ctx.request_repaint();
        });
    }

    fn spawn_login(&mut self, ctx: &egui::Context) {
        if self.username.trim().is_empty() || self.password.is_empty() {
            self.set_banner("Enter username and password to log in.", ACCENT_AMBER);
            return;
        }
        let cfg = self.current_cfg_snapshot();
        let (client, url, _) =
            match build_http_client_from_cfg(None, None, None, self.insecure_http, &cfg) {
                Ok(v) => v,
                Err(e) => {
                    self.set_banner(e, ACCENT_ROSE);
                    return;
                }
            };
        let user = self.username.trim().to_string();
        let pass = self.password.clone();
        self.busy_label = Some(format!("Logging in '{user}'..."));
        let tx = self.events_tx.clone();
        let ctx = ctx.clone();
        self.rt.spawn(async move {
            match client.login_password(&user, &pass).await {
                Ok(tok) => {
                    let _ = tx.send(UiEvent::LoginDone {
                        username: user,
                        role: tok.role,
                        token: tok.token,
                        master_url: url,
                    });
                }
                Err(e) => {
                    let _ = tx.send(UiEvent::ActionError(format!("Login failed: {e}")));
                }
            }
            ctx.request_repaint();
        });
    }

    fn spawn_create_user(&mut self, ctx: &egui::Context) {
        let cfg = self.current_cfg_snapshot();
        let cid = eazyconnect_client::resolve_client_id(Some(&self.client_id), &cfg);
        let token = match load_bearer_token(&cid, &self.loaded_cfg) {
            Ok(t) => t,
            Err(e) => {
                self.set_banner(e, ACCENT_ROSE);
                return;
            }
        };
        let (client, _, _) =
            match build_http_client_from_cfg(None, None, None, self.insecure_http, &cfg) {
                Ok(v) => v,
                Err(e) => {
                    self.set_banner(e, ACCENT_ROSE);
                    return;
                }
            };
        let uname = self.new_user_name.trim().to_string();
        let upass = self.new_user_pass.clone();
        let is_admin = self.new_user_admin;
        if uname.is_empty() || upass.len() < 8 {
            self.set_banner("New username must be non-empty and password >= 8 chars.", ACCENT_AMBER);
            return;
        }
        self.busy_label = Some(format!("Creating user '{uname}'..."));
        let tx = self.events_tx.clone();
        let ctx = ctx.clone();
        self.rt.spawn(async move {
            match client
                .create_user(
                    &token,
                    &CreateUserRequest {
                        username: uname.clone(),
                        password: upass,
                        is_admin,
                    },
                )
                .await
            {
                Ok(_) => {
                    let _ = tx.send(UiEvent::UserCreated(format!(
                        "Created user '{uname}' (admin={is_admin})."
                    )));
                }
                Err(e) => {
                    let _ = tx.send(UiEvent::ActionError(format!("Create user failed: {e}")));
                }
            }
            ctx.request_repaint();
        });
    }

    fn spawn_upload(&mut self, ctx: &egui::Context) {
        let local = PathBuf::from(self.upload_local_path.trim());
        if !local.is_file() {
            self.set_banner("Choose a valid local file to upload.", ACCENT_AMBER);
            return;
        }
        let rel = if self.upload_remote_path.trim().is_empty() {
            local
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("upload.bin")
                .to_string()
        } else {
            self.upload_remote_path.trim().to_string()
        };
        let cfg = self.current_cfg_snapshot();
        let cid = eazyconnect_client::resolve_client_id(Some(&self.client_id), &cfg);
        let token = match load_bearer_token(&cid, &self.loaded_cfg) {
            Ok(t) => t,
            Err(e) => {
                self.set_banner(e, ACCENT_ROSE);
                return;
            }
        };
        let (client, _, _) =
            match build_http_client_from_cfg(None, None, None, self.insecure_http, &cfg) {
                Ok(v) => v,
                Err(e) => {
                    self.set_banner(e, ACCENT_ROSE);
                    return;
                }
            };
        let e2e = self.files_e2e;
        let vault_hex = self.vault_key_hex.clone();
        let cfg_path = self.config_path.clone();
        let ks = self.keystore_dir.clone();

        self.busy_label = Some(format!("Uploading '{rel}'..."));
        let tx = self.events_tx.clone();
        let ctx = ctx.clone();
        self.rt.spawn(async move {
            let res = async {
                let plain =
                    fs::read(&local).map_err(|e| format!("failed to read {}: {e}", local.display()))?;
                let payload = if e2e {
                    let id = DeviceIdentity::load_or_create(&cid, ks.as_deref(), None)?;
                    let vkey = load_or_create_vault_key(
                        cfg_path.as_deref(),
                        &cid,
                        (!vault_hex.trim().is_empty()).then_some(vault_hex.trim()),
                    )?;
                    encrypt_file_for_vault(id.hardware_provider(), &vkey, &rel, &plain)?
                } else {
                    plain
                };
                client.upload_bytes(&token, &rel, &payload, e2e).await
            }
            .await;
            match res {
                Ok(entry) => {
                    let _ = tx.send(UiEvent::UploadDone(entry));
                }
                Err(e) => {
                    let _ = tx.send(UiEvent::ActionError(format!("Upload failed: {e}")));
                }
            }
            ctx.request_repaint();
        });
    }

    fn spawn_sync_folder(&mut self, ctx: &egui::Context) {
        let folder = PathBuf::from(self.sync_folder_path.trim());
        if !folder.is_dir() {
            self.set_banner("Select an existing local folder to sync.", ACCENT_AMBER);
            return;
        }
        let cfg = self.current_cfg_snapshot();
        let cid = eazyconnect_client::resolve_client_id(Some(&self.client_id), &cfg);
        let token = match load_bearer_token(&cid, &self.loaded_cfg) {
            Ok(t) => t,
            Err(e) => {
                self.set_banner(e, ACCENT_ROSE);
                return;
            }
        };
        let (client, _, _) =
            match build_http_client_from_cfg(None, None, None, self.insecure_http, &cfg) {
                Ok(v) => v,
                Err(e) => {
                    self.set_banner(e, ACCENT_ROSE);
                    return;
                }
            };
        let e2e = self.files_e2e;
        let vault_hex = self.vault_key_hex.clone();
        let cfg_path = self.config_path.clone();
        let ks = self.keystore_dir.clone();
        let manifest_path = default_sync_manifest_path(cfg_path.as_deref());

        self.busy_label = Some("Syncing folder delta...".to_string());
        let tx = self.events_tx.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let res = (|| -> Result<SyncRunSummary, String> {
                let local_rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| e.to_string())?;
                local_rt.block_on(async {
                    if e2e {
                        let id = DeviceIdentity::load_or_create(&cid, ks.as_deref(), None)?;
                        let vkey = load_or_create_vault_key(
                            cfg_path.as_deref(),
                            &cid,
                            (!vault_hex.trim().is_empty()).then_some(vault_hex.trim()),
                        )?;
                        sync_folder_to_master(
                            &client,
                            &token,
                            &folder,
                            &manifest_path,
                            Some((id.hardware_provider(), &vkey)),
                        )
                        .await
                    } else {
                        sync_folder_to_master(&client, &token, &folder, &manifest_path, None).await
                    }
                })
            })();
            match res {
                Ok(s) => {
                    let _ = tx.send(UiEvent::SyncDone(s));
                }
                Err(e) => {
                    let _ = tx.send(UiEvent::ActionError(format!("Folder sync failed: {e}")));
                }
            }
            ctx.request_repaint();
        });
    }

    fn spawn_list_files(&mut self, ctx: &egui::Context) {
        let cfg = self.current_cfg_snapshot();
        let cid = eazyconnect_client::resolve_client_id(Some(&self.client_id), &cfg);
        let token = match load_bearer_token(&cid, &self.loaded_cfg) {
            Ok(t) => t,
            Err(e) => {
                self.set_banner(e, ACCENT_ROSE);
                return;
            }
        };
        let (client, _, _) =
            match build_http_client_from_cfg(None, None, None, self.insecure_http, &cfg) {
                Ok(v) => v,
                Err(e) => {
                    self.set_banner(e, ACCENT_ROSE);
                    return;
                }
            };
        let owner = (!self.owner_filter.trim().is_empty()).then(|| self.owner_filter.trim().to_string());
        self.busy_label = Some("Refreshing file list...".to_string());
        let tx = self.events_tx.clone();
        let ctx = ctx.clone();
        self.rt.spawn(async move {
            match client.list_files(&token, owner.as_deref()).await {
                Ok(res) => {
                    let _ = tx.send(UiEvent::FilesListed {
                        owner: res.owner,
                        files: res.files,
                    });
                }
                Err(e) => {
                    let _ = tx.send(UiEvent::ActionError(format!("List failed: {e}")));
                }
            }
            ctx.request_repaint();
        });
    }

    fn spawn_download_file(&mut self, ctx: &egui::Context, file: ServerFileEntry, dest: PathBuf) {
        let cfg = self.current_cfg_snapshot();
        let cid = eazyconnect_client::resolve_client_id(Some(&self.client_id), &cfg);
        let token = match load_bearer_token(&cid, &self.loaded_cfg) {
            Ok(t) => t,
            Err(e) => {
                self.set_banner(e, ACCENT_ROSE);
                return;
            }
        };
        let (client, _, _) =
            match build_http_client_from_cfg(None, None, None, self.insecure_http, &cfg) {
                Ok(v) => v,
                Err(e) => {
                    self.set_banner(e, ACCENT_ROSE);
                    return;
                }
            };
        let owner = if !self.owner_filter.trim().is_empty() {
            self.owner_filter.trim().to_string()
        } else {
            self.loaded_cfg
                .username
                .clone()
                .unwrap_or_else(|| cid.clone())
        };
        let force_e2e = self.files_e2e || file.e2e_encrypted;
        let vault_hex = self.vault_key_hex.clone();
        let cfg_path = self.config_path.clone();
        let ks = self.keystore_dir.clone();
        let remote = file.filename;

        self.busy_label = Some(format!("Downloading '{remote}'..."));
        let tx = self.events_tx.clone();
        let ctx = ctx.clone();
        self.rt.spawn(async move {
            let res = async {
                let (raw, _hash, server_e2e) = client.download_bytes(&token, &owner, &remote).await?;
                let use_e2e = force_e2e || server_e2e;
                let final_bytes = if use_e2e {
                    let id = DeviceIdentity::load_or_create(&cid, ks.as_deref(), None)?;
                    let vkey = load_or_create_vault_key(
                        cfg_path.as_deref(),
                        &cid,
                        (!vault_hex.trim().is_empty()).then_some(vault_hex.trim()),
                    )?;
                    decrypt_file_from_vault(id.hardware_provider(), &vkey, &remote, &raw)?
                } else {
                    raw
                };
                if let Some(parent) = dest.parent() {
                    if !parent.as_os_str().is_empty() {
                        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
                    }
                }
                fs::write(&dest, &final_bytes)
                    .map_err(|e| format!("failed to write {}: {e}", dest.display()))?;
                Ok::<_, String>((final_bytes.len(), use_e2e))
            }
            .await;
            match res {
                Ok((bytes, e2e)) => {
                    let _ = tx.send(UiEvent::DownloadDone {
                        remote,
                        dest: dest.display().to_string(),
                        bytes,
                        e2e,
                    });
                }
                Err(e) => {
                    let _ = tx.send(UiEvent::ActionError(format!("Download failed: {e}")));
                }
            }
            ctx.request_repaint();
        });
    }

    fn spawn_delete_file(&mut self, ctx: &egui::Context, rel: String) {
        let cfg = self.current_cfg_snapshot();
        let cid = eazyconnect_client::resolve_client_id(Some(&self.client_id), &cfg);
        let token = match load_bearer_token(&cid, &self.loaded_cfg) {
            Ok(t) => t,
            Err(e) => {
                self.set_banner(e, ACCENT_ROSE);
                return;
            }
        };
        let (client, _, _) =
            match build_http_client_from_cfg(None, None, None, self.insecure_http, &cfg) {
                Ok(v) => v,
                Err(e) => {
                    self.set_banner(e, ACCENT_ROSE);
                    return;
                }
            };
        self.busy_label = Some(format!("Deleting '{rel}'..."));
        let tx = self.events_tx.clone();
        let ctx = ctx.clone();
        self.rt.spawn(async move {
            match client.delete_file(&token, &rel).await {
                Ok(()) => {
                    let _ = tx.send(UiEvent::DeleteDone(rel));
                }
                Err(e) => {
                    let _ = tx.send(UiEvent::ActionError(format!("Delete failed: {e}")));
                }
            }
            ctx.request_repaint();
        });
    }

    fn spawn_refresh_hardware(&mut self, ctx: &egui::Context) {
        let tx = self.events_tx.clone();
        let ctx = ctx.clone();
        self.rt.spawn(async move {
            if let Ok(rep) = tokio::task::spawn_blocking(collect_hardware_report).await {
                let _ = tx.send(UiEvent::HardwareDone(rep));
                ctx.request_repaint();
            }
        });
    }

    fn spawn_serial_send(&mut self, ctx: &egui::Context) {
        let port = self.serial_port.trim().to_string();
        let Ok(baud) = self.serial_baud.trim().parse::<u32>() else {
            self.set_banner("Invalid serial baud rate.", ACCENT_ROSE);
            return;
        };
        let bytes = if self.serial_hex_mode {
            match hex::decode(self.serial_payload.trim().replace(' ', "")) {
                Ok(b) => b,
                Err(e) => {
                    self.set_banner(format!("Invalid hex payload: {e}"), ACCENT_ROSE);
                    return;
                }
            }
        } else {
            self.serial_payload.as_bytes().to_vec()
        };
        if port.is_empty() {
            self.set_banner("Specify a COM/serial port (e.g. COM4).", ACCENT_AMBER);
            return;
        }

        self.busy_label = Some(format!("Sending serial command to {port}..."));
        let tx = self.events_tx.clone();
        let ctx = ctx.clone();
        self.rt.spawn(async move {
            let res = tokio::task::spawn_blocking(move || {
                send_serial_command(&port, baud, &bytes, 600)
            })
            .await
            .map_err(|e| e.to_string())
            .and_then(|r| r);
            let _ = tx.send(UiEvent::SerialDone(res));
            ctx.request_repaint();
        });
    }

    fn spawn_diagnostics(&mut self, ctx: &egui::Context, upload: bool) {
        let cfg = self.current_cfg_snapshot();
        let cid = eazyconnect_client::resolve_client_id(Some(&self.client_id), &cfg);
        let probe = build_http_client_from_cfg(None, None, None, self.insecure_http, &cfg)
            .ok()
            .map(|(c, _, _)| c);
        let token = if upload {
            match load_bearer_token(&cid, &self.loaded_cfg) {
                Ok(t) => Some(t),
                Err(e) => {
                    self.set_banner(e, ACCENT_ROSE);
                    return;
                }
            }
        } else {
            None
        };
        let cfg_path = self.config_path.clone();
        let master_override = (!self.master_url.trim().is_empty()).then(|| self.master_url.trim().to_string());

        self.busy_label = Some("Running hardware + UDP + TLS diagnostics...".to_string());
        let tx = self.events_tx.clone();
        let ctx = ctx.clone();
        self.rt.spawn(async move {
            let res = async {
                let report = run_diagnostics(
                    cfg_path.as_deref(),
                    master_override.as_deref(),
                    Duration::from_millis(1200),
                    probe.as_ref(),
                )
                .await?;
                let upload_msg = if let (Some(c), Some(tok)) = (probe, token) {
                    let val = serde_json::to_value(&report).map_err(|e| e.to_string())?;
                    Some(c.send_report(&tok, &val).await?.to_string())
                } else {
                    None
                };
                Ok::<_, String>((report, upload_msg))
            }
            .await;
            let _ = tx.send(UiEvent::DiagDone(res));
            ctx.request_repaint();
        });
    }

    fn spawn_relay_connect(&mut self, ctx: &egui::Context) {
        let cfg = self.current_cfg_snapshot();
        let cid = eazyconnect_client::resolve_client_id(Some(&self.client_id), &cfg);
        let (_, url, tls_config) =
            match build_http_client_from_cfg(None, None, None, self.insecure_http, &cfg) {
                Ok(v) => v,
                Err(e) => {
                    self.set_banner(e, ACCENT_ROSE);
                    return;
                }
            };
        let ks = self.keystore_dir.clone();
        let allow_insecure_ws = self.insecure_http;
        let node_slot = Arc::clone(&self.active_node);
        let tx = self.events_tx.clone();
        let ctx = ctx.clone();

        self.relay_status = RelayStatus::Connecting;
        self.rt.spawn(async move {
            if let Some(old) = node_slot.lock().await.take() {
                old.shutdown().await;
            }
            let res = async {
                let id = DeviceIdentity::load_or_create(&cid, ks.as_deref(), None)?;
                EazyNode::connect(
                    id,
                    NodeConnectOptions {
                        ws_url: url,
                        tls_config,
                        allow_insecure_ws,
                        allow_remote_serial_os_fallback: false,
                        allow_remote_hw_probe: true,
                        auto_reconnect: true,
                    },
                )
                .await
            }
            .await;

            match res {
                Ok(node) => {
                    let mut rx = node.subscribe();
                    let peers = node.online_peers().await.unwrap_or_default();
                    *node_slot.lock().await = Some(node);
                    let _ = tx.send(UiEvent::RelayConnected(peers));
                    ctx.request_repaint();

                    let tx_ev = tx.clone();
                    let ctx_ev = ctx.clone();
                    tokio::spawn(async move {
                        loop {
                            match rx.recv().await {
                                Ok(ev) => {
                                    let done = matches!(ev, NodeEvent::Disconnected { .. });
                                    let _ = tx_ev.send(UiEvent::RelayNodeEvent(ev));
                                    ctx_ev.request_repaint();
                                    if done {
                                        break;
                                    }
                                }
                                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                                Err(_) => break,
                            }
                        }
                    });
                }
                Err(e) => {
                    let _ = tx.send(UiEvent::RelayConnectFailed(e));
                    ctx.request_repaint();
                }
            }
        });
    }

    fn spawn_relay_disconnect(&mut self, ctx: &egui::Context) {
        let node_slot = Arc::clone(&self.active_node);
        let tx = self.events_tx.clone();
        let ctx = ctx.clone();
        self.rt.spawn(async move {
            if let Some(node) = node_slot.lock().await.take() {
                node.shutdown().await;
            }
            let _ = tx.send(UiEvent::RelayStopped);
            ctx.request_repaint();
        });
    }

    fn spawn_pair_offer(&mut self, ctx: &egui::Context, peer: String) {
        let node_slot = Arc::clone(&self.active_node);
        let profile = self.pair_profile;
        let psk = self.chat_psk.as_bytes().to_vec();
        let tx = self.events_tx.clone();
        let ctx = ctx.clone();
        self.rt.spawn(async move {
            let guard = node_slot.lock().await;
            let Some(node) = guard.as_ref() else {
                let _ = tx.send(UiEvent::ActionError("Connect to relay first.".to_string()));
                ctx.request_repaint();
                return;
            };
            match node.send_pair_offer(&peer, profile, &psk).await {
                Ok(pid) => {
                    let _ = tx.send(UiEvent::RelayInfo(format!(
                        "Sent PairOffer ({pid}) to '{peer}'."
                    )));
                }
                Err(e) => {
                    let _ = tx.send(UiEvent::ActionError(format!("PairOffer failed: {e}")));
                }
            }
            ctx.request_repaint();
        });
    }

    fn spawn_accept_offer(&mut self, ctx: &egui::Context, offer: PendingOffer) {
        let node_slot = Arc::clone(&self.active_node);
        let psk = self.chat_psk.as_bytes().to_vec();
        let tx = self.events_tx.clone();
        let ctx = ctx.clone();
        self.rt.spawn(async move {
            let guard = node_slot.lock().await;
            let Some(node) = guard.as_ref() else {
                return;
            };
            if let Err(e) = node.accept_pair_offer(&offer.pair_id, &psk).await {
                let _ = tx.send(UiEvent::ActionError(format!("AcceptPair failed: {e}")));
            }
            ctx.request_repaint();
        });
    }

    fn spawn_send_chat(&mut self, ctx: &egui::Context) {
        let peer = self.selected_peer.trim().to_string();
        let text = self.chat_input.trim().to_string();
        if peer.is_empty() || text.is_empty() {
            return;
        }
        self.chat_input.clear();
        self.chat_lines.push(ChatLine {
            badge: "TX".to_string(),
            badge_color: ACCENT_EMERALD,
            body: format!("[to {peer}] {text}"),
        });

        let node_slot = Arc::clone(&self.active_node);
        let tx = self.events_tx.clone();
        let ctx = ctx.clone();
        self.rt.spawn(async move {
            let guard = node_slot.lock().await;
            let Some(node) = guard.as_ref() else {
                let _ = tx.send(UiEvent::ActionError("Connect & pair first.".to_string()));
                ctx.request_repaint();
                return;
            };
            if let Err(e) = node
                .send_app_message(&peer, EazyAppMessage::ChatText { text })
                .await
            {
                let _ = tx.send(UiEvent::ActionError(format!("Send failed: {e}")));
            }
            ctx.request_repaint();
        });
    }

    fn spawn_peer_utility(&mut self, ctx: &egui::Context, peer: String, op: &'static str) {
        let node_slot = Arc::clone(&self.active_node);
        let tx = self.events_tx.clone();
        let ctx = ctx.clone();
        self.rt.spawn(async move {
            let guard = node_slot.lock().await;
            let Some(node) = guard.as_ref() else {
                let _ = tx.send(UiEvent::ActionError("Relay not connected.".to_string()));
                ctx.request_repaint();
                return;
            };
            let res: Result<(), String> = match op {
                "hop" => node.hop_epoch(&peer).await.map(|_| ()),
                "hwprobe" => node.request_remote_hardware_probe(&peer).await.map(|_| ()),
                "tamper" => node.send_tampered_probe(&peer).await.map(|_| {
                    let _ = tx.send(UiEvent::RelayInfo(format!(
                        "Sent tampered frame to '{peer}' to exercise constant-work DTE decoy."
                    )));
                }),
                _ => Ok(()),
            };
            if let Err(e) = res {
                let _ = tx.send(UiEvent::ActionError(format!("{op} failed: {e}")));
            }
            ctx.request_repaint();
        });
    }

    // --- UI Rendering -------------------------------------------------------

    fn render_top_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(
                RichText::new("EazyConnect")
                    .size(20.0)
                    .strong()
                    .color(ACCENT_CYAN),
            );
            ui.label(RichText::new("Native Control Center").size(13.0).color(TEXT_MUTED));
            ui.add_space(12.0);

            if let Some(ref hw) = self.hardware {
                if hw.vpn_adapters_detected.is_empty() {
                    status_pill(ui, "LAN Direct", ACCENT_EMERALD);
                } else {
                    status_pill(
                        ui,
                        &format!("VPN: {}", hw.vpn_adapters_detected.join(", ")),
                        ACCENT_AMBER,
                    );
                }
            }

            match &self.relay_status {
                RelayStatus::Disconnected => status_pill(ui, "Relay: Offline", TEXT_MUTED),
                RelayStatus::Connecting => status_pill(ui, "Relay: Connecting...", ACCENT_CYAN),
                RelayStatus::Online => status_pill(ui, "Relay: WSS Online", ACCENT_EMERALD),
                RelayStatus::Reconnecting { attempt, .. } => status_pill(
                    ui,
                    &format!("Relay: Reconnecting #{attempt}"),
                    ACCENT_AMBER,
                ),
            }

            if !self.tls_pin_hex.trim().is_empty() {
                let p = self.tls_pin_hex.trim();
                status_pill(ui, &format!("Pin: {}..", &p[..8.min(p.len())]), ACCENT_CYAN);
            }
        });

        ui.add_space(8.0);
        ui.horizontal_wrapped(|ui| {
            let tabs = [
                (ActiveTab::Connect, "Connect & Discover"),
                (ActiveTab::Files, "Files & E2E Vault"),
                (ActiveTab::Chat, "CubeHash Chat"),
                (ActiveTab::Hardware, "Hardware & Serial"),
                (ActiveTab::Diagnostics, "Diagnostics"),
                (ActiveTab::Profile, "Profile"),
            ];
            for (tab, label) in tabs {
                let selected = self.active_tab == tab;
                if ui.selectable_label(selected, RichText::new(label).size(13.5)).clicked() {
                    self.active_tab = tab;
                }
            }
        });
    }

    fn render_connect_tab(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        card_frame().show(ui, |ui| {
            section_heading(
                ui,
                "UDP 37020 Master Discovery (Ed25519 Verified)",
                "Finds LAN Masters past Exit VPNs via per-NIC directed broadcasts, or queries a Mesh VPN IP directly.",
            );
            ui.horizontal(|ui| {
                ui.label("Target IP:Port");
                ui.add(egui::TextEdit::singleline(&mut self.discovery_target).desired_width(220.0));
                if ui.button("Discover Masters").clicked() {
                    self.spawn_discover(&ctx);
                }
            });

            if !self.discovered_masters.is_empty() {
                ui.add_space(8.0);
                let discovered = self.discovered_masters.clone();
                for m in discovered {
                    ui.horizontal_wrapped(|ui| {
                        let sig_color = if m.signature_valid {
                            ACCENT_EMERALD
                        } else {
                            ACCENT_ROSE
                        };
                        status_pill(
                            ui,
                            if m.signature_valid { "SIG OK" } else { "BAD SIG" },
                            sig_color,
                        );
                        ui.label(RichText::new(&m.url).strong().color(TEXT_PRIMARY));
                        if ui.button("Use URL").clicked() {
                            apply_discovered_master(
                                &m,
                                &m.url,
                                &mut self.master_url,
                                &mut self.tls_pin_hex,
                                &mut self.insecure_http,
                            );
                            self.set_banner(
                                format!("Selected {} + TLS pin.", m.url),
                                ACCENT_CYAN,
                            );
                        }
                        for alt in &m.alternate_urls {
                            if ui.button(format!("Alt: {alt}")).clicked() {
                                apply_discovered_master(
                                    &m,
                                    alt,
                                    &mut self.master_url,
                                    &mut self.tls_pin_hex,
                                    &mut self.insecure_http,
                                );
                                self.set_banner(format!("Selected alternate {alt}."), ACCENT_CYAN);
                            }
                        }
                    });
                }
            }
        });

        ui.add_space(10.0);

        ui.columns(2, |cols| {
            card_frame().show(&mut cols[0], |ui| {
                section_heading(
                    ui,
                    "Master Connection & Enrollment",
                    "Ed25519 identity keys and tokens are sealed natively with Windows DPAPI.",
                );
                egui::Grid::new("conn_grid")
                    .num_columns(2)
                    .spacing([10.0, 8.0])
                    .show(ui, |ui| {
                        ui.label("Master URL:");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.master_url)
                                .hint_text("https://192.168.1.50:8000")
                                .desired_width(280.0),
                        );
                        ui.end_row();

                        ui.label("TLS SHA-256 Pin:");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.tls_pin_hex)
                                .hint_text("64 hex fingerprint")
                                .desired_width(280.0),
                        );
                        ui.end_row();

                        ui.label("CA PEM (optional):");
                        ui.horizontal(|ui| {
                            ui.add(
                                egui::TextEdit::singleline(&mut self.tls_ca_pem_path)
                                    .desired_width(210.0),
                            );
                            if ui.button("Browse").clicked() {
                                if let Some(p) = rfd::FileDialog::new()
                                    .add_filter("PEM", &["pem", "crt"])
                                    .pick_file()
                                {
                                    self.tls_ca_pem_path = p.display().to_string();
                                }
                            }
                        });
                        ui.end_row();

                        ui.label("Client ID:");
                        ui.add(egui::TextEdit::singleline(&mut self.client_id).desired_width(280.0));
                        ui.end_row();

                        ui.label("Invite Code:");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.invite_code)
                                .hint_text("Required when Master uses --invite-code")
                                .desired_width(280.0),
                        );
                        ui.end_row();
                    });

                ui.add_space(4.0);
                ui.checkbox(
                    &mut self.insecure_http,
                    "Allow insecure HTTP/WS (local lab testing only)",
                );
                ui.add_space(8.0);
                ui.horizontal_wrapped(|ui| {
                    if ui.button("Save Config").clicked() {
                        match self.persist_current_cfg() {
                            Ok(p) => self.set_banner(
                                format!("Saved settings to {}", p.display()),
                                ACCENT_EMERALD,
                            ),
                            Err(e) => self.set_banner(e, ACCENT_ROSE),
                        }
                    }
                    if ui.button("Check Health").clicked() {
                        self.spawn_health(&ctx);
                    }
                    if ui.button("Enroll Device").clicked() {
                        self.spawn_enroll(&ctx);
                    }
                });
            });

            card_frame().show(&mut cols[1], |ui| {
                section_heading(
                    ui,
                    "User Account Login & Provisioning",
                    "Use bootstrap admin credentials from bootstrap-admin.txt to create accounts.",
                );
                egui::Grid::new("login_grid")
                    .num_columns(2)
                    .spacing([10.0, 8.0])
                    .show(ui, |ui| {
                        ui.label("Username:");
                        ui.add(egui::TextEdit::singleline(&mut self.username).desired_width(220.0));
                        ui.end_row();

                        ui.label("Password:");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.password)
                                .password(true)
                                .desired_width(220.0),
                        );
                        ui.end_row();
                    });
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui.button("Login User").clicked() {
                        self.spawn_login(&ctx);
                    }
                    status_pill(
                        ui,
                        if self.has_sealed_token {
                            "DPAPI Token Present"
                        } else {
                            "No Token Yet"
                        },
                        if self.has_sealed_token {
                            ACCENT_EMERALD
                        } else {
                            TEXT_MUTED
                        },
                    );
                });

                ui.add_space(12.0);
                ui.separator();
                ui.add_space(8.0);
                ui.label(RichText::new("Admin: Create User").strong().color(TEXT_PRIMARY));
                egui::Grid::new("create_user_grid")
                    .num_columns(2)
                    .spacing([10.0, 6.0])
                    .show(ui, |ui| {
                        ui.label("New Username:");
                        ui.add(egui::TextEdit::singleline(&mut self.new_user_name).desired_width(200.0));
                        ui.end_row();

                        ui.label("New Password:");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.new_user_pass)
                                .password(true)
                                .hint_text("Min 8 chars")
                                .desired_width(200.0),
                        );
                        ui.end_row();
                    });
                ui.horizontal(|ui| {
                    ui.checkbox(&mut self.new_user_admin, "Admin privileges");
                    if ui.button("Create User").clicked() {
                        self.spawn_create_user(&ctx);
                    }
                });
            });
        });
    }

    fn render_files_tab(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        ui.columns(2, |cols| {
            card_frame().show(&mut cols[0], |ui| {
                section_heading(
                    ui,
                    "Upload Single File",
                    "With E2E checked, files are sealed client-side (EZV1 / XChaCha20-Poly1305) before leaving this PC.",
                );
                ui.horizontal(|ui| {
                    ui.label("Local file:");
                    ui.add(egui::TextEdit::singleline(&mut self.upload_local_path).desired_width(230.0));
                    if ui.button("Browse").clicked() {
                        if let Some(p) = rfd::FileDialog::new().pick_file() {
                            self.upload_local_path = p.display().to_string();
                        }
                    }
                });
                ui.horizontal(|ui| {
                    ui.label("Remote name:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.upload_remote_path)
                            .hint_text("Optional relative path")
                            .desired_width(220.0),
                    );
                    if ui.button("Upload").clicked() {
                        self.spawn_upload(&ctx);
                    }
                });
            });

            card_frame().show(&mut cols[1], |ui| {
                section_heading(
                    ui,
                    "Incremental BLAKE3 Folder Sync",
                    "Only uploads files changed since sync-manifest.json.",
                );
                ui.horizontal(|ui| {
                    ui.label("Folder:");
                    ui.add(egui::TextEdit::singleline(&mut self.sync_folder_path).desired_width(230.0));
                    if ui.button("Browse").clicked() {
                        if let Some(p) = rfd::FileDialog::new().pick_folder() {
                            self.sync_folder_path = p.display().to_string();
                        }
                    }
                });
                ui.horizontal(|ui| {
                    if ui.button("Sync Folder").clicked() {
                        self.spawn_sync_folder(&ctx);
                    }
                    ui.checkbox(&mut self.files_e2e, "E2E Vault Encrypt (EZV1)");
                });
                if !self.last_sync_summary.is_empty() {
                    ui.add_space(4.0);
                    ui.label(RichText::new(&self.last_sync_summary).size(12.0).color(ACCENT_CYAN));
                }
            });
        });

        ui.add_space(8.0);
        card_frame().show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label("Vault Key Hex (optional 64-hex shared override):");
                ui.add(
                    egui::TextEdit::singleline(&mut self.vault_key_hex)
                        .hint_text("Leave blank to use DPAPI-sealed vault.key.sealed")
                        .desired_width(360.0),
                );
            });
        });

        ui.add_space(10.0);
        card_frame().show(ui, |ui| {
            section_heading(
                ui,
                "Master File Repository",
                "Downloads verify X-Eazy-Blake3 automatically and decrypt EZV1 envelopes locally.",
            );
            ui.horizontal(|ui| {
                ui.label("Owner filter:");
                ui.add(egui::TextEdit::singleline(&mut self.owner_filter).desired_width(180.0));
                if ui.button("Refresh List").clicked() {
                    self.spawn_list_files(&ctx);
                }
            });
            ui.add_space(8.0);

            egui::ScrollArea::vertical().max_height(260.0).show(ui, |ui| {
                let files = self.remote_files.clone();
                if files.is_empty() {
                    ui.label(RichText::new("No files loaded yet — click Refresh List.").color(TEXT_MUTED));
                }
                for file in files {
                    ui.horizontal(|ui| {
                        if file.e2e_encrypted {
                            status_pill(ui, "E2E", ACCENT_EMERALD);
                        } else {
                            status_pill(ui, "PLAIN", ACCENT_AMBER);
                        }
                        ui.label(RichText::new(&file.filename).strong());
                        ui.label(RichText::new(format_bytes(file.size_bytes)).color(TEXT_MUTED));
                        ui.label(
                            RichText::new(format!("b3:{}..", &file.blake3_hex[..10.min(file.blake3_hex.len())]))
                                .size(11.5)
                                .color(TEXT_MUTED),
                        );
                        if ui.button("Download").clicked() {
                            let suggested = Path::new(&file.filename)
                                .file_name()
                                .and_then(|s| s.to_str())
                                .unwrap_or("download.bin");
                            if let Some(dest) =
                                rfd::FileDialog::new().set_file_name(suggested).save_file()
                            {
                                self.spawn_download_file(&ctx, file.clone(), dest);
                            }
                        }
                        if ui.button("Delete").clicked() {
                            self.spawn_delete_file(&ctx, file.filename.clone());
                        }
                    });
                }
            });
        });
    }

    fn render_chat_tab(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        card_frame().show(ui, |ui| {
            section_heading(
                ui,
                "CubeHash Zero-Knowledge WSS Relay",
                "Uses Ed25519 auth, 20s heartbeats, session reclaim across VPN drops, and 256B bucket padding.",
            );
            ui.horizontal_wrapped(|ui| {
                match self.relay_status {
                    RelayStatus::Disconnected => {
                        if ui.button("Connect Relay").clicked() {
                            self.spawn_relay_connect(&ctx);
                        }
                    }
                    RelayStatus::Connecting => {
                        ui.add_enabled(false, egui::Button::new("Connecting..."));
                    }
                    RelayStatus::Online | RelayStatus::Reconnecting { .. } => {
                        if ui.button("Disconnect Relay").clicked() {
                            self.spawn_relay_disconnect(&ctx);
                        }
                    }
                }

                ui.label("Mesh Profile:");
                egui::ComboBox::from_id_salt("mesh_profile")
                    .selected_text(profile_label(self.pair_profile))
                    .show_ui(ui, |ui| {
                        for prof in [
                            EazyMeshProfile::Standard,
                            EazyMeshProfile::Compact,
                            EazyMeshProfile::HighCapacity,
                        ] {
                            ui.selectable_value(&mut self.pair_profile, prof, profile_label(prof));
                        }
                    });

                ui.label("PSK:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.chat_psk)
                        .password(true)
                        .hint_text("Optional shared secret")
                        .desired_width(150.0),
                );
            });
        });

        if !self.pending_offers.is_empty() {
            ui.add_space(8.0);
            card_frame().show(ui, |ui| {
                ui.label(RichText::new("Incoming Pair Offers").strong().color(ACCENT_AMBER));
                let offers = self.pending_offers.clone();
                for offer in offers {
                    ui.horizontal(|ui| {
                        ui.label(format!(
                            "From '{}' ({}, psk={})",
                            offer.from,
                            profile_label(offer.profile),
                            offer.has_psk
                        ));
                        if ui.button("Accept & Pair").clicked() {
                            self.spawn_accept_offer(&ctx, offer);
                        }
                    });
                }
            });
        }

        ui.add_space(10.0);
        ui.columns(2, |cols| {
            card_frame().show(&mut cols[0], |ui| {
                section_heading(ui, "Online & Paired Peers", "");
                let my_id = self.client_id.trim().to_string();
                let peers = self.online_peers.clone();
                if peers.is_empty() {
                    ui.label(RichText::new("No peers reported online yet.").color(TEXT_MUTED));
                } else {
                    for peer in peers {
                        if peer.client_id == my_id {
                            continue;
                        }
                        ui.horizontal(|ui| {
                            let is_sel = self.selected_peer == peer.client_id;
                            if ui.selectable_label(is_sel, &peer.client_id).clicked() {
                                self.selected_peer = peer.client_id.clone();
                            }
                            if let Some(info) = sort_paired_label(&self.paired_peers, &peer.client_id) {
                                status_pill(ui, &info, ACCENT_EMERALD);
                            } else if ui.button("Pair").clicked() {
                                self.selected_peer = peer.client_id.clone();
                                self.spawn_pair_offer(&ctx, peer.client_id);
                            }
                        });
                    }
                }
            });

            card_frame().show(&mut cols[1], |ui| {
                ui.horizontal_wrapped(|ui| {
                    let target = if self.selected_peer.is_empty() {
                        "<select a peer>"
                    } else {
                        self.selected_peer.as_str()
                    };
                    ui.label(RichText::new(format!("Session: {target}")).strong());
                    if !self.selected_peer.is_empty() {
                        let p = self.selected_peer.clone();
                        if ui.button("/hop Epoch").clicked() {
                            self.spawn_peer_utility(&ctx, p.clone(), "hop");
                        }
                        if ui.button("/hwprobe").clicked() {
                            self.spawn_peer_utility(&ctx, p.clone(), "hwprobe");
                        }
                        if ui.button("Tamper Test").clicked() {
                            self.spawn_peer_utility(&ctx, p, "tamper");
                        }
                    }
                });

                ui.add_space(6.0);
                egui::ScrollArea::vertical()
                    .max_height(240.0)
                    .stick_to_bottom(true)
                    .show(ui, |ui| {
                        for line in &self.chat_lines {
                            ui.horizontal_wrapped(|ui| {
                                status_pill(ui, &line.badge, line.badge_color);
                                ui.label(&line.body);
                            });
                        }
                    });

                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    let resp = ui.add(
                        egui::TextEdit::singleline(&mut self.chat_input)
                            .hint_text("Type E2E message...")
                            .desired_width(260.0),
                    );
                    let enter =
                        resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    if (ui.button("Send").clicked() || enter) && !self.chat_input.trim().is_empty()
                    {
                        self.spawn_send_chat(&ctx);
                    }
                });
            });
        });
    }

    fn render_hardware_tab(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        card_frame().show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("Host OS & Hardware Inventory").size(16.0).strong());
                if ui.button("Refresh Hardware").clicked() {
                    self.spawn_refresh_hardware(&ctx);
                }
            });

            if let Some(ref hw) = self.hardware {
                ui.add_space(6.0);
                ui.horizontal_wrapped(|ui| {
                    status_pill(
                        ui,
                        if hw.tpm2_cng_available { "TPM 2.0 OK" } else { "No TPM" },
                        if hw.tpm2_cng_available { ACCENT_EMERALD } else { ACCENT_AMBER },
                    );
                    status_pill(
                        ui,
                        if hw.dpapi_available { "DPAPI Ready" } else { "Non-Windows" },
                        ACCENT_CYAN,
                    );
                    status_pill(
                        ui,
                        if hw.machine_id_present { "MachineGuid Bound" } else { "No MachineGuid" },
                        ACCENT_EMERALD,
                    );
                    status_pill(
                        ui,
                        if hw.is_elevated_admin { "Admin Elevated" } else { "Standard User" },
                        TEXT_MUTED,
                    );
                });

                ui.add_space(10.0);
                egui::ScrollArea::vertical().max_height(260.0).show(ui, |ui| {
                    ui.label(RichText::new("Network & VPN Adapters").strong().color(ACCENT_CYAN));
                    for nic in &hw.network_adapters {
                        ui.horizontal_wrapped(|ui| {
                            status_pill(
                                ui,
                                if nic.is_up { "UP" } else { "DOWN" },
                                if nic.is_up { ACCENT_EMERALD } else { TEXT_MUTED },
                            );
                            if nic.is_vpn_like {
                                status_pill(ui, "VPN", ACCENT_AMBER);
                            }
                            ui.label(RichText::new(&nic.name).strong());
                            ui.label(
                                RichText::new(format!("[{}]", nic.ipv4_cidrs.join(", ")))
                                    .color(TEXT_MUTED),
                            );
                        });
                    }

                    ui.add_space(8.0);
                    ui.label(
                        RichText::new(format!(
                            "COM Ports ({}) | USB Devices ({}) | HID Devices ({})",
                            hw.serial_ports.len(),
                            hw.usb_devices.len(),
                            hw.hid_devices.len()
                        ))
                        .strong()
                        .color(ACCENT_CYAN),
                    );
                    for sp in &hw.serial_ports {
                        ui.label(format!("  Serial: {} ({})", sp.port_name, sp.transport_kind));
                    }
                    for usb in &hw.usb_devices {
                        ui.label(format!(
                            "  USB {:04x}:{:04x} {}",
                            usb.vendor_id,
                            usb.product_id,
                            usb.product.as_deref().unwrap_or("<unnamed>")
                        ));
                    }
                });
            }
        });

        ui.add_space(10.0);
        card_frame().show(ui, |ui| {
            section_heading(
                ui,
                "Direct Serial / COM I/O",
                "Communicates natively via OS COM ports or bridges over CubeHash from Chat tab.",
            );
            ui.horizontal_wrapped(|ui| {
                ui.label("Port:");
                ui.add(egui::TextEdit::singleline(&mut self.serial_port).desired_width(90.0));
                ui.label("Baud:");
                ui.add(egui::TextEdit::singleline(&mut self.serial_baud).desired_width(80.0));
                ui.checkbox(&mut self.serial_hex_mode, "Hex");
                ui.label("Payload:");
                ui.add(egui::TextEdit::singleline(&mut self.serial_payload).desired_width(200.0));
                if ui.button("Send Serial").clicked() {
                    self.spawn_serial_send(&ctx);
                }
            });
            if !self.serial_output.is_empty() {
                ui.add_space(6.0);
                ui.monospace(&self.serial_output);
            }
        });
    }

    fn render_diag_tab(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        card_frame().show(ui, |ui| {
            section_heading(
                ui,
                "System, VPN & TLS Diagnostics",
                "Collects hardware posture, LAN discovery beacons, and Master HTTPS health.",
            );
            ui.horizontal(|ui| {
                if ui.button("Run Diagnostics").clicked() {
                    self.spawn_diagnostics(&ctx, false);
                }
                if ui.button("Run & Upload to Master").clicked() {
                    self.spawn_diagnostics(&ctx, true);
                }
                if !self.diag_json.is_empty() && ui.button("Copy JSON").clicked() {
                    ui.ctx().copy_text(self.diag_json.clone());
                    self.set_banner("Copied diagnostics JSON to clipboard.", ACCENT_CYAN);
                }
            });
            ui.add_space(8.0);
            egui::ScrollArea::vertical().max_height(380.0).show(ui, |ui| {
                ui.add(
                    egui::TextEdit::multiline(&mut self.diag_json)
                        .font(egui::TextStyle::Monospace)
                        .desired_width(f32::INFINITY)
                        .desired_rows(20),
                );
            });
        });
    }

    fn render_profile_tab(&mut self, ui: &mut egui::Ui) {
        card_frame().show(ui, |ui| {
            section_heading(
                ui,
                "User Profile Settings",
                "Compatible with EazyConnect CLI (`profile show` / `profile set`).",
            );
            egui::Grid::new("profile_grid")
                .num_columns(2)
                .spacing([10.0, 10.0])
                .show(ui, |ui| {
                    ui.label("Display Name:");
                    ui.add(egui::TextEdit::singleline(&mut self.profile_name).desired_width(280.0));
                    ui.end_row();

                    ui.label("Photo Path:");
                    ui.horizontal(|ui| {
                        ui.add(egui::TextEdit::singleline(&mut self.profile_photo).desired_width(220.0));
                        if ui.button("Choose Photo").clicked() {
                            if let Some(p) = rfd::FileDialog::new()
                                .add_filter("Images", &["png", "jpg", "jpeg", "bmp"])
                                .pick_file()
                            {
                                self.profile_photo = p.display().to_string();
                            }
                        }
                    });
                    ui.end_row();

                    ui.label("Language:");
                    egui::ComboBox::from_id_salt("profile_lang")
                        .selected_text(if self.profile_lang == "fa" {
                            "fa (Persian)"
                        } else {
                            "en (English)"
                        })
                        .show_ui(ui, |ui| {
                            ui.selectable_value(
                                &mut self.profile_lang,
                                "en".to_string(),
                                "en (English)",
                            );
                            ui.selectable_value(
                                &mut self.profile_lang,
                                "fa".to_string(),
                                "fa (Persian)",
                            );
                        });
                    ui.end_row();
                });

            ui.add_space(10.0);
            if ui.button("Save Profile").clicked() {
                match self.persist_current_cfg() {
                    Ok(p) => self.set_banner(
                        format!("Saved profile to {}", p.display()),
                        ACCENT_EMERALD,
                    ),
                    Err(e) => self.set_banner(e, ACCENT_ROSE),
                }
            }
        });
    }
}

impl eframe::App for EazyUiApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.poll_async_events();

        let top_frame = egui::Frame::new()
            .fill(BG_PANEL)
            .inner_margin(egui::Margin::symmetric(16, 12));
        egui::Panel::top("top_nav").frame(top_frame).show(ui, |ui| {
            self.render_top_bar(ui);
        });

        let bot_frame = egui::Frame::new()
            .fill(BG_PANEL)
            .inner_margin(egui::Margin::symmetric(16, 8));
        egui::Panel::bottom("status_bar").frame(bot_frame).show(ui, |ui| {
            ui.horizontal(|ui| {
                if let Some(ref busy) = self.busy_label {
                    ui.spinner();
                    ui.label(RichText::new(busy).color(ACCENT_CYAN));
                    ui.separator();
                }
                if let Some((ref msg, color)) = self.status_banner {
                    ui.label(RichText::new(msg).color(color));
                }
            });
        });

        let central_frame = egui::Frame::new()
            .fill(BG_CANVAS)
            .inner_margin(egui::Margin::same(16));
        egui::CentralPanel::default()
            .frame(central_frame)
            .show(ui, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| match self.active_tab {
                    ActiveTab::Connect => self.render_connect_tab(ui),
                    ActiveTab::Files => self.render_files_tab(ui),
                    ActiveTab::Chat => self.render_chat_tab(ui),
                    ActiveTab::Hardware => self.render_hardware_tab(ui),
                    ActiveTab::Diagnostics => self.render_diag_tab(ui),
                    ActiveTab::Profile => self.render_profile_tab(ui),
                });
            });
    }
}
