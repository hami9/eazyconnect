use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use eazyconnect_client::{
    build_http_client_from_cfg, load_bearer_token, resolve_client_id, EazyNode,
    NodeConnectOptions, NodeEvent,
};
use eazyconnect_core::{
    discover_masters, load_client_config, save_client_config, ClientConfig, CreateUserRequest,
    DiscoveredMaster, EazyAppMessage, EazyMeshProfile, PeerIdentity,
};
use eazyconnect_hw::DeviceIdentity;
use egui::{
    Align, Color32, ColorImage, CornerRadius, Frame, Layout, Margin, RichText, ScrollArea, Sense,
    Stroke, TextureHandle, TextureOptions, Vec2,
};
use tokio::runtime::Runtime;
use tokio::sync::Mutex as TokioMutex;

use crate::state::{
    avatar_color_for, broadcast_discovery_target, discovery_target_for_server, format_time_now,
    normalize_server_url, paint_avatar, status_pill, AppScreen, ChatMessage, ConnectionState,
    PeerConversation, SettingsSection, UiEvent,
};
use crate::theme::{apply_theme_to_ctx, palette, ThemeMode, ThemePalette};

pub struct EazyUiApp {
    rt: Arc<Runtime>,
    config_path: Option<PathBuf>,
    keystore_dir: Option<PathBuf>,
    events_tx: mpsc::Sender<UiEvent>,
    events_rx: mpsc::Receiver<UiEvent>,

    // Navigation & overlays
    screen: AppScreen,
    settings_open: bool,
    settings_section: SettingsSection,
    profile_popover_open: bool,
    show_advanced_tls: bool,
    show_account_login: bool,
    new_dm_open: bool,
    new_dm_input: String,

    // Theme & Appearance
    theme_mode: ThemeMode,
    compact_messages: bool,
    font_size: f32,

    // Persisted Profile & Credentials
    loaded_cfg: ClientConfig,
    server_input: String,
    tls_pin_hex: String,
    tls_ca_pem_path: String,
    insecure_http: bool,
    invite_code: String,
    shared_passphrase: String,
    auto_reconnect: bool,
    client_id: String,
    display_name: String,
    profile_photo: String,
    profile_lang: String,
    avatar_texture: Option<TextureHandle>,
    avatar_loaded_path: String,

    // Optional User Account Login / Provisioning inside Account Settings
    login_username: String,
    login_password: String,
    new_user_name: String,
    new_user_pass: String,
    new_user_admin: bool,

    // Discovery & Network status (friendly summary, zero crypto jargon)
    discovered_servers: Vec<DiscoveredMaster>,
    active_vpns: Vec<String>,
    conn_state: ConnectionState,
    toast_notice: Option<(String, bool)>,

    // Live Relay & Chat State
    active_node: Arc<TokioMutex<Option<EazyNode>>>,
    online_peers: Vec<PeerIdentity>,
    peer_search: String,
    selected_peer: Option<String>,
    conversations: BTreeMap<String, PeerConversation>,
    pending_drafts: HashMap<String, Vec<String>>,
    composer_text: String,
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
        let theme_mode = ThemeMode::from_config(cfg.theme.as_deref());
        let font_size = 14.5_f32;
        apply_theme_to_ctx(ctx, theme_mode, font_size);

        let client_id = resolve_client_id(None, &cfg);
        let display_name = if cfg.profile.name.trim().is_empty() {
            client_id.clone()
        } else {
            cfg.profile.name.clone()
        };
        let has_saved_master = cfg
            .master
            .as_deref()
            .is_some_and(|s| !s.trim().is_empty());
        let has_token = cfg.sealed_token_hex.is_some();

        let mut app = Self {
            rt,
            config_path,
            keystore_dir,
            events_tx,
            events_rx,
            screen: if has_saved_master && has_token {
                AppScreen::Chat
            } else {
                AppScreen::Onboarding
            },
            settings_open: false,
            settings_section: SettingsSection::Account,
            profile_popover_open: false,
            show_advanced_tls: false,
            show_account_login: false,
            new_dm_open: false,
            new_dm_input: String::new(),
            theme_mode,
            compact_messages: false,
            font_size,
            server_input: cfg.master.clone().unwrap_or_default(),
            tls_pin_hex: cfg.tls_pin_hex.clone().unwrap_or_default(),
            tls_ca_pem_path: cfg.tls_ca_pem_path.clone().unwrap_or_default(),
            insecure_http: !cfg.verify,
            invite_code: String::new(),
            shared_passphrase: String::new(),
            auto_reconnect: true,
            client_id,
            display_name,
            profile_photo: cfg.profile.photo.clone(),
            profile_lang: if cfg.profile.language.is_empty() {
                "en".to_string()
            } else {
                cfg.profile.language.clone()
            },
            avatar_texture: None,
            avatar_loaded_path: String::new(),
            login_username: cfg.username.clone().unwrap_or_default(),
            login_password: String::new(),
            new_user_name: String::new(),
            new_user_pass: String::new(),
            new_user_admin: false,
            discovered_servers: Vec::new(),
            active_vpns: Vec::new(),
            conn_state: ConnectionState::Disconnected,
            toast_notice: None,
            active_node: Arc::new(TokioMutex::new(None)),
            online_peers: Vec::new(),
            peer_search: String::new(),
            selected_peer: None,
            conversations: BTreeMap::new(),
            pending_drafts: HashMap::new(),
            composer_text: String::new(),
            loaded_cfg: cfg,
        };

        app.refresh_avatar_texture(ctx);
        app.spawn_background_probe(ctx);
        if has_saved_master {
            app.spawn_auto_connect(ctx);
        }
        app
    }

    fn refresh_avatar_texture(&mut self, ctx: &egui::Context) {
        let p = self.profile_photo.trim();
        if p == self.avatar_loaded_path {
            return;
        }
        self.avatar_loaded_path = p.to_string();
        if p.is_empty() {
            self.avatar_texture = None;
            return;
        }
        if let Some(img) = load_cropped_square_avatar(Path::new(p), 96) {
            let tex = ctx.load_texture("user_avatar", img, TextureOptions::LINEAR);
            self.avatar_texture = Some(tex);
        } else {
            self.avatar_texture = None;
        }
    }

    fn current_cfg_snapshot(&self) -> ClientConfig {
        let mut cfg = self.loaded_cfg.clone();
        let norm_url = normalize_server_url(&self.server_input, self.insecure_http);
        cfg.master = (!norm_url.is_empty()).then_some(norm_url);
        cfg.tls_pin_hex =
            (!self.tls_pin_hex.trim().is_empty()).then(|| self.tls_pin_hex.trim().to_string());
        cfg.tls_ca_pem_path = (!self.tls_ca_pem_path.trim().is_empty())
            .then(|| self.tls_ca_pem_path.trim().to_string());
        cfg.verify = !self.insecure_http;
        cfg.client_id =
            (!self.client_id.trim().is_empty()).then(|| self.client_id.trim().to_string());
        cfg.username = (!self.login_username.trim().is_empty())
            .then(|| self.login_username.trim().to_string());
        cfg.theme = Some(self.theme_mode.as_key().to_string());
        cfg.profile.name = self.display_name.trim().to_string();
        cfg.profile.photo = self.profile_photo.trim().to_string();
        cfg.profile.language = if self.profile_lang == "fa" {
            "fa".to_string()
        } else {
            "en".to_string()
        };
        cfg
    }

    fn save_settings_to_disk(&mut self) -> Result<(), String> {
        let snap = self.current_cfg_snapshot();
        save_client_config(&snap, self.config_path.as_deref())?;
        self.loaded_cfg = snap;
        Ok(())
    }

    fn set_notice(&mut self, msg: impl Into<String>, is_error: bool) {
        self.toast_notice = Some((msg.into(), is_error));
    }

    fn spawn_background_probe(&mut self, ctx: &egui::Context) {
        let tx_hw = self.events_tx.clone();
        let ctx_hw = ctx.clone();
        self.rt.spawn(async move {
            if let Ok(rep) =
                tokio::task::spawn_blocking(eazyconnect_hw::collect_hardware_report).await
            {
                let _ = tx_hw.send(UiEvent::HardwareChecked(rep));
                ctx_hw.request_repaint();
            }
        });

        let tx_disc = self.events_tx.clone();
        let ctx_disc = ctx.clone();
        self.rt.spawn(async move {
            let list = discover_masters(broadcast_discovery_target(), Duration::from_millis(1400))
                .await
                .unwrap_or_default();
            let _ = tx_disc.send(UiEvent::DiscoveryDone(list));
            ctx_disc.request_repaint();
        });
    }

    fn spawn_auto_connect(&mut self, ctx: &egui::Context) {
        let normalized_url = normalize_server_url(&self.server_input, self.insecure_http);
        if normalized_url.is_empty() {
            self.set_notice("Please enter or select a server address.", true);
            return;
        }
        self.server_input = normalized_url.clone();
        self.conn_state = ConnectionState::Connecting;
        self.toast_notice = None;

        let mut cfg = self.current_cfg_snapshot();
        let cid = resolve_client_id(Some(&self.client_id), &cfg);
        let ks = self.keystore_dir.clone();
        let invite = (!self.invite_code.trim().is_empty())
            .then(|| self.invite_code.trim().to_string());
        let existing_token = load_bearer_token(&cid, &cfg).ok();
        let allow_insecure = self.insecure_http;
        let auto_reconnect = self.auto_reconnect;
        let node_slot = Arc::clone(&self.active_node);
        let tx = self.events_tx.clone();
        let ctx = ctx.clone();

        self.rt.spawn(async move {
            if let Some(old) = node_slot.lock().await.take() {
                old.shutdown().await;
            }

            let outcome = async {
                // Step 1: Automatically resolve & verify TLS SHA-256 fingerprint via signed UDP beacon if unset.
                if cfg.tls_pin_hex.as_deref().unwrap_or("").is_empty()
                    && cfg.tls_ca_pem_path.as_deref().unwrap_or("").is_empty()
                    && normalized_url.starts_with("https://")
                {
                    if let Some(unicast_disc) = discovery_target_for_server(&normalized_url) {
                        if let Ok(found) =
                            discover_masters(unicast_disc, Duration::from_millis(1100)).await
                        {
                            if let Some(m) = found
                                .into_iter()
                                .find(|m| m.signature_valid && m.tls_cert_sha256_hex.is_some())
                            {
                                cfg.tls_pin_hex = m.tls_cert_sha256_hex;
                            }
                        }
                    }
                    if cfg.tls_pin_hex.is_none() {
                        if let Ok(found) = discover_masters(
                            broadcast_discovery_target(),
                            Duration::from_millis(1000),
                        )
                        .await
                        {
                            if let Some(m) = found.into_iter().find(|m| {
                                m.signature_valid
                                    && m.tls_cert_sha256_hex.is_some()
                                    && (m.url == normalized_url
                                        || m.alternate_urls.contains(&normalized_url))
                            }) {
                                cfg.tls_pin_hex = m.tls_cert_sha256_hex;
                            }
                        }
                    }
                }

                // Step 2: Load/create DPAPI-sealed device identity and enroll silently if no token yet.
                let id = DeviceIdentity::load_or_create(&cid, ks.as_deref(), None)?;
                let (client, url, tls_config) = build_http_client_from_cfg(
                    Some(&normalized_url),
                    cfg.tls_pin_hex.as_deref(),
                    cfg.tls_ca_pem_path.as_deref().map(Path::new),
                    allow_insecure,
                    &cfg,
                )?;

                let new_token = if existing_token.is_none() {
                    let tok = client.enroll_device(&id, invite.as_deref()).await?;
                    Some((tok.token, tok.role))
                } else {
                    None
                };

                // Step 3: Connect live WSS relay automatically with heartbeat + reconnect continuity.
                let node = EazyNode::connect(
                    id,
                    NodeConnectOptions {
                        ws_url: url.clone(),
                        tls_config,
                        allow_insecure_ws: allow_insecure,
                        allow_remote_serial_os_fallback: false,
                        allow_remote_hw_probe: true,
                        auto_reconnect,
                    },
                )
                .await?;

                let mut rx = node.subscribe();
                let peers = node.online_peers().await.unwrap_or_default();
                *node_slot.lock().await = Some(node);

                let tx_ev = tx.clone();
                let ctx_ev = ctx.clone();
                tokio::spawn(async move {
                    loop {
                        match rx.recv().await {
                            Ok(ev) => {
                                let closed = matches!(ev, NodeEvent::Disconnected { .. });
                                let _ = tx_ev.send(UiEvent::NodeEvent(ev));
                                ctx_ev.request_repaint();
                                if closed {
                                    break;
                                }
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                            Err(_) => break,
                        }
                    }
                });

                Ok::<_, String>((url, cfg.tls_pin_hex, cid, new_token, peers))
            }
            .await;

            match outcome {
                Ok((master_url, tls_pin_hex, client_id, token, peers)) => {
                    let _ = tx.send(UiEvent::AutoConnectOk {
                        master_url,
                        tls_pin_hex,
                        client_id,
                        token,
                        peers,
                    });
                }
                Err(err) => {
                    let _ = tx.send(UiEvent::AutoConnectFailed(friendly_connect_error(&err)));
                }
            }
            ctx.request_repaint();
        });
    }

    fn spawn_disconnect(&mut self, ctx: &egui::Context, clear_session: bool) {
        if clear_session {
            self.loaded_cfg.sealed_token_hex = None;
            let _ = save_client_config(&self.loaded_cfg, self.config_path.as_deref());
            self.screen = AppScreen::Onboarding;
            self.settings_open = false;
        }
        let node_slot = Arc::clone(&self.active_node);
        let tx = self.events_tx.clone();
        let ctx = ctx.clone();
        self.rt.spawn(async move {
            if let Some(node) = node_slot.lock().await.take() {
                node.shutdown().await;
            }
            let _ = tx.send(UiEvent::DisconnectedCleanly);
            ctx.request_repaint();
        });
    }

    fn ensure_peer_paired(&mut self, ctx: &egui::Context, peer_id: &str) {
        let entry = self.conversations.entry(peer_id.to_string()).or_default();
        if entry.paired || entry.pairing_in_flight {
            return;
        }
        if self.conn_state != ConnectionState::Online {
            return;
        }
        entry.pairing_in_flight = true;

        let node_slot = Arc::clone(&self.active_node);
        let peer = peer_id.to_string();
        let psk = self.shared_passphrase.as_bytes().to_vec();
        let tx = self.events_tx.clone();
        let ctx = ctx.clone();
        self.rt.spawn(async move {
            let guard = node_slot.lock().await;
            if let Some(node) = guard.as_ref() {
                if let Err(e) = node
                    .send_pair_offer(&peer, EazyMeshProfile::Standard, &psk)
                    .await
                {
                    let _ = tx.send(UiEvent::Notice {
                        msg: format!("Could not start chat with '{peer}': {e}"),
                        is_error: true,
                    });
                }
            }
            ctx.request_repaint();
        });
    }

    fn auto_accept_offer(&self, ctx: &egui::Context, pair_id: String, from: String) {
        let node_slot = Arc::clone(&self.active_node);
        let psk = self.shared_passphrase.as_bytes().to_vec();
        let tx = self.events_tx.clone();
        let ctx = ctx.clone();
        self.rt.spawn(async move {
            let guard = node_slot.lock().await;
            if let Some(node) = guard.as_ref() {
                if let Err(e) = node.accept_pair_offer(&pair_id, &psk).await {
                    let _ = tx.send(UiEvent::Notice {
                        msg: format!("Security check failed for '{from}': {e}"),
                        is_error: true,
                    });
                }
            }
            ctx.request_repaint();
        });
    }

    fn send_message_to_active(&mut self, ctx: &egui::Context) {
        let Some(peer) = self.selected_peer.clone() else {
            return;
        };
        let text = self.composer_text.trim().to_string();
        if text.is_empty() {
            return;
        }
        self.composer_text.clear();

        let my_name = if self.display_name.trim().is_empty() {
            self.client_id.clone()
        } else {
            self.display_name.clone()
        };

        let conv = self.conversations.entry(peer.clone()).or_default();
        conv.messages.push(ChatMessage {
            sender: my_name,
            text: text.clone(),
            timestamp: format_time_now(),
            outgoing: true,
        });

        if !conv.paired {
            self.pending_drafts.entry(peer.clone()).or_default().push(text);
            self.ensure_peer_paired(ctx, &peer);
            return;
        }

        self.dispatch_chat_text(ctx, peer, text);
    }

    fn dispatch_chat_text(&self, ctx: &egui::Context, peer: String, text: String) {
        let node_slot = Arc::clone(&self.active_node);
        let tx = self.events_tx.clone();
        let ctx = ctx.clone();
        self.rt.spawn(async move {
            let guard = node_slot.lock().await;
            let Some(node) = guard.as_ref() else {
                let _ = tx.send(UiEvent::Notice {
                    msg: "Waiting for connection before sending...".to_string(),
                    is_error: true,
                });
                ctx.request_repaint();
                return;
            };
            if let Err(e) = node
                .send_app_message(&peer, EazyAppMessage::ChatText { text })
                .await
            {
                let _ = tx.send(UiEvent::Notice {
                    msg: format!("Message delivery issue: {e}"),
                    is_error: true,
                });
            }
            ctx.request_repaint();
        });
    }

    fn spawn_account_login(&mut self, ctx: &egui::Context) {
        if self.login_username.trim().is_empty() || self.login_password.is_empty() {
            self.set_notice("Enter username and password.", true);
            return;
        }
        let cfg = self.current_cfg_snapshot();
        let (client, url, _) = match build_http_client_from_cfg(
            cfg.master.as_deref(),
            cfg.tls_pin_hex.as_deref(),
            cfg.tls_ca_pem_path.as_deref().map(Path::new),
            self.insecure_http,
            &cfg,
        ) {
            Ok(v) => v,
            Err(e) => {
                self.set_notice(e, true);
                return;
            }
        };
        let user = self.login_username.trim().to_string();
        let pass = self.login_password.clone();
        let tx = self.events_tx.clone();
        let ctx = ctx.clone();
        self.rt.spawn(async move {
            match client.login_password(&user, &pass).await {
                Ok(tok) => {
                    let _ = tx.send(UiEvent::LoginOk {
                        username: user,
                        role: tok.role,
                        token: tok.token,
                        master_url: url,
                    });
                }
                Err(e) => {
                    let _ = tx.send(UiEvent::Notice {
                        msg: format!("Sign-in failed: {e}"),
                        is_error: true,
                    });
                }
            }
            ctx.request_repaint();
        });
    }

    fn spawn_create_user(&mut self, ctx: &egui::Context) {
        let cfg = self.current_cfg_snapshot();
        let cid = resolve_client_id(Some(&self.client_id), &cfg);
        let token = match load_bearer_token(&cid, &self.loaded_cfg) {
            Ok(t) => t,
            Err(e) => {
                self.set_notice(e, true);
                return;
            }
        };
        let (client, _, _) = match build_http_client_from_cfg(
            cfg.master.as_deref(),
            cfg.tls_pin_hex.as_deref(),
            cfg.tls_ca_pem_path.as_deref().map(Path::new),
            self.insecure_http,
            &cfg,
        ) {
            Ok(v) => v,
            Err(e) => {
                self.set_notice(e, true);
                return;
            }
        };
        let uname = self.new_user_name.trim().to_string();
        let upass = self.new_user_pass.clone();
        let is_admin = self.new_user_admin;
        if uname.is_empty() || upass.len() < 8 {
            self.set_notice("Username required and password must be at least 8 characters.", true);
            return;
        }
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
                        "Account '{uname}' created."
                    )));
                }
                Err(e) => {
                    let _ = tx.send(UiEvent::Notice {
                        msg: format!("Create account failed: {e}"),
                        is_error: true,
                    });
                }
            }
            ctx.request_repaint();
        });
    }

    fn poll_events(&mut self, ctx: &egui::Context) {
        while let Ok(ev) = self.events_rx.try_recv() {
            match ev {
                UiEvent::DiscoveryDone(list) => {
                    self.discovered_servers = list
                        .into_iter()
                        .filter(|m| m.signature_valid)
                        .collect();
                }
                UiEvent::HardwareChecked(rep) => {
                    self.active_vpns = rep.vpn_adapters_detected;
                }
                UiEvent::AutoConnectOk {
                    master_url,
                    tls_pin_hex,
                    client_id,
                    token,
                    peers,
                } => {
                    self.server_input = master_url.clone();
                    if let Some(ref pin) = tls_pin_hex {
                        self.tls_pin_hex = pin.clone();
                    }
                    self.loaded_cfg = self.current_cfg_snapshot();
                    self.loaded_cfg.master = Some(master_url);
                    self.loaded_cfg.tls_pin_hex = tls_pin_hex;
                    self.loaded_cfg.client_id = Some(client_id.clone());
                    if let Some((tok, role)) = token {
                        self.loaded_cfg.role = Some(role);
                        let _ = self.loaded_cfg.set_token(&client_id, &tok);
                    }
                    let _ = save_client_config(&self.loaded_cfg, self.config_path.as_deref());

                    self.conn_state = ConnectionState::Online;
                    self.screen = AppScreen::Chat;
                    self.online_peers = peers;
                    self.toast_notice = None;
                }
                UiEvent::AutoConnectFailed(msg) => {
                    self.conn_state = ConnectionState::Disconnected;
                    self.set_notice(msg, true);
                }
                UiEvent::LoginOk {
                    username,
                    role,
                    token,
                    master_url,
                } => {
                    let cid = resolve_client_id(Some(&self.client_id), &self.loaded_cfg);
                    self.loaded_cfg.master = Some(master_url);
                    self.loaded_cfg.username = Some(username.clone());
                    self.loaded_cfg.role = Some(role);
                    self.login_password.clear();
                    let _ = self.loaded_cfg.set_token(&cid, &token);
                    let _ = save_client_config(&self.loaded_cfg, self.config_path.as_deref());
                    self.set_notice(format!("Signed in as '{username}'."), false);
                }
                UiEvent::UserCreated(msg) => {
                    self.new_user_pass.clear();
                    self.set_notice(msg, false);
                }
                UiEvent::Notice { msg, is_error } => {
                    self.set_notice(msg, is_error);
                }
                UiEvent::DisconnectedCleanly => {
                    self.conn_state = ConnectionState::Disconnected;
                    self.online_peers.clear();
                }
                UiEvent::NodeEvent(nev) => self.handle_node_event(ctx, nev),
            }
        }
    }

    fn handle_node_event(&mut self, ctx: &egui::Context, nev: NodeEvent) {
        match nev {
            NodeEvent::Registered { online_peers, .. }
            | NodeEvent::PeerListUpdated { online_peers } => {
                self.online_peers = online_peers;
            }
            NodeEvent::IncomingPairOffer { pair_id, from, .. } => {
                // Transparent automatic pairing — client users never manage cryptographic handshakes manually.
                let conv = self.conversations.entry(from.clone()).or_default();
                conv.pairing_in_flight = true;
                self.auto_accept_offer(ctx, pair_id, from);
            }
            NodeEvent::Paired {
                peer,
                safety_fingerprint,
                ..
            } => {
                let conv = self.conversations.entry(peer.clone()).or_default();
                conv.paired = true;
                conv.pairing_in_flight = false;
                conv.safety_code = Some(safety_fingerprint);

                if let Some(queued) = self.pending_drafts.remove(&peer) {
                    for text in queued {
                        self.dispatch_chat_text(ctx, peer.clone(), text);
                    }
                }
            }
            NodeEvent::MessageReceived { from, msg, .. } => {
                let text = match msg {
                    EazyAppMessage::ChatText { text } => text,
                    EazyAppMessage::FileShared {
                        filename,
                        size_bytes,
                        ..
                    } => format!("Shared file: {filename} ({size_bytes} bytes)"),
                    EazyAppMessage::SerialData { port, data } => {
                        format!("[{port}] {}", String::from_utf8_lossy(&data))
                    }
                    other => format!("{other:?}"),
                };
                let conv = self.conversations.entry(from.clone()).or_default();
                conv.messages.push(ChatMessage {
                    sender: from.clone(),
                    text,
                    timestamp: format_time_now(),
                    outgoing: false,
                });
                if self.selected_peer.as_deref() != Some(from.as_str()) {
                    conv.unread = conv.unread.saturating_add(1);
                }
            }
            NodeEvent::Reconnecting { attempt, .. } => {
                self.conn_state = ConnectionState::Reconnecting { attempt };
            }
            NodeEvent::Reconnected => {
                self.conn_state = ConnectionState::Online;
            }
            NodeEvent::Disconnected { .. } => {
                self.conn_state = ConnectionState::Disconnected;
            }
            NodeEvent::RelayError { code, detail, peer } => {
                if let Some(p) = peer {
                    if let Some(conv) = self.conversations.get_mut(&p) {
                        conv.pairing_in_flight = false;
                    }
                }
                if code != "peer_offline" {
                    self.set_notice(friendly_connect_error(&detail), true);
                } else {
                    self.set_notice(detail, true);
                }
            }
            NodeEvent::DeliveryAcked { .. }
            | NodeEvent::HoneyDecoyTriggered { .. }
            | NodeEvent::EpochHopped { .. } => {}
        }
    }

    // --- UI Views -----------------------------------------------------------

    fn render_onboarding(&mut self, ui: &mut egui::Ui, pal: &ThemePalette) {
        let ctx = ui.ctx().clone();
        egui::CentralPanel::default()
            .frame(Frame::new().fill(pal.chat_bg))
            .show(ui, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(48.0);
                    Frame::new()
                        .fill(pal.sidebar_bg)
                        .stroke(Stroke::new(1.0, pal.border))
                        .corner_radius(CornerRadius::same(14))
                        .inner_margin(Margin::same(28))
                        .show(ui, |ui| {
                            ui.set_max_width(470.0);
                            ui.vertical_centered(|ui| {
                                paint_avatar(
                                    ui,
                                    58.0,
                                    "ec",
                                    "EC",
                                    None,
                                    pal.sidebar_bg,
                                    None,
                                );
                                ui.add_space(10.0);
                                ui.label(
                                    RichText::new("Welcome to EazyConnect")
                                        .size(22.0)
                                        .strong()
                                        .color(pal.text_primary),
                                );
                                ui.label(
                                    RichText::new("Private encrypted team & peer chat")
                                        .size(13.5)
                                        .color(pal.text_muted),
                                );
                            });

                            ui.add_space(18.0);

                            if !self.discovered_servers.is_empty() {
                                ui.label(
                                    RichText::new("DETECTED NEARBY SERVERS")
                                        .size(11.0)
                                        .strong()
                                        .color(pal.text_muted),
                                );
                                ui.add_space(6.0);
                                let servers = self.discovered_servers.clone();
                                for srv in servers {
                                    Frame::new()
                                        .fill(pal.dock_bg)
                                        .stroke(Stroke::new(1.0, pal.border))
                                        .corner_radius(CornerRadius::same(8))
                                        .inner_margin(Margin::symmetric(12, 8))
                                        .show(ui, |ui| {
                                            ui.horizontal(|ui| {
                                                ui.colored_label(pal.online, "●");
                                                ui.label(
                                                    RichText::new(&srv.url)
                                                        .strong()
                                                        .color(pal.text_primary),
                                                );
                                                ui.with_layout(
                                                    Layout::right_to_left(Align::Center),
                                                    |ui| {
                                                        if ui
                                                            .add(
                                                                egui::Button::new(
                                                                    RichText::new("Select")
                                                                        .color(Color32::WHITE)
                                                                        .strong(),
                                                                )
                                                                .fill(pal.blurple),
                                                            )
                                                            .clicked()
                                                        {
                                                            self.server_input = srv.url.clone();
                                                            if let Some(pin) = srv.tls_cert_sha256_hex
                                                            {
                                                                self.tls_pin_hex = pin;
                                                            }
                                                        }
                                                    },
                                                );
                                            });
                                        });
                                    ui.add_space(4.0);
                                }
                                ui.add_space(10.0);
                            }

                            ui.label(
                                RichText::new("DISPLAY NAME").size(11.0).strong().color(pal.text_muted),
                            );
                            ui.add_space(4.0);
                            ui.add(
                                egui::TextEdit::singleline(&mut self.display_name)
                                    .desired_width(f32::INFINITY)
                                    .hint_text("Your name shown to peers"),
                            );

                            ui.add_space(10.0);
                            ui.label(
                                RichText::new("SERVER ADDRESS")
                                    .size(11.0)
                                    .strong()
                                    .color(pal.text_muted),
                            );
                            ui.add_space(4.0);
                            ui.add(
                                egui::TextEdit::singleline(&mut self.server_input)
                                    .desired_width(f32::INFINITY)
                                    .hint_text("192.168.1.50:8000 or 10.8.0.1:8000"),
                            );

                            ui.add_space(10.0);
                            ui.label(
                                RichText::new("INVITE CODE (IF REQUIRED)")
                                    .size(11.0)
                                    .strong()
                                    .color(pal.text_muted),
                            );
                            ui.add_space(4.0);
                            ui.add(
                                egui::TextEdit::singleline(&mut self.invite_code)
                                    .desired_width(f32::INFINITY)
                                    .hint_text("Optional invite code"),
                            );

                            if let Some((ref msg, is_err)) = self.toast_notice {
                                ui.add_space(10.0);
                                ui.label(
                                    RichText::new(msg)
                                        .size(12.5)
                                        .color(if is_err { pal.danger } else { pal.online }),
                                );
                            }

                            ui.add_space(16.0);
                            ui.horizontal(|ui| {
                                let connecting = self.conn_state == ConnectionState::Connecting;
                                let btn_lbl = if connecting {
                                    "Connecting..."
                                } else {
                                    "Connect & Open Chat"
                                };
                                if ui
                                    .add_enabled(
                                        !connecting,
                                        egui::Button::new(
                                            RichText::new(btn_lbl)
                                                .size(14.5)
                                                .strong()
                                                .color(Color32::WHITE),
                                        )
                                        .fill(pal.blurple)
                                        .min_size(Vec2::new(260.0, 38.0)),
                                    )
                                    .clicked()
                                {
                                    self.spawn_auto_connect(&ctx);
                                }
                                if ui.button("Scan Nearby").clicked() {
                                    self.spawn_background_probe(&ctx);
                                }
                            });

                            ui.add_space(8.0);
                            ui.horizontal(|ui| {
                                if ui.link("Theme & Advanced Connection Settings").clicked() {
                                    self.settings_section = SettingsSection::Connection;
                                    self.settings_open = true;
                                }
                            });
                        });
                });
            });
    }

    fn render_discord_workspace(&mut self, ui: &mut egui::Ui, pal: &ThemePalette) {
        let ctx = ui.ctx().clone();

        // 1. Far-left Server Rail (classic Discord narrow dark rail)
        egui::Panel::left("guild_rail")
            .exact_size(68.0)
            .show_separator_line(false)
            .frame(
                Frame::new()
                    .fill(pal.rail_bg)
                    .inner_margin(Margin::symmetric(10, 12)),
            )
            .show(ui, |ui| {
                ui.vertical_centered(|ui| {
                    // Active App / DM pill
                    let (rect, resp) = ui.allocate_exact_size(Vec2::splat(46.0), Sense::click());
                    ui.painter().rect_filled(rect, CornerRadius::same(14), pal.blurple);
                    ui.painter().text(
                        rect.center(),
                        egui::Align2::CENTER_CENTER,
                        "EC",
                        egui::FontId::proportional(17.0),
                        Color32::WHITE,
                    );
                    if resp.clicked() {
                        self.settings_open = false;
                    }
                    resp.on_hover_text("Direct Messages");

                    ui.add_space(10.0);
                    ui.separator();

                    // Push utility controls cleanly to bottom of rail
                    ui.with_layout(Layout::bottom_up(Align::Center), |ui| {
                        let gear_btn = egui::Button::new(
                            RichText::new("Settings").size(11.0).color(pal.text_primary),
                        )
                        .fill(pal.dock_bg)
                        .corner_radius(CornerRadius::same(12))
                        .min_size(Vec2::new(50.0, 34.0));
                        if ui.add(gear_btn).clicked() {
                            self.settings_open = true;
                        }

                        ui.add_space(6.0);
                        let theme_lbl = match self.theme_mode {
                            ThemeMode::Light => "Light",
                            ThemeMode::Midnight => "OLED",
                            ThemeMode::DiscordDark => "Dark",
                        };
                        let theme_btn = egui::Button::new(
                            RichText::new(theme_lbl).size(11.0).color(pal.text_muted),
                        )
                        .fill(pal.dock_bg)
                        .corner_radius(CornerRadius::same(12))
                        .min_size(Vec2::new(50.0, 30.0));
                        if ui
                            .add(theme_btn)
                            .on_hover_text("Cycle theme")
                            .clicked()
                        {
                            self.theme_mode = match self.theme_mode {
                                ThemeMode::DiscordDark => ThemeMode::Midnight,
                                ThemeMode::Midnight => ThemeMode::Light,
                                ThemeMode::Light => ThemeMode::DiscordDark,
                            };
                            apply_theme_to_ctx(&ctx, self.theme_mode, self.font_size);
                            let _ = self.save_settings_to_disk();
                        }
                    });
                });
            });

        // 2. Direct Messages Sidebar + Bottom User Dock
        egui::Panel::left("dm_sidebar")
            .exact_size(248.0)
            .show_separator_line(false)
            .frame(Frame::new().fill(pal.sidebar_bg))
            .show(ui, |ui| {
                // Top Server Header
                Frame::new()
                    .fill(pal.sidebar_bg)
                    .stroke(Stroke::new(1.0, pal.border))
                    .inner_margin(Margin::symmetric(14, 12))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            let (dot_color, dot_tip) = match &self.conn_state {
                                ConnectionState::Online => (pal.online, "Connected"),
                                ConnectionState::Connecting => (pal.idle, "Connecting..."),
                                ConnectionState::Reconnecting { .. } => {
                                    (pal.idle, "Reconnecting...")
                                }
                                ConnectionState::Disconnected => (pal.danger, "Offline"),
                            };
                            ui.colored_label(dot_color, "●").on_hover_text(dot_tip);
                            ui.label(
                                RichText::new("EazyConnect")
                                    .size(15.0)
                                    .strong()
                                    .color(pal.text_primary),
                            );
                            if !self.active_vpns.is_empty() {
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    status_pill(ui, pal, "VPN", pal.online);
                                });
                            }
                        });
                    });

                // Search bar + DM list (leaves 60px room at bottom for User Dock)
                let avail_h = (ui.available_height() - 62.0).max(120.0);
                Frame::new()
                    .inner_margin(Margin::symmetric(10, 10))
                    .show(ui, |ui| {
                        ui.set_min_height(avail_h);
                        ui.set_max_height(avail_h);

                        ui.add(
                            egui::TextEdit::singleline(&mut self.peer_search)
                                .desired_width(f32::INFINITY)
                                .hint_text("Find or start a conversation"),
                        );
                        ui.add_space(10.0);

                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new("DIRECT MESSAGES")
                                    .size(11.0)
                                    .strong()
                                    .color(pal.text_muted),
                            );
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if ui
                                    .small_button("+")
                                    .on_hover_text("Start DM by ID")
                                    .clicked()
                                {
                                    self.new_dm_open = !self.new_dm_open;
                                }
                            });
                        });

                        if self.new_dm_open {
                            ui.add_space(4.0);
                            ui.horizontal(|ui| {
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.new_dm_input)
                                        .desired_width(150.0)
                                        .hint_text("Peer ID"),
                                );
                                if ui.small_button("Open").clicked() {
                                    let pid = self.new_dm_input.trim().to_string();
                                    if !pid.is_empty() && pid != self.client_id {
                                        self.new_dm_input.clear();
                                        self.new_dm_open = false;
                                        self.selected_peer = Some(pid.clone());
                                        self.ensure_peer_paired(&ctx, &pid);
                                    }
                                }
                            });
                        }

                        ui.add_space(6.0);
                        let peers = self.collect_sidebar_peers();
                        ScrollArea::vertical().show(ui, |ui| {
                            if peers.is_empty() {
                                ui.add_space(16.0);
                                ui.label(
                                    RichText::new("No peers online yet.")
                                        .size(12.5)
                                        .color(pal.text_muted),
                                );
                            }
                            for (peer_id, is_online, unread) in peers {
                                let selected =
                                    self.selected_peer.as_deref() == Some(peer_id.as_str());
                                let row_bg = if selected {
                                    pal.selected_bg
                                } else {
                                    Color32::TRANSPARENT
                                };
                                let resp = Frame::new()
                                    .fill(row_bg)
                                    .corner_radius(CornerRadius::same(7))
                                    .inner_margin(Margin::symmetric(8, 6))
                                    .show(ui, |ui| {
                                        ui.set_min_width(ui.available_width());
                                        ui.horizontal(|ui| {
                                            paint_avatar(
                                                ui,
                                                32.0,
                                                &peer_id,
                                                &peer_id,
                                                Some(if is_online {
                                                    pal.online
                                                } else {
                                                    pal.text_muted
                                                }),
                                                if selected {
                                                    pal.selected_bg
                                                } else {
                                                    pal.sidebar_bg
                                                },
                                                None,
                                            );
                                            ui.add_space(4.0);
                                            ui.label(
                                                RichText::new(&peer_id)
                                                    .size(14.0)
                                                    .strong()
                                                    .color(if selected {
                                                        pal.text_primary
                                                    } else {
                                                        pal.text_muted
                                                    }),
                                            );
                                            if unread > 0 {
                                                ui.with_layout(
                                                    Layout::right_to_left(Align::Center),
                                                    |ui| {
                                                        status_pill(
                                                            ui,
                                                            pal,
                                                            &unread.to_string(),
                                                            pal.danger,
                                                        );
                                                    },
                                                );
                                            }
                                        });
                                    })
                                    .response
                                    .interact(Sense::click());

                                if resp.clicked() {
                                    self.selected_peer = Some(peer_id.clone());
                                    if let Some(conv) = self.conversations.get_mut(&peer_id) {
                                        conv.unread = 0;
                                    }
                                    self.ensure_peer_paired(&ctx, &peer_id);
                                }
                            }
                        });
                    });

                // Bottom-Left Discord User Dock
                Frame::new()
                    .fill(pal.dock_bg)
                    .inner_margin(Margin::symmetric(10, 9))
                    .show(ui, |ui| {
                        ui.set_min_height(44.0);
                        ui.horizontal(|ui| {
                            let me_id = self.client_id.clone();
                            let me_name = if self.display_name.trim().is_empty() {
                                me_id.clone()
                            } else {
                                self.display_name.clone()
                            };
                            let status_col = match self.conn_state {
                                ConnectionState::Online => pal.online,
                                ConnectionState::Connecting
                                | ConnectionState::Reconnecting { .. } => pal.idle,
                                ConnectionState::Disconnected => pal.text_muted,
                            };

                            let profile_resp = ui
                                .horizontal(|ui| {
                                    paint_avatar(
                                        ui,
                                        34.0,
                                        &me_id,
                                        &me_name,
                                        Some(status_col),
                                        pal.dock_bg,
                                        self.avatar_texture.as_ref(),
                                    );
                                    ui.vertical(|ui| {
                                        ui.spacing_mut().item_spacing.y = 1.0;
                                        ui.label(
                                            RichText::new(&me_name)
                                                .size(13.0)
                                                .strong()
                                                .color(pal.text_primary),
                                        );
                                        let sub = match &self.conn_state {
                                            ConnectionState::Online => "Online",
                                            ConnectionState::Connecting => "Connecting...",
                                            ConnectionState::Reconnecting { .. } => "Reconnecting...",
                                            ConnectionState::Disconnected => "Offline",
                                        };
                                        ui.label(
                                            RichText::new(sub).size(11.0).color(pal.text_muted),
                                        );
                                    });
                                })
                                .response
                                .interact(Sense::click());
                            if profile_resp.clicked() {
                                self.profile_popover_open = !self.profile_popover_open;
                            }

                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if ui
                                    .button("⚙")
                                    .on_hover_text("User Settings")
                                    .clicked()
                                {
                                    self.settings_open = true;
                                }
                            });
                        });
                    });
            });

        // 3. Central Chat Panel
        egui::CentralPanel::default()
            .frame(Frame::new().fill(pal.chat_bg))
            .show(ui, |ui| {
                self.render_chat_canvas(ui, pal);
            });

        // Floating Profile Popout Card (bottom-left style like Discord)
        if self.profile_popover_open {
            self.render_profile_popover(&ctx, pal);
        }
    }

    fn collect_sidebar_peers(&self) -> Vec<(String, bool, u32)> {
        let mut map: BTreeMap<String, (bool, u32)> = BTreeMap::new();
        for p in &self.online_peers {
            if p.client_id != self.client_id {
                let unread = self
                    .conversations
                    .get(&p.client_id)
                    .map_or(0, |c| c.unread);
                map.insert(p.client_id.clone(), (true, unread));
            }
        }
        for (pid, conv) in &self.conversations {
            if pid != &self.client_id && !map.contains_key(pid) {
                map.insert(pid.clone(), (false, conv.unread));
            }
        }
        let needle = self.peer_search.trim().to_ascii_lowercase();
        map.into_iter()
            .filter(|(pid, _)| needle.is_empty() || pid.to_ascii_lowercase().contains(&needle))
            .map(|(pid, (online, unread))| (pid, online, unread))
            .collect()
    }

    fn render_chat_canvas(&mut self, ui: &mut egui::Ui, pal: &ThemePalette) {
        let ctx = ui.ctx().clone();

        // Top Channel Header
        Frame::new()
            .fill(pal.chat_bg)
            .stroke(Stroke::new(1.0, pal.border))
            .inner_margin(Margin::symmetric(18, 12))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    if let Some(ref peer) = self.selected_peer {
                        let is_online = self.online_peers.iter().any(|p| &p.client_id == peer);
                        ui.colored_label(
                            if is_online { pal.online } else { pal.text_muted },
                            "●",
                        );
                        ui.label(
                            RichText::new(format!("@{peer}"))
                                .size(16.0)
                                .strong()
                                .color(pal.text_primary),
                        );

                        if let Some(conv) = self.conversations.get(peer) {
                            if conv.paired {
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    let resp = ui.label(
                                        RichText::new("Encrypted")
                                            .size(11.5)
                                            .strong()
                                            .color(pal.online),
                                    );
                                    if let Some(ref code) = conv.safety_code {
                                        resp.on_hover_text(format!("Verified Safety Number: {code}"));
                                    }
                                });
                            } else if conv.pairing_in_flight {
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    ui.label(
                                        RichText::new("Securing...")
                                            .size(11.5)
                                            .color(pal.text_muted),
                                    );
                                });
                            }
                        }
                    } else {
                        ui.label(
                            RichText::new("Direct Messages")
                                .size(16.0)
                                .strong()
                                .color(pal.text_primary),
                        );
                    }
                });
            });

        if let Some((notice, is_err)) = self.toast_notice.clone() {
            Frame::new()
                .fill(if is_err {
                    Color32::from_rgba_unmultiplied(pal.danger.r(), pal.danger.g(), pal.danger.b(), 26)
                } else {
                    Color32::from_rgba_unmultiplied(pal.online.r(), pal.online.g(), pal.online.b(), 26)
                })
                .inner_margin(Margin::symmetric(16, 6))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(&notice)
                                .size(12.5)
                                .color(if is_err { pal.danger } else { pal.online }),
                        );
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if ui.small_button("Dismiss").clicked() {
                                self.toast_notice = None;
                            }
                        });
                    });
                });
        }

        // Message Feed + Composer
        let composer_reserve = 68.0;
        let feed_height = (ui.available_height() - composer_reserve).max(100.0);

        if let Some(peer) = self.selected_peer.clone() {
            let messages = self
                .conversations
                .get(&peer)
                .map(|c| c.messages.clone())
                .unwrap_or_default();

            ScrollArea::vertical()
                .max_height(feed_height)
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    ui.add_space(12.0);
                    if messages.is_empty() {
                        Frame::new()
                            .inner_margin(Margin::symmetric(20, 20))
                            .show(ui, |ui| {
                                paint_avatar(
                                    ui,
                                    64.0,
                                    &peer,
                                    &peer,
                                    None,
                                    pal.chat_bg,
                                    None,
                                );
                                ui.add_space(8.0);
                                ui.label(
                                    RichText::new(&peer)
                                        .size(22.0)
                                        .strong()
                                        .color(pal.text_primary),
                                );
                                ui.label(
                                    RichText::new(format!(
                                        "This is the beginning of your private conversation with @{peer}."
                                    ))
                                    .size(13.5)
                                    .color(pal.text_muted),
                                );
                            });
                    }

                    let mut prev_sender: Option<String> = None;
                    for msg in &messages {
                        let grouped = prev_sender.as_deref() == Some(msg.sender.as_str());
                        let top_pad = if self.compact_messages || grouped {
                            2
                        } else {
                            10
                        };

                        Frame::new()
                            .inner_margin(Margin {
                                left: 18,
                                right: 18,
                                top: top_pad,
                                bottom: 2,
                            })
                            .show(ui, |ui| {
                                ui.horizontal_top(|ui| {
                                    if grouped {
                                        ui.add_space(46.0);
                                    } else {
                                        let seed = if msg.outgoing {
                                            self.client_id.as_str()
                                        } else {
                                            peer.as_str()
                                        };
                                        let tex = if msg.outgoing {
                                            self.avatar_texture.as_ref()
                                        } else {
                                            None
                                        };
                                        paint_avatar(
                                            ui,
                                            38.0,
                                            seed,
                                            &msg.sender,
                                            None,
                                            pal.chat_bg,
                                            tex,
                                        );
                                        ui.add_space(8.0);
                                    }

                                    ui.vertical(|ui| {
                                        ui.spacing_mut().item_spacing.y = 2.0;
                                        if !grouped {
                                            ui.horizontal(|ui| {
                                                let name_col = if msg.outgoing {
                                                    pal.blurple
                                                } else {
                                                    avatar_color_for(&peer)
                                                };
                                                ui.label(
                                                    RichText::new(&msg.sender)
                                                        .strong()
                                                        .color(name_col),
                                                );
                                                ui.label(
                                                    RichText::new(&msg.timestamp)
                                                        .size(11.0)
                                                        .color(pal.text_muted),
                                                );
                                            });
                                        }
                                        ui.label(
                                            RichText::new(&msg.text)
                                                .size(self.font_size)
                                                .color(pal.text_primary),
                                        );
                                    });
                                });
                            });
                        prev_sender = Some(msg.sender.clone());
                    }
                    ui.add_space(12.0);
                });

            // Bottom Composer Pill
            Frame::new()
                .inner_margin(Margin::symmetric(16, 10))
                .show(ui, |ui| {
                    Frame::new()
                        .fill(pal.composer_bg)
                        .corner_radius(CornerRadius::same(10))
                        .inner_margin(Margin::symmetric(12, 8))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                let input_w = (ui.available_width() - 78.0).max(140.0);
                                let resp = ui.add(
                                    egui::TextEdit::singleline(&mut self.composer_text)
                                        .desired_width(input_w)
                                        .frame(Frame::NONE)
                                        .hint_text(format!("Message @{peer}")),
                                );
                                let hit_enter = resp.lost_focus()
                                    && ui.input(|i| i.key_pressed(egui::Key::Enter));

                                let mut send_clicked = false;
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    send_clicked = ui
                                        .add(
                                            egui::Button::new(
                                                RichText::new("Send")
                                                    .color(Color32::WHITE)
                                                    .strong(),
                                            )
                                            .fill(pal.blurple),
                                        )
                                        .clicked();
                                });

                                if hit_enter || send_clicked {
                                    self.send_message_to_active(&ctx);
                                    resp.request_focus();
                                }
                            });
                        });
                });
        } else {
            ui.vertical_centered(|ui| {
                ui.add_space(feed_height * 0.35);
                ui.label(
                    RichText::new("Select a conversation to start chatting")
                        .size(18.0)
                        .strong()
                        .color(pal.text_primary),
                );
                ui.add_space(6.0);
                ui.label(
                    RichText::new(
                        "All encryption, device authentication, and network roaming run automatically.",
                    )
                    .size(13.5)
                    .color(pal.text_muted),
                );
                if self.conn_state != ConnectionState::Online {
                    ui.add_space(14.0);
                    if ui
                        .add(
                            egui::Button::new(
                                RichText::new("Reconnect Now")
                                    .color(Color32::WHITE)
                                    .strong(),
                            )
                            .fill(pal.blurple),
                        )
                        .clicked()
                    {
                        self.spawn_auto_connect(&ctx);
                    }
                }
            });
        }
    }

    fn render_profile_popover(&mut self, ctx: &egui::Context, pal: &ThemePalette) {
        let me_name = if self.display_name.trim().is_empty() {
            self.client_id.clone()
        } else {
            self.display_name.clone()
        };
        egui::Window::new("User Profile")
            .title_bar(false)
            .resizable(false)
            .collapsible(false)
            .anchor(egui::Align2::LEFT_BOTTOM, egui::vec2(78.0, -68.0))
            .frame(
                Frame::new()
                    .fill(pal.dock_bg)
                    .stroke(Stroke::new(1.0, pal.border))
                    .corner_radius(CornerRadius::same(12))
                    .inner_margin(Margin::same(16)),
            )
            .show(ctx, |ui| {
                ui.set_width(250.0);
                ui.horizontal(|ui| {
                    paint_avatar(
                        ui,
                        56.0,
                        &self.client_id,
                        &me_name,
                        Some(if self.conn_state == ConnectionState::Online {
                            pal.online
                        } else {
                            pal.idle
                        }),
                        pal.dock_bg,
                        self.avatar_texture.as_ref(),
                    );
                    ui.add_space(8.0);
                    ui.vertical(|ui| {
                        ui.label(
                            RichText::new(&me_name)
                                .size(16.0)
                                .strong()
                                .color(pal.text_primary),
                        );
                        ui.label(
                            RichText::new(format!("@{}", self.client_id))
                                .size(12.5)
                                .color(pal.text_muted),
                        );
                        ui.label(
                            RichText::new(format!(
                                "Lang: {}",
                                if self.profile_lang == "fa" { "FA" } else { "EN" }
                            ))
                            .size(11.5)
                            .color(pal.text_muted),
                        );
                    });
                });

                ui.add_space(10.0);
                ui.separator();
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui
                        .add(
                            egui::Button::new(
                                RichText::new("Edit Profile & Settings")
                                    .color(Color32::WHITE)
                                    .strong(),
                            )
                            .fill(pal.blurple),
                        )
                        .clicked()
                    {
                        self.profile_popover_open = false;
                        self.settings_section = SettingsSection::Account;
                        self.settings_open = true;
                    }
                    if ui.button("Close").clicked() {
                        self.profile_popover_open = false;
                    }
                });
            });
    }

    fn render_settings_view(&mut self, ui: &mut egui::Ui, pal: &ThemePalette) {
        let ctx = ui.ctx().clone();
        if ui.input(|i| i.key_pressed(egui::Key::Escape)) {
            self.settings_open = false;
        }

        egui::Panel::left("settings_nav")
            .exact_size(220.0)
            .show_separator_line(false)
            .frame(
                Frame::new()
                    .fill(pal.sidebar_bg)
                    .inner_margin(Margin::symmetric(14, 22)),
            )
            .show(ui, |ui| {
                ui.label(
                    RichText::new("USER SETTINGS")
                        .size(11.0)
                        .strong()
                        .color(pal.text_muted),
                );
                ui.add_space(8.0);

                for (sec, label) in [
                    (SettingsSection::Account, "My Account & Profile"),
                    (SettingsSection::Theme, "Appearance & Theme"),
                    (SettingsSection::Connection, "Connection & Network"),
                ] {
                    let active = self.settings_section == sec;
                    if ui
                        .selectable_label(active, RichText::new(label).size(14.0))
                        .clicked()
                    {
                        self.settings_section = sec;
                    }
                    ui.add_space(2.0);
                }

                ui.add_space(14.0);
                ui.separator();
                ui.add_space(10.0);
                if ui
                    .button(RichText::new("Switch Server / Log Out").color(pal.danger))
                    .clicked()
                {
                    self.spawn_disconnect(&ctx, true);
                }
            });

        egui::CentralPanel::default()
            .frame(
                Frame::new()
                    .fill(pal.chat_bg)
                    .inner_margin(Margin::symmetric(28, 22)),
            )
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    let heading = match self.settings_section {
                        SettingsSection::Account => "My Account & Profile",
                        SettingsSection::Theme => "Appearance & Theme",
                        SettingsSection::Connection => "Connection & Network",
                    };
                    ui.label(
                        RichText::new(heading)
                            .size(20.0)
                            .strong()
                            .color(pal.text_primary),
                    );
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui.button("Close (ESC)").clicked() {
                            self.settings_open = false;
                        }
                    });
                });
                ui.add_space(14.0);

                ScrollArea::vertical().show(ui, |ui| match self.settings_section {
                    SettingsSection::Account => self.render_settings_account(ui, &ctx, pal),
                    SettingsSection::Theme => self.render_settings_theme(ui, &ctx, pal),
                    SettingsSection::Connection => self.render_settings_connection(ui, &ctx, pal),
                });
            });
    }

    fn render_settings_account(
        &mut self,
        ui: &mut egui::Ui,
        ctx: &egui::Context,
        pal: &ThemePalette,
    ) {
        let me_name = if self.display_name.trim().is_empty() {
            self.client_id.clone()
        } else {
            self.display_name.clone()
        };

        Frame::new()
            .fill(pal.dock_bg)
            .corner_radius(CornerRadius::same(10))
            .inner_margin(Margin::same(18))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    paint_avatar(
                        ui,
                        68.0,
                        &self.client_id,
                        &me_name,
                        Some(pal.online),
                        pal.dock_bg,
                        self.avatar_texture.as_ref(),
                    );
                    ui.add_space(12.0);
                    ui.vertical(|ui| {
                        ui.label(
                            RichText::new(&me_name)
                                .size(17.0)
                                .strong()
                                .color(pal.text_primary),
                        );
                        ui.label(
                            RichText::new(format!("Handle: @{}", self.client_id))
                                .size(12.5)
                                .color(pal.text_muted),
                        );
                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            if ui.button("Change Avatar").clicked() {
                                if let Some(p) = rfd::FileDialog::new()
                                    .add_filter("Images", &["png", "jpg", "jpeg"])
                                    .pick_file()
                                {
                                    self.profile_photo = p.display().to_string();
                                    self.refresh_avatar_texture(ctx);
                                }
                            }
                            if !self.profile_photo.is_empty() && ui.button("Remove Photo").clicked()
                            {
                                self.profile_photo.clear();
                                self.refresh_avatar_texture(ctx);
                            }
                        });
                    });
                });
            });

        ui.add_space(14.0);
        egui::Grid::new("acc_fields")
            .num_columns(2)
            .spacing([14.0, 10.0])
            .show(ui, |ui| {
                ui.label("Display Name:");
                ui.add(egui::TextEdit::singleline(&mut self.display_name).desired_width(280.0));
                ui.end_row();

                ui.label("User Handle (ID):");
                ui.add(egui::TextEdit::singleline(&mut self.client_id).desired_width(280.0));
                ui.end_row();

                ui.label("Language:");
                egui::ComboBox::from_id_salt("ui_lang")
                    .selected_text(if self.profile_lang == "fa" {
                        "Persian (fa)"
                    } else {
                        "English (en)"
                    })
                    .show_ui(ui, |ui| {
                        ui.selectable_value(
                            &mut self.profile_lang,
                            "en".to_string(),
                            "English (en)",
                        );
                        ui.selectable_value(
                            &mut self.profile_lang,
                            "fa".to_string(),
                            "Persian (fa)",
                        );
                    });
                ui.end_row();
            });

        ui.add_space(12.0);
        if ui
            .add(
                egui::Button::new(RichText::new("Save Account Changes").color(Color32::WHITE).strong())
                    .fill(pal.blurple),
            )
            .clicked()
        {
            match self.save_settings_to_disk() {
                Ok(()) => self.set_notice("Account & profile saved.", false),
                Err(e) => self.set_notice(e, true),
            }
        }

        ui.add_space(16.0);
        ui.checkbox(&mut self.show_account_login, "Server Username Sign-In / Admin User Creation");
        if self.show_account_login {
            ui.add_space(8.0);
            Frame::new()
                .fill(pal.sidebar_bg)
                .stroke(Stroke::new(1.0, pal.border))
                .corner_radius(CornerRadius::same(8))
                .inner_margin(Margin::same(14))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label("Username:");
                        ui.add(egui::TextEdit::singleline(&mut self.login_username).desired_width(140.0));
                        ui.label("Password:");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.login_password)
                                .password(true)
                                .desired_width(140.0),
                        );
                        if ui.button("Sign In").clicked() {
                            self.spawn_account_login(ctx);
                        }
                    });
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        ui.label("New User:");
                        ui.add(egui::TextEdit::singleline(&mut self.new_user_name).desired_width(130.0));
                        ui.label("Pass:");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.new_user_pass)
                                .password(true)
                                .desired_width(130.0),
                        );
                        ui.checkbox(&mut self.new_user_admin, "Admin");
                        if ui.button("Create").clicked() {
                            self.spawn_create_user(ctx);
                        }
                    });
                });
        }
    }

    fn render_settings_theme(
        &mut self,
        ui: &mut egui::Ui,
        ctx: &egui::Context,
        pal: &ThemePalette,
    ) {
        ui.label(RichText::new("THEME").size(11.0).strong().color(pal.text_muted));
        ui.add_space(8.0);
        ui.horizontal_wrapped(|ui| {
            for mode in [ThemeMode::DiscordDark, ThemeMode::Midnight, ThemeMode::Light] {
                let p = palette(mode);
                let active = self.theme_mode == mode;
                let frame = Frame::new()
                    .fill(p.chat_bg)
                    .stroke(Stroke::new(
                        if active { 2.5 } else { 1.0 },
                        if active { pal.blurple } else { pal.border },
                    ))
                    .corner_radius(CornerRadius::same(10))
                    .inner_margin(Margin::same(14));
                let resp = frame
                    .show(ui, |ui| {
                        ui.set_min_size(Vec2::new(140.0, 56.0));
                        ui.vertical(|ui| {
                            ui.label(
                                RichText::new(mode.label())
                                    .strong()
                                    .color(p.text_primary),
                            );
                            ui.label(
                                RichText::new(if active { "Active" } else { "Select" })
                                    .size(11.5)
                                    .color(if active { pal.blurple } else { p.text_muted }),
                            );
                        });
                    })
                    .response
                    .interact(Sense::click());
                if resp.clicked() {
                    self.theme_mode = mode;
                    apply_theme_to_ctx(ctx, mode, self.font_size);
                    let _ = self.save_settings_to_disk();
                }
            }
        });

        ui.add_space(16.0);
        ui.label(
            RichText::new("MESSAGE DISPLAY")
                .size(11.0)
                .strong()
                .color(pal.text_muted),
        );
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            if ui
                .selectable_label(!self.compact_messages, "Cozy (Default)")
                .clicked()
            {
                self.compact_messages = false;
            }
            if ui
                .selectable_label(self.compact_messages, "Compact")
                .clicked()
            {
                self.compact_messages = true;
            }
        });

        ui.add_space(12.0);
        ui.horizontal(|ui| {
            ui.label("Font Size:");
            if ui
                .add(egui::Slider::new(&mut self.font_size, 12.5..=18.0).step_by(0.5))
                .changed()
            {
                apply_theme_to_ctx(ctx, self.theme_mode, self.font_size);
            }
        });
    }

    fn render_settings_connection(
        &mut self,
        ui: &mut egui::Ui,
        ctx: &egui::Context,
        pal: &ThemePalette,
    ) {
        ui.horizontal(|ui| {
            let (lbl, col) = match &self.conn_state {
                ConnectionState::Online => ("Connected", pal.online),
                ConnectionState::Connecting => ("Connecting...", pal.idle),
                ConnectionState::Reconnecting { attempt } => {
                    let _ = attempt;
                    ("Reconnecting...", pal.idle)
                }
                ConnectionState::Disconnected => ("Disconnected", pal.danger),
            };
            status_pill(ui, pal, lbl, col);
            if !self.active_vpns.is_empty() {
                status_pill(
                    ui,
                    pal,
                    &format!("VPN Active: {}", self.active_vpns.join(", ")),
                    pal.online,
                );
            }
        });

        ui.add_space(12.0);
        egui::Grid::new("conn_settings_grid")
            .num_columns(2)
            .spacing([14.0, 10.0])
            .show(ui, |ui| {
                ui.label("Server Address:");
                ui.add(egui::TextEdit::singleline(&mut self.server_input).desired_width(300.0));
                ui.end_row();

                ui.label("Invite Code:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.invite_code)
                        .hint_text("Optional")
                        .desired_width(300.0),
                );
                ui.end_row();
            });

        ui.add_space(8.0);
        ui.checkbox(
            &mut self.auto_reconnect,
            "Automatically reconnect after Wi-Fi / VPN switches",
        );

        ui.add_space(10.0);
        ui.horizontal(|ui| {
            if ui
                .add(
                    egui::Button::new(
                        RichText::new("Save & Reconnect")
                            .color(Color32::WHITE)
                            .strong(),
                    )
                    .fill(pal.blurple),
                )
                .clicked()
            {
                let _ = self.save_settings_to_disk();
                self.spawn_auto_connect(ctx);
            }
            if ui.button("Scan Nearby Servers").clicked() {
                self.spawn_background_probe(ctx);
            }
        });

        if !self.discovered_servers.is_empty() {
            ui.add_space(10.0);
            ui.label(
                RichText::new("AVAILABLE SERVERS")
                    .size(11.0)
                    .strong()
                    .color(pal.text_muted),
            );
            let list = self.discovered_servers.clone();
            for m in list {
                ui.horizontal(|ui| {
                    ui.colored_label(pal.online, "●");
                    ui.label(&m.url);
                    if ui.small_button("Use").clicked() {
                        self.server_input = m.url;
                        if let Some(ref pin) = m.tls_cert_sha256_hex {
                            self.tls_pin_hex = pin.clone();
                        }
                    }
                    for alt in m.alternate_urls {
                        if ui.small_button(format!("Use {alt}")).clicked() {
                            self.server_input = alt;
                            if let Some(ref pin) = m.tls_cert_sha256_hex {
                                self.tls_pin_hex = pin.clone();
                            }
                        }
                    }
                });
            }
        }

        ui.add_space(14.0);
        ui.checkbox(&mut self.show_advanced_tls, "Advanced Security Options");
        if self.show_advanced_tls {
            ui.add_space(6.0);
            Frame::new()
                .fill(pal.sidebar_bg)
                .stroke(Stroke::new(1.0, pal.border))
                .corner_radius(CornerRadius::same(8))
                .inner_margin(Margin::same(14))
                .show(ui, |ui| {
                    egui::Grid::new("adv_tls_grid")
                        .num_columns(2)
                        .spacing([10.0, 8.0])
                        .show(ui, |ui| {
                            ui.label("Room Passphrase (optional):");
                            ui.add(
                                egui::TextEdit::singleline(&mut self.shared_passphrase)
                                    .password(true)
                                    .desired_width(260.0),
                            );
                            ui.end_row();

                            ui.label("TLS Fingerprint Pin:");
                            ui.add(
                                egui::TextEdit::singleline(&mut self.tls_pin_hex)
                                    .hint_text("Auto-fetched via discovery")
                                    .desired_width(260.0),
                            );
                            ui.end_row();

                            ui.label("Custom CA PEM:");
                            ui.horizontal(|ui| {
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.tls_ca_pem_path)
                                        .desired_width(200.0),
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
                        });
                    ui.checkbox(
                        &mut self.insecure_http,
                        "Allow unencrypted HTTP/WS (local testing only)",
                    );
                });
        }

        if let Some((ref msg, is_err)) = self.toast_notice {
            ui.add_space(10.0);
            ui.label(
                RichText::new(msg)
                    .size(12.5)
                    .color(if is_err { pal.danger } else { pal.online }),
            );
        }
    }
}

impl eframe::App for EazyUiApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.poll_events(&ctx);
        let pal = palette(self.theme_mode);

        if self.settings_open {
            self.render_settings_view(ui, &pal);
            return;
        }

        match self.screen {
            AppScreen::Onboarding => self.render_onboarding(ui, &pal),
            AppScreen::Chat => self.render_discord_workspace(ui, &pal),
        }
    }
}

fn friendly_connect_error(raw: &str) -> String {
    if raw.contains("os error 10013") {
        "Local connection blocked by firewall (enable 'Allow LAN Traffic' in your VPN app or use localhost / VPN IP)."
            .to_string()
    } else if raw.contains("certificate") || raw.contains("UnknownIssuer") {
        "Server certificate check failed — try clicking 'Scan Nearby Servers' or entering the server fingerprint in Settings -> Connection."
            .to_string()
    } else if raw.contains("invite") {
        "This workspace requires a valid Invite Code.".to_string()
    } else {
        raw.to_string()
    }
}

fn load_cropped_square_avatar(path: &Path, target_px: u32) -> Option<ColorImage> {
    let bytes = fs::read(path).ok()?;
    let dyn_img = image::load_from_memory(&bytes).ok()?;
    let rgba = dyn_img.to_rgba8();
    let (w, h) = rgba.dimensions();
    let side = w.min(h);
    if side == 0 {
        return None;
    }
    let ox = (w - side) / 2;
    let oy = (h - side) / 2;
    let cropped = image::imageops::crop_imm(&rgba, ox, oy, side, side).to_image();
    let resized = image::imageops::resize(
        &cropped,
        target_px,
        target_px,
        image::imageops::FilterType::Triangle,
    );
    Some(ColorImage::from_rgba_unmultiplied(
        [target_px as usize, target_px as usize],
        resized.as_raw(),
    ))
}
