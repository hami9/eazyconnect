use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::ws::{Message, WebSocket};
use cubehash_core::PayloadMode;
use eazyconnect_core::{
    epoch_hop_sign_bytes, pair_offer_sign_bytes, relay_auth_challenge_sign_bytes, PeerIdentity,
    RelayFrame, RelayTelemetrySnapshot, RelayTrafficEvent,
};
use eazyconnect_hw::{validate_id, DeviceIdentity};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::{mpsc, oneshot, RwLock};

use crate::auth::AuthStore;

const MAX_TELEMETRY_HISTORY: usize = 100;
const WS_AUTH_TIMEOUT: Duration = Duration::from_secs(10);
const WS_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(20);
const WS_IDLE_TIMEOUT: Duration = Duration::from_secs(65);

struct ActivePeer {
    conn_id: u64,
    current_wire: bool,
    ed25519_pub: [u8; 32],
    tx: mpsc::UnboundedSender<Message>,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

/// Zero-knowledge blind relay state embedded in `eazyconnect-server`.
/// Shares identity pins with REST `AuthStore` so impersonation is blocked across both surfaces.
#[derive(Clone)]
pub struct BlindRelayState {
    auth_store: Arc<RwLock<AuthStore>>,
    clients: Arc<RwLock<HashMap<String, ActivePeer>>>,
    telemetry: Arc<RwLock<VecDeque<RelayTrafficEvent>>>,
    seq_counter: Arc<AtomicU64>,
    conn_counter: Arc<AtomicU64>,
    started_at: Instant,
}

impl BlindRelayState {
    pub fn new(auth_store: Arc<RwLock<AuthStore>>) -> Self {
        Self {
            auth_store,
            clients: Arc::new(RwLock::new(HashMap::new())),
            telemetry: Arc::new(RwLock::new(VecDeque::new())),
            seq_counter: Arc::new(AtomicU64::new(0)),
            conn_counter: Arc::new(AtomicU64::new(0)),
            started_at: Instant::now(),
        }
    }

    pub async fn online_count(&self) -> usize {
        self.clients.read().await.len()
    }

    pub(crate) fn uptime_seconds(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }

    pub async fn snapshot(&self) -> RelayTelemetrySnapshot {
        let mut peers: Vec<String> = self.clients.read().await.keys().cloned().collect();
        peers.sort();
        let telemetry = self.telemetry.read().await;
        RelayTelemetrySnapshot {
            online_peers: peers,
            total_routed_frames: self.seq_counter.load(Ordering::Relaxed),
            recent_frames: telemetry.iter().cloned().collect(),
        }
    }

    async fn record_event(&self, mut event: RelayTrafficEvent) {
        let mut guard = self.telemetry.write().await;
        event.seq = self.seq_counter.fetch_add(1, Ordering::Relaxed) + 1;
        if guard.len() >= MAX_TELEMETRY_HISTORY {
            guard.pop_front();
        }
        guard.push_back(event);
    }

    async fn broadcast_peer_list(&self) {
        let clients = self.clients.read().await;
        send_peer_list(&clients);
    }

    pub(crate) async fn set_device_blocked(
        &self,
        client_id: &str,
        blocked: bool,
    ) -> Result<(), (u16, String)> {
        let mut store = self.auth_store.write().await;
        if !blocked {
            return store.set_device_blocked(client_id, false);
        }

        // Acquire both locks before persisting the block so cancellation cannot leave a
        // live relay session for a device whose access was disabled.
        let mut clients = self.clients.write().await;
        store.set_device_blocked(client_id, true)?;
        if let Some(peer) = clients.remove(client_id) {
            if let Some(shutdown) = peer.shutdown_tx {
                let _ = shutdown.send(());
            }
            send_peer_list(&clients);
        }
        Ok(())
    }

    async fn forward_to(&self, conn_id: u64, raw_json: String, event: RelayTrafficEvent) {
        let clients = self.clients.read().await;
        let Some(sender) = clients
            .get(&event.from)
            .filter(|peer| peer.conn_id == conn_id)
        else {
            return;
        };
        let (peer, message) = match clients.get(&event.to) {
            Some(target) if target.current_wire != sender.current_wire => {
                let err = RelayFrame::RelayError {
                    code: "cubehash_version_mismatch".to_string(),
                    detail: format!("Both clients must use the same CubeHash wire version to connect to '{}'. Update both clients to CubeHash 1.0.2.", event.to),
                    peer: Some(event.to),
                };
                if let Ok(text) = serde_json::to_string(&err) {
                    let _ = sender.tx.send(Message::Text(text.into()));
                }
                return;
            }
            Some(target) => (target, Some(raw_json)),
            None => {
                let err = RelayFrame::RelayError {
                    code: "peer_offline".to_string(),
                    detail: format!("recipient '{}' is not connected", event.to),
                    peer: Some(event.to.clone()),
                };
                (sender, serde_json::to_string(&err).ok())
            }
        };
        self.record_event(event).await;
        if let Some(text) = message {
            let _ = peer.tx.send(Message::Text(text.into()));
        }
    }
}

fn send_peer_list(clients: &HashMap<String, ActivePeer>) {
    let online_peers = peer_identities(clients);
    let Ok(payload) = serde_json::to_string(&RelayFrame::PeerList { online_peers }) else {
        return;
    };
    for entry in clients.values() {
        let _ = entry.tx.send(Message::Text(payload.clone().into()));
    }
}

fn peer_identities(clients: &HashMap<String, ActivePeer>) -> Vec<PeerIdentity> {
    let mut peers: Vec<PeerIdentity> = clients
        .iter()
        .map(|(client_id, peer)| PeerIdentity {
            client_id: client_id.clone(),
            ed25519_pub: peer.ed25519_pub,
        })
        .collect();
    peers.sort_by(|a, b| a.client_id.cmp(&b.client_id));
    peers
}

async fn send_ws_error(tx: &mpsc::UnboundedSender<Message>, code: &str, detail: &str) {
    let err = RelayFrame::RelayError {
        code: code.to_string(),
        detail: detail.to_string(),
        peer: None,
    };
    if let Ok(txt) = serde_json::to_string(&err) {
        let _ = tx.send(Message::Text(txt.into()));
    }
}

pub async fn handle_relay_socket(socket: WebSocket, state: BlindRelayState) {
    let conn_id = state.conn_counter.fetch_add(1, Ordering::Relaxed) + 1;
    let current_wire = socket.protocol().is_some();
    let (mut ws_tx, mut ws_rx) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();

    let writer_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if ws_tx.send(msg).await.is_err() {
                break;
            }
        }
    });

    let mut challenge_nonce = [0u8; 32];
    if getrandom::getrandom(&mut challenge_nonce).is_err() {
        writer_task.abort();
        return;
    }
    let challenge = RelayFrame::AuthChallenge {
        nonce: challenge_nonce,
    };
    if let Ok(txt) = serde_json::to_string(&challenge) {
        if tx.send(Message::Text(txt.into())).is_err() {
            writer_task.abort();
            return;
        }
    }

    let mut authed: Option<(String, [u8; 32], oneshot::Receiver<()>)> = None;
    let deadline = tokio::time::Instant::now() + WS_AUTH_TIMEOUT;

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            send_ws_error(&tx, "auth_timeout", "Ed25519 challenge timed out").await;
            break;
        }
        let Ok(next_item) = tokio::time::timeout(remaining, ws_rx.next()).await else {
            send_ws_error(&tx, "auth_timeout", "Ed25519 challenge timed out").await;
            break;
        };
        let Some(Ok(msg)) = next_item else {
            break;
        };
        match &msg {
            Message::Ping(p) => {
                let _ = tx.send(Message::Pong(p.clone()));
                continue;
            }
            Message::Pong(_) => continue,
            Message::Close(_) => break,
            _ => {}
        }
        let Message::Text(text) = msg else {
            continue;
        };
        let Ok(frame) = serde_json::from_str::<RelayFrame>(&text) else {
            continue;
        };

        match frame {
            RelayFrame::RegisterAuth {
                client_id,
                ed25519_pub,
                signature,
            } => {
                let Ok(clean_id) = validate_id(&client_id) else {
                    send_ws_error(&tx, "invalid_id", "client_id invalid").await;
                    break;
                };
                let sign_msg = relay_auth_challenge_sign_bytes(&challenge_nonce, &clean_id);
                if !DeviceIdentity::verify_signature(&ed25519_pub, &sign_msg, &signature) {
                    send_ws_error(&tx, "auth_failed", "invalid Ed25519 challenge signature").await;
                    break;
                }

                let mut store = state.auth_store.write().await;
                if let Err((_, err_msg)) =
                    store.check_or_pin_device_key(&clean_id, ed25519_pub, None)
                {
                    drop(store);
                    send_ws_error(&tx, "identity_mismatch", &err_msg).await;
                    break;
                }

                // Keep the auth lock until registration is visible to device access changes.
                let (shutdown_tx, shutdown_rx) = oneshot::channel();
                let displaced = {
                    let mut clients = state.clients.write().await;
                    let displaced = clients.insert(
                        clean_id.clone(),
                        ActivePeer {
                            conn_id,
                            current_wire,
                            ed25519_pub,
                            tx: tx.clone(),
                            shutdown_tx: Some(shutdown_tx),
                        },
                    );
                    let reg = RelayFrame::Registered {
                        client_id: clean_id.clone(),
                        online_peers: peer_identities(&clients),
                    };
                    if let Ok(txt) = serde_json::to_string(&reg) {
                        let _ = tx.send(Message::Text(txt.into()));
                    }
                    displaced
                };
                drop(store);
                if let Some(mut old_peer) = displaced {
                    send_ws_error(
                        &old_peer.tx,
                        "session_replaced",
                        "client_id session reclaimed by verified Ed25519 reconnect",
                    )
                    .await;
                    let _ = old_peer.tx.send(Message::Close(None));
                    if let Some(sig) = old_peer.shutdown_tx.take() {
                        let _ = sig.send(());
                    }
                }

                authed = Some((clean_id, ed25519_pub, shutdown_rx));
                state.broadcast_peer_list().await;
                break;
            }
            _ => {
                send_ws_error(&tx, "unauthenticated", "complete RegisterAuth first").await;
            }
        }
    }

    let Some((authed_id, authed_pub, mut shutdown_rx)) = authed else {
        tokio::time::sleep(Duration::from_millis(25)).await;
        writer_task.abort();
        return;
    };

    let mut heartbeat = tokio::time::interval(WS_HEARTBEAT_INTERVAL);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    heartbeat.tick().await;
    let mut last_rx = tokio::time::Instant::now();

    loop {
        let msg = tokio::select! {
            biased;
            _ = &mut shutdown_rx => break,
            _ = heartbeat.tick() => {
                if last_rx.elapsed() > WS_IDLE_TIMEOUT {
                    send_ws_error(&tx, "idle_timeout", "WebSocket keepalive expired").await;
                    break;
                }
                if tx.send(Message::Ping(Vec::new().into())).is_err() {
                    break;
                }
                continue;
            }
            maybe_ws = ws_rx.next() => {
                match maybe_ws {
                    Some(Ok(msg)) => msg,
                    _ => break,
                }
            }
        };

        last_rx = tokio::time::Instant::now();
        let text = match msg {
            Message::Text(text) => text,
            Message::Ping(payload) => {
                let _ = tx.send(Message::Pong(payload));
                continue;
            }
            Message::Pong(_) => continue,
            Message::Close(_) => break,
            Message::Binary(_) => continue,
        };
        let Ok(frame) = serde_json::from_str::<RelayFrame>(&text) else {
            continue;
        };

        let claimed_from = match &frame {
            RelayFrame::PairOffer { from, .. }
            | RelayFrame::PairAccept { from, .. }
            | RelayFrame::EncryptedPacket { from, .. }
            | RelayFrame::AckFrame { from, .. }
            | RelayFrame::EpochHopNotice { from, .. } => Some(from.as_str()),
            _ => None,
        };
        if let Some(sender) = claimed_from {
            if sender != authed_id {
                send_ws_error(
                    &tx,
                    "spoofed_sender",
                    "frame 'from' does not match authenticated Ed25519 identity",
                )
                .await;
                continue;
            }
        }

        match &frame {
            RelayFrame::PairOffer {
                from,
                to,
                pair_id,
                eph_pub,
                init_rx_dh_pub,
                sender_ed25519_pub,
                profile,
                has_psk,
                signature,
            } => {
                let sign_msg = pair_offer_sign_bytes(
                    from,
                    to,
                    pair_id,
                    eph_pub,
                    init_rx_dh_pub,
                    sender_ed25519_pub,
                    *profile,
                    *has_psk,
                );
                if sender_ed25519_pub != &authed_pub
                    || !DeviceIdentity::verify_signature(sender_ed25519_pub, &sign_msg, signature)
                {
                    send_ws_error(&tx, "bad_signature", "PairOffer failed Ed25519 check").await;
                    continue;
                }
                state
                    .forward_to(
                        conn_id,
                        text.to_string(),
                        RelayTrafficEvent {
                            seq: 0,
                            frame_type: "PairOffer (Ed25519+X25519)".to_string(),
                            from: from.clone(),
                            to: to.clone(),
                            wire_fingerprint_hex: None,
                            wire_base_bytes: None,
                            wire_total_bytes: None,
                            ciphertext_bytes: None,
                        },
                    )
                    .await;
            }
            RelayFrame::PairAccept {
                from,
                to,
                sender_ed25519_pub,
                ..
            } => {
                if sender_ed25519_pub != &authed_pub {
                    send_ws_error(&tx, "bad_signature", "PairAccept Ed25519 key mismatch").await;
                    continue;
                }
                state
                    .forward_to(
                        conn_id,
                        text.to_string(),
                        RelayTrafficEvent {
                            seq: 0,
                            frame_type: "PairAccept (Ed25519+X25519)".to_string(),
                            from: from.clone(),
                            to: to.clone(),
                            wire_fingerprint_hex: None,
                            wire_base_bytes: None,
                            wire_total_bytes: None,
                            ciphertext_bytes: None,
                        },
                    )
                    .await;
            }
            RelayFrame::EncryptedPacket {
                from, to, packet, ..
            } => {
                let ct_bytes = match &packet.payload_mode {
                    PayloadMode::RawCore256 => Some(0),
                    PayloadMode::ArbitraryCiphertext { ciphertext } => Some(ciphertext.len()),
                };
                state
                    .forward_to(
                        conn_id,
                        text.to_string(),
                        RelayTrafficEvent {
                            seq: 0,
                            frame_type: if matches!(packet.payload_mode, PayloadMode::RawCore256) {
                                "WirePacket (RawCore256)".to_string()
                            } else {
                                "WirePacket (ArbitraryAEAD)".to_string()
                            },
                            from: from.clone(),
                            to: to.clone(),
                            wire_fingerprint_hex: Some(hex::encode(
                                packet.wire_cube.cube_fingerprint,
                            )),
                            wire_base_bytes: Some(packet.wire_cube.base_byte_len()),
                            wire_total_bytes: Some(packet.wire_cube.total_byte_len()),
                            ciphertext_bytes: ct_bytes,
                        },
                    )
                    .await;
            }
            RelayFrame::AckFrame { from, to, ack, .. } => {
                state
                    .forward_to(
                        conn_id,
                        text.to_string(),
                        RelayTrafficEvent {
                            seq: 0,
                            frame_type: "DeliveryAck".to_string(),
                            from: from.clone(),
                            to: to.clone(),
                            wire_fingerprint_hex: Some(hex::encode(ack.cube_fingerprint)),
                            wire_base_bytes: None,
                            wire_total_bytes: None,
                            ciphertext_bytes: None,
                        },
                    )
                    .await;
            }
            RelayFrame::EpochHopNotice {
                from,
                to,
                new_epoch,
                epoch_eph_pub,
                sender_ed25519_pub,
                signature,
            } => {
                let sign_msg =
                    epoch_hop_sign_bytes(from, to, *new_epoch, epoch_eph_pub, sender_ed25519_pub);
                if sender_ed25519_pub != &authed_pub
                    || !DeviceIdentity::verify_signature(sender_ed25519_pub, &sign_msg, signature)
                {
                    send_ws_error(&tx, "bad_signature", "EpochHopNotice failed Ed25519 check")
                        .await;
                    continue;
                }
                state
                    .forward_to(
                        conn_id,
                        text.to_string(),
                        RelayTrafficEvent {
                            seq: 0,
                            frame_type: "EpochHopNotice (Signed+DH)".to_string(),
                            from: from.clone(),
                            to: to.clone(),
                            wire_fingerprint_hex: None,
                            wire_base_bytes: None,
                            wire_total_bytes: None,
                            ciphertext_bytes: None,
                        },
                    )
                    .await;
            }
            RelayFrame::AuthChallenge { .. }
            | RelayFrame::RegisterAuth { .. }
            | RelayFrame::Registered { .. }
            | RelayFrame::PeerList { .. }
            | RelayFrame::RelayError { .. } => {}
        }
    }

    let removed = {
        let mut guard = state.clients.write().await;
        if guard.get(&authed_id).is_some_and(|e| e.conn_id == conn_id) {
            guard.remove(&authed_id);
            true
        } else {
            false
        }
    };
    if removed {
        state.broadcast_peer_list().await;
    }
    writer_task.abort();
}
