use std::collections::{HashMap, VecDeque};
use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex};

use cubehash_core::{DuplexCubeSession, HoneyProfile, MeshAuditStats, ReceiveOutcome};
use eazyconnect_core::{
    decode_app_payload, encode_app_payload, epoch_hop_sign_bytes, pair_accept_sign_bytes,
    pair_offer_sign_bytes, parse_endpoint_url, provision_duplex_from_ecdh,
    relay_auth_challenge_sign_bytes, ClientTlsConfig, EazyAppMessage, EazyMeshProfile,
    PairTranscriptParams, PeerIdentity, RelayFrame,
};
use eazyconnect_hw::{
    collect_hardware_report, send_serial_command, DeviceIdentity, SerialTransport,
};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc, oneshot, Mutex};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Send {}
impl<T: AsyncRead + AsyncWrite + Send> AsyncReadWrite for T {}
type BoxedStream = Pin<Box<dyn AsyncReadWrite>>;

#[derive(Debug, Clone)]
pub struct NodeConnectOptions {
    pub ws_url: String,
    pub tls_config: ClientTlsConfig,
    pub allow_insecure_ws: bool,
    pub allow_remote_serial_os_fallback: bool,
    pub allow_remote_hw_probe: bool,
}

#[derive(Debug, Clone)]
pub enum NodeEvent {
    Registered {
        client_id: String,
        online_peers: Vec<PeerIdentity>,
    },
    PeerListUpdated {
        online_peers: Vec<PeerIdentity>,
    },
    IncomingPairOffer {
        pair_id: String,
        from: String,
        profile: EazyMeshProfile,
        has_psk: bool,
    },
    Paired {
        peer: String,
        safety_fingerprint: String,
        epoch: u64,
    },
    MessageReceived {
        from: String,
        msg_id: String,
        msg: EazyAppMessage,
        healed_bits: usize,
        epoch: u64,
    },
    DeliveryAcked {
        from: String,
        msg_id: String,
    },
    HoneyDecoyTriggered {
        from: String,
        msg_id: String,
        plausible_preview: String,
    },
    EpochHopped {
        peer: String,
        new_epoch: u64,
    },
    RelayError {
        code: String,
        detail: String,
        peer: Option<String>,
    },
    Disconnected {
        reason: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairedResult {
    pub peer: String,
    pub safety_fingerprint: String,
    pub epoch: u64,
}

struct OutboundOffer {
    peer_id: String,
    profile: EazyMeshProfile,
    psk: Vec<u8>,
    eph_secret: [u8; 32],
    eph_pub: [u8; 32],
    init_rx_secret: [u8; 32],
    init_rx_pub: [u8; 32],
}

impl Drop for OutboundOffer {
    fn drop(&mut self) {
        self.psk.zeroize();
        self.eph_secret.zeroize();
        self.init_rx_secret.zeroize();
    }
}

struct InboundOffer {
    from: String,
    pair_id: String,
    profile: EazyMeshProfile,
    peer_eph_pub: [u8; 32],
    peer_init_rx_pub: [u8; 32],
    peer_ed25519_pub: [u8; 32],
    has_psk: bool,
}

struct PendingAppSend {
    msg: EazyAppMessage,
    done_tx: oneshot::Sender<Result<String, String>>,
}

struct InflightAppSend {
    msg_id: String,
    done_tx: oneshot::Sender<Result<String, String>>,
}

struct PeerSessionEntry {
    peer_ed25519_pub: [u8; 32],
    safety_fingerprint: String,
    session: DuplexCubeSession,
    inflight: Option<InflightAppSend>,
    outbound_queue: VecDeque<PendingAppSend>,
}

enum NodeCommand {
    SendPairOffer {
        peer_id: String,
        profile: EazyMeshProfile,
        psk: Vec<u8>,
        reply: oneshot::Sender<Result<String, String>>,
    },
    AcceptPairOffer {
        pair_id: String,
        psk: Vec<u8>,
        reply: oneshot::Sender<Result<PairedResult, String>>,
    },
    SendAppMessage {
        peer_id: String,
        msg: EazyAppMessage,
        reply: oneshot::Sender<Result<String, String>>,
    },
    SendTamperedProbe {
        peer_id: String,
        reply: oneshot::Sender<Result<(), String>>,
    },
    HopEpoch {
        peer_id: String,
        reply: oneshot::Sender<Result<u64, String>>,
    },
    GetOnlinePeers {
        reply: oneshot::Sender<Vec<PeerIdentity>>,
    },
    GetSessionAudit {
        peer_id: String,
        reply: oneshot::Sender<Result<(String, MeshAuditStats, MeshAuditStats), String>>,
    },
    AttachSerialBridge {
        port: String,
        transport: Arc<StdMutex<Box<dyn SerialTransport>>>,
    },
    Shutdown,
}

pub struct EazyNode {
    client_id: String,
    ed25519_pub: [u8; 32],
    cmd_tx: mpsc::UnboundedSender<NodeCommand>,
    events_tx: broadcast::Sender<NodeEvent>,
    task_handle: Option<JoinHandle<()>>,
}

impl EazyNode {
    pub async fn connect(
        identity: DeviceIdentity,
        opts: NodeConnectOptions,
    ) -> Result<Self, String> {
        let ws_url = normalize_ws_url(&opts.ws_url)?;
        let endpoint = parse_endpoint_url(&ws_url)?;
        if !endpoint.is_tls && !opts.allow_insecure_ws {
            return Err(format!(
                "refusing plaintext ws:// connection '{}' without allow_insecure_ws opt-in",
                endpoint.full_url
            ));
        }

        let tcp = TcpStream::connect(&endpoint.tcp_addr)
            .await
            .map_err(|e| format!("failed to connect TCP {} for WS: {e}", endpoint.tcp_addr))?;

        let stream: BoxedStream = if endpoint.is_tls {
            let connector = opts.tls_config.build_connector()?;
            let tls_stream = connector
                .connect(endpoint.server_name.clone(), tcp)
                .await
                .map_err(|e| format!("WSS TLS handshake failed: {e}"))?;
            Box::pin(tls_stream)
        } else {
            Box::pin(tcp)
        };

        let (mut ws_stream, _resp) = tokio_tungstenite::client_async(&ws_url, stream)
            .await
            .map_err(|e| format!("WebSocket upgrade failed on {ws_url}: {e}"))?;

        let challenge_nonce = loop {
            match ws_stream.next().await {
                Some(Ok(WsMessage::Text(txt))) => {
                    let frame: RelayFrame = serde_json::from_str(&txt)
                        .map_err(|e| format!("invalid relay frame during auth: {e}"))?;
                    match frame {
                        RelayFrame::AuthChallenge { nonce } => break nonce,
                        RelayFrame::RelayError { code, detail, .. } => {
                            return Err(format!("relay error ({code}): {detail}"));
                        }
                        _ => {}
                    }
                }
                Some(Ok(WsMessage::Close(_))) | None => {
                    return Err("relay closed connection before auth challenge".to_string());
                }
                Some(Ok(_)) => continue,
                Some(Err(e)) => return Err(format!("WS error waiting for challenge: {e}")),
            }
        };

        let sig_msg = relay_auth_challenge_sign_bytes(&challenge_nonce, identity.client_id());
        let reg = RelayFrame::RegisterAuth {
            client_id: identity.client_id().to_string(),
            ed25519_pub: identity.ed25519_pub(),
            signature: identity.sign(&sig_msg),
        };
        let reg_txt = serde_json::to_string(&reg).map_err(|e| e.to_string())?;
        ws_stream
            .send(WsMessage::Text(reg_txt.into()))
            .await
            .map_err(|e| format!("failed to send RegisterAuth: {e}"))?;

        let initial_peers = loop {
            match ws_stream.next().await {
                Some(Ok(WsMessage::Text(txt))) => {
                    let frame: RelayFrame = serde_json::from_str(&txt)
                        .map_err(|e| format!("invalid relay response: {e}"))?;
                    match frame {
                        RelayFrame::Registered { online_peers, .. } => break online_peers,
                        RelayFrame::RelayError { code, detail, .. } => {
                            return Err(format!("relay registration rejected ({code}): {detail}"));
                        }
                        _ => {}
                    }
                }
                Some(Ok(WsMessage::Close(_))) | None => {
                    return Err("relay closed connection during registration".to_string());
                }
                Some(Ok(_)) => continue,
                Some(Err(e)) => return Err(format!("WS error during registration: {e}")),
            }
        };

        let client_id = identity.client_id().to_string();
        let ed25519_pub = identity.ed25519_pub();
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (events_tx, _) = broadcast::channel(256);

        let _ = events_tx.send(NodeEvent::Registered {
            client_id: client_id.clone(),
            online_peers: initial_peers.clone(),
        });

        let events_clone = events_tx.clone();
        let cmd_tx_actor = cmd_tx.clone();
        let task_handle = tokio::spawn(run_node_actor(
            identity,
            ws_stream,
            initial_peers,
            cmd_rx,
            cmd_tx_actor,
            events_clone,
            opts.allow_remote_serial_os_fallback,
            opts.allow_remote_hw_probe,
        ));

        Ok(Self {
            client_id,
            ed25519_pub,
            cmd_tx,
            events_tx,
            task_handle: Some(task_handle),
        })
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    pub fn ed25519_pub(&self) -> [u8; 32] {
        self.ed25519_pub
    }

    pub fn subscribe(&self) -> broadcast::Receiver<NodeEvent> {
        self.events_tx.subscribe()
    }

    pub async fn online_peers(&self) -> Result<Vec<PeerIdentity>, String> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(NodeCommand::GetOnlinePeers { reply: tx })
            .map_err(|_| "node actor is closed".to_string())?;
        rx.await.map_err(|_| "node actor dropped reply".to_string())
    }

    pub async fn send_pair_offer(
        &self,
        peer_id: &str,
        profile: EazyMeshProfile,
        psk: &[u8],
    ) -> Result<String, String> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(NodeCommand::SendPairOffer {
                peer_id: peer_id.to_string(),
                profile,
                psk: psk.to_vec(),
                reply: tx,
            })
            .map_err(|_| "node actor is closed".to_string())?;
        rx.await.map_err(|_| "node actor dropped reply".to_string())?
    }

    pub async fn accept_pair_offer(
        &self,
        pair_id: &str,
        psk: &[u8],
    ) -> Result<PairedResult, String> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(NodeCommand::AcceptPairOffer {
                pair_id: pair_id.to_string(),
                psk: psk.to_vec(),
                reply: tx,
            })
            .map_err(|_| "node actor is closed".to_string())?;
        rx.await.map_err(|_| "node actor dropped reply".to_string())?
    }

    pub async fn send_app_message(
        &self,
        peer_id: &str,
        msg: EazyAppMessage,
    ) -> Result<String, String> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(NodeCommand::SendAppMessage {
                peer_id: peer_id.to_string(),
                msg,
                reply: tx,
            })
            .map_err(|_| "node actor is closed".to_string())?;
        rx.await.map_err(|_| "node actor dropped reply".to_string())?
    }

    pub async fn send_chat_message(&self, peer_id: &str, text: &str) -> Result<String, String> {
        self.send_app_message(
            peer_id,
            EazyAppMessage::ChatText {
                text: text.to_string(),
            },
        )
        .await
    }

    pub async fn send_file_notice(
        &self,
        peer_id: &str,
        owner: &str,
        filename: &str,
        blake3_hex: &str,
        size_bytes: u64,
        e2e: bool,
    ) -> Result<String, String> {
        self.send_app_message(
            peer_id,
            EazyAppMessage::FileShared {
                owner: owner.to_string(),
                filename: filename.to_string(),
                blake3_hex: blake3_hex.to_string(),
                size_bytes,
                e2e,
            },
        )
        .await
    }

    pub async fn send_serial_command_remote(
        &self,
        peer_id: &str,
        port: &str,
        baud_rate: u32,
        data: Vec<u8>,
    ) -> Result<String, String> {
        self.send_app_message(
            peer_id,
            EazyAppMessage::SerialCommand {
                port: port.to_string(),
                baud_rate,
                data,
            },
        )
        .await
    }

    pub async fn request_remote_hardware_probe(&self, peer_id: &str) -> Result<String, String> {
        self.send_app_message(peer_id, EazyAppMessage::HardwareProbeRequest)
            .await
    }

    pub async fn send_tampered_probe(&self, peer_id: &str) -> Result<(), String> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(NodeCommand::SendTamperedProbe {
                peer_id: peer_id.to_string(),
                reply: tx,
            })
            .map_err(|_| "node actor is closed".to_string())?;
        rx.await.map_err(|_| "node actor dropped reply".to_string())?
    }

    pub async fn hop_epoch(&self, peer_id: &str) -> Result<u64, String> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(NodeCommand::HopEpoch {
                peer_id: peer_id.to_string(),
                reply: tx,
            })
            .map_err(|_| "node actor is closed".to_string())?;
        rx.await.map_err(|_| "node actor dropped reply".to_string())?
    }

    pub async fn session_audit(
        &self,
        peer_id: &str,
    ) -> Result<(String, MeshAuditStats, MeshAuditStats), String> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(NodeCommand::GetSessionAudit {
                peer_id: peer_id.to_string(),
                reply: tx,
            })
            .map_err(|_| "node actor is closed".to_string())?;
        rx.await.map_err(|_| "node actor dropped reply".to_string())?
    }

    pub fn attach_serial_transport(
        &self,
        port: &str,
        transport: Box<dyn SerialTransport>,
    ) -> Result<(), String> {
        self.cmd_tx
            .send(NodeCommand::AttachSerialBridge {
                port: port.to_string(),
                transport: Arc::new(StdMutex::new(transport)),
            })
            .map_err(|_| "node actor is closed".to_string())
    }

    pub async fn shutdown(mut self) {
        let _ = self.cmd_tx.send(NodeCommand::Shutdown);
        if let Some(h) = self.task_handle.take() {
            let _ = h.await;
        }
    }
}

struct ActorState {
    identity: DeviceIdentity,
    online_peers: Vec<PeerIdentity>,
    outbound_offers: HashMap<String, OutboundOffer>,
    inbound_offers: HashMap<String, InboundOffer>,
    sessions: HashMap<String, PeerSessionEntry>,
    serial_bridges: HashMap<String, Arc<StdMutex<Box<dyn SerialTransport>>>>,
    allow_remote_serial_os_fallback: bool,
    allow_remote_hw_probe: bool,
    events_tx: broadcast::Sender<NodeEvent>,
    self_cmd_tx: mpsc::UnboundedSender<NodeCommand>,
}

#[allow(clippy::too_many_arguments)]
async fn run_node_actor(
    identity: DeviceIdentity,
    ws_stream: tokio_tungstenite::WebSocketStream<BoxedStream>,
    initial_peers: Vec<PeerIdentity>,
    mut cmd_rx: mpsc::UnboundedReceiver<NodeCommand>,
    self_cmd_tx: mpsc::UnboundedSender<NodeCommand>,
    events_tx: broadcast::Sender<NodeEvent>,
    allow_remote_serial_os_fallback: bool,
    allow_remote_hw_probe: bool,
) {
    let (ws_sink, mut ws_rx) = ws_stream.split();
    let ws_sink = Arc::new(Mutex::new(ws_sink));
    let mut state = ActorState {
        identity,
        online_peers: initial_peers,
        outbound_offers: HashMap::new(),
        inbound_offers: HashMap::new(),
        sessions: HashMap::new(),
        serial_bridges: HashMap::new(),
        allow_remote_serial_os_fallback,
        allow_remote_hw_probe,
        events_tx,
        self_cmd_tx,
    };

    loop {
        tokio::select! {
            maybe_cmd = cmd_rx.recv() => {
                let Some(cmd) = maybe_cmd else { break; };
                if matches!(cmd, NodeCommand::Shutdown) {
                    let _ = ws_sink.lock().await.close().await;
                    break;
                }
                handle_command(&mut state, &ws_sink, cmd).await;
            }
            maybe_ws = ws_rx.next() => {
                match maybe_ws {
                    Some(Ok(WsMessage::Text(txt))) => {
                        match serde_json::from_str::<RelayFrame>(&txt) {
                            Ok(frame) => handle_incoming_frame(&mut state, &ws_sink, frame).await,
                            Err(e) => {
                                let _ = state.events_tx.send(NodeEvent::RelayError {
                                    code: "bad_frame".to_string(),
                                    detail: format!("invalid JSON from relay: {e}"),
                                    peer: None,
                                });
                            }
                        }
                    }
                    Some(Ok(WsMessage::Ping(payload))) => {
                        let _ = ws_sink.lock().await.send(WsMessage::Pong(payload)).await;
                    }
                    Some(Ok(WsMessage::Close(_))) => {
                        let _ = state.events_tx.send(NodeEvent::Disconnected {
                            reason: "relay closed WebSocket".to_string(),
                        });
                        break;
                    }
                    Some(Ok(_)) => {}
                    Some(Err(e)) => {
                        let _ = state.events_tx.send(NodeEvent::Disconnected {
                            reason: format!("WebSocket read error: {e}"),
                        });
                        break;
                    }
                    None => {
                        let _ = state.events_tx.send(NodeEvent::Disconnected {
                            reason: "WebSocket stream ended".to_string(),
                        });
                        break;
                    }
                }
            }
        }
    }
}

async fn handle_command(
    state: &mut ActorState,
    ws_sink: &Arc<Mutex<futures_util::stream::SplitSink<tokio_tungstenite::WebSocketStream<BoxedStream>, WsMessage>>>,
    cmd: NodeCommand,
) {
    match cmd {
        NodeCommand::GetOnlinePeers { reply } => {
            let _ = reply.send(state.online_peers.clone());
        }
        NodeCommand::AttachSerialBridge { port, transport } => {
            state.serial_bridges.insert(port, transport);
        }
        NodeCommand::SendPairOffer {
            peer_id,
            profile,
            psk,
            reply,
        } => {
            let res = do_send_pair_offer(state, ws_sink, &peer_id, profile, psk).await;
            let _ = reply.send(res);
        }
        NodeCommand::AcceptPairOffer {
            pair_id,
            psk,
            reply,
        } => {
            let res = do_accept_pair_offer(state, ws_sink, &pair_id, psk).await;
            let _ = reply.send(res);
        }
        NodeCommand::SendAppMessage {
            peer_id,
            msg,
            reply,
        } => {
            if let Some(sess) = state.sessions.get_mut(&peer_id) {
                sess.outbound_queue.push_back(PendingAppSend { msg, done_tx: reply });
                pump_outbound_for_peer(state, ws_sink, &peer_id).await;
            } else {
                let _ = reply.send(Err(format!("no paired CubeHash session with '{peer_id}'")));
            }
        }
        NodeCommand::SendTamperedProbe { peer_id, reply } => {
            let res = do_send_tampered_probe(state, ws_sink, &peer_id).await;
            let _ = reply.send(res);
        }
        NodeCommand::HopEpoch { peer_id, reply } => {
            let res = do_hop_epoch(state, ws_sink, &peer_id).await;
            let _ = reply.send(res);
        }
        NodeCommand::GetSessionAudit { peer_id, reply } => {
            let res = match state.sessions.get(&peer_id) {
                Some(entry) => Ok((
                    entry.safety_fingerprint.clone(),
                    entry.session.tx.audit_stats(),
                    entry.session.rx.audit_stats(),
                )),
                None => Err(format!("no active session for '{peer_id}'")),
            };
            let _ = reply.send(res);
        }
        NodeCommand::Shutdown => {}
    }
}

async fn do_send_pair_offer(
    state: &mut ActorState,
    ws_sink: &Arc<Mutex<futures_util::stream::SplitSink<tokio_tungstenite::WebSocketStream<BoxedStream>, WsMessage>>>,
    peer_id: &str,
    profile: EazyMeshProfile,
    psk: Vec<u8>,
) -> Result<String, String> {
    let pair_id = random_hex_16()?;
    let (eph_secret, eph_pub) = gen_x25519_keypair()?;
    let (init_rx_secret, init_rx_pub) = gen_x25519_keypair()?;

    let from = state.identity.client_id().to_string();
    let sender_ed25519_pub = state.identity.ed25519_pub();
    let has_psk = !psk.is_empty();
    let sig_msg = pair_offer_sign_bytes(
        &from,
        peer_id,
        &pair_id,
        &eph_pub,
        &init_rx_pub,
        &sender_ed25519_pub,
        profile,
        has_psk,
    );
    let signature = state.identity.sign(&sig_msg);

    let frame = RelayFrame::PairOffer {
        from,
        to: peer_id.to_string(),
        pair_id: pair_id.clone(),
        eph_pub,
        init_rx_dh_pub: init_rx_pub,
        sender_ed25519_pub,
        profile,
        has_psk,
        signature,
    };

    state.outbound_offers.insert(
        pair_id.clone(),
        OutboundOffer {
            peer_id: peer_id.to_string(),
            profile,
            psk,
            eph_secret,
            eph_pub,
            init_rx_secret,
            init_rx_pub,
        },
    );

    if let Err(e) = send_relay_frame(ws_sink, &frame).await {
        state.outbound_offers.remove(&pair_id);
        return Err(e);
    }
    Ok(pair_id)
}

async fn do_accept_pair_offer(
    state: &mut ActorState,
    ws_sink: &Arc<Mutex<futures_util::stream::SplitSink<tokio_tungstenite::WebSocketStream<BoxedStream>, WsMessage>>>,
    pair_id: &str,
    psk: Vec<u8>,
) -> Result<PairedResult, String> {
    let needs_psk = state
        .inbound_offers
        .get(pair_id)
        .ok_or_else(|| format!("unknown pair offer '{pair_id}'"))?
        .has_psk;
    if needs_psk && psk.is_empty() {
        return Err("peer required a pre-shared secret (--psk) for this pair offer".to_string());
    }
    let offer = state
        .inbound_offers
        .remove(pair_id)
        .ok_or_else(|| format!("unknown pair offer '{pair_id}'"))?;

    let (my_eph_secret, my_eph_pub) = gen_x25519_keypair()?;
    let (my_rx_secret, my_rx_pub) = gen_x25519_keypair()?;

    let mut shared_ecdh = x25519_dh(&my_eph_secret, &offer.peer_eph_pub);
    let my_ed = state.identity.ed25519_pub();
    let my_id = state.identity.client_id().to_string();

    let sig_msg = pair_accept_sign_bytes(
        &my_id,
        &offer.from,
        &offer.pair_id,
        &offer.peer_eph_pub,
        &my_eph_pub,
        &my_rx_pub,
        &my_ed,
    );
    let signature = state.identity.sign(&sig_msg);

    let derived = provision_duplex_from_ecdh(
        PairTranscriptParams {
            profile: offer.profile,
            shared_ecdh: &shared_ecdh,
            psk: &psk,
            pair_id: &offer.pair_id,
            offerer_id: &offer.from,
            accepter_id: &my_id,
            offerer_pub: &offer.peer_eph_pub,
            accepter_pub: &my_eph_pub,
            offerer_ed25519_pub: &offer.peer_ed25519_pub,
            accepter_ed25519_pub: &my_ed,
            my_rx_dh_secret: &my_rx_secret,
            my_rx_dh_pub: &my_rx_pub,
            peer_rx_dh_pub: &offer.peer_init_rx_pub,
            is_offerer: false,
        },
        state.identity.hardware_provider(),
    )
    .map_err(|e| e.to_string())?;
    shared_ecdh.zeroize();

    let accept_frame = RelayFrame::PairAccept {
        from: my_id,
        to: offer.from.clone(),
        pair_id: offer.pair_id.clone(),
        eph_pub: my_eph_pub,
        init_rx_dh_pub: my_rx_pub,
        sender_ed25519_pub: my_ed,
        signature,
    };
    send_relay_frame(ws_sink, &accept_frame).await?;

    let epoch = derived.session.tx.epoch();
    let safety_fingerprint = derived.safety_fingerprint.clone();
    state.sessions.insert(
        offer.from.clone(),
        PeerSessionEntry {
            peer_ed25519_pub: offer.peer_ed25519_pub,
            safety_fingerprint: safety_fingerprint.clone(),
            session: derived.session,
            inflight: None,
            outbound_queue: VecDeque::new(),
        },
    );

    let _ = state.events_tx.send(NodeEvent::Paired {
        peer: offer.from.clone(),
        safety_fingerprint: safety_fingerprint.clone(),
        epoch,
    });

    Ok(PairedResult {
        peer: offer.from,
        safety_fingerprint,
        epoch,
    })
}

async fn pump_outbound_for_peer(
    state: &mut ActorState,
    ws_sink: &Arc<Mutex<futures_util::stream::SplitSink<tokio_tungstenite::WebSocketStream<BoxedStream>, WsMessage>>>,
    peer_id: &str,
) {
    loop {
        let Some(sess) = state.sessions.get_mut(peer_id) else {
            return;
        };
        if sess.inflight.is_some() || sess.session.tx.has_pending_outbound() {
            return;
        }
        let Some(next_item) = sess.outbound_queue.pop_front() else {
            return;
        };

        let padded = match encode_app_payload(&next_item.msg) {
            Ok(p) => p,
            Err(e) => {
                let _ = next_item.done_tx.send(Err(e));
                continue;
            }
        };
        let packet = match sess
            .session
            .begin_send_message(state.identity.hardware_provider(), &padded)
        {
            Ok(pkt) => pkt,
            Err(e) => {
                let _ = next_item.done_tx.send(Err(e.to_string()));
                continue;
            }
        };
        let msg_id = match random_hex_16() {
            Ok(id) => id,
            Err(e) => {
                let _ = sess.session.rollback_outbound();
                let _ = next_item.done_tx.send(Err(e));
                continue;
            }
        };

        let frame = RelayFrame::EncryptedPacket {
            from: state.identity.client_id().to_string(),
            to: peer_id.to_string(),
            msg_id: msg_id.clone(),
            packet,
        };

        if let Err(e) = send_relay_frame(ws_sink, &frame).await {
            let _ = sess.session.rollback_outbound();
            let _ = next_item.done_tx.send(Err(e));
            continue;
        }

        sess.inflight = Some(InflightAppSend {
            msg_id,
            done_tx: next_item.done_tx,
        });
        return;
    }
}

async fn do_send_tampered_probe(
    state: &mut ActorState,
    ws_sink: &Arc<Mutex<futures_util::stream::SplitSink<tokio_tungstenite::WebSocketStream<BoxedStream>, WsMessage>>>,
    peer_id: &str,
) -> Result<(), String> {
    let sess = state
        .sessions
        .get_mut(peer_id)
        .ok_or_else(|| format!("no paired session for '{peer_id}'"))?;
    if sess.inflight.is_some() || sess.session.tx.has_pending_outbound() {
        return Err("cannot run probe while another TX message awaits DeliveryAck".to_string());
    }

    let padded = encode_app_payload(&EazyAppMessage::ChatText {
        text: "dummy probe".to_string(),
    })?;
    let mut forged = sess
        .session
        .begin_send_message(state.identity.hardware_provider(), &padded)
        .map_err(|e| e.to_string())?;
    // Immediately roll back sender TX so sender stays clean while the forged copy tests peer zero-oracle!
    let _ = sess.session.rollback_outbound();
    forged.packet_mac[0] ^= 0x5A;

    let frame = RelayFrame::EncryptedPacket {
        from: state.identity.client_id().to_string(),
        to: peer_id.to_string(),
        msg_id: format!("probe-{}", random_hex_16()?),
        packet: forged,
    };
    send_relay_frame(ws_sink, &frame).await
}

async fn do_hop_epoch(
    state: &mut ActorState,
    ws_sink: &Arc<Mutex<futures_util::stream::SplitSink<tokio_tungstenite::WebSocketStream<BoxedStream>, WsMessage>>>,
    peer_id: &str,
) -> Result<u64, String> {
    let sess = state
        .sessions
        .get_mut(peer_id)
        .ok_or_else(|| format!("no paired session for '{peer_id}'"))?;
    let (new_epoch, epoch_eph_pub) = sess
        .session
        .hop_epoch_tx_ratchet(state.identity.hardware_provider())
        .map_err(|e| e.to_string())?;

    let from = state.identity.client_id().to_string();
    let sender_ed = state.identity.ed25519_pub();
    let sig_msg = epoch_hop_sign_bytes(&from, peer_id, new_epoch, &epoch_eph_pub, &sender_ed);
    let signature = state.identity.sign(&sig_msg);

    let frame = RelayFrame::EpochHopNotice {
        from,
        to: peer_id.to_string(),
        new_epoch,
        epoch_eph_pub,
        sender_ed25519_pub: sender_ed,
        signature,
    };
    send_relay_frame(ws_sink, &frame).await?;
    Ok(new_epoch)
}

async fn handle_incoming_frame(
    state: &mut ActorState,
    ws_sink: &Arc<Mutex<futures_util::stream::SplitSink<tokio_tungstenite::WebSocketStream<BoxedStream>, WsMessage>>>,
    frame: RelayFrame,
) {
    match frame {
        RelayFrame::PeerList { online_peers } => {
            state.online_peers = online_peers.clone();
            let _ = state
                .events_tx
                .send(NodeEvent::PeerListUpdated { online_peers });
        }
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
            if to != state.identity.client_id() {
                return;
            }
            let sig_msg = pair_offer_sign_bytes(
                &from,
                &to,
                &pair_id,
                &eph_pub,
                &init_rx_dh_pub,
                &sender_ed25519_pub,
                profile,
                has_psk,
            );
            if !DeviceIdentity::verify_signature(&sender_ed25519_pub, &sig_msg, &signature) {
                let _ = state.events_tx.send(NodeEvent::RelayError {
                    code: "bad_signature".to_string(),
                    detail: format!("rejected PairOffer from '{from}' with invalid signature"),
                    peer: Some(from),
                });
                return;
            }
            if let Err(e) = state.identity.verify_or_pin_peer(&from, sender_ed25519_pub) {
                let _ = state.events_tx.send(NodeEvent::RelayError {
                    code: "identity_pin_mismatch".to_string(),
                    detail: e,
                    peer: Some(from),
                });
                return;
            }

            state.inbound_offers.insert(
                pair_id.clone(),
                InboundOffer {
                    from: from.clone(),
                    pair_id: pair_id.clone(),
                    profile,
                    peer_eph_pub: eph_pub,
                    peer_init_rx_pub: init_rx_dh_pub,
                    peer_ed25519_pub: sender_ed25519_pub,
                    has_psk,
                },
            );
            let _ = state.events_tx.send(NodeEvent::IncomingPairOffer {
                pair_id,
                from,
                profile,
                has_psk,
            });
        }
        RelayFrame::PairAccept {
            from,
            to,
            pair_id,
            eph_pub,
            init_rx_dh_pub,
            sender_ed25519_pub,
            signature,
        } => {
            if to != state.identity.client_id() {
                return;
            }
            let Some(offer) = state.outbound_offers.remove(&pair_id) else {
                return;
            };
            if offer.peer_id != from {
                return;
            }
            let sig_msg = pair_accept_sign_bytes(
                &from,
                &to,
                &pair_id,
                &offer.eph_pub,
                &eph_pub,
                &init_rx_dh_pub,
                &sender_ed25519_pub,
            );
            if !DeviceIdentity::verify_signature(&sender_ed25519_pub, &sig_msg, &signature) {
                let _ = state.events_tx.send(NodeEvent::RelayError {
                    code: "bad_signature".to_string(),
                    detail: format!("rejected PairAccept from '{from}' with invalid signature"),
                    peer: Some(from),
                });
                return;
            }
            if let Err(e) = state.identity.verify_or_pin_peer(&from, sender_ed25519_pub) {
                let _ = state.events_tx.send(NodeEvent::RelayError {
                    code: "identity_pin_mismatch".to_string(),
                    detail: e,
                    peer: Some(from),
                });
                return;
            }

            let mut shared_ecdh = x25519_dh(&offer.eph_secret, &eph_pub);
            let my_id = state.identity.client_id().to_string();
            let my_ed = state.identity.ed25519_pub();

            let derived = provision_duplex_from_ecdh(
                PairTranscriptParams {
                    profile: offer.profile,
                    shared_ecdh: &shared_ecdh,
                    psk: &offer.psk,
                    pair_id: &pair_id,
                    offerer_id: &my_id,
                    accepter_id: &from,
                    offerer_pub: &offer.eph_pub,
                    accepter_pub: &eph_pub,
                    offerer_ed25519_pub: &my_ed,
                    accepter_ed25519_pub: &sender_ed25519_pub,
                    my_rx_dh_secret: &offer.init_rx_secret,
                    my_rx_dh_pub: &offer.init_rx_pub,
                    peer_rx_dh_pub: &init_rx_dh_pub,
                    is_offerer: true,
                },
                state.identity.hardware_provider(),
            );
            shared_ecdh.zeroize();

            match derived {
                Ok(d) => {
                    let epoch = d.session.tx.epoch();
                    let fp = d.safety_fingerprint.clone();
                    state.sessions.insert(
                        from.clone(),
                        PeerSessionEntry {
                            peer_ed25519_pub: sender_ed25519_pub,
                            safety_fingerprint: fp.clone(),
                            session: d.session,
                            inflight: None,
                            outbound_queue: VecDeque::new(),
                        },
                    );
                    let _ = state.events_tx.send(NodeEvent::Paired {
                        peer: from,
                        safety_fingerprint: fp,
                        epoch,
                    });
                }
                Err(e) => {
                    let _ = state.events_tx.send(NodeEvent::RelayError {
                        code: "pair_derive_failed".to_string(),
                        detail: e.to_string(),
                        peer: Some(from),
                    });
                }
            }
        }
        RelayFrame::EncryptedPacket {
            from,
            to,
            msg_id,
            packet,
        } => {
            if to != state.identity.client_id() {
                return;
            }
            let Some(sess) = state.sessions.get_mut(&from) else {
                return;
            };
            match sess.session.decrypt_zero_oracle(
                state.identity.hardware_provider(),
                &packet,
                HoneyProfile::ChatPlaintext,
            ) {
                ReceiveOutcome::Authentic {
                    plaintext,
                    ack,
                    healed_bits,
                } => {
                    let ack_frame = RelayFrame::AckFrame {
                        from: state.identity.client_id().to_string(),
                        to: from.clone(),
                        msg_id: msg_id.clone(),
                        ack,
                    };
                    let _ = send_relay_frame(ws_sink, &ack_frame).await;

                    if let Ok(app_msg) = decode_app_payload(&plaintext) {
                        let epoch = sess.session.rx.epoch();
                        maybe_dispatch_hardware_request(state, &from, &app_msg);
                        let _ = state.events_tx.send(NodeEvent::MessageReceived {
                            from,
                            msg_id,
                            msg: app_msg,
                            healed_bits,
                            epoch,
                        });
                    }
                }
                ReceiveOutcome::HoneyDeception {
                    plausible_output,
                    ..
                } => {
                    let preview = String::from_utf8_lossy(&plausible_output).into_owned();
                    let _ = state.events_tx.send(NodeEvent::HoneyDecoyTriggered {
                        from,
                        msg_id,
                        plausible_preview: preview,
                    });
                }
            }
        }
        RelayFrame::AckFrame {
            from,
            to,
            msg_id,
            ack,
        } => {
            if to != state.identity.client_id() {
                return;
            }
            if let Some(sess) = state.sessions.get_mut(&from) {
                let commit_res = sess
                    .session
                    .commit_ack(state.identity.hardware_provider(), &ack)
                    .map_err(|e| e.to_string());
                if let Some(inflight) = sess.inflight.take() {
                    if inflight.msg_id == msg_id {
                        let _ = inflight.done_tx.send(commit_res.map(|_| msg_id.clone()));
                    } else {
                        let _ = inflight
                            .done_tx
                            .send(Err("mismatched DeliveryAck msg_id".to_string()));
                    }
                }
                let _ = state.events_tx.send(NodeEvent::DeliveryAcked { from: from.clone(), msg_id });
                pump_outbound_for_peer(state, ws_sink, &from).await;
            }
        }
        RelayFrame::EpochHopNotice {
            from,
            to,
            new_epoch,
            epoch_eph_pub,
            sender_ed25519_pub,
            signature,
        } => {
            if to != state.identity.client_id() {
                return;
            }
            let Some(sess) = state.sessions.get_mut(&from) else {
                return;
            };
            if sess.peer_ed25519_pub != sender_ed25519_pub {
                return;
            }
            let sig_msg =
                epoch_hop_sign_bytes(&from, &to, new_epoch, &epoch_eph_pub, &sender_ed25519_pub);
            if !DeviceIdentity::verify_signature(&sender_ed25519_pub, &sig_msg, &signature) {
                return;
            }
            if sess
                .session
                .hop_epoch_rx_ratchet(state.identity.hardware_provider(), new_epoch, epoch_eph_pub)
                .is_ok()
            {
                let _ = state
                    .events_tx
                    .send(NodeEvent::EpochHopped { peer: from, new_epoch });
            }
        }
        RelayFrame::RelayError { code, detail, peer } => {
            if let Some(ref p) = peer {
                if let Some(sess) = state.sessions.get_mut(p) {
                    if sess.session.tx.has_pending_outbound() {
                        let _ = sess.session.rollback_outbound();
                    }
                    if let Some(inflight) = sess.inflight.take() {
                        let _ = inflight.done_tx.send(Err(format!("{code}: {detail}")));
                    }
                    pump_outbound_for_peer(state, ws_sink, p).await;
                }
            }
            let _ = state
                .events_tx
                .send(NodeEvent::RelayError { code, detail, peer });
        }
        RelayFrame::AuthChallenge { .. }
        | RelayFrame::RegisterAuth { .. }
        | RelayFrame::Registered { .. } => {}
    }
}

fn maybe_dispatch_hardware_request(state: &ActorState, from: &str, msg: &EazyAppMessage) {
    match msg {
        EazyAppMessage::SerialCommand {
            port,
            baud_rate,
            data,
        } => {
            let bridge = state.serial_bridges.get(port).cloned();
            let allow_os = state.allow_remote_serial_os_fallback;
            let port_owned = port.clone();
            let port_reply = port.clone();
            let baud = *baud_rate;
            let payload = data.clone();
            let peer = from.to_string();
            let cmd_tx = state.self_cmd_tx.clone();

            tokio::spawn(async move {
                let outcome = tokio::task::spawn_blocking(move || -> Result<Vec<u8>, String> {
                    if let Some(transport_arc) = bridge {
                        let mut guard = transport_arc
                            .lock()
                            .map_err(|_| "serial bridge lock poisoned".to_string())?;
                        guard.write_bytes(&payload)?;
                        std::thread::sleep(std::time::Duration::from_millis(15));
                        guard.read_available(4096)
                    } else if allow_os {
                        send_serial_command(&port_owned, baud, &payload, 200)
                    } else {
                        Err(format!("serial bridge for '{port_owned}' not attached"))
                    }
                })
                .await;

                if let Ok(Ok(resp)) = outcome {
                    let (done_tx, _done_rx) = oneshot::channel();
                    let _ = cmd_tx.send(NodeCommand::SendAppMessage {
                        peer_id: peer,
                        msg: EazyAppMessage::SerialData {
                            port: port_reply,
                            data: resp,
                        },
                        reply: done_tx,
                    });
                }
            });
        }
        EazyAppMessage::HardwareProbeRequest if state.allow_remote_hw_probe => {
            let peer = from.to_string();
            let cmd_tx = state.self_cmd_tx.clone();
            tokio::spawn(async move {
                if let Ok(report) = tokio::task::spawn_blocking(collect_hardware_report).await {
                    let (done_tx, _done_rx) = oneshot::channel();
                    let _ = cmd_tx.send(NodeCommand::SendAppMessage {
                        peer_id: peer,
                        msg: EazyAppMessage::HardwareProbeResponse { report },
                        reply: done_tx,
                    });
                }
            });
        }
        _ => {}
    }
}

async fn send_relay_frame(
    ws_sink: &Arc<Mutex<futures_util::stream::SplitSink<tokio_tungstenite::WebSocketStream<BoxedStream>, WsMessage>>>,
    frame: &RelayFrame,
) -> Result<(), String> {
    let txt = serde_json::to_string(frame).map_err(|e| e.to_string())?;
    ws_sink
        .lock()
        .await
        .send(WsMessage::Text(txt.into()))
        .await
        .map_err(|e| format!("failed to send WS frame: {e}"))
}

fn normalize_ws_url(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim().trim_end_matches('/');
    let converted = if let Some(rest) = trimmed.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = trimmed.strip_prefix("http://") {
        format!("ws://{rest}")
    } else if trimmed.starts_with("wss://") || trimmed.starts_with("ws://") {
        trimmed.to_string()
    } else {
        return Err("master URL must start with https://, wss://, http://, or ws://".to_string());
    };
    if converted.ends_with("/ws") {
        Ok(converted)
    } else {
        Ok(format!("{converted}/ws"))
    }
}

fn random_hex_16() -> Result<String, String> {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).map_err(|e| e.to_string())?;
    Ok(hex::encode(b))
}

fn gen_x25519_keypair() -> Result<([u8; 32], [u8; 32]), String> {
    let mut raw = [0u8; 32];
    getrandom::getrandom(&mut raw).map_err(|e| e.to_string())?;
    let secret = StaticSecret::from(raw);
    let pub_key = PublicKey::from(&secret);
    Ok((secret.to_bytes(), pub_key.to_bytes()))
}

fn x25519_dh(my_secret: &[u8; 32], peer_pub: &[u8; 32]) -> [u8; 32] {
    let sec = StaticSecret::from(*my_secret);
    let pk = PublicKey::from(*peer_pub);
    sec.diffie_hellman(&pk).to_bytes()
}
