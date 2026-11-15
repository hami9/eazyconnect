use cubehash_core::primitives::{hkdf_expand_label, hmac_sha256_parts};
use cubehash_core::{
    build_custody_bundle, AuditorCube, CellularMesh, CombiningFn, DeliveryAck, DuplexCubeSession,
    HardwareProvider, MainCube, MeshConfig, MotherCube, Result, ThreeCubeCustody, TimeAlgorithm,
    WirePacket,
};
use eazyconnect_hw::SystemHardwareReport;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

pub const APP_BUCKET_BYTES: usize = 256;

/// Custom serde module for `[u8; 64]` Ed25519 signatures encoded as hex strings.
pub mod sig64_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(val: &[u8; 64], s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(val))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<[u8; 64], D::Error> {
        let hex_str = String::deserialize(d)?;
        let raw = hex::decode(hex_str).map_err(serde::de::Error::custom)?;
        <[u8; 64]>::try_from(raw.as_slice())
            .map_err(|_| serde::de::Error::custom("expected 64-byte Ed25519 signature"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EazyMeshProfile {
    Compact,
    Standard,
    HighCapacity,
}

impl EazyMeshProfile {
    pub fn to_config(self) -> MeshConfig {
        match self {
            Self::Compact => MeshConfig::compact(),
            Self::Standard => MeshConfig::standard(),
            Self::HighCapacity => MeshConfig::high_capacity(),
        }
    }

    pub fn from_name(name: &str) -> Self {
        match name.trim().to_ascii_lowercase().as_str() {
            "compact" => Self::Compact,
            "high" | "high_capacity" => Self::HighCapacity,
            _ => Self::Standard,
        }
    }

    pub fn tag_byte(self) -> u8 {
        match self {
            Self::Compact => 1,
            Self::Standard => 2,
            Self::HighCapacity => 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerIdentity {
    pub client_id: String,
    pub ed25519_pub: [u8; 32],
}

/// Frames routed over `/ws` through the blind Master Relay.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RelayFrame {
    AuthChallenge {
        nonce: [u8; 32],
    },
    RegisterAuth {
        client_id: String,
        ed25519_pub: [u8; 32],
        #[serde(with = "sig64_serde")]
        signature: [u8; 64],
    },
    Registered {
        client_id: String,
        online_peers: Vec<PeerIdentity>,
    },
    PeerList {
        online_peers: Vec<PeerIdentity>,
    },
    PairOffer {
        from: String,
        to: String,
        pair_id: String,
        eph_pub: [u8; 32],
        init_rx_dh_pub: [u8; 32],
        sender_ed25519_pub: [u8; 32],
        profile: EazyMeshProfile,
        has_psk: bool,
        #[serde(with = "sig64_serde")]
        signature: [u8; 64],
    },
    PairAccept {
        from: String,
        to: String,
        pair_id: String,
        eph_pub: [u8; 32],
        init_rx_dh_pub: [u8; 32],
        sender_ed25519_pub: [u8; 32],
        #[serde(with = "sig64_serde")]
        signature: [u8; 64],
    },
    EncryptedPacket {
        from: String,
        to: String,
        msg_id: String,
        packet: WirePacket,
    },
    AckFrame {
        from: String,
        to: String,
        msg_id: String,
        ack: DeliveryAck,
    },
    EpochHopNotice {
        from: String,
        to: String,
        new_epoch: u64,
        epoch_eph_pub: [u8; 32],
        sender_ed25519_pub: [u8; 32],
        #[serde(with = "sig64_serde")]
        signature: [u8; 64],
    },
    RelayError {
        code: String,
        detail: String,
        peer: Option<String>,
    },
}

/// Application messages carried strictly INSIDE 256-byte bucket-padded CubeHash AEAD payloads.
/// The blind relay cannot distinguish chat text, file notices, or hardware serial telemetry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EazyAppMessage {
    ChatText {
        text: String,
    },
    FileShared {
        owner: String,
        filename: String,
        blake3_hex: String,
        size_bytes: u64,
        e2e: bool,
    },
    SerialData {
        port: String,
        data: Vec<u8>,
    },
    SerialCommand {
        port: String,
        baud_rate: u32,
        data: Vec<u8>,
    },
    HardwareProbeRequest,
    HardwareProbeResponse {
        report: SystemHardwareReport,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayTrafficEvent {
    pub seq: u64,
    pub frame_type: String,
    pub from: String,
    pub to: String,
    pub wire_fingerprint_hex: Option<String>,
    pub wire_base_bytes: Option<usize>,
    pub wire_total_bytes: Option<usize>,
    pub ciphertext_bytes: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayTelemetrySnapshot {
    pub online_peers: Vec<String>,
    pub total_routed_frames: u64,
    pub recent_frames: Vec<RelayTrafficEvent>,
}

// --- REST API DTOs ---------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthChallengeResponse {
    pub challenge_id: String,
    pub nonce_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceAuthRequest {
    pub client_id: String,
    pub challenge_id: String,
    pub ed25519_pub_hex: String,
    pub signature_hex: String,
    pub invite_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordLoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthTokenResponse {
    pub token: String,
    pub expires_unix: u64,
    pub role: String,
    pub client_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
    pub is_admin: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRecordView {
    pub client_id: String,
    pub ed25519_pub_hex: String,
    pub enrolled_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerFileEntry {
    pub filename: String,
    pub size_bytes: u64,
    pub blake3_hex: String,
    pub modified_unix: u64,
    pub e2e_encrypted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListFilesResponse {
    pub owner: String,
    pub files: Vec<ServerFileEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub master_ed25519_pub_hex: String,
    pub tls_cert_sha256_hex: Option<String>,
    pub device_count: usize,
    pub online_ws_peers: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryBeacon {
    pub version: String,
    pub host: String,
    pub port: u16,
    pub https: bool,
    pub tls_cert_sha256_hex: Option<String>,
    pub master_ed25519_pub: [u8; 32],
    #[serde(default)]
    pub alternate_urls: Vec<String>,
    #[serde(with = "sig64_serde")]
    pub signature: [u8; 64],
}

// --- Canonical Ed25519 Signature Payloads ----------------------------------

fn push_lp_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(bytes);
}

pub fn relay_auth_challenge_sign_bytes(nonce: &[u8; 32], client_id: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64 + client_id.len());
    buf.extend_from_slice(b"eazyconnect-ws-register-v2");
    buf.extend_from_slice(nonce);
    push_lp_bytes(&mut buf, client_id.as_bytes());
    buf
}

pub fn http_auth_sign_bytes(nonce: &[u8; 32], client_id: &str, challenge_id: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(96 + client_id.len() + challenge_id.len());
    buf.extend_from_slice(b"eazyconnect-http-auth-v2");
    buf.extend_from_slice(nonce);
    push_lp_bytes(&mut buf, client_id.as_bytes());
    push_lp_bytes(&mut buf, challenge_id.as_bytes());
    buf
}

pub fn discovery_beacon_sign_bytes(
    version: &str,
    host: &str,
    port: u16,
    https: bool,
    tls_cert_sha256_hex: Option<&str>,
    master_ed25519_pub: &[u8; 32],
    alternate_urls: &[String],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(160);
    buf.extend_from_slice(b"eazyconnect-discover-v3");
    push_lp_bytes(&mut buf, version.as_bytes());
    push_lp_bytes(&mut buf, host.as_bytes());
    buf.extend_from_slice(&port.to_le_bytes());
    buf.push(u8::from(https));
    push_lp_bytes(&mut buf, tls_cert_sha256_hex.unwrap_or("").as_bytes());
    buf.extend_from_slice(master_ed25519_pub);
    buf.extend_from_slice(&(alternate_urls.len() as u32).to_le_bytes());
    for alt in alternate_urls {
        push_lp_bytes(&mut buf, alt.as_bytes());
    }
    buf
}

#[allow(clippy::too_many_arguments)]
pub fn pair_offer_sign_bytes(
    from: &str,
    to: &str,
    pair_id: &str,
    eph_pub: &[u8; 32],
    init_rx_dh_pub: &[u8; 32],
    sender_ed25519_pub: &[u8; 32],
    profile: EazyMeshProfile,
    has_psk: bool,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(192);
    buf.extend_from_slice(b"eazyconnect-pair-offer-v2");
    push_lp_bytes(&mut buf, from.as_bytes());
    push_lp_bytes(&mut buf, to.as_bytes());
    push_lp_bytes(&mut buf, pair_id.as_bytes());
    buf.extend_from_slice(eph_pub);
    buf.extend_from_slice(init_rx_dh_pub);
    buf.extend_from_slice(sender_ed25519_pub);
    buf.push(profile.tag_byte());
    buf.push(u8::from(has_psk));
    buf
}

pub fn pair_accept_sign_bytes(
    from: &str,
    to: &str,
    pair_id: &str,
    offerer_pub: &[u8; 32],
    accepter_pub: &[u8; 32],
    init_rx_dh_pub: &[u8; 32],
    sender_ed25519_pub: &[u8; 32],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(192);
    buf.extend_from_slice(b"eazyconnect-pair-accept-v2");
    push_lp_bytes(&mut buf, from.as_bytes());
    push_lp_bytes(&mut buf, to.as_bytes());
    push_lp_bytes(&mut buf, pair_id.as_bytes());
    buf.extend_from_slice(offerer_pub);
    buf.extend_from_slice(accepter_pub);
    buf.extend_from_slice(init_rx_dh_pub);
    buf.extend_from_slice(sender_ed25519_pub);
    buf
}

pub fn epoch_hop_sign_bytes(
    from: &str,
    to: &str,
    new_epoch: u64,
    epoch_eph_pub: &[u8; 32],
    sender_ed25519_pub: &[u8; 32],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);
    buf.extend_from_slice(b"eazyconnect-epoch-hop-v2");
    push_lp_bytes(&mut buf, from.as_bytes());
    push_lp_bytes(&mut buf, to.as_bytes());
    buf.extend_from_slice(&new_epoch.to_le_bytes());
    buf.extend_from_slice(epoch_eph_pub);
    buf.extend_from_slice(sender_ed25519_pub);
    buf
}

// --- 256-Byte Bucketed Padding & Application Framing -----------------------

pub fn encode_padded_bucket(payload: &[u8]) -> std::result::Result<Vec<u8>, String> {
    let total = 4usize
        .checked_add(payload.len())
        .ok_or_else(|| "payload too large".to_string())?;
    let buckets = total.div_ceil(APP_BUCKET_BYTES).max(1);
    let padded_len = buckets * APP_BUCKET_BYTES;

    let mut out = vec![0u8; padded_len];
    getrandom::getrandom(&mut out[total..]).map_err(|e| e.to_string())?;
    out[0..4].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    out[4..4 + payload.len()].copy_from_slice(payload);
    Ok(out)
}

pub fn decode_padded_bucket(buf: &[u8]) -> std::result::Result<Vec<u8>, String> {
    if buf.len() < 4 {
        return Err("padded payload too short".to_string());
    }
    let len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if 4usize.checked_add(len).is_none_or(|end| end > buf.len()) {
        return Err("corrupted padded payload length".to_string());
    }
    Ok(buf[4..4 + len].to_vec())
}

pub fn encode_app_payload(msg: &EazyAppMessage) -> std::result::Result<Vec<u8>, String> {
    let json = serde_json::to_vec(msg).map_err(|e| e.to_string())?;
    encode_padded_bucket(&json)
}

pub fn decode_app_payload(padded: &[u8]) -> std::result::Result<EazyAppMessage, String> {
    let raw = decode_padded_bucket(padded)?;
    serde_json::from_slice(&raw).map_err(|e| format!("invalid app payload: {e}"))
}

// --- CubeHash Duplex Session Provisioning ----------------------------------

pub struct DerivedSession {
    pub session: DuplexCubeSession,
    pub safety_fingerprint: String,
    pub config: MeshConfig,
}

pub struct PairTranscriptParams<'a> {
    pub profile: EazyMeshProfile,
    pub shared_ecdh: &'a [u8; 32],
    pub psk: &'a [u8],
    pub pair_id: &'a str,
    pub offerer_id: &'a str,
    pub accepter_id: &'a str,
    pub offerer_pub: &'a [u8; 32],
    pub accepter_pub: &'a [u8; 32],
    pub offerer_ed25519_pub: &'a [u8; 32],
    pub accepter_ed25519_pub: &'a [u8; 32],
    pub my_rx_dh_secret: &'a [u8; 32],
    pub my_rx_dh_pub: &'a [u8; 32],
    pub peer_rx_dh_pub: &'a [u8; 32],
    pub is_offerer: bool,
}

pub fn provision_duplex_from_ecdh(
    params: PairTranscriptParams<'_>,
    local_hw: &dyn HardwareProvider,
) -> Result<DerivedSession> {
    let config = params.profile.to_config();
    let mut transcript = Vec::with_capacity(256);
    transcript.extend_from_slice(b"eazyconnect-pair-v2");
    transcript.push(params.profile.tag_byte());
    push_lp_bytes(&mut transcript, params.pair_id.as_bytes());
    push_lp_bytes(&mut transcript, params.offerer_id.as_bytes());
    push_lp_bytes(&mut transcript, params.accepter_id.as_bytes());
    transcript.extend_from_slice(params.offerer_pub);
    transcript.extend_from_slice(params.accepter_pub);
    transcript.extend_from_slice(params.offerer_ed25519_pub);
    transcript.extend_from_slice(params.accepter_ed25519_pub);

    let mut ikm = hmac_sha256_parts(params.shared_ecdh, &[&transcript, params.psk]);

    let mut root_ab = [0u8; 32];
    let mut root_ba = [0u8; 32];
    let mut safety_raw = [0u8; 16];
    hkdf_expand_label(&ikm, &transcript, b"eazyconnect-dir-ab-v2", &mut root_ab)?;
    hkdf_expand_label(&ikm, &transcript, b"eazyconnect-dir-ba-v2", &mut root_ba)?;
    hkdf_expand_label(&ikm, &transcript, b"eazyconnect-safety-v2", &mut safety_raw)?;
    ikm.zeroize();

    let (custody_ab, seed_ab) = derive_directional_custody(&config, &root_ab);
    let (custody_ba, seed_ba) = derive_directional_custody(&config, &root_ba);

    let (tx_custody, tx_seed, rx_custody, rx_seed) = if params.is_offerer {
        (custody_ab, seed_ab, custody_ba, seed_ba)
    } else {
        (custody_ba, seed_ba, custody_ab, seed_ab)
    };

    let mut tx = CellularMesh::provision_device(config.clone(), tx_custody, local_hw, &tx_seed)?;
    let mut rx = CellularMesh::provision_device(config.clone(), rx_custody, local_hw, &rx_seed)?;

    tx.set_peer_dh_pub(*params.peer_rx_dh_pub)?;
    rx.set_local_dh_keypair(*params.my_rx_dh_secret, *params.my_rx_dh_pub)?;

    root_ab.zeroize();
    root_ba.zeroize();

    let hex_code = hex::encode_upper(safety_raw);
    let safety_fingerprint = format!(
        "{}-{}-{}-{}",
        &hex_code[0..4],
        &hex_code[4..8],
        &hex_code[8..12],
        &hex_code[12..16]
    );

    Ok(DerivedSession {
        session: DuplexCubeSession { tx, rx },
        safety_fingerprint,
        config,
    })
}

fn derive_directional_custody(config: &MeshConfig, root: &[u8; 32]) -> (ThreeCubeCustody, [u8; 32]) {
    let mother_secret = hmac_sha256_parts(root, &[b"eazy-mother-secret"]);
    let owner_salt: [u8; 16] = hmac_sha256_parts(root, &[b"eazy-owner-salt"])[..16]
        .try_into()
        .unwrap();
    let chain_id: [u8; 16] = hmac_sha256_parts(root, &[b"eazy-chain-id"])[..16]
        .try_into()
        .unwrap();
    let root_pattern = hmac_sha256_parts(root, &[b"eazy-root-pattern"]);
    let auditor_secret = hmac_sha256_parts(root, &[b"eazy-auditor-secret"]);
    let synthesis_salt: [u8; 16] = hmac_sha256_parts(root, &[b"eazy-synth-salt"])[..16]
        .try_into()
        .unwrap();
    let mesh_seed = hmac_sha256_parts(root, &[b"eazy-mesh-seed"]);

    let coeff_digest = hmac_sha256_parts(root, &[b"eazy-spiral-coeffs"]);
    let c0 = (u32::from_le_bytes(coeff_digest[0..4].try_into().unwrap()) % 97) + 3;
    let c1 = (u32::from_le_bytes(coeff_digest[4..8].try_into().unwrap()) % 97) + 5;
    let c2 = (u32::from_le_bytes(coeff_digest[8..12].try_into().unwrap()) % 97) + 7;

    let custody = build_custody_bundle(
        MotherCube::from_custody_bytes(mother_secret, owner_salt),
        MainCube::from_parts(chain_id, root_pattern, 0),
        AuditorCube::from_parts(
            auditor_secret,
            synthesis_salt,
            TimeAlgorithm::HybridTriMix,
            CombiningFn::FeistelNonLinear,
            [c0, c1, c2],
            config.quorum_select,
            config.consume_for_next,
        ),
    );
    (custody, mesh_seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_bucket_padding_hides_lengths() {
        let short = encode_app_payload(&EazyAppMessage::ChatText {
            text: "hi".to_string(),
        })
        .unwrap();
        let medium = encode_app_payload(&EazyAppMessage::ChatText {
            text: "Medium length EazyConnect confidential LAN payload cleanly fitting first bucket".to_string(),
        })
        .unwrap();
        assert_eq!(short.len(), 256);
        assert_eq!(medium.len(), 256);

        let dec = decode_app_payload(&medium).unwrap();
        match dec {
            EazyAppMessage::ChatText { text } => assert!(text.starts_with("Medium length")),
            other => panic!("unexpected decoded message: {other:?}"),
        }
    }
}
