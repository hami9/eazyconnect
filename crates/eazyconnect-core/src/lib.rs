pub mod config;
pub mod discovery;
pub mod envelope;
pub mod protocol;
pub mod tls;

pub use config::{
    default_config_path, load_client_config, profile_heading, save_client_config, ClientConfig,
    UserProfile,
};
pub use discovery::{
    detect_local_ipv4, discover_masters, select_beacon_endpoints, spawn_discovery_responder,
    DiscoveredMaster, DEFAULT_DISCOVERY_PORT, DISCOVERY_MAGIC,
};
pub use envelope::{
    decrypt_file_from_vault, encrypt_file_for_vault, scan_folder_delta, PendingSyncFile,
    SyncManifest, SyncedFileEntry,
};
pub use protocol::{
    decode_app_payload, decode_padded_bucket, discovery_beacon_sign_bytes, encode_app_payload,
    encode_padded_bucket, epoch_hop_sign_bytes, http_auth_sign_bytes, pair_accept_sign_bytes,
    pair_offer_sign_bytes, provision_duplex_from_ecdh, relay_auth_challenge_sign_bytes,
    AuthChallengeResponse, AuthTokenResponse, CreateUserRequest, DerivedSession, DeviceAuthRequest,
    DeviceRecordView, DiscoveryBeacon, EazyAppMessage, EazyMeshProfile, HealthResponse,
    ListFilesResponse, PairTranscriptParams, PasswordLoginRequest, PeerIdentity, RelayFrame,
    RelayTelemetrySnapshot, RelayTrafficEvent, ServerFileEntry,
};
pub use tls::{
    configure_tcp_keepalive, connect_tcp_keepalive, parse_endpoint_url, parse_sha256_pin_hex,
    BuiltServerTls, ClientTlsConfig, ParsedEndpoint, ServerTlsConfig,
};
