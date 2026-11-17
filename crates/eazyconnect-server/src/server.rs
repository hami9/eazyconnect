use std::convert::Infallible;
use std::fs;
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path as AxumPath, Query, State, WebSocketUpgrade};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use eazyconnect_core::{
    configure_tcp_keepalive, spawn_discovery_responder, AuthTokenResponse, BuiltServerTls,
    CreateUserRequest, DeviceAccessRequest, DeviceAuthRequest, HealthResponse, ListFilesResponse,
    NetworkSnapshot, PasswordLoginRequest, ServerFileEntry, ServerTlsConfig,
};
use eazyconnect_hw::{validate_id, DeviceIdentity};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tower::Service;

use crate::auth::{AuthStore, AuthenticatedPrincipal, EnrollmentPolicy};
use crate::relay::{handle_relay_socket, BlindRelayState};

const MAX_UPLOAD_BYTES: usize = 128 * 1024 * 1024;
const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub listen_addr: SocketAddr,
    pub data_dir: PathBuf,
    pub keystore_dir: Option<PathBuf>,
    pub tls: ServerTlsConfig,
    pub discovery_addr: Option<SocketAddr>,
    pub advertised_host: Option<String>,
    pub enrollment: EnrollmentPolicy,
    pub bootstrap_admin_pass: Option<String>,
}

#[derive(Clone)]
pub struct ServerState {
    pub auth_store: Arc<RwLock<AuthStore>>,
    pub relay: BlindRelayState,
    pub data_dir: PathBuf,
    pub master_ed25519_pub_hex: String,
    pub tls_cert_sha256_hex: Option<String>,
}

pub struct StartedServer {
    pub addr: SocketAddr,
    pub is_tls: bool,
    pub tls_cert_sha256_hex: Option<String>,
    pub tls_cert_pem: Option<String>,
    pub discovery_addr: Option<SocketAddr>,
    pub master_ed25519_pub_hex: String,
    pub state: ServerState,
    pub http_handle: JoinHandle<()>,
    pub discovery_handle: Option<JoinHandle<()>>,
}

impl StartedServer {
    pub fn abort(self) {
        self.http_handle.abort();
        if let Some(h) = self.discovery_handle {
            h.abort();
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredFileMeta {
    blake3_hex: String,
    size_bytes: u64,
    modified_unix: u64,
    e2e_encrypted: bool,
}

#[derive(Debug, Deserialize)]
struct UploadQuery {
    path: String,
    #[serde(default)]
    e2e: bool,
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    owner: Option<String>,
}

pub async fn start_server(cfg: ServerConfig) -> Result<StartedServer, String> {
    fs::create_dir_all(&cfg.data_dir)
        .map_err(|e| format!("failed to create server data_dir: {e}"))?;

    let ks_dir = cfg
        .keystore_dir
        .clone()
        .unwrap_or_else(|| cfg.data_dir.join("keystore"));
    let master_identity =
        DeviceIdentity::load_or_create("eazyconnect-master", Some(&ks_dir), None)?;
    let master_ed25519_pub_hex = master_identity.ed25519_pub_hex();

    let tls = BuiltServerTls::build(cfg.tls)?;
    let is_tls = tls.acceptor.is_some();
    let tls_cert_sha256_hex = tls.cert_sha256.map(hex::encode);
    let tls_cert_pem = tls.cert_pem;

    let auth_store = AuthStore::load_or_init(
        &cfg.data_dir,
        cfg.enrollment.clone(),
        cfg.bootstrap_admin_pass.as_deref(),
    )?;
    let auth_store = Arc::new(RwLock::new(auth_store));
    let relay = BlindRelayState::new(Arc::clone(&auth_store));

    let state = ServerState {
        auth_store,
        relay,
        data_dir: cfg.data_dir.clone(),
        master_ed25519_pub_hex: master_ed25519_pub_hex.clone(),
        tls_cert_sha256_hex: tls_cert_sha256_hex.clone(),
    };

    let app = build_router(state.clone());

    let listener = TcpListener::bind(cfg.listen_addr)
        .await
        .map_err(|e| format!("failed to bind {}: {e}", cfg.listen_addr))?;
    let addr = listener.local_addr().map_err(|e| e.to_string())?;

    let (discovery_addr, discovery_handle) = match cfg.discovery_addr {
        Some(bind_udp) => {
            let (bound_udp, handle) = spawn_discovery_responder(
                bind_udp,
                cfg.advertised_host.clone(),
                addr.port(),
                is_tls,
                tls_cert_sha256_hex.clone(),
                master_identity,
            )
            .await
            .map_err(|e| format!("failed to bind UDP discovery responder {bind_udp}: {e}"))?;
            (Some(bound_udp), Some(handle))
        }
        None => (None, None),
    };

    let acceptor = tls.acceptor;
    let http_handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _peer)) = listener.accept().await else {
                break;
            };
            configure_tcp_keepalive(&stream);
            let app_clone = app.clone();
            let acceptor_clone = acceptor.clone();

            tokio::spawn(async move {
                let svc = service_fn(move |req: hyper::Request<Incoming>| {
                    let mut router = app_clone.clone();
                    async move { router.call(req).await }
                });
                let builder = ConnBuilder::new(TokioExecutor::new());

                if let Some(tls_acc) = acceptor_clone {
                    let Ok(tls_stream) = tls_acc.accept(stream).await else {
                        return;
                    };
                    let _ = builder
                        .serve_connection_with_upgrades(TokioIo::new(tls_stream), svc)
                        .await;
                } else {
                    let _ = builder
                        .serve_connection_with_upgrades(TokioIo::new(stream), svc)
                        .await;
                }
            });
        }
    });

    Ok(StartedServer {
        addr,
        is_tls,
        tls_cert_sha256_hex,
        tls_cert_pem,
        discovery_addr,
        master_ed25519_pub_hex,
        state,
        http_handle,
        discovery_handle,
    })
}

pub fn build_router(state: ServerState) -> Router<()> {
    Router::new()
        .route("/api/v1/health", get(handle_health))
        .route("/api/v1/auth/challenge", get(handle_auth_challenge))
        .route("/api/v1/auth/verify", post(handle_auth_verify))
        .route("/api/v1/auth/login", post(handle_auth_login))
        .route("/api/v1/users", post(handle_create_user))
        .route("/api/v1/devices", get(handle_list_devices))
        .route(
            "/api/v1/files/upload",
            post(handle_upload_file).layer(DefaultBodyLimit::max(MAX_UPLOAD_BYTES)),
        )
        .route("/api/v1/files/list", get(handle_list_files))
        .route(
            "/api/v1/files/download/{owner}/{*path}",
            get(handle_download_file),
        )
        .route("/api/v1/files/{*path}", delete(handle_delete_file))
        .route("/api/v1/report", post(handle_upload_report))
        .route("/api/v1/relay/telemetry", get(handle_relay_telemetry))
        .route("/api/v1/network", get(handle_network_snapshot))
        .route(
            "/api/v1/network/devices/{client_id}",
            put(handle_device_access),
        )
        .route("/ws", get(handle_ws_upgrade))
        .with_state(state)
}

async fn handle_health(State(state): State<ServerState>) -> Json<HealthResponse> {
    let device_count = state.auth_store.read().await.device_count();
    let online_ws_peers = state.relay.online_count().await;
    Json(HealthResponse {
        status: "ok".to_string(),
        version: VERSION.to_string(),
        master_ed25519_pub_hex: state.master_ed25519_pub_hex,
        tls_cert_sha256_hex: state.tls_cert_sha256_hex,
        device_count,
        online_ws_peers,
    })
}

async fn handle_auth_challenge(State(state): State<ServerState>) -> Response {
    let mut store = state.auth_store.write().await;
    match store.issue_challenge() {
        Ok(c) => Json(c).into_response(),
        Err(e) => api_error(500, e),
    }
}

async fn handle_auth_verify(
    State(state): State<ServerState>,
    Json(req): Json<DeviceAuthRequest>,
) -> Response {
    let mut store = state.auth_store.write().await;
    match store.verify_device_challenge(&req) {
        Ok(tok) => Json::<AuthTokenResponse>(tok).into_response(),
        Err((code, msg)) => api_error(code, msg),
    }
}

async fn handle_auth_login(
    State(state): State<ServerState>,
    Json(req): Json<PasswordLoginRequest>,
) -> Response {
    let mut store = state.auth_store.write().await;
    match store.login_password(&req.username, &req.password) {
        Ok(tok) => Json::<AuthTokenResponse>(tok).into_response(),
        Err((code, msg)) => api_error(code, msg),
    }
}

async fn handle_create_user(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Json(req): Json<CreateUserRequest>,
) -> Response {
    let principal = match require_auth(&state, &headers).await {
        Ok(p) => p,
        Err(resp) => return *resp,
    };
    let mut store = state.auth_store.write().await;
    match store.create_user(&principal, &req.username, &req.password, req.is_admin) {
        Ok(()) => (
            StatusCode::CREATED,
            Json(json!({ "status": "ok", "username": req.username })),
        )
            .into_response(),
        Err((code, msg)) => api_error(code, msg),
    }
}

async fn handle_list_devices(State(state): State<ServerState>, headers: HeaderMap) -> Response {
    if let Err(resp) = require_auth(&state, &headers).await {
        return *resp;
    }
    let devices = state.auth_store.read().await.list_devices();
    Json(devices).into_response()
}

async fn handle_upload_file(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Query(query): Query<UploadQuery>,
    body: Bytes,
) -> Response {
    let principal = match require_auth(&state, &headers).await {
        Ok(p) => p,
        Err(resp) => return *resp,
    };

    let rel = match validate_rel_path(&query.path) {
        Ok(p) => p,
        Err((code, msg)) => return api_error(code, msg),
    };

    let owner = match validate_id(&principal.subject) {
        Ok(o) => o,
        Err(msg) => return api_error(400, msg),
    };

    let file_path = join_rel_path(&state.data_dir.join("files").join(&owner), &rel);
    let meta_path = meta_path_for(&state.data_dir, &owner, &rel);

    let blake3_hex = blake3::hash(&body).to_hex().to_string();
    let size_bytes = body.len() as u64;
    let modified_unix = now_unix();
    let meta = StoredFileMeta {
        blake3_hex: blake3_hex.clone(),
        size_bytes,
        modified_unix,
        e2e_encrypted: query.e2e,
    };

    if let Err(e) = write_bytes_atomic(&file_path, &body) {
        return api_error(500, format!("failed to store uploaded file: {e}"));
    }
    let meta_json = match serde_json::to_vec_pretty(&meta) {
        Ok(v) => v,
        Err(e) => return api_error(500, e.to_string()),
    };
    if let Err(e) = write_bytes_atomic(&meta_path, &meta_json) {
        return api_error(500, format!("failed to write file metadata: {e}"));
    }

    Json(ServerFileEntry {
        filename: rel,
        size_bytes,
        blake3_hex,
        modified_unix,
        e2e_encrypted: query.e2e,
    })
    .into_response()
}

async fn handle_list_files(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Response {
    let principal = match require_auth(&state, &headers).await {
        Ok(p) => p,
        Err(resp) => return *resp,
    };

    let target_owner = match query.owner.as_deref() {
        Some(requested) if requested != principal.subject => {
            if !principal.is_admin {
                return api_error(403, "admin privileges required to list another owner");
            }
            match validate_id(requested) {
                Ok(v) => v,
                Err(e) => return api_error(400, e),
            }
        }
        _ => match validate_id(&principal.subject) {
            Ok(v) => v,
            Err(e) => return api_error(400, e),
        },
    };

    let owner_dir = state.data_dir.join("files").join(&target_owner);
    let mut entries = Vec::new();
    if owner_dir.exists() {
        let mut stack = vec![owner_dir.clone()];
        while let Some(dir) = stack.pop() {
            let Ok(rd) = fs::read_dir(&dir) else {
                continue;
            };
            for item in rd.flatten() {
                let path = item.path();
                let Ok(ft) = item.file_type() else {
                    continue;
                };
                if ft.is_symlink() {
                    continue;
                }
                if ft.is_dir() {
                    stack.push(path);
                } else if ft.is_file() {
                    let Ok(rel_os) = path.strip_prefix(&owner_dir) else {
                        continue;
                    };
                    let rel = rel_to_forward_slashes(rel_os);
                    if rel.starts_with(".tmp-") {
                        continue;
                    }
                    let meta_path = meta_path_for(&state.data_dir, &target_owner, &rel);
                    let entry = if let Ok(raw_meta) = fs::read(&meta_path) {
                        if let Ok(m) = serde_json::from_slice::<StoredFileMeta>(&raw_meta) {
                            ServerFileEntry {
                                filename: rel,
                                size_bytes: m.size_bytes,
                                blake3_hex: m.blake3_hex,
                                modified_unix: m.modified_unix,
                                e2e_encrypted: m.e2e_encrypted,
                            }
                        } else {
                            compute_entry_from_disk(&path, rel)
                        }
                    } else {
                        compute_entry_from_disk(&path, rel)
                    };
                    entries.push(entry);
                }
            }
        }
    }
    entries.sort_by(|a, b| a.filename.cmp(&b.filename));

    Json(ListFilesResponse {
        owner: target_owner,
        files: entries,
    })
    .into_response()
}

async fn handle_download_file(
    State(state): State<ServerState>,
    headers: HeaderMap,
    AxumPath((owner, raw_path)): AxumPath<(String, String)>,
) -> Response {
    let principal = match require_auth(&state, &headers).await {
        Ok(p) => p,
        Err(resp) => return *resp,
    };

    let clean_owner = match validate_id(&owner) {
        Ok(o) => o,
        Err(msg) => return api_error(400, msg),
    };
    if principal.subject != clean_owner && !principal.is_admin {
        return api_error(403, "cannot download another owner's files");
    }

    let rel = match validate_rel_path(&raw_path) {
        Ok(r) => r,
        Err((code, msg)) => return api_error(code, msg),
    };

    let file_path = join_rel_path(&state.data_dir.join("files").join(&clean_owner), &rel);
    let data = match fs::read(&file_path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return api_error(404, format!("file not found: {rel}"));
        }
        Err(e) => return api_error(500, e.to_string()),
    };

    let blake3_hex = blake3::hash(&data).to_hex().to_string();
    let e2e = fs::read(meta_path_for(&state.data_dir, &clean_owner, &rel))
        .ok()
        .and_then(|b| serde_json::from_slice::<StoredFileMeta>(&b).ok())
        .map(|m| m.e2e_encrypted)
        .unwrap_or(false);

    let mut resp = (StatusCode::OK, data).into_response();
    let hdrs = resp.headers_mut();
    hdrs.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    if let Ok(hv) = HeaderValue::from_str(&blake3_hex) {
        hdrs.insert("x-eazy-blake3", hv);
    }
    hdrs.insert(
        "x-eazy-e2e",
        HeaderValue::from_static(if e2e { "true" } else { "false" }),
    );
    resp
}

async fn handle_delete_file(
    State(state): State<ServerState>,
    headers: HeaderMap,
    AxumPath(raw_path): AxumPath<String>,
) -> Response {
    let principal = match require_auth(&state, &headers).await {
        Ok(p) => p,
        Err(resp) => return *resp,
    };

    let owner = match validate_id(&principal.subject) {
        Ok(o) => o,
        Err(msg) => return api_error(400, msg),
    };
    let rel = match validate_rel_path(&raw_path) {
        Ok(r) => r,
        Err((code, msg)) => return api_error(code, msg),
    };

    let file_path = join_rel_path(&state.data_dir.join("files").join(&owner), &rel);
    if !file_path.exists() {
        return api_error(404, format!("file not found: {rel}"));
    }
    if let Err(e) = fs::remove_file(&file_path) {
        return api_error(500, format!("failed to delete file: {e}"));
    }
    let meta_path = meta_path_for(&state.data_dir, &owner, &rel);
    let _ = fs::remove_file(meta_path);

    Json(json!({ "status": "deleted", "path": rel })).into_response()
}

async fn handle_upload_report(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Json(report): Json<Value>,
) -> Response {
    let principal = match require_auth(&state, &headers).await {
        Ok(p) => p,
        Err(resp) => return *resp,
    };
    let owner = match validate_id(&principal.subject) {
        Ok(o) => o,
        Err(msg) => return api_error(400, msg),
    };
    let ts = now_unix();
    let mut rnd = [0u8; 4];
    let _ = getrandom::getrandom(&mut rnd);
    let filename = format!("{ts}-{}.json", hex::encode(rnd));
    let dest = state.data_dir.join("reports").join(&owner).join(&filename);
    let Ok(bytes) = serde_json::to_vec_pretty(&report) else {
        return api_error(400, "invalid JSON report");
    };
    if let Err(e) = write_bytes_atomic(&dest, &bytes) {
        return api_error(500, format!("failed to write diagnostic report: {e}"));
    }
    Json(json!({ "status": "ok", "saved_as": filename })).into_response()
}

async fn handle_relay_telemetry(
    State(state): State<ServerState>,
    headers: HeaderMap,
) -> Response {
    if let Err(resp) = require_auth(&state, &headers).await {
        return *resp;
    }
    Json(state.relay.snapshot().await).into_response()
}

async fn handle_network_snapshot(State(state): State<ServerState>, headers: HeaderMap) -> Response {
    if let Err(resp) = require_admin(&state, &headers).await {
        return *resp;
    }
    let store = state.auth_store.read().await;
    let relay = state.relay.snapshot().await;
    let snapshot = NetworkSnapshot {
        uptime_seconds: state.relay.uptime_seconds(),
        devices: store.network_devices(&relay.online_peers),
        relay,
    };
    ([(header::CACHE_CONTROL, "no-store")], Json(snapshot)).into_response()
}

async fn handle_device_access(
    State(state): State<ServerState>,
    headers: HeaderMap,
    AxumPath(client_id): AxumPath<String>,
    Json(req): Json<DeviceAccessRequest>,
) -> Response {
    if let Err(resp) = require_admin(&state, &headers).await {
        return *resp;
    }
    let client_id = match validate_id(&client_id) {
        Ok(id) => id,
        Err(err) => return api_error(400, err),
    };

    match state.relay.set_device_blocked(&client_id, req.blocked).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err((status, err)) => api_error(status, err),
    }
}

async fn handle_ws_upgrade(ws: WebSocketUpgrade, State(state): State<ServerState>) -> Response {
    let relay = state.relay.clone();
    ws.on_upgrade(move |socket| async move {
        handle_relay_socket(socket, relay).await;
    })
}

async fn require_auth(
    state: &ServerState,
    headers: &HeaderMap,
) -> Result<AuthenticatedPrincipal, Box<Response>> {
    let Some(token) = extract_bearer(headers) else {
        return Err(Box::new(api_error(401, "missing Bearer authorization header")));
    };
    let mut store = state.auth_store.write().await;
    store
        .authenticate_bearer(&token)
        .ok_or_else(|| Box::new(api_error(401, "invalid or expired token")))
}

async fn require_admin(state: &ServerState, headers: &HeaderMap) -> Result<(), Box<Response>> {
    let principal = require_auth(state, headers).await?;
    if principal.is_admin {
        Ok(())
    } else {
        Err(Box::new(api_error(403, "admin privileges required")))
    }
}

fn extract_bearer(headers: &HeaderMap) -> Option<String> {
    let val = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let trimmed = val.trim();
    if trimmed.len() >= 7 && trimmed[..7].eq_ignore_ascii_case("bearer ") {
        Some(trimmed[7..].trim().to_string())
    } else {
        None
    }
}

fn api_error(status: u16, msg: impl Into<String>) -> Response {
    let code = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let body = Json(json!({ "error": msg.into() }));
    (code, body).into_response()
}

pub fn validate_rel_path(raw: &str) -> Result<String, (u16, String)> {
    let normalized = raw.trim().replace('\\', "/");
    if normalized.is_empty() || normalized.len() > 512 {
        return Err((400, "relative path cannot be empty or exceed 512 chars".to_string()));
    }
    if normalized.starts_with('/') || normalized.contains('\0') || normalized.contains(':') {
        return Err((400, "invalid characters or absolute prefix in path".to_string()));
    }
    let mut parts = Vec::new();
    for seg in normalized.split('/') {
        if seg.is_empty() || seg == "." || seg == ".." {
            return Err((400, "path traversal or empty segment is forbidden".to_string()));
        }
        if seg.chars().any(|c| c.is_control()) {
            return Err((400, "control characters in path are forbidden".to_string()));
        }
        parts.push(seg);
    }
    let joined = parts.join("/");
    let check_path = Path::new(&joined);
    if check_path
        .components()
        .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err((400, "unsafe path component".to_string()));
    }
    Ok(joined)
}

fn join_rel_path(base: &Path, clean_rel: &str) -> PathBuf {
    let mut out = base.to_path_buf();
    for seg in clean_rel.split('/') {
        out.push(seg);
    }
    out
}

fn meta_path_for(data_dir: &Path, owner: &str, clean_rel: &str) -> PathBuf {
    let rel_meta = format!("{clean_rel}.meta.json");
    join_rel_path(&data_dir.join("meta").join(owner), &rel_meta)
}

fn rel_to_forward_slashes(path: &Path) -> String {
    path.components()
        .filter_map(|c| match c {
            Component::Normal(s) => s.to_str(),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn compute_entry_from_disk(path: &Path, rel: String) -> ServerFileEntry {
    let bytes = fs::read(path).unwrap_or_default();
    let blake3_hex = blake3::hash(&bytes).to_hex().to_string();
    let modified_unix = fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    ServerFileEntry {
        filename: rel,
        size_bytes: bytes.len() as u64,
        blake3_hex,
        modified_unix,
        e2e_encrypted: false,
    }
}

fn write_bytes_atomic(dest: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut rnd = [0u8; 6];
    let _ = getrandom::getrandom(&mut rnd);
    let tmp_name = format!(
        ".tmp-{}-{}",
        dest.file_name().and_then(|s| s.to_str()).unwrap_or("blob"),
        hex::encode(rnd)
    );
    let tmp_path = dest.with_file_name(tmp_name);
    fs::write(&tmp_path, bytes)?;
    let _ = fs::remove_file(dest);
    fs::rename(&tmp_path, dest)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[allow(dead_code)]
fn _assert_infallible(_: Infallible) {}
