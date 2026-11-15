use std::time::Duration;

use bytes::Bytes;
use eazyconnect_core::{
    connect_tcp_keepalive, http_auth_sign_bytes, parse_endpoint_url, AuthChallengeResponse,
    AuthTokenResponse, ClientTlsConfig, CreateUserRequest, DeviceAuthRequest, DeviceRecordView,
    HealthResponse, ListFilesResponse, ParsedEndpoint, PasswordLoginRequest,
    RelayTelemetrySnapshot, ServerFileEntry,
};
use eazyconnect_hw::DeviceIdentity;
use http_body_util::{BodyExt, Full};
use hyper::header::{AUTHORIZATION, CONNECTION, CONTENT_TYPE, HOST};
use hyper::{HeaderMap, Method, Request};
use hyper_util::rt::TokioIo;
use serde::de::DeserializeOwned;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

fn transfer_timeout(method: &Method, path_and_query: &str, body_len: usize) -> Duration {
    if *method == Method::GET && path_and_query.starts_with("/api/v1/files/download/") {
        return Duration::from_secs(300);
    }
    let secs = 30u64.saturating_add((body_len as u64) / (64 * 1024));
    Duration::from_secs(secs.min(600))
}

#[derive(Clone)]
pub struct MasterHttpClient {
    endpoint: ParsedEndpoint,
    tls_config: ClientTlsConfig,
    allow_insecure_http: bool,
}

impl MasterHttpClient {
    pub fn new(
        base_url: &str,
        tls_config: ClientTlsConfig,
        allow_insecure_http: bool,
    ) -> Result<Self, String> {
        let endpoint = parse_endpoint_url(base_url)?;
        if !endpoint.is_tls && !allow_insecure_http {
            return Err(format!(
                "refusing plaintext HTTP endpoint '{}' without explicit --insecure-http opt-in",
                endpoint.full_url
            ));
        }
        if endpoint.is_tls {
            // Validate TLS configuration upfront (e.g. PEM parsing).
            let _ = tls_config.build_client_config()?;
        }
        Ok(Self {
            endpoint,
            tls_config,
            allow_insecure_http,
        })
    }

    pub fn base_url(&self) -> &str {
        &self.endpoint.full_url
    }

    pub async fn health(&self) -> Result<HealthResponse, String> {
        self.get_json("/api/v1/health", None).await
    }

    pub async fn auth_challenge(&self) -> Result<AuthChallengeResponse, String> {
        self.get_json("/api/v1/auth/challenge", None).await
    }

    pub async fn enroll_device(
        &self,
        identity: &DeviceIdentity,
        invite_code: Option<&str>,
    ) -> Result<AuthTokenResponse, String> {
        let ch = self.auth_challenge().await?;
        let nonce_raw =
            hex::decode(&ch.nonce_hex).map_err(|e| format!("invalid nonce_hex from server: {e}"))?;
        let nonce: [u8; 32] = nonce_raw
            .as_slice()
            .try_into()
            .map_err(|_| "server challenge nonce must be 32 bytes".to_string())?;
        let msg = http_auth_sign_bytes(&nonce, identity.client_id(), &ch.challenge_id);
        let sig = identity.sign(&msg);

        let body = DeviceAuthRequest {
            client_id: identity.client_id().to_string(),
            challenge_id: ch.challenge_id,
            ed25519_pub_hex: identity.ed25519_pub_hex(),
            signature_hex: hex::encode(sig),
            invite_code: invite_code.map(ToString::to_string),
        };
        self.post_json("/api/v1/auth/verify", None, &body).await
    }

    pub async fn login_password(
        &self,
        username: &str,
        password: &str,
    ) -> Result<AuthTokenResponse, String> {
        let req = PasswordLoginRequest {
            username: username.to_string(),
            password: password.to_string(),
        };
        self.post_json("/api/v1/auth/login", None, &req).await
    }

    pub async fn create_user(&self, token: &str, req: &CreateUserRequest) -> Result<(), String> {
        let payload = serde_json::to_vec(req).map_err(|e| e.to_string())?;
        let (status, _, resp) = self
            .send_raw(
                Method::POST,
                "/api/v1/users",
                Some(token),
                Some("application/json"),
                payload,
            )
            .await?;
        ensure_success(status, &resp)
    }

    pub async fn list_devices(&self, token: &str) -> Result<Vec<DeviceRecordView>, String> {
        self.get_json("/api/v1/devices", Some(token)).await
    }

    pub async fn upload_bytes(
        &self,
        token: &str,
        rel_path: &str,
        bytes: &[u8],
        e2e: bool,
    ) -> Result<ServerFileEntry, String> {
        let enc_path = url_encode_component(rel_path);
        let uri = format!("/api/v1/files/upload?path={enc_path}&e2e={e2e}");
        let (status, _, resp) = self
            .send_raw(
                Method::POST,
                &uri,
                Some(token),
                Some("application/octet-stream"),
                bytes.to_vec(),
            )
            .await?;
        ensure_success(status, &resp)?;
        serde_json::from_slice(&resp)
            .map_err(|e| format!("invalid upload response JSON: {e}"))
    }

    pub async fn list_files(
        &self,
        token: &str,
        owner: Option<&str>,
    ) -> Result<ListFilesResponse, String> {
        let uri = match owner {
            Some(o) => format!("/api/v1/files/list?owner={}", url_encode_component(o)),
            None => "/api/v1/files/list".to_string(),
        };
        self.get_json(&uri, Some(token)).await
    }

    pub async fn download_bytes(
        &self,
        token: &str,
        owner: &str,
        rel_path: &str,
    ) -> Result<(Vec<u8>, Option<String>, bool), String> {
        let enc_owner = url_encode_component(owner);
        let enc_path = url_encode_path_segments(rel_path);
        let uri = format!("/api/v1/files/download/{enc_owner}/{enc_path}");
        let (status, headers, resp) = self
            .send_raw(Method::GET, &uri, Some(token), None, Vec::new())
            .await?;
        ensure_success(status, &resp)?;

        let expected_hash = headers
            .get("x-eazy-blake3")
            .and_then(|v| v.to_str().ok())
            .map(ToString::to_string);
        if let Some(ref expected) = expected_hash {
            let actual = blake3::hash(&resp).to_hex().to_string();
            if actual != *expected {
                return Err(format!(
                    "downloaded file integrity mismatch: expected {expected}, got {actual}"
                ));
            }
        }
        let e2e = headers
            .get("x-eazy-e2e")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v == "true");

        Ok((resp, expected_hash, e2e))
    }

    pub async fn delete_file(&self, token: &str, rel_path: &str) -> Result<(), String> {
        let uri = format!("/api/v1/files/{}", url_encode_path_segments(rel_path));
        let (status, _, resp) = self
            .send_raw(Method::DELETE, &uri, Some(token), None, Vec::new())
            .await?;
        ensure_success(status, &resp)
    }

    pub async fn send_report(
        &self,
        token: &str,
        report: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        self.post_json("/api/v1/report", Some(token), report).await
    }

    pub async fn relay_telemetry(&self, token: &str) -> Result<RelayTelemetrySnapshot, String> {
        self.get_json("/api/v1/relay/telemetry", Some(token)).await
    }

    async fn get_json<T: DeserializeOwned>(
        &self,
        path: &str,
        token: Option<&str>,
    ) -> Result<T, String> {
        let (status, _, body) = self
            .send_raw(Method::GET, path, token, None, Vec::new())
            .await?;
        ensure_success(status, &body)?;
        serde_json::from_slice(&body)
            .map_err(|e| format!("failed to parse JSON from {path}: {e}"))
    }

    async fn post_json<B: serde::Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        token: Option<&str>,
        req_body: &B,
    ) -> Result<T, String> {
        let payload = serde_json::to_vec(req_body).map_err(|e| e.to_string())?;
        let (status, _, body) = self
            .send_raw(
                Method::POST,
                path,
                token,
                Some("application/json"),
                payload,
            )
            .await?;
        ensure_success(status, &body)?;
        serde_json::from_slice(&body)
            .map_err(|e| format!("failed to parse JSON from {path}: {e}"))
    }

    async fn send_raw(
        &self,
        method: Method,
        path_and_query: &str,
        token: Option<&str>,
        content_type: Option<&str>,
        body: Vec<u8>,
    ) -> Result<(u16, HeaderMap, Vec<u8>), String> {
        let timeout = transfer_timeout(&method, path_and_query, body.len());
        let tcp = connect_tcp_keepalive(&self.endpoint.tcp_addr, CONNECT_TIMEOUT).await?;

        tokio::time::timeout(timeout, async {
            let full_path = if self.endpoint.base_path.is_empty() {
                path_and_query.to_string()
            } else {
                format!("{}{}", self.endpoint.base_path, path_and_query)
            };

            let mut builder = Request::builder()
                .method(method)
                .uri(&full_path)
                .header(HOST, &self.endpoint.host_header)
                .header(CONNECTION, "close");

            if let Some(tok) = token {
                builder = builder.header(AUTHORIZATION, format!("Bearer {tok}"));
            }
            if let Some(ct) = content_type {
                builder = builder.header(CONTENT_TYPE, ct);
            }
            let req = builder
                .body(Full::new(Bytes::from(body)))
                .map_err(|e| format!("failed to build HTTP request: {e}"))?;

            let (status, headers, resp_bytes) = if self.endpoint.is_tls {
                let connector = self.tls_config.build_connector()?;
                let tls = connector
                    .connect(self.endpoint.server_name.clone(), tcp)
                    .await
                    .map_err(|e| format!("TLS handshake failed: {e}"))?;
                send_over_stream(tls, req).await?
            } else if self.allow_insecure_http {
                send_over_stream(tcp, req).await?
            } else {
                return Err("insecure HTTP disallowed".to_string());
            };

            Ok((status, headers, resp_bytes))
        })
        .await
        .map_err(|_| format!("HTTP request to '{}' timed out after {}s", self.endpoint.full_url, timeout.as_secs()))?
    }
}

async fn send_over_stream<S>(
    stream: S,
    req: Request<Full<Bytes>>,
) -> Result<(u16, HeaderMap, Vec<u8>), String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|e| format!("HTTP/1.1 handshake failed: {e}"))?;

    tokio::spawn(async move {
        let _ = conn.await;
    });

    let resp = sender
        .send_request(req)
        .await
        .map_err(|e| format!("HTTP send_request failed: {e}"))?;
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let collected = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| format!("failed to read HTTP response body: {e}"))?;
    Ok((status, headers, collected.to_bytes().to_vec()))
}

fn ensure_success(status: u16, body: &[u8]) -> Result<(), String> {
    if (200..300).contains(&status) {
        return Ok(());
    }
    let detail = std::str::from_utf8(body).unwrap_or("<binary error body>");
    Err(format!("HTTP {status}: {detail}"))
}

pub fn url_encode_component(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(*b, b'-' | b'_' | b'.' | b'~') {
            out.push(*b as char);
        } else {
            out.push('%');
            out.push_str(&format!("{:02X}", b));
        }
    }
    out
}

fn url_encode_path_segments(rel_path: &str) -> String {
    rel_path
        .replace('\\', "/")
        .split('/')
        .filter(|s| !s.is_empty())
        .map(url_encode_component)
        .collect::<Vec<_>>()
        .join("/")
}
