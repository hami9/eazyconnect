use std::collections::HashSet;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rcgen::generate_simple_self_signed;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{
    ring as rustls_ring, verify_tls12_signature, verify_tls13_signature, WebPkiSupportedAlgorithms,
};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore,
    ServerConfig, SignatureScheme,
};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Master server TLS configuration (defaults to TLS with persistent self-signed or PEM certs).
#[derive(Clone, Debug)]
pub enum ServerTlsConfig {
    SelfSigned {
        san_hosts: Vec<String>,
    },
    /// Loads PEM files from `cert_path`/`key_path`, or generates and persists a stable self-signed
    /// certificate on first start (preserving `--tls-pin` for remote VPN peers across restarts).
    LoadOrCreateSelfSigned {
        cert_path: PathBuf,
        key_path: PathBuf,
        san_hosts: Vec<String>,
        force_regen: bool,
    },
    PemFiles {
        cert_pem: Vec<u8>,
        key_pem: Vec<u8>,
    },
    /// Explicitly disables TLS (`http://` & `ws://`). Intended only for local testing.
    InsecureDisabled,
}

impl ServerTlsConfig {
    pub fn from_pem_paths(cert_path: &Path, key_path: &Path) -> Result<Self, String> {
        let cert_pem = std::fs::read(cert_path)
            .map_err(|e| format!("failed to read TLS cert {}: {e}", cert_path.display()))?;
        let key_pem = std::fs::read(key_path)
            .map_err(|e| format!("failed to read TLS key {}: {e}", key_path.display()))?;
        Ok(Self::PemFiles { cert_pem, key_pem })
    }
}

fn dedupe_san_hosts(san_hosts: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for host in san_hosts {
        let trimmed = host.trim();
        if !trimmed.is_empty() && seen.insert(trimmed.to_string()) {
            out.push(trimmed.to_string());
        }
    }
    if out.is_empty() {
        out.push("localhost".to_string());
        out.push("127.0.0.1".to_string());
    }
    out
}

fn generate_self_signed_pem(san_hosts: Vec<String>) -> Result<(Vec<u8>, Vec<u8>), String> {
    let hosts = dedupe_san_hosts(san_hosts);
    let certified = generate_simple_self_signed(hosts)
        .map_err(|e| format!("failed to generate self-signed TLS cert: {e}"))?;
    let cert_pem = certified.cert.pem().into_bytes();
    let key_pem = certified.key_pair.serialize_pem().into_bytes();
    Ok((cert_pem, key_pem))
}

fn write_pem_atomic(path: &Path, data: &[u8], is_secret_key: bool) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create TLS dir {}: {e}", parent.display()))?;
        }
    }
    let tmp_name = format!(
        "{}.tmp.{}",
        path.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("tls.pem"),
        std::process::id()
    );
    let tmp_path = path.with_file_name(tmp_name);
    std::fs::write(&tmp_path, data)
        .map_err(|e| format!("failed to write temporary TLS file {}: {e}", tmp_path.display()))?;

    #[cfg(unix)]
    if is_secret_key {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600)).map_err(
            |e| format!("failed to restrict permissions on {}: {e}", tmp_path.display()),
        )?;
    }
    #[cfg(not(unix))]
    let _ = is_secret_key;

    std::fs::rename(&tmp_path, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp_path);
        format!("failed to commit TLS file {}: {e}", path.display())
    })
}

fn build_tls_from_pem(cert_pem: Vec<u8>, key_pem: Vec<u8>) -> Result<BuiltServerTls, String> {
    let mut cert_reader = Cursor::new(&cert_pem);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("failed to parse TLS cert PEM: {e}"))?;
    if certs.is_empty() {
        return Err("TLS cert PEM contains no certificates".to_string());
    }
    let cert_sha256: [u8; 32] = Sha256::digest(certs[0].as_ref()).into();

    let mut key_reader = Cursor::new(&key_pem);
    let key_der = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| format!("failed to parse TLS key PEM: {e}"))?
        .ok_or_else(|| "TLS key PEM contains no private key".to_string())?;

    let mut server_cfg = ServerConfig::builder_with_provider(Arc::new(
        rustls_ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| e.to_string())?
    .with_no_client_auth()
    .with_single_cert(certs, key_der)
    .map_err(|e| format!("failed to configure rustls server: {e}"))?;
    server_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(BuiltServerTls {
        acceptor: Some(tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg))),
        cert_sha256: Some(cert_sha256),
        cert_pem: Some(String::from_utf8_lossy(&cert_pem).into_owned()),
    })
}

/// Prepared server TLS acceptor and SHA-256 certificate pin.
#[derive(Clone)]
pub struct BuiltServerTls {
    pub acceptor: Option<tokio_rustls::TlsAcceptor>,
    pub cert_sha256: Option<[u8; 32]>,
    pub cert_pem: Option<String>,
}

impl BuiltServerTls {
    pub fn build(cfg: ServerTlsConfig) -> Result<Self, String> {
        match cfg {
            ServerTlsConfig::InsecureDisabled => Ok(Self {
                acceptor: None,
                cert_sha256: None,
                cert_pem: None,
            }),
            ServerTlsConfig::SelfSigned { san_hosts } => {
                let (cert_pem, key_pem) = generate_self_signed_pem(san_hosts)?;
                build_tls_from_pem(cert_pem, key_pem)
            }
            ServerTlsConfig::LoadOrCreateSelfSigned {
                cert_path,
                key_path,
                san_hosts,
                force_regen,
            } => {
                if !force_regen && cert_path.exists() && key_path.exists() {
                    let cert_pem = std::fs::read(&cert_path).map_err(|e| {
                        format!("failed to read persisted TLS cert {}: {e}", cert_path.display())
                    })?;
                    let key_pem = std::fs::read(&key_path).map_err(|e| {
                        format!("failed to read persisted TLS key {}: {e}", key_path.display())
                    })?;
                    return build_tls_from_pem(cert_pem, key_pem);
                }

                let (cert_pem, key_pem) = generate_self_signed_pem(san_hosts)?;
                write_pem_atomic(&cert_path, &cert_pem, false)?;
                write_pem_atomic(&key_path, &key_pem, true)?;
                build_tls_from_pem(cert_pem, key_pem)
            }
            ServerTlsConfig::PemFiles { cert_pem, key_pem } => {
                build_tls_from_pem(cert_pem, key_pem)
            }
        }
    }
}

/// Applies `TCP_NODELAY` and OS-level `SO_KEEPALIVE` probes for long-lived VPN/NAT connections.
pub fn configure_tcp_keepalive(stream: &tokio::net::TcpStream) {
    let _ = stream.set_nodelay(true);
    let sock_ref = socket2::SockRef::from(stream);
    let _ = sock_ref.set_keepalive(true);
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(20))
        .with_interval(Duration::from_secs(10));
    let _ = sock_ref.set_tcp_keepalive(&keepalive);
}

/// Connects a TCP stream with an explicit connect timeout and enables TCP keepalive + `TCP_NODELAY`.
pub async fn connect_tcp_keepalive(
    tcp_addr: &str,
    connect_timeout: Duration,
) -> Result<tokio::net::TcpStream, String> {
    let stream = tokio::time::timeout(connect_timeout, tokio::net::TcpStream::connect(tcp_addr))
        .await
        .map_err(|_| format!("TCP connect timed out after {}s to {tcp_addr}", connect_timeout.as_secs()))?
        .map_err(|e| format!("TCP connect failed to {tcp_addr}: {e}"))?;
    configure_tcp_keepalive(&stream);
    Ok(stream)
}

/// Client TLS trust policy shared cleanly across HTTPS REST calls and WSS WebSocket streams.
#[derive(Clone, Debug)]
pub enum ClientTlsConfig {
    WebPkiRoots,
    CaPem(Vec<u8>),
    PinnedCertSha256([u8; 32]),
}

impl ClientTlsConfig {
    pub fn build_client_config(&self) -> Result<ClientConfig, String> {
        let provider = Arc::new(rustls_ring::default_provider());
        let builder = ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?;

        let cfg = match self {
            Self::WebPkiRoots => {
                let mut roots = RootCertStore::empty();
                roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                builder
                    .with_root_certificates(roots)
                    .with_no_client_auth()
            }
            Self::CaPem(pem_bytes) => {
                let mut reader = Cursor::new(pem_bytes);
                let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| format!("failed to parse CA PEM: {e}"))?;
                if certs.is_empty() {
                    return Err("CA PEM contains no certificates".to_string());
                }
                let mut roots = RootCertStore::empty();
                let (added, _) = roots.add_parsable_certificates(certs);
                if added == 0 {
                    return Err("failed to load any valid X.509 certificate from CA PEM".to_string());
                }
                builder
                    .with_root_certificates(roots)
                    .with_no_client_auth()
            }
            Self::PinnedCertSha256(expected_sha256) => {
                let verifier = Arc::new(PinnedCertVerifier {
                    expected_sha256: *expected_sha256,
                    supported: provider.signature_verification_algorithms,
                });
                builder
                    .dangerous()
                    .with_custom_certificate_verifier(verifier)
                    .with_no_client_auth()
            }
        };

        Ok(cfg)
    }

    pub fn build_connector(&self) -> Result<tokio_rustls::TlsConnector, String> {
        Ok(tokio_rustls::TlsConnector::from(Arc::new(
            self.build_client_config()?,
        )))
    }
}

#[derive(Debug)]
struct PinnedCertVerifier {
    expected_sha256: [u8; 32],
    supported: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let actual: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if actual.ct_eq(&self.expected_sha256).into() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(TlsError::InvalidCertificate(CertificateError::BadSignature))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(message, cert, dss, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.supported_schemes()
    }
}

/// Parsed URL details supporting `https://`, `http://`, `wss://`, and `ws://`.
#[derive(Clone, Debug)]
pub struct ParsedEndpoint {
    pub is_tls: bool,
    pub host_header: String,
    pub tcp_addr: String,
    pub server_name: ServerName<'static>,
    pub base_path: String,
    pub full_url: String,
}

pub fn parse_endpoint_url(raw: &str) -> Result<ParsedEndpoint, String> {
    let trimmed = raw.trim().trim_end_matches('/');
    let (is_tls, default_port, rest) = if let Some(r) = trimmed.strip_prefix("https://") {
        (true, 443u16, r)
    } else if let Some(r) = trimmed.strip_prefix("wss://") {
        (true, 443u16, r)
    } else if let Some(r) = trimmed.strip_prefix("http://") {
        (false, 80u16, r)
    } else if let Some(r) = trimmed.strip_prefix("ws://") {
        (false, 80u16, r)
    } else {
        return Err("URL must begin with https://, wss://, http://, or ws://".to_string());
    };

    let (authority, path_tail) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, ""),
    };
    if authority.is_empty() {
        return Err("URL missing host".to_string());
    }

    let (host, port) = if let Some(stripped) = authority.strip_prefix('[') {
        let end = stripped
            .find(']')
            .ok_or_else(|| "invalid IPv6 host in URL".to_string())?;
        let ip_part = &stripped[..end];
        let after = &stripped[end + 1..];
        let port = if let Some(p) = after.strip_prefix(':') {
            p.parse::<u16>().map_err(|_| "invalid port in URL")?
        } else {
            default_port
        };
        (ip_part.to_string(), port)
    } else if let Some((h, p)) = authority.rsplit_once(':') {
        let port = p.parse::<u16>().map_err(|_| "invalid port in URL")?;
        (h.to_string(), port)
    } else {
        (authority.to_string(), default_port)
    };

    let tcp_addr = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let server_name = ServerName::try_from(host)
        .map_err(|_| "invalid TLS server name in URL".to_string())?
        .to_owned();

    Ok(ParsedEndpoint {
        is_tls,
        host_header: authority.to_string(),
        tcp_addr,
        server_name,
        base_path: path_tail.to_string(),
        full_url: trimmed.to_string(),
    })
}

pub fn parse_sha256_pin_hex(input: &str) -> Result<[u8; 32], String> {
    let cleaned: String = input
        .chars()
        .filter(|c| !matches!(c, ':' | '-' | ' '))
        .collect();
    let bytes = hex::decode(&cleaned).map_err(|e| format!("invalid hex digest: {e}"))?;
    <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| "expected 32-byte (64 hex characters) SHA-256 or Ed25519 key".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_persistent_self_signed_tls_pin_survives_reload_and_rotates_on_regen() {
        let dir = std::env::temp_dir().join(format!(
            "eazyconnect_tls_persist_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let cert_path = dir.join("tls").join("cert.pem");
        let key_path = dir.join("tls").join("key.pem");

        let first = BuiltServerTls::build(ServerTlsConfig::LoadOrCreateSelfSigned {
            cert_path: cert_path.clone(),
            key_path: key_path.clone(),
            san_hosts: vec![
                "localhost".to_string(),
                "127.0.0.1".to_string(),
                "10.8.0.1".to_string(),
            ],
            force_regen: false,
        })
        .expect("initial self-signed TLS generation");
        assert!(cert_path.exists());
        assert!(key_path.exists());

        let second = BuiltServerTls::build(ServerTlsConfig::LoadOrCreateSelfSigned {
            cert_path: cert_path.clone(),
            key_path: key_path.clone(),
            san_hosts: vec!["localhost".to_string()],
            force_regen: false,
        })
        .expect("reload persisted TLS files");
        assert_eq!(first.cert_sha256, second.cert_sha256);

        let rotated = BuiltServerTls::build(ServerTlsConfig::LoadOrCreateSelfSigned {
            cert_path,
            key_path,
            san_hosts: vec!["localhost".to_string(), "127.0.0.1".to_string()],
            force_regen: true,
        })
        .expect("force_regen TLS rotation");
        assert_ne!(first.cert_sha256, rotated.cert_sha256);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
