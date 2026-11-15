use std::io::Cursor;
use std::path::Path;
use std::sync::Arc;

use rcgen::generate_simple_self_signed;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{
    ring as rustls_ring, verify_tls12_signature, verify_tls13_signature, WebPkiSupportedAlgorithms,
};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore,
    ServerConfig, SignatureScheme,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Master server TLS configuration (defaults to TLS with self-signed or PEM certs).
#[derive(Clone, Debug)]
pub enum ServerTlsConfig {
    SelfSigned { san_hosts: Vec<String> },
    PemFiles { cert_pem: Vec<u8>, key_pem: Vec<u8> },
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
            ServerTlsConfig::SelfSigned { mut san_hosts } => {
                if san_hosts.is_empty() {
                    san_hosts.push("localhost".to_string());
                    san_hosts.push("127.0.0.1".to_string());
                }
                let certified = generate_simple_self_signed(san_hosts)
                    .map_err(|e| format!("failed to generate self-signed TLS cert: {e}"))?;
                let cert_pem = certified.cert.pem();
                let cert_der = CertificateDer::from(certified.cert.der().to_vec());
                let cert_sha256: [u8; 32] = Sha256::digest(cert_der.as_ref()).into();
                let key_der = PrivateKeyDer::try_from(certified.key_pair.serialize_der())
                    .map_err(|e| format!("invalid generated TLS key: {e}"))?;

                let mut server_cfg = ServerConfig::builder_with_provider(Arc::new(
                    rustls_ring::default_provider(),
                ))
                .with_safe_default_protocol_versions()
                .map_err(|e| e.to_string())?
                .with_no_client_auth()
                .with_single_cert(vec![cert_der], key_der)
                .map_err(|e| format!("failed to configure rustls server: {e}"))?;
                server_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];

                Ok(Self {
                    acceptor: Some(tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg))),
                    cert_sha256: Some(cert_sha256),
                    cert_pem: Some(cert_pem),
                })
            }
            ServerTlsConfig::PemFiles { cert_pem, key_pem } => {
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

                Ok(Self {
                    acceptor: Some(tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg))),
                    cert_sha256: Some(cert_sha256),
                    cert_pem: Some(String::from_utf8_lossy(&cert_pem).into_owned()),
                })
            }
        }
    }
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
