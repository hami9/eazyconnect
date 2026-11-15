use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use eazyconnect_hw::DeviceIdentity;
use serde::{Deserialize, Serialize};

use crate::protocol::{discovery_beacon_sign_bytes, DiscoveryBeacon};

pub const DEFAULT_DISCOVERY_PORT: u16 = 37020;
pub const DISCOVERY_MAGIC: &[u8] = b"DISCOVER_EAZYCONNECT";
const PROTOCOL_VERSION: &str = "eazyconnect/0.2";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredMaster {
    pub url: String,
    pub host: String,
    pub port: u16,
    pub https: bool,
    pub source_ip: String,
    pub tls_cert_sha256_hex: Option<String>,
    pub master_ed25519_pub_hex: String,
    pub signature_valid: bool,
}

/// Best-effort local IPv4 address via routing probe (no packets emitted to the Internet).
pub fn detect_local_ipv4() -> String {
    if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
        if sock.connect("10.255.255.254:80").is_ok() {
            if let Ok(addr) = sock.local_addr() {
                if let IpAddr::V4(v4) = addr.ip() {
                    if !v4.is_unspecified() {
                        return v4.to_string();
                    }
                }
            }
        }
    }
    "127.0.0.1".to_string()
}

/// Spawns an async UDP LAN discovery responder signing every beacon with the Master's Ed25519 key.
pub async fn spawn_discovery_responder(
    bind_addr: SocketAddr,
    advertised_host: Option<String>,
    http_port: u16,
    https: bool,
    tls_cert_sha256_hex: Option<String>,
    master_identity: DeviceIdentity,
) -> std::io::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let sock = tokio::net::UdpSocket::bind(bind_addr).await?;
    let local = sock.local_addr()?;

    let handle = tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        loop {
            let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                continue;
            };
            if n < DISCOVERY_MAGIC.len() || !buf[..n].starts_with(DISCOVERY_MAGIC) {
                continue;
            }
            let host = advertised_host
                .clone()
                .unwrap_or_else(detect_local_ipv4);
            let master_pub = master_identity.ed25519_pub();
            let sign_msg = discovery_beacon_sign_bytes(
                PROTOCOL_VERSION,
                &host,
                http_port,
                https,
                tls_cert_sha256_hex.as_deref(),
                &master_pub,
            );
            let signature = master_identity.sign(&sign_msg);
            let beacon = DiscoveryBeacon {
                version: PROTOCOL_VERSION.to_string(),
                host,
                port: http_port,
                https,
                tls_cert_sha256_hex: tls_cert_sha256_hex.clone(),
                master_ed25519_pub: master_pub,
                signature,
            };
            if let Ok(payload) = serde_json::to_vec(&beacon) {
                let _ = sock.send_to(&payload, peer).await;
            }
        }
    });

    Ok((local, handle))
}

/// Broadcasts `DISCOVER_EAZYCONNECT` to `target_addr` (usually `255.255.255.255:37020`) and verifies signatures.
pub async fn discover_masters(
    target_addr: SocketAddr,
    timeout: Duration,
) -> Result<Vec<DiscoveredMaster>, String> {
    tokio::task::spawn_blocking(move || discover_masters_blocking(target_addr, timeout))
        .await
        .map_err(|e| format!("discovery task error: {e}"))?
}

fn discover_masters_blocking(
    target_addr: SocketAddr,
    timeout: Duration,
) -> Result<Vec<DiscoveredMaster>, String> {
    let sock = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
        .map_err(|e| format!("failed to bind UDP discovery socket: {e}"))?;
    sock.set_broadcast(true)
        .map_err(|e| format!("failed to enable UDP broadcast: {e}"))?;
    sock.set_read_timeout(Some(Duration::from_millis(200)))
        .map_err(|e| format!("failed to configure UDP timeout: {e}"))?;

    sock.send_to(DISCOVERY_MAGIC, target_addr)
        .map_err(|e| format!("failed to broadcast LAN discovery probe: {e}"))?;

    let mut results = Vec::new();
    let deadline = Instant::now() + timeout;
    let mut buf = [0u8; 4096];

    while Instant::now() < deadline {
        match sock.recv_from(&mut buf) {
            Ok((n, src)) => {
                if let Ok(beacon) = serde_json::from_slice::<DiscoveryBeacon>(&buf[..n]) {
                    let sign_msg = discovery_beacon_sign_bytes(
                        &beacon.version,
                        &beacon.host,
                        beacon.port,
                        beacon.https,
                        beacon.tls_cert_sha256_hex.as_deref(),
                        &beacon.master_ed25519_pub,
                    );
                    let signature_valid = DeviceIdentity::verify_signature(
                        &beacon.master_ed25519_pub,
                        &sign_msg,
                        &beacon.signature,
                    );
                    let scheme = if beacon.https { "https" } else { "http" };
                    let url = format!("{scheme}://{}:{}", beacon.host, beacon.port);
                    results.push(DiscoveredMaster {
                        url,
                        host: beacon.host,
                        port: beacon.port,
                        https: beacon.https,
                        source_ip: src.ip().to_string(),
                        tls_cert_sha256_hex: beacon.tls_cert_sha256_hex,
                        master_ed25519_pub_hex: hex::encode(beacon.master_ed25519_pub),
                        signature_valid,
                    });
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                if !results.is_empty() {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    Ok(results)
}
