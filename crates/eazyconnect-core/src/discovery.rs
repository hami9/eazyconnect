use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use eazyconnect_hw::{
    best_lan_ipv4, best_lan_ipv4_from, collect_lan_and_vpn_ipv4s_from,
    collect_lan_directed_broadcasts, detect_network_adapters, DeviceIdentity,
    NetworkAdapterSummary,
};
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
    #[serde(default)]
    pub alternate_urls: Vec<String>,
}

/// Best-effort local IPv4 address via routing probe (prefers non-VPN LAN NICs over Exit-VPN default routes).
pub fn detect_local_ipv4() -> String {
    if let Some(lan_ip) = best_lan_ipv4() {
        return lan_ip;
    }
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

fn match_peer_subnet_ip(
    peer_v4: Ipv4Addr,
    adapters: &[NetworkAdapterSummary],
    lan_ips: &[String],
    vpn_ips: &[String],
) -> Option<String> {
    if peer_v4.is_loopback() {
        return None;
    }
    let peer_u32 = u32::from(peer_v4);
    for is_vpn_pass in [false, true] {
        for adapter in adapters
            .iter()
            .filter(|a| a.is_up && a.is_vpn_like == is_vpn_pass)
        {
            for cidr in &adapter.ipv4_cidrs {
                if let Some((ip_str, prefix_str)) = cidr.split_once('/') {
                    if let (Ok(ip), Ok(prefix)) =
                        (ip_str.parse::<Ipv4Addr>(), prefix_str.parse::<u8>())
                    {
                        if prefix > 0 && prefix <= 30 {
                            let mask = (!0u32) << (32 - u32::from(prefix));
                            if (u32::from(ip) & mask) == (peer_u32 & mask) {
                                return Some(ip.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    let peer_octets = peer_v4.octets();
    for ip_str in lan_ips.iter().chain(vpn_ips.iter()) {
        if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
            if ip.octets()[0..3] == peer_octets[0..3] {
                return Some(ip_str.clone());
            }
        }
    }
    None
}

/// Picks the best primary `host` for `peer_ip` plus sorted `alternate_urls` for secondary LAN/VPN paths.
pub fn select_beacon_endpoints(
    peer_ip: IpAddr,
    advertised_host: Option<&str>,
    adapters: &[NetworkAdapterSummary],
    http_port: u16,
    https: bool,
) -> (String, Vec<String>) {
    let (lan_ips, vpn_ips) = collect_lan_and_vpn_ipv4s_from(adapters);
    let peer_match = match peer_ip {
        IpAddr::V4(pv4) => match_peer_subnet_ip(pv4, adapters, &lan_ips, &vpn_ips),
        IpAddr::V6(_) => None,
    };

    let primary = advertised_host
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .or(peer_match)
        .or_else(|| best_lan_ipv4_from(adapters))
        .or_else(|| vpn_ips.first().cloned())
        .unwrap_or_else(detect_local_ipv4);

    let scheme = if https { "https" } else { "http" };
    let mut alternates = Vec::new();
    for candidate in lan_ips.iter().chain(vpn_ips.iter()) {
        if candidate != &primary {
            let url = format!("{scheme}://{candidate}:{http_port}");
            if !alternates.contains(&url) {
                alternates.push(url);
            }
        }
    }
    (primary, alternates)
}

/// Spawns an async UDP discovery responder signing every beacon with the Master's Ed25519 key.
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
            let adapters = detect_network_adapters().unwrap_or_default();
            let (host, alternate_urls) = select_beacon_endpoints(
                peer.ip(),
                advertised_host.as_deref(),
                &adapters,
                http_port,
                https,
            );
            let master_pub = master_identity.ed25519_pub();
            let sign_msg = discovery_beacon_sign_bytes(
                PROTOCOL_VERSION,
                &host,
                http_port,
                https,
                tls_cert_sha256_hex.as_deref(),
                &master_pub,
                &alternate_urls,
            );
            let signature = master_identity.sign(&sign_msg);
            let beacon = DiscoveryBeacon {
                version: PROTOCOL_VERSION.to_string(),
                host,
                port: http_port,
                https,
                tls_cert_sha256_hex: tls_cert_sha256_hex.clone(),
                master_ed25519_pub: master_pub,
                alternate_urls,
                signature,
            };
            if let Ok(payload) = serde_json::to_vec(&beacon) {
                let _ = sock.send_to(&payload, peer).await;
            }
        }
    });

    Ok((local, handle))
}

/// Broadcasts/unicasts `DISCOVER_EAZYCONNECT` to `target_addr` (including per-NIC LAN directed broadcasts).
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
    let mut sockets = Vec::new();
    let mut sent_any = false;
    let mut last_send_err = None;

    let default_sock = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
        .map_err(|e| format!("failed to bind UDP discovery socket: {e}"))?;
    default_sock
        .set_broadcast(true)
        .map_err(|e| format!("failed to enable UDP broadcast: {e}"))?;
    match default_sock.send_to(DISCOVERY_MAGIC, target_addr) {
        Ok(_) => sent_any = true,
        Err(e) => last_send_err = Some(e.to_string()),
    }
    sockets.push(default_sock);

    // When performing broadcast discovery, also send subnet-directed broadcasts bound to each
    // non-VPN LAN interface so an active full-tunnel Exit VPN never swallows local LAN probes.
    if target_addr.ip() == IpAddr::V4(Ipv4Addr::BROADCAST) {
        for (local_ip, bcast_ip) in collect_lan_directed_broadcasts() {
            if let Ok(nic_sock) = UdpSocket::bind(SocketAddr::from((local_ip, 0))) {
                let _ = nic_sock.set_broadcast(true);
                let bcast_target = SocketAddr::from((bcast_ip, target_addr.port()));
                if nic_sock.send_to(DISCOVERY_MAGIC, bcast_target).is_ok() {
                    sent_any = true;
                    sockets.push(nic_sock);
                }
            }
        }
    }

    if !sent_any {
        return Err(format!(
            "failed to send UDP discovery probe: {}",
            last_send_err.unwrap_or_else(|| "no usable socket".to_string())
        ));
    }

    let single_socket = sockets.len() == 1;
    let read_wait = if single_socket {
        Duration::from_millis(160)
    } else {
        Duration::from_millis(50)
    };
    for sock in &sockets {
        let _ = sock.set_read_timeout(Some(read_wait));
    }

    let mut results = Vec::new();
    let mut seen = HashSet::new();
    let mut deadline = Instant::now() + timeout;
    let mut buf = [0u8; 8192];

    while Instant::now() < deadline {
        let mut any_timeout = false;
        for sock in &sockets {
            if Instant::now() >= deadline {
                break;
            }
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
                            &beacon.alternate_urls,
                        );
                        let signature_valid = DeviceIdentity::verify_signature(
                            &beacon.master_ed25519_pub,
                            &sign_msg,
                            &beacon.signature,
                        );
                        let scheme = if beacon.https { "https" } else { "http" };
                        let url = format!("{scheme}://{}:{}", beacon.host, beacon.port);
                        let key_hex = hex::encode(beacon.master_ed25519_pub);
                        if seen.insert((key_hex.clone(), url.clone())) {
                            results.push(DiscoveredMaster {
                                url,
                                host: beacon.host,
                                port: beacon.port,
                                https: beacon.https,
                                source_ip: src.ip().to_string(),
                                tls_cert_sha256_hex: beacon.tls_cert_sha256_hex,
                                master_ed25519_pub_hex: key_hex,
                                signature_valid,
                                alternate_urls: beacon.alternate_urls,
                            });
                            if !single_socket {
                                deadline = deadline.min(Instant::now() + Duration::from_millis(220));
                            }
                        }
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    any_timeout = true;
                }
                Err(_) => {}
            }
        }
        if single_socket && any_timeout && !results.is_empty() {
            break;
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_select_beacon_endpoints_prefers_matching_subnet_and_lists_vpn_alternate() {
        let adapters = vec![
            NetworkAdapterSummary {
                name: "Wi-Fi".to_string(),
                description: "Intel Wi-Fi".to_string(),
                is_up: true,
                is_vpn_like: false,
                ipv4_addrs: vec!["192.168.1.50".to_string()],
                ipv4_cidrs: vec!["192.168.1.50/24".to_string()],
            },
            NetworkAdapterSummary {
                name: "Tailscale".to_string(),
                description: "Tailscale Tunnel".to_string(),
                is_up: true,
                is_vpn_like: true,
                ipv4_addrs: vec!["100.64.0.10".to_string()],
                ipv4_cidrs: vec!["100.64.0.10/10".to_string()],
            },
        ];

        // Peer on Tailscale subnet receives Tailscale primary IP + LAN alternate URL.
        let (host, alts) = select_beacon_endpoints(
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 22)),
            None,
            &adapters,
            8443,
            true,
        );
        assert_eq!(host, "100.64.0.10");
        assert_eq!(alts, vec!["https://192.168.1.50:8443".to_string()]);

        // Peer on LAN receives LAN primary IP + Tailscale alternate URL.
        let (lan_host, lan_alts) = select_beacon_endpoints(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 99)),
            None,
            &adapters,
            8443,
            true,
        );
        assert_eq!(lan_host, "192.168.1.50");
        assert_eq!(lan_alts, vec!["https://100.64.0.10:8443".to_string()]);

        // Explicit --advertised-host overrides primary while exposing both LAN & VPN alternates.
        let (adv_host, adv_alts) = select_beacon_endpoints(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 99)),
            Some("relay.example.ts.net"),
            &adapters,
            8443,
            true,
        );
        assert_eq!(adv_host, "relay.example.ts.net");
        assert_eq!(
            adv_alts,
            vec![
                "https://192.168.1.50:8443".to_string(),
                "https://100.64.0.10:8443".to_string(),
            ]
        );
    }
}
