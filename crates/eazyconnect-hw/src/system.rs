use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::keystore::{detect_os_machine_id, detect_tpm_cng};
use crate::peripherals::{
    enumerate_hid_devices, enumerate_serial_ports, enumerate_usb_devices, HidDeviceSummary,
    SerialPortSummary, UsbDeviceSummary,
};

/// Summary of an OS network interface and whether it appears to be a VPN/tunnel adapter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAdapterSummary {
    pub name: String,
    pub description: String,
    pub is_up: bool,
    pub is_vpn_like: bool,
    pub ipv4_addrs: Vec<String>,
    #[serde(default)]
    pub ipv4_cidrs: Vec<String>,
}

const VPN_KEYWORDS: &[&str] = &[
    "VPN",
    "TAP",
    "TUN",
    "WINTUN",
    "WIREGUARD",
    "OPENVPN",
    "WINDSCRIBE",
    "CISCO",
    "ANYCONNECT",
    "TAILSCALE",
    "ZEROTIER",
    "CLOUDFLARE",
    "WARP",
    "MULLVAD",
    "PROTON",
    "FORTI",
    "OUTLINE",
    "NEKORAY",
    "SING-BOX",
    "GLOBALPROTECT",
    "PULSE SECURE",
    "SOFTETHER",
    "HAMACHI",
    "NORDLYNX",
];

/// Returns true if an adapter's friendly name or description matches known VPN/tunnel drivers.
pub fn classify_vpn_adapter(name: &str, description: &str) -> bool {
    let combined_upper = format!("{name} {description}").to_ascii_uppercase();
    VPN_KEYWORDS.iter().any(|kw| combined_upper.contains(kw))
}

fn is_usable_endpoint_v4(ip: Ipv4Addr) -> bool {
    !ip.is_loopback() && !ip.is_unspecified() && !ip.is_link_local() && !ip.is_multicast()
}

/// Parses `"a.b.c.d/prefix"` into `(interface_ipv4, directed_broadcast_ipv4)` for LAN subnets.
pub fn ipv4_directed_broadcast(cidr: &str) -> Option<(Ipv4Addr, Ipv4Addr)> {
    let (ip_str, prefix_str) = cidr.split_once('/')?;
    let ip: Ipv4Addr = ip_str.parse().ok()?;
    let prefix: u8 = prefix_str.parse().ok()?;
    if !is_usable_endpoint_v4(ip) || prefix == 0 || prefix >= 31 {
        return None;
    }
    let mask = (!0u32) << (32 - u32::from(prefix));
    let bcast = Ipv4Addr::from(u32::from(ip) | !mask);
    Some((ip, bcast))
}

/// Separates usable IPv4 addresses across up adapters into `(lan_ips, vpn_ips)`.
pub fn collect_lan_and_vpn_ipv4s_from(
    adapters: &[NetworkAdapterSummary],
) -> (Vec<String>, Vec<String>) {
    let mut lan = Vec::new();
    let mut vpn = Vec::new();
    for adapter in adapters.iter().filter(|a| a.is_up) {
        let target = if adapter.is_vpn_like {
            &mut vpn
        } else {
            &mut lan
        };
        for s in &adapter.ipv4_addrs {
            if let Ok(ip) = s.parse::<Ipv4Addr>() {
                if is_usable_endpoint_v4(ip) && !target.contains(s) {
                    target.push(s.clone());
                }
            }
        }
    }
    (lan, vpn)
}

/// Returns `(lan_ips, vpn_ips)` across all currently active OS network adapters.
pub fn collect_lan_and_vpn_ipv4s() -> (Vec<String>, Vec<String>) {
    let adapters = detect_network_adapters().unwrap_or_default();
    collect_lan_and_vpn_ipv4s_from(&adapters)
}

/// Collects all usable IPv4 endpoint addresses (LAN adapters first, then active VPN adapters).
pub fn collect_local_endpoint_ips() -> Vec<String> {
    let (mut lan, vpn) = collect_lan_and_vpn_ipv4s();
    for ip in vpn {
        if !lan.contains(&ip) {
            lan.push(ip);
        }
    }
    lan
}

/// Computes `(local_ip, subnet_broadcast_ip)` pairs for active non-VPN LAN interfaces.
pub fn collect_lan_directed_broadcasts_from(
    adapters: &[NetworkAdapterSummary],
) -> Vec<(Ipv4Addr, Ipv4Addr)> {
    let mut out = Vec::new();
    for adapter in adapters.iter().filter(|a| a.is_up && !a.is_vpn_like) {
        for cidr in &adapter.ipv4_cidrs {
            if let Some(pair) = ipv4_directed_broadcast(cidr) {
                if !out.contains(&pair) {
                    out.push(pair);
                }
            }
        }
    }
    out
}

/// Computes `(local_ip, subnet_broadcast_ip)` pairs for all up OS LAN interfaces.
pub fn collect_lan_directed_broadcasts() -> Vec<(Ipv4Addr, Ipv4Addr)> {
    let adapters = detect_network_adapters().unwrap_or_default();
    collect_lan_directed_broadcasts_from(&adapters)
}

/// Picks the preferred non-VPN LAN IPv4 address from a list of adapters (RFC1918 preferred).
pub fn best_lan_ipv4_from(adapters: &[NetworkAdapterSummary]) -> Option<String> {
    let (lan, _) = collect_lan_and_vpn_ipv4s_from(adapters);
    lan.iter()
        .find(|s| s.parse::<Ipv4Addr>().is_ok_and(|ip| ip.is_private()))
        .cloned()
        .or_else(|| lan.into_iter().next())
}

/// Picks the preferred non-VPN LAN IPv4 address on the current host, if any.
pub fn best_lan_ipv4() -> Option<String> {
    let adapters = detect_network_adapters().unwrap_or_default();
    best_lan_ipv4_from(&adapters)
}

/// Complete native hardware + OS security inventory for diagnostics and attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemHardwareReport {
    pub hostname: String,
    pub os: String,
    pub arch: String,
    pub tpm2_cng_available: bool,
    pub dpapi_available: bool,
    pub machine_id_present: bool,
    pub is_elevated_admin: bool,
    pub network_adapters: Vec<NetworkAdapterSummary>,
    pub vpn_adapters_detected: Vec<String>,
    pub serial_ports: Vec<SerialPortSummary>,
    pub usb_devices: Vec<UsbDeviceSummary>,
    pub hid_devices: Vec<HidDeviceSummary>,
}

pub fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown-host".to_string())
}

#[cfg(windows)]
pub fn is_process_elevated() -> bool {
    use windows_sys::Win32::UI::Shell::IsUserAnAdmin;
    // SAFETY: Parameterless Win32 API query.
    unsafe { IsUserAnAdmin() != 0 }
}

#[cfg(not(windows))]
pub fn is_process_elevated() -> bool {
    false
}

/// Enumerates local network interfaces on Windows via `GetAdaptersAddresses`, flagging VPN adapters.
#[cfg(windows)]
pub fn detect_network_adapters() -> Result<Vec<NetworkAdapterSummary>, String> {
    use std::net::Ipv4Addr;
    use std::ptr;
    use windows_sys::Win32::Foundation::ERROR_BUFFER_OVERFLOW;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_INCLUDE_PREFIX, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_UNSPEC, SOCKADDR_IN};

    let mut buf_len = 16 * 1024u32;
    let mut buf = vec![0u8; buf_len as usize];

    for _ in 0..3 {
        // SAFETY: Valid buffer pointer matching buf_len.
        let ret = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                GAA_FLAG_INCLUDE_PREFIX,
                ptr::null_mut(),
                buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                &mut buf_len,
            )
        };
        if ret == ERROR_BUFFER_OVERFLOW {
            buf.resize(buf_len as usize, 0);
            continue;
        }
        if ret != 0 {
            return Err(format!("GetAdaptersAddresses failed with code {ret}"));
        }

        let mut adapters = Vec::new();
        let mut curr = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        while !curr.is_null() {
            // SAFETY: curr points within `buf` populated by GetAdaptersAddresses.
            let node = unsafe { &*curr };
            let name = unsafe { wide_ptr_to_string(node.FriendlyName) };
            let desc = unsafe { wide_ptr_to_string(node.Description) };
            let is_up = node.OperStatus == IfOperStatusUp;

            let is_vpn_like = classify_vpn_adapter(&name, &desc);

            let mut ipv4_addrs = Vec::new();
            let mut ipv4_cidrs = Vec::new();
            let mut uni = node.FirstUnicastAddress;
            while !uni.is_null() {
                // SAFETY: Unicast address linked list node inside `buf`.
                let ua = unsafe { &*uni };
                let sa = ua.Address.lpSockaddr;
                if !sa.is_null() {
                    // SAFETY: Socket address header tells family.
                    let family = unsafe { (*sa).sa_family };
                    if family == AF_INET {
                        // SAFETY: AF_INET guarantees SOCKADDR_IN layout.
                        let sin = unsafe { &*(sa as *const SOCKADDR_IN) };
                        // SAFETY: S_addr holds IPv4 bytes in network byte order.
                        let addr_u32 = u32::from_be(unsafe { sin.sin_addr.S_un.S_addr });
                        let ip = Ipv4Addr::from(addr_u32);
                        ipv4_addrs.push(ip.to_string());
                        if ua.OnLinkPrefixLength <= 32 {
                            ipv4_cidrs.push(format!("{ip}/{}", ua.OnLinkPrefixLength));
                        }
                    }
                }
                uni = ua.Next;
            }

            adapters.push(NetworkAdapterSummary {
                name,
                description: desc,
                is_up,
                is_vpn_like,
                ipv4_addrs,
                ipv4_cidrs,
            });
            curr = node.Next;
        }
        return Ok(adapters);
    }
    Err("GetAdaptersAddresses buffer exhausted".to_string())
}

#[cfg(windows)]
unsafe fn wide_ptr_to_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while len < 512 && *ptr.add(len) != 0 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
}

#[cfg(not(windows))]
pub fn detect_network_adapters() -> Result<Vec<NetworkAdapterSummary>, String> {
    Ok(Vec::new())
}

/// Collects a full native OS, crypto-hardware, network/VPN, and USB/Serial/HID hardware report.
pub fn collect_hardware_report() -> SystemHardwareReport {
    let network_adapters = detect_network_adapters().unwrap_or_default();
    let vpn_adapters_detected = network_adapters
        .iter()
        .filter(|a| a.is_vpn_like && a.is_up)
        .map(|a| a.name.clone())
        .collect();

    SystemHardwareReport {
        hostname: hostname(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        tpm2_cng_available: detect_tpm_cng(),
        dpapi_available: cfg!(windows),
        machine_id_present: detect_os_machine_id().is_some(),
        is_elevated_admin: is_process_elevated(),
        network_adapters,
        vpn_adapters_detected,
        serial_ports: enumerate_serial_ports().unwrap_or_default(),
        usb_devices: enumerate_usb_devices().unwrap_or_default(),
        hid_devices: enumerate_hid_devices().unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collect_hardware_report() {
        let rep = collect_hardware_report();
        assert!(!rep.hostname.is_empty());
        assert_eq!(rep.os, std::env::consts::OS);
        #[cfg(windows)]
        {
            assert!(rep.dpapi_available);
            assert!(rep.machine_id_present);
            assert!(!rep.network_adapters.is_empty());
        }
    }

    #[test]
    fn test_classify_vpn_adapter_covers_modern_tunnels() {
        assert!(classify_vpn_adapter("Tailscale", "Tailscale Tunnel"));
        assert!(classify_vpn_adapter("ZeroTier One", "ZeroTier Virtual Port"));
        assert!(classify_vpn_adapter("CloudflareWARP", "Wintun Userspace Tunnel"));
        assert!(classify_vpn_adapter("wg0", "WireGuard Tunnel"));
        assert!(classify_vpn_adapter("ProtonVPN", "TAP-Windows Adapter V9"));
        assert!(classify_vpn_adapter("nekoray-tun", "sing-box tun"));
        assert!(!classify_vpn_adapter("Wi-Fi", "Intel(R) Wi-Fi 6E AX211"));
        assert!(!classify_vpn_adapter("Ethernet", "Realtek PCIe GbE Family Controller"));
    }

    #[test]
    fn test_directed_broadcast_and_lan_selection() {
        assert_eq!(
            ipv4_directed_broadcast("192.168.1.42/24"),
            Some((Ipv4Addr::new(192, 168, 1, 42), Ipv4Addr::new(192, 168, 1, 255)))
        );
        assert_eq!(
            ipv4_directed_broadcast("10.20.30.4/16"),
            Some((Ipv4Addr::new(10, 20, 30, 4), Ipv4Addr::new(10, 20, 255, 255)))
        );
        assert_eq!(ipv4_directed_broadcast("127.0.0.1/8"), None);
        assert_eq!(ipv4_directed_broadcast("169.254.1.5/16"), None);
        assert_eq!(ipv4_directed_broadcast("10.0.0.1/32"), None);

        let adapters = vec![
            NetworkAdapterSummary {
                name: "WireGuard".to_string(),
                description: "WireGuard Tunnel".to_string(),
                is_up: true,
                is_vpn_like: true,
                ipv4_addrs: vec!["10.8.0.2".to_string()],
                ipv4_cidrs: vec!["10.8.0.2/24".to_string()],
            },
            NetworkAdapterSummary {
                name: "Wi-Fi".to_string(),
                description: "Intel Wi-Fi".to_string(),
                is_up: true,
                is_vpn_like: false,
                ipv4_addrs: vec!["192.168.50.15".to_string()],
                ipv4_cidrs: vec!["192.168.50.15/24".to_string()],
            },
            NetworkAdapterSummary {
                name: "Ethernet".to_string(),
                description: "Down NIC".to_string(),
                is_up: false,
                is_vpn_like: false,
                ipv4_addrs: vec!["192.168.99.2".to_string()],
                ipv4_cidrs: vec!["192.168.99.2/24".to_string()],
            },
        ];
        assert_eq!(best_lan_ipv4_from(&adapters), Some("192.168.50.15".to_string()));
        assert_eq!(
            collect_lan_and_vpn_ipv4s_from(&adapters),
            (vec!["192.168.50.15".to_string()], vec!["10.8.0.2".to_string()])
        );
        assert_eq!(
            collect_lan_directed_broadcasts_from(&adapters),
            vec![(Ipv4Addr::new(192, 168, 50, 15), Ipv4Addr::new(192, 168, 50, 255))]
        );
    }
}
