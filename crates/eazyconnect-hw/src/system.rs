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

            let combined_upper = format!("{name} {desc}").to_ascii_uppercase();
            let is_vpn_like = ["VPN", "TAP", "TUN", "WIREGUARD", "OPENVPN", "WINDSCRIBE", "CISCO"]
                .iter()
                .any(|kw| combined_upper.contains(kw));

            let mut ipv4_addrs = Vec::new();
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
                        ipv4_addrs.push(Ipv4Addr::from(addr_u32).to_string());
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
}
