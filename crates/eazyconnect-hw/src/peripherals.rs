use std::collections::VecDeque;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serialport::SerialPortType;

/// Summary of an attached OS serial / COM port.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerialPortSummary {
    pub port_name: String,
    pub transport_kind: String,
    pub vid: Option<u16>,
    pub pid: Option<u16>,
    pub manufacturer: Option<String>,
    pub product: Option<String>,
    pub serial_number: Option<String>,
}

/// Summary of an attached USB device discovered via native OS descriptors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbDeviceSummary {
    pub bus_number: u8,
    pub device_address: u8,
    pub vendor_id: u16,
    pub product_id: u16,
    pub class_code: u8,
    pub subclass_code: u8,
    pub protocol_code: u8,
    pub manufacturer: Option<String>,
    pub product: Option<String>,
    pub serial_number: Option<String>,
}

/// Summary of a Human Interface Device (HID) discovered via Win32 SetupAPI/HID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HidDeviceSummary {
    pub device_path: String,
    pub vendor_id: u16,
    pub product_id: u16,
    pub version_number: u16,
    pub manufacturer: Option<String>,
    pub product: Option<String>,
    pub serial_number: Option<String>,
}

/// Trait abstracting real physical Serial/COM hardware and virtual test harnesses.
pub trait SerialTransport: Send {
    fn port_name(&self) -> &str;
    fn write_bytes(&mut self, data: &[u8]) -> Result<usize, String>;
    fn read_available(&mut self, max_len: usize) -> Result<Vec<u8>, String>;
}

/// Live OS serial port wrapper powered by `serialport`.
pub struct OsSerialTransport {
    name: String,
    port: Box<dyn serialport::SerialPort>,
}

impl OsSerialTransport {
    pub fn open(port_name: &str, baud_rate: u32, timeout_ms: u64) -> Result<Self, String> {
        let port = serialport::new(port_name, baud_rate)
            .timeout(Duration::from_millis(timeout_ms))
            .open()
            .map_err(|e| format!("failed to open serial port '{port_name}' @ {baud_rate}bps: {e}"))?;
        Ok(Self {
            name: port_name.to_string(),
            port,
        })
    }
}

impl SerialTransport for OsSerialTransport {
    fn port_name(&self) -> &str {
        &self.name
    }

    fn write_bytes(&mut self, data: &[u8]) -> Result<usize, String> {
        let written = self
            .port
            .write(data)
            .map_err(|e| format!("serial write error on {}: {e}", self.name))?;
        self.port
            .flush()
            .map_err(|e| format!("serial flush error on {}: {e}", self.name))?;
        Ok(written)
    }

    fn read_available(&mut self, max_len: usize) -> Result<Vec<u8>, String> {
        let cap = max_len.clamp(1, 65536);
        let mut buf = vec![0u8; cap];
        match self.port.read(&mut buf) {
            Ok(n) => {
                buf.truncate(n);
                Ok(buf)
            }
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => Ok(Vec::new()),
            Err(e) => Err(format!("serial read error on {}: {e}", self.name)),
        }
    }
}

/// Thread-safe in-memory full-duplex mock serial device pair for testing hardware bridging.
#[derive(Clone)]
pub struct MemorySerialTransport {
    name: String,
    tx_to_peer: Arc<Mutex<VecDeque<u8>>>,
    rx_from_peer: Arc<Mutex<VecDeque<u8>>>,
}

impl MemorySerialTransport {
    pub fn pair(port_a: &str, port_b: &str) -> (Self, Self) {
        let a_to_b = Arc::new(Mutex::new(VecDeque::new()));
        let b_to_a = Arc::new(Mutex::new(VecDeque::new()));
        (
            Self {
                name: port_a.to_string(),
                tx_to_peer: Arc::clone(&a_to_b),
                rx_from_peer: Arc::clone(&b_to_a),
            },
            Self {
                name: port_b.to_string(),
                tx_to_peer: b_to_a,
                rx_from_peer: a_to_b,
            },
        )
    }
}

impl SerialTransport for MemorySerialTransport {
    fn port_name(&self) -> &str {
        &self.name
    }

    fn write_bytes(&mut self, data: &[u8]) -> Result<usize, String> {
        let mut guard = self.tx_to_peer.lock().map_err(|_| "lock poisoned".to_string())?;
        guard.extend(data.iter().copied());
        Ok(data.len())
    }

    fn read_available(&mut self, max_len: usize) -> Result<Vec<u8>, String> {
        let mut guard = self
            .rx_from_peer
            .lock()
            .map_err(|_| "lock poisoned".to_string())?;
        let count = guard.len().min(max_len.max(1));
        Ok(guard.drain(..count).collect())
    }
}

/// Sends a command frame over a serial port and reads any immediate reply within `timeout_ms`.
pub fn send_serial_command(
    port_name: &str,
    baud_rate: u32,
    payload: &[u8],
    timeout_ms: u64,
) -> Result<Vec<u8>, String> {
    let mut port = OsSerialTransport::open(port_name, baud_rate, timeout_ms)?;
    port.write_bytes(payload)?;
    port.read_available(4096)
}

/// Enumerates all available serial / COM ports with USB metadata when present.
pub fn enumerate_serial_ports() -> Result<Vec<SerialPortSummary>, String> {
    let ports = serialport::available_ports().map_err(|e| format!("serial enum failed: {e}"))?;
    let mut out = Vec::with_capacity(ports.len());
    for p in ports {
        let summary = match p.port_type {
            SerialPortType::UsbPort(info) => SerialPortSummary {
                port_name: p.port_name,
                transport_kind: "usb-serial".to_string(),
                vid: Some(info.vid),
                pid: Some(info.pid),
                manufacturer: info.manufacturer,
                product: info.product,
                serial_number: info.serial_number,
            },
            SerialPortType::PciPort => SerialPortSummary {
                port_name: p.port_name,
                transport_kind: "pci-serial".to_string(),
                vid: None,
                pid: None,
                manufacturer: None,
                product: None,
                serial_number: None,
            },
            SerialPortType::BluetoothPort => SerialPortSummary {
                port_name: p.port_name,
                transport_kind: "bluetooth-serial".to_string(),
                vid: None,
                pid: None,
                manufacturer: None,
                product: None,
                serial_number: None,
            },
            SerialPortType::Unknown => SerialPortSummary {
                port_name: p.port_name,
                transport_kind: "unknown".to_string(),
                vid: None,
                pid: None,
                manufacturer: None,
                product: None,
                serial_number: None,
            },
        };
        out.push(summary);
    }
    out.sort_by(|a, b| a.port_name.cmp(&b.port_name));
    Ok(out)
}

/// Enumerates all attached USB devices natively via `nusb` (pure Rust, zero external C DLLs).
pub fn enumerate_usb_devices() -> Result<Vec<UsbDeviceSummary>, String> {
    let iter = nusb::list_devices().map_err(|e| format!("USB enumeration failed: {e}"))?;
    let mut out: Vec<UsbDeviceSummary> = iter
        .map(|d| UsbDeviceSummary {
            bus_number: d.bus_number(),
            device_address: d.device_address(),
            vendor_id: d.vendor_id(),
            product_id: d.product_id(),
            class_code: d.class(),
            subclass_code: d.subclass(),
            protocol_code: d.protocol(),
            manufacturer: d.manufacturer_string().map(str::to_string),
            product: d.product_string().map(str::to_string),
            serial_number: d.serial_number().map(str::to_string),
        })
        .collect();
    out.sort_by_key(|d| (d.bus_number, d.device_address, d.vendor_id, d.product_id));
    Ok(out)
}

/// Enumerates physical HID devices on Windows using native SetupAPI + `hid.dll`.
#[cfg(windows)]
pub fn enumerate_hid_devices() -> Result<Vec<HidDeviceSummary>, String> {
    use std::ptr;
    use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
        SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInterfaces, SetupDiGetClassDevsW,
        SetupDiGetDeviceInterfaceDetailW, DIGCF_DEVICEINTERFACE, DIGCF_PRESENT, HDEVINFO,
        SP_DEVICE_INTERFACE_DATA, SP_DEVICE_INTERFACE_DETAIL_DATA_W,
    };
    use windows_sys::Win32::Devices::HumanInterfaceDevice::{
        HidD_GetAttributes, HidD_GetHidGuid, HidD_GetManufacturerString, HidD_GetProductString,
        HidD_GetSerialNumberString, HIDD_ATTRIBUTES,
    };
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };

    let mut hid_guid = unsafe { std::mem::zeroed() };
    // SAFETY: Valid mutable pointer to GUID.
    unsafe {
        HidD_GetHidGuid(&mut hid_guid);
    }

    // SAFETY: Enumerating present HID interface class devices.
    let dev_info: HDEVINFO = unsafe {
        SetupDiGetClassDevsW(
            &hid_guid,
            ptr::null(),
            ptr::null_mut(),
            DIGCF_PRESENT | DIGCF_DEVICEINTERFACE,
        )
    };
    if dev_info == (INVALID_HANDLE_VALUE as isize) || dev_info == 0 {
        return Err("SetupDiGetClassDevsW failed for HID class".to_string());
    }

    let mut results = Vec::new();
    let mut index: u32 = 0;

    loop {
        let mut iface_data: SP_DEVICE_INTERFACE_DATA = unsafe { std::mem::zeroed() };
        iface_data.cbSize = std::mem::size_of::<SP_DEVICE_INTERFACE_DATA>() as u32;

        // SAFETY: dev_info is valid, iface_data has valid cbSize.
        let ok = unsafe {
            SetupDiEnumDeviceInterfaces(
                dev_info,
                ptr::null(),
                &hid_guid,
                index,
                &mut iface_data,
            )
        };
        index += 1;
        if ok == 0 {
            break;
        }

        let mut required_size = 0u32;
        // SAFETY: Querying required detail buffer size cleanly.
        unsafe {
            SetupDiGetDeviceInterfaceDetailW(
                dev_info,
                &iface_data,
                ptr::null_mut(),
                0,
                &mut required_size,
                ptr::null_mut(),
            );
        }
        if required_size == 0 || required_size > 4096 {
            continue;
        }

        let mut detail_buf = vec![0u8; required_size as usize];
        // SAFETY: detail_buf has size >= required_size >= size_of::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>().
        let detail_ptr = detail_buf.as_mut_ptr() as *mut SP_DEVICE_INTERFACE_DETAIL_DATA_W;
        unsafe {
            (*detail_ptr).cbSize =
                std::mem::size_of::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>() as u32;
        }

        // SAFETY: Populating device interface detail path string into detail_buf.
        let got_detail = unsafe {
            SetupDiGetDeviceInterfaceDetailW(
                dev_info,
                &iface_data,
                detail_ptr,
                required_size,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if got_detail == 0 {
            continue;
        }

        // SAFETY: DevicePath begins at offset of DevicePath field inside detail_buf.
        let path_slice_u16 = unsafe {
            let start = (&(*detail_ptr).DevicePath) as *const u16;
            let byte_offset = (start as usize) - (detail_buf.as_ptr() as usize);
            let max_u16 = (detail_buf.len().saturating_sub(byte_offset)) / 2;
            let raw_u16 = std::slice::from_raw_parts(start, max_u16);
            let nul_pos = raw_u16.iter().position(|&c| c == 0).unwrap_or(raw_u16.len());
            &raw_u16[..nul_pos]
        };
        let device_path = String::from_utf16_lossy(path_slice_u16);
        let mut path_z: Vec<u16> = path_slice_u16.to_vec();
        path_z.push(0);

        // Open with dwDesiredAccess = 0 (metadata query only) so even exclusive OS keyboards/mice don't fail.
        // SAFETY: Valid null-terminated Win32 device interface path.
        let handle = unsafe {
            CreateFileW(
                path_z.as_ptr(),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null(),
                OPEN_EXISTING,
                0,
                ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            continue;
        }

        let mut attrs: HIDD_ATTRIBUTES = unsafe { std::mem::zeroed() };
        attrs.Size = std::mem::size_of::<HIDD_ATTRIBUTES>() as u32;
        // SAFETY: Valid HID device handle with sized HIDD_ATTRIBUTES struct.
        let has_attrs = unsafe { HidD_GetAttributes(handle, &mut attrs) };

        let read_hid_str = |func: unsafe extern "system" fn(
            windows_sys::Win32::Foundation::HANDLE,
            *mut std::ffi::c_void,
            u32,
        ) -> bool|
         -> Option<String> {
            let mut wbuf = [0u16; 128];
            // SAFETY: Valid HID handle and 256-byte zeroed UTF-16 buffer.
            let ok = unsafe { func(handle, wbuf.as_mut_ptr() as *mut _, 256) };
            if !ok {
                return None;
            }
            let len = wbuf.iter().position(|&c| c == 0).unwrap_or(wbuf.len());
            let s = String::from_utf16_lossy(&wbuf[..len]).trim().to_string();
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        };

        if has_attrs {
            results.push(HidDeviceSummary {
                device_path,
                vendor_id: attrs.VendorID,
                product_id: attrs.ProductID,
                version_number: attrs.VersionNumber,
                manufacturer: read_hid_str(HidD_GetManufacturerString),
                product: read_hid_str(HidD_GetProductString),
                serial_number: read_hid_str(HidD_GetSerialNumberString),
            });
        }

        // SAFETY: Valid handle opened by CreateFileW.
        unsafe {
            CloseHandle(handle);
        }
    }

    // SAFETY: Valid dev_info returned by SetupDiGetClassDevsW.
    unsafe {
        SetupDiDestroyDeviceInfoList(dev_info);
    }

    results.sort_by_key(|d| (d.vendor_id, d.product_id));
    Ok(results)
}

#[cfg(not(windows))]
pub fn enumerate_hid_devices() -> Result<Vec<HidDeviceSummary>, String> {
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_serial_transport_duplex() {
        let (mut a, mut b) = MemorySerialTransport::pair("VCOM1", "VCOM2");
        assert_eq!(a.port_name(), "VCOM1");
        a.write_bytes(b"AT+SENSOR?\r\n").unwrap();
        let req = b.read_available(64).unwrap();
        assert_eq!(req, b"AT+SENSOR?\r\n");

        b.write_bytes(b"TEMP=24.6C\r\n").unwrap();
        let resp = a.read_available(64).unwrap();
        assert_eq!(resp, b"TEMP=24.6C\r\n");
    }

    #[test]
    fn test_host_hardware_enumeration_runs_cleanly() {
        let _serial = enumerate_serial_ports().expect("serial enum should not fail");
        let usb = enumerate_usb_devices().expect("usb enum should not fail");
        let hid = enumerate_hid_devices().expect("hid enum should not fail");
        assert!(usb.len() + hid.len() > 0 || cfg!(not(windows)));
    }
}
