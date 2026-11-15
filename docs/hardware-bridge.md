# OS Custody & Hardware Peripheral Bridge

The `eazyconnect-hw` crate provides direct Rust integration with Windows security hardware, OS network configuration, and local peripherals without external helper scripts or Python dependencies.

## 1. Windows Security & Key Custody (`keystore.rs`)

- **DPAPI Sealing**: Private key material (`Ed25519` signing seeds), local secrets (`seal_local_secret` / `unseal_local_secret`), and stored client bearer tokens are encrypted at rest using Win32 `CryptProtectData` / `CryptUnprotectData` (`CRYPTPROTECT_UI_FORBIDDEN`) bound to caller entropy (`eazyconnect-dpapi-v2` + `client_id` + optional passphrase).
  - *Non-Windows fallback*: Uses `XChaCha20-Poly1305` keyed via HKDF from `/etc/machine-id` (or fallback host marker) + application context so Linux/macOS targets also compile and test cleanly.
- **TPM 2.0 CNG Probe**: Calls Win32 `NCryptOpenStorageProvider` (`MS_PLATFORM_CRYPTO_PROVIDER`) to report whether a hardware TPM 2.0 Platform Crypto Provider is present on the host (`tpm2_cng_available`).
- **MachineGuid Hardware Lock**: Reads `SOFTWARE\Microsoft\Cryptography\MachineGuid` (falling back to `/etc/machine-id` on Linux) and binds `OsBoundHardwareProvider` into `cubehash-core` sessions and `EZV1` file vaults.

## 2. Host Diagnostics & Network / VPN Inspection (`system.rs`)

- **Network Adapters**: Calls `GetAdaptersAddresses` (`GAA_FLAG_INCLUDE_PREFIX`) to enumerate interfaces, operational status (`IfOperStatusUp`), IPv4 addresses, and flags VPN/tunnel adapters (`is_vpn_like`, matching OpenVPN/TAP/TUN/WireGuard/ZeroTier/Tailscale/Cisco/Forti/AnyConnect patterns).
- **Privilege Check**: Calls `IsUserAnAdmin` (`is_elevated_admin`) for diagnostics.
- **Unified Report**: `collect_hardware_report()` aggregates OS/arch, TPM/DPAPI/MachineGuid readiness, adapters, serial ports, USB devices, and HID devices into `SystemHardwareReport`.

## 3. Direct Peripherals (`peripherals.rs`)

- **Serial / COM Ports**: `enumerate_serial_ports()` and `OsSerialTransport::open(port, baud, timeout_ms)` built on `serialport`, reporting USB VID/PID/product/serial metadata when available.
- **USB Devices**: `enumerate_usb_devices()` powered by pure-Rust `nusb`, exposing bus/address, vendor/product IDs, USB class/subclass/protocol, manufacturer, product, and serial string.
- **Human Interface Devices (HID)**: On Windows, queries `HidD_GetHidGuid`, `SetupDiGetClassDevsW` (`DIGCF_PRESENT | DIGCF_DEVICEINTERFACE`), and `HidD_GetAttributes` / `HidD_Get*String` (`windows-sys`) to inventory attached HID hardware safely without opening write handles during enumeration.

## 4. Testable Abstraction & Encrypted Remote Bridge

`SerialTransport` abstracts live physical ports (`OsSerialTransport`) and deterministic in-memory full-duplex mocks (`MemorySerialTransport::pair`):

```text
Operator Node                      Blind /ws Relay                   Edge Host Node
-------------                      ---------------                   --------------
send_serial_command_remote()
  -> CubeHash TX (256B bucket) --> routes EncryptedPacket ---------> decrypt_zero_oracle()
                                                                       -> bridge/OsSerialTransport
                                                                       -> reads COM reply bytes
                               <-- routes EncryptedPacket <--------- CubeHash TX (SerialData)
receives EazyAppMessage::SerialData
```

- Because `SerialCommand`, `SerialData`, `HardwareProbeRequest`, and `HardwareProbeResponse` are wrapped inside 256-byte bucket-padded `EazyAppMessage` frames encrypted by a paired `DuplexCubeSession`, the Master Relay never sees port names, baud rates, AT commands, sensor telemetry, or host hardware reports.
- `eazyconnect-client hw serial bridge --port COM3 --baud 115200` mounts an explicit local port on the node while keeping OS fallback disabled by default (`allow_remote_serial_os_fallback: false`), so remote peers can only access explicitly bridged ports.
