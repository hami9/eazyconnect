# EazyConnect (Rust + CubeHash Edition)

EazyConnect is a high-speed, headless LAN synchronization, zero-knowledge peer messaging, and OS/hardware-bridged communication platform rewritten in Rust (`v0.2.0`) and powered by **CubeHash** cellular cryptography, **XChaCha20-Poly1305**, **Ed25519 + X25519**, **TLS 1.3**, and Windows **DPAPI / TPM 2.0 / MachineGuid** hardware custody.

> Legacy Python prototype source (`v0.1.0`) remains preserved in the `v0.1.0` git tag.

## Documentation

- [Architecture Overview](docs/architecture.md) — 5-crate Rust workspace, CubeHash session lifecycle, signed UDP discovery, and REST / WebSocket routes.
- [Security Architecture & Threat Model](docs/security.md) — Hardware key custody, TOFU Ed25519 pinning, Argon2id/SHA-256 auth, E2E vault format, and blind relay guarantees.
- [CLI Reference](docs/cli-reference.md) — Complete options and subcommands for `eazyconnect-server` and `eazyconnect-client`.
- [Hardware & Peripheral Bridge](docs/hardware-bridge.md) — Windows DPAPI, TPM 2.0 CNG probe, `MachineGuid` lock, COM/Serial, USB, HID, and encrypted remote hardware bridging.
- [VPN & Dual-Homed Networks](docs/vpn-guide.md) — Mesh VPN setup (WireGuard, Tailscale, ZeroTier), Exit VPN LAN discovery bypass, persistent TLS pinning, and WSS auto-reconnect.
- [Changelog](CHANGELOG.md) — Release history (`v0.1.0` -> `v0.2.0` + VPN support).

## Workspace Architecture

| Crate | Purpose |
| --- | --- |
| `crates/cubehash-core` | `#![forbid(unsafe_code)]` cellular 3-cube cryptography engine (`XChaCha20-Poly1305`, `X25519` DH ratchet, TMR bit-rot self-healing, zero-oracle DTE Honey deception) |
| `crates/eazyconnect-hw` | Windows DPAPI (`CryptProtectData` / `CryptUnprotectData`), TPM 2.0 CNG probe, Registry `MachineGuid` binding, Win32 adapter/VPN inspection, COM/Serial (`serialport`), USB (`nusb`), and Windows HID (`SetupAPI`/`HidD_*`) |
| `crates/eazyconnect-core` | Wire protocol (`RelayFrame`, 256-byte bucket-padded `EazyAppMessage`), Ed25519-signed UDP `37020` LAN discovery beacons, TLS 1.3 CA / SHA-256 pinning, `EZV1` E2E file vault envelopes, and `BLAKE3` delta manifest |
| `crates/eazyconnect-server` | Headless HTTPS + WSS Master Server, Argon2id user auth, Ed25519 TOFU device enrollment + invite gate, `BLAKE3` file storage host, zero-knowledge blind `/ws` relay, UDP discovery responder, and Windows startup task helper |
| `crates/eazyconnect-client` | Headless CLI client, E2E file vault & incremental folder sync, CubeHash E2E terminal `chat`, COM/USB/HID inspection & encrypted serial bridging, diagnostics, and Windows logon task helper |
| `crates/eazyconnect-ui` | Native Discord-style Rust desktop chat UI (`eframe`/`egui`) with automatic server discovery, automatic TLS pinning & DPAPI enrollment, automatic E2E peer pairing, user profile popout, and Account / Theme / Connection settings |
| `installer/` | Graphical Fluent WPF prerequisite & deployment wizard ([EazyConnect-Setup.ps1](installer/EazyConnect-Setup.ps1), [Setup-EazyConnect.bat](Setup-EazyConnect.bat)) + Inno Setup 6 packager ([eazyconnect.iss](installer/eazyconnect.iss)) |

## Build & Verify

Requires Rust toolchain (`cargo` / `rustc`, Rust 2021 edition).

```powershell
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --release --bins
```

Compiled release binaries are written to:

- `target/release/eazyconnect-server.exe`
- `target/release/eazyconnect-client.exe`
- `target/release/eazyconnect-ui.exe`

You can also run [Setup-EazyConnect.bat](Setup-EazyConnect.bat) on Windows to open the graphical prerequisite installer & setup wizard (auto-installing Visual C++ Runtime, Rust toolchain, Git, Inno Setup, firewall rules, shortcuts, and VPN setup hints).

## Quick Start

### 1. Start the Master Server (HTTPS + WSS + UDP 37020)

```powershell
eazyconnect-server --listen 0.0.0.0:8000 --invite-code TEAM-LAN-KEY
```

On first launch without `--admin-pass`, `eazyconnect-server` generates a random CSPRNG password in `<data-dir>/bootstrap-admin.txt` and prints its `TLS SHA-256 Pin` and `Master Ed25519` public key.

### 2. Discover & Enroll a Client

```powershell
eazyconnect-client discover
eazyconnect-client --master https://<master-host>:8000 --tls-pin <sha256-hex> enroll --invite-code TEAM-LAN-KEY
```

The enrolled private identity is stored DPAPI-sealed (`*.eazyconnect-id.json`) and the bearer session token is stored DPAPI-sealed inside `config.json`.

### 3. Admin Login & User Creation

```powershell
eazyconnect-client login admin <bootstrap-password>
eazyconnect-client create-user operator "StrongPass#2026"
```

### 4. Incremental BLAKE3 & E2E File Vault Sync

```powershell
eazyconnect-client sync .\shared-docs --e2e
eazyconnect-client list
eazyconnect-client download report.pdf .\out\report.pdf --e2e
```

With `--e2e`, files are encrypted client-side using hardware-bound HKDF + `XChaCha20-Poly1305` (`EZV1`) before upload; the server stores opaque ciphertext only.

### 5. CubeHash E2E Chat & Hardware Bridging

```powershell
# Terminal E2E peer chat
eazyconnect-client chat --peer bob --psk shared-secret

# Local hardware inventory & COM serial I/O
eazyconnect-client hw list
eazyconnect-client hw serial list
eazyconnect-client hw serial send COM3 115200 "AT+INFO?"

# Expose local serial hardware over encrypted CubeHash WSS relay
eazyconnect-client hw serial bridge --port COM3 --baud 115200 --psk hw-secret
```

### 6. Diagnostics & Bilingual Profile (`en` / `fa`)

```powershell
eazyconnect-client profile set --name "Operator" --lang fa
eazyconnect-client diag --upload
```

## Public Repository Hygiene

Runtime secrets and state (`users.json`, `devices.json`, `tokens.json`, `config.json`, `sync-manifest.json`, `bootstrap-admin.txt`, `*.key`, `*.pem`, `*.sealed`, `*.keystore`, `*keystore*.json`, `*.eazyconnect-id.json`, `keystore/`, `data/`, `target/`) are excluded by `.gitignore`. Never commit generated runtime directories or keys to a public repository.
