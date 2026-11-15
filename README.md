# EazyConnect (Rust + CubeHash Edition)

EazyConnect is a high-speed, cross-platform (Windows-first) headless platform written in Rust for LAN discovery, end-to-end encrypted file synchronization, zero-knowledge peer messaging, and direct OS/hardware peripheral bridging — secured by **CubeHash** cellular cryptography, **XChaCha20-Poly1305**, **Ed25519 + X25519**, **TLS 1.3**, and Windows **DPAPI / TPM 2.0 / MachineGuid** hardware custody.

> Legacy Python `v0.1.0` history remains preserved in the `v0.1.0` git tag.

## Workspace Architecture

| Crate | Purpose |
| --- | --- |
| `crates/cubehash-core` | `#![forbid(unsafe_code)]` cellular 3-cube cryptography engine (XChaCha20-Poly1305, X25519 DH ratchet, TMR bit-rot self-healing, zero-oracle DTE Honey encryption) |
| `crates/eazyconnect-hw` | Windows DPAPI (`CryptProtectData` / `CryptUnprotectData`), TPM 2.0 CNG probe, Registry `MachineGuid` binding, Win32 adapter/VPN inspection, direct COM/Serial (`serialport`), USB (`nusb`), and Windows HID (`SetupAPI`/`HidD_*`) |
| `crates/eazyconnect-core` | Shared protocol frames (`RelayFrame`, 256B bucket-padded `EazyAppMessage`), signed UDP `37020` LAN discovery beacons, TLS 1.3 self-signed / CA / SHA-256 pinning, E2E file vault envelopes, BLAKE3 delta manifest |
| `crates/eazyconnect-server` | Headless HTTPS + WSS Master Server, Argon2id user auth, Ed25519 TOFU device enrollment + invite gate, BLAKE3 file storage host, zero-knowledge blind WebSocket relay (`/ws`), UDP discovery responder, and Windows task helper |
| `crates/eazyconnect-client` | Headless Rust CLI client, E2E file vault & incremental folder sync, CubeHash E2E terminal chat (`Messages`), COM/USB hardware bridge, diagnostics, and Windows task helper |

## Security Highlights

- **No hardcoded credentials**: On first startup without `--admin-pass`, `eazyconnect-server` generates a CSPRNG bootstrap admin password saved locally to `<data-dir>/bootstrap-admin.txt` (gitignored) and stores Argon2id hashes plus SHA-256 hashed bearer tokens.
- **TLS everywhere by default**: `eazyconnect-server` serves HTTPS + WSS with self-signed Ed25519/ECDSA or custom PEM certificates and publishes a SHA-256 certificate pin (`--tls-pin`). `eazyconnect-client` refuses plaintext `http://` / `ws://` unless `--insecure-http` is passed explicitly.
- **Ed25519-signed LAN discovery**: UDP port `37020` beacons (`DISCOVER_EAZYCONNECT`) carry the Master's TLS SHA-256 pin and Ed25519 public key + signature.
- **Hardware-locked identity & token storage**: Client private identities (`*.eazyconnect-id.json`), E2E file vault keys (`vault.key.sealed`), and bearer tokens (`config.json`) are sealed at rest via Windows DPAPI + `OsBoundHardwareProvider`.
- **End-to-End Encrypted Files (`--e2e`)**: With `--e2e`, files are encrypted client-side using hardware-bound HKDF + XChaCha20-Poly1305 (`EZV1`) before upload; the server never observes plaintext or vault keys.
- **Blind CubeHash `/ws` Relay**: Terminal `chat` and remote `hw serial` commands run over 256-byte bucket-padded `DuplexCubeSession` frames with X25519 ratcheting, DeliveryAck rollback safety, TMR bit-rot repair, and zero-oracle tampering resilience.

## Build & Verify

```powershell
cargo test --workspace
cargo build --release --bins
```

Binaries are emitted under `target/release/eazyconnect-server.exe` and `target/release/eazyconnect-client.exe`.

## Quick Start

### 1. Start Master Server (HTTPS + WSS + UDP 37020 Discovery)

```powershell
eazyconnect-server --listen 0.0.0.0:8000 --invite-code TEAM-LAN-KEY
```

Note the printed `TLS SHA-256 Pin` and `<data-dir>/bootstrap-admin.txt`.

### 2. Discover & Enroll a Client

```powershell
eazyconnect-client discover
eazyconnect-client --master https://<master-host>:8000 --tls-pin <sha256-hex> enroll --invite-code TEAM-LAN-KEY
```

### 3. Admin Login & User Creation

```powershell
eazyconnect-client --master https://<master-host>:8000 --tls-pin <sha256-hex> login admin <bootstrap-password>
eazyconnect-client create-user operator "StrongPass#2026"
```

### 4. Incremental BLAKE3 & E2E File Sync

```powershell
eazyconnect-client sync .\shared-docs --e2e
eazyconnect-client list
eazyconnect-client download report.pdf .\out\report.pdf --e2e
```

### 5. CubeHash E2E Chat & Hardware Bridging

```powershell
# Terminal chat
eazyconnect-client chat --peer bob --psk shared-secret

# Hardware inventory & direct COM serial I/O
eazyconnect-client hw list
eazyconnect-client hw serial list
eazyconnect-client hw serial send COM3 115200 "AT+INFO?"

# Expose local serial port over CubeHash E2E relay
eazyconnect-client hw serial bridge --port COM3 --baud 115200 --psk hw-secret
```

### 6. Diagnostics & Bilingual Profile (`en` / `fa`)

```powershell
eazyconnect-client profile set --name "Operator" --lang fa
eazyconnect-client diag --upload
```

## Public Repository Hygiene

Runtime secrets (`users.json`, `devices.json`, `tokens.json`, `config.json`, `*.key`, `*.pem`, `*.sealed`, `*keystore*`, `bootstrap-admin.txt`, `data/`, `target/`) are strictly excluded via `.gitignore`. Never remove these ignore rules before pushing to a public repository.
