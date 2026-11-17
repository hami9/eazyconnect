# Changelog

All notable changes to **EazyConnect** are documented in this file.

## v0.3.0 — Network Console

- Added the administrator network console with live master and relay status, searchable device inventory, and persistent device blocking.
- Redesigned desktop navigation and connection setup for wide and narrow windows.
- Updated the vendored CubeHash engine to 1.0.2. Upgrade the master first, then update both clients before pairing them again. Existing EZV1 vault files remain readable.

### Native Desktop UI (`eazyconnect-ui`), CubeHash Chat Files & Simplified Wizard (`installer/`)
- Added direct CubeHash P2P E2E chunked file transfer in chat (`EazyAppMessage::FileChunk` + `FileTransferAssembler` with 128 KiB chunks, 25 MiB cap, and `BLAKE3` whole-file integrity verification in `eazyconnect-core`, `EazyNode::send_e2e_file_bytes` in `eazyconnect-client`, and `+` attach file button with transfer progress, inline image previews, and `Save` attachment cards in `eazyconnect-ui`).
- Refined `eazyconnect-ui` button styling (`widgets.rs`: unified Blurple/Ghost/Danger buttons, squircle rail icons, unread pills) and added 3-tier responsive viewport adaptation (`LayoutMetrics`: wide desktop, compact sidebar, and narrow single-pane navigation with `<- Peers` back button & Settings strip).
- Added `eazyconnect-client ui` subcommand and shared session/vault helpers in `eazyconnect-client::session`.
- Simplified [installer/EazyConnect-Setup.ps1](installer/EazyConnect-Setup.ps1) with instant async background system scanning, a 3-card quick-start menu (`Install EazyConnect Desktop App` + `1-Click Express Install`, `Host Master Server`, and `System Prerequisites`), role-specific options, collapsed `Advanced & Developer Options` and log drawers, and explicit cross-runspace UI binding alongside [installer/eazyconnect.iss](installer/eazyconnect.iss) and [installer/build-installer.ps1](installer/build-installer.ps1).

### VPN Topology & Discovery
- Expanded `classify_vpn_adapter` in `eazyconnect-hw` for WireGuard, Tailscale, ZeroTier, OpenVPN, Cloudflare WARP, Wintun, Proton, Mullvad, Cisco AnyConnect, GlobalProtect, Outline, Nekoray/Sing-box, Forti, SoftEther, and Hamachi, and added Win32 IPv4 prefix (`ipv4_cidrs`) extraction to compute subnet-directed LAN broadcasts (`collect_lan_directed_broadcasts`) and preferred non-VPN LAN endpoints (`best_lan_ipv4`).
- Updated `discover_masters` to transmit per-NIC subnet-directed broadcasts alongside `255.255.255.255:37020` so local LAN discovery continues working when a full-tunnel Exit VPN captures `0.0.0.0/0`.
- Updated signed `DiscoveryBeacon` (`eazyconnect-discover-v3`) to match each requester's subnet (`select_beacon_endpoints`) and include secondary LAN/VPN endpoints inside `alternate_urls`.

### Persistent TLS, Keepalive & Reconnect Resilience
- Added `ServerTlsConfig::LoadOrCreateSelfSigned` so `eazyconnect-server` persists `<data-dir>/tls/cert.pem` and `<data-dir>/tls/key.pem` across restarts (keeping `--tls-pin` stable for remote VPN peers), automatically includes all active LAN + VPN IPv4 endpoints in X.509 SANs, and adds `--regen-tls` and `--lan-only` CLI options plus a startup warning when VPN adapters are up under `OpenLan`.
- Added shared `configure_tcp_keepalive` / `connect_tcp_keepalive` helpers (`TCP_NODELAY` + 20s/10s `SO_KEEPALIVE` via `socket2`) across server accept loops, `MasterHttpClient`, and `EazyNode`.
- Added 20s WebSocket `Ping` heartbeats (65s idle timeout) on both blind relay and client actors, atomic Ed25519-verified session reclaim on `/ws` reconnect (`session_replaced`), stateful `EazyNode` `auto_reconnect` (rolling back any un-ACKed `inflight` TX packet while preserving paired `DuplexCubeSession` keys), and scaled slow-VPN HTTP transfer timeouts (`30s`–`600s`; `300s` for downloads).

## v0.2.0 — Rust + CubeHash Rewrite

### Architecture & Performance
- Replaced Python (FastAPI / Tkinter) stack with a 5-crate Rust workspace (`cubehash-core`, `eazyconnect-hw`, `eazyconnect-core`, `eazyconnect-server`, `eazyconnect-client`).
- Preserved legacy Python code and installer scripts under git tag `v0.1.0`.
- Consolidated desktop UI and standalone relay experiments into native headless binaries (`eazyconnect-server` and `eazyconnect-client`).

### Cryptography & Security
- Embedded `cubehash-core` (`#![forbid(unsafe_code)]`) providing 3-cube custody, cellular state evolution, `X25519` DH ratcheting, Triple Modular Redundancy (TMR) bit-rot healing, and constant-work `HoneyDeception` DTE fallback.
- Replaced hardcoded bootstrap credentials with CSPRNG password generation (`bootstrap-admin.txt`), `Argon2id` password verification, and SHA-256 hashed bearer tokens.
- Added mandatory TLS verification by default in the client (supporting WebPKI roots, custom CA PEM, and `PinnedCertSha256`), refusing plaintext `http://` / `ws://` without explicit `--insecure-http`.
- Signed UDP `37020` LAN discovery beacons with the Master's `Ed25519` identity key and embedded its TLS certificate SHA-256 fingerprint.
- Added client-side E2E file vault encryption (`--e2e`, `EZV1` format) bound to the local device's `HardwareProvider` and `XChaCha20-Poly1305`.
- Completed the `Messages` subsystem with full-duplex CubeHash E2E terminal chat over a zero-knowledge blind `/ws` relay padded into 256-byte buckets.
- Hardened server relative path validation (`validate_rel_path`) and device/owner identifier validation (`validate_id`) against path traversal.

### Native OS & Hardware Integration (`eazyconnect-hw`)
- Added Windows DPAPI secret sealing (`CryptProtectData` / `CryptUnprotectData`), TPM 2.0 CNG availability probing, and Registry `MachineGuid` hardware locking.
- Added direct OS peripheral enumeration and access for COM/Serial (`serialport`), USB (`nusb`), Windows HID (`SetupAPI` / `HidD_*`), and Win32 network/VPN adapter inspection (`GetAdaptersAddresses`).
- Added testable `SerialTransport` (`OsSerialTransport` + `MemorySerialTransport`) and encrypted CubeHash remote serial bridging (`hw serial bridge`).
- Added Windows Task Scheduler service helpers (`service install-task` / `uninstall-task`) in both binaries.

### Verification
- Verified workspace cleanly with `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` (26/26 tests passing across unit, security, and E2E suites), and release binary builds (`eazyconnect-server.exe`, `eazyconnect-client.exe`).

## v0.1.0 — Initial Prototype Release
- Legacy Python FastAPI master server, UDP `37020` LAN discovery, Tkinter GUI, Python CLI client, and Inno Setup Windows installer scripts.
