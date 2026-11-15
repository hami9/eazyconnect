# Changelog

All notable changes to **EazyConnect** are documented in this file.

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
