# EazyConnect Security Architecture

## 1. Security Objectives

1. **No static or hardcoded credentials**: Eliminate default `admin/admin` accounts and plaintext token files.
2. **Transport authentication by default**: Reject unencrypted `http://` / `ws://` unless explicitly overridden for isolated lab testing (`--insecure-http`), and support strict TLS SHA-256 certificate pinning (`--tls-pin`).
3. **Hardware-locked key custody**: Bind local signing keys, file vault keys, and bearer tokens to OS hardware mechanisms (`DPAPI`, `MachineGuid`, TPM presence check).
4. **Zero-knowledge Master Server option**: Enable client-side `--e2e` file encryption (`EZV1`) and end-to-end encrypted CubeHash `/ws` peer sessions so the Master Relay cannot read file contents, chat messages, or hardware serial telemetry.
5. **Anti-impersonation & anti-traversal hardening**: Pin device `Ed25519` public keys across REST enrollment and WebSocket relay registration, and validate every relative file path and identifier strictly.

## 2. Authentication & Identity Custody

### User Accounts & Tokens (`AuthStore`)
- When initialized without `--admin-pass`, `eazyconnect-server` generates a 16-byte CSPRNG password (hex-encoded) for the initial `admin` user and writes it to `<data-dir>/bootstrap-admin.txt` (`0600` on Unix).
- Passwords are stored using `Argon2id` (`argon2`) salted hashes in `<data-dir>/users.json`.
- Session bearer tokens (`ezc_<64hex>`, 24-hour TTL) are issued from CSPRNG and stored on disk only as their SHA-256 hex digest in `<data-dir>/tokens.json`.

### Device Enrollment & Impersonation Defense
- Devices enroll via challenge-response: `GET /api/v1/auth/challenge` -> client signs `eazyconnect-http-auth-v2 || nonce || len(client_id) || client_id || len(challenge_id) || challenge_id` with its `Ed25519` key -> `POST /api/v1/auth/verify`.
- Server supports `EnrollmentPolicy::OpenLan` or `EnrollmentPolicy::InviteCode(code)` checked in constant time (`subtle::ConstantTimeEq`). When active VPN adapters are detected under `OpenLan` (without `--lan-only`), `eazyconnect-server` warns the operator at startup to enable `--invite-code`.
- On first valid enrollment (or first WS registration), the device's `[u8; 32]` `Ed25519` public key is pinned to `client_id` in `<data-dir>/devices.json` (`check_or_pin_device_key`). Subsequent attempts using the same `client_id` with any different key fail with `403 identity_mismatch` on HTTP and rejection on `/ws`.
- When a roaming or reconnecting device proves ownership of its pinned `Ed25519` key over a fresh WebSocket `challenge_nonce`, the relay atomically replaces any lingering half-open session (`session_replaced`); mismatched keys are still blocked before session replacement.
- Default self-signed server certificates are persisted under `<data-dir>/tls/{cert.pem,key.pem}` (`0600` key on Unix) so client `--tls-pin` values remain valid across server restarts until `--regen-tls` is invoked.

### Signed Discovery (`UDP 37020`)
- `DISCOVER_EAZYCONNECT` probes return a `DiscoveryBeacon` JSON signed with the Master's `Ed25519` key over `eazyconnect-discover-v3 || version || host || port || https || tls_cert_sha256_hex || master_ed25519_pub || alternate_urls`.
- `discover_masters` verifies every beacon signature (`signature_valid`) before returning it to CLI callers or diagnostics.

## 3. Client-Side E2E File Vault (`EZV1`)

With `--e2e`, `eazyconnect-client` encrypts each file locally before calling `POST /api/v1/files/upload`:

1. Local 32-byte `vault_key` is stored sealed via `seal_local_secret` (`vault.key.sealed`) or supplied across trusted devices via `--vault-key-hex`.
2. `encrypt_file_for_vault` generates a random 16-byte `salt` and 24-byte `nonce`.
3. `HardwareProvider::seal_secret(b"eazyconnect-file-vault-v1", vault_key)` binds the key to the host `OsBoundHardwareProvider`.
4. `hkdf_expand_label` derives a unique per-file `XChaCha20-Poly1305` key bound to `(salt, relative_filename)` and seals with `AAD = "eazyconnect-vault-aad-v1" || salt || relative_filename`.
5. Output envelope layout: `EZV1 (4B) || salt (16B) || nonce (24B) || ciphertext + tag`.

Copying ciphertext off the Master Server or attempting decryption on an unauthorized machine / mismatched filename fails authentication.

## 4. CubeHash E2E Peer Sessions (`/ws` Blind Relay)

- **Key Exchange**: `PairOffer` and `PairAccept` exchange ephemeral `X25519` keys and initial ratchet keys, signed with each peer's `Ed25519` identity (`pair_offer_sign_bytes`, `pair_accept_sign_bytes`) and TOFU-pinned via `verify_or_pin_peer`.
- **Transcript & PSK Binding**: Shared ECDH output, transcript (`pair_id`, IDs, ephemeral & `Ed25519` keys), and optional pre-shared key (`--psk`) feed `hmac_sha256_parts` + `hkdf_expand_label` to provision asymmetric TX/RX `DuplexCubeSession` directions plus a human-verifiable `safety_fingerprint` (`XXXX-XXXX-XXXX-XXXX`).
- **Metadata Padding**: All `EazyAppMessage` variants (`ChatText`, `FileShared`, `SerialData`, `SerialCommand`, `HardwareProbeRequest`, `HardwareProbeResponse`) are encoded into **256-byte bucket multiples** with CSPRNG padding (`encode_padded_bucket`) before CubeHash encryption so the blind relay cannot distinguish chat messages from hardware serial commands or leak exact lengths.
- **Zero-Oracle & Commit/Rollback**:
  - Senders keep TX mesh mutation staged (`pending_outbound`) until receiving `DeliveryAck` (`commit_ack`) or rolling back cleanly (`rollback_outbound`) on peer disconnect.
  - Receivers decrypt via `decrypt_zero_oracle` with `HoneyProfile::ChatPlaintext`, executing constant work without mutating session state or exposing error oracles on tampered/forged frames.
- **Bit-Rot Repair & Epoch Hopping**:
  - `WirePacket` carries TMR shadow bytes healed automatically by bitwise majority voting (`healed_bits`).
  - `hop_epoch` executes TX/RX `X25519` ratchets signed with `Ed25519` (`epoch_hop_sign_bytes`).

## 5. Input & Storage Hygiene

- `validate_id` (`eazyconnect-hw`): enforces non-empty identifiers (<= 128 chars) containing only `[A-Za-z0-9_.-]` and rejects traversal sequences (`..`, slashes, colons).
- `validate_rel_path` (`eazyconnect-server`): rejects empty/oversized paths (> 512 chars), leading slashes, drive letters (`:`), NUL/control characters, empty segments, `.` and `..`, and non-normal OS path components; skips symlinks during recursive listing.
- Secret/state files are excluded via `.gitignore` (`bootstrap-admin.txt`, `users.json`, `devices.json`, `tokens.json`, `config.json`, `sync-manifest.json`, `*.key`, `*.pem`, `*.sealed`, `*.keystore`, `*keystore*.json`, `*.eazyconnect-id.json`, `tls/`, `keystore/`, `data/`, `target/`).
