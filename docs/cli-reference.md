# EazyConnect CLI Reference

All examples below apply to compiled binaries `eazyconnect-server` and `eazyconnect-client` (or via `cargo run --release --bin ...`).

---

## `eazyconnect-server`

```text
eazyconnect-server [run] [OPTIONS]
eazyconnect-server service <install-task|uninstall-task> [--name <TaskName>] [OPTIONS]
```

### Server Options

| Flag | Default | Description |
| --- | --- | --- |
| `--listen <ip:port>` | `0.0.0.0:8000` | TCP bind address for HTTPS REST + WSS `/ws` |
| `--data-dir <dir>` | `%LOCALAPPDATA%\eazyconnect-server` (Windows) / `data` | Directory holding `users.json`, `devices.json`, `tokens.json`, uploaded `files/`, `meta/`, `reports/`, `bootstrap-admin.txt` |
| `--keystore-dir <dir>` | `<data-dir>/keystore` | OS-sealed keystore for Master `Ed25519` identity |
| `--tls-cert <pem>` | Self-signed generated | Path to custom server TLS certificate PEM |
| `--tls-key <pem>` | Self-signed generated | Path to custom server TLS private key PEM |
| `--insecure-http` | Off (`false`) | Disable TLS and serve plaintext HTTP/WS (testing only) |
| `--discovery-port <u16>` | `37020` | UDP LAN discovery responder port (`0` disables) |
| `--no-discovery` | Enabled | Disable UDP discovery responder |
| `--advertised-host <host>` | Auto-detected LAN IPv4 | Override host/IP advertised in signed UDP beacons |
| `--invite-code <code>` | Open LAN enrollment | Require constant-time invite code when enrolling new devices |
| `--admin-pass <password>` | Random in `bootstrap-admin.txt` | Explicit bootstrap password for `admin` on initial DB creation |

### Server Windows Task Helper

```powershell
# Register startup task (Windows)
eazyconnect-server service install-task --name EazyConnectMaster --listen 0.0.0.0:8000 --invite-code TEAM-KEY

# Remove startup task
eazyconnect-server service uninstall-task --name EazyConnectMaster
```

---

## `eazyconnect-client`

```text
eazyconnect-client [GLOBAL OPTIONS] <SUBCOMMAND> [ARGS...]
```

### Global Options

| Flag | Description |
| --- | --- |
| `--master <url>` | Master server URL (`https://...` or `wss://...`) |
| `--tls-pin <sha256>` | Pin Master TLS certificate SHA-256 hex fingerprint |
| `--tls-ca <pem>` | Trust custom root/CA PEM certificate |
| `--insecure-http` | Allow plaintext `http://` / `ws://` connections (testing only) |
| `--config <path>` | Override `config.json` path (`%APPDATA%\eazyconnect\config.json` by default) |
| `--client-id <id>` | Override local device `client_id` (defaults to saved ID or host name) |
| `--keystore-dir <dir>` | Override OS-sealed keystore directory |

### Discovery & Authentication

```powershell
# Broadcast Ed25519-signed UDP discovery query on LAN
eazyconnect-client discover [--target 255.255.255.255:37020] [--timeout-ms 1500]

# Enroll DPAPI-sealed Ed25519 device identity (persists master URL & sealed token)
eazyconnect-client --master https://<host>:8000 --tls-pin <sha256> enroll [--invite-code <code>]

# Password login (stores DPAPI-sealed bearer token in config.json)
eazyconnect-client --master https://<host>:8000 --tls-pin <sha256> login <username> <password>

# Admin user creation (password >= 8 chars; requires admin bearer token)
eazyconnect-client create-user <username> <password> [--admin]
```

### Files & Incremental Sync

```powershell
# Single-file upload (add --e2e for client-side hardware-bound vault encryption)
eazyconnect-client upload <local_file> [--remote <rel_path>] [--e2e] [--vault-key-hex <64hex>]

# List files stored on Master
eazyconnect-client list [--owner <id>]

# Download file (verifies x-eazy-blake3 automatically; --e2e decrypts EZV1 envelopes)
eazyconnect-client download <remote_path> <dest_file> [--owner <id>] [--e2e] [--vault-key-hex <64hex>]

# Incremental BLAKE3 folder sync (skips unchanged files using sync-manifest.json)
eazyconnect-client sync <folder> [--manifest <path>] [--e2e] [--vault-key-hex <64hex>]
```

### Encrypted Peer Chat (`Messages`)

```powershell
# Wait for incoming CubeHash pair offer over WSS
eazyconnect-client chat --listen [--psk <secret>]

# Initiate CubeHash E2E session with peer
eazyconnect-client chat --peer <peer_id> [--profile standard|compact|high] [--psk <secret>]
```

Interactive commands inside `chat`:
- `/hop` — Execute `X25519` epoch ratchet hop with connected peer.
- `/hwprobe` — Request encrypted remote host hardware report from peer.
- `/quit` — Close WSS session gracefully.
- Any other line — Send 256-byte bucket-padded E2E chat message.

### Hardware & Serial Commands

```powershell
# JSON report: TPM 2.0 CNG, DPAPI, MachineGuid, Admin, NIC/VPN adapters, COM, USB, HID
eazyconnect-client hw list

# List serial / COM ports
eazyconnect-client hw serial list

# Send raw UTF-8 or hex payload directly to a local serial port
eazyconnect-client hw serial send <port> <baud> <payload> [--hex] [--timeout-ms 500]

# Expose local serial port to paired peers over encrypted CubeHash WSS relay
eazyconnect-client hw serial bridge --port <COMx> [--baud 9600] [--psk <secret>]
```

### Profile, Diagnostics & Windows Logon Task

```powershell
# View or update bilingual user profile (en / fa)
eazyconnect-client profile show
eazyconnect-client profile set [--name <name>] [--lang en|fa]

# Run hardware + LAN UDP discovery + optional Master /api/v1/health check
eazyconnect-client diag [--upload]

# Windows logon scheduled task management
eazyconnect-client service install-task [--name EazyConnectClient] [args...]
eazyconnect-client service uninstall-task [--name EazyConnectClient]
```
