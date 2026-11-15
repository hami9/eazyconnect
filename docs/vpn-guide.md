# EazyConnect Over VPN & Dual-Homed Networks

EazyConnect works both across **peer/mesh VPNs** (WireGuard, Tailscale, ZeroTier, site-to-site OpenVPN) and on hosts running **full-tunnel commercial Exit VPNs** where the default route (`0.0.0.0/0`) goes through a TUN/TAP adapter.

---

## 1. Peer / Mesh VPN Setup (WireGuard, Tailscale, ZeroTier)

When Master and Clients communicate over a virtual overlay network (e.g., `10.8.0.x` or `100.64.x.x`):

### On the Master Server

Start `eazyconnect-server` with an `--invite-code` so remote peers on the VPN cannot enroll without authorization:

```powershell
eazyconnect-server --listen 0.0.0.0:8000 --invite-code TEAM-VPN-SECRET
```

- **Persistent Self-Signed TLS Pin**: Unless `--tls-cert`/`--tls-key` or `--insecure-http` are passed, the server creates and persists `<data-dir>/tls/cert.pem` and `<data-dir>/tls/key.pem` across restarts (`--regen-tls` rotates them intentionally). Remote VPN clients keep working without re-pinning after a server restart.
- **Automatic Multi-Homed SANs**: Generated certificates automatically include `localhost`, `127.0.0.1`, `::1`, all active LAN IPv4s, and all active VPN interface IPv4s (plus `--advertised-host` if given).
- **Security Warning on `OpenLan`**: If active VPN adapters are detected without `--invite-code` or `--lan-only`, the server emits a startup warning recommending `--invite-code`.

### On Remote VPN Clients

Because Layer-3 VPNs do not forward local LAN broadcast (`255.255.255.255:37020`), use either unicast UDP discovery or direct pinning:

```powershell
# Option A: Ed25519-signed unicast UDP 37020 query to the Master's VPN IP
eazyconnect-client discover --target 100.64.0.10:37020

# Option B: Direct HTTPS enrollment with pinned SHA-256 fingerprint
eazyconnect-client --master https://100.64.0.10:8000 --tls-pin <sha256-hex> enroll --invite-code TEAM-VPN-SECRET
```

Signed discovery beacons return the subnet-matched primary URL plus `alternate_urls` for any secondary LAN/VPN interfaces.

---

## 2. Full-Tunnel Exit VPN Coexistence on LAN

When a device runs an Exit VPN (Proton, Mullvad, Windscribe, Cloudflare WARP, Cisco AnyConnect, etc.), `0.0.0.0/0` traffic is captured by the tunnel adapter:

1. **Adapter Classification (`eazyconnect-hw`)**: Win32 `GetAdaptersAddresses` enumerates adapter IPv4 addresses alongside prefix lengths (`ipv4_cidrs`) and classifies VPN/TUN/TAP/Wintun/overlay drivers separately from physical Wi-Fi and Ethernet NICs.
2. **LAN Broadcast Bypass (`discover`)**: When targeting `255.255.255.255:37020`, `eazyconnect-client` also binds sockets directly to each active non-VPN LAN interface and transmits subnet-directed broadcasts (e.g., `192.168.1.255:37020`), bypassing the Exit VPN default route so local LAN peers still find the Master.
3. **Peer-Matched Beacon Endpoints**: When the Master replies to `DISCOVER_EAZYCONNECT`, `select_beacon_endpoints` chooses the local interface sharing the requester's subnet instead of leaking an unreachable Exit-VPN tunnel IP.
4. **LAN Strict Isolation**: Pass `--lan-only` on `eazyconnect-server` (without `--listen`) to bind strictly to the primary non-VPN LAN IPv4 address and exclude VPN SANs.

---

## 3. Connection Resilience & Transport Tuning

- **TCP Keepalive & `TCP_NODELAY`**: All client HTTP/WSS connections and accepted server streams enable `TCP_NODELAY` and OS `SO_KEEPALIVE` (`20s` idle, `10s` interval via `socket2`).
- **WebSocket Heartbeat**: Both `/ws` relay handlers and `EazyNode` issue `20s` WebSocket `Ping` frames with a `65s` idle timeout so silently dropped NAT/VPN mappings are detected cleanly.
- **Authenticated Session Reclaim**: After brief VPN roaming or half-open disconnects, when a client re-authenticates via Ed25519 challenge-response for its pinned `client_id`, the relay atomically replaces the stale connection instead of locking it out with `id_in_use`.
- **Stateful Auto-Reconnect (`chat` & `hw serial bridge`)**: `EazyNode` (`auto_reconnect: true`) cleanly rolls back any un-ACKed `inflight` CubeHash TX frame before reconnecting with backoff (`200ms`, then `1s..5s`), preserving paired `DuplexCubeSession` keys and epochs across transient tunnel drops.
- **Slow-VPN HTTP Timeouts**: `MasterHttpClient` uses a `15s` TCP connect budget while scaling transfer timeouts dynamically (`30s + payload_bytes / 64KiB`, capped at `600s`; `300s` for encrypted file downloads).
