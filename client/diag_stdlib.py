import os
import sys
import json
import socket
import time
import subprocess
import tempfile
import datetime
import ssl
import ctypes
from urllib.parse import urlparse


def get_config_path():
    appdata = os.environ.get("APPDATA")
    if appdata:
        cfg_dir = os.path.join(appdata, "eazyconnect")
        try:
            os.makedirs(cfg_dir, exist_ok=True)
        except Exception:
            pass
        return os.path.join(cfg_dir, "config.json")
    return os.path.join(os.path.dirname(__file__), "config.json")


def load_config(path):
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def udp_discover(timeout=2):
    port = 37020
    msg = b"DISCOVER_EAZYCONNECT"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(timeout)
    out = []
    try:
        sock.sendto(msg, ("<broadcast>", port))
    except Exception as e:
        return [f"send error: {e}"]
    start = time.time()
    while time.time() - start < timeout:
        try:
            data, addr = sock.recvfrom(4096)
            try:
                info = json.loads(data.decode("utf-8"))
            except Exception:
                info = {"raw": data.decode("utf-8", errors="ignore")}
            info["from"] = addr[0]
            out.append(info)
        except socket.timeout:
            break
        except Exception:
            continue
    sock.close()
    return out


def http_check(master, verify=True):
    if not master:
        return "no master"
    try:
        parsed = urlparse(master)
        ctx = None
        if parsed.scheme in ("https",) and not verify:
            ctx = ssl._create_unverified_context()
        import urllib.request
        with urllib.request.urlopen(master, timeout=5, context=ctx) as r:
            return f"{r.status} {r.reason}"
    except Exception as e:
        return f"error: {e}"


def main():
    out_path = None
    if len(sys.argv) >= 3 and sys.argv[1] in ("--out", "-o"):
        out_path = sys.argv[2]
    elif len(sys.argv) >= 2 and sys.argv[1].startswith("--out="):
        out_path = sys.argv[1].split("=", 1)[1]

    lines = []
    ts = datetime.datetime.utcnow().isoformat() + "Z"
    lines.append(f"EazyConnect diag {ts}")
    cfg_path = get_config_path()
    lines.append(f"Config path: {cfg_path}")
    cfg = load_config(cfg_path)
    masked = dict(cfg)
    if "token" in masked:
        masked["token"] = "***REDACTED***"
    lines.append("Config:")
    try:
        lines.append(json.dumps(masked, indent=2, ensure_ascii=False))
    except Exception:
        lines.append(str(masked))

    master = cfg.get("master")
    verify = cfg.get("verify", True)
    lines.append("")
    lines.append(f"Master: {master} (verify={verify})")
    lines.append("HTTP check: " + http_check(master, verify))
    try:
        host = urlparse(master).hostname if master else None
        ip = socket.gethostbyname(host) if host else None
        lines.append(f"Resolved: {host} -> {ip}")
    except Exception as e:
        lines.append(f"DNS error: {e}")

    if ip:
        try:
            p = subprocess.run(["route", "print"], capture_output=True, text=True)
            lines.append("Route contains master ip: %s" % (str(ip in p.stdout)))
        except Exception as e:
            lines.append(f"Route check error: {e}")

    lines.append("")
    lines.append("UDP discovery (short):")
    try:
        disc = udp_discover(timeout=2)
        lines.append(json.dumps(disc, indent=2, ensure_ascii=False))
    except Exception as e:
        lines.append(f"Discovery error: {e}")

    lines.append("")
    candidates = [
        os.path.join(os.path.dirname(__file__), "cert.pem"),
        os.path.join(os.path.dirname(__file__), "..", "server", "certs", "cert.pem"),
        os.path.join(os.path.dirname(__file__), "installer_build", "cert.pem"),
    ]
    for c in candidates:
        lines.append(f"cert: {c} -> {os.path.exists(c)}")

    try:
        g = subprocess.run(["git", "--version"], capture_output=True, text=True)
        lines.append("git: " + (g.stdout.strip() or g.stderr.strip()))
    except Exception as e:
        lines.append(f"git error: {e}")

    try:
        iscc = subprocess.run(["where", "ISCC.exe"], capture_output=True, text=True)
        lines.append("ISCC: " + (iscc.stdout.strip() or iscc.stderr.strip()))
    except Exception as e:
        lines.append(f"ISCC check error: {e}")

    try:
        admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        lines.append(f"Is admin: {admin}")
    except Exception:
        lines.append("Is admin: unknown")

    exe_path = os.path.join(os.path.dirname(__file__), "..", "dist", "eazyconnect-client.exe")
    lines.append(f"Packaged EXE exists: {os.path.exists(exe_path)} ({exe_path})")

    if not out_path:
        out_path = os.path.join(tempfile.gettempdir(), f"eazyconnect_diag_{int(time.time())}.txt")
    try:
        with open(out_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        print(out_path)
    except Exception as e:
        print("failed to write report:", e)
        print("---")
        print("\n".join(lines))


if __name__ == '__main__':
    main()
