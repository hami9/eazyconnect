import requests
import os
import json
import time
import argparse
import socket
import subprocess
import datetime
import tempfile
import io
import contextlib
from urllib.parse import urlparse
import ctypes

def get_config_path():
    """Return the preferred config path.

    Priority:
    - %APPDATA%/eazyconnect/config.json (when available)
    - fallback to the script-local config.json
    """
    appdata = os.environ.get("APPDATA")
    if appdata:
        cfg_dir = os.path.join(appdata, "eazyconnect")
        try:
            os.makedirs(cfg_dir, exist_ok=True)
        except Exception:
            pass
        return os.path.join(cfg_dir, "config.json")
    return os.path.join(os.path.dirname(__file__), "config.json")

CONFIG_PATH = get_config_path()


def load_config():
    try:
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    # fallback to script-local config if different
    local = os.path.join(os.path.dirname(__file__), "config.json")
    try:
        if os.path.exists(local):
            with open(local, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def save_config(cfg):
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
            return
    except Exception:
        pass
    # fallback: try to write next to script
    local = os.path.join(os.path.dirname(__file__), "config.json")
    with open(local, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)


def login(master_url, username, password):
    cfg = load_config()
    verify = cfg.get("verify", True)
    r = requests.post(f"{master_url}/auth", params={"username": username, "password": password}, verify=verify)
    r.raise_for_status()
    tok = r.json().get("token")
    cfg.update({"master": master_url, "username": username, "token": tok})
    save_config(cfg)
    print("logged in, token saved")


def upload(file_path):
    cfg = load_config()
    master = cfg.get("master")
    tok = cfg.get("token")
    if not master or not tok:
        print("not configured. run login first")
        return
    files = {"file": open(file_path, "rb")}
    headers = {"x-token": tok}
    verify = cfg.get("verify", True)
    r = requests.post(f"{master}/upload", files=files, headers=headers, verify=verify)
    r.raise_for_status()
    print(r.json())


def list_files():
    cfg = load_config()
    master = cfg.get("master")
    tok = cfg.get("token")
    verify = cfg.get("verify", True)
    r = requests.get(f"{master}/list", headers={"x-token": tok}, verify=verify)
    r.raise_for_status()
    print(json.dumps(r.json(), indent=2, ensure_ascii=False))


def discover(timeout=3):
    port = 37020
    msg = b"DISCOVER_EAZYCONNECT"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(timeout)
    try:
        sock.sendto(msg, ("<broadcast>", port))
    except Exception as e:
        print("send error", e)
        sock.close()
        return
    results = []
    start = time.time()
    while time.time() - start < timeout:
        try:
            data, addr = sock.recvfrom(4096)
            try:
                info = json.loads(data.decode("utf-8"))
            except Exception:
                info = {"raw": data.decode("utf-8", errors="ignore")}
            info["from"] = addr[0]
            results.append(info)
        except socket.timeout:
            break
        except Exception:
            continue
    sock.close()
    print(json.dumps(results, indent=2, ensure_ascii=False))


def git_push(repo_path: str = "..", message: str = "Auto commit from client"):
    repo = os.path.abspath(os.path.join(os.path.dirname(__file__), repo_path))
    if not os.path.exists(os.path.join(repo, ".git")):
        print("No git repo found at", repo)
        return
    try:
        subprocess.run(["git", "add", "."], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-m", message], cwd=repo, check=False)
        subprocess.run(["git", "push", "origin", "HEAD"], cwd=repo, check=True)
        print("git push attempted")
    except Exception as e:
        print("git push failed:", e)


def download(owner, filename, dest):
    cfg = load_config()
    master = cfg.get("master")
    tok = cfg.get("token")
    verify = cfg.get("verify", True)
    r = requests.get(f"{master}/download/{owner}/{filename}", headers={"x-token": tok}, stream=True, verify=verify)
    if r.status_code != 200:
        print(r.text)
        return
    os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
    with open(dest, "wb") as f:
        for chunk in r.iter_content(4096):
            f.write(chunk)
    print("saved", dest)


def _mask_token(cfg: dict) -> dict:
    c = dict(cfg)
    if "token" in c:
        c["token"] = "***REDACTED***"
    return c


def diagnose(output_path: str = None, discover_timeout: int = 2):
    """Run diagnostic checks and write a report to `output_path` (or temp file).

    Checks performed:
    - Config file path and contents (token redacted)
    - Master reachability (HTTP)
    - UDP discovery (quick)
    - DNS resolution for master host
    - Route table contains entry for master IP (Windows `route print` scan)
    - Presence of cert.pem in common locations
    - Tool checks: `git --version`, `where ISCC.exe`
    - Whether process is elevated (admin)
    """
    lines = []
    ts = datetime.datetime.utcnow().isoformat() + "Z"
    lines.append(f"EazyConnect diagnostic report {ts}")
    lines.append("")

    cfg = load_config()
    lines.append("Config path: %s" % CONFIG_PATH)
    lines.append("Config (redacted):")
    try:
        lines.append(json.dumps(_mask_token(cfg), indent=2, ensure_ascii=False))
    except Exception as e:
        lines.append(f"  (error reading config: {e})")

    master = cfg.get("master")
    verify = cfg.get("verify", True)
    if master:
        lines.append("")
        lines.append(f"Master: {master} (verify={verify})")
        # HTTP reachability
        try:
            r = requests.get(master, timeout=5, verify=verify)
            lines.append(f"HTTP GET {master} -> {r.status_code} {r.reason}")
        except Exception as e:
            lines.append(f"HTTP GET {master} failed: {repr(e)}")
        # DNS resolution
        try:
            host = urlparse(master).hostname
            ip = socket.gethostbyname(host) if host else None
            lines.append(f"Resolved host: {host} -> {ip}")
        except Exception as e:
            ip = None
            lines.append(f"DNS resolution failed: {repr(e)}")
        # route table scan (Windows)
        if ip:
            try:
                p = subprocess.run(["route", "print"], capture_output=True, text=True)
                found = ip in p.stdout
                lines.append(f"Route table contains master IP: {found}")
            except Exception as e:
                lines.append(f"Route check failed: {repr(e)}")

    else:
        lines.append("Master not configured in config.json")

    # UDP discovery (reuse discover()) capture stdout
    lines.append("")
    lines.append("Running UDP discovery (short timeout)")
    try:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            discover(timeout=discover_timeout)
        disc_out = buf.getvalue().strip()
        lines.append(disc_out or "(no discovery output)")
    except Exception as e:
        lines.append(f"Discovery failed: {repr(e)}")

    # Check cert locations
    lines.append("")
    candidates = [
        os.path.join(os.path.dirname(__file__), "cert.pem"),
        os.path.join(os.path.dirname(__file__), "..", "server", "certs", "cert.pem"),
        os.path.join(os.path.dirname(__file__), "installer_build", "cert.pem"),
    ]
    for c in candidates:
        exists = os.path.exists(c)
        lines.append(f"cert check: {c} -> {exists}")

    # Tool checks
    lines.append("")
    try:
        g = subprocess.run(["git", "--version"], capture_output=True, text=True)
        lines.append(f"git: {g.stdout.strip() or g.stderr.strip()}")
    except Exception as e:
        lines.append(f"git check failed: {repr(e)}")

    try:
        iscc = subprocess.run(["where", "ISCC.exe"], capture_output=True, text=True)
        lines.append(f"ISCC lookup: {iscc.stdout.strip() or iscc.stderr.strip()}")
    except Exception as e:
        lines.append(f"ISCC lookup failed: {repr(e)}")

    # Admin check (Windows)
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        lines.append(f"Is elevated (admin): {is_admin}")
    except Exception:
        lines.append("Is elevated (admin): unknown")

    # PyInstaller exe presence
    exe_path = os.path.join(os.path.dirname(__file__), "..", "dist", "eazyconnect-client.exe")
    lines.append(f"Packaged EXE exists: {os.path.exists(exe_path)} ({exe_path})")

    # Write to output
    if not output_path:
        output_path = os.path.join(tempfile.gettempdir(), f"eazyconnect_diag_{int(time.time())}.txt")
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        print("Diagnostic report written to:", output_path)
    except Exception as e:
        print("Failed to write diagnostic report:", e)
        print("--- Report ---")
        print("\n".join(lines))


# --- Profile / i18n support -----------------------------------------------
TRANSLATIONS = {
    "en": {
        "menu_title": "User Profile",
        "menu_options": "1) View profile\n2) Edit name\n3) Edit photo path\n4) Change language\n5) Exit",
        "prompt_choice": "Choose an option:",
        "current_profile": "Current profile:",
        "name_prompt": "Enter display name:",
        "photo_prompt": "Enter path to photo (can be empty):",
        "lang_prompt": "Choose language ('en' or 'fa'):",
        "saved": "Saved.",
        "invalid": "Invalid choice.",
    },
    "fa": {
        "menu_title": "پروفایل کاربری",
        "menu_options": "1) مشاهده پروفایل\n2) ویرایش نام\n3) ویرایش مسیر عکس\n4) تغییر زبان\n5) خروج",
        "prompt_choice": "یک گزینه انتخاب کنید:",
        "current_profile": "پروفایل کنونی:",
        "name_prompt": "نام نمایشی را وارد کنید:",
        "photo_prompt": "مسیر عکس را وارد کنید (می‌تواند خالی باشد):",
        "lang_prompt": "زبان را انتخاب کنید ('en' یا 'fa'):",
        "saved": "ذخیره شد.",
        "invalid": "انتخاب نامعتبر.",
    },
}


def _get_text(key: str, lang: str):
    return TRANSLATIONS.get(lang, TRANSLATIONS["en"]).get(key, key)


def profile_menu(noninteractive: dict = None):
    """Interactive profile editor. If `noninteractive` dict provided, applies
    changes without interactive prompts.
    """
    cfg = load_config()
    profile = cfg.get("profile", {})
    lang = profile.get("language", cfg.get("language", "en")) or "en"

    def show_profile():
        print(_get_text("current_profile", lang))
        print(json.dumps(profile, indent=2, ensure_ascii=False))

    if noninteractive:
        # Apply non-interactive changes
        changed = False
        if "name" in noninteractive:
            profile["name"] = noninteractive["name"]
            changed = True
        if "photo" in noninteractive:
            profile["photo"] = noninteractive["photo"]
            changed = True
        if "language" in noninteractive:
            profile["language"] = noninteractive["language"]
            changed = True
        if changed:
            cfg["profile"] = profile
            cfg.setdefault("language", profile.get("language", lang))
            save_config(cfg)
            print(_get_text("saved", profile.get("language", lang)))
        else:
            show_profile()
        return

    while True:
        print("----", _get_text("menu_title", lang), "----")
        print(_get_text("menu_options", lang))
        ch = input(_get_text("prompt_choice", lang) + " ")
        if ch == "1":
            show_profile()
        elif ch == "2":
            v = input(_get_text("name_prompt", lang) + " ")
            profile["name"] = v
            cfg["profile"] = profile
            save_config(cfg)
            print(_get_text("saved", lang))
        elif ch == "3":
            v = input(_get_text("photo_prompt", lang) + " ")
            profile["photo"] = v
            cfg["profile"] = profile
            save_config(cfg)
            print(_get_text("saved", lang))
        elif ch == "4":
            v = input(_get_text("lang_prompt", lang) + " ")
            if v not in ("en", "fa"):
                print(_get_text("invalid", lang))
            else:
                profile["language"] = v
                cfg["profile"] = profile
                cfg["language"] = v
                save_config(cfg)
                lang = v
                print(_get_text("saved", lang))
        elif ch == "5":
            break
        else:
            print(_get_text("invalid", lang))




def sync(folder, interval=10):
    cfg = load_config()
    master = cfg.get("master")
    tok = cfg.get("token")
    verify = cfg.get("verify", True)
    seen = set()
    if not master or not tok:
        print("not configured. run login first")
        return
    print(f"syncing {folder} -> {master} every {interval}s")
    while True:
        for root, _, files in os.walk(folder):
            for f in files:
                path = os.path.join(root, f)
                if path in seen:
                    continue
                try:
                    files_d = {"file": open(path, "rb")}
                    r = requests.post(f"{master}/upload", files=files_d, headers={"x-token": tok}, timeout=30, verify=verify)
                    if r.status_code == 200:
                        print("uploaded", path)
                        seen.add(path)
                except Exception as e:
                    print("upload error", e)
        time.sleep(interval)


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd")
    l = sub.add_parser("login")
    l.add_argument("master")
    l.add_argument("username")
    l.add_argument("password")
    sub.add_parser("discover")

    u = sub.add_parser("upload")
    u.add_argument("file")

    s = sub.add_parser("sync")
    s.add_argument("folder")
    s.add_argument("--interval", type=int, default=10)

    ls = sub.add_parser("list")

    d = sub.add_parser("download")
    d.add_argument("owner")
    d.add_argument("filename")
    d.add_argument("dest")
    gp = sub.add_parser("gitpush")
    gp.add_argument("--repo", help="path to repo relative to client folder", default="..")
    gp.add_argument("--message", help="commit message", default="Auto commit from client")

    pprof = sub.add_parser("profile")
    pprof.add_argument("--set-name", dest="set_name", help="Set display name non-interactively")
    pprof.add_argument("--set-photo", dest="set_photo", help="Set photo path non-interactively")
    pprof.add_argument("--set-lang", dest="set_lang", help="Set language non-interactively ('en' or 'fa')")

    args = parser.parse_args()
    if args.cmd == "login":
        login(args.master, args.username, args.password)
    elif args.cmd == "upload":
        upload(args.file)
    elif args.cmd == "sync":
        sync(args.folder, args.interval)
    elif args.cmd == "list":
        list_files()
    elif args.cmd == "download":
        download(args.owner, args.filename, args.dest)
    elif args.cmd == "discover":
        discover()
    elif args.cmd == "gitpush":
        # optional args: repo_path, message
        repo = getattr(args, "repo", "..")
        msg = getattr(args, "message", "Auto commit from client")
        git_push(repo, msg)
    elif args.cmd in ("diag", "diagnose", "troubleshoot"):
        out = getattr(args, "out", None)
        diagnose(output_path=out)
    elif args.cmd == "profile":
        noninteractive = {}
        if getattr(args, "set_name", None):
            noninteractive["name"] = args.set_name
        if getattr(args, "set_photo", None):
            noninteractive["photo"] = args.set_photo
        if getattr(args, "set_lang", None):
            noninteractive["language"] = args.set_lang
        if noninteractive:
            profile_menu(noninteractive=noninteractive)
        else:
            profile_menu()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
