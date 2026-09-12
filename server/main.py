from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, Header
from fastapi.responses import FileResponse, JSONResponse
from passlib.context import CryptContext
from typing import Optional
import uuid
import os
import json
from datetime import datetime, timedelta
import socket
import threading

APP_DIR = os.path.dirname(__file__)
DATA_DIR = os.path.join(APP_DIR, "data")
USERS_FILE = os.path.join(APP_DIR, "users.json")
TOKENS_FILE = os.path.join(APP_DIR, "tokens.json")
DISCOVERY_PORT = 37020
CERT_DIR = os.path.join(APP_DIR, "certs")
KEY_PATH = os.path.join(CERT_DIR, "key.pem")
CERT_PATH = os.path.join(CERT_DIR, "cert.pem")


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def discovery_responder(stop_event: threading.Event):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("", DISCOVERY_PORT))
    except Exception:
        return
    while not stop_event.is_set():
        try:
            data, addr = sock.recvfrom(1024)
            if not data:
                continue
            if data.startswith(b"DISCOVER_EAZYCONNECT"):
                resp = json.dumps({"host": get_local_ip(), "port": 8000}).encode("utf-8")
                sock.sendto(resp, addr)
        except Exception:
            continue
    sock.close()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI(title="EazyConnect Master Server")


def ensure_dirs():
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.exists(USERS_FILE):
        # create default admin user with password 'admin' (change after first run)
        admin_hash = pwd_context.hash("admin")
        with open(USERS_FILE, "w", encoding="utf-8") as f:
            json.dump({"admin": {"password_hash": admin_hash, "is_admin": True}}, f)
    if not os.path.exists(TOKENS_FILE):
        with open(TOKENS_FILE, "w", encoding="utf-8") as f:
            json.dump({}, f)


def load_users():
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_users(u):
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(u, f, indent=2)


def load_tokens():
    with open(TOKENS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_tokens(t):
    with open(TOKENS_FILE, "w", encoding="utf-8") as f:
        json.dump(t, f, indent=2)


def create_token(username: str, hours=24):
    tokens = load_tokens()
    tok = str(uuid.uuid4())
    tokens[tok] = {"user": username, "expires": (datetime.utcnow() + timedelta(hours=hours)).isoformat()}
    save_tokens(tokens)
    return tok


def validate_token(token: str) -> Optional[str]:
    if not token:
        return None
    tokens = load_tokens()
    info = tokens.get(token)
    if not info:
        return None
    exp = datetime.fromisoformat(info["expires"])
    if datetime.utcnow() > exp:
        # remove expired
        tokens.pop(token, None)
        save_tokens(tokens)
        return None
    return info["user"]


def get_user_obj(username: str):
    users = load_users()
    return users.get(username)


@app.on_event("startup")
def startup_event():
    ensure_dirs()
    # start discovery responder thread
    stop_event = threading.Event()
    t = threading.Thread(target=discovery_responder, args=(stop_event,), daemon=True)
    t.start()
    # store stop_event in app state so it can be stopped later if needed
    app.state.discovery_stop = stop_event


@app.post("/auth")
def auth(username: str, password: str):
    users = load_users()
    u = users.get(username)
    if not u:
        raise HTTPException(status_code=401, detail="invalid credentials")
    if not pwd_context.verify(password, u["password_hash"]):
        raise HTTPException(status_code=401, detail="invalid credentials")
    token = create_token(username)
    return {"token": token}


def require_user(x_token: Optional[str] = Header(None)):
    user = validate_token(x_token)
    if not user:
        raise HTTPException(status_code=401, detail="invalid or expired token")
    return user


@app.post("/create_user")
def create_user(new_username: str, new_password: str, is_admin: bool = False, x_token: Optional[str] = Header(None)):
    requester = validate_token(x_token)
    if not requester:
        raise HTTPException(status_code=401, detail="invalid token")
    req_obj = get_user_obj(requester)
    if not req_obj or not req_obj.get("is_admin"):
        raise HTTPException(status_code=403, detail="admin required")
    users = load_users()
    if new_username in users:
        raise HTTPException(status_code=400, detail="user exists")
    users[new_username] = {"password_hash": pwd_context.hash(new_password), "is_admin": is_admin}
    save_users(users)
    os.makedirs(os.path.join(DATA_DIR, new_username), exist_ok=True)
    return {"ok": True}


@app.post("/upload")
async def upload(x_token: Optional[str] = Header(None), file: UploadFile = File(...)):
    user = require_user(x_token)
    safe_user = os.path.basename(user)
    user_dir = os.path.join(DATA_DIR, safe_user)
    os.makedirs(user_dir, exist_ok=True)
    safe_filename = os.path.basename(file.filename)
    if not safe_filename:
        raise HTTPException(status_code=400, detail="invalid filename")
    dest = os.path.join(user_dir, safe_filename)
    with open(dest, "wb") as f:
        contents = await file.read()
        f.write(contents)
    return {"ok": True, "path": dest}


@app.get("/list")
def list_files(x_token: Optional[str] = Header(None)):
    user = require_user(x_token)
    safe_user = os.path.basename(user)
    user_dir = os.path.join(DATA_DIR, safe_user)
    if not os.path.exists(user_dir):
        return {"files": []}
    files = os.listdir(user_dir)
    return {"files": files}


@app.get("/download/{owner}/{filename}")
def download(owner: str, filename: str, x_token: Optional[str] = Header(None)):
    requester = require_user(x_token)
    safe_owner = os.path.basename(owner)
    safe_filename = os.path.basename(filename)
    if not safe_owner or not safe_filename:
        raise HTTPException(status_code=400, detail="invalid path")

    if requester != safe_owner:
        req_obj = get_user_obj(requester)
        if not req_obj or not req_obj.get("is_admin"):
            raise HTTPException(status_code=403, detail="not allowed")
    path = os.path.join(DATA_DIR, safe_owner, safe_filename)
    if not os.path.exists(path) or not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="not found")
    return FileResponse(path, filename=safe_filename)


@app.post("/report")
def report(payload: dict, x_token: Optional[str] = Header(None)):
    user = require_user(x_token)
    log_dir = os.path.join(DATA_DIR, "_reports")
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, f"{user}.log")
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(f"{datetime.utcnow().isoformat()} - {json.dumps(payload, ensure_ascii=False)}\n")
    return {"ok": True}


if __name__ == "__main__":
    import uvicorn
    # if certs exist, run with TLS
    if os.path.exists(KEY_PATH) and os.path.exists(CERT_PATH):
        uvicorn.run("main:app", host="0.0.0.0", port=8000, ssl_certfile=CERT_PATH, ssl_keyfile=KEY_PATH)
    else:
        uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
