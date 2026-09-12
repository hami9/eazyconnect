# EazyConnect — LAN File Sharing & Messaging System

A lightweight, secure LAN-based file sharing, folder synchronization, and messaging platform designed for local Windows networks with auto-discovery and zero cloud dependencies.

---

## 🌟 Features
- **LAN Auto-Discovery:** Automatic discovery of the master server via UDP broadcast (`port 37020`) — no need to memorize IP addresses.
- **FastAPI Master Server:** Fast, token-authenticated REST API with role-based access control.
- **TLS / HTTPS:** Built-in self-signed certificate generation with automated Windows certificate installation.
- **CLI & GUI Clients:** Modern Tkinter desktop GUI alongside an automated CLI for continuous folder synchronization.
- **Windows Packaging:** Automated build scripts with PyInstaller and Inno Setup installer wizard.

---

## 🚀 Quick Start (Python 3.10+)

### 1. Master Server Setup

On the master PC:
```powershell
python -m pip install -r server\requirements.txt
python server\main.py
```
Server runs on port `8000` by default.

#### TLS / HTTPS Setup (Recommended)
To enable TLS encryption, generate the certificate on the master PC:
```powershell
python server\generate_selfsigned.py
python server\main.py
```
The server will automatically detect `server\certs\key.pem` and `server\certs\cert.pem` and run over HTTPS.

---

### 2. Client Setup

On client PCs:
```powershell
python -m pip install -r client\requirements.txt
```

#### Run Desktop GUI
```powershell
python client\gui_main.py
```

#### CLI Commands
```powershell
# Auto-discover master server on LAN
python client\client.py discover

# Login to master server
python client\client.py login https://<MASTER_IP>:8000 username password

# Upload a file
python client\client.py upload path\to\file.txt

# Download a file
python client\client.py download <owner> <filename> <dest_path>

# Continuously sync a folder (e.g. every 15 seconds)
python client\client.py sync C:\Users\User\EazySync --interval 15

# Run client environment diagnostics
python client\client.py diag
```

---

## 📦 Windows Packaging & Installer

1. **Build Single-File Executable:**
   ```powershell
   cd client
   make_windows_exe.bat
   ```

2. **Trust Self-Signed Certificate on Client:**
   ```powershell
   powershell -ExecutionPolicy Bypass -File client\install_cert_windows.ps1 -CertPath .\cert.pem
   ```

3. **Build Inno Setup Installer:**
   ```powershell
   cd client
   build_installer.bat
   ```

---

## 🇮🇷 راهنمای فارسی (Persian Quick Guide)

پروژه **EazyConnect** برای ارتباط، اشتراک فایل و همگام‌سازی پوشه‌ها در بستر شبکه محلی (بدون نیاز به اینترنت) طراحی شده است.

- **کشف خودکار سرور:** کلاینت‌ها بدون نیاز به دانستن IP سرور می‌توانند با دستور `python client\client.py discover` یا از طریق رابط گرافیکی سرور را در شبکه پیدا کنند.
- **همگام‌سازی لحظه‌ای:** پوشه مشخص‌شده به صورت خودکار تغییرات را با سرور همگام می‌کند.
- **رابط کاربری دسکتاپ:** برای اجرای نسخه گرافیکی دستور `python client\gui_main.py` را اجرا کنید.
