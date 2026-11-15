use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::Command;

use eazyconnect_core::{ServerTlsConfig, DEFAULT_DISCOVERY_PORT};
use eazyconnect_hw::{
    best_lan_ipv4, collect_lan_and_vpn_ipv4s_from, collect_local_endpoint_ips,
    detect_network_adapters,
};
use eazyconnect_server::{start_server, EnrollmentPolicy, ServerConfig};

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(err) = run_cli(&args).await {
        eprintln!("eazyconnect-server error: {err}");
        std::process::exit(1);
    }
}

async fn run_cli(args: &[String]) -> Result<(), String> {
    if args.first().map(String::as_str) == Some("service") {
        return handle_service_cmd(&args[1..]);
    }
    if args.iter().any(|a| a == "-h" || a == "--help") {
        print_help();
        return Ok(());
    }

    let start_idx = if args.first().map(String::as_str) == Some("run") {
        1
    } else {
        0
    };

    let mut listen_addr: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8000);
    let mut listen_explicit = false;
    let mut lan_only = false;
    let mut data_dir: PathBuf = default_server_data_dir();
    let mut keystore_dir: Option<PathBuf> = None;
    let mut tls_cert: Option<PathBuf> = None;
    let mut tls_key: Option<PathBuf> = None;
    let mut regen_tls = false;
    let mut insecure_http = false;
    let mut discovery_port: Option<u16> = Some(DEFAULT_DISCOVERY_PORT);
    let mut advertised_host: Option<String> = None;
    let mut invite_code: Option<String> = None;
    let mut bootstrap_admin_pass: Option<String> = None;

    let mut i = start_idx;
    while i < args.len() {
        match args[i].as_str() {
            "--listen" => {
                i += 1;
                let v = args.get(i).ok_or("--listen requires <ip:port>")?;
                listen_addr = v
                    .parse()
                    .map_err(|e| format!("invalid --listen '{v}': {e}"))?;
                listen_explicit = true;
            }
            "--lan-only" => {
                lan_only = true;
            }
            "--regen-tls" => {
                regen_tls = true;
            }
            "--data-dir" => {
                i += 1;
                data_dir = PathBuf::from(args.get(i).ok_or("--data-dir requires <path>")?);
            }
            "--keystore-dir" => {
                i += 1;
                keystore_dir = Some(PathBuf::from(
                    args.get(i).ok_or("--keystore-dir requires <path>")?,
                ));
            }
            "--tls-cert" => {
                i += 1;
                tls_cert = Some(PathBuf::from(
                    args.get(i).ok_or("--tls-cert requires <pem>")?,
                ));
            }
            "--tls-key" => {
                i += 1;
                tls_key = Some(PathBuf::from(
                    args.get(i).ok_or("--tls-key requires <pem>")?,
                ));
            }
            "--insecure-http" => {
                insecure_http = true;
            }
            "--no-discovery" => {
                discovery_port = None;
            }
            "--discovery-port" => {
                i += 1;
                let v = args.get(i).ok_or("--discovery-port requires <u16>")?;
                let p: u16 = v.parse().map_err(|_| format!("invalid port '{v}'"))?;
                discovery_port = if p == 0 { None } else { Some(p) };
            }
            "--advertised-host" => {
                i += 1;
                advertised_host = Some(
                    args.get(i)
                        .ok_or("--advertised-host requires <host>")?
                        .clone(),
                );
            }
            "--invite-code" => {
                i += 1;
                invite_code = Some(args.get(i).ok_or("--invite-code requires <code>")?.clone());
            }
            "--admin-pass" => {
                i += 1;
                bootstrap_admin_pass =
                    Some(args.get(i).ok_or("--admin-pass requires <password>")?.clone());
            }
            other => {
                return Err(format!("unknown argument '{other}' (try --help)"));
            }
        }
        i += 1;
    }

    if lan_only && !listen_explicit {
        let lan_ip = best_lan_ipv4()
            .ok_or_else(|| "no active non-VPN LAN IPv4 adapter found for --lan-only".to_string())?;
        let parsed_ip: IpAddr = lan_ip
            .parse()
            .map_err(|e| format!("invalid detected LAN IP '{lan_ip}': {e}"))?;
        listen_addr = SocketAddr::new(parsed_ip, listen_addr.port());
    }

    let tls = if insecure_http {
        ServerTlsConfig::InsecureDisabled
    } else if let (Some(cert_path), Some(key_path)) = (tls_cert, tls_key) {
        let cert_pem = fs::read(cert_path).map_err(|e| format!("failed to read tls cert: {e}"))?;
        let key_pem = fs::read(key_path).map_err(|e| format!("failed to read tls key: {e}"))?;
        ServerTlsConfig::PemFiles { cert_pem, key_pem }
    } else {
        let mut san_hosts = vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
            "::1".to_string(),
        ];
        if !listen_addr.ip().is_unspecified() {
            san_hosts.push(listen_addr.ip().to_string());
        }
        if lan_only {
            if let Some(lan_ip) = best_lan_ipv4() {
                san_hosts.push(lan_ip);
            }
        } else {
            san_hosts.extend(collect_local_endpoint_ips());
        }
        if let Some(ref h) = advertised_host {
            san_hosts.push(h.clone());
        }
        let tls_dir = data_dir.join("tls");
        ServerTlsConfig::LoadOrCreateSelfSigned {
            cert_path: tls_dir.join("cert.pem"),
            key_path: tls_dir.join("key.pem"),
            san_hosts,
            force_regen: regen_tls,
        }
    };

    let discovery_addr =
        discovery_port.map(|p| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), p));
    let enrollment = match invite_code {
        Some(c) => EnrollmentPolicy::InviteCode(c),
        None => EnrollmentPolicy::OpenLan,
    };
    let open_lan = matches!(enrollment, EnrollmentPolicy::OpenLan);

    let started = start_server(ServerConfig {
        listen_addr,
        data_dir: data_dir.clone(),
        keystore_dir,
        tls,
        discovery_addr,
        advertised_host,
        enrollment,
        bootstrap_admin_pass,
    })
    .await?;

    let adapters = detect_network_adapters().unwrap_or_default();
    let (lan_ips, vpn_ips) = collect_lan_and_vpn_ipv4s_from(&adapters);
    let active_vpns: Vec<String> = adapters
        .iter()
        .filter(|a| a.is_up && a.is_vpn_like)
        .map(|a| {
            if a.ipv4_addrs.is_empty() {
                a.name.clone()
            } else {
                format!("{} ({})", a.name, a.ipv4_addrs.join(", "))
            }
        })
        .collect();

    let scheme = if started.is_tls { "https" } else { "http" };
    println!(
        "EazyConnect Master Server listening on {scheme}://{}",
        started.addr
    );
    println!("  Data dir       : {}", data_dir.display());
    println!("  Master Ed25519 : {}", started.master_ed25519_pub_hex);
    if let Some(pin) = &started.tls_cert_sha256_hex {
        println!("  TLS SHA-256 Pin: {pin}");
    }
    if !lan_ips.is_empty() {
        println!("  LAN Endpoints  : {}", lan_ips.join(", "));
    }
    if !vpn_ips.is_empty() {
        println!("  VPN Endpoints  : {}", vpn_ips.join(", "));
    }
    if let Some(d_addr) = started.discovery_addr {
        println!("  UDP Discovery  : {d_addr}");
    }
    if !started.is_tls {
        eprintln!("WARNING: running in insecure HTTP mode (--insecure-http)");
    }
    if !active_vpns.is_empty() && open_lan && !lan_only {
        eprintln!(
            "WARNING: active VPN adapter(s) [{}] with OpenLan enrollment! Pass --invite-code <code> or --lan-only to prevent unauthorized remote tunnel enrollments.",
            active_vpns.join("; ")
        );
    }

    tokio::signal::ctrl_c()
        .await
        .map_err(|e| format!("ctrl-c handler error: {e}"))?;
    println!("Shutting down EazyConnect Master Server...");
    started.abort();
    Ok(())
}

fn handle_service_cmd(args: &[String]) -> Result<(), String> {
    let sub = args.first().map(String::as_str).unwrap_or("help");
    match sub {
        "install-task" => {
            let mut task_name = "EazyConnectMaster".to_string();
            let mut forward_args: Vec<String> = Vec::new();
            let mut i = 1;
            while i < args.len() {
                if args[i] == "--name" {
                    i += 1;
                    task_name = args.get(i).ok_or("--name requires <task>")?.clone();
                } else {
                    forward_args.push(args[i].clone());
                }
                i += 1;
            }
            install_windows_task(&task_name, &forward_args)
        }
        "uninstall-task" => {
            let mut task_name = "EazyConnectMaster".to_string();
            if args.get(1).map(String::as_str) == Some("--name") {
                task_name = args.get(2).ok_or("--name requires <task>")?.clone();
            }
            uninstall_windows_task(&task_name)
        }
        _ => {
            println!("Usage: eazyconnect-server service <install-task|uninstall-task> [--name <TaskName>] [server flags...]");
            Ok(())
        }
    }
}

fn install_windows_task(task_name: &str, forward_args: &[String]) -> Result<(), String> {
    if !cfg!(windows) {
        return Err("Windows Task Scheduler helper is only supported on Windows".to_string());
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let mut cmdline = format!("\"{}\"", exe.display());
    for a in forward_args {
        cmdline.push(' ');
        cmdline.push_str(a);
    }
    let status = Command::new("schtasks")
        .args([
            "/Create", "/F", "/SC", "ONSTART", "/TN", task_name, "/TR", &cmdline,
        ])
        .status()
        .map_err(|e| format!("failed to launch schtasks: {e}"))?;
    if !status.success() {
        return Err(format!("schtasks /Create failed with status {status}"));
    }
    println!("Installed Windows startup task '{task_name}' -> {cmdline}");
    Ok(())
}

fn uninstall_windows_task(task_name: &str) -> Result<(), String> {
    if !cfg!(windows) {
        return Err("Windows Task Scheduler helper is only supported on Windows".to_string());
    }
    let status = Command::new("schtasks")
        .args(["/Delete", "/F", "/TN", task_name])
        .status()
        .map_err(|e| format!("failed to launch schtasks: {e}"))?;
    if !status.success() {
        return Err(format!("schtasks /Delete failed with status {status}"));
    }
    println!("Removed Windows startup task '{task_name}'");
    Ok(())
}

fn default_server_data_dir() -> PathBuf {
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        return PathBuf::from(local).join("eazyconnect-server");
    }
    PathBuf::from("data")
}

fn print_help() {
    println!(
        "EazyConnect Master Server v{}\n\
         Usage:\n\
         \teazyconnect-server [run] [OPTIONS]\n\
         \teazyconnect-server service <install-task|uninstall-task> [--name <TaskName>] [OPTIONS]\n\
         \n\
         Options:\n\
         \t--listen <ip:port>        Bind address (default 0.0.0.0:8000)\n\
         \t--data-dir <dir>          Data directory for users/devices/files\n\
         \t--keystore-dir <dir>      OS-sealed keystore directory\n\
         \t--tls-cert <pem>          Server TLS certificate PEM\n\
         \t--tls-key <pem>           Server TLS private key PEM\n\
         \t--regen-tls               Force-regenerate persisted self-signed TLS cert & key\n\
         \t--lan-only                Bind strictly to primary non-VPN LAN IP when --listen is omitted\n\
         \t--insecure-http           Disable TLS (testing only)\n\
         \t--discovery-port <u16>    UDP discovery port (default 37020, 0 disables)\n\
         \t--no-discovery            Disable UDP discovery responder\n\
         \t--advertised-host <host>  Override host/IP inside UDP discovery beacons\n\
         \t--invite-code <code>      Require invite code for new device enrollments\n\
         \t--admin-pass <password>   Bootstrap admin password (else random in bootstrap-admin.txt)",
        env!("CARGO_PKG_VERSION")
    );
}
