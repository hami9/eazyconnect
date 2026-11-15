use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use eazyconnect_client::{
    default_sync_manifest_path, run_diagnostics, sync_folder_to_master, EazyNode, MasterHttpClient,
    NodeConnectOptions, NodeEvent,
};
use eazyconnect_core::{
    decrypt_file_from_vault, discover_masters, encrypt_file_for_vault, load_client_config,
    parse_sha256_pin_hex, profile_heading, save_client_config, ClientConfig, ClientTlsConfig,
    CreateUserRequest, EazyAppMessage, EazyMeshProfile, DEFAULT_DISCOVERY_PORT,
};
use eazyconnect_hw::{
    collect_hardware_report, enumerate_serial_ports, hostname, seal_local_secret,
    send_serial_command, unseal_local_secret, DeviceIdentity, OsSerialTransport,
};
use tokio::io::{AsyncBufReadExt, BufReader};

struct GlobalOpts {
    config_path: Option<PathBuf>,
    master: Option<String>,
    tls_pin: Option<String>,
    tls_ca: Option<PathBuf>,
    insecure_http: bool,
    client_id: Option<String>,
    keystore_dir: Option<PathBuf>,
    rest: Vec<String>,
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") && args.len() == 1 {
        print_help();
        return;
    }

    let opts = match parse_global_opts(&args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("argument error: {e}");
            std::process::exit(2);
        }
    };

    if let Err(e) = dispatch(opts).await {
        eprintln!("eazyconnect error: {e}");
        std::process::exit(1);
    }
}

fn parse_global_opts(args: &[String]) -> Result<GlobalOpts, String> {
    let mut config_path = None;
    let mut master = None;
    let mut tls_pin = None;
    let mut tls_ca = None;
    let mut insecure_http = false;
    let mut client_id = None;
    let mut keystore_dir = None;
    let mut rest = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => {
                i += 1;
                config_path = Some(PathBuf::from(args.get(i).ok_or("--config requires <path>")?));
            }
            "--master" => {
                i += 1;
                master = Some(args.get(i).ok_or("--master requires <url>")?.clone());
            }
            "--tls-pin" => {
                i += 1;
                tls_pin = Some(args.get(i).ok_or("--tls-pin requires <sha256>")?.clone());
            }
            "--tls-ca" => {
                i += 1;
                tls_ca = Some(PathBuf::from(args.get(i).ok_or("--tls-ca requires <pem>")?));
            }
            "--insecure-http" => {
                insecure_http = true;
            }
            "--client-id" => {
                i += 1;
                client_id = Some(args.get(i).ok_or("--client-id requires <id>")?.clone());
            }
            "--keystore-dir" => {
                i += 1;
                keystore_dir = Some(PathBuf::from(
                    args.get(i).ok_or("--keystore-dir requires <dir>")?,
                ));
            }
            other => {
                rest.push(other.to_string());
            }
        }
        i += 1;
    }

    Ok(GlobalOpts {
        config_path,
        master,
        tls_pin,
        tls_ca,
        insecure_http,
        client_id,
        keystore_dir,
        rest,
    })
}

async fn dispatch(opts: GlobalOpts) -> Result<(), String> {
    let sub = opts.rest.first().map(String::as_str).unwrap_or("help");
    let sub_args = opts.rest.get(1..).unwrap_or(&[]);

    match sub {
        "help" | "-h" | "--help" => {
            print_help();
            Ok(())
        }
        "discover" => cmd_discover(sub_args).await,
        "enroll" => cmd_enroll(&opts, sub_args).await,
        "login" => cmd_login(&opts, sub_args).await,
        "create-user" => cmd_create_user(&opts, sub_args).await,
        "upload" => cmd_upload(&opts, sub_args).await,
        "list" => cmd_list(&opts, sub_args).await,
        "download" => cmd_download(&opts, sub_args).await,
        "sync" => cmd_sync(&opts, sub_args).await,
        "chat" => cmd_chat(&opts, sub_args).await,
        "hw" => cmd_hw(&opts, sub_args).await,
        "profile" => cmd_profile(&opts, sub_args),
        "diag" => cmd_diag(&opts, sub_args).await,
        "service" => cmd_service(sub_args),
        other => Err(format!("unknown subcommand '{other}' (try --help)")),
    }
}

async fn cmd_discover(args: &[String]) -> Result<(), String> {
    let mut target = format!("255.255.255.255:{DEFAULT_DISCOVERY_PORT}");
    let mut timeout_ms: u64 = 1500;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--target" => {
                i += 1;
                target = args.get(i).ok_or("--target requires <ip:port>")?.clone();
            }
            "--timeout-ms" => {
                i += 1;
                let v = args.get(i).ok_or("--timeout-ms requires <ms>")?;
                timeout_ms = v.parse().map_err(|_| "invalid --timeout-ms")?;
            }
            other => return Err(format!("unknown discover option '{other}'")),
        }
        i += 1;
    }

    let target_sock: std::net::SocketAddr = target
        .parse()
        .map_err(|e| format!("invalid discovery target '{target}': {e}"))?;
    let found = discover_masters(target_sock, Duration::from_millis(timeout_ms)).await?;
    if found.is_empty() {
        println!("No EazyConnect Masters discovered on {target}.");
    } else {
        for m in found {
            println!(
                "{} | source={} | sig_valid={} | tls_pin={} | master_ed25519={}",
                m.url,
                m.source_ip,
                m.signature_valid,
                m.tls_cert_sha256_hex.as_deref().unwrap_or("<none>"),
                m.master_ed25519_pub_hex
            );
            if !m.alternate_urls.is_empty() {
                println!("  alternates: {}", m.alternate_urls.join(", "));
            }
        }
    }
    Ok(())
}

async fn cmd_enroll(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let mut invite_code: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--invite-code" => {
                i += 1;
                invite_code = Some(args.get(i).ok_or("--invite-code requires <code>")?.clone());
            }
            other => return Err(format!("unknown enroll option '{other}'")),
        }
        i += 1;
    }

    let mut cfg = load_client_config(opts.config_path.as_deref())?;
    let (client, resolved_url) = build_http_client(opts, &cfg)?;
    let cid = resolve_client_id(opts, &cfg);
    let identity = DeviceIdentity::load_or_create(&cid, opts.keystore_dir.as_deref(), None)?;

    let tok = client
        .enroll_device(&identity, invite_code.as_deref())
        .await?;
    cfg.master = Some(resolved_url.clone());
    cfg.client_id = Some(cid.clone());
    cfg.role = Some(tok.role.clone());
    if let Some(pin) = opts.tls_pin.clone() {
        cfg.tls_pin_hex = Some(pin);
    }
    if let Some(ca) = opts.tls_ca.as_ref() {
        cfg.tls_ca_pem_path = Some(ca.display().to_string());
    }
    cfg.verify = !opts.insecure_http;
    cfg.set_token(&cid, &tok.token)?;
    let saved_path = save_client_config(&cfg, opts.config_path.as_deref())?;

    println!(
        "Enrolled device '{}' ({}) on {} [role={}, config={}]",
        cid,
        identity.backend_label(),
        resolved_url,
        tok.role,
        saved_path.display()
    );
    Ok(())
}

async fn cmd_login(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    if args.len() < 2 {
        return Err("usage: eazyconnect-client login <username> <password>".to_string());
    }
    let username = &args[0];
    let password = &args[1];

    let mut cfg = load_client_config(opts.config_path.as_deref())?;
    let (client, resolved_url) = build_http_client(opts, &cfg)?;
    let cid = resolve_client_id(opts, &cfg);

    let tok = client.login_password(username, password).await?;
    cfg.master = Some(resolved_url.clone());
    cfg.client_id = Some(cid.clone());
    cfg.username = Some(username.clone());
    cfg.role = Some(tok.role.clone());
    if let Some(pin) = opts.tls_pin.clone() {
        cfg.tls_pin_hex = Some(pin);
    }
    cfg.verify = !opts.insecure_http;
    cfg.set_token(&cid, &tok.token)?;
    let saved_path = save_client_config(&cfg, opts.config_path.as_deref())?;

    println!(
        "Logged in as '{}' [role={}] on {} (DPAPI token saved to {})",
        username,
        tok.role,
        resolved_url,
        saved_path.display()
    );
    Ok(())
}

async fn cmd_create_user(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    if args.len() < 2 {
        return Err(
            "usage: eazyconnect-client create-user <username> <password> [--admin]".to_string(),
        );
    }
    let username = args[0].clone();
    let password = args[1].clone();
    let is_admin = args.get(2).is_some_and(|a| a == "--admin");

    let cfg = load_client_config(opts.config_path.as_deref())?;
    let (client, _) = build_http_client(opts, &cfg)?;
    let token = load_bearer_from_cfg(opts, &cfg)?;
    client
        .create_user(
            &token,
            &CreateUserRequest {
                username: username.clone(),
                password,
                is_admin,
            },
        )
        .await?;
    println!("Created user '{}' (admin={})", username, is_admin);
    Ok(())
}

async fn cmd_upload(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let local = args
        .first()
        .ok_or("usage: eazyconnect-client upload <file> [--remote <path>] [--e2e] [--vault-key-hex <hex>]")?;
    let mut remote: Option<String> = None;
    let mut e2e = false;
    let mut vault_hex: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--remote" => {
                i += 1;
                remote = Some(args.get(i).ok_or("--remote requires <path>")?.clone());
            }
            "--e2e" => e2e = true,
            "--vault-key-hex" => {
                i += 1;
                vault_hex = Some(args.get(i).ok_or("--vault-key-hex requires <64hex>")?.clone());
            }
            other => return Err(format!("unknown upload option '{other}'")),
        }
        i += 1;
    }

    let local_path = Path::new(local);
    let rel_name = remote.unwrap_or_else(|| {
        local_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("upload.bin")
            .to_string()
    });
    let plain = fs::read(local_path)
        .map_err(|e| format!("failed to read {}: {e}", local_path.display()))?;

    let cfg = load_client_config(opts.config_path.as_deref())?;
    let (client, _) = build_http_client(opts, &cfg)?;
    let token = load_bearer_from_cfg(opts, &cfg)?;

    let body = if e2e {
        let cid = resolve_client_id(opts, &cfg);
        let identity = DeviceIdentity::load_or_create(&cid, opts.keystore_dir.as_deref(), None)?;
        let vkey = load_or_create_vault_key(opts, &cid, vault_hex.as_deref())?;
        encrypt_file_for_vault(identity.hardware_provider(), &vkey, &rel_name, &plain)?
    } else {
        plain
    };

    let entry = client.upload_bytes(&token, &rel_name, &body, e2e).await?;
    println!(
        "Uploaded {} ({} bytes, blake3={}, e2e={})",
        entry.filename, entry.size_bytes, entry.blake3_hex, entry.e2e_encrypted
    );
    Ok(())
}

async fn cmd_list(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let mut owner = None;
    if args.first().map(String::as_str) == Some("--owner") {
        owner = args.get(1).cloned();
    }
    let cfg = load_client_config(opts.config_path.as_deref())?;
    let (client, _) = build_http_client(opts, &cfg)?;
    let token = load_bearer_from_cfg(opts, &cfg)?;
    let list = client.list_files(&token, owner.as_deref()).await?;
    println!("Files for owner '{}':", list.owner);
    for f in list.files {
        println!(
            "  {} | {} bytes | blake3={} | e2e={}",
            f.filename, f.size_bytes, f.blake3_hex, f.e2e_encrypted
        );
    }
    Ok(())
}

async fn cmd_download(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    if args.len() < 2 {
        return Err(
            "usage: eazyconnect-client download <remote_path> <dest_file> [--owner <id>] [--e2e] [--vault-key-hex <hex>]".to_string(),
        );
    }
    let remote = &args[0];
    let dest = Path::new(&args[1]);
    let mut owner_override = None;
    let mut force_e2e = false;
    let mut vault_hex = None;

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--owner" => {
                i += 1;
                owner_override = Some(args.get(i).ok_or("--owner requires <id>")?.clone());
            }
            "--e2e" => force_e2e = true,
            "--vault-key-hex" => {
                i += 1;
                vault_hex = Some(args.get(i).ok_or("--vault-key-hex requires <64hex>")?.clone());
            }
            other => return Err(format!("unknown download option '{other}'")),
        }
        i += 1;
    }

    let cfg = load_client_config(opts.config_path.as_deref())?;
    let (client, _) = build_http_client(opts, &cfg)?;
    let token = load_bearer_from_cfg(opts, &cfg)?;
    let cid = resolve_client_id(opts, &cfg);
    let owner = owner_override
        .or_else(|| cfg.username.clone())
        .unwrap_or_else(|| cid.clone());

    let (raw, _hash, server_e2e) = client.download_bytes(&token, &owner, remote).await?;
    let final_bytes = if force_e2e || server_e2e {
        let identity = DeviceIdentity::load_or_create(&cid, opts.keystore_dir.as_deref(), None)?;
        let vkey = load_or_create_vault_key(opts, &cid, vault_hex.as_deref())?;
        decrypt_file_from_vault(identity.hardware_provider(), &vkey, remote, &raw)?
    } else {
        raw
    };

    if let Some(parent) = dest.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
    }
    fs::write(dest, &final_bytes)
        .map_err(|e| format!("failed to write {}: {e}", dest.display()))?;
    println!(
        "Downloaded '{}' -> {} ({} bytes, e2e={})",
        remote,
        dest.display(),
        final_bytes.len(),
        force_e2e || server_e2e
    );
    Ok(())
}

async fn cmd_sync(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let folder = args
        .first()
        .ok_or("usage: eazyconnect-client sync <folder> [--manifest <path>] [--e2e] [--vault-key-hex <hex>]")?;
    let mut manifest_path = default_sync_manifest_path(opts.config_path.as_deref());
    let mut e2e = false;
    let mut vault_hex = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--manifest" => {
                i += 1;
                manifest_path = PathBuf::from(args.get(i).ok_or("--manifest requires <path>")?);
            }
            "--e2e" => e2e = true,
            "--vault-key-hex" => {
                i += 1;
                vault_hex = Some(args.get(i).ok_or("--vault-key-hex requires <64hex>")?.clone());
            }
            other => return Err(format!("unknown sync option '{other}'")),
        }
        i += 1;
    }

    let cfg = load_client_config(opts.config_path.as_deref())?;
    let (client, _) = build_http_client(opts, &cfg)?;
    let token = load_bearer_from_cfg(opts, &cfg)?;
    let cid = resolve_client_id(opts, &cfg);

    let summary = if e2e {
        let identity = DeviceIdentity::load_or_create(&cid, opts.keystore_dir.as_deref(), None)?;
        let vkey = load_or_create_vault_key(opts, &cid, vault_hex.as_deref())?;
        sync_folder_to_master(
            &client,
            &token,
            Path::new(folder),
            &manifest_path,
            Some((identity.hardware_provider(), &vkey)),
        )
        .await?
    } else {
        sync_folder_to_master(&client, &token, Path::new(folder), &manifest_path, None).await?
    };

    println!(
        "Sync complete: folder={} | uploaded={} | tracked={} | e2e={}",
        summary.scanned_folder,
        summary.uploaded_count,
        summary.total_manifest_entries,
        summary.e2e_encrypted
    );
    Ok(())
}

async fn cmd_chat(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let mut peer: Option<String> = None;
    let mut profile = EazyMeshProfile::Standard;
    let mut psk = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--peer" => {
                i += 1;
                peer = Some(args.get(i).ok_or("--peer requires <client_id>")?.clone());
            }
            "--profile" => {
                i += 1;
                profile = EazyMeshProfile::from_name(args.get(i).ok_or("--profile requires name")?);
            }
            "--psk" => {
                i += 1;
                psk = args.get(i).ok_or("--psk requires <secret>")?.as_bytes().to_vec();
            }
            "--listen" => {}
            other => return Err(format!("unknown chat option '{other}'")),
        }
        i += 1;
    }

    let cfg = load_client_config(opts.config_path.as_deref())?;
    let (master_url, tls_config) = resolve_url_and_tls(opts, &cfg)?;
    let cid = resolve_client_id(opts, &cfg);
    let identity = DeviceIdentity::load_or_create(&cid, opts.keystore_dir.as_deref(), None)?;

    let node = EazyNode::connect(
        identity,
        NodeConnectOptions {
            ws_url: master_url.clone(),
            tls_config,
            allow_insecure_ws: opts.insecure_http,
            allow_remote_serial_os_fallback: false,
            allow_remote_hw_probe: true,
            auto_reconnect: true,
        },
    )
    .await?;

    let mut rx = node.subscribe();
    let psk_for_accept = psk.clone();
    let mut active_peer = peer.clone();

    if let Some(ref target_peer) = peer {
        let pair_id = node.send_pair_offer(target_peer, profile, &psk).await?;
        println!("Sent CubeHash PairOffer ({pair_id}) to '{target_peer}'...");
    } else {
        println!("Connected as '{}' to {master_url}; waiting for peer PairOffer...", node.client_id());
    }

    let mut stdin_lines = BufReader::new(tokio::io::stdin()).lines();
    println!("Commands: /hop, /hwprobe, /quit, or type a message to send.");

    loop {
        tokio::select! {
            ev = rx.recv() => {
                match ev {
                    Ok(NodeEvent::IncomingPairOffer { pair_id, from, .. }) => {
                        let accept = node.accept_pair_offer(&pair_id, &psk_for_accept).await?;
                        active_peer = Some(from.clone());
                        println!("[paired with {} | safety={}]", accept.peer, accept.safety_fingerprint);
                    }
                    Ok(NodeEvent::Paired { peer: p, safety_fingerprint, epoch }) => {
                        active_peer = Some(p.clone());
                        println!("[paired with {p} | safety={safety_fingerprint} | epoch={epoch}]");
                    }
                    Ok(NodeEvent::MessageReceived { from, msg, healed_bits, epoch, .. }) => {
                        match msg {
                            EazyAppMessage::ChatText { text } => {
                                println!("[{from} @e{epoch} healed={healed_bits}b] {text}");
                            }
                            EazyAppMessage::FileShared { filename, blake3_hex, size_bytes, e2e, .. } => {
                                println!("[file notice from {from}] {filename} ({size_bytes}B, blake3={blake3_hex}, e2e={e2e})");
                            }
                            EazyAppMessage::SerialData { port, data } => {
                                println!("[serial {port} from {from}] {}", String::from_utf8_lossy(&data));
                            }
                            EazyAppMessage::HardwareProbeResponse { report } => {
                                println!(
                                    "[hwprobe from {from}] host={} tpm={} adapters={}",
                                    report.hostname,
                                    report.tpm2_cng_available,
                                    report.network_adapters.len()
                                );
                            }
                            other => println!("[app msg from {from}] {other:?}"),
                        }
                    }
                    Ok(NodeEvent::HoneyDecoyTriggered { from, plausible_preview, .. }) => {
                        println!("[honey zero-oracle from {from}] {plausible_preview}");
                    }
                    Ok(NodeEvent::EpochHopped { peer: p, new_epoch }) => {
                        println!("[epoch hopped with {p} -> {new_epoch}]");
                    }
                    Ok(NodeEvent::RelayError { code, detail, .. }) => {
                        eprintln!("[relay error {code}] {detail}");
                    }
                    Ok(NodeEvent::Reconnecting { reason, attempt }) => {
                        eprintln!("[reconnecting #{attempt}] {reason}");
                    }
                    Ok(NodeEvent::Reconnected) => {
                        println!("[reconnected; E2E CubeHash sessions preserved]");
                    }
                    Ok(NodeEvent::Disconnected { reason }) => {
                        eprintln!("[disconnected] {reason}");
                        break;
                    }
                    _ => {}
                }
            }
            line = stdin_lines.next_line() => {
                match line {
                    Ok(Some(txt)) => {
                        let trimmed = txt.trim();
                        if trimmed == "/quit" {
                            break;
                        }
                        let Some(ref target) = active_peer else {
                            println!("Not paired with a peer yet.");
                            continue;
                        };
                        if trimmed == "/hop" {
                            let e = node.hop_epoch(target).await?;
                            println!("[local initiated epoch hop -> {e}]");
                        } else if trimmed == "/hwprobe" {
                            node.request_remote_hardware_probe(target).await?;
                        } else if !trimmed.is_empty() {
                            node.send_chat_message(target, trimmed).await?;
                        }
                    }
                    Ok(None) | Err(_) => break,
                }
            }
        }
    }

    node.shutdown().await;
    Ok(())
}

async fn cmd_hw(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let sub = args.first().map(String::as_str).unwrap_or("list");
    match sub {
        "list" => {
            let report = collect_hardware_report();
            println!("{}", serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?);
            Ok(())
        }
        "serial" => {
            let act = args.get(1).map(String::as_str).unwrap_or("list");
            match act {
                "list" => {
                    for p in enumerate_serial_ports()? {
                        println!("{} | {} | {:?}", p.port_name, p.transport_kind, p.product);
                    }
                    Ok(())
                }
                "send" => {
                    if args.len() < 5 {
                        return Err("usage: eazyconnect-client hw serial send <port> <baud> <payload> [--hex] [--timeout-ms 500]".to_string());
                    }
                    let port = &args[2];
                    let baud: u32 = args[3].parse().map_err(|_| "invalid baud rate")?;
                    let use_hex = args.iter().any(|a| a == "--hex");
                    let payload = if use_hex {
                        hex::decode(&args[4]).map_err(|e| format!("invalid hex payload: {e}"))?
                    } else {
                        args[4].as_bytes().to_vec()
                    };
                    let mut timeout_ms = 500u64;
                    if let Some(pos) = args.iter().position(|a| a == "--timeout-ms") {
                        if let Some(v) = args.get(pos + 1) {
                            timeout_ms = v.parse().map_err(|_| "invalid --timeout-ms")?;
                        }
                    }
                    let reply = send_serial_command(port, baud, &payload, timeout_ms)?;
                    println!(
                        "Serial reply ({} bytes): hex={} utf8={}",
                        reply.len(),
                        hex::encode(&reply),
                        String::from_utf8_lossy(&reply)
                    );
                    Ok(())
                }
                "bridge" => {
                    let mut port: Option<String> = None;
                    let mut baud: u32 = 9600;
                    let mut psk = Vec::new();
                    let mut i = 2;
                    while i < args.len() {
                        match args[i].as_str() {
                            "--port" => {
                                i += 1;
                                port = Some(args.get(i).ok_or("--port requires <COMx>")?.clone());
                            }
                            "--baud" => {
                                i += 1;
                                baud = args.get(i).ok_or("--baud requires <u32>")?.parse().map_err(|_| "invalid baud")?;
                            }
                            "--psk" => {
                                i += 1;
                                psk = args.get(i).ok_or("--psk requires <secret>")?.as_bytes().to_vec();
                            }
                            other => return Err(format!("unknown serial bridge option '{other}'")),
                        }
                        i += 1;
                    }
                    let port_name = port.ok_or("--port is required")?;
                    let transport = OsSerialTransport::open(&port_name, baud, 300)?;
                    let cfg = load_client_config(opts.config_path.as_deref())?;
                    let (master_url, tls_config) = resolve_url_and_tls(opts, &cfg)?;
                    let cid = resolve_client_id(opts, &cfg);
                    let identity = DeviceIdentity::load_or_create(&cid, opts.keystore_dir.as_deref(), None)?;

                    let node = EazyNode::connect(
                        identity,
                        NodeConnectOptions {
                            ws_url: master_url.clone(),
                            tls_config,
                            allow_insecure_ws: opts.insecure_http,
                            allow_remote_serial_os_fallback: false,
                            allow_remote_hw_probe: true,
                            auto_reconnect: true,
                        },
                    )
                    .await?;
                    node.attach_serial_transport(&port_name, Box::new(transport))?;
                    println!("Encrypted Serial Bridge '{}' ({baud} baud) online as '{}'", port_name, node.client_id());

                    let mut rx = node.subscribe();
                    loop {
                        tokio::select! {
                            _ = tokio::signal::ctrl_c() => break,
                            ev = rx.recv() => {
                                if let Ok(NodeEvent::IncomingPairOffer { pair_id, from, .. }) = ev {
                                    let _ = node.accept_pair_offer(&pair_id, &psk).await;
                                    println!("Serial Bridge paired with '{from}'");
                                }
                            }
                        }
                    }
                    node.shutdown().await;
                    Ok(())
                }
                other => Err(format!("unknown hw serial action '{other}'")),
            }
        }
        other => Err(format!("unknown hw subcommand '{other}'")),
    }
}

fn cmd_profile(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let act = args.first().map(String::as_str).unwrap_or("show");
    let mut cfg = load_client_config(opts.config_path.as_deref())?;
    match act {
        "show" => {
            println!("{}", profile_heading(&cfg.profile.language));
            println!(
                "  name={} | language={} | master={} | client_id={}",
                cfg.profile.name,
                cfg.profile.language,
                cfg.master.as_deref().unwrap_or("<unset>"),
                cfg.client_id.as_deref().unwrap_or("<unset>")
            );
            Ok(())
        }
        "set" => {
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--name" => {
                        i += 1;
                        cfg.profile.name = args.get(i).ok_or("--name requires <name>")?.clone();
                    }
                    "--lang" => {
                        i += 1;
                        let lang = args.get(i).ok_or("--lang requires en|fa")?;
                        if lang != "en" && lang != "fa" {
                            return Err("language must be 'en' or 'fa'".to_string());
                        }
                        cfg.profile.language = lang.clone();
                    }
                    other => return Err(format!("unknown profile set flag '{other}'")),
                }
                i += 1;
            }
            let p = save_client_config(&cfg, opts.config_path.as_deref())?;
            println!("Saved profile ({}) to {}", profile_heading(&cfg.profile.language), p.display());
            Ok(())
        }
        other => Err(format!("unknown profile action '{other}'")),
    }
}

async fn cmd_diag(opts: &GlobalOpts, args: &[String]) -> Result<(), String> {
    let upload = args.iter().any(|a| a == "--upload");
    let cfg = load_client_config(opts.config_path.as_deref())?;
    let probe_client = build_http_client(opts, &cfg).ok().map(|(c, _)| c);
    let report = run_diagnostics(
        opts.config_path.as_deref(),
        opts.master.as_deref(),
        Duration::from_millis(1200),
        probe_client.as_ref(),
    )
    .await?;

    let val = serde_json::to_value(&report).map_err(|e| e.to_string())?;
    println!(
        "{}",
        serde_json::to_string_pretty(&val).map_err(|e| e.to_string())?
    );

    if upload {
        let (client, _) = build_http_client(opts, &cfg)?;
        let token = load_bearer_from_cfg(opts, &cfg)?;
        let saved = client.send_report(&token, &val).await?;
        println!("Uploaded diagnostic report -> {saved}");
    }
    Ok(())
}

fn cmd_service(args: &[String]) -> Result<(), String> {
    if !cfg!(windows) {
        return Err("Windows scheduled task helper is only available on Windows".to_string());
    }
    let act = args.first().map(String::as_str).unwrap_or("help");
    match act {
        "install-task" => {
            let mut task_name = "EazyConnectClient".to_string();
            let mut forward = Vec::new();
            let mut i = 1;
            while i < args.len() {
                if args[i] == "--name" {
                    i += 1;
                    task_name = args.get(i).ok_or("--name requires <task>")?.clone();
                } else {
                    forward.push(args[i].clone());
                }
                i += 1;
            }
            let exe = std::env::current_exe().map_err(|e| e.to_string())?;
            let mut cmdline = format!("\"{}\"", exe.display());
            for a in forward {
                cmdline.push(' ');
                cmdline.push_str(&a);
            }
            let status = Command::new("schtasks")
                .args(["/Create", "/F", "/SC", "ONLOGON", "/TN", &task_name, "/TR", &cmdline])
                .status()
                .map_err(|e| e.to_string())?;
            if !status.success() {
                return Err(format!("schtasks /Create failed: {status}"));
            }
            println!("Installed Windows logon task '{task_name}'");
            Ok(())
        }
        "uninstall-task" => {
            let task_name = if args.get(1).map(String::as_str) == Some("--name") {
                args.get(2).ok_or("--name requires <task>")?.as_str()
            } else {
                "EazyConnectClient"
            };
            let status = Command::new("schtasks")
                .args(["/Delete", "/F", "/TN", task_name])
                .status()
                .map_err(|e| e.to_string())?;
            if !status.success() {
                return Err(format!("schtasks /Delete failed: {status}"));
            }
            println!("Removed Windows task '{task_name}'");
            Ok(())
        }
        _ => {
            println!("Usage: eazyconnect-client service <install-task|uninstall-task> [--name <TaskName>]");
            Ok(())
        }
    }
}

fn resolve_client_id(opts: &GlobalOpts, cfg: &ClientConfig) -> String {
    opts.client_id
        .clone()
        .or_else(|| cfg.client_id.clone())
        .unwrap_or_else(hostname)
}

fn resolve_url_and_tls(
    opts: &GlobalOpts,
    cfg: &ClientConfig,
) -> Result<(String, ClientTlsConfig), String> {
    let url = opts
        .master
        .clone()
        .or_else(|| cfg.master.clone())
        .ok_or_else(|| "no master URL configured (pass --master or run enroll/login first)".to_string())?;

    let tls = if let Some(pin_hex) = opts.tls_pin.as_ref().or(cfg.tls_pin_hex.as_ref()) {
        ClientTlsConfig::PinnedCertSha256(parse_sha256_pin_hex(pin_hex)?)
    } else if let Some(ref ca_path) = opts
        .tls_ca
        .clone()
        .or_else(|| cfg.tls_ca_pem_path.as_ref().map(PathBuf::from))
    {
        let pem = fs::read(ca_path)
            .map_err(|e| format!("failed to read --tls-ca {}: {e}", ca_path.display()))?;
        ClientTlsConfig::CaPem(pem)
    } else {
        ClientTlsConfig::WebPkiRoots
    };

    Ok((url, tls))
}

fn build_http_client(
    opts: &GlobalOpts,
    cfg: &ClientConfig,
) -> Result<(MasterHttpClient, String), String> {
    let (url, tls) = resolve_url_and_tls(opts, cfg)?;
    let client = MasterHttpClient::new(&url, tls, opts.insecure_http)?;
    Ok((client, url))
}

fn load_bearer_from_cfg(opts: &GlobalOpts, cfg: &ClientConfig) -> Result<String, String> {
    let cid = resolve_client_id(opts, cfg);
    cfg.load_token(&cid)?
        .ok_or_else(|| "no sealed session token stored; run enroll or login first".to_string())
}

fn load_or_create_vault_key(
    opts: &GlobalOpts,
    client_id: &str,
    override_hex: Option<&str>,
) -> Result<[u8; 32], String> {
    if let Some(hex_str) = override_hex {
        return parse_sha256_pin_hex(hex_str);
    }
    let vault_path = match &opts.config_path {
        Some(p) => p.with_file_name("vault.key.sealed"),
        None => eazyconnect_core::default_config_path()?.with_file_name("vault.key.sealed"),
    };
    if vault_path.exists() {
        let hex_blob = fs::read_to_string(&vault_path).map_err(|e| e.to_string())?;
        let raw = unseal_local_secret(&format!("{client_id}-vault"), hex_blob.trim())?;
        return <[u8; 32]>::try_from(raw.as_slice())
            .map_err(|_| "corrupted sealed vault key length".to_string());
    }
    let mut key = [0u8; 32];
    getrandom::getrandom(&mut key).map_err(|e| e.to_string())?;
    let sealed = seal_local_secret(&format!("{client_id}-vault"), &key)?;
    if let Some(parent) = vault_path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::write(&vault_path, sealed).map_err(|e| e.to_string())?;
    io::stdout().flush().ok();
    Ok(key)
}

fn print_help() {
    println!(
        "EazyConnect Headless Rust Client v{}\n\
         Global options:\n\
         \t--master <url>         Master server URL (https://... or wss://...)\n\
         \t--tls-pin <sha256>     Pin Master TLS certificate SHA-256 hex digest\n\
         \t--tls-ca <pem>         Trust custom TLS CA PEM file\n\
         \t--insecure-http        Allow plaintext HTTP/WS (testing only)\n\
         \t--config <path>        Override config.json path\n\
         \t--client-id <id>       Override device client_id\n\
         \t--keystore-dir <dir>   Override OS-sealed keystore directory\n\
         \n\
         Subcommands:\n\
         \tdiscover               Broadcast UDP 37020 Ed25519-signed LAN discovery\n\
         \tenroll                 Enroll DPAPI-sealed Ed25519 device identity\n\
         \tlogin <user> <pass>    Authenticate user & store DPAPI-sealed token\n\
         \tcreate-user <u> <p>    Create user (admin token required)\n\
         \tupload <file>          Upload file (add --e2e for client-side CubeHash vault)\n\
         \tlist                   List files on Master\n\
         \tdownload <r> <dest>    Download & verify BLAKE3 (+ optional --e2e decrypt)\n\
         \tsync <folder>          Incremental BLAKE3 folder delta sync (+ optional --e2e)\n\
         \tchat                   Encrypted CubeHash E2E terminal chat via Master /ws relay\n\
         \thw list                Inspect TPM, DPAPI, MachineGuid, adapters, USB, HID, COM\n\
         \thw serial list|send|bridge  Direct COM/USB serial I/O & E2E CubeHash bridge\n\
         \tprofile show|set       View/update bilingual (en/fa) profile settings\n\
         \tdiag [--upload]        Run hardware + LAN + TLS diagnostics\n\
         \tservice <cmd>          Manage Windows Task Scheduler logon helper",
        env!("CARGO_PKG_VERSION")
    );
}
