use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cubehash_core::OsBoundHardwareProvider;
use eazyconnect_client::{sync_folder_to_master, EazyNode, MasterHttpClient, NodeConnectOptions, NodeEvent};
use eazyconnect_core::{
    decrypt_file_from_vault, discover_masters, load_client_config, parse_sha256_pin_hex,
    save_client_config, ClientConfig, ClientTlsConfig, CreateUserRequest, EazyAppMessage,
    EazyMeshProfile, ServerTlsConfig,
};
use eazyconnect_hw::{DeviceIdentity, MemorySerialTransport, SerialTransport};
use eazyconnect_server::{start_server, EnrollmentPolicy, ServerConfig, StartedServer};
use tokio::sync::broadcast;

struct TempTestDir(PathBuf);

impl TempTestDir {
    fn new(prefix: &str) -> Self {
        let mut rnd = [0u8; 6];
        getrandom::getrandom(&mut rnd).unwrap();
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let dir = std::env::temp_dir().join(format!("{prefix}_{ts}_{}", hex::encode(rnd)));
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for TempTestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

async fn boot_test_master(
    dir: &TempTestDir,
    with_discovery: bool,
    enrollment: EnrollmentPolicy,
    admin_pass: Option<String>,
) -> (StartedServer, String, ClientTlsConfig, [u8; 32]) {
    let srv = start_server(ServerConfig {
        listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        data_dir: dir.0.join("server_data"),
        keystore_dir: Some(dir.0.join("server_ks")),
        tls: ServerTlsConfig::SelfSigned {
            san_hosts: vec!["localhost".to_string(), "127.0.0.1".to_string()],
        },
        discovery_addr: with_discovery
            .then_some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)),
        advertised_host: Some("127.0.0.1".to_string()),
        enrollment,
        bootstrap_admin_pass: admin_pass,
    })
    .await
    .expect("master server must start");

    let url = format!("https://{}", srv.addr);
    let pin_hex = srv
        .tls_cert_sha256_hex
        .clone()
        .expect("self-signed TLS server must report cert SHA-256");
    let pin = parse_sha256_pin_hex(&pin_hex).unwrap();
    let tls_cfg = ClientTlsConfig::PinnedCertSha256(pin);
    (srv, url, tls_cfg, pin)
}

async fn wait_event<F, T>(rx: &mut broadcast::Receiver<NodeEvent>, mut pred: F) -> T
where
    F: FnMut(&NodeEvent) -> Option<T>,
{
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match rx.recv().await {
                Ok(ev) => {
                    if let Some(res) = pred(&ev) {
                        return res;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(e) => panic!("node event channel closed while waiting: {e}"),
            }
        }
    })
    .await
    .expect("timed out waiting for expected NodeEvent")
}

#[tokio::test]
async fn test_tls_pinning_lan_discovery_and_enrollment_gate() {
    let dir = TempTestDir::new("ezc_e2e_auth");
    let (srv, url, tls_cfg, _pin) = boot_test_master(
        &dir,
        true,
        EnrollmentPolicy::InviteCode("INVITE-991".to_string()),
        None,
    )
    .await;

    let disc_addr = srv.discovery_addr.expect("UDP discovery enabled");
    let discovered = discover_masters(disc_addr, Duration::from_millis(800))
        .await
        .expect("discovery query should succeed");
    assert_eq!(discovered.len(), 1);
    assert_eq!(discovered[0].url, url);
    assert!(discovered[0].signature_valid);
    assert_eq!(discovered[0].tls_cert_sha256_hex, srv.tls_cert_sha256_hex);

    // 1. Refuse plaintext HTTP without opt-in.
    assert!(MasterHttpClient::new("http://127.0.0.1:8000", ClientTlsConfig::WebPkiRoots, false).is_err());

    // 2. Reject wrong SHA-256 certificate pin.
    let bad_client = MasterHttpClient::new(
        &url,
        ClientTlsConfig::PinnedCertSha256([0xAA; 32]),
        false,
    )
    .unwrap();
    assert!(bad_client.health().await.is_err());

    // 3. Valid TLS pin connects cleanly.
    let client = MasterHttpClient::new(&url, tls_cfg.clone(), false).unwrap();
    let health = client.health().await.unwrap();
    assert_eq!(health.status, "ok");

    // 4. Enrollment without or with wrong invite code is denied.
    let alice_id =
        DeviceIdentity::load_or_create("alice-dev", Some(&dir.0.join("client_ks")), None).unwrap();
    assert!(client.enroll_device(&alice_id, None).await.is_err());
    assert!(client.enroll_device(&alice_id, Some("WRONG")).await.is_err());

    // 5. Valid invite code enrolls device and prevents Ed25519 impersonation.
    let alice_tok = client
        .enroll_device(&alice_id, Some("INVITE-991"))
        .await
        .unwrap();
    assert_eq!(alice_tok.client_id, "alice-dev");
    assert_eq!(alice_tok.role, "device");

    let impostor = DeviceIdentity::ephemeral_csprng("alice-dev").unwrap();
    let imp_err = client
        .enroll_device(&impostor, Some("INVITE-991"))
        .await
        .unwrap_err();
    assert!(imp_err.contains("403") || imp_err.contains("identity_mismatch"), "{imp_err}");

    // 6. Hardcoded admin/admin must fail; generated bootstrap-admin.txt password must succeed.
    assert!(client.login_password("admin", "admin").await.is_err());
    let bootstrap_txt = fs::read_to_string(dir.0.join("server_data").join("bootstrap-admin.txt"))
        .expect("bootstrap-admin.txt should exist");
    let pw = bootstrap_txt
        .lines()
        .find_map(|l| l.strip_prefix("password:"))
        .expect("password line in bootstrap-admin.txt")
        .trim();
    let admin_tok = client.login_password("admin", pw).await.unwrap();
    assert_eq!(admin_tok.role, "admin");

    // Admin creates user 'hamed' and verifies password login.
    client
        .create_user(
            &admin_tok.token,
            &CreateUserRequest {
                username: "hamed".to_string(),
                password: "StrongPassword!123".to_string(),
                is_admin: false,
            },
        )
        .await
        .unwrap();
    let hamed_tok = client
        .login_password("hamed", "StrongPassword!123")
        .await
        .unwrap();
    assert_eq!(hamed_tok.client_id, "hamed");

    srv.abort();
}

#[tokio::test]
async fn test_file_upload_incremental_sync_and_e2e_vault() {
    let dir = TempTestDir::new("ezc_e2e_sync");
    let (srv, url, tls_cfg, _pin) =
        boot_test_master(&dir, false, EnrollmentPolicy::OpenLan, None).await;

    let client = MasterHttpClient::new(&url, tls_cfg, false).unwrap();
    let id =
        DeviceIdentity::load_or_create("sync-node", Some(&dir.0.join("client_ks")), None).unwrap();
    let tok = client.enroll_device(&id, None).await.unwrap();

    // Persist bearer token with host DPAPI protection inside config.json and reload.
    let cfg_path = dir.0.join("client_cfg").join("config.json");
    let mut cfg = ClientConfig {
        master: Some(url.clone()),
        client_id: Some("sync-node".to_string()),
        verify: true,
        ..Default::default()
    };
    cfg.set_token("sync-node", &tok.token).unwrap();
    save_client_config(&cfg, Some(&cfg_path)).unwrap();
    let reloaded = load_client_config(Some(&cfg_path)).unwrap();
    assert_eq!(reloaded.load_token("sync-node").unwrap().unwrap(), tok.token);

    // Prepare sample sync tree.
    let sync_root = dir.0.join("sync_folder");
    fs::create_dir_all(sync_root.join("nested")).unwrap();
    let plain_alpha = b"Confidential EazyConnect E2E Document Alpha";
    let plain_nested = b"Binary firmware chunk v1";
    fs::write(sync_root.join("alpha.txt"), plain_alpha).unwrap();
    fs::write(sync_root.join("nested").join("telemetry.bin"), plain_nested).unwrap();

    let manifest_path = dir.0.join("sync-manifest.json");
    let vault_key = [0x5Au8; 32];

    let run1 = sync_folder_to_master(
        &client,
        &tok.token,
        &sync_root,
        &manifest_path,
        Some((id.hardware_provider(), &vault_key)),
    )
    .await
    .unwrap();
    assert_eq!(run1.uploaded_count, 2);
    assert!(run1.e2e_encrypted);

    // Verify Master storage contains ciphertext only (zero plaintext leaks on server disk).
    let stored_alpha =
        fs::read(dir.0.join("server_data").join("files").join("sync-node").join("alpha.txt"))
            .unwrap();
    assert!(!stored_alpha.windows(plain_alpha.len()).any(|w| w == plain_alpha));

    // Re-syncing unmodified folder skips unchanged files via BLAKE3 manifest.
    let run2 = sync_folder_to_master(
        &client,
        &tok.token,
        &sync_root,
        &manifest_path,
        Some((id.hardware_provider(), &vault_key)),
    )
    .await
    .unwrap();
    assert_eq!(run2.uploaded_count, 0);

    // Updating one file uploads only that delta.
    let updated_nested = b"Binary firmware chunk v2-patched";
    fs::write(sync_root.join("nested").join("telemetry.bin"), updated_nested).unwrap();
    let run3 = sync_folder_to_master(
        &client,
        &tok.token,
        &sync_root,
        &manifest_path,
        Some((id.hardware_provider(), &vault_key)),
    )
    .await
    .unwrap();
    assert_eq!(run3.uploaded_count, 1);
    assert_eq!(run3.uploaded_files, vec!["nested/telemetry.bin"]);

    // List and download encrypted files, verifying BLAKE3 & client-side hardware-bound decrypt.
    let listed = client.list_files(&tok.token, None).await.unwrap();
    assert_eq!(listed.files.len(), 2);

    let (dl_ct, _hash, dl_e2e) = client
        .download_bytes(&tok.token, "sync-node", "nested/telemetry.bin")
        .await
        .unwrap();
    assert!(dl_e2e);
    let decrypted = decrypt_file_from_vault(
        id.hardware_provider(),
        &vault_key,
        "nested/telemetry.bin",
        &dl_ct,
    )
    .unwrap();
    assert_eq!(decrypted, updated_nested);

    // Different hardware lock or wrong key cannot decrypt.
    let alien_hw = OsBoundHardwareProvider::from_host_and_secret(&[0xEEu8; 32], b"alien");
    assert!(
        decrypt_file_from_vault(&alien_hw, &vault_key, "nested/telemetry.bin", &dl_ct).is_err()
    );

    srv.abort();
}

#[tokio::test]
async fn test_e2e_cubehash_chat_zero_oracle_and_epoch_hop_over_wss() {
    let dir = TempTestDir::new("ezc_e2e_chat");
    let (srv, url, tls_cfg, _pin) =
        boot_test_master(&dir, false, EnrollmentPolicy::OpenLan, Some("AdminPass#2026".to_string())).await;

    let http = MasterHttpClient::new(&url, tls_cfg.clone(), false).unwrap();
    let admin_tok = http.login_password("admin", "AdminPass#2026").await.unwrap();

    let alice_id =
        DeviceIdentity::load_or_create("alice", Some(&dir.0.join("ks_alice")), None).unwrap();
    let bob_id =
        DeviceIdentity::load_or_create("bob", Some(&dir.0.join("ks_bob")), None).unwrap();

    let alice = EazyNode::connect(
        alice_id,
        NodeConnectOptions {
            ws_url: url.clone(),
            tls_config: tls_cfg.clone(),
            allow_insecure_ws: false,
            allow_remote_serial_os_fallback: false,
            allow_remote_hw_probe: false,
            auto_reconnect: false,
        },
    )
    .await
    .unwrap();
    let mut alice_ev = alice.subscribe();

    let bob = EazyNode::connect(
        bob_id,
        NodeConnectOptions {
            ws_url: url.clone(),
            tls_config: tls_cfg.clone(),
            allow_insecure_ws: false,
            allow_remote_serial_os_fallback: false,
            allow_remote_hw_probe: false,
            auto_reconnect: false,
        },
    )
    .await
    .unwrap();
    let mut bob_ev = bob.subscribe();

    let psk = b"eazyconnect-session-psk";
    let pair_id = alice
        .send_pair_offer("bob", EazyMeshProfile::Standard, psk)
        .await
        .unwrap();

    let incoming_id = wait_event(&mut bob_ev, |e| match e {
        NodeEvent::IncomingPairOffer { pair_id, from, .. } if from == "alice" => {
            Some(pair_id.clone())
        }
        _ => None,
    })
    .await;
    assert_eq!(incoming_id, pair_id);

    let bob_paired = bob.accept_pair_offer(&pair_id, psk).await.unwrap();
    let alice_fp = wait_event(&mut alice_ev, |e| match e {
        NodeEvent::Paired {
            peer,
            safety_fingerprint,
            ..
        } if peer == "bob" => Some(safety_fingerprint.clone()),
        _ => None,
    })
    .await;
    assert_eq!(alice_fp, bob_paired.safety_fingerprint);

    let secret_text = "ULTRA_SECRET_EAZYCONNECT_CHAT_918273";
    alice.send_chat_message("bob", secret_text).await.unwrap();
    let recv_text = wait_event(&mut bob_ev, |e| match e {
        NodeEvent::MessageReceived {
            from,
            msg: EazyAppMessage::ChatText { text },
            ..
        } if from == "alice" => Some(text.clone()),
        _ => None,
    })
    .await;
    assert_eq!(recv_text, secret_text);

    // Zero-oracle honey probe across real WSS relay does NOT desync healthy session.
    alice.send_tampered_probe("bob").await.unwrap();
    let _honey = wait_event(&mut bob_ev, |e| match e {
        NodeEvent::HoneyDecoyTriggered { from, plausible_preview, .. } if from == "alice" => {
            Some(plausible_preview.clone())
        }
        _ => None,
    })
    .await;

    // Epoch hop + DH ratchet over WSS relay, then follow-up encrypted message at epoch 1.
    let new_epoch = alice.hop_epoch("bob").await.unwrap();
    assert_eq!(new_epoch, 1);
    let bob_epoch = wait_event(&mut bob_ev, |e| match e {
        NodeEvent::EpochHopped { peer, new_epoch } if peer == "alice" => Some(*new_epoch),
        _ => None,
    })
    .await;
    assert_eq!(bob_epoch, 1);

    let after_hop = "POST_EPOCH_HOP_SURVIVED_MESSAGE";
    alice.send_chat_message("bob", after_hop).await.unwrap();
    let (recv2, epoch2) = wait_event(&mut bob_ev, |e| match e {
        NodeEvent::MessageReceived {
            from,
            epoch,
            msg: EazyAppMessage::ChatText { text },
            ..
        } if from == "alice" && text == after_hop => Some((text.clone(), *epoch)),
        _ => None,
    })
    .await;
    assert_eq!(recv2, after_hop);
    assert_eq!(epoch2, 1);

    // Verify Master Relay telemetry proves zero-knowledge routing (no plaintext leakage).
    let snap = http.relay_telemetry(&admin_tok.token).await.unwrap();
    let snap_json = serde_json::to_string(&snap).unwrap();
    assert!(!snap_json.contains(secret_text));
    assert!(!snap_json.contains(after_hop));
    assert!(snap.total_routed_frames >= 4);

    alice.shutdown().await;
    bob.shutdown().await;
    srv.abort();
}

#[tokio::test]
async fn test_encrypted_serial_and_hardware_probe_bridge_e2e() {
    let dir = TempTestDir::new("ezc_e2e_hw");
    let (srv, url, tls_cfg, _pin) =
        boot_test_master(&dir, false, EnrollmentPolicy::OpenLan, Some("AdminPass#Hw".to_string())).await;

    let http = MasterHttpClient::new(&url, tls_cfg.clone(), false).unwrap();
    let admin_tok = http.login_password("admin", "AdminPass#Hw").await.unwrap();

    // Virtual serial peripheral simulating an attached COM microcontroller / Modbus device.
    let (pc_serial, mut mcu_serial) = MemorySerialTransport::pair("COM_MOCK_1", "MCU_SIDE");
    let stop_flag = Arc::new(AtomicBool::new(false));
    let stop_clone = Arc::clone(&stop_flag);
    let mcu_thread = std::thread::spawn(move || {
        while !stop_clone.load(Ordering::Relaxed) {
            if let Ok(req) = mcu_serial.read_available(256) {
                if !req.is_empty() {
                    let cmd = String::from_utf8_lossy(&req);
                    if cmd.contains("AT+TEMP?") {
                        let _ = mcu_serial.write_bytes(b"TEMP=36.5C;OK\n");
                    } else {
                        let _ = mcu_serial.write_bytes(b"ERR\n");
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    });

    let alice_id =
        DeviceIdentity::load_or_create("edge-host", Some(&dir.0.join("ks_edge")), None).unwrap();
    let bob_id =
        DeviceIdentity::load_or_create("operator", Some(&dir.0.join("ks_op")), None).unwrap();

    let edge = EazyNode::connect(
        alice_id,
        NodeConnectOptions {
            ws_url: url.clone(),
            tls_config: tls_cfg.clone(),
            allow_insecure_ws: false,
            allow_remote_serial_os_fallback: false,
            allow_remote_hw_probe: true,
            auto_reconnect: false,
        },
    )
    .await
    .unwrap();
    edge.attach_serial_transport("COM_MOCK_1", Box::new(pc_serial))
        .unwrap();
    let mut edge_ev = edge.subscribe();

    let operator = EazyNode::connect(
        bob_id,
        NodeConnectOptions {
            ws_url: url.clone(),
            tls_config: tls_cfg.clone(),
            allow_insecure_ws: false,
            allow_remote_serial_os_fallback: false,
            allow_remote_hw_probe: false,
            auto_reconnect: false,
        },
    )
    .await
    .unwrap();
    let mut op_ev = operator.subscribe();

    let psk = b"hw-bridge-secret";
    let pair_id = operator
        .send_pair_offer("edge-host", EazyMeshProfile::Compact, psk)
        .await
        .unwrap();

    let incoming = wait_event(&mut edge_ev, |e| match e {
        NodeEvent::IncomingPairOffer { pair_id, from, .. } if from == "operator" => {
            Some(pair_id.clone())
        }
        _ => None,
    })
    .await;
    assert_eq!(incoming, pair_id);
    edge.accept_pair_offer(&pair_id, psk).await.unwrap();

    wait_event(&mut op_ev, |e| match e {
        NodeEvent::Paired { peer, .. } if peer == "edge-host" => Some(()),
        _ => None,
    })
    .await;

    // 1. Remote encrypted serial command -> MCU reply over CubeHash E2E -> operator.
    operator
        .send_serial_command_remote("edge-host", "COM_MOCK_1", 115200, b"AT+TEMP?\n".to_vec())
        .await
        .unwrap();

    let serial_reply = wait_event(&mut op_ev, |e| match e {
        NodeEvent::MessageReceived {
            from,
            msg: EazyAppMessage::SerialData { port, data },
            ..
        } if from == "edge-host" && port == "COM_MOCK_1" => Some(data.clone()),
        _ => None,
    })
    .await;
    assert_eq!(serial_reply, b"TEMP=36.5C;OK\n");

    // 2. Encrypted remote OS hardware probe.
    operator
        .request_remote_hardware_probe("edge-host")
        .await
        .unwrap();
    let report = wait_event(&mut op_ev, |e| match e {
        NodeEvent::MessageReceived {
            from,
            msg: EazyAppMessage::HardwareProbeResponse { report },
            ..
        } if from == "edge-host" => Some(report.clone()),
        _ => None,
    })
    .await;
    assert!(!report.os.is_empty());

    // Zero plaintext hardware commands/readings leaked to relay telemetry.
    let snap = http.relay_telemetry(&admin_tok.token).await.unwrap();
    let snap_json = serde_json::to_string(&snap).unwrap();
    assert!(!snap_json.contains("AT+TEMP"));
    assert!(!snap_json.contains("36.5C"));

    stop_flag.store(true, Ordering::Relaxed);
    let _ = mcu_thread.join();
    operator.shutdown().await;
    edge.shutdown().await;
    srv.abort();
}

#[tokio::test]
async fn test_persistent_tls_pin_survives_server_restart() {
    let dir = TempTestDir::new("ezc_e2e_tls_persist");
    let cert_path = dir.0.join("server_data").join("tls").join("cert.pem");
    let key_path = dir.0.join("server_data").join("tls").join("key.pem");

    let srv1 = start_server(ServerConfig {
        listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        data_dir: dir.0.join("server_data"),
        keystore_dir: Some(dir.0.join("server_ks")),
        tls: ServerTlsConfig::LoadOrCreateSelfSigned {
            cert_path: cert_path.clone(),
            key_path: key_path.clone(),
            san_hosts: vec!["localhost".to_string(), "127.0.0.1".to_string()],
            force_regen: false,
        },
        discovery_addr: None,
        advertised_host: Some("127.0.0.1".to_string()),
        enrollment: EnrollmentPolicy::InviteCode("VPN-PIN-TEST".to_string()),
        bootstrap_admin_pass: Some("AdminPass!2026".to_string()),
    })
    .await
    .unwrap();
    let pin1_hex = srv1.tls_cert_sha256_hex.clone().unwrap();
    let pin1 = parse_sha256_pin_hex(&pin1_hex).unwrap();
    srv1.abort();

    // Restart on the same data_dir with LoadOrCreateSelfSigned: remote peers keep working with pin1.
    let srv2 = start_server(ServerConfig {
        listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        data_dir: dir.0.join("server_data"),
        keystore_dir: Some(dir.0.join("server_ks")),
        tls: ServerTlsConfig::LoadOrCreateSelfSigned {
            cert_path,
            key_path,
            san_hosts: vec!["localhost".to_string(), "127.0.0.1".to_string()],
            force_regen: false,
        },
        discovery_addr: None,
        advertised_host: Some("127.0.0.1".to_string()),
        enrollment: EnrollmentPolicy::InviteCode("VPN-PIN-TEST".to_string()),
        bootstrap_admin_pass: None,
    })
    .await
    .unwrap();
    assert_eq!(srv2.tls_cert_sha256_hex.as_deref(), Some(pin1_hex.as_str()));

    let url2 = format!("https://{}", srv2.addr);
    let client =
        MasterHttpClient::new(&url2, ClientTlsConfig::PinnedCertSha256(pin1), false).unwrap();
    let health = client.health().await.unwrap();
    assert_eq!(health.status, "ok");

    srv2.abort();
}

#[tokio::test]
async fn test_relay_reclaim_and_auto_reconnect_preserve_cubehash_session() {
    let dir = TempTestDir::new("ezc_e2e_reclaim");
    let (srv, url, tls_cfg, _pin) =
        boot_test_master(&dir, false, EnrollmentPolicy::OpenLan, None).await;

    let alice_id =
        DeviceIdentity::load_or_create("alice", Some(&dir.0.join("ks_alice")), None).unwrap();
    let alice_reclaim_id =
        DeviceIdentity::load_or_create("alice", Some(&dir.0.join("ks_alice")), None).unwrap();
    let bob_id =
        DeviceIdentity::load_or_create("bob", Some(&dir.0.join("ks_bob")), None).unwrap();

    let http = MasterHttpClient::new(&url, tls_cfg.clone(), false).unwrap();
    http.enroll_device(&alice_id, None).await.unwrap();
    http.enroll_device(&bob_id, None).await.unwrap();

    let alice = EazyNode::connect(
        alice_id,
        NodeConnectOptions {
            ws_url: url.clone(),
            tls_config: tls_cfg.clone(),
            allow_insecure_ws: false,
            allow_remote_serial_os_fallback: false,
            allow_remote_hw_probe: false,
            auto_reconnect: true,
        },
    )
    .await
    .unwrap();
    let mut alice_ev = alice.subscribe();

    let bob = EazyNode::connect(
        bob_id,
        NodeConnectOptions {
            ws_url: url.clone(),
            tls_config: tls_cfg.clone(),
            allow_insecure_ws: false,
            allow_remote_serial_os_fallback: false,
            allow_remote_hw_probe: false,
            auto_reconnect: false,
        },
    )
    .await
    .unwrap();
    let mut bob_ev = bob.subscribe();

    let psk = b"vpn-continuity-psk";
    let pair_id = alice
        .send_pair_offer("bob", EazyMeshProfile::Compact, psk)
        .await
        .unwrap();
    let incoming_id = wait_event(&mut bob_ev, |e| match e {
        NodeEvent::IncomingPairOffer { pair_id, from, .. } if from == "alice" => {
            Some(pair_id.clone())
        }
        _ => None,
    })
    .await;
    assert_eq!(incoming_id, pair_id);
    bob.accept_pair_offer(&pair_id, psk).await.unwrap();
    wait_event(&mut alice_ev, |e| match e {
        NodeEvent::Paired { peer, .. } if peer == "bob" => Some(()),
        _ => None,
    })
    .await;

    alice
        .send_app_message(
            "bob",
            EazyAppMessage::ChatText {
                text: "before-vpn-drop".to_string(),
            },
        )
        .await
        .unwrap();
    let first_msg = wait_event(&mut bob_ev, |e| match e {
        NodeEvent::MessageReceived {
            from,
            msg: EazyAppMessage::ChatText { text },
            ..
        } if from == "alice" => Some(text.clone()),
        _ => None,
    })
    .await;
    assert_eq!(first_msg, "before-vpn-drop");

    // Impostor with mismatched Ed25519 key must still be blocked from reclaiming "alice".
    let impostor = DeviceIdentity::ephemeral_csprng("alice").unwrap();
    let hijack = EazyNode::connect(
        impostor,
        NodeConnectOptions {
            ws_url: url.clone(),
            tls_config: tls_cfg.clone(),
            allow_insecure_ws: false,
            allow_remote_serial_os_fallback: false,
            allow_remote_hw_probe: false,
            auto_reconnect: false,
        },
    )
    .await;
    assert!(hijack.is_err());

    // Verified same Ed25519 owner reclaims "alice" cleanly without `id_in_use`.
    let alice_reclaimer = EazyNode::connect(
        alice_reclaim_id,
        NodeConnectOptions {
            ws_url: url.clone(),
            tls_config: tls_cfg.clone(),
            allow_insecure_ws: false,
            allow_remote_serial_os_fallback: false,
            allow_remote_hw_probe: false,
            auto_reconnect: false,
        },
    )
    .await
    .expect("same verified Ed25519 owner should reclaim active relay session");

    wait_event(&mut alice_ev, |e| match e {
        NodeEvent::Reconnecting { .. } => Some(()),
        _ => None,
    })
    .await;

    // Step aside cleanly so `alice`'s auto-reconnect completes and preserves its paired CubeHash session.
    alice_reclaimer.shutdown().await;
    wait_event(&mut alice_ev, |e| match e {
        NodeEvent::Reconnected => Some(()),
        _ => None,
    })
    .await;

    // Preserved DuplexCubeSession sends another encrypted message immediately without re-pairing!
    alice
        .send_app_message(
            "bob",
            EazyAppMessage::ChatText {
                text: "after-vpn-roam".to_string(),
            },
        )
        .await
        .unwrap();
    let post_msg = wait_event(&mut bob_ev, |e| match e {
        NodeEvent::MessageReceived {
            from,
            msg: EazyAppMessage::ChatText { text },
            ..
        } if from == "alice" => Some(text.clone()),
        _ => None,
    })
    .await;
    assert_eq!(post_msg, "after-vpn-roam");

    alice.shutdown().await;
    bob.shutdown().await;
    srv.abort();
}

#[test]
fn test_discovery_beacon_alternate_urls_signed_and_tamper_rejected() {
    let dir = TempTestDir::new("ezc_beacon_alts");
    let master = DeviceIdentity::load_or_create("master", Some(&dir.0), None).unwrap();
    let pub_key = master.ed25519_pub();
    let alts = vec![
        "https://192.168.1.50:8000".to_string(),
        "https://100.64.0.10:8000".to_string(),
    ];
    let sign_msg = eazyconnect_core::discovery_beacon_sign_bytes(
        "eazyconnect/0.2",
        "10.8.0.1",
        8000,
        true,
        Some("abcd"),
        &pub_key,
        &alts,
    );
    let sig = master.sign(&sign_msg);
    assert!(DeviceIdentity::verify_signature(&pub_key, &sign_msg, &sig));

    let tampered_alts = vec![
        "https://192.168.1.50:8000".to_string(),
        "https://evil.invalid:8000".to_string(),
    ];
    let tampered_msg = eazyconnect_core::discovery_beacon_sign_bytes(
        "eazyconnect/0.2",
        "10.8.0.1",
        8000,
        true,
        Some("abcd"),
        &pub_key,
        &tampered_alts,
    );
    assert!(!DeviceIdentity::verify_signature(
        &pub_key,
        &tampered_msg,
        &sig
    ));
}

#[tokio::test]
async fn test_cubehash_chunked_file_transfer_over_wss() {
    let dir = TempTestDir::new("ezc_e2e_file_chunks");
    let (srv, url, tls_cfg, _pin) =
        boot_test_master(&dir, false, EnrollmentPolicy::OpenLan, None).await;

    let alice_id =
        DeviceIdentity::load_or_create("alice", Some(&dir.0.join("ks_alice")), None).unwrap();
    let bob_id =
        DeviceIdentity::load_or_create("bob", Some(&dir.0.join("ks_bob")), None).unwrap();

    let http = MasterHttpClient::new(&url, tls_cfg.clone(), false).unwrap();
    http.enroll_device(&alice_id, None).await.unwrap();
    http.enroll_device(&bob_id, None).await.unwrap();

    let alice = EazyNode::connect(
        alice_id,
        NodeConnectOptions {
            ws_url: url.clone(),
            tls_config: tls_cfg.clone(),
            allow_insecure_ws: false,
            allow_remote_serial_os_fallback: false,
            allow_remote_hw_probe: false,
            auto_reconnect: false,
        },
    )
    .await
    .unwrap();
    let mut alice_ev = alice.subscribe();

    let bob = EazyNode::connect(
        bob_id,
        NodeConnectOptions {
            ws_url: url.clone(),
            tls_config: tls_cfg.clone(),
            allow_insecure_ws: false,
            allow_remote_serial_os_fallback: false,
            allow_remote_hw_probe: false,
            auto_reconnect: false,
        },
    )
    .await
    .unwrap();
    let mut bob_ev = bob.subscribe();

    let psk = b"cubehash-file-psk";
    let pair_id = alice
        .send_pair_offer("bob", EazyMeshProfile::Compact, psk)
        .await
        .unwrap();
    let incoming_id = wait_event(&mut bob_ev, |e| match e {
        NodeEvent::IncomingPairOffer { pair_id, .. } => Some(pair_id.clone()),
        _ => None,
    })
    .await;
    assert_eq!(incoming_id, pair_id);
    bob.accept_pair_offer(&pair_id, psk).await.unwrap();
    wait_event(&mut alice_ev, |e| match e {
        NodeEvent::Paired { peer, .. } if peer == "bob" => Some(()),
        _ => None,
    })
    .await;

    // 300 KiB deterministic payload (spans 3 x 128 KiB CubeHash E2E chunks + BLAKE3 check).
    let payload: Vec<u8> = (0..(300 * 1024)).map(|i| ((i * 37) & 0xFF) as u8).collect();
    let expected_b3 = blake3::hash(&payload).to_hex().to_string();

    let send_handle = tokio::spawn(async move {
        let mut progress = Vec::new();
        let res = alice
            .send_e2e_file_bytes("bob", "telemetry-dump.bin", &payload, |sent, total| {
                progress.push((sent, total));
            })
            .await;
        (alice, res, progress)
    });

    let mut assembler = eazyconnect_core::FileTransferAssembler::default();
    let assembled = loop {
        if let NodeEvent::MessageReceived {
            from,
            msg:
                EazyAppMessage::FileChunk {
                    transfer_id,
                    filename,
                    total_size,
                    blake3_hex,
                    chunk_index,
                    total_chunks,
                    data,
                },
            ..
        } = bob_ev.recv().await.unwrap()
        {
            match assembler
                .push_chunk(
                    &from,
                    &transfer_id,
                    &filename,
                    total_size,
                    &blake3_hex,
                    chunk_index,
                    total_chunks,
                    data,
                )
                .unwrap()
            {
                eazyconnect_core::FileAssembleStatus::Progress { .. } => {}
                eazyconnect_core::FileAssembleStatus::Completed {
                    filename,
                    blake3_hex,
                    bytes,
                } => break (filename, blake3_hex, bytes),
            }
        }
    };

    let (alice, send_res, progress) = send_handle.await.unwrap();
    let (_, sent_b3) = send_res.unwrap();
    assert_eq!(progress, vec![(1, 3), (2, 3), (3, 3)]);
    assert_eq!(assembled.0, "telemetry-dump.bin");
    assert_eq!(assembled.1, expected_b3);
    assert_eq!(sent_b3, expected_b3);
    assert_eq!(assembled.2.len(), 300 * 1024);

    alice.shutdown().await;
    bob.shutdown().await;
    srv.abort();
}
