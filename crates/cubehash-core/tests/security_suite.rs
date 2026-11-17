use std::collections::HashSet;
use std::time::Instant;

use blake2::{Blake2b512, Digest as Blake2Digest};
use cubehash_core::primitives::{aead_seal, fixed_budget_mix, hmac_sha256};
use cubehash_core::{
    lag1_bit_autocorrelation, ones_ratio, pearson_chi_square_uniform,
    shannon_entropy_bits_per_byte, CellularMesh, CombiningFn, Coord3D, CubeHashError, DteEngine,
    DuplexCubeSession, HardwareProvider, HoneyProfile, HybridTriMix, MeshConfig,
    OsBoundHardwareProvider, PayloadMode, ReceiveOutcome, SpiralSpace, ThreeCubeCustody,
    TimeAlgorithm, VirtualHardwareEnclave, WirePacket,
};
use sha2::Sha256;
use sha3::{Sha3_256, Sha3_512};

fn make_custody(config: &MeshConfig) -> ThreeCubeCustody {
    ThreeCubeCustody::generate(
        TimeAlgorithm::HybridTriMix,
        CombiningFn::FeistelNonLinear,
        config.quorum_select,
        config.consume_for_next,
    )
    .expect("custody generation")
}

#[test]
fn test_config_validation_and_resizing() {
    // Reject invalid sizing constraints
    let mut bad_tmr = MeshConfig::standard();
    bad_tmr.sub_matrix_bytes = 40; // < 2 * 32
    assert_eq!(
        bad_tmr.validate(),
        Err(CubeHashError::InvalidConfig(
            "sub_matrix_bytes must be at least 2 * core_bytes for TMR shadows"
        ))
    );

    let mut bad_quorum = MeshConfig::standard();
    bad_quorum.quorum_select = 101;
    assert!(matches!(
        bad_quorum.validate(),
        Err(CubeHashError::InvalidConfig(_))
    ));

    // Verify all three built-in resizable profiles run end-to-end
    for cfg in [
        MeshConfig::compact(),
        MeshConfig::standard(),
        MeshConfig::high_capacity(),
    ] {
        cfg.validate().expect("valid preset");
        let custody = make_custody(&cfg);
        let alice_hw = VirtualHardwareEnclave::random().unwrap();
        let bob_hw = VirtualHardwareEnclave::random().unwrap();
        let (mut alice, mut bob) =
            CellularMesh::new_paired(cfg.clone(), custody, &alice_hw, &bob_hw).unwrap();

        let msg = format!("Resized profile test mesh_size={}", cfg.mesh_size);
        let mut pkt = alice.begin_send_message(&alice_hw, msg.as_bytes()).unwrap();
        assert_eq!(pkt.wire_cube.base_byte_len(), cfg.wire_cube_base_bytes());

        let (pt, ack, healed) = bob.receive_authenticated(&bob_hw, &mut pkt).unwrap();
        assert_eq!(healed, 0);
        assert_eq!(pt, msg.as_bytes());
        alice.commit_ack(&alice_hw, &ack).unwrap();
    }
}

#[test]
fn test_dual_mode_raw_core_and_arbitrary_payload() {
    let cfg = MeshConfig::standard();
    let custody = make_custody(&cfg);
    let alice_hw = VirtualHardwareEnclave::random().unwrap();
    let bob_hw = VirtualHardwareEnclave::random().unwrap();
    let (mut alice, mut bob) =
        CellularMesh::new_paired(cfg.clone(), custody, &alice_hw, &bob_hw).unwrap();

    // 1. RawCore256 mode: max 24 bytes directly inside 173-byte wire cube
    let key_slice = b"BTC-SEED-KEY-24-BYTES!!!";
    assert_eq!(key_slice.len(), cfg.raw_core_payload_capacity());
    let mut raw_pkt = alice.begin_send_raw_core(&alice_hw, key_slice).unwrap();
    assert_eq!(raw_pkt.wire_cube.base_byte_len(), 173);
    assert!(matches!(raw_pkt.payload_mode, PayloadMode::RawCore256));
    assert!(
        raw_pkt.wire_cube.weight_padding.len() >= cfg.weight_min_bytes
            && raw_pkt.wire_cube.weight_padding.len() <= cfg.weight_max_bytes
    );

    let (recovered_raw, ack1, _) = bob.receive_authenticated(&bob_hw, &mut raw_pkt).unwrap();
    assert_eq!(recovered_raw.as_slice(), key_slice);
    alice.commit_ack(&alice_hw, &ack1).unwrap();

    // Exceeding raw core capacity must return explicit PayloadTooLargeForCore error
    let too_big = [0xABu8; 25];
    assert!(matches!(
        alice.begin_send_raw_core(&alice_hw, &too_big),
        Err(CubeHashError::PayloadTooLargeForCore {
            max_bytes: 24,
            actual_bytes: 25
        })
    ));

    // 2. ArbitraryPayload mode: UTF-8 + multi-KB messages
    let long_chat =
        "سلام! این یک پیام تستی رمزنگاری‌شده با شبکه سلولی ۱۰۰ کیوبی CubeHash است. 🚀 ".repeat(35);
    let mut chat_pkt = alice
        .begin_send_message(&alice_hw, long_chat.as_bytes())
        .unwrap();
    assert!(matches!(
        chat_pkt.payload_mode,
        PayloadMode::ArbitraryCiphertext { .. }
    ));

    let (recovered_chat, ack2, _) = bob.receive_authenticated(&bob_hw, &mut chat_pkt).unwrap();
    assert_eq!(recovered_chat, long_chat.as_bytes());
    alice.commit_ack(&alice_hw, &ack2).unwrap();
}

#[test]
fn test_100_cube_cellular_lifecycle_entropy_and_ram() {
    let cfg = MeshConfig::standard();
    let custody = make_custody(&cfg);
    let alice_hw = VirtualHardwareEnclave::random().unwrap();
    let bob_hw = VirtualHardwareEnclave::random().unwrap();
    let (mut alice, mut bob) =
        CellularMesh::new_paired(cfg.clone(), custody, &alice_hw, &bob_hw).unwrap();

    let stats0 = alice.audit_stats();
    assert_eq!(stats0.mesh_size, 100);
    // 100 cubes * (16 + 8 + 32 + 125) = 18,100 bytes (~17.7 KB, matching ~16 KB spec)
    assert_eq!(stats0.approx_ram_bytes, 18_100);
    assert!(
        (0.45..=0.55).contains(&stats0.avg_ones_ratio),
        "unexpected bit bias: {}",
        stats0.avg_ones_ratio
    );
    assert!(
        stats0.avg_entropy_bits_per_byte > 6.5,
        "unexpected low entropy: {}",
        stats0.avg_entropy_bits_per_byte
    );

    // Run 120 messages so all 100 original cubes rotate out via kill+birth
    for seq in 1..=120u64 {
        let msg = format!("msg #{seq}");
        let mut pkt = alice.begin_send_message(&alice_hw, msg.as_bytes()).unwrap();
        let (pt, ack, _) = bob.receive_authenticated(&bob_hw, &mut pkt).unwrap();
        assert_eq!(pt, msg.as_bytes());
        alice.commit_ack(&alice_hw, &ack).unwrap();
        assert_eq!(alice.cubes().len(), 100);
        assert_eq!(bob.cubes().len(), 100);
    }

    assert_eq!(alice.sequence(), 120);
    assert_eq!(bob.sequence(), 120);
    // Every original generation-0 cube must have died and been replaced by generation >= 21
    assert!(alice.cubes().iter().all(|c| c.generation >= 21));

    // Verify wire cube statistical 50/50 bit distribution across payload + padding
    let pkt = alice
        .begin_send_raw_core(&alice_hw, b"probe-stats")
        .unwrap();
    let mut wire_bytes = Vec::new();
    wire_bytes.extend_from_slice(&pkt.wire_cube.partial_256b);
    wire_bytes.extend_from_slice(&pkt.wire_cube.partial_1000b);
    wire_bytes.extend_from_slice(&pkt.wire_cube.weight_padding);
    let wire_ratio = ones_ratio(&wire_bytes);
    let wire_ent = shannon_entropy_bits_per_byte(&wire_bytes);
    assert!((0.40..=0.60).contains(&wire_ratio));
    assert!(wire_ent > 6.5);
    alice.rollback_outbound().unwrap();
}

#[test]
fn test_ack_commit_and_network_drop_rollback() {
    let cfg = MeshConfig::standard();
    let custody = make_custody(&cfg);
    let alice_hw = VirtualHardwareEnclave::random().unwrap();
    let bob_hw = VirtualHardwareEnclave::random().unwrap();
    let (mut alice, mut bob) = CellularMesh::new_paired(cfg, custody, &alice_hw, &bob_hw).unwrap();

    let snapshot_seq = alice.sequence();
    let snapshot_gen0 = alice.cubes()[0].generation;

    // Begin send -> arrival-triggered means Alice does NOT commit yet
    let _dropped_pkt = alice
        .begin_send_message(&alice_hw, b"lost in transit")
        .unwrap();
    assert!(alice.has_pending_outbound());
    assert_eq!(alice.sequence(), snapshot_seq);
    assert_eq!(alice.cubes()[0].generation, snapshot_gen0);

    // Concurrent send before ACK/rollback must fail
    assert_eq!(
        alice.begin_send_message(&alice_hw, b"blocked"),
        Err(CubeHashError::PendingTransactionExists)
    );

    // Rollback on network drop restores clean pre-send state
    alice.rollback_outbound().unwrap();
    assert!(!alice.has_pending_outbound());
    assert_eq!(alice.sequence(), 0);

    // Subsequent message transmits and commits cleanly
    let mut pkt = alice
        .begin_send_message(&alice_hw, b"after rollback")
        .unwrap();
    let (pt, mut ack, _) = bob.receive_authenticated(&bob_hw, &mut pkt).unwrap();
    assert_eq!(pt, b"after rollback");

    // Forged ACK fails cleanly without committing
    ack.ack_mac[0] ^= 0xFF;
    assert_eq!(
        alice.commit_ack(&alice_hw, &ack),
        Err(CubeHashError::AckMismatch)
    );
    assert!(alice.has_pending_outbound());

    // Genuine ACK commits cleanly
    ack.ack_mac[0] ^= 0xFF;
    alice.commit_ack(&alice_hw, &ack).unwrap();
    assert!(!alice.has_pending_outbound());
    assert_eq!(alice.sequence(), 1);
}

#[test]
fn test_bitwise_majority_voting_self_healing_wire_and_storage() {
    let cfg = MeshConfig::standard();
    let custody = make_custody(&cfg);
    let alice_hw = VirtualHardwareEnclave::random().unwrap();
    let bob_hw = VirtualHardwareEnclave::random().unwrap();
    let (mut alice, mut bob) = CellularMesh::new_paired(cfg, custody, &alice_hw, &bob_hw).unwrap();

    let mut pkt = alice
        .begin_send_message(&alice_hw, b"noisy wireless transmission!")
        .unwrap();

    // Corrupt 10 bytes in partial_256b (first half) AND 10 bytes in shadow_a (second half)
    // so every bit still has at least 2 of 3 uncorrupted copies!
    for i in 0..10 {
        pkt.wire_cube.partial_256b[i] ^= 0x5A; // 4 flipped bits each = 40 bits in core
        pkt.wire_cube.partial_1000b[16 + i] ^= 0xA5; // 4 flipped bits each = 40 bits in shadow_a
    }

    let (pt, ack, healed_bits) = bob.receive_authenticated(&bob_hw, &mut pkt).unwrap();
    assert_eq!(pt, b"noisy wireless transmission!");
    assert_eq!(healed_bits, 80);
    alice.commit_ack(&alice_hw, &ack).unwrap();

    // Also test TMR self-healing on stored mesh cubes AFTER bijective epoch hopping
    alice.hop_epoch(&alice_hw).unwrap();
    alice.hop_epoch(&alice_hw).unwrap();
    bob.hop_epoch(&bob_hw).unwrap();
    bob.hop_epoch(&bob_hw).unwrap();
    alice.cubes_mut()[7].core_pattern[3] ^= 0xFF; // flip 8 bits in stored cube core
    let report = alice.heal_stored_cube(&alice_hw, 7).unwrap();
    assert_eq!(report.repaired_core_bits, 8);
    assert!(!report.unrecoverable_anomaly);

    // Severe corruption flipping all 3 copies in same positions + hot-spare must be rejected
    let mut ruined_pkt = alice
        .begin_send_message(&alice_hw, b"catastrophic")
        .unwrap();
    for i in 0..32 {
        ruined_pkt.wire_cube.partial_256b[i] ^= 0xFF;
        ruined_pkt.wire_cube.partial_1000b[i] ^= 0xFF;
        ruined_pkt.wire_cube.partial_1000b[32 + i] ^= 0xFF;
    }
    for b in &mut ruined_pkt.wire_cube.partial_1000b[64..72] {
        *b ^= 0xFF;
    }
    assert_eq!(
        bob.receive_authenticated(&bob_hw, &mut ruined_pkt),
        Err(CubeHashError::UnrecoverableCorruption)
    );
    alice.rollback_outbound().unwrap();
}

#[test]
fn test_hardware_lock_cloning_attack_and_3cube_recovery() {
    let cfg = MeshConfig::standard();
    let custody = make_custody(&cfg);
    let alice_hw = VirtualHardwareEnclave::random().unwrap();
    let bob_hw = VirtualHardwareEnclave::random().unwrap();
    let eve_stolen_hw = VirtualHardwareEnclave::random().unwrap();

    let (mut alice, mut bob) =
        CellularMesh::new_paired(cfg.clone(), custody.clone(), &alice_hw, &bob_hw).unwrap();

    // Attacker clones Alice's state onto Eve's device -> blocked by hardware enclave lock
    assert_eq!(
        alice.begin_send_message(&eve_stolen_hw, b"cloned session"),
        Err(CubeHashError::UnauthorizedHardware)
    );

    // Verify OsBoundHardwareProvider binds to explicit device secret + host traits
    let host_p1 = OsBoundHardwareProvider::from_host_and_secret(&[0x11; 32], b"chat-app");
    let host_p2 = OsBoundHardwareProvider::from_host_and_secret(&[0x22; 32], b"chat-app");
    assert_ne!(host_p1.device_hw_id(), host_p2.device_hw_id());

    // Verify 2-of-3 custody subset fails to reproduce root capability
    let mut missing_auditor = custody.clone();
    missing_auditor.auditor.auditor_secret = [0u8; 32];
    assert_ne!(
        custody.derive_root_capability(cfg.fixed_step_budget),
        missing_auditor.derive_root_capability(cfg.fixed_step_budget)
    );

    // Recover Alice onto replacement hardware via 3-Cube Custody and continue chatting with Bob
    let replacement_hw = VirtualHardwareEnclave::random().unwrap();
    alice.recover_onto_new_hardware(&replacement_hw).unwrap();
    assert_eq!(
        alice.begin_send_message(&alice_hw, b"old device revoked"),
        Err(CubeHashError::UnauthorizedHardware)
    );
    let mut pkt = alice
        .begin_send_message(&replacement_hw, b"recovered on new TPM!")
        .unwrap();
    let (pt, ack, _) = bob.receive_authenticated(&bob_hw, &mut pkt).unwrap();
    assert_eq!(pt, b"recovered on new TPM!");
    alice.commit_ack(&replacement_hw, &ack).unwrap();
}

#[test]
fn test_replay_and_monotonic_clock_protection() {
    let cfg = MeshConfig::standard();
    let custody = make_custody(&cfg);
    let alice_hw = VirtualHardwareEnclave::random().unwrap();
    let bob_hw = VirtualHardwareEnclave::random().unwrap();
    let (mut alice, mut bob) = CellularMesh::new_paired(cfg, custody, &alice_hw, &bob_hw).unwrap();

    let mut pkt = alice.begin_send_message(&alice_hw, b"nonce-once").unwrap();
    let pkt_replay = pkt.clone();
    let (_, ack, _) = bob.receive_authenticated(&bob_hw, &mut pkt).unwrap();
    alice.commit_ack(&alice_hw, &ack).unwrap();

    // Replaying sequence=1 after sequence=1 was consumed must be rejected
    let mut replay_copy = pkt_replay;
    assert_eq!(
        bob.receive_authenticated(&bob_hw, &mut replay_copy),
        Err(CubeHashError::ReplayDetected)
    );

    // Monotonic tick verifier rejects rollback/equal tick
    let mut last_tick = 5u64;
    assert!(bob
        .clock_guard_mut()
        .verify_and_advance_observed_tick(&mut last_tick, 6)
        .is_ok());
    assert_eq!(
        bob.clock_guard_mut()
            .verify_and_advance_observed_tick(&mut last_tick, 6),
        Err(CubeHashError::ReplayDetected)
    );
}

#[test]
fn test_bijective_epoch_hopping_and_spiral_window_lookup() {
    let spiral = SpiralSpace::new(1000, [17, 31, 53]);
    let epoch_key = [0x42u8; 32];

    // 1. 3D coordinate bijection: collision-free & exact inverse across 500 coords
    let mut mapped_set = HashSet::new();
    for i in 0..500u32 {
        let orig = Coord3D {
            x: (i * 7) % 1000,
            y: (i * 13 + 99) % 1000,
            z: (i * 29 + 500) % 1000,
        };
        let hopped = spiral.hop_coord_bijective(&epoch_key, 1, orig);
        let back = spiral.unhop_coord_bijective(&epoch_key, 1, hopped);
        assert_eq!(back, orig);
        assert!(mapped_set.insert(hopped));
    }

    // 2. 250-nibble bijection round-trip
    let mut nibbles = [0u8; 125];
    for (i, b) in nibbles.iter_mut().enumerate() {
        *b = ((i * 37 + 11) % 256) as u8;
    }
    let orig_nibbles = nibbles;
    SpiralSpace::permute_nibbles(&mut nibbles, &epoch_key, 3);
    assert_ne!(nibbles, orig_nibbles);
    SpiralSpace::unpermute_nibbles(&mut nibbles, &epoch_key, 3);
    assert_eq!(nibbles, orig_nibbles);

    // 3. Full mesh epoch hopping + O(W) spiral window lookup
    let cfg = MeshConfig::standard();
    let custody = make_custody(&cfg);
    let alice_hw = VirtualHardwareEnclave::random().unwrap();
    let bob_hw = VirtualHardwareEnclave::random().unwrap();
    let (mut alice, mut bob) =
        CellularMesh::new_paired(cfg.clone(), custody, &alice_hw, &bob_hw).unwrap();

    let epoch0_coords = alice.coords().to_vec();
    let epoch0_sub0 = alice.cubes()[0].sub_matrix.clone();

    let new_epoch = alice.hop_epoch(&alice_hw).unwrap();
    assert_eq!(new_epoch, 1);
    bob.hop_epoch(&bob_hw).unwrap();

    // 100% of coordinates and sub-matrices moved on epoch transition
    assert!(alice
        .coords()
        .iter()
        .zip(epoch0_coords.iter())
        .all(|(a, b)| a != b));
    assert_ne!(alice.cubes()[0].sub_matrix, epoch0_sub0);

    // Windowed spiral search locates slot 42 within spiral_window (16) steps
    let target = alice.coords()[42];
    let (found, inspected) = alice.lookup_spiral_window(35, target);
    assert_eq!(found, Some(42));
    assert!(inspected <= cfg.spiral_window);

    // Peers remain synchronized after epoch hop
    let mut pkt = alice.begin_send_message(&alice_hw, b"post-epoch").unwrap();
    let (pt, ack, _) = bob.receive_authenticated(&bob_hw, &mut pkt).unwrap();
    assert_eq!(pt, b"post-epoch");
    alice.commit_ack(&alice_hw, &ack).unwrap();
}

#[test]
fn test_zero_oracle_honey_encryption_and_anti_desync() {
    let cfg = MeshConfig::standard();
    let custody = make_custody(&cfg);
    let alice_hw = VirtualHardwareEnclave::random().unwrap();
    let bob_hw = VirtualHardwareEnclave::random().unwrap();
    let attacker_hw = VirtualHardwareEnclave::random().unwrap();
    let (mut alice, mut bob) = CellularMesh::new_paired(cfg, custody, &alice_hw, &bob_hw).unwrap();

    let pkt = alice
        .begin_send_message(&alice_hw, b"top secret wallet mnemonic")
        .unwrap();

    // 1. Unauthorized hardware probe -> Honey BIP-39 phrase with valid SHA-256 checksum!
    let outcome_bip39 =
        bob.decrypt_zero_oracle(&attacker_hw, &pkt, HoneyProfile::Bip39ChecksumPhrase);
    match outcome_bip39 {
        ReceiveOutcome::HoneyDeception {
            plausible_output, ..
        } => {
            let phrase = String::from_utf8(plausible_output).expect("valid utf8 mnemonic");
            assert_eq!(phrase.split_whitespace().count(), 12);
            assert!(DteEngine::verify_bip39_like_checksum(&phrase));
        }
        ReceiveOutcome::Authentic { .. } => panic!("attacker hardware must not authenticate"),
    }

    // 2. Tampered packet on legitimate hardware -> Honey Chat output, NO error oracle, NO desync!
    let mut tampered = pkt.clone();
    tampered.packet_mac[0] ^= 0x01;
    let outcome_chat = bob.decrypt_zero_oracle(&bob_hw, &tampered, HoneyProfile::ChatPlaintext);
    match outcome_chat {
        ReceiveOutcome::HoneyDeception {
            plausible_output, ..
        } => {
            let text = String::from_utf8(plausible_output).expect("valid utf8 chat");
            assert!(!text.is_empty());
        }
        ReceiveOutcome::Authentic { .. } => panic!("tampered packet must not authenticate"),
    }

    // 3. Legitimate packet still authenticates cleanly because failed probes never mutate state!
    let outcome_real = bob.decrypt_zero_oracle(&bob_hw, &pkt, HoneyProfile::ChatPlaintext);
    match outcome_real {
        ReceiveOutcome::Authentic { plaintext, ack, .. } => {
            assert_eq!(plaintext, b"top secret wallet mnemonic");
            alice.commit_ack(&alice_hw, &ack).unwrap();
        }
        ReceiveOutcome::HoneyDeception { .. } => panic!("authentic packet must decrypt"),
    }
}

#[test]
fn test_full_duplex_concurrent_chat_session() {
    let cfg = MeshConfig::standard();
    let c_ab = make_custody(&cfg);
    let c_ba = make_custody(&cfg);
    let alice_hw = VirtualHardwareEnclave::random().unwrap();
    let bob_hw = VirtualHardwareEnclave::random().unwrap();

    let (mut alice, mut bob) =
        DuplexCubeSession::new_paired(cfg, c_ab, c_ba, &alice_hw, &bob_hw).unwrap();

    // Concurrent bidirectional flight without TX/RX state collision
    let mut a_pkt = alice
        .begin_send_message(&alice_hw, b"Alice: hello Bob!")
        .unwrap();
    let mut b_pkt = bob
        .begin_send_message(&bob_hw, b"Bob: hello Alice!")
        .unwrap();

    let (pt_at_bob, ack_for_alice, _) = bob.receive_authenticated(&bob_hw, &mut a_pkt).unwrap();
    let (pt_at_alice, ack_for_bob, _) = alice.receive_authenticated(&alice_hw, &mut b_pkt).unwrap();

    assert_eq!(pt_at_bob, b"Alice: hello Bob!");
    assert_eq!(pt_at_alice, b"Bob: hello Alice!");

    alice.commit_ack(&alice_hw, &ack_for_alice).unwrap();
    bob.commit_ack(&bob_hw, &ack_for_bob).unwrap();
}

#[test]
fn test_wire_serialization_and_subcube_layout() {
    let cfg = MeshConfig::standard();
    let custody = make_custody(&cfg);
    let alice_hw = VirtualHardwareEnclave::random().unwrap();
    let bob_hw = VirtualHardwareEnclave::random().unwrap();
    let (mut alice, mut bob) = CellularMesh::new_paired(cfg, custody, &alice_hw, &bob_hw).unwrap();

    // Verify Section 7 SubCube TryFrom layout matches standard 32B / 125B cube
    let sub_cube = cubehash_core::SubCube::try_from(&alice.cubes()[0]).unwrap();
    assert_eq!(sub_cube.core_256b.len(), 32);
    assert_eq!(sub_cube.sub_1000b.len(), 125);
    let sub_json = serde_json::to_string(&sub_cube).unwrap();
    let sub_roundtrip: cubehash_core::SubCube = serde_json::from_str(&sub_json).unwrap();
    assert_eq!(sub_roundtrip.cube_uid, sub_cube.cube_uid);

    // Serialize WirePacket + DeliveryAck over simulated JSON network transport
    let pkt = alice
        .begin_send_message(&alice_hw, b"json-transport-frame")
        .unwrap();
    let pkt_wire_bytes = serde_json::to_vec(&pkt).unwrap();
    let mut rx_pkt: cubehash_core::WirePacket = serde_json::from_slice(&pkt_wire_bytes).unwrap();

    let (pt, ack, _) = bob.receive_authenticated(&bob_hw, &mut rx_pkt).unwrap();
    assert_eq!(pt, b"json-transport-frame");

    let ack_wire_bytes = serde_json::to_vec(&ack).unwrap();
    let rx_ack: cubehash_core::DeliveryAck = serde_json::from_slice(&ack_wire_bytes).unwrap();
    alice.commit_ack(&alice_hw, &rx_ack).unwrap();
}

#[test]
fn test_os_hardware_provider_and_all_time_algorithms() {
    let cfg = MeshConfig {
        sub_matrix_bytes: 160,
        core_bytes: 40,
        weight_min_bytes: 20,
        weight_max_bytes: 48,
        mesh_size: 48,
        quorum_select: 16,
        consume_for_next: 12,
        space_dim: 500,
        spiral_window: 10,
        decoy_chain_count: 6,
        fixed_step_budget: 3,
        variable_wire_padding: true,
    };
    cfg.validate().unwrap();

    for (idx, algo) in [
        TimeAlgorithm::Blake2b,
        TimeAlgorithm::Sha3_256,
        TimeAlgorithm::HmacSha256,
        TimeAlgorithm::HybridTriMix,
    ]
    .into_iter()
    .enumerate()
    {
        let custody = ThreeCubeCustody::generate(
            algo,
            CombiningFn::HmacTreeCombine,
            cfg.quorum_select,
            cfg.consume_for_next,
        )
        .unwrap();
        let alice_hw =
            OsBoundHardwareProvider::from_host_and_secret(&[0x33 + idx as u8; 32], b"alice");
        let bob_hw = OsBoundHardwareProvider::from_host_and_secret(&[0x77 + idx as u8; 32], b"bob");
        let (mut alice, mut bob) =
            CellularMesh::new_paired(cfg.clone(), custody, &alice_hw, &bob_hw).unwrap();

        let mut pkt = alice
            .begin_send_raw_core(&alice_hw, b"custom-40B-core-msg")
            .unwrap();
        let (pt, ack, _) = bob.receive_authenticated(&bob_hw, &mut pkt).unwrap();
        assert_eq!(pt, b"custom-40B-core-msg");
        alice.commit_ack(&alice_hw, &ack).unwrap();
    }
}

#[test]
fn test_dh_ratchet_forward_post_compromise_and_tamper_resistance() {
    let cfg = MeshConfig::standard();
    let custody = make_custody(&cfg);
    let alice_hw = VirtualHardwareEnclave::random().unwrap();
    let bob_hw = VirtualHardwareEnclave::random().unwrap();
    let (mut alice, mut bob) = CellularMesh::new_paired(cfg, custody, &alice_hw, &bob_hw).unwrap();

    // Independent X25519 keys on Alice and Bob from genesis
    assert_ne!(alice.local_dh_pub(), bob.local_dh_pub());

    let mut pkt1 = alice.begin_send_message(&alice_hw, b"msg-one").unwrap();
    let rpub1 = pkt1.ratchet_pub;
    let (_, ack1, _) = bob.receive_authenticated(&bob_hw, &mut pkt1).unwrap();
    let bob_pub_after_1 = ack1.next_ratchet_pub;
    assert_eq!(bob.local_dh_pub(), bob_pub_after_1);
    alice.commit_ack(&alice_hw, &ack1).unwrap();

    // Next packet uses Bob's rotated public key and Alice generates a brand-new ephemeral X25519 key
    let mut pkt2 = alice.begin_send_message(&alice_hw, b"msg-two").unwrap();
    assert_ne!(pkt2.ratchet_pub, rpub1);

    // Tampering with WirePacket.ratchet_pub alters algo_key -> wire TMR rejects and zero-oracle emits Honey
    let mut bad_rpub_pkt = pkt2.clone();
    bad_rpub_pkt.ratchet_pub[0] ^= 0xFF;
    assert_eq!(
        bob.receive_authenticated(&bob_hw, &mut bad_rpub_pkt),
        Err(CubeHashError::UnrecoverableCorruption)
    );
    assert!(matches!(
        bob.decrypt_zero_oracle(&bob_hw, &bad_rpub_pkt, HoneyProfile::ChatPlaintext),
        ReceiveOutcome::HoneyDeception { .. }
    ));

    // Non-contributory all-zero ratchet_pub fails cleanly
    let mut zero_rpub_pkt = pkt2.clone();
    zero_rpub_pkt.ratchet_pub = [0u8; 32];
    assert_eq!(
        bob.receive_authenticated(&bob_hw, &mut zero_rpub_pkt),
        Err(CubeHashError::AuthenticationFailed)
    );

    let (pt2, mut ack2, _) = bob.receive_authenticated(&bob_hw, &mut pkt2).unwrap();
    assert_eq!(pt2, b"msg-two");
    assert_ne!(ack2.next_ratchet_pub, bob_pub_after_1);

    // Tampering with DeliveryAck.next_ratchet_pub fails ACK MAC verification cleanly
    ack2.next_ratchet_pub[3] ^= 0x01;
    assert_eq!(
        alice.commit_ack(&alice_hw, &ack2),
        Err(CubeHashError::AckMismatch)
    );
    ack2.next_ratchet_pub[3] ^= 0x01;
    alice.commit_ack(&alice_hw, &ack2).unwrap();

    // Synchronized DH-ratcheted Epoch Hop rotates both sides forward without breaking sync
    let (new_ep, epoch_pub) = alice.hop_epoch_ratchet_tx(&alice_hw).unwrap();
    assert_eq!(new_ep, 1);
    assert_eq!(
        bob.hop_epoch_ratchet_rx(&bob_hw, new_ep, epoch_pub)
            .unwrap(),
        1
    );

    let mut pkt3 = alice
        .begin_send_message(&alice_hw, b"post-dh-epoch")
        .unwrap();
    let (pt3, ack3, _) = bob.receive_authenticated(&bob_hw, &mut pkt3).unwrap();
    assert_eq!(pt3, b"post-dh-epoch");
    alice.commit_ack(&alice_hw, &ack3).unwrap();
}

#[test]
fn test_zero_oracle_constant_work_never_mutates_on_any_failure() {
    let cfg = MeshConfig::standard();
    let custody = make_custody(&cfg);
    let alice_hw = VirtualHardwareEnclave::random().unwrap();
    let bob_hw = VirtualHardwareEnclave::random().unwrap();
    let attacker_hw = VirtualHardwareEnclave::random().unwrap();
    let (mut alice, mut bob) = CellularMesh::new_paired(cfg, custody, &alice_hw, &bob_hw).unwrap();

    let pkt = alice
        .begin_send_message(&alice_hw, b"sensitive-payload")
        .unwrap();
    let tick_before = bob.clock_guard_mut().local_monotonic_tick;
    let dh_before = bob.local_dh_pub();

    // 1. Malformed wire dimensions probe
    let mut bad_dim = pkt.clone();
    bad_dim.wire_cube.partial_256b.truncate(5);
    assert!(matches!(
        bob.decrypt_zero_oracle(&bob_hw, &bad_dim, HoneyProfile::Bip39ChecksumPhrase),
        ReceiveOutcome::HoneyDeception { .. }
    ));

    // 2. Wrong hardware probe
    assert!(matches!(
        bob.decrypt_zero_oracle(&attacker_hw, &pkt, HoneyProfile::ChatPlaintext),
        ReceiveOutcome::HoneyDeception { .. }
    ));

    // 3. Stale sequence probe
    let mut wrong_seq = pkt.clone();
    wrong_seq.sequence = 99;
    assert!(matches!(
        bob.decrypt_zero_oracle(&bob_hw, &wrong_seq, HoneyProfile::RawUniform { len: 32 }),
        ReceiveOutcome::HoneyDeception { .. }
    ));

    // Verify ZERO state mutation (not even monotonic clock tick!) after all probes
    assert_eq!(bob.clock_guard_mut().local_monotonic_tick, tick_before);
    assert_eq!(bob.local_dh_pub(), dh_before);
    assert_eq!(bob.sequence(), 0);

    // Authentic decrypt still works seamlessly
    match bob.decrypt_zero_oracle(&bob_hw, &pkt, HoneyProfile::ChatPlaintext) {
        ReceiveOutcome::Authentic { plaintext, ack, .. } => {
            assert_eq!(plaintext, b"sensitive-payload");
            assert_eq!(bob.clock_guard_mut().local_monotonic_tick, tick_before + 1);
            alice.commit_ack(&alice_hw, &ack).unwrap();
        }
        ReceiveOutcome::HoneyDeception { .. } => panic!("authentic packet rejected"),
    }
}

fn bit_hamming_distance(a: &[u8], b: &[u8]) -> usize {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| (x ^ y).count_ones() as usize)
        .sum()
}

#[test]
fn test_avalanche_sac_chi_square_and_baseline_indistinguishability() {
    // 1. Strict Avalanche Criterion (SAC) on fixed_budget_mix (1-bit input & key flip)
    let key = [0x5Au8; 32];
    let mut base_msg = [0x3Cu8; 64];
    let base_digest = fixed_budget_mix(TimeAlgorithm::HybridTriMix, &key, b"sac", &base_msg, 4);

    let mut total_flips = 0usize;
    let trials = 200usize;
    for trial in 0..trials {
        let bit_pos = trial % (base_msg.len() * 8);
        base_msg[bit_pos / 8] ^= 1u8 << (bit_pos % 8);
        let flipped_digest =
            fixed_budget_mix(TimeAlgorithm::HybridTriMix, &key, b"sac", &base_msg, 4);
        base_msg[bit_pos / 8] ^= 1u8 << (bit_pos % 8);
        total_flips += bit_hamming_distance(&base_digest, &flipped_digest);
    }
    let mean_sac = total_flips as f64 / (trials as f64 * 256.0);
    assert!(
        (0.45..=0.55).contains(&mean_sac),
        "SAC mean flip ratio outside 0.45..=0.55: {mean_sac:.4}"
    );

    // 2. Compare 64 KiB statistical uniformity of CubeHash ciphertext stream vs SHA-256 & XChaCha20-Poly1305
    let cfg = MeshConfig::standard();
    let custody = make_custody(&cfg);
    let alice_hw = VirtualHardwareEnclave::random().unwrap();
    let bob_hw = VirtualHardwareEnclave::random().unwrap();
    let (mut alice, mut bob) = CellularMesh::new_paired(cfg, custody, &alice_hw, &bob_hw).unwrap();

    // Repetitive predictable plaintext (all zeroes + sequential tag) must produce uniform wire ciphertext
    let mut cubehash_stream = Vec::with_capacity(68 * 1024);
    let plain_block = vec![0u8; 1024];
    while cubehash_stream.len() < 65_536 {
        let mut pkt = alice.begin_send_message(&alice_hw, &plain_block).unwrap();
        cubehash_stream.extend_from_slice(&pkt.wire_cube.partial_256b);
        cubehash_stream.extend_from_slice(&pkt.packet_mac);
        if let PayloadMode::ArbitraryCiphertext { ref ciphertext } = pkt.payload_mode {
            cubehash_stream.extend_from_slice(ciphertext);
        }
        let (_, ack, _) = bob.receive_authenticated(&bob_hw, &mut pkt).unwrap();
        alice.commit_ack(&alice_hw, &ack).unwrap();
    }
    cubehash_stream.truncate(65_536);

    let mut std_aead_stream = Vec::with_capacity(68 * 1024);
    let std_key = [0x42u8; 32];
    let mut counter = 0u64;
    while std_aead_stream.len() < 65_536 {
        let mut nonce = [0u8; 24];
        nonce[..8].copy_from_slice(&counter.to_le_bytes());
        let ct = aead_seal(&std_key, &nonce, b"baseline", &plain_block).unwrap();
        std_aead_stream.extend_from_slice(&ct);
        counter += 1;
    }
    std_aead_stream.truncate(65_536);

    let mut sha2_stream = Vec::with_capacity(65_536);
    for blk in 0..2048u64 {
        let digest = Sha256::digest(blk.to_le_bytes());
        sha2_stream.extend_from_slice(&digest);
    }

    for (label, sample) in [
        ("CubeHash-64KiB", cubehash_stream.as_slice()),
        ("XChaCha20-Poly1305-64KiB", std_aead_stream.as_slice()),
        ("SHA-256-64KiB", sha2_stream.as_slice()),
    ] {
        let ratio = ones_ratio(sample);
        let entropy = shannon_entropy_bits_per_byte(sample);
        let chi2 = pearson_chi_square_uniform(sample);
        let ac = lag1_bit_autocorrelation(sample);
        assert!(
            (0.49..=0.51).contains(&ratio),
            "{label} bit ratio out of bounds: {ratio:.5}"
        );
        assert!(
            entropy > 7.99,
            "{label} Shannon entropy below 7.99 b/B: {entropy:.5}"
        );
        assert!(
            chi2 < 330.5,
            "{label} chi-square exceeded p=0.001 critical bound (330.5): {chi2:.2}"
        );
        assert!(
            ac.abs() < 0.02,
            "{label} lag-1 bit autocorrelation too high: {ac:.5}"
        );
    }
}

#[test]
fn test_hybrid_trimix_combiner_strength_and_non_degeneracy() {
    let key = [0xA5u8; 32];
    let input = [0u8; 128];

    let h_blake = fixed_budget_mix(TimeAlgorithm::Blake2b, &key, b"dom", &input, 4);
    let h_sha3 = fixed_budget_mix(TimeAlgorithm::Sha3_256, &key, b"dom", &input, 4);
    let h_hmac = fixed_budget_mix(TimeAlgorithm::HmacSha256, &key, b"dom", &input, 4);
    let h_hybrid = fixed_budget_mix(TimeAlgorithm::HybridTriMix, &key, b"dom", &input, 4);

    // Exact algebraic identity: HybridTriMix_i = BLAKE_i ^ rotl(SHA3_i, 3) ^ rotr(HMAC_i, 5)
    for i in 0..32 {
        assert_eq!(
            h_hybrid[i],
            h_blake[i] ^ h_sha3[i].rotate_left(3) ^ h_hmac[i].rotate_right(5)
        );
    }

    // Domain separation & non-degeneracy against standalone standard SHA3-256 / BLAKE2b / HMAC
    let mut b2 = Blake2b512::new();
    b2.update(input);
    let b2_raw = &b2.finalize()[..32];
    let s3_raw = Sha3_256::digest(input);
    let hm_raw = hmac_sha256(&key, &input);
    assert_ne!(h_hybrid.as_slice(), b2_raw);
    assert_ne!(h_hybrid.as_slice(), s3_raw.as_slice());
    assert_ne!(h_hybrid.as_slice(), &hm_raw);

    // 1-bit flip in domain & key produces ~50% Hamming transition
    let h_dom2 = fixed_budget_mix(TimeAlgorithm::HybridTriMix, &key, b"don", &input, 4);
    let mut key2 = key;
    key2[0] ^= 0x01;
    let h_key2 = fixed_budget_mix(TimeAlgorithm::HybridTriMix, &key2, b"dom", &input, 4);

    let dom_flip = bit_hamming_distance(&h_hybrid, &h_dom2) as f64 / 256.0;
    let key_flip = bit_hamming_distance(&h_hybrid, &h_key2) as f64 / 256.0;
    assert!((0.35..=0.65).contains(&dom_flip), "dom_flip={dom_flip:.3}");
    assert!((0.35..=0.65).contains(&key_flip), "key_flip={key_flip:.3}");
}

#[test]
fn test_system_level_decrypt_zero_oracle_timing_consistency() {
    let cfg = MeshConfig::standard();
    let custody = make_custody(&cfg);
    let alice_hw = VirtualHardwareEnclave::random().unwrap();
    let bob_hw = VirtualHardwareEnclave::random().unwrap();
    let wrong_hw = VirtualHardwareEnclave::random().unwrap();

    let samples = 64usize;
    let mut auth_pairs: Vec<(CellularMesh, WirePacket)> = Vec::with_capacity(samples);
    for i in 0..samples {
        let (mut a, b) =
            CellularMesh::new_paired(cfg.clone(), custody.clone(), &alice_hw, &bob_hw).unwrap();
        let pkt = a
            .begin_send_message(&alice_hw, format!("timing-sample-{i:04}").as_bytes())
            .unwrap();
        auth_pairs.push((b, pkt));
    }
    let (_, mut bob_probe) = CellularMesh::new_paired(cfg, custody, &alice_hw, &bob_hw).unwrap();

    let probe_template = auth_pairs[0].1.clone();
    let mut bad_mac_pkt = probe_template.clone();
    bad_mac_pkt.packet_mac[0] ^= 0xFF;
    let mut bad_seq_pkt = probe_template.clone();
    bad_seq_pkt.sequence = 999;
    let mut bad_dim_pkt = probe_template.clone();
    bad_dim_pkt.wire_cube.partial_256b.truncate(4);

    // Warmup CPU & caches
    for _ in 0..8 {
        let _ = bob_probe.decrypt_zero_oracle(&bob_hw, &bad_mac_pkt, HoneyProfile::ChatPlaintext);
    }

    let mut t_auth = Vec::with_capacity(samples);
    let mut t_bad_mac = Vec::with_capacity(samples);
    let mut t_wrong_hw = Vec::with_capacity(samples);
    let mut t_bad_seq = Vec::with_capacity(samples);
    let mut t_bad_dim = Vec::with_capacity(samples);

    for (mut bob_i, pkt) in auth_pairs {
        let s0 = Instant::now();
        let out_a = bob_i.decrypt_zero_oracle(&bob_hw, &pkt, HoneyProfile::ChatPlaintext);
        t_auth.push(s0.elapsed().as_nanos() as u64);
        assert!(matches!(out_a, ReceiveOutcome::Authentic { .. }));

        let s1 = Instant::now();
        let out_m =
            bob_probe.decrypt_zero_oracle(&bob_hw, &bad_mac_pkt, HoneyProfile::ChatPlaintext);
        t_bad_mac.push(s1.elapsed().as_nanos() as u64);
        assert!(matches!(out_m, ReceiveOutcome::HoneyDeception { .. }));

        let s2 = Instant::now();
        let out_h =
            bob_probe.decrypt_zero_oracle(&wrong_hw, &probe_template, HoneyProfile::ChatPlaintext);
        t_wrong_hw.push(s2.elapsed().as_nanos() as u64);
        assert!(matches!(out_h, ReceiveOutcome::HoneyDeception { .. }));

        let s3 = Instant::now();
        let out_s =
            bob_probe.decrypt_zero_oracle(&bob_hw, &bad_seq_pkt, HoneyProfile::ChatPlaintext);
        t_bad_seq.push(s3.elapsed().as_nanos() as u64);
        assert!(matches!(out_s, ReceiveOutcome::HoneyDeception { .. }));

        let s4 = Instant::now();
        let out_d =
            bob_probe.decrypt_zero_oracle(&bob_hw, &bad_dim_pkt, HoneyProfile::ChatPlaintext);
        t_bad_dim.push(s4.elapsed().as_nanos() as u64);
        assert!(matches!(out_d, ReceiveOutcome::HoneyDeception { .. }));
    }

    let median = |v: &mut Vec<u64>| -> f64 {
        v.sort_unstable();
        v[v.len() / 2] as f64
    };
    let m_auth = median(&mut t_auth).max(1.0);
    for (label, mut vec) in [
        ("bad_mac", t_bad_mac),
        ("wrong_hw", t_wrong_hw),
        ("bad_seq", t_bad_seq),
        ("bad_dim", t_bad_dim),
    ] {
        let ratio = median(&mut vec) / m_auth;
        assert!(
            (0.25..=2.5).contains(&ratio),
            "system-level timing discrepancy on {label}: ratio={ratio:.2} vs authentic"
        );
    }
}

#[test]
fn test_complete_hybrid_trimix_engine_256_512_xof_streaming_and_mac() {
    let key = [0x4Eu8; 32];
    let domain = b"htx2-formal-verification";
    let msg: Vec<u8> = (0..1337u32)
        .map(|i| (i.wrapping_mul(31) ^ 0xA5) as u8)
        .collect();

    // 1. Independent leg subkeys (no reuse across BLAKE2b / SHA3 / HMAC)
    let (kb, ks, kh) = HybridTriMix::derive_subkeys(&key, domain);
    assert_ne!(kb, ks);
    assert_ne!(ks, kh);
    assert_ne!(kb, kh);

    // 2. Canonical length-delimited framing immunity against split-boundary collisions
    assert_ne!(
        HybridTriMix::mix_256(b"ab", b"c", &msg, 2),
        HybridTriMix::mix_256(b"a", b"bc", &msg, 2)
    );

    // 3. Bit-exact streaming parity across irregular chunk sizes for both 256-bit and 512-bit modes
    let one_shot_256 = HybridTriMix::mix_256(&key, domain, &msg, 3);
    let one_shot_512 = HybridTriMix::digest_512(&key, domain, &msg, 3);

    let mut hasher_256 = HybridTriMix::new_hasher(&key, domain);
    let mut hasher_512 = HybridTriMix::new_hasher(&key, domain);
    let mut offset = 0usize;
    for &sz in &[1usize, 7, 63, 255, 512, 9999] {
        if offset >= msg.len() {
            break;
        }
        let end = (offset + sz).min(msg.len());
        hasher_256.update(&msg[offset..end]);
        hasher_512.update(&msg[offset..end]);
        offset = end;
    }
    assert_eq!(hasher_256.finalize_256(3), one_shot_256);
    assert_eq!(hasher_512.finalize_512(3), one_shot_512);

    // 4. Constant-time MAC verification rejects any 1-bit forgery
    assert!(HybridTriMix::verify_tag_256(
        &key,
        domain,
        &msg,
        3,
        &one_shot_256
    ));
    let mut forged = one_shot_256;
    forged[15] ^= 0x01;
    assert!(!HybridTriMix::verify_tag_256(
        &key, domain, &msg, 3, &forged
    ));

    // 5. Unkeyed 512-bit combiner is distinct from bare BLAKE2b-512 & SHA3-512
    let u512 = HybridTriMix::hash_unkeyed_512(domain, &msg);
    let raw_b2: [u8; 64] = Blake2b512::digest(&msg).into();
    let raw_s3_512: [u8; 64] = Sha3_512::digest(&msg).into();
    assert_ne!(u512, raw_b2);
    assert_ne!(u512, raw_s3_512);

    // 6. 64 KiB Extendable Output Function (XOF) passes full uniformity & independence statistics
    let mut xof = vec![0u8; 65_536];
    HybridTriMix::expand_xof(&key, domain, b"stream-64k", &mut xof);
    let ratio = ones_ratio(&xof);
    let entropy = shannon_entropy_bits_per_byte(&xof);
    let chi2 = pearson_chi_square_uniform(&xof);
    let ac = lag1_bit_autocorrelation(&xof);
    assert!((0.49..=0.51).contains(&ratio), "xof ones_ratio={ratio}");
    assert!(entropy > 7.99, "xof entropy={entropy}");
    assert!(chi2 < 330.5, "xof chi2={chi2}");
    assert!(ac.abs() < 0.02, "xof lag1={ac}");
}

#[test]
fn test_two_tier_high_throughput_ratchet_and_forward_secrecy() {
    let cfg = MeshConfig::standard();
    let custody = make_custody(&cfg);
    let alice_hw = VirtualHardwareEnclave::random().unwrap();
    let bob_hw = VirtualHardwareEnclave::random().unwrap();
    let (mut alice, mut bob) =
        CellularMesh::new_paired(cfg.clone(), custody, &alice_hw, &bob_hw).unwrap();

    alice.set_dh_rekey_interval(16);
    bob.set_dh_rekey_interval(16);
    assert_eq!(alice.dh_rekey_interval(), 16);

    let mut seen_macs = HashSet::new();
    let mut bob_pub_history = Vec::new();
    let initial_bob_pub = bob.local_dh_pub();

    // Send 40 messages spanning 3 DH rekey boundaries: seq 1, 17, 33
    for seq in 1..=40u64 {
        let mut pkt = alice
            .begin_send_message(&alice_hw, b"identical-high-throughput-frame")
            .unwrap();
        assert!(seen_macs.insert(pkt.packet_mac));

        // Corrupt 40 bits on intermediate symmetric frames too -> TMR must still self-heal
        if seq == 5 {
            for b in &mut pkt.wire_cube.partial_256b[..5] {
                *b ^= 0xFF;
            }
        }

        // Tampering ratchet_pub on an intermediate fast frame must fail cleanly and zero-oracle must hide
        if seq == 10 {
            let mut tampered = pkt.clone();
            tampered.ratchet_pub[0] ^= 0x01;
            assert_eq!(
                bob.receive_authenticated(&bob_hw, &mut tampered),
                Err(CubeHashError::AuthenticationFailed)
            );
            assert!(matches!(
                bob.decrypt_zero_oracle(&bob_hw, &tampered, HoneyProfile::ChatPlaintext),
                ReceiveOutcome::HoneyDeception { .. }
            ));
        }

        let (pt, ack, healed) = bob.receive_authenticated(&bob_hw, &mut pkt).unwrap();
        assert_eq!(pt, b"identical-high-throughput-frame");
        if seq == 5 {
            assert_eq!(healed, 40);
        }
        alice.commit_ack(&alice_hw, &ack).unwrap();

        if (seq - 1) % 16 == 0 {
            // Every DH boundary must rotate Bob's Curve25519 keypair to a brand-new key
            assert_ne!(bob.local_dh_pub(), initial_bob_pub);
            bob_pub_history.push(bob.local_dh_pub());
        } else {
            // Intermediate frames advance symmetric HybridTriMix chain without expensive ECDH
            assert_eq!(bob.local_dh_pub(), *bob_pub_history.last().unwrap());
        }
    }

    assert_eq!(bob_pub_history.len(), 3);
    assert_ne!(bob_pub_history[0], bob_pub_history[1]);
    assert_ne!(bob_pub_history[1], bob_pub_history[2]);

    // Rollback cleanly preserves fast-ratchet synchronization
    let _lost = alice
        .begin_send_message(&alice_hw, b"dropped-fast-frame")
        .unwrap();
    alice.rollback_outbound().unwrap();
    let mut recovery_pkt = alice
        .begin_send_message(&alice_hw, b"recovered-fast-frame")
        .unwrap();
    let (pt, ack, _) = bob
        .receive_authenticated(&bob_hw, &mut recovery_pkt)
        .unwrap();
    assert_eq!(pt, b"recovered-fast-frame");
    alice.commit_ack(&alice_hw, &ack).unwrap();
}
