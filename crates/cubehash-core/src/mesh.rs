use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::config::{MeshConfig, FINGERPRINT_BYTES};
use crate::custody::{
    AuditorCube, HardwareProvider, LocalClientClockGuard, MainCube, MotherCube, ThreeCubeCustody,
};
use crate::error::{CubeHashError, Result};
use crate::honey::{generate_decoy_cubes, DteEngine, HoneyProfile};
use crate::primitives::{
    aead_open, aead_seal, combine_non_linear, constant_time_eq, fill_random, fixed_budget_mix,
    hkdf_expand_label, hmac_sha256_parts, whitened_stream,
};
use crate::spiral::{Coord3D, SpiralSpace};
use crate::voxel::{encode_sub_matrix_with_shadows, generate_variable_weight, VoxelCube};

const CORE_FLAG_RAW: u8 = 0x01;
const CORE_FLAG_AEAD: u8 = 0x02;

/// One-time ephemeral algorithm synthesized in-register upon cube arrival (`Section 5` & `7`).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EphemeralCubeAlgorithm {
    pub algo_key: [u8; 32],
    pub rotation_profile: Vec<u32>,
    pub selected_indices: Vec<usize>,
}

/// Incomplete wire cube (~173 bytes base + optional variable padding) sent across the network (`Section 5` & `7`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UniqueWireCube {
    pub cube_fingerprint: [u8; FINGERPRINT_BYTES],
    pub partial_256b: Vec<u8>,
    pub partial_1000b: Vec<u8>,
    pub weight_padding: Vec<u8>,
}

impl UniqueWireCube {
    /// Base wire size without variable weight padding (`173` bytes in standard config).
    pub fn base_byte_len(&self) -> usize {
        self.cube_fingerprint.len() + self.partial_256b.len() + self.partial_1000b.len()
    }

    /// Total wire size including variable weight padding.
    pub fn total_byte_len(&self) -> usize {
        self.base_byte_len() + self.weight_padding.len()
    }
}

/// Dual-mode wire payload container supporting both compact 256-bit core data and
/// arbitrary-length AEAD-protected messages (chat, files, IPC frames).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PayloadMode {
    /// Payload lives directly inside `wire_cube.partial_256b` + `partial_1000b` TMR shadows.
    RawCore256,
    /// Arbitrary-length payload encrypted via `XChaCha20-Poly1305` under the cube-synthesized key.
    ArbitraryCiphertext { ciphertext: Vec<u8> },
}

/// Complete network frame emitted by `CellularMesh::begin_send_*`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WirePacket {
    pub wire_cube: UniqueWireCube,
    pub sequence: u64,
    pub epoch: u64,
    pub ratchet_pub: [u8; 32],
    pub payload_mode: PayloadMode,
    pub packet_mac: [u8; 32],
}

/// Cryptographic acknowledgment emitted by receiver and required by sender to commit state (`Section 5`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryAck {
    pub cube_fingerprint: [u8; FINGERPRINT_BYTES],
    pub sequence: u64,
    pub new_generation: u64,
    pub next_ratchet_pub: [u8; 32],
    pub ack_mac: [u8; 32],
}

/// Outcome of zero-oracle inspection (`decrypt_zero_oracle`), never leaking cryptographic errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiveOutcome {
    Authentic {
        plaintext: Vec<u8>,
        ack: DeliveryAck,
        healed_bits: usize,
    },
    HoneyDeception {
        plausible_output: Vec<u8>,
        profile: HoneyProfile,
    },
}

/// Runtime audit metrics for verifying RAM footprint, entropy, and 50/50 bit balance.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeshAuditStats {
    pub mesh_size: usize,
    pub approx_ram_bytes: usize,
    pub epoch: u64,
    pub sequence: u64,
    pub avg_ones_ratio: f64,
    pub avg_entropy_bits_per_byte: f64,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct DhRatchetState {
    local_dh_secret: [u8; 32],
    local_dh_pub: [u8; 32],
    peer_dh_pub: [u8; 32],
    chain_key: [u8; 32],
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct PendingTransition {
    cube_fingerprint: [u8; FINGERPRINT_BYTES],
    next_sequence: u64,
    kill_idx: usize,
    born_cube: VoxelCube,
    #[zeroize(skip)]
    born_coord: Coord3D,
    next_main_root: [u8; 32],
    ack_mac_key: [u8; 32],
    dh_out: [u8; 32],
}

/// Synchronized 100-cube cellular cryptography mesh (`Section 5`) with per-message X25519 DH Ratchet.
pub struct CellularMesh {
    config: MeshConfig,
    cubes: Vec<VoxelCube>,
    coords: Vec<Coord3D>,
    decoys: Vec<VoxelCube>,
    custody: ThreeCubeCustody,
    clock_guard: LocalClientClockGuard,
    ratchet: DhRatchetState,
    epoch: u64,
    sequence: u64,
    pending_outbound: Option<PendingTransition>,
}

impl CellularMesh {
    /// Provisions a single peer's hardware-bound `CellularMesh` from shared custody & genesis seed.
    ///
    /// Two peers calling `provision_device` with identical `config`, `custody`, and `shared_mesh_seed`,
    /// each binding to their own `HardwareProvider`, start synchronized while keeping hardware locks
    /// strictly bound to their own physical devices. On the very first ACK/DH step, receiver keys
    /// rotate to independent OS CSPRNG X25519 keypairs for Post-Compromise Security.
    pub fn provision_device(
        config: MeshConfig,
        custody: ThreeCubeCustody,
        hw: &dyn HardwareProvider,
        shared_mesh_seed: &[u8; 32],
    ) -> Result<Self> {
        config.validate()?;
        if custody.auditor.quorum_select != config.quorum_select
            || custody.auditor.consume_for_next != config.consume_for_next
        {
            return Err(CubeHashError::InvalidConfig(
                "AuditorCube quorum parameters do not match MeshConfig",
            ));
        }

        let mut root_cap = custody.derive_root_capability(config.fixed_step_budget);
        let mut raw_hw_secret = [0u8; 32];
        fill_random(&mut raw_hw_secret)?;
        let clock_guard = LocalClientClockGuard::seal_new(hw, &raw_hw_secret)?;
        raw_hw_secret.zeroize();

        let epoch_key = Self::derive_epoch_key(&root_cap, &custody.main.chain_id, 0);
        let spiral = SpiralSpace::new(config.space_dim, custody.auditor.spiral_coeffs);

        let mut cubes = Vec::with_capacity(config.mesh_size);
        let mut coords = Vec::with_capacity(config.mesh_size);
        for slot in 0..config.mesh_size {
            let cube_seed = hmac_sha256_parts(
                shared_mesh_seed,
                &[b"init-mesh-cube", &custody.main.chain_id, &(slot as u64).to_le_bytes()],
            );
            let cube = VoxelCube::generate_mesh_cube(&config, &root_cap, 0, &cube_seed)?;
            coords.push(spiral.spiral_arm_coord(&epoch_key, 0, slot));
            cubes.push(cube);
        }

        let decoy_seed = hmac_sha256_parts(&root_cap, &[b"decoy-root", &custody.main.chain_id]);
        let decoys = generate_decoy_cubes(&config, &decoy_seed, &cubes);
        root_cap.zeroize();

        let init_dh_secret =
            hmac_sha256_parts(shared_mesh_seed, &[b"init-dh-ratchet-sk", &custody.main.chain_id]);
        let init_dh_pub = PublicKey::from(&StaticSecret::from(init_dh_secret)).to_bytes();
        let init_chain_key =
            hmac_sha256_parts(shared_mesh_seed, &[b"init-dh-chain", &custody.main.chain_id]);

        Ok(Self {
            config,
            cubes,
            coords,
            decoys,
            custody,
            clock_guard,
            ratchet: DhRatchetState {
                local_dh_secret: init_dh_secret,
                local_dh_pub: init_dh_pub,
                peer_dh_pub: init_dh_pub,
                chain_key: init_chain_key,
            },
            epoch: 0,
            sequence: 0,
            pending_outbound: None,
        })
    }

    /// Convenience helper creating a synchronized `(Alice -> Bob)` mesh pair with distinct hardware
    /// enclaves and independent OS CSPRNG initial X25519 ratchet keys (zero shared DH private keys).
    pub fn new_paired(
        config: MeshConfig,
        custody: ThreeCubeCustody,
        alice_hw: &dyn HardwareProvider,
        bob_hw: &dyn HardwareProvider,
    ) -> Result<(Self, Self)> {
        let mut shared_mesh_seed = [0u8; 32];
        fill_random(&mut shared_mesh_seed)?;
        let mut alice = Self::provision_device(config.clone(), custody.clone(), alice_hw, &shared_mesh_seed)?;
        let mut bob = Self::provision_device(config, custody, bob_hw, &shared_mesh_seed)?;
        shared_mesh_seed.zeroize();

        let (mut bob_sk, bob_pk) = Self::generate_dh_keypair()?;
        let (mut alice_sk, alice_pk) = Self::generate_dh_keypair()?;
        alice.set_local_dh_keypair(alice_sk, alice_pk)?;
        alice.set_peer_dh_pub(bob_pk)?;
        bob.set_local_dh_keypair(bob_sk, bob_pk)?;
        bob.set_peer_dh_pub(alice_pk)?;
        bob_sk.zeroize();
        alice_sk.zeroize();

        Ok((alice, bob))
    }

    /// Returns this mesh's current local X25519 ratchet public key.
    pub fn local_dh_pub(&self) -> [u8; 32] {
        self.ratchet.local_dh_pub
    }

    /// Sets the peer's current X25519 ratchet public key after verifying it is non-zero.
    pub fn set_peer_dh_pub(&mut self, peer_pub: [u8; 32]) -> Result<()> {
        if constant_time_eq(&peer_pub, &[0u8; 32]) {
            return Err(CubeHashError::InvalidConfig(
                "peer ratchet public key cannot be all-zero",
            ));
        }
        self.ratchet.peer_dh_pub = peer_pub;
        Ok(())
    }

    /// Replaces the local X25519 ratchet secret/public keypair cleanly.
    pub fn set_local_dh_keypair(
        &mut self,
        local_secret: [u8; 32],
        local_pub: [u8; 32],
    ) -> Result<()> {
        if constant_time_eq(&local_pub, &[0u8; 32]) {
            return Err(CubeHashError::InvalidConfig(
                "local ratchet public key cannot be all-zero",
            ));
        }
        self.ratchet.local_dh_secret.zeroize();
        self.ratchet.local_dh_secret = local_secret;
        self.ratchet.local_dh_pub = local_pub;
        Ok(())
    }

    /// Sends compact critical data (up to `core_bytes - 8` = `24` bytes in standard config)
    /// directly inside `UniqueWireCube::partial_256b` with TMR self-healing (`RawCore256` mode).
    ///
    /// Does NOT mutate the committed cellular mesh until [`Self::commit_ack`] succeeds.
    pub fn begin_send_raw_core(
        &mut self,
        hw: &dyn HardwareProvider,
        payload: &[u8],
    ) -> Result<WirePacket> {
        let max_bytes = self.config.raw_core_payload_capacity();
        if payload.len() > max_bytes {
            return Err(CubeHashError::PayloadTooLargeForCore {
                max_bytes,
                actual_bytes: payload.len(),
            });
        }
        self.begin_send_inner(hw, payload, true)
    }

    /// Sends arbitrary-length data (chat messages, files, structured records) encrypted via an
    /// ephemeral cube-derived `XChaCha20-Poly1305` key + variable weight padding (`ArbitraryPayload` mode).
    ///
    /// Does NOT mutate the committed cellular mesh until [`Self::commit_ack`] succeeds.
    pub fn begin_send_message(
        &mut self,
        hw: &dyn HardwareProvider,
        plaintext: &[u8],
    ) -> Result<WirePacket> {
        self.begin_send_inner(hw, plaintext, false)
    }

    /// Commits the staged cellular mutation (`25 select / 20 consume / 1 kill + 1 birth`) and
    /// advances the X25519 DH Ratchet upon receiving a valid [`DeliveryAck`] (`Section 5`).
    pub fn commit_ack(&mut self, hw: &dyn HardwareProvider, ack: &DeliveryAck) -> Result<()> {
        let _exec_token = self.clock_guard.authorize_local_execution(hw)?;
        let pending = self
            .pending_outbound
            .as_ref()
            .ok_or(CubeHashError::NoPendingTransaction)?;

        let expected_ack_mac = Self::compute_ack_mac(
            &pending.ack_mac_key,
            &ack.cube_fingerprint,
            ack.sequence,
            &ack.next_ratchet_pub,
        );
        if !constant_time_eq(&pending.cube_fingerprint, &ack.cube_fingerprint)
            || pending.next_sequence != ack.sequence
            || pending.next_sequence != ack.new_generation
            || constant_time_eq(&ack.next_ratchet_pub, &[0u8; 32])
            || !constant_time_eq(&expected_ack_mac, &ack.ack_mac)
        {
            return Err(CubeHashError::AckMismatch);
        }

        let next_peer_pub = ack.next_ratchet_pub;
        let committed = self.pending_outbound.take().unwrap();
        let next_chain_key = Self::advance_ratchet_chain_key(
            &self.ratchet.chain_key,
            &committed.dh_out,
            &next_peer_pub,
        );
        self.apply_transition(committed);
        self.ratchet.chain_key = next_chain_key;
        self.ratchet.peer_dh_pub = next_peer_pub;
        Ok(())
    }

    /// Cleanly rolls back an unacknowledged outbound transaction (e.g., network drop / timeout),
    /// restoring the exact prior mesh generation without desync (`Section 5`).
    pub fn rollback_outbound(&mut self) -> Result<()> {
        if self.pending_outbound.is_none() {
            return Err(CubeHashError::NoPendingTransaction);
        }
        self.pending_outbound = None;
        Ok(())
    }

    /// Authenticated receive path: verifies hardware lock, heals bit-rot in the wire cube via TMR
    /// Majority Voting, computes X25519 DH ratchet secret, verifies MAC, decrypts payload,
    /// rotates receiver X25519 keypair, commits `25/20/kill/birth`, and emits `DeliveryAck`.
    pub fn receive_authenticated(
        &mut self,
        hw: &dyn HardwareProvider,
        packet: &mut WirePacket,
    ) -> Result<(Vec<u8>, DeliveryAck, usize)> {
        let _exec_token = self.clock_guard.authorize_local_execution(hw)?;
        if packet.epoch != self.epoch || packet.sequence != self.sequence + 1 {
            return Err(CubeHashError::ReplayDetected);
        }
        if packet.wire_cube.partial_256b.len() != self.config.core_bytes
            || packet.wire_cube.partial_1000b.len() != self.config.sub_matrix_bytes
        {
            return Err(CubeHashError::InvalidConfig(
                "wire cube dimensions do not match MeshConfig",
            ));
        }

        let mut root_cap = self.custody.derive_root_capability(self.config.fixed_step_budget);
        let mut dh_out = match Self::dh_exchange(&self.ratchet.local_dh_secret, &packet.ratchet_pub)
        {
            Ok(s) => s,
            Err(e) => {
                root_cap.zeroize();
                return Err(e);
            }
        };
        let mut ratcheted_root =
            Self::derive_ratcheted_root(&root_cap, &self.ratchet.chain_key, &dh_out);
        let algo = self.synthesize_ephemeral_algorithm(
            &ratcheted_root,
            &packet.wire_cube.cube_fingerprint,
            packet.sequence,
            packet.epoch,
        );

        // 1. Self-heal the incoming wire cube BEFORE MAC verification (`Section 4.3`).
        let wire_tmr_key = Self::derive_wire_tmr_key(
            &algo.algo_key,
            &packet.wire_cube.cube_fingerprint,
            packet.sequence,
        );
        let mut wire_voxel = VoxelCube {
            cube_uid: packet.wire_cube.cube_fingerprint,
            generation: packet.sequence,
            sub_matrix: packet.wire_cube.partial_1000b.clone(),
            core_pattern: packet.wire_cube.partial_256b.clone(),
            weight_layer: Vec::new(),
        };
        let heal_report = match wire_voxel.heal_bitwise(&wire_tmr_key) {
            Ok(r) => r,
            Err(e) => {
                root_cap.zeroize();
                ratcheted_root.zeroize();
                dh_out.zeroize();
                return Err(e);
            }
        };
        packet.wire_cube.partial_256b = wire_voxel.core_pattern.clone();
        packet.wire_cube.partial_1000b = wire_voxel.sub_matrix.clone();

        // 2. Verify packet MAC over healed wire cube + sequence + epoch + ratchet_pub + ciphertext.
        let expected_mac = Self::compute_packet_mac(
            &algo.algo_key,
            &packet.wire_cube.cube_fingerprint,
            packet.sequence,
            packet.epoch,
            &packet.ratchet_pub,
            &packet.wire_cube.partial_256b,
            &packet.payload_mode,
        );
        if !constant_time_eq(&expected_mac, &packet.packet_mac) {
            root_cap.zeroize();
            ratcheted_root.zeroize();
            dh_out.zeroize();
            return Err(CubeHashError::AuthenticationFailed);
        }

        // 3. Unmask core_pattern and recover plaintext according to Dual Mode.
        let (payload_ok, plaintext) =
            self.decrypt_payload_uniform(&algo.algo_key, packet, &packet.wire_cube.partial_256b);
        if payload_ok != 1 {
            root_cap.zeroize();
            ratcheted_root.zeroize();
            dh_out.zeroize();
            return Err(CubeHashError::AuthenticationFailed);
        }

        // 4. Stage, rotate local X25519 ratchet keypair, commit cellular transition, and emit DeliveryAck.
        let (mut next_dh_sk, next_dh_pub) = Self::generate_dh_keypair()?;
        let transition = self.build_transition(
            &root_cap,
            &algo,
            packet.wire_cube.cube_fingerprint,
            packet.sequence,
            dh_out,
        )?;
        let ack = DeliveryAck {
            cube_fingerprint: packet.wire_cube.cube_fingerprint,
            sequence: packet.sequence,
            new_generation: packet.sequence,
            next_ratchet_pub: next_dh_pub,
            ack_mac: Self::compute_ack_mac(
                &transition.ack_mac_key,
                &packet.wire_cube.cube_fingerprint,
                packet.sequence,
                &next_dh_pub,
            ),
        };
        self.commit_receive_transition(
            transition,
            next_dh_sk,
            next_dh_pub,
            packet.ratchet_pub,
            &dh_out,
        );
        next_dh_sk.zeroize();
        root_cap.zeroize();
        ratcheted_root.zeroize();
        dh_out.zeroize();

        Ok((
            plaintext,
            ack,
            heal_report.repaired_core_bits + heal_report.repaired_shadow_bits,
        ))
    }

    /// Constant-work, zero-oracle decryption entrypoint (`Section 4.2`):
    /// - Executes the full cryptographic evaluation, cellular transition dry-run, AND DTE decoy
    ///   synthesis uniformly without early returns so authentic vs forged/unauthorized probes
    ///   cannot be distinguished by timing or error side-channels.
    /// - Mutates session state ONLY when all hardware, sequence, TMR, MAC, and AEAD checks pass.
    pub fn decrypt_zero_oracle(
        &mut self,
        hw: &dyn HardwareProvider,
        packet: &WirePacket,
        honey_profile: HoneyProfile,
    ) -> ReceiveOutcome {
        let observed_hw = hw.device_hw_id();
        let mut authentic_mask =
            u8::from(constant_time_eq(&self.clock_guard.device_hw_id, &observed_hw));
        let (unseal_ok, mut unsealed) = match hw
            .unseal_secret(LocalClientClockGuard::SEAL_LABEL, &self.clock_guard.sealed_hw_secret)
        {
            Ok(u) => (1u8, u),
            Err(_) => (0u8, [0u8; 32]),
        };
        authentic_mask &= unseal_ok;
        let (tick_ok, candidate_tick) = match self.clock_guard.local_monotonic_tick.checked_add(1) {
            Some(t) => (1u8, t),
            None => (0u8, self.clock_guard.local_monotonic_tick),
        };
        authentic_mask &= tick_ok;
        let _exec_token = hmac_sha256_parts(
            &unsealed,
            &[&self.clock_guard.device_hw_id, &candidate_tick.to_le_bytes()],
        );
        unsealed.zeroize();

        let expected_seq = self.sequence.wrapping_add(1);
        authentic_mask &= u8::from(packet.epoch == self.epoch)
            & u8::from(packet.sequence == expected_seq)
            & u8::from(packet.wire_cube.partial_256b.len() == self.config.core_bytes)
            & u8::from(packet.wire_cube.partial_1000b.len() == self.config.sub_matrix_bytes);

        let mut norm_256b = vec![0u8; self.config.core_bytes];
        let c_copy = packet
            .wire_cube
            .partial_256b
            .len()
            .min(self.config.core_bytes);
        norm_256b[..c_copy].copy_from_slice(&packet.wire_cube.partial_256b[..c_copy]);

        let mut norm_1000b = vec![0u8; self.config.sub_matrix_bytes];
        let s_copy = packet
            .wire_cube
            .partial_1000b
            .len()
            .min(self.config.sub_matrix_bytes);
        norm_1000b[..s_copy].copy_from_slice(&packet.wire_cube.partial_1000b[..s_copy]);

        let mut root_cap = self.custody.derive_root_capability(self.config.fixed_step_budget);
        let (dh_ok, mut dh_out) =
            match Self::dh_exchange(&self.ratchet.local_dh_secret, &packet.ratchet_pub) {
                Ok(s) => (1u8, s),
                Err(_) => (0u8, [0u8; 32]),
            };
        authentic_mask &= dh_ok;

        let mut ratcheted_root =
            Self::derive_ratcheted_root(&root_cap, &self.ratchet.chain_key, &dh_out);
        let algo = self.synthesize_ephemeral_algorithm(
            &ratcheted_root,
            &packet.wire_cube.cube_fingerprint,
            packet.sequence,
            packet.epoch,
        );

        let wire_tmr_key = Self::derive_wire_tmr_key(
            &algo.algo_key,
            &packet.wire_cube.cube_fingerprint,
            packet.sequence,
        );
        let mut wire_voxel = VoxelCube {
            cube_uid: packet.wire_cube.cube_fingerprint,
            generation: packet.sequence,
            sub_matrix: norm_1000b,
            core_pattern: norm_256b,
            weight_layer: Vec::new(),
        };
        let (tmr_ok, healed_bits) = match wire_voxel.heal_bitwise(&wire_tmr_key) {
            Ok(r) => (1u8, r.repaired_core_bits + r.repaired_shadow_bits),
            Err(_) => (0u8, 0usize),
        };
        authentic_mask &= tmr_ok;

        let expected_mac = Self::compute_packet_mac(
            &algo.algo_key,
            &packet.wire_cube.cube_fingerprint,
            packet.sequence,
            packet.epoch,
            &packet.ratchet_pub,
            &wire_voxel.core_pattern,
            &packet.payload_mode,
        );
        authentic_mask &= u8::from(constant_time_eq(&expected_mac, &packet.packet_mac));

        let (payload_ok, mut plaintext) =
            self.decrypt_payload_uniform(&algo.algo_key, packet, &wire_voxel.core_pattern);
        authentic_mask &= payload_ok;

        let transition_res = self.build_transition(
            &root_cap,
            &algo,
            packet.wire_cube.cube_fingerprint,
            packet.sequence,
            dh_out,
        );
        let (next_dh_ok, mut next_dh_sk, next_dh_pub) = match Self::generate_dh_keypair() {
            Ok((sk, pk)) => (1u8, sk, pk),
            Err(_) => (0u8, [0u8; 32], [0u8; 32]),
        };
        authentic_mask &= next_dh_ok;

        let mut probe = Vec::with_capacity(self.config.core_bytes + FINGERPRINT_BYTES + 8);
        probe.extend_from_slice(&packet.wire_cube.cube_fingerprint);
        probe.extend_from_slice(&wire_voxel.core_pattern);
        probe.extend_from_slice(&packet.sequence.to_le_bytes());
        let mut plausible_output =
            DteEngine::synthesize_honey_output(&self.config, honey_profile, &probe, &self.decoys);
        probe.zeroize();

        let outcome = if authentic_mask == 1 {
            if let Ok(transition) = transition_res {
                let ack = DeliveryAck {
                    cube_fingerprint: packet.wire_cube.cube_fingerprint,
                    sequence: packet.sequence,
                    new_generation: packet.sequence,
                    next_ratchet_pub: next_dh_pub,
                    ack_mac: Self::compute_ack_mac(
                        &transition.ack_mac_key,
                        &packet.wire_cube.cube_fingerprint,
                        packet.sequence,
                        &next_dh_pub,
                    ),
                };
                self.clock_guard.local_monotonic_tick = candidate_tick;
                self.commit_receive_transition(
                    transition,
                    next_dh_sk,
                    next_dh_pub,
                    packet.ratchet_pub,
                    &dh_out,
                );
                plausible_output.zeroize();
                ReceiveOutcome::Authentic {
                    plaintext,
                    ack,
                    healed_bits,
                }
            } else {
                plaintext.zeroize();
                ReceiveOutcome::HoneyDeception {
                    plausible_output,
                    profile: honey_profile,
                }
            }
        } else {
            plaintext.zeroize();
            ReceiveOutcome::HoneyDeception {
                plausible_output,
                profile: honey_profile,
            }
        };

        next_dh_sk.zeroize();
        root_cap.zeroize();
        ratcheted_root.zeroize();
        dh_out.zeroize();
        outcome
    }

    /// Executes Bijective Epoch Hopping (`Section 4.1`):
    /// Simultaneously maps 100% of 3D coordinates and 100% of 250 nibbles inside every real and decoy cube
    /// to a brand-new bijective permutation so historical snapshots cannot be correlated.
    pub fn hop_epoch(&mut self, hw: &dyn HardwareProvider) -> Result<u64> {
        let _exec_token = self.clock_guard.authorize_local_execution(hw)?;
        if self.pending_outbound.is_some() {
            return Err(CubeHashError::PendingTransactionExists);
        }
        self.apply_epoch_hop_internal()
    }

    /// Executes Bijective Epoch Hopping on a TX mesh AND steps the X25519 DH Ratchet forward,
    /// returning `(new_epoch, epoch_eph_pub)` for authenticated delivery to the receiver.
    pub fn hop_epoch_ratchet_tx(&mut self, hw: &dyn HardwareProvider) -> Result<(u64, [u8; 32])> {
        let _exec_token = self.clock_guard.authorize_local_execution(hw)?;
        if self.pending_outbound.is_some() {
            return Err(CubeHashError::PendingTransactionExists);
        }
        let (mut eph_sk, eph_pub) = Self::generate_dh_keypair()?;
        let mut dh_out = Self::dh_exchange(&eph_sk, &self.ratchet.peer_dh_pub)?;
        eph_sk.zeroize();
        let new_epoch = self.apply_epoch_hop_internal()?;
        self.ratchet.chain_key =
            Self::advance_ratchet_chain_key(&self.ratchet.chain_key, &dh_out, &eph_pub);
        dh_out.zeroize();
        Ok((new_epoch, eph_pub))
    }

    /// Advances an RX mesh to `target_epoch` and folds the sender's `epoch_eph_pub` into its DH ratchet.
    pub fn hop_epoch_ratchet_rx(
        &mut self,
        hw: &dyn HardwareProvider,
        target_epoch: u64,
        epoch_eph_pub: [u8; 32],
    ) -> Result<u64> {
        let _exec_token = self.clock_guard.authorize_local_execution(hw)?;
        if target_epoch != self.epoch + 1 {
            return Err(CubeHashError::ReplayDetected);
        }
        let mut dh_out = Self::dh_exchange(&self.ratchet.local_dh_secret, &epoch_eph_pub)?;
        let new_epoch = self.apply_epoch_hop_internal()?;
        self.ratchet.chain_key =
            Self::advance_ratchet_chain_key(&self.ratchet.chain_key, &dh_out, &epoch_eph_pub);
        dh_out.zeroize();
        Ok(new_epoch)
    }

    fn apply_epoch_hop_internal(&mut self) -> Result<u64> {
        let mut root_cap = self.custody.derive_root_capability(self.config.fixed_step_budget);
        let prev_epoch = self.epoch;
        let next_epoch = prev_epoch + 1;
        let prev_epoch_key = Self::derive_epoch_key(&root_cap, &self.custody.main.chain_id, prev_epoch);
        let next_epoch_key = Self::derive_epoch_key(&root_cap, &self.custody.main.chain_id, next_epoch);
        let spiral = SpiralSpace::new(self.config.space_dim, self.custody.auditor.spiral_coeffs);

        for (slot, coord) in self.coords.iter_mut().enumerate() {
            *coord = spiral.spiral_arm_coord(&next_epoch_key, next_epoch, slot);
        }
        for cube in self.cubes.iter_mut().chain(self.decoys.iter_mut()) {
            if prev_epoch > 0 {
                SpiralSpace::unpermute_nibbles(&mut cube.sub_matrix, &prev_epoch_key, prev_epoch);
            }
            SpiralSpace::permute_nibbles(&mut cube.sub_matrix, &next_epoch_key, next_epoch);
        }

        self.epoch = next_epoch;
        root_cap.zeroize();
        Ok(next_epoch)
    }

    /// Runs Bitwise Majority Voting self-healing (`Section 4.3`) on a stored mesh cube at `slot`,
    /// accounting transparently for any active bijective nibble permutation at `self.epoch`.
    pub fn heal_stored_cube(
        &mut self,
        hw: &dyn HardwareProvider,
        slot: usize,
    ) -> Result<crate::voxel::HealReport> {
        let _exec_token = self.clock_guard.authorize_local_execution(hw)?;
        if slot >= self.cubes.len() {
            return Err(CubeHashError::InvalidConfig("cube slot index out of bounds"));
        }
        let mut root_cap = self.custody.derive_root_capability(self.config.fixed_step_budget);
        let epoch_key = Self::derive_epoch_key(&root_cap, &self.custody.main.chain_id, self.epoch);
        let res = self.cubes[slot].heal_at_epoch(&root_cap, Some((&epoch_key, self.epoch)));
        root_cap.zeroize();
        res
    }

    /// Mutable reference to stored cubes for fault-injection and bit-rot testing.
    pub fn cubes_mut(&mut self) -> &mut [VoxelCube] {
        &mut self.cubes
    }

    /// Performs `O(W * K)` windowed spiral lookup for `target` coordinate (`Section 4.1`).
    pub fn lookup_spiral_window(&self, start_slot: usize, target: Coord3D) -> (Option<usize>, usize) {
        let mut root_cap = self.custody.derive_root_capability(self.config.fixed_step_budget);
        let epoch_key = Self::derive_epoch_key(&root_cap, &self.custody.main.chain_id, self.epoch);
        let spiral = SpiralSpace::new(self.config.space_dim, self.custody.auditor.spiral_coeffs);
        let res = spiral.search_spiral_window(
            &self.coords,
            &epoch_key,
            self.epoch,
            start_slot,
            self.config.spiral_window,
            target,
        );
        root_cap.zeroize();
        res
    }

    /// Re-seals the local hardware clock guard onto replacement hardware using 3-Cube Custody (`Section 3.1`).
    pub fn recover_onto_new_hardware(&mut self, new_hw: &dyn HardwareProvider) -> Result<()> {
        let (mut new_guard, _) = self
            .custody
            .recover_on_new_hardware(new_hw, self.config.fixed_step_budget)?;
        new_guard.local_monotonic_tick = self.clock_guard.local_monotonic_tick;
        self.clock_guard = new_guard;
        Ok(())
    }

    /// Returns read-only audit metrics for RAM size, entropy, and 50/50 bit balance.
    pub fn audit_stats(&self) -> MeshAuditStats {
        let mut total_bytes = 0usize;
        let mut ratio_sum = 0.0;
        let mut entropy_sum = 0.0;
        for c in &self.cubes {
            total_bytes += c.cube_uid.len()
                + std::mem::size_of::<u64>()
                + c.core_pattern.len()
                + c.sub_matrix.len();
            ratio_sum += c.bit_balance_ratio();
            entropy_sum += c.visible_entropy_bits_per_byte();
        }
        let n = self.cubes.len().max(1) as f64;
        MeshAuditStats {
            mesh_size: self.cubes.len(),
            approx_ram_bytes: total_bytes,
            epoch: self.epoch,
            sequence: self.sequence,
            avg_ones_ratio: ratio_sum / n,
            avg_entropy_bits_per_byte: entropy_sum / n,
        }
    }

    pub fn config(&self) -> &MeshConfig {
        &self.config
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn coords(&self) -> &[Coord3D] {
        &self.coords
    }

    pub fn cubes(&self) -> &[VoxelCube] {
        &self.cubes
    }

    pub fn decoys(&self) -> &[VoxelCube] {
        &self.decoys
    }

    pub fn custody(&self) -> &ThreeCubeCustody {
        &self.custody
    }

    pub fn has_pending_outbound(&self) -> bool {
        self.pending_outbound.is_some()
    }

    pub fn clock_guard_mut(&mut self) -> &mut LocalClientClockGuard {
        &mut self.clock_guard
    }

    fn begin_send_inner(
        &mut self,
        hw: &dyn HardwareProvider,
        payload: &[u8],
        raw_core_mode: bool,
    ) -> Result<WirePacket> {
        if self.pending_outbound.is_some() {
            return Err(CubeHashError::PendingTransactionExists);
        }
        let _exec_token = self.clock_guard.authorize_local_execution(hw)?;

        let next_seq = self.sequence + 1;
        let mut cube_fingerprint = [0u8; FINGERPRINT_BYTES];
        fill_random(&mut cube_fingerprint)?;

        let (mut eph_sk, ratchet_pub) = Self::generate_dh_keypair()?;
        let mut dh_out = match Self::dh_exchange(&eph_sk, &self.ratchet.peer_dh_pub) {
            Ok(s) => s,
            Err(e) => {
                eph_sk.zeroize();
                return Err(e);
            }
        };
        eph_sk.zeroize();

        let mut root_cap = self.custody.derive_root_capability(self.config.fixed_step_budget);
        let mut ratcheted_root =
            Self::derive_ratcheted_root(&root_cap, &self.ratchet.chain_key, &dh_out);
        let algo = self.synthesize_ephemeral_algorithm(
            &ratcheted_root,
            &cube_fingerprint,
            next_seq,
            self.epoch,
        );

        let mut plain_core = vec![0u8; self.config.core_bytes];
        fill_random(&mut plain_core)?;

        let payload_mode = if raw_core_mode {
            let len_bytes = (payload.len() as u16).to_le_bytes();
            plain_core[0] = len_bytes[0];
            plain_core[1] = len_bytes[1];
            plain_core[2] = CORE_FLAG_RAW;
            let tag = hmac_sha256_parts(&algo.algo_key, &[b"raw-core-tag", &next_seq.to_le_bytes()]);
            plain_core[3..8].copy_from_slice(&tag[..5]);
            plain_core[8..8 + payload.len()].copy_from_slice(payload);
            PayloadMode::RawCore256
        } else {
            // `plain_core[8..]` holds CSPRNG nonce seed (works for any `core_bytes >= 16`).
            plain_core[2] = CORE_FLAG_AEAD;
            let mut nonce = [0u8; 24];
            hkdf_expand_label(
                &algo.algo_key,
                &plain_core[8..],
                b"cubehash-aead-nonce",
                &mut nonce,
            )?;

            let mut msg_key = [0u8; 32];
            hkdf_expand_label(
                &algo.algo_key,
                &cube_fingerprint,
                b"cubehash-aead-payload",
                &mut msg_key,
            )?;
            let aad = Self::build_aead_aad(&cube_fingerprint, next_seq, self.epoch, &ratchet_pub);
            let ciphertext = aead_seal(&msg_key, &nonce, &aad, payload)?;
            msg_key.zeroize();
            PayloadMode::ArbitraryCiphertext { ciphertext }
        };

        let mut core_mask = vec![0u8; self.config.core_bytes];
        whitened_stream(&algo.algo_key, b"wire-core-mask", &mut core_mask);
        let mut partial_256b = vec![0u8; self.config.core_bytes];
        for i in 0..self.config.core_bytes {
            partial_256b[i] = plain_core[i] ^ core_mask[i];
        }
        core_mask.zeroize();
        plain_core.zeroize();

        let wire_tmr_key = Self::derive_wire_tmr_key(&algo.algo_key, &cube_fingerprint, next_seq);
        let partial_1000b = encode_sub_matrix_with_shadows(
            &self.config,
            &wire_tmr_key,
            &cube_fingerprint,
            next_seq,
            &partial_256b,
        );
        let weight_padding = generate_variable_weight(&self.config)?;
        let packet_mac = Self::compute_packet_mac(
            &algo.algo_key,
            &cube_fingerprint,
            next_seq,
            self.epoch,
            &ratchet_pub,
            &partial_256b,
            &payload_mode,
        );

        let pending = self.build_transition(&root_cap, &algo, cube_fingerprint, next_seq, dh_out)?;
        self.pending_outbound = Some(pending);
        root_cap.zeroize();
        ratcheted_root.zeroize();
        dh_out.zeroize();

        Ok(WirePacket {
            wire_cube: UniqueWireCube {
                cube_fingerprint,
                partial_256b,
                partial_1000b,
                weight_padding,
            },
            sequence: next_seq,
            epoch: self.epoch,
            ratchet_pub,
            payload_mode,
            packet_mac,
        })
    }

    fn decrypt_payload_uniform(
        &self,
        algo_key: &[u8; 32],
        packet: &WirePacket,
        healed_core: &[u8],
    ) -> (u8, Vec<u8>) {
        let fingerprint = &packet.wire_cube.cube_fingerprint;
        let sequence = packet.sequence;
        let epoch = packet.epoch;
        let ratchet_pub = &packet.ratchet_pub;
        let payload_mode = &packet.payload_mode;

        let mut core_mask = vec![0u8; self.config.core_bytes];
        whitened_stream(algo_key, b"wire-core-mask", &mut core_mask);
        let mut plain_core = vec![0u8; self.config.core_bytes];
        for i in 0..self.config.core_bytes {
            plain_core[i] = healed_core[i] ^ core_mask[i];
        }
        core_mask.zeroize();

        let result = match payload_mode {
            PayloadMode::RawCore256 => {
                let flag_ok = u8::from(plain_core[2] == CORE_FLAG_RAW);
                let len = u16::from_le_bytes([plain_core[0], plain_core[1]]) as usize;
                let cap = self.config.raw_core_payload_capacity();
                let len_ok = u8::from(len <= cap);
                let expected_tag =
                    hmac_sha256_parts(algo_key, &[b"raw-core-tag", &sequence.to_le_bytes()]);
                let tag_ok = u8::from(constant_time_eq(&plain_core[3..8], &expected_tag[..5]));
                let ok = flag_ok & len_ok & tag_ok;
                let safe_len = len.min(cap).min(plain_core.len().saturating_sub(8));
                let pt = if ok == 1 {
                    plain_core[8..8 + safe_len].to_vec()
                } else {
                    Vec::new()
                };
                (ok, pt)
            }
            PayloadMode::ArbitraryCiphertext { ciphertext } => {
                let flag_ok = u8::from(plain_core[2] == CORE_FLAG_AEAD && plain_core.len() >= 16);
                let mut nonce = [0u8; 24];
                let mut msg_key = [0u8; 32];
                let kdf_ok = u8::from(
                    hkdf_expand_label(algo_key, &plain_core[8..], b"cubehash-aead-nonce", &mut nonce)
                        .is_ok()
                        && hkdf_expand_label(
                            algo_key,
                            fingerprint,
                            b"cubehash-aead-payload",
                            &mut msg_key,
                        )
                        .is_ok(),
                );
                let aad = Self::build_aead_aad(fingerprint, sequence, epoch, ratchet_pub);
                let aead_res = aead_open(&msg_key, &nonce, &aad, ciphertext);
                msg_key.zeroize();
                match aead_res {
                    Ok(pt) => (flag_ok & kdf_ok, pt),
                    Err(_) => (0u8, Vec::new()),
                }
            }
        };

        plain_core.zeroize();
        result
    }

    fn synthesize_ephemeral_algorithm(
        &self,
        ratcheted_root: &[u8; 32],
        fingerprint: &[u8; FINGERPRINT_BYTES],
        sequence: u64,
        epoch: u64,
    ) -> EphemeralCubeAlgorithm {
        let sel_seed = hmac_sha256_parts(
            ratcheted_root,
            &[
                b"quorum-select",
                &self.custody.auditor.synthesis_salt,
                fingerprint,
                &sequence.to_le_bytes(),
                &epoch.to_le_bytes(),
            ],
        );

        let mut indices: Vec<usize> = (0..self.config.mesh_size).collect();
        let mut stream = vec![0u8; self.config.mesh_size * 4];
        whitened_stream(&sel_seed, b"quorum-perm", &mut stream);
        for i in (1..indices.len()).rev() {
            let off = i * 4;
            let r = u32::from_le_bytes([stream[off], stream[off + 1], stream[off + 2], stream[off + 3]]);
            let j = (r as usize) % (i + 1);
            indices.swap(i, j);
        }
        let selected_indices = indices[..self.config.quorum_select].to_vec();

        // Gather canonical core patterns from the selected 25 cubes to feed ephemeral synthesis.
        let mut quorum_material = Vec::with_capacity(
            self.config.quorum_select * self.config.core_bytes + FINGERPRINT_BYTES + 48,
        );
        quorum_material.extend_from_slice(fingerprint);
        quorum_material.extend_from_slice(&sequence.to_le_bytes());
        quorum_material.extend_from_slice(&epoch.to_le_bytes());
        quorum_material.extend_from_slice(&self.custody.main.active_chain_state);
        for &idx in &selected_indices {
            quorum_material.extend_from_slice(&self.cubes[idx].core_pattern);
        }

        let algo_key = fixed_budget_mix(
            self.custody.auditor.time_algorithm,
            ratcheted_root,
            b"ephemeral-algo-synthesis",
            &quorum_material,
            self.config.fixed_step_budget,
        );
        quorum_material.zeroize();

        let mut rot_stream = vec![0u8; self.config.quorum_select * 4];
        whitened_stream(&algo_key, b"rot-profile", &mut rot_stream);
        let mut rotation_profile = Vec::with_capacity(self.config.quorum_select);
        for i in 0..self.config.quorum_select {
            let off = i * 4;
            rotation_profile.push(u32::from_le_bytes([
                rot_stream[off],
                rot_stream[off + 1],
                rot_stream[off + 2],
                rot_stream[off + 3],
            ]));
        }

        EphemeralCubeAlgorithm {
            algo_key,
            rotation_profile,
            selected_indices,
        }
    }

    fn build_transition(
        &self,
        root_cap: &[u8; 32],
        algo: &EphemeralCubeAlgorithm,
        fingerprint: [u8; FINGERPRINT_BYTES],
        next_sequence: u64,
        dh_out: [u8; 32],
    ) -> Result<PendingTransition> {
        let consume_count = self.config.consume_for_next;
        let consumed_slices: Vec<&[u8]> = algo.selected_indices[..consume_count]
            .iter()
            .map(|&idx| self.cubes[idx].core_pattern.as_slice())
            .collect();

        let mut next_seed = combine_non_linear(
            self.custody.auditor.combining_fn,
            &algo.algo_key,
            &consumed_slices,
            self.config.fixed_step_budget,
        );

        // Deterministic kill target: oldest generation among the mesh (tie-broken by selected index).
        let kill_idx = self
            .cubes
            .iter()
            .enumerate()
            .min_by_key(|(idx, c)| (c.generation, *idx))
            .map(|(idx, _)| idx)
            .unwrap_or(0);

        let mut born_cube =
            VoxelCube::generate_mesh_cube(&self.config, root_cap, next_sequence, &next_seed)?;
        let epoch_key = Self::derive_epoch_key(root_cap, &self.custody.main.chain_id, self.epoch);
        if self.epoch > 0 {
            SpiralSpace::permute_nibbles(&mut born_cube.sub_matrix, &epoch_key, self.epoch);
        }
        let spiral = SpiralSpace::new(self.config.space_dim, self.custody.auditor.spiral_coeffs);
        let born_coord = spiral.spiral_arm_coord(&epoch_key, self.epoch, kill_idx);

        let next_main_root = hmac_sha256_parts(
            &algo.algo_key,
            &[b"next-main-root", &self.custody.main.active_chain_state, &next_seed],
        );
        let ack_mac_key = hmac_sha256_parts(&algo.algo_key, &[b"delivery-ack-key-v2"]);
        next_seed.zeroize();

        Ok(PendingTransition {
            cube_fingerprint: fingerprint,
            next_sequence,
            kill_idx,
            born_cube,
            born_coord,
            next_main_root,
            ack_mac_key,
            dh_out,
        })
    }

    fn apply_transition(&mut self, mut t: PendingTransition) {
        self.cubes[t.kill_idx] = t.born_cube.clone();
        self.coords[t.kill_idx] = t.born_coord;
        self.custody.main.active_chain_state = t.next_main_root;
        self.custody.main.generation = t.next_sequence;
        self.sequence = t.next_sequence;
        t.born_cube.zeroize();
    }

    fn commit_receive_transition(
        &mut self,
        t: PendingTransition,
        next_local_sk: [u8; 32],
        next_local_pub: [u8; 32],
        sender_ratchet_pub: [u8; 32],
        dh_out: &[u8; 32],
    ) {
        self.apply_transition(t);
        self.ratchet.chain_key =
            Self::advance_ratchet_chain_key(&self.ratchet.chain_key, dh_out, &next_local_pub);
        self.ratchet.local_dh_secret.zeroize();
        self.ratchet.local_dh_secret = next_local_sk;
        self.ratchet.local_dh_pub = next_local_pub;
        self.ratchet.peer_dh_pub = sender_ratchet_pub;
    }

    fn generate_dh_keypair() -> Result<([u8; 32], [u8; 32])> {
        let mut sk_bytes = [0u8; 32];
        fill_random(&mut sk_bytes)?;
        let secret = StaticSecret::from(sk_bytes);
        let pub_bytes = PublicKey::from(&secret).to_bytes();
        Ok((sk_bytes, pub_bytes))
    }

    fn dh_exchange(secret_bytes: &[u8; 32], peer_pub_bytes: &[u8; 32]) -> Result<[u8; 32]> {
        let sk = StaticSecret::from(*secret_bytes);
        let pk = PublicKey::from(*peer_pub_bytes);
        let shared = sk.diffie_hellman(&pk);
        if !shared.was_contributory() {
            return Err(CubeHashError::AuthenticationFailed);
        }
        Ok(shared.to_bytes())
    }

    fn derive_ratcheted_root(
        root_cap: &[u8; 32],
        chain_key: &[u8; 32],
        dh_out: &[u8; 32],
    ) -> [u8; 32] {
        hmac_sha256_parts(root_cap, &[b"dh-ratchet-root-v1", chain_key, dh_out])
    }

    fn advance_ratchet_chain_key(
        chain_key: &[u8; 32],
        dh_out: &[u8; 32],
        next_pub: &[u8; 32],
    ) -> [u8; 32] {
        hmac_sha256_parts(chain_key, &[b"dh-ratchet-chain-v1", dh_out, next_pub])
    }

    fn compute_ack_mac(
        ack_mac_key: &[u8; 32],
        fingerprint: &[u8; FINGERPRINT_BYTES],
        seq: u64,
        next_ratchet_pub: &[u8; 32],
    ) -> [u8; 32] {
        hmac_sha256_parts(
            ack_mac_key,
            &[b"delivery-ack-v2", fingerprint, &seq.to_le_bytes(), next_ratchet_pub],
        )
    }

    fn derive_epoch_key(root_cap: &[u8; 32], chain_id: &[u8; 16], epoch: u64) -> [u8; 32] {
        hmac_sha256_parts(root_cap, &[b"epoch-key", chain_id, &epoch.to_le_bytes()])
    }

    fn derive_wire_tmr_key(
        algo_key: &[u8; 32],
        fingerprint: &[u8; FINGERPRINT_BYTES],
        seq: u64,
    ) -> [u8; 32] {
        hmac_sha256_parts(algo_key, &[b"wire-tmr", fingerprint, &seq.to_le_bytes()])
    }

    fn build_aead_aad(
        fingerprint: &[u8; FINGERPRINT_BYTES],
        seq: u64,
        epoch: u64,
        ratchet_pub: &[u8; 32],
    ) -> [u8; 64] {
        let mut aad = [0u8; 64];
        aad[..16].copy_from_slice(fingerprint);
        aad[16..24].copy_from_slice(&seq.to_le_bytes());
        aad[24..32].copy_from_slice(&epoch.to_le_bytes());
        aad[32..64].copy_from_slice(ratchet_pub);
        aad
    }

    fn compute_packet_mac(
        algo_key: &[u8; 32],
        fingerprint: &[u8; FINGERPRINT_BYTES],
        seq: u64,
        epoch: u64,
        ratchet_pub: &[u8; 32],
        partial_256b: &[u8],
        payload_mode: &PayloadMode,
    ) -> [u8; 32] {
        match payload_mode {
            PayloadMode::RawCore256 => hmac_sha256_parts(
                algo_key,
                &[
                    b"wire-mac-raw-v2",
                    fingerprint,
                    &seq.to_le_bytes(),
                    &epoch.to_le_bytes(),
                    ratchet_pub,
                    partial_256b,
                ],
            ),
            PayloadMode::ArbitraryCiphertext { ciphertext } => hmac_sha256_parts(
                algo_key,
                &[
                    b"wire-mac-aead-v2",
                    fingerprint,
                    &seq.to_le_bytes(),
                    &epoch.to_le_bytes(),
                    ratchet_pub,
                    partial_256b,
                    ciphertext,
                ],
            ),
        }
    }
}

/// Full-duplex bidirectional session pairing independent TX and RX `CellularMesh` instances
/// so two parties (e.g., chat clients) can send and receive concurrently without collision.
pub struct DuplexCubeSession {
    pub tx: CellularMesh,
    pub rx: CellularMesh,
}

impl DuplexCubeSession {
    /// Provisions a matched full-duplex pair `(Alice, Bob)` bound to their respective hardware providers.
    pub fn new_paired(
        config: MeshConfig,
        alice_to_bob_custody: ThreeCubeCustody,
        bob_to_alice_custody: ThreeCubeCustody,
        alice_hw: &dyn HardwareProvider,
        bob_hw: &dyn HardwareProvider,
    ) -> Result<(Self, Self)> {
        let (a_tx, b_rx) =
            CellularMesh::new_paired(config.clone(), alice_to_bob_custody, alice_hw, bob_hw)?;
        let (b_tx, a_rx) = CellularMesh::new_paired(config, bob_to_alice_custody, bob_hw, alice_hw)?;
        Ok((Self { tx: a_tx, rx: a_rx }, Self { tx: b_tx, rx: b_rx }))
    }

    /// Initiates sending arbitrary data over the TX mesh (awaiting `commit_ack` / `rollback_outbound`).
    pub fn begin_send_message(
        &mut self,
        hw: &dyn HardwareProvider,
        plaintext: &[u8],
    ) -> Result<WirePacket> {
        self.tx.begin_send_message(hw, plaintext)
    }

    /// Initiates sending compact core payload (up to 24 bytes in standard mode) over the TX mesh.
    pub fn begin_send_raw_core(
        &mut self,
        hw: &dyn HardwareProvider,
        payload: &[u8],
    ) -> Result<WirePacket> {
        self.tx.begin_send_raw_core(hw, payload)
    }

    /// Commits TX state after receiving `DeliveryAck`.
    pub fn commit_ack(&mut self, hw: &dyn HardwareProvider, ack: &DeliveryAck) -> Result<()> {
        self.tx.commit_ack(hw, ack)
    }

    /// Rolls back unacknowledged TX state on disconnect/timeout.
    pub fn rollback_outbound(&mut self) -> Result<()> {
        self.tx.rollback_outbound()
    }

    /// Receives and authenticates an incoming packet on the RX mesh.
    pub fn receive_authenticated(
        &mut self,
        hw: &dyn HardwareProvider,
        packet: &mut WirePacket,
    ) -> Result<(Vec<u8>, DeliveryAck, usize)> {
        self.rx.receive_authenticated(hw, packet)
    }

    /// Zero-oracle receive on the RX mesh.
    pub fn decrypt_zero_oracle(
        &mut self,
        hw: &dyn HardwareProvider,
        packet: &WirePacket,
        honey_profile: HoneyProfile,
    ) -> ReceiveOutcome {
        self.rx.decrypt_zero_oracle(hw, packet, honey_profile)
    }

    /// Executes epoch hop + TX DH ratchet advancement.
    pub fn hop_epoch_tx_ratchet(&mut self, hw: &dyn HardwareProvider) -> Result<(u64, [u8; 32])> {
        self.tx.hop_epoch_ratchet_tx(hw)
    }

    /// Synchronizes RX epoch hop + folds sender's epoch DH ratchet key.
    pub fn hop_epoch_rx_ratchet(
        &mut self,
        hw: &dyn HardwareProvider,
        target_epoch: u64,
        epoch_eph_pub: [u8; 32],
    ) -> Result<u64> {
        self.rx.hop_epoch_ratchet_rx(hw, target_epoch, epoch_eph_pub)
    }
}

// Re-export custody primitives needed when constructing external bundles.
pub fn build_custody_bundle(
    mother: MotherCube,
    main: MainCube,
    auditor: AuditorCube,
) -> ThreeCubeCustody {
    ThreeCubeCustody {
        mother,
        main,
        auditor,
    }
}
