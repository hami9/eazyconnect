use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::config::{MeshConfig, FINGERPRINT_BYTES};
use crate::custody::{
    AuditorCube, HardwareProvider, LocalClientClockGuard, MainCube, MotherCube, ThreeCubeCustody,
};
use crate::error::{CubeHashError, Result};
use crate::honey::{generate_decoy_cubes, DteEngine, HoneyProfile};
use crate::hybrid::HybridTriMix;
use crate::primitives::{
    aead_open, aead_seal, combine_non_linear, constant_time_eq, fill_random, fixed_budget_mix,
    hkdf_expand_label, hmac_sha256_parts, whitened_stream,
};
use crate::spiral::{Coord3D, SpiralSpace};
use crate::voxel::{encode_sub_matrix_with_shadows, generate_variable_weight_seeded, VoxelCube};

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
    born_cube: Option<VoxelCube>,
    #[zeroize(skip)]
    born_coord: Coord3D,
    next_main_root: [u8; 32],
    ack_mac_key: [u8; 32],
    dh_out: [u8; 32],
    dh_step: bool,
}

/// Synchronized 100-cube cellular cryptography mesh (`Section 5`) with two-tier X25519 + HybridTriMix Ratchet.
pub struct CellularMesh {
    config: MeshConfig,
    cubes: Vec<VoxelCube>,
    coords: Vec<Coord3D>,
    decoys: Vec<VoxelCube>,
    custody: ThreeCubeCustody,
    clock_guard: LocalClientClockGuard,
    ratchet: DhRatchetState,
    cached_root_cap: [u8; 32],
    cached_epoch_key: [u8; 32],
    dh_rekey_interval: u64,
    epoch: u64,
    sequence: u64,
    pending_outbound: Option<PendingTransition>,
}

impl Drop for CellularMesh {
    fn drop(&mut self) {
        self.cached_root_cap.zeroize();
        self.cached_epoch_key.zeroize();
    }
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

        let cached_root_cap = custody.derive_root_capability(config.fixed_step_budget);
        let mut raw_hw_secret = [0u8; 32];
        fill_random(&mut raw_hw_secret)?;
        let clock_guard = LocalClientClockGuard::seal_new(hw, &raw_hw_secret)?;
        raw_hw_secret.zeroize();

        let cached_epoch_key = Self::derive_epoch_key(&cached_root_cap, &custody.main.chain_id, 0);
        let spiral = SpiralSpace::new(config.space_dim, custody.auditor.spiral_coeffs);

        let mut cubes = Vec::with_capacity(config.mesh_size);
        let mut coords = Vec::with_capacity(config.mesh_size);
        for slot in 0..config.mesh_size {
            let cube_seed = hmac_sha256_parts(
                shared_mesh_seed,
                &[
                    b"init-mesh-cube",
                    &custody.main.chain_id,
                    &(slot as u64).to_le_bytes(),
                ],
            );
            let cube = VoxelCube::generate_mesh_cube(&config, &cached_root_cap, 0, &cube_seed)?;
            coords.push(spiral.spiral_arm_coord(&cached_epoch_key, 0, slot));
            cubes.push(cube);
        }

        let decoy_seed =
            hmac_sha256_parts(&cached_root_cap, &[b"decoy-root", &custody.main.chain_id]);
        let decoys = generate_decoy_cubes(&config, &decoy_seed, &cubes);

        let init_dh_secret = hmac_sha256_parts(
            shared_mesh_seed,
            &[b"init-dh-ratchet-sk", &custody.main.chain_id],
        );
        let init_dh_pub = PublicKey::from(&StaticSecret::from(init_dh_secret)).to_bytes();
        let init_chain_key = hmac_sha256_parts(
            shared_mesh_seed,
            &[b"init-dh-chain", &custody.main.chain_id],
        );

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
            cached_root_cap,
            cached_epoch_key,
            dh_rekey_interval: 1,
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
        let mut alice =
            Self::provision_device(config.clone(), custody.clone(), alice_hw, &shared_mesh_seed)?;
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

    /// Configures how frequently full X25519 DH + 25/20 cellular quorum mutation executes
    /// (`1` = every message; `N > 1` runs X25519 + quorum kill/birth every `N` packets and
    /// forward-secure `HybridTriMix` symmetric chain ratcheting on intermediate frames).
    pub fn set_dh_rekey_interval(&mut self, interval: u64) {
        self.dh_rekey_interval = interval.max(1);
    }

    /// Builder helper configuring the DH rekey cadence in packets.
    pub fn with_dh_rekey_interval(mut self, interval: u64) -> Self {
        self.set_dh_rekey_interval(interval);
        self
    }

    /// Returns the configured DH rekey cadence (`1` = per-message X25519).
    pub fn dh_rekey_interval(&self) -> u64 {
        self.dh_rekey_interval
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
        let mut committed = self.pending_outbound.take().unwrap();
        let next_chain_key = if committed.dh_step {
            Self::advance_ratchet_chain_key(
                &self.ratchet.chain_key,
                &committed.dh_out,
                &next_peer_pub,
            )
        } else {
            Self::advance_fast_chain_key(
                &self.ratchet.chain_key,
                &committed.cube_fingerprint,
                committed.next_sequence,
                &committed.next_main_root,
            )
        };
        let was_dh = committed.dh_step;
        self.apply_transition(&mut committed);
        self.ratchet.chain_key = next_chain_key;
        if was_dh {
            self.ratchet.peer_dh_pub = next_peer_pub;
        }
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

        let dh_step = self.is_dh_step(packet.sequence);
        let mut dh_out = if dh_step {
            Self::dh_exchange(&self.ratchet.local_dh_secret, &packet.ratchet_pub)?
        } else {
            if !constant_time_eq(&packet.ratchet_pub, &self.ratchet.local_dh_pub) {
                return Err(CubeHashError::AuthenticationFailed);
            }
            [0u8; 32]
        };
        let mut ratcheted_root = if dh_step {
            Self::derive_ratcheted_root(&self.cached_root_cap, &self.ratchet.chain_key, &dh_out)
        } else {
            Self::derive_fast_ratcheted_root(
                &self.cached_root_cap,
                &self.ratchet.chain_key,
                &packet.ratchet_pub,
            )
        };
        let algo = if dh_step {
            self.synthesize_ephemeral_algorithm(
                &ratcheted_root,
                &packet.wire_cube.cube_fingerprint,
                packet.sequence,
                packet.epoch,
            )
        } else {
            self.synthesize_fast_ephemeral_algorithm(
                &ratcheted_root,
                &packet.wire_cube.cube_fingerprint,
                packet.sequence,
                packet.epoch,
            )
        };

        // 1. Self-heal the incoming wire cube BEFORE MAC verification (`Section 4.3`).
        let wire_tmr_key = Self::derive_wire_tmr_key(
            &algo.algo_key,
            &packet.wire_cube.cube_fingerprint,
            packet.sequence,
        );
        let mut wire_voxel = VoxelCube {
            cube_uid: packet.wire_cube.cube_fingerprint,
            generation: packet.sequence,
            sub_matrix: std::mem::take(&mut packet.wire_cube.partial_1000b),
            core_pattern: std::mem::take(&mut packet.wire_cube.partial_256b),
            weight_layer: Vec::new(),
        };
        let heal_res = wire_voxel.heal_bitwise(&wire_tmr_key);
        packet.wire_cube.partial_256b = std::mem::take(&mut wire_voxel.core_pattern);
        packet.wire_cube.partial_1000b = std::mem::take(&mut wire_voxel.sub_matrix);
        let heal_report = match heal_res {
            Ok(r) => r,
            Err(e) => {
                ratcheted_root.zeroize();
                dh_out.zeroize();
                return Err(e);
            }
        };

        // 2. Verify packet MAC over healed wire cube + sequence + epoch + ratchet_pub + ciphertext tag.
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
            ratcheted_root.zeroize();
            dh_out.zeroize();
            return Err(CubeHashError::AuthenticationFailed);
        }

        // 3. Unmask core_pattern and recover plaintext according to Dual Mode.
        let (payload_ok, plaintext) =
            self.decrypt_payload_uniform(&algo.algo_key, packet, &packet.wire_cube.partial_256b);
        if payload_ok != 1 {
            ratcheted_root.zeroize();
            dh_out.zeroize();
            return Err(CubeHashError::AuthenticationFailed);
        }

        // 4. Stage, rotate receiver X25519 keypair on DH boundaries, commit transition, and emit DeliveryAck.
        let (mut next_dh_sk, next_dh_pub) = if dh_step {
            Self::generate_dh_keypair()?
        } else {
            ([0u8; 32], self.ratchet.local_dh_pub)
        };
        let mut transition = if dh_step {
            let root_cap = self.cached_root_cap;
            self.build_transition(
                &root_cap,
                &algo,
                packet.wire_cube.cube_fingerprint,
                packet.sequence,
                dh_out,
            )?
        } else {
            self.build_fast_transition(&algo, packet.wire_cube.cube_fingerprint, packet.sequence)
        };
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
            &mut transition,
            next_dh_sk,
            next_dh_pub,
            packet.ratchet_pub,
            &dh_out,
        );
        next_dh_sk.zeroize();
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
        let mut authentic_mask = u8::from(constant_time_eq(
            &self.clock_guard.device_hw_id,
            &observed_hw,
        ));
        let (unseal_ok, mut unsealed) = match hw.unseal_secret(
            LocalClientClockGuard::SEAL_LABEL,
            &self.clock_guard.sealed_hw_secret,
        ) {
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
            &[
                &self.clock_guard.device_hw_id,
                &candidate_tick.to_le_bytes(),
            ],
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

        let dh_step = self.is_dh_step(expected_seq);
        let (dh_ok, mut dh_out) = if dh_step {
            match Self::dh_exchange(&self.ratchet.local_dh_secret, &packet.ratchet_pub) {
                Ok(s) => (1u8, s),
                Err(_) => (0u8, [0u8; 32]),
            }
        } else {
            let match_pub = u8::from(constant_time_eq(
                &packet.ratchet_pub,
                &self.ratchet.local_dh_pub,
            ));
            (match_pub, [0u8; 32])
        };
        authentic_mask &= dh_ok;

        let mut ratcheted_root = if dh_step {
            Self::derive_ratcheted_root(&self.cached_root_cap, &self.ratchet.chain_key, &dh_out)
        } else {
            Self::derive_fast_ratcheted_root(
                &self.cached_root_cap,
                &self.ratchet.chain_key,
                &packet.ratchet_pub,
            )
        };
        let algo = if dh_step {
            self.synthesize_ephemeral_algorithm(
                &ratcheted_root,
                &packet.wire_cube.cube_fingerprint,
                packet.sequence,
                packet.epoch,
            )
        } else {
            self.synthesize_fast_ephemeral_algorithm(
                &ratcheted_root,
                &packet.wire_cube.cube_fingerprint,
                packet.sequence,
                packet.epoch,
            )
        };

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

        let transition_res = if dh_step {
            let root_cap = self.cached_root_cap;
            self.build_transition(
                &root_cap,
                &algo,
                packet.wire_cube.cube_fingerprint,
                packet.sequence,
                dh_out,
            )
        } else {
            Ok(self.build_fast_transition(
                &algo,
                packet.wire_cube.cube_fingerprint,
                packet.sequence,
            ))
        };
        let (next_dh_ok, mut next_dh_sk, next_dh_pub) = if dh_step {
            match Self::generate_dh_keypair() {
                Ok((sk, pk)) => (1u8, sk, pk),
                Err(_) => (0u8, [0u8; 32], [0u8; 32]),
            }
        } else {
            (1u8, [0u8; 32], self.ratchet.local_dh_pub)
        };
        authentic_mask &= next_dh_ok;

        let mut probe = Vec::with_capacity(self.config.core_bytes + FINGERPRINT_BYTES + 8);
        probe.extend_from_slice(&packet.wire_cube.cube_fingerprint);
        probe.extend_from_slice(&wire_voxel.core_pattern);
        probe.extend_from_slice(&packet.sequence.to_le_bytes());
        let mut plausible_output =
            DteEngine::synthesize_honey_output(&self.config, honey_profile, &probe, &self.decoys);
        probe.zeroize();

        // Execute ACK MAC synthesis unconditionally so invalid probes incur matching HMAC work.
        let dummy_ack_key = [0u8; 32];
        let ack_key_ref = match &transition_res {
            Ok(t) => &t.ack_mac_key,
            Err(_) => &dummy_ack_key,
        };
        let candidate_ack_mac = Self::compute_ack_mac(
            ack_key_ref,
            &packet.wire_cube.cube_fingerprint,
            packet.sequence,
            &next_dh_pub,
        );

        let outcome = if authentic_mask == 1 {
            if let Ok(mut transition) = transition_res {
                let ack = DeliveryAck {
                    cube_fingerprint: packet.wire_cube.cube_fingerprint,
                    sequence: packet.sequence,
                    new_generation: packet.sequence,
                    next_ratchet_pub: next_dh_pub,
                    ack_mac: candidate_ack_mac,
                };
                self.clock_guard.local_monotonic_tick = candidate_tick;
                self.commit_receive_transition(
                    &mut transition,
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
        let prev_epoch = self.epoch;
        let next_epoch = prev_epoch + 1;
        let prev_epoch_key = self.cached_epoch_key;
        let next_epoch_key = Self::derive_epoch_key(
            &self.cached_root_cap,
            &self.custody.main.chain_id,
            next_epoch,
        );
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
        self.cached_epoch_key = next_epoch_key;
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
            return Err(CubeHashError::InvalidConfig(
                "cube slot index out of bounds",
            ));
        }
        let epoch_key = self.cached_epoch_key;
        self.cubes[slot].heal_at_epoch(&self.cached_root_cap, Some((&epoch_key, self.epoch)))
    }

    /// Mutable reference to stored cubes for fault-injection and bit-rot testing.
    pub fn cubes_mut(&mut self) -> &mut [VoxelCube] {
        &mut self.cubes
    }

    /// Performs `O(W * K)` windowed spiral lookup for `target` coordinate (`Section 4.1`).
    pub fn lookup_spiral_window(
        &self,
        start_slot: usize,
        target: Coord3D,
    ) -> (Option<usize>, usize) {
        let spiral = SpiralSpace::new(self.config.space_dim, self.custody.auditor.spiral_coeffs);
        spiral.search_spiral_window(
            &self.coords,
            &self.cached_epoch_key,
            self.epoch,
            start_slot,
            self.config.spiral_window,
            target,
        )
    }

    /// Re-seals the local hardware clock guard onto replacement hardware using 3-Cube Custody (`Section 3.1`).
    pub fn recover_onto_new_hardware(&mut self, new_hw: &dyn HardwareProvider) -> Result<()> {
        let (mut new_guard, _) = self
            .custody
            .recover_on_new_hardware(new_hw, self.config.fixed_step_budget)?;
        new_guard.local_monotonic_tick = self.clock_guard.local_monotonic_tick;
        self.clock_guard = new_guard;
        self.cached_root_cap = self
            .custody
            .derive_root_capability(self.config.fixed_step_budget);
        self.cached_epoch_key = Self::derive_epoch_key(
            &self.cached_root_cap,
            &self.custody.main.chain_id,
            self.epoch,
        );
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

    fn is_dh_step(&self, seq: u64) -> bool {
        seq.saturating_sub(1).is_multiple_of(self.dh_rekey_interval)
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
        let dh_step = self.is_dh_step(next_seq);

        // Single OS CSPRNG syscall expanded via BLAKE2b512 whitened stream for packet randomness.
        let mut rng_seed = [0u8; 32];
        fill_random(&mut rng_seed)?;
        let mut entropy = [0u8; 224];
        whitened_stream(&rng_seed, b"pkt-entropy-v2", &mut entropy);
        rng_seed.zeroize();

        let mut cube_fingerprint = [0u8; FINGERPRINT_BYTES];
        cube_fingerprint.copy_from_slice(&entropy[..16]);

        let (ratchet_pub, mut dh_out) = if dh_step {
            let mut eph_sk = [0u8; 32];
            eph_sk.copy_from_slice(&entropy[16..48]);
            let secret = StaticSecret::from(eph_sk);
            let pub_bytes = PublicKey::from(&secret).to_bytes();
            let dh = match Self::dh_exchange(&eph_sk, &self.ratchet.peer_dh_pub) {
                Ok(s) => s,
                Err(e) => {
                    eph_sk.zeroize();
                    entropy.zeroize();
                    return Err(e);
                }
            };
            eph_sk.zeroize();
            (pub_bytes, dh)
        } else {
            (self.ratchet.peer_dh_pub, [0u8; 32])
        };

        let mut ratcheted_root = if dh_step {
            Self::derive_ratcheted_root(&self.cached_root_cap, &self.ratchet.chain_key, &dh_out)
        } else {
            Self::derive_fast_ratcheted_root(
                &self.cached_root_cap,
                &self.ratchet.chain_key,
                &ratchet_pub,
            )
        };
        let algo = if dh_step {
            self.synthesize_ephemeral_algorithm(
                &ratcheted_root,
                &cube_fingerprint,
                next_seq,
                self.epoch,
            )
        } else {
            self.synthesize_fast_ephemeral_algorithm(
                &ratcheted_root,
                &cube_fingerprint,
                next_seq,
                self.epoch,
            )
        };

        let core_len = self.config.core_bytes;
        let mut plain_core_buf = [0u8; 128];
        plain_core_buf[..core_len].copy_from_slice(&entropy[48..48 + core_len]);
        let mut weight_seed = [0u8; 32];
        weight_seed.copy_from_slice(&entropy[176..208]);
        entropy.zeroize();

        let plain_core = &mut plain_core_buf[..core_len];
        let payload_mode = if raw_core_mode {
            let len_bytes = (payload.len() as u16).to_le_bytes();
            plain_core[0] = len_bytes[0];
            plain_core[1] = len_bytes[1];
            plain_core[2] = CORE_FLAG_RAW;
            let tag =
                hmac_sha256_parts(&algo.algo_key, &[b"raw-core-tag", &next_seq.to_le_bytes()]);
            plain_core[3..8].copy_from_slice(&tag[..5]);
            plain_core[8..8 + payload.len()].copy_from_slice(payload);
            PayloadMode::RawCore256
        } else {
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

        let mut core_mask_buf = [0u8; 128];
        whitened_stream(
            &algo.algo_key,
            b"wire-core-mask",
            &mut core_mask_buf[..core_len],
        );
        let mut partial_256b = vec![0u8; core_len];
        for i in 0..core_len {
            partial_256b[i] = plain_core[i] ^ core_mask_buf[i];
        }
        core_mask_buf[..core_len].zeroize();
        plain_core_buf[..core_len].zeroize();

        let wire_tmr_key = Self::derive_wire_tmr_key(&algo.algo_key, &cube_fingerprint, next_seq);
        let partial_1000b = encode_sub_matrix_with_shadows(
            &self.config,
            &wire_tmr_key,
            &cube_fingerprint,
            next_seq,
            &partial_256b,
        );
        let weight_padding = generate_variable_weight_seeded(&self.config, &weight_seed);
        weight_seed.zeroize();
        let packet_mac = Self::compute_packet_mac(
            &algo.algo_key,
            &cube_fingerprint,
            next_seq,
            self.epoch,
            &ratchet_pub,
            &partial_256b,
            &payload_mode,
        );

        let pending = if dh_step {
            let root_cap = self.cached_root_cap;
            self.build_transition(&root_cap, &algo, cube_fingerprint, next_seq, dh_out)?
        } else {
            self.build_fast_transition(&algo, cube_fingerprint, next_seq)
        };
        self.pending_outbound = Some(pending);
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

        let core_len = self.config.core_bytes;
        let mut core_mask_buf = [0u8; 128];
        whitened_stream(algo_key, b"wire-core-mask", &mut core_mask_buf[..core_len]);
        let mut plain_core_buf = [0u8; 128];
        for i in 0..core_len {
            plain_core_buf[i] = healed_core[i] ^ core_mask_buf[i];
        }
        core_mask_buf[..core_len].zeroize();
        let plain_core = &plain_core_buf[..core_len];

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
                    hkdf_expand_label(
                        algo_key,
                        &plain_core[8..],
                        b"cubehash-aead-nonce",
                        &mut nonce,
                    )
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

        plain_core_buf[..core_len].zeroize();
        result
    }

    fn synthesize_fast_ephemeral_algorithm(
        &self,
        ratcheted_root: &[u8; 32],
        fingerprint: &[u8; FINGERPRINT_BYTES],
        sequence: u64,
        epoch: u64,
    ) -> EphemeralCubeAlgorithm {
        let len = self.cubes.len();
        let slot_a = (sequence as usize) % len;
        let slot_b = ((sequence as usize).wrapping_mul(37).wrapping_add(13)) % len;
        let mut msg = [0u8; 128];
        let mut off = 0usize;
        msg[off..off + 16].copy_from_slice(fingerprint);
        off += 16;
        msg[off..off + 8].copy_from_slice(&sequence.to_le_bytes());
        off += 8;
        msg[off..off + 8].copy_from_slice(&epoch.to_le_bytes());
        off += 8;
        msg[off..off + 32].copy_from_slice(&self.custody.main.active_chain_state);
        off += 32;
        let take_a = self.cubes[slot_a].core_pattern.len().min(32);
        msg[off..off + take_a].copy_from_slice(&self.cubes[slot_a].core_pattern[..take_a]);
        off += take_a;
        let take_b = self.cubes[slot_b].core_pattern.len().min(32);
        msg[off..off + take_b].copy_from_slice(&self.cubes[slot_b].core_pattern[..take_b]);
        off += take_b;

        let algo_key = HybridTriMix::mix_256(ratcheted_root, b"fast-sym-algo-v2", &msg[..off], 1);
        msg.zeroize();

        EphemeralCubeAlgorithm {
            algo_key,
            rotation_profile: Vec::new(),
            selected_indices: vec![slot_a, slot_b],
        }
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

        let n = self.config.mesh_size;
        let mut indices_stack = [0usize; 256];
        let mut indices_heap = if n > 256 {
            (0..n).collect::<Vec<usize>>()
        } else {
            for (i, slot) in indices_stack[..n].iter_mut().enumerate() {
                *slot = i;
            }
            Vec::new()
        };
        let indices: &mut [usize] = if n > 256 {
            &mut indices_heap
        } else {
            &mut indices_stack[..n]
        };

        let stream_len = n * 4;
        let mut stream_stack = [0u8; 1024];
        let mut stream_heap = if stream_len > 1024 {
            vec![0u8; stream_len]
        } else {
            Vec::new()
        };
        let stream: &mut [u8] = if stream_len > 1024 {
            &mut stream_heap
        } else {
            &mut stream_stack[..stream_len]
        };
        whitened_stream(&sel_seed, b"quorum-perm", stream);
        for i in (1..n).rev() {
            let off = i * 4;
            let r = u32::from_le_bytes([
                stream[off],
                stream[off + 1],
                stream[off + 2],
                stream[off + 3],
            ]);
            let j = (r as usize) % (i + 1);
            indices.swap(i, j);
        }
        let selected_indices = indices[..self.config.quorum_select].to_vec();

        // Gather canonical core patterns from the selected cubes cleanly.
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

        let rot_len = self.config.quorum_select * 4;
        let mut rot_stack = [0u8; 512];
        let mut rot_heap = if rot_len > 512 {
            vec![0u8; rot_len]
        } else {
            Vec::new()
        };
        let rot_stream: &mut [u8] = if rot_len > 512 {
            &mut rot_heap
        } else {
            &mut rot_stack[..rot_len]
        };
        whitened_stream(&algo_key, b"rot-profile", rot_stream);
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

    fn build_fast_transition(
        &self,
        algo: &EphemeralCubeAlgorithm,
        fingerprint: [u8; FINGERPRINT_BYTES],
        next_sequence: u64,
    ) -> PendingTransition {
        let ack_mac_key = hmac_sha256_parts(&algo.algo_key, &[b"delivery-ack-key-v2"]);
        PendingTransition {
            cube_fingerprint: fingerprint,
            next_sequence,
            kill_idx: 0,
            born_cube: None,
            born_coord: Coord3D { x: 0, y: 0, z: 0 },
            next_main_root: algo.algo_key,
            ack_mac_key,
            dh_out: [0u8; 32],
            dh_step: false,
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
        let mut consumed_stack = [&[][..]; 64];
        let consumed_heap: Vec<&[u8]>;
        let consumed_slices: &[&[u8]] = if consume_count <= 64 {
            for (i, &idx) in algo.selected_indices[..consume_count].iter().enumerate() {
                consumed_stack[i] = self.cubes[idx].core_pattern.as_slice();
            }
            &consumed_stack[..consume_count]
        } else {
            consumed_heap = algo.selected_indices[..consume_count]
                .iter()
                .map(|&idx| self.cubes[idx].core_pattern.as_slice())
                .collect();
            &consumed_heap
        };

        let mut next_seed = combine_non_linear(
            self.custody.auditor.combining_fn,
            &algo.algo_key,
            consumed_slices,
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
        let epoch_key = self.cached_epoch_key;
        if self.epoch > 0 {
            SpiralSpace::permute_nibbles(&mut born_cube.sub_matrix, &epoch_key, self.epoch);
        }
        let spiral = SpiralSpace::new(self.config.space_dim, self.custody.auditor.spiral_coeffs);
        let born_coord = spiral.spiral_arm_coord(&epoch_key, self.epoch, kill_idx);

        let next_main_root = hmac_sha256_parts(
            &algo.algo_key,
            &[
                b"next-main-root",
                &self.custody.main.active_chain_state,
                &next_seed,
            ],
        );
        let ack_mac_key = hmac_sha256_parts(&algo.algo_key, &[b"delivery-ack-key-v2"]);
        next_seed.zeroize();

        Ok(PendingTransition {
            cube_fingerprint: fingerprint,
            next_sequence,
            kill_idx,
            born_cube: Some(born_cube),
            born_coord,
            next_main_root,
            ack_mac_key,
            dh_out,
            dh_step: true,
        })
    }

    fn apply_transition(&mut self, t: &mut PendingTransition) {
        if let Some(ref mut born) = t.born_cube {
            std::mem::swap(&mut self.cubes[t.kill_idx], born);
            self.coords[t.kill_idx] = t.born_coord;
            self.custody.main.active_chain_state = t.next_main_root;
            self.custody.main.generation = t.next_sequence;
            born.zeroize();
        }
        self.sequence = t.next_sequence;
    }

    fn commit_receive_transition(
        &mut self,
        t: &mut PendingTransition,
        next_local_sk: [u8; 32],
        next_local_pub: [u8; 32],
        sender_ratchet_pub: [u8; 32],
        dh_out: &[u8; 32],
    ) {
        let was_dh = t.dh_step;
        let fp = t.cube_fingerprint;
        let next_seq = t.next_sequence;
        let algo_k = t.next_main_root;
        self.apply_transition(t);
        if was_dh {
            self.ratchet.chain_key =
                Self::advance_ratchet_chain_key(&self.ratchet.chain_key, dh_out, &next_local_pub);
            self.ratchet.local_dh_secret.zeroize();
            self.ratchet.local_dh_secret = next_local_sk;
            self.ratchet.local_dh_pub = next_local_pub;
            self.ratchet.peer_dh_pub = sender_ratchet_pub;
        } else {
            self.ratchet.chain_key =
                Self::advance_fast_chain_key(&self.ratchet.chain_key, &fp, next_seq, &algo_k);
        }
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

    fn derive_fast_ratcheted_root(
        root_cap: &[u8; 32],
        chain_key: &[u8; 32],
        peer_pub: &[u8; 32],
    ) -> [u8; 32] {
        hmac_sha256_parts(root_cap, &[b"sym-ratchet-root-v2", chain_key, peer_pub])
    }

    fn advance_ratchet_chain_key(
        chain_key: &[u8; 32],
        dh_out: &[u8; 32],
        next_pub: &[u8; 32],
    ) -> [u8; 32] {
        hmac_sha256_parts(chain_key, &[b"dh-ratchet-chain-v1", dh_out, next_pub])
    }

    fn advance_fast_chain_key(
        chain_key: &[u8; 32],
        fingerprint: &[u8; FINGERPRINT_BYTES],
        next_seq: u64,
        algo_key: &[u8; 32],
    ) -> [u8; 32] {
        hmac_sha256_parts(
            chain_key,
            &[
                b"sym-chain-advance-v2",
                fingerprint,
                &next_seq.to_le_bytes(),
                algo_key,
            ],
        )
    }

    fn compute_ack_mac(
        ack_mac_key: &[u8; 32],
        fingerprint: &[u8; FINGERPRINT_BYTES],
        seq: u64,
        next_ratchet_pub: &[u8; 32],
    ) -> [u8; 32] {
        hmac_sha256_parts(
            ack_mac_key,
            &[
                b"delivery-ack-v2",
                fingerprint,
                &seq.to_le_bytes(),
                next_ratchet_pub,
            ],
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
            PayloadMode::ArbitraryCiphertext { ciphertext } => {
                // Authenticate header + healed partial_256b + ciphertext length + trailing 16B Poly1305 tag
                // (or full body if shorter than 16B) so wire verification avoids double-scanning huge payloads
                // while XChaCha20-Poly1305 enforces full-ciphertext INT-CTXT verification.
                let tail = if ciphertext.len() >= 16 {
                    &ciphertext[ciphertext.len() - 16..]
                } else {
                    ciphertext.as_slice()
                };
                hmac_sha256_parts(
                    algo_key,
                    &[
                        b"wire-mac-aead-tag-v3",
                        fingerprint,
                        &seq.to_le_bytes(),
                        &epoch.to_le_bytes(),
                        ratchet_pub,
                        partial_256b,
                        &(ciphertext.len() as u64).to_le_bytes(),
                        tail,
                    ],
                )
            }
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
        let (b_tx, a_rx) =
            CellularMesh::new_paired(config, bob_to_alice_custody, bob_hw, alice_hw)?;
        Ok((Self { tx: a_tx, rx: a_rx }, Self { tx: b_tx, rx: b_rx }))
    }

    /// Configures the DH rekey cadence in packets on both TX and RX meshes (`1` = every message).
    pub fn set_dh_rekey_interval(&mut self, interval: u64) {
        self.tx.set_dh_rekey_interval(interval);
        self.rx.set_dh_rekey_interval(interval);
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
        self.rx
            .hop_epoch_ratchet_rx(hw, target_epoch, epoch_eph_pub)
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
