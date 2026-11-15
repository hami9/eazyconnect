use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::config::MeshConfig;
use crate::error::{CubeHashError, Result};
use crate::primitives::{
    fill_random, hmac_sha256_parts, ones_ratio, random_usize_inclusive,
    shannon_entropy_bits_per_byte, whitened_stream,
};

/// Result of Bitwise Majority Voting self-healing (`Section 4.3`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealReport {
    /// Number of flipped bits repaired in `core_pattern`.
    pub repaired_core_bits: usize,
    /// Number of flipped bits repaired across shadow copies inside `sub_matrix`.
    pub repaired_shadow_bits: usize,
    /// True when the hot-spare checksum detected corruption that TMR could not resolve alone.
    pub unrecoverable_anomaly: bool,
}

/// Three-layer `VoxelCube` (`Section 2`) with configurable dimensions (`MeshConfig`):
/// 1. `sub_matrix`: 10x10x10 structure (default 1000 bits / 125 bytes / 250 nibbles) hosting
///    masked TMR self-healing shadows and hot-spare integrity bits.
/// 2. `core_pattern`: default 256-bit (32-byte) core holding flags, payload/next ID, and MAC.
/// 3. `weight_layer`: variable-length (default 16..96 bytes) whitened padding preventing size leaks.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct VoxelCube {
    pub cube_uid: [u8; 16],
    pub generation: u64,
    pub sub_matrix: Vec<u8>,
    pub core_pattern: Vec<u8>,
    pub weight_layer: Vec<u8>,
}

/// Compact Section 7 representation for standard 1000-bit / 256-bit cubes (`181` bytes).
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SubCube {
    pub cube_uid: [u8; 16],
    pub generation: u64,
    pub core_256b: [u8; 32],
    #[serde(with = "serde_bytes_125")]
    pub sub_1000b: [u8; 125],
}

mod serde_bytes_125 {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(val: &[u8; 125], s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_bytes(val)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<[u8; 125], D::Error> {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(d)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 125 bytes for sub_1000b"))
    }
}

impl TryFrom<&VoxelCube> for SubCube {
    type Error = CubeHashError;

    fn try_from(v: &VoxelCube) -> Result<Self> {
        if v.core_pattern.len() != 32 || v.sub_matrix.len() != 125 {
            return Err(CubeHashError::InvalidConfig(
                "SubCube fixed layout requires standard 32B core and 125B sub_matrix",
            ));
        }
        let mut core_256b = [0u8; 32];
        let mut sub_1000b = [0u8; 125];
        core_256b.copy_from_slice(&v.core_pattern);
        sub_1000b.copy_from_slice(&v.sub_matrix);
        Ok(Self {
            cube_uid: v.cube_uid,
            generation: v.generation,
            core_256b,
            sub_1000b,
        })
    }
}

impl VoxelCube {
    /// Generates a fresh `VoxelCube` with self-healing TMR shadows and whitened variable weight.
    pub fn build_with_core(
        config: &MeshConfig,
        seal_key: &[u8; 32],
        cube_uid: [u8; 16],
        generation: u64,
        core_pattern: Vec<u8>,
    ) -> Result<Self> {
        config.validate()?;
        if core_pattern.len() != config.core_bytes {
            return Err(CubeHashError::InvalidConfig(
                "core_pattern length does not match MeshConfig.core_bytes",
            ));
        }

        let sub_matrix =
            encode_sub_matrix_with_shadows(config, seal_key, &cube_uid, generation, &core_pattern);
        let weight_layer = generate_variable_weight(config)?;

        Ok(Self {
            cube_uid,
            generation,
            sub_matrix,
            core_pattern,
            weight_layer,
        })
    }

    /// Generates a randomized mesh cube initialized from `seed_material`.
    pub fn generate_mesh_cube(
        config: &MeshConfig,
        seal_key: &[u8; 32],
        generation: u64,
        seed_material: &[u8; 32],
    ) -> Result<Self> {
        let mut cube_uid = [0u8; 16];
        let uid_digest = hmac_sha256_parts(seed_material, &[b"cube-uid", &generation.to_le_bytes()]);
        cube_uid.copy_from_slice(&uid_digest[..16]);

        let mut core_pattern = vec![0u8; config.core_bytes];
        whitened_stream(seed_material, &cube_uid, &mut core_pattern);

        Self::build_with_core(config, seal_key, cube_uid, generation, core_pattern)
    }

    /// Executes Bitwise Majority Voting (`Section 4.3`) on a cube whose `sub_matrix` may have
    /// undergone bijective nibble permutation at `epoch`.
    pub fn heal_at_epoch(
        &mut self,
        seal_key: &[u8; 32],
        epoch_key: Option<(&[u8; 32], u64)>,
    ) -> Result<HealReport> {
        if let Some((key, epoch)) = epoch_key.filter(|(_, e)| *e > 0) {
            crate::spiral::SpiralSpace::unpermute_nibbles(&mut self.sub_matrix, key, epoch);
        }
        let report = self.heal_bitwise(seal_key);
        if let Some((key, epoch)) = epoch_key.filter(|(_, e)| *e > 0) {
            crate::spiral::SpiralSpace::permute_nibbles(&mut self.sub_matrix, key, epoch);
        }
        report
    }

    /// Executes Bitwise Majority Voting (`Section 4.3`) to repair bit-rot/noise in either
    /// `core_pattern` or the masked shadow copies embedded inside `sub_matrix`.
    pub fn heal_bitwise(&mut self, seal_key: &[u8; 32]) -> Result<HealReport> {
        let core_len = self.core_pattern.len();
        if self.sub_matrix.len() < core_len * 2 {
            return Err(CubeHashError::InvalidConfig(
                "sub_matrix too small for TMR shadows",
            ));
        }
        let (mask_a, mask_b, spare_key) =
            derive_shadow_masks(seal_key, &self.cube_uid, self.generation, core_len);

        let mut repaired_core_bits = 0usize;
        let mut repaired_shadow_bits = 0usize;

        for i in 0..core_len {
            let c = self.core_pattern[i];
            let a = self.sub_matrix[i] ^ mask_a[i];
            let b = self.sub_matrix[core_len + i] ^ mask_b[i];

            let voted = (c & a) | (c & b) | (a & b);
            repaired_core_bits += (c ^ voted).count_ones() as usize;
            repaired_shadow_bits += ((a ^ voted).count_ones() + (b ^ voted).count_ones()) as usize;

            self.core_pattern[i] = voted;
            self.sub_matrix[i] = voted ^ mask_a[i];
            self.sub_matrix[core_len + i] = voted ^ mask_b[i];
        }

        // Verify hot-spare checksum when room exists after the two shadow copies (true for all valid configs).
        let spare_offset = core_len * 2;
        let spare_len = self.sub_matrix.len() - spare_offset;
        let mut unrecoverable_anomaly = false;
        if spare_len >= 8 {
            let expected_tag = compute_hot_spare_tag(&spare_key, &self.core_pattern);
            let observed = &self.sub_matrix[spare_offset..spare_offset + 8];
            // Tolerate minor bit flips inside the hot-spare tag itself (Hamming distance <= 2 bits),
            // while flagging catastrophic multi-copy divergence.
            let diff_bits: u32 = expected_tag
                .iter()
                .zip(observed.iter())
                .map(|(x, y)| (x ^ y).count_ones())
                .sum();
            if diff_bits > 2 {
                unrecoverable_anomaly = true;
            }
        }

        if unrecoverable_anomaly {
            return Err(CubeHashError::UnrecoverableCorruption);
        }

        Ok(HealReport {
            repaired_core_bits,
            repaired_shadow_bits,
            unrecoverable_anomaly,
        })
    }

    /// Fraction of `1` bits across the sub-matrix + weight layer (expected near `0.5`).
    pub fn bit_balance_ratio(&self) -> f64 {
        let mut buf = Vec::with_capacity(self.sub_matrix.len() + self.weight_layer.len());
        buf.extend_from_slice(&self.sub_matrix);
        buf.extend_from_slice(&self.weight_layer);
        ones_ratio(&buf)
    }

    /// Empirical Shannon entropy of the outer visible cube layers in bits/byte.
    pub fn visible_entropy_bits_per_byte(&self) -> f64 {
        let mut buf = Vec::with_capacity(self.sub_matrix.len() + self.weight_layer.len());
        buf.extend_from_slice(&self.sub_matrix);
        buf.extend_from_slice(&self.weight_layer);
        shannon_entropy_bits_per_byte(&buf)
    }
}

/// Encodes `core_pattern` into two independently masked TMR shadow copies plus a hot-spare tag
/// and whitened 50/50 filler inside `sub_matrix` (`Section 2` & `Section 4.3`).
pub(crate) fn encode_sub_matrix_with_shadows(
    config: &MeshConfig,
    seal_key: &[u8; 32],
    cube_uid: &[u8; 16],
    generation: u64,
    core_pattern: &[u8],
) -> Vec<u8> {
    let core_len = core_pattern.len();
    let (mask_a, mask_b, spare_key) =
        derive_shadow_masks(seal_key, cube_uid, generation, core_len);
    let mut sub = vec![0u8; config.sub_matrix_bytes];

    for i in 0..core_len {
        sub[i] = core_pattern[i] ^ mask_a[i];
        sub[core_len + i] = core_pattern[i] ^ mask_b[i];
    }

    let spare_offset = core_len * 2;
    let remaining = config.sub_matrix_bytes - spare_offset;
    if remaining > 0 {
        // Fill hot-spare and remaining bytes with whitened uniform stream first.
        whitened_stream(&spare_key, cube_uid, &mut sub[spare_offset..]);
        if remaining >= 8 {
            let tag = compute_hot_spare_tag(&spare_key, core_pattern);
            sub[spare_offset..spare_offset + 8].copy_from_slice(&tag);
        }
    }

    sub
}

/// Generates variable-size whitened weight padding (`weight_min_bytes..=weight_max_bytes`).
pub(crate) fn generate_variable_weight(config: &MeshConfig) -> Result<Vec<u8>> {
    if !config.variable_wire_padding || config.weight_max_bytes == 0 {
        return Ok(Vec::new());
    }
    let len = random_usize_inclusive(config.weight_min_bytes, config.weight_max_bytes)?;
    let mut buf = vec![0u8; len];
    fill_random(&mut buf)?;
    Ok(buf)
}

fn derive_shadow_masks(
    seal_key: &[u8; 32],
    cube_uid: &[u8; 16],
    generation: u64,
    core_len: usize,
) -> (Vec<u8>, Vec<u8>, [u8; 32]) {
    let gen_bytes = generation.to_le_bytes();
    let seed_a = hmac_sha256_parts(seal_key, &[b"tmr-shadow-a", cube_uid, &gen_bytes]);
    let seed_b = hmac_sha256_parts(seal_key, &[b"tmr-shadow-b", cube_uid, &gen_bytes]);
    let spare_key = hmac_sha256_parts(seal_key, &[b"tmr-hot-spare", cube_uid, &gen_bytes]);

    let mut mask_a = vec![0u8; core_len];
    let mut mask_b = vec![0u8; core_len];
    whitened_stream(&seed_a, b"mask-a", &mut mask_a);
    whitened_stream(&seed_b, b"mask-b", &mut mask_b);
    (mask_a, mask_b, spare_key)
}

fn compute_hot_spare_tag(spare_key: &[u8; 32], core_pattern: &[u8]) -> [u8; 8] {
    let digest = hmac_sha256_parts(spare_key, &[b"hot-spare-mac", core_pattern]);
    let mut tag = [0u8; 8];
    tag.copy_from_slice(&digest[..8]);
    tag
}
