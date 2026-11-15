use serde::{Deserialize, Serialize};

use crate::error::{CubeHashError, Result};

/// Default number of sub-cubes in a client cellular mesh (`Section 5`).
pub const DEFAULT_MESH_SIZE: usize = 100;
/// Default number of complementary sub-cubes selected per transaction (`Section 5`).
pub const DEFAULT_QUORUM_SELECT: usize = 25;
/// Default number of selected sub-cubes consumed into the next-generation reaction (`Section 5`).
pub const DEFAULT_CONSUME_FOR_NEXT: usize = 20;
/// Default sub-matrix size in bytes (`1000 bits = 125 bytes = 250 nibbles`).
pub const DEFAULT_SUB_MATRIX_BYTES: usize = 125;
/// Default core pattern size in bytes (`256 bits = 32 bytes`).
pub const DEFAULT_CORE_BYTES: usize = 32;
/// Default fingerprint size on the wire in bytes (`128 bits = 16 bytes`).
pub const FINGERPRINT_BYTES: usize = 16;

/// Configurable sizing and security parameters for `VoxelCube` and `CellularMesh`.
///
/// Defaults match the `cubehash` specification (`1000`-bit sub-matrix, `256`-bit core,
/// `16..96`-byte variable weight padding, `100`-cube mesh, `25` selected / `20` consumed,
/// `1000x1000x1000` 3D spiral space). Parameters can be resized for constrained IoT
/// targets or high-throughput workloads while enforcing security invariants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshConfig {
    /// Size of the sub-matrix layer per cube in bytes (`125` = `1000` bits = `250` nibbles).
    pub sub_matrix_bytes: usize,
    /// Size of the core pattern layer per cube in bytes (`32` = `256` bits).
    pub core_bytes: usize,
    /// Minimum variable weight padding bytes appended per cube (`16`).
    pub weight_min_bytes: usize,
    /// Maximum variable weight padding bytes appended per cube (`96`).
    pub weight_max_bytes: usize,
    /// Total number of active sub-cubes maintained in the client mesh (`100`).
    pub mesh_size: usize,
    /// Number of complementary sub-cubes selected per arrival/send cycle (`25`).
    pub quorum_select: usize,
    /// Number of selected cubes reacted non-linearly to forge the next core (`20`).
    pub consume_for_next: usize,
    /// Edge dimension `D` of the `D x D x D` 3D spiral coordinate space (`1000`).
    pub space_dim: u32,
    /// Spiral search window `W` for `O(W * K)` keyed lookup (`16`).
    pub spiral_window: usize,
    /// Number of decoy chains derived from real cubes for zero-oracle deception.
    pub decoy_chain_count: usize,
    /// Constant iteration budget executed per cryptographic step (`Section 4.4`).
    pub fixed_step_budget: usize,
    /// Whether variable weight padding (`weight_min_bytes..=weight_max_bytes`) is appended on wire.
    pub variable_wire_padding: bool,
}

impl Default for MeshConfig {
    fn default() -> Self {
        Self::standard()
    }
}

impl MeshConfig {
    /// Exact default sizing from the `cubehash` specification.
    pub fn standard() -> Self {
        Self {
            sub_matrix_bytes: DEFAULT_SUB_MATRIX_BYTES,
            core_bytes: DEFAULT_CORE_BYTES,
            weight_min_bytes: 16,
            weight_max_bytes: 96,
            mesh_size: DEFAULT_MESH_SIZE,
            quorum_select: DEFAULT_QUORUM_SELECT,
            consume_for_next: DEFAULT_CONSUME_FOR_NEXT,
            space_dim: 1000,
            spiral_window: 16,
            decoy_chain_count: 8,
            fixed_step_budget: 4,
            variable_wire_padding: true,
        }
    }

    /// Resized compact profile suitable for low-bandwidth / IoT links while keeping TMR healing.
    pub fn compact() -> Self {
        Self {
            sub_matrix_bytes: 64,
            core_bytes: 16,
            weight_min_bytes: 8,
            weight_max_bytes: 32,
            mesh_size: 40,
            quorum_select: 12,
            consume_for_next: 9,
            space_dim: 256,
            spiral_window: 8,
            decoy_chain_count: 4,
            fixed_step_budget: 2,
            variable_wire_padding: true,
        }
    }

    /// Resized high-capacity profile with larger matrices and wider quorum mixing.
    pub fn high_capacity() -> Self {
        Self {
            sub_matrix_bytes: 256,
            core_bytes: 64,
            weight_min_bytes: 32,
            weight_max_bytes: 160,
            mesh_size: 160,
            quorum_select: 40,
            consume_for_next: 32,
            space_dim: 2000,
            spiral_window: 24,
            decoy_chain_count: 16,
            fixed_step_budget: 6,
            variable_wire_padding: true,
        }
    }

    /// Validates all structural and cryptographic invariants of the sizing parameters.
    pub fn validate(&self) -> Result<()> {
        if self.core_bytes < 16 || self.core_bytes > 128 {
            return Err(CubeHashError::InvalidConfig(
                "core_bytes must be between 16 and 128 bytes",
            ));
        }
        // TMR self-healing embeds two full masked shadow copies inside sub_matrix.
        if self.sub_matrix_bytes < self.core_bytes * 2 {
            return Err(CubeHashError::InvalidConfig(
                "sub_matrix_bytes must be at least 2 * core_bytes for TMR shadows",
            ));
        }
        if self.weight_min_bytes > self.weight_max_bytes {
            return Err(CubeHashError::InvalidConfig(
                "weight_min_bytes cannot exceed weight_max_bytes",
            ));
        }
        if self.mesh_size < 4 {
            return Err(CubeHashError::InvalidConfig("mesh_size must be at least 4"));
        }
        if self.quorum_select == 0 || self.quorum_select > self.mesh_size {
            return Err(CubeHashError::InvalidConfig(
                "quorum_select must be in 1..=mesh_size",
            ));
        }
        if self.consume_for_next == 0 || self.consume_for_next > self.quorum_select {
            return Err(CubeHashError::InvalidConfig(
                "consume_for_next must be in 1..=quorum_select",
            ));
        }
        if self.space_dim < 16 {
            return Err(CubeHashError::InvalidConfig("space_dim must be at least 16"));
        }
        if self.spiral_window == 0 {
            return Err(CubeHashError::InvalidConfig(
                "spiral_window must be at least 1",
            ));
        }
        if self.fixed_step_budget == 0 {
            return Err(CubeHashError::InvalidConfig(
                "fixed_step_budget must be at least 1",
            ));
        }
        Ok(())
    }

    /// Number of bits in the sub-matrix layer (`1000` for standard config).
    pub fn sub_matrix_bits(&self) -> usize {
        self.sub_matrix_bytes * 8
    }

    /// Number of 4-bit nibbles in the sub-matrix layer (`250` for standard config).
    pub fn sub_matrix_nibbles(&self) -> usize {
        self.sub_matrix_bytes * 2
    }

    /// Base size of a `UniqueWireCube` without variable padding (`173` bytes for standard config).
    pub fn wire_cube_base_bytes(&self) -> usize {
        FINGERPRINT_BYTES + self.core_bytes + self.sub_matrix_bytes
    }

    /// Maximum direct payload bytes carried inside `partial_256b` in `RawCore256` mode.
    /// Reserves 8 bytes for length, flags, and integrity tag inside the core slice.
    pub fn raw_core_payload_capacity(&self) -> usize {
        self.core_bytes.saturating_sub(8)
    }
}
