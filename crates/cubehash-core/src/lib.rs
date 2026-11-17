#![forbid(unsafe_code)]
//! `cubehash-core`: Standalone, general-purpose hierarchical, self-healing, hardware-bound
//! cellular cube cryptography engine.

pub mod config;
pub mod custody;
pub mod error;
pub mod honey;
pub mod hybrid;
pub mod mesh;
pub mod primitives;
pub mod spiral;
pub mod voxel;

pub use config::{
    MeshConfig, DEFAULT_CONSUME_FOR_NEXT, DEFAULT_CORE_BYTES, DEFAULT_MESH_SIZE,
    DEFAULT_QUORUM_SELECT, DEFAULT_SUB_MATRIX_BYTES, FINGERPRINT_BYTES,
};
pub use custody::{
    AuditorCube, HardwareProvider, LocalClientClockGuard, MainCube, MotherCube,
    OsBoundHardwareProvider, ThreeCubeCustody, VirtualHardwareEnclave,
};
pub use error::{CubeHashError, Result};
pub use honey::{DteEngine, HoneyProfile};
pub use hybrid::{HybridTriMix, HybridTriMixHasher};
pub use mesh::{
    build_custody_bundle, CellularMesh, DeliveryAck, DuplexCubeSession, EphemeralCubeAlgorithm,
    MeshAuditStats, PayloadMode, ReceiveOutcome, UniqueWireCube, WirePacket,
};
pub use primitives::{
    lag1_bit_autocorrelation, ones_ratio, pearson_chi_square_uniform,
    shannon_entropy_bits_per_byte, CombiningFn, TimeAlgorithm,
};
pub use spiral::{Coord3D, SpiralSpace};
pub use voxel::{HealReport, SubCube, VoxelCube};
