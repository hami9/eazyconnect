use serde::{Deserialize, Serialize};

use crate::primitives::{hmac_sha256_parts, whitened_stream};

/// Discrete 3D coordinate inside the `D x D x D` cube storage space (`Section 4.1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Coord3D {
    pub x: u32,
    pub y: u32,
    pub z: u32,
}

/// Manages 3D keyed spiral placement, `O(W * K)` windowed lookup, and provably bijective
/// epoch hopping across coordinates and sub-matrix nibbles (`Section 4.1`).
#[derive(Debug, Clone)]
pub struct SpiralSpace {
    pub space_dim: u32,
    pub spiral_coeffs: [u32; 3],
}

impl SpiralSpace {
    /// Creates a spiral coordinate engine for a `space_dim^3` grid.
    pub fn new(space_dim: u32, spiral_coeffs: [u32; 3]) -> Self {
        Self {
            space_dim: space_dim.max(16),
            spiral_coeffs,
        }
    }

    /// Places `slot_index` onto a keyed 3D spiral arm for `epoch`.
    pub fn spiral_arm_coord(&self, epoch_key: &[u8; 32], epoch: u64, slot_index: usize) -> Coord3D {
        let d = self.space_dim as u64;
        let idx = slot_index as u64;
        let arm_digest = hmac_sha256_parts(
            epoch_key,
            &[b"spiral-arm", &epoch.to_le_bytes(), &idx.to_le_bytes()],
        );
        let jx = u64::from_le_bytes(arm_digest[0..8].try_into().unwrap());
        let jy = u64::from_le_bytes(arm_digest[8..16].try_into().unwrap());
        let jz = u64::from_le_bytes(arm_digest[16..24].try_into().unwrap());

        let base = Coord3D {
            x: ((idx * self.spiral_coeffs[0] as u64 + jx) % d) as u32,
            y: ((idx * self.spiral_coeffs[1] as u64 + jy) % d) as u32,
            z: ((idx * self.spiral_coeffs[2] as u64 + jz) % d) as u32,
        };
        self.hop_coord_bijective(epoch_key, epoch, base)
    }

    /// Applies a provably invertible 1-to-1 (bijective) keyed permutation across `[0, space_dim)^3`.
    pub fn hop_coord_bijective(
        &self,
        epoch_key: &[u8; 32],
        epoch: u64,
        coord: Coord3D,
    ) -> Coord3D {
        let d = self.space_dim as i64;
        let params = self.derive_bijection_params(epoch_key, epoch);

        // Layer 1: modular affine transform per axis with multipliers coprime to `space_dim`.
        let x1 = ((params.ax * coord.x as i64 + params.bx).rem_euclid(d)) as u32;
        let y1 = ((params.ay * coord.y as i64 + params.by).rem_euclid(d)) as u32;
        let z1 = ((params.az * coord.z as i64 + params.bz).rem_euclid(d)) as u32;

        // Layer 2: triangular Feistel cross-axis mixing (guaranteed bijective).
        let x2 = ((x1 as i64 + mix_pair(&params.mix_key, 1, y1, z1, d)).rem_euclid(d)) as u32;
        let y2 = ((y1 as i64 + mix_pair(&params.mix_key, 2, x2, z1, d)).rem_euclid(d)) as u32;
        let z2 = ((z1 as i64 + mix_pair(&params.mix_key, 3, x2, y2, d)).rem_euclid(d)) as u32;

        Coord3D {
            x: x2,
            y: y2,
            z: z2,
        }
    }

    /// Exact mathematical inverse of [`Self::hop_coord_bijective`].
    pub fn unhop_coord_bijective(
        &self,
        epoch_key: &[u8; 32],
        epoch: u64,
        hopped: Coord3D,
    ) -> Coord3D {
        let d = self.space_dim as i64;
        let params = self.derive_bijection_params(epoch_key, epoch);

        // Inverse Layer 2 in reverse order.
        let z1 = ((hopped.z as i64 - mix_pair(&params.mix_key, 3, hopped.x, hopped.y, d))
            .rem_euclid(d)) as u32;
        let y1 = ((hopped.y as i64 - mix_pair(&params.mix_key, 2, hopped.x, z1, d))
            .rem_euclid(d)) as u32;
        let x1 = ((hopped.x as i64 - mix_pair(&params.mix_key, 1, y1, z1, d)).rem_euclid(d)) as u32;

        // Inverse Layer 1 using modular multiplicative inverses.
        let x = ((params.ax_inv * (x1 as i64 - params.bx)).rem_euclid(d)) as u32;
        let y = ((params.ay_inv * (y1 as i64 - params.by)).rem_euclid(d)) as u32;
        let z = ((params.az_inv * (z1 as i64 - params.bz)).rem_euclid(d)) as u32;

        Coord3D { x, y, z }
    }

    /// Generates a keyed Fisher-Yates bijection over `n_nibbles` (default `250`).
    pub fn nibble_permutation(epoch_key: &[u8; 32], epoch: u64, n_nibbles: usize) -> Vec<usize> {
        let mut perm: Vec<usize> = (0..n_nibbles).collect();
        if n_nibbles <= 1 {
            return perm;
        }
        let mut stream = vec![0u8; n_nibbles * 4];
        whitened_stream(epoch_key, &epoch.to_le_bytes(), &mut stream);
        for i in (1..n_nibbles).rev() {
            let off = i * 4;
            let raw = u32::from_le_bytes([stream[off], stream[off + 1], stream[off + 2], stream[off + 3]]);
            let j = (raw as usize) % (i + 1);
            perm.swap(i, j);
        }
        perm
    }

    /// Permutes all 4-bit nibbles of `bytes` in-place via a bijective epoch permutation.
    pub fn permute_nibbles(bytes: &mut [u8], epoch_key: &[u8; 32], epoch: u64) {
        let n_nibbles = bytes.len() * 2;
        let perm = Self::nibble_permutation(epoch_key, epoch, n_nibbles);
        let mut out = vec![0u8; bytes.len()];
        for (src_idx, &dst_idx) in perm.iter().enumerate() {
            let nibble = get_nibble(bytes, src_idx);
            set_nibble(&mut out, dst_idx, nibble);
        }
        bytes.copy_from_slice(&out);
    }

    /// Exact inverse of [`Self::permute_nibbles`].
    pub fn unpermute_nibbles(bytes: &mut [u8], epoch_key: &[u8; 32], epoch: u64) {
        let n_nibbles = bytes.len() * 2;
        let perm = Self::nibble_permutation(epoch_key, epoch, n_nibbles);
        let mut out = vec![0u8; bytes.len()];
        for (src_idx, &dst_idx) in perm.iter().enumerate() {
            let nibble = get_nibble(bytes, dst_idx);
            set_nibble(&mut out, src_idx, nibble);
        }
        bytes.copy_from_slice(&out);
    }

    /// Scans only a `window` slice along the keyed spiral arm (`O(W * K)` instead of `O(N * K)`).
    /// Returns the matching slot index and number of candidate slots inspected.
    pub fn search_spiral_window(
        &self,
        coords: &[Coord3D],
        epoch_key: &[u8; 32],
        epoch: u64,
        start_slot: usize,
        window: usize,
        target: Coord3D,
    ) -> (Option<usize>, usize) {
        if coords.is_empty() || window == 0 {
            return (None, 0);
        }
        let n = coords.len();
        let steps = window.min(n);
        let mut inspected = 0usize;
        for offset in 0..steps {
            let slot = (start_slot + offset) % n;
            inspected += 1;
            let expected = self.spiral_arm_coord(epoch_key, epoch, slot);
            if coords[slot] == target && expected == target {
                return (Some(slot), inspected);
            }
        }
        (None, inspected)
    }

    fn derive_bijection_params(&self, epoch_key: &[u8; 32], epoch: u64) -> BijectionParams {
        let d = self.space_dim as i64;
        let seed = hmac_sha256_parts(epoch_key, &[b"coord-bijection", &epoch.to_le_bytes()]);
        let raw_ax = u32::from_le_bytes(seed[0..4].try_into().unwrap()) as i64;
        let raw_ay = u32::from_le_bytes(seed[4..8].try_into().unwrap()) as i64;
        let raw_az = u32::from_le_bytes(seed[8..12].try_into().unwrap()) as i64;

        let ax = next_coprime(raw_ax, d);
        let ay = next_coprime(raw_ay, d);
        let az = next_coprime(raw_az, d);

        BijectionParams {
            ax,
            ay,
            az,
            ax_inv: mod_inverse(ax, d),
            ay_inv: mod_inverse(ay, d),
            az_inv: mod_inverse(az, d),
            bx: (u32::from_le_bytes(seed[12..16].try_into().unwrap()) as i64).rem_euclid(d),
            by: (u32::from_le_bytes(seed[16..20].try_into().unwrap()) as i64).rem_euclid(d),
            bz: (u32::from_le_bytes(seed[20..24].try_into().unwrap()) as i64).rem_euclid(d),
            mix_key: seed,
        }
    }
}

struct BijectionParams {
    ax: i64,
    ay: i64,
    az: i64,
    ax_inv: i64,
    ay_inv: i64,
    az_inv: i64,
    bx: i64,
    by: i64,
    bz: i64,
    mix_key: [u8; 32],
}

fn mix_pair(key: &[u8; 32], tag: u8, u: u32, v: u32, modulus: i64) -> i64 {
    let mut msg = [0u8; 9];
    msg[0] = tag;
    msg[1..5].copy_from_slice(&u.to_le_bytes());
    msg[5..9].copy_from_slice(&v.to_le_bytes());
    let digest = hmac_sha256_parts(key, &[&msg]);
    (u64::from_le_bytes(digest[0..8].try_into().unwrap()) % modulus as u64) as i64
}

fn gcd(mut a: i64, mut b: i64) -> i64 {
    while b != 0 {
        let t = a % b;
        a = b;
        b = t;
    }
    a.abs()
}

fn next_coprime(seed: i64, modulus: i64) -> i64 {
    let mut candidate = (seed.rem_euclid(modulus - 1)) + 1;
    if candidate % 2 == 0 {
        candidate += 1;
    }
    while gcd(candidate, modulus) != 1 {
        candidate += 2;
        if candidate >= modulus {
            candidate = 1;
        }
    }
    candidate
}

fn mod_inverse(a: i64, m: i64) -> i64 {
    let (mut t, mut new_t) = (0i64, 1i64);
    let (mut r, mut new_r) = (m, a.rem_euclid(m));
    while new_r != 0 {
        let q = r / new_r;
        (t, new_t) = (new_t, t - q * new_t);
        (r, new_r) = (new_r, r - q * new_r);
    }
    t.rem_euclid(m)
}

#[inline]
fn get_nibble(bytes: &[u8], nibble_idx: usize) -> u8 {
    let b = bytes[nibble_idx / 2];
    if nibble_idx.is_multiple_of(2) {
        b >> 4
    } else {
        b & 0x0F
    }
}

#[inline]
fn set_nibble(bytes: &mut [u8], nibble_idx: usize, val: u8) {
    let slot = &mut bytes[nibble_idx / 2];
    if nibble_idx.is_multiple_of(2) {
        *slot = (*slot & 0x0F) | ((val & 0x0F) << 4);
    } else {
        *slot = (*slot & 0xF0) | (val & 0x0F);
    }
}
