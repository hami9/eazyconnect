use blake2::{Blake2b512, Digest as Blake2Digest};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sha3::Sha3_256;
use subtle::{ConditionallySelectable, ConstantTimeEq};

use crate::error::{CubeHashError, Result};

type HmacSha256 = Hmac<Sha256>;

/// Time/digest algorithm selected by the `AuditorCube` (`Section 3.1` & `4.4`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimeAlgorithm {
    Blake2b,
    Sha3_256,
    HmacSha256,
    HybridTriMix,
}

/// Non-linear combining function selected by the `AuditorCube` (`Section 3.1` & `5`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CombiningFn {
    XorFoldMix,
    FeistelNonLinear,
    HmacTreeCombine,
}

/// Fills `buf` from the operating system CSPRNG.
pub fn fill_random(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|_| CubeHashError::RngFailure)
}

/// Returns a random value uniformly distributed in `min..=max` using rejection sampling.
pub fn random_usize_inclusive(min: usize, max: usize) -> Result<usize> {
    if min >= max {
        return Ok(min);
    }
    let span = (max - min) as u64 + 1;
    let limit = u64::MAX - (u64::MAX % span);
    let mut raw = [0u8; 8];
    loop {
        fill_random(&mut raw)?;
        let val = u64::from_le_bytes(raw);
        if val < limit {
            return Ok(min + (val % span) as usize);
        }
    }
}

/// Computes `HMAC-SHA256(key, data)` as referenced in Section 7.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    hmac_sha256_parts(key, &[data])
}

/// Computes `HMAC-SHA256` over multiple ordered slices without allocating a combined buffer.
pub fn hmac_sha256_parts(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac =
        <HmacSha256 as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

/// Expands keying material using `HKDF-SHA256` with domain separation.
pub fn hkdf_expand_label(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    hk.expand(info, out)
        .map_err(|_| CubeHashError::CryptoFailure("hkdf output length exceeded"))
}

/// Generates an arbitrary-length cryptographically whitened byte stream from a 32-byte seed.
pub fn whitened_stream(seed: &[u8; 32], domain: &[u8], out: &mut [u8]) {
    let mut offset = 0usize;
    let mut counter: u64 = 0;
    while offset < out.len() {
        let mut hasher = Blake2b512::new();
        hasher.update(seed);
        hasher.update(domain);
        hasher.update(counter.to_le_bytes());
        let block = hasher.finalize();
        let take = (out.len() - offset).min(block.len());
        out[offset..offset + take].copy_from_slice(&block[..take]);
        offset += take;
        counter += 1;
    }
}

/// Constant-time slice equality check to avoid timing side-channels.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Executes BLAKE2b, SHA3-256, and HMAC-SHA256 under a fixed iteration budget (`Section 4.4`)
/// and selects the target algorithm's digest in constant time so execution work and timing do not
/// vary by selected branch or chain position.
pub fn fixed_budget_mix(
    algo: TimeAlgorithm,
    key: &[u8],
    domain: &[u8],
    data: &[u8],
    rounds: usize,
) -> [u8; 32] {
    let iterations = rounds.max(1);
    let key_len = (key.len() as u64).to_le_bytes();
    let dom_len = (domain.len() as u64).to_le_bytes();
    let data_len = (data.len() as u64).to_le_bytes();

    // Round 0 absorbs arbitrary-length inputs once per primitive with canonical length framing.
    let mut b2 = Blake2b512::new();
    b2.update(b"FB-B2");
    b2.update(key_len);
    b2.update(key);
    b2.update(dom_len);
    b2.update(domain);
    b2.update(data_len);
    b2.update(data);
    let b2_init = b2.finalize();
    let mut state_blake = [0u8; 32];
    for i in 0..32 {
        state_blake[i] = b2_init[i] ^ b2_init[32 + i];
    }

    let mut s3 = Sha3_256::new();
    s3.update(b"FB-S3");
    s3.update(key_len);
    s3.update(key);
    s3.update(dom_len);
    s3.update(domain);
    s3.update(data_len);
    s3.update(data);
    let mut state_sha3: [u8; 32] = s3.finalize().into();

    let mut state_hmac = hmac_sha256_parts(key, &[b"FB-HM", &dom_len, domain, &data_len, data]);

    // Subsequent rounds ratchet compact 32-byte states cleanly under constant iteration work.
    for round in 1..iterations {
        let r_bytes = (round as u64).to_le_bytes();

        let mut b2r = Blake2b512::new();
        b2r.update(b"FB-R-B2");
        b2r.update(key_len);
        b2r.update(key);
        b2r.update(r_bytes);
        b2r.update(state_blake);
        let b2_full = b2r.finalize();
        for i in 0..32 {
            state_blake[i] = b2_full[i] ^ b2_full[32 + i];
        }

        let mut s3r = Sha3_256::new();
        s3r.update(b"FB-R-S3");
        s3r.update(key_len);
        s3r.update(key);
        s3r.update(r_bytes);
        s3r.update(state_sha3);
        state_sha3.copy_from_slice(&s3r.finalize());

        state_hmac = hmac_sha256_parts(key, &[b"FB-R-HM", &r_bytes, &state_hmac]);
    }

    let mut hybrid = [0u8; 32];
    for i in 0..32 {
        hybrid[i] = state_blake[i] ^ state_sha3[i].rotate_left(3) ^ state_hmac[i].rotate_right(5);
    }

    // Constant-time branchless selection across the four outputs.
    let is_blake = subtle::Choice::from((algo == TimeAlgorithm::Blake2b) as u8);
    let is_sha3 = subtle::Choice::from((algo == TimeAlgorithm::Sha3_256) as u8);
    let is_hmac = subtle::Choice::from((algo == TimeAlgorithm::HmacSha256) as u8);

    let mut out = hybrid;
    for i in 0..32 {
        out[i] = u8::conditional_select(&out[i], &state_blake[i], is_blake);
        out[i] = u8::conditional_select(&out[i], &state_sha3[i], is_sha3);
        out[i] = u8::conditional_select(&out[i], &state_hmac[i], is_hmac);
    }
    out
}

/// Non-linear reaction mixer used during the 20-cube consumption step (`Section 5`).
pub fn combine_non_linear(
    combiner: CombiningFn,
    algo_key: &[u8; 32],
    inputs: &[&[u8]],
    budget: usize,
) -> [u8; 32] {
    let mut acc = [0u8; 32];
    for (idx, chunk) in inputs.iter().enumerate() {
        let mut b2 = Blake2b512::new();
        b2.update(b"combine-step-v2");
        b2.update(algo_key);
        b2.update((idx as u64).to_le_bytes());
        b2.update((chunk.len() as u64).to_le_bytes());
        b2.update(chunk);
        let full = b2.finalize();
        let mut step_digest = [0u8; 32];
        step_digest.copy_from_slice(&full[..32]);
        match combiner {
            CombiningFn::XorFoldMix => {
                for i in 0..32 {
                    acc[i] ^= step_digest[i].rotate_left((idx % 7 + 1) as u32);
                }
            }
            CombiningFn::FeistelNonLinear => {
                // 2-round bytewise ARX + S-box-like modular mixing
                for i in 0..16 {
                    let l = acc[i];
                    let r = acc[i + 16];
                    let f = r.wrapping_add(step_digest[i]).rotate_left(3) ^ step_digest[i + 16];
                    acc[i] = r;
                    acc[i + 16] = l ^ f;
                }
            }
            CombiningFn::HmacTreeCombine => {
                acc = hmac_sha256_parts(algo_key, &[&acc, &step_digest]);
            }
        }
    }
    // Final fixed-budget HybridTriMix whitening pass across the accumulator.
    fixed_budget_mix(
        TimeAlgorithm::HybridTriMix,
        algo_key,
        b"combine-final",
        &acc,
        budget,
    )
}

/// Encrypts arbitrary-length plaintext with `XChaCha20-Poly1305` and explicit AAD.
pub fn aead_seal(
    key: &[u8; 32],
    nonce: &[u8; 24],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CubeHashError::CryptoFailure("aead encryption failed"))
}

/// Decrypts `XChaCha20-Poly1305` ciphertext and verifies AAD.
pub fn aead_open(
    key: &[u8; 32],
    nonce: &[u8; 24],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CubeHashError::AuthenticationFailed)
}

/// Measures fraction of `1` bits in `bytes` (expected near `0.5` for 50/50 whitened data).
pub fn ones_ratio(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let ones: u64 = bytes.iter().map(|b| b.count_ones() as u64).sum();
    ones as f64 / (bytes.len() as f64 * 8.0)
}

/// Computes empirical Shannon entropy in bits per byte (`0.0..=8.0`).
pub fn shannon_entropy_bits_per_byte(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    let mut entropy = 0.0;
    for &c in &counts {
        if c > 0 {
            let p = c as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Computes Pearson's chi-squared statistic (`df = 255`) testing byte uniformity (`expected = n / 256`).
pub fn pearson_chi_square_uniform(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let expected = bytes.len() as f64 / 256.0;
    counts
        .iter()
        .map(|&obs| {
            let diff = obs as f64 - expected;
            (diff * diff) / expected
        })
        .sum()
}

/// Computes empirical lag-1 bit-level serial correlation (`-1.0..=1.0`, ideal uniform `0.0`).
pub fn lag1_bit_autocorrelation(bytes: &[u8]) -> f64 {
    let total_bits = bytes.len() * 8;
    if total_bits < 2 {
        return 0.0;
    }
    let mut same_count = 0usize;
    let mut prev_bit = bytes[0] & 1;
    for (idx, &byte) in bytes.iter().enumerate() {
        let start = if idx == 0 { 1 } else { 0 };
        for shift in start..8 {
            let cur = (byte >> shift) & 1;
            if cur == prev_bit {
                same_count += 1;
            }
            prev_bit = cur;
        }
    }
    let pairs = (total_bits - 1) as f64;
    let diff_count = (total_bits - 1) - same_count;
    (same_count as f64 - diff_count as f64) / pairs
}
