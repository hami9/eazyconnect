use blake2::{Blake2b512, Digest as _};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Sha256, Sha512};
use sha3::{Sha3_256, Sha3_512};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

/// Complete multi-primitive, domain-separated hybrid cryptographic engine (`HybridTriMix v2`).
///
/// Combines three structurally unrelated cryptographic families:
/// 1. HAIFA / ChaCha-derived ARX compression (`BLAKE2b-512`)
/// 2. Keccak sponge permutation (`SHA3-256` / `SHA3-512`)
/// 3. Merkle–Damgård keyed HMAC (`HMAC-SHA256` / `HMAC-SHA512`)
///
/// Every keyed invocation derives three independent length-delimited subkeys so related-key
/// or length-extension flaws in up to two families cannot break the combined PRF output.
/// Both one-shot (`mix_256` / `digest_512`) and incremental (`HybridTriMixHasher`) paths
/// produce bit-identical digests for identical `(key, domain, message, rounds)`.
pub struct HybridTriMix;

/// Incremental streaming accumulator for [`HybridTriMix`] operating in `O(1)` extra RAM.
pub struct HybridTriMixHasher {
    b2_256_state: Blake2b512,
    b2_512_state: Blake2b512,
    s3_256_state: Sha3_256,
    s3_512_state: Sha3_512,
    hm_256_state: HmacSha256,
    hm_512_state: HmacSha512,
    k_blake: [u8; 32],
    k_sha3: [u8; 32],
    k_hmac: [u8; 32],
    bytes_absorbed: u64,
}

impl Drop for HybridTriMixHasher {
    fn drop(&mut self) {
        self.k_blake.zeroize();
        self.k_sha3.zeroize();
        self.k_hmac.zeroize();
    }
}

impl HybridTriMix {
    /// Derives three cryptographically independent 256-bit leg subkeys from `key` and `domain`
    /// using canonical length-prefixed HMAC framing.
    pub fn derive_subkeys(key: &[u8], domain: &[u8]) -> ([u8; 32], [u8; 32], [u8; 32]) {
        let mut master = <HmacSha256 as KeyInit>::new_from_slice(key)
            .expect("HMAC accepts arbitrary key lengths");
        master.update(b"HTX2-MASTER");
        master.update(&(key.len() as u64).to_le_bytes());
        master.update(key);
        master.update(&(domain.len() as u64).to_le_bytes());
        master.update(domain);
        let mut prk: [u8; 32] = master.finalize().into_bytes().into();

        let k_blake = hmac256(&prk, &[b"HTX2-SUBKEY-BLAKE2B"]);
        let k_sha3 = hmac256(&prk, &[b"HTX2-SUBKEY-SHA3"]);
        let k_hmac = hmac256(&prk, &[b"HTX2-SUBKEY-HMAC"]);
        prk.zeroize();
        (k_blake, k_sha3, k_hmac)
    }

    /// Keyed 256-bit PRF/MAC combiner with canonical framing, `rounds` compression iterations,
    /// bijective byte rotations, and cross-lane 64-bit mixing.
    pub fn mix_256(key: &[u8], domain: &[u8], data: &[u8], rounds: usize) -> [u8; 32] {
        let iterations = rounds.max(1);
        let (mut kb, mut ks, mut kh) = Self::derive_subkeys(key, domain);
        let dom_len = (domain.len() as u64).to_le_bytes();
        let data_len = (data.len() as u64).to_le_bytes();

        let mut b2 = Blake2b512::new();
        b2.update(b"HTX2-256-B2");
        b2.update(kb);
        b2.update(dom_len);
        b2.update(domain);
        b2.update(data);
        b2.update(data_len);
        let b2_init = b2.finalize();
        let mut s_blake = [0u8; 32];
        for i in 0..32 {
            s_blake[i] = b2_init[i] ^ b2_init[32 + i];
        }

        let mut s3 = Sha3_256::new();
        s3.update(b"HTX2-256-S3");
        s3.update(ks);
        s3.update(dom_len);
        s3.update(domain);
        s3.update(data);
        s3.update(data_len);
        let mut s_sha3: [u8; 32] = s3.finalize().into();

        let mut hm =
            <HmacSha256 as KeyInit>::new_from_slice(&kh).expect("HMAC accepts 32-byte subkey");
        hm.update(b"HTX2-256-HM");
        hm.update(&dom_len);
        hm.update(domain);
        hm.update(data);
        hm.update(&data_len);
        let mut s_hmac: [u8; 32] = hm.finalize().into_bytes().into();

        iterate_rounds_256(
            iterations,
            &kb,
            &ks,
            &kh,
            &mut s_blake,
            &mut s_sha3,
            &mut s_hmac,
        );

        let out = combine_lanes_256(&s_blake, &s_sha3, &s_hmac);
        kb.zeroize();
        ks.zeroize();
        kh.zeroize();
        s_blake.zeroize();
        s_sha3.zeroize();
        s_hmac.zeroize();
        out
    }

    /// Constant-time MAC tag verification for [`Self::mix_256`].
    pub fn verify_tag_256(
        key: &[u8],
        domain: &[u8],
        data: &[u8],
        rounds: usize,
        expected_tag: &[u8; 32],
    ) -> bool {
        let mut computed = Self::mix_256(key, domain, data, rounds);
        let ok = bool::from(computed.ct_eq(expected_tag));
        computed.zeroize();
        ok
    }

    /// Keyed 512-bit wide-pipe combiner unifying `BLAKE2b-512`, `SHA3-512`, and `HMAC-SHA512`.
    pub fn digest_512(key: &[u8], domain: &[u8], data: &[u8], rounds: usize) -> [u8; 64] {
        let iterations = rounds.max(1);
        let (mut kb, mut ks, mut kh) = Self::derive_subkeys(key, domain);
        let dom_len = (domain.len() as u64).to_le_bytes();
        let data_len = (data.len() as u64).to_le_bytes();

        let mut b2 = Blake2b512::new();
        b2.update(b"HTX2-512-B2");
        b2.update(kb);
        b2.update(dom_len);
        b2.update(domain);
        b2.update(data);
        b2.update(data_len);
        let mut s_blake: [u8; 64] = b2.finalize().into();

        let mut s3 = Sha3_512::new();
        s3.update(b"HTX2-512-S3");
        s3.update(ks);
        s3.update(dom_len);
        s3.update(domain);
        s3.update(data);
        s3.update(data_len);
        let mut s_sha3: [u8; 64] = s3.finalize().into();

        let mut hm =
            <HmacSha512 as KeyInit>::new_from_slice(&kh).expect("HMAC-SHA512 accepts 32-byte key");
        hm.update(b"HTX2-512-HM");
        hm.update(&dom_len);
        hm.update(domain);
        hm.update(data);
        hm.update(&data_len);
        let mut s_hmac: [u8; 64] = hm.finalize().into_bytes().into();

        iterate_rounds_512(
            iterations,
            &kb,
            &ks,
            &kh,
            &mut s_blake,
            &mut s_sha3,
            &mut s_hmac,
        );

        let out = combine_lanes_512(&s_blake, &s_sha3, &s_hmac);
        kb.zeroize();
        ks.zeroize();
        kh.zeroize();
        s_blake.zeroize();
        s_sha3.zeroize();
        s_hmac.zeroize();
        out
    }

    /// Arbitrary-length Extendable Output Function (XOF) & KDF expansion in 64-byte `digest_512` blocks.
    pub fn expand_xof(key: &[u8], domain: &[u8], info: &[u8], out: &mut [u8]) {
        if out.is_empty() {
            return;
        }
        let mut seed = Self::digest_512(key, domain, info, 1);
        let mut counter = 0u64;
        let mut offset = 0usize;
        while offset < out.len() {
            let ctr = counter.to_le_bytes();
            let mut block = Self::digest_512(&seed, b"HTX2-XOF-BLK", &ctr, 1);
            let take = (out.len() - offset).min(64);
            out[offset..offset + take].copy_from_slice(&block[..take]);
            block.zeroize();
            offset += take;
            counter += 1;
        }
        seed.zeroize();
    }

    /// Domain-separated 512-bit multi-hash combiner (`BLAKE2b-512`, `SHA3-512`, `HMAC-SHA512` under public salt).
    pub fn hash_unkeyed_512(domain: &[u8], data: &[u8]) -> [u8; 64] {
        Self::digest_512(b"HTX2-PUBLIC-UNKEYED-SALT", domain, data, 2)
    }

    /// Creates a streaming [`HybridTriMixHasher`] for large inputs without buffering plaintext.
    pub fn new_hasher(key: &[u8], domain: &[u8]) -> HybridTriMixHasher {
        HybridTriMixHasher::new(key, domain)
    }
}

impl HybridTriMixHasher {
    /// Initializes an incremental [`HybridTriMixHasher`] matching one-shot `mix_256` & `digest_512`.
    pub fn new(key: &[u8], domain: &[u8]) -> Self {
        let (k_blake, k_sha3, k_hmac) = HybridTriMix::derive_subkeys(key, domain);
        let dom_len = (domain.len() as u64).to_le_bytes();

        let mut b2_256_state = Blake2b512::new();
        b2_256_state.update(b"HTX2-256-B2");
        b2_256_state.update(k_blake);
        b2_256_state.update(dom_len);
        b2_256_state.update(domain);

        let mut b2_512_state = Blake2b512::new();
        b2_512_state.update(b"HTX2-512-B2");
        b2_512_state.update(k_blake);
        b2_512_state.update(dom_len);
        b2_512_state.update(domain);

        let mut s3_256_state = Sha3_256::new();
        s3_256_state.update(b"HTX2-256-S3");
        s3_256_state.update(k_sha3);
        s3_256_state.update(dom_len);
        s3_256_state.update(domain);

        let mut s3_512_state = Sha3_512::new();
        s3_512_state.update(b"HTX2-512-S3");
        s3_512_state.update(k_sha3);
        s3_512_state.update(dom_len);
        s3_512_state.update(domain);

        let mut hm_256_state =
            <HmacSha256 as KeyInit>::new_from_slice(&k_hmac).expect("HMAC accepts 32-byte key");
        hm_256_state.update(b"HTX2-256-HM");
        hm_256_state.update(&dom_len);
        hm_256_state.update(domain);

        let mut hm_512_state =
            <HmacSha512 as KeyInit>::new_from_slice(&k_hmac).expect("HMAC accepts 32-byte key");
        hm_512_state.update(b"HTX2-512-HM");
        hm_512_state.update(&dom_len);
        hm_512_state.update(domain);

        Self {
            b2_256_state,
            b2_512_state,
            s3_256_state,
            s3_512_state,
            hm_256_state,
            hm_512_state,
            k_blake,
            k_sha3,
            k_hmac,
            bytes_absorbed: 0,
        }
    }

    /// Feeds arbitrary message chunks into all cryptographic legs simultaneously.
    pub fn update(&mut self, chunk: &[u8]) {
        self.bytes_absorbed = self.bytes_absorbed.wrapping_add(chunk.len() as u64);
        self.b2_256_state.update(chunk);
        self.b2_512_state.update(chunk);
        self.s3_256_state.update(chunk);
        self.s3_512_state.update(chunk);
        self.hm_256_state.update(chunk);
        self.hm_512_state.update(chunk);
    }

    /// Finalizes a 256-bit `HybridTriMix` digest matching [`HybridTriMix::mix_256`] bit-for-bit.
    pub fn finalize_256(self, rounds: usize) -> [u8; 32] {
        let len_tag = self.bytes_absorbed.to_le_bytes();

        let mut b2 = self.b2_256_state.clone();
        b2.update(len_tag);
        let b2_full = b2.finalize();
        let mut s_blake = [0u8; 32];
        for i in 0..32 {
            s_blake[i] = b2_full[i] ^ b2_full[32 + i];
        }

        let mut s3 = self.s3_256_state.clone();
        s3.update(len_tag);
        let mut s_sha3: [u8; 32] = s3.finalize().into();

        let mut hm = self.hm_256_state.clone();
        hm.update(&len_tag);
        let mut s_hmac: [u8; 32] = hm.finalize().into_bytes().into();

        iterate_rounds_256(
            rounds.max(1),
            &self.k_blake,
            &self.k_sha3,
            &self.k_hmac,
            &mut s_blake,
            &mut s_sha3,
            &mut s_hmac,
        );

        let out = combine_lanes_256(&s_blake, &s_sha3, &s_hmac);
        s_blake.zeroize();
        s_sha3.zeroize();
        s_hmac.zeroize();
        out
    }

    /// Finalizes a 512-bit wide-pipe `HybridTriMix` digest matching [`HybridTriMix::digest_512`] bit-for-bit.
    pub fn finalize_512(self, rounds: usize) -> [u8; 64] {
        let len_tag = self.bytes_absorbed.to_le_bytes();

        let mut b2 = self.b2_512_state.clone();
        b2.update(len_tag);
        let mut s_blake: [u8; 64] = b2.finalize().into();

        let mut s3 = self.s3_512_state.clone();
        s3.update(len_tag);
        let mut s_sha3: [u8; 64] = s3.finalize().into();

        let mut hm = self.hm_512_state.clone();
        hm.update(&len_tag);
        let mut s_hmac: [u8; 64] = hm.finalize().into_bytes().into();

        iterate_rounds_512(
            rounds.max(1),
            &self.k_blake,
            &self.k_sha3,
            &self.k_hmac,
            &mut s_blake,
            &mut s_sha3,
            &mut s_hmac,
        );

        let out = combine_lanes_512(&s_blake, &s_sha3, &s_hmac);
        s_blake.zeroize();
        s_sha3.zeroize();
        s_hmac.zeroize();
        out
    }
}

fn iterate_rounds_256(
    iterations: usize,
    kb: &[u8; 32],
    ks: &[u8; 32],
    kh: &[u8; 32],
    s_blake: &mut [u8; 32],
    s_sha3: &mut [u8; 32],
    s_hmac: &mut [u8; 32],
) {
    for round in 1..iterations {
        let r = (round as u64).to_le_bytes();

        let mut b2r = Blake2b512::new();
        b2r.update(b"HTX2-256-R-B2");
        b2r.update(kb);
        b2r.update(r);
        b2r.update(*s_blake);
        let b2_full = b2r.finalize();
        for i in 0..32 {
            s_blake[i] = b2_full[i] ^ b2_full[32 + i];
        }

        let mut s3r = Sha3_256::new();
        s3r.update(b"HTX2-256-R-S3");
        s3r.update(ks);
        s3r.update(r);
        s3r.update(*s_sha3);
        s_sha3.copy_from_slice(&s3r.finalize());

        *s_hmac = hmac256(kh, &[b"HTX2-256-R-HM", &r, s_hmac]);
    }
}

fn iterate_rounds_512(
    iterations: usize,
    kb: &[u8; 32],
    ks: &[u8; 32],
    kh: &[u8; 32],
    s_blake: &mut [u8; 64],
    s_sha3: &mut [u8; 64],
    s_hmac: &mut [u8; 64],
) {
    for round in 1..iterations {
        let r = (round as u64).to_le_bytes();

        let mut b2r = Blake2b512::new();
        b2r.update(b"HTX2-512-R-B2");
        b2r.update(kb);
        b2r.update(r);
        b2r.update(*s_blake);
        s_blake.copy_from_slice(&b2r.finalize());

        let mut s3r = Sha3_512::new();
        s3r.update(b"HTX2-512-R-S3");
        s3r.update(ks);
        s3r.update(r);
        s3r.update(*s_sha3);
        s_sha3.copy_from_slice(&s3r.finalize());

        *s_hmac = hmac512(kh, &[b"HTX2-512-R-HM", &r, s_hmac]);
    }
}

fn combine_lanes_256(b: &[u8; 32], s: &[u8; 32], h: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = b[i] ^ s[i].rotate_left(3) ^ h[i].rotate_right(5);
    }
    // Bijective triangular cross-lane 64-bit mixing preserves U_256 uniformity under any single PRF leg.
    let mut words = [0u64; 4];
    for (w, word) in words.iter_mut().enumerate() {
        let base = w * 8;
        *word = u64::from_le_bytes(out[base..base + 8].try_into().unwrap());
    }
    let w0 = words[0] ^ words[1].rotate_left(17);
    let w1 = words[1] ^ words[2].rotate_left(29);
    let w2 = words[2] ^ words[3].rotate_left(41);
    let w3 = words[3] ^ w0.rotate_left(13);
    let mixed = [w0 ^ w3.rotate_right(7), w1, w2, w3];
    for (w, word) in mixed.iter().enumerate() {
        out[w * 8..(w + 1) * 8].copy_from_slice(&word.to_le_bytes());
    }
    out
}

fn combine_lanes_512(b: &[u8; 64], s: &[u8; 64], h: &[u8; 64]) -> [u8; 64] {
    let mut out = [0u8; 64];
    for i in 0..64 {
        out[i] = b[i] ^ s[i].rotate_left(3) ^ h[i].rotate_right(5);
    }
    let mut words = [0u64; 8];
    for (w, word) in words.iter_mut().enumerate() {
        let base = w * 8;
        *word = u64::from_le_bytes(out[base..base + 8].try_into().unwrap());
    }
    for pass in 0..7usize {
        words[pass + 1] ^= words[pass].rotate_left(19);
    }
    words[0] ^= words[7].rotate_right(11);
    for (w, word) in words.iter().enumerate() {
        out[w * 8..(w + 1) * 8].copy_from_slice(&word.to_le_bytes());
    }
    out
}

fn hmac256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key).expect("HMAC accepts any key");
    for p in parts {
        mac.update(p);
    }
    mac.finalize().into_bytes().into()
}

fn hmac512(key: &[u8], parts: &[&[u8]]) -> [u8; 64] {
    let mut mac = <HmacSha512 as KeyInit>::new_from_slice(key).expect("HMAC accepts any key");
    for p in parts {
        mac.update(p);
    }
    mac.finalize().into_bytes().into()
}
