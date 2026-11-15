use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::MeshConfig;
use crate::primitives::{fixed_budget_mix, hmac_sha256_parts, whitened_stream, TimeAlgorithm};
use crate::voxel::{encode_sub_matrix_with_shadows, generate_variable_weight, VoxelCube};

/// Output profile used by the Distribution-Transforming Encoder (DTE) when producing
/// plausible Honey outputs with zero error oracle (`Section 4.2`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HoneyProfile {
    /// Generates a plausible 12-word BIP-39-like recovery phrase with a valid SHA-256 checksum word.
    Bip39ChecksumPhrase,
    /// Generates plausible everyday conversational chat messages in UTF-8.
    ChatPlaintext,
    /// Generates uniform plausible raw binary output of exact length `len`.
    RawUniform { len: usize },
}

/// Curated 256-word vocabulary for deterministic BIP-39-style Honey recovery phrase synthesis.
const HONEY_WORDS: [&str; 256] = [
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
    "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
    "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual",
    "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance",
    "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent",
    "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album",
    "alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone",
    "alpha", "already", "also", "alter", "always", "amateur", "amazing", "among",
    "amount", "amused", "analyst", "anchor", "ancient", "anger", "angle", "angry",
    "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique",
    "anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april",
    "arch", "arctic", "area", "arena", "argue", "arm", "armed", "armor",
    "army", "around", "arrange", "arrest", "arrive", "arrow", "art", "artefact",
    "artist", "artwork", "ask", "aspect", "assault", "asset", "assist", "assume",
    "asthma", "athlete", "atom", "attack", "attend", "attitude", "attract", "auction",
    "audit", "august", "aunt", "author", "auto", "autumn", "average", "avocado",
    "avoid", "awake", "aware", "away", "awesome", "awful", "awkward", "axis",
    "baby", "bachelor", "bacon", "badge", "bag", "balance", "balcony", "ball",
    "bamboo", "banana", "banner", "bar", "barely", "bargain", "barrel", "base",
    "basic", "basket", "battle", "beach", "bean", "beauty", "because", "become",
    "beef", "before", "begin", "behave", "behind", "believe", "below", "belt",
    "bench", "benefit", "best", "betray", "better", "between", "beyond", "bicycle",
    "bid", "bike", "bind", "biology", "bird", "birth", "bitter", "black",
    "blade", "blame", "blanket", "blast", "bleak", "bless", "blind", "blood",
    "blossom", "blouse", "blue", "blur", "blush", "board", "boat", "body",
    "boil", "bomb", "bone", "bonus", "book", "boost", "border", "boring",
    "borrow", "boss", "bottom", "bounce", "box", "boy", "bracket", "brain",
    "brand", "brass", "brave", "bread", "breeze", "brick", "bridge", "brief",
    "bright", "bring", "brisk", "broccoli", "broken", "bronze", "broom", "brother",
    "brown", "brush", "bubble", "buddy", "budget", "buffalo", "build", "bulb",
    "bulk", "bullet", "bundle", "bunker", "burden", "burger", "burst", "bus",
    "business", "busy", "butter", "buyer", "buzz", "cabbage", "cabin", "cable",
];

const CHAT_OPENERS: [&str; 8] = [
    "Hey, did you get a chance to check",
    "Quick update on",
    "Sounds good, let's meet later about",
    "Just finished reviewing",
    "Can we reschedule",
    "Sending over the notes for",
    "Everything looks fine with",
    "Remind me tomorrow morning regarding",
];

const CHAT_TOPICS: [&str; 8] = [
    "the weekend coffee meetup.",
    "today's grocery list and dinner.",
    "the updated project timeline.",
    "picking up the package after work.",
    "the lecture slides from Thursday.",
    "booking the train tickets for Friday.",
    "the design mockup we discussed.",
    "syncing up at 6 PM.",
];

/// Generates structurally indistinguishable decoy chains (`99%` identical geometry & entropy)
/// from real mesh cubes using divergent key material (`Section 4.2`).
pub fn generate_decoy_cubes(
    config: &MeshConfig,
    decoy_seed: &[u8; 32],
    real_cubes: &[VoxelCube],
) -> Vec<VoxelCube> {
    let count = config.decoy_chain_count.min(real_cubes.len());
    let mut decoys = Vec::with_capacity(count);
    for (idx, real) in real_cubes.iter().take(count).enumerate() {
        let faulty_key = hmac_sha256_parts(
            decoy_seed,
            &[b"decoy-faulty-schedule", &real.cube_uid, &(idx as u64).to_le_bytes()],
        );
        let mut fake_core = vec![0u8; config.core_bytes];
        whitened_stream(&faulty_key, b"decoy-core", &mut fake_core);

        let sub_matrix = encode_sub_matrix_with_shadows(
            config,
            &faulty_key,
            &real.cube_uid,
            real.generation,
            &fake_core,
        );
        let weight_layer = generate_variable_weight(config).unwrap_or_default();

        decoys.push(VoxelCube {
            cube_uid: real.cube_uid,
            generation: real.generation,
            sub_matrix,
            core_pattern: fake_core,
            weight_layer,
        });
    }
    decoys
}

/// Distribution-Transforming Encoder (DTE) that turns failed/unauthorized probes into plausible
/// valid-format decoy outputs with constant step budget and zero error oracle.
pub struct DteEngine;

impl DteEngine {
    /// Runs a fixed-budget traversal over decoy cubes and produces a deterministic Honey output.
    pub fn synthesize_honey_output(
        config: &MeshConfig,
        profile: HoneyProfile,
        probe_material: &[u8],
        decoys: &[VoxelCube],
    ) -> Vec<u8> {
        let mut decoy_acc = [0u8; 32];
        for (idx, d) in decoys.iter().take(config.quorum_select.min(decoys.len())).enumerate() {
            let step = fixed_budget_mix(
                TimeAlgorithm::HybridTriMix,
                &decoy_acc,
                &(idx as u64).to_le_bytes(),
                &d.core_pattern,
                config.fixed_step_budget,
            );
            for i in 0..32 {
                decoy_acc[i] ^= step[i];
            }
        }
        let seed = fixed_budget_mix(
            TimeAlgorithm::HybridTriMix,
            &decoy_acc,
            b"cubehash-dte-seed",
            probe_material,
            config.fixed_step_budget,
        );
        Self::encode_from_seed(profile, &seed)
    }

    /// Deterministically transforms a 32-byte uniform seed into the requested plausible output format.
    pub fn encode_from_seed(profile: HoneyProfile, seed: &[u8; 32]) -> Vec<u8> {
        match profile {
            HoneyProfile::Bip39ChecksumPhrase => {
                // 11 payload words + 1 checksum word derived via SHA-256 over the 11 indices.
                let mut indices = [0u8; 11];
                indices.copy_from_slice(&seed[..11]);
                let checksum_digest = Sha256::digest(indices);
                let checksum_idx = checksum_digest[0];

                let mut words = Vec::with_capacity(12);
                for idx in indices {
                    words.push(HONEY_WORDS[idx as usize]);
                }
                words.push(HONEY_WORDS[checksum_idx as usize]);
                words.join(" ").into_bytes()
            }
            HoneyProfile::ChatPlaintext => {
                let opener = CHAT_OPENERS[(seed[0] as usize) % CHAT_OPENERS.len()];
                let topic = CHAT_TOPICS[(seed[1] as usize) % CHAT_TOPICS.len()];
                let tag = u16::from_le_bytes([seed[2], seed[3]]) % 90 + 10;
                format!("{opener} {topic} (#{tag})").into_bytes()
            }
            HoneyProfile::RawUniform { len } => {
                let mut out = vec![0u8; len];
                whitened_stream(seed, b"dte-raw-uniform", &mut out);
                out
            }
        }
    }

    /// Validates that a synthesized 12-word phrase satisfies the SHA-256 checksum word property.
    pub fn verify_bip39_like_checksum(phrase: &str) -> bool {
        let parts: Vec<&str> = phrase.split_whitespace().collect();
        if parts.len() != 12 {
            return false;
        }
        let mut indices = [0u8; 11];
        for (i, w) in parts[..11].iter().enumerate() {
            match HONEY_WORDS.iter().position(|entry| entry == w) {
                Some(idx) => indices[i] = idx as u8,
                None => return false,
            }
        }
        let expected_idx = Sha256::digest(indices)[0];
        HONEY_WORDS[expected_idx as usize] == parts[11]
    }
}
