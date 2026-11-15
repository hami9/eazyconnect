use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use cubehash_core::primitives::{aead_open, aead_seal, hkdf_expand_label};
use cubehash_core::HardwareProvider;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

const VAULT_MAGIC: &[u8; 4] = b"EZV1";

/// Encrypts a file payload end-to-end using hardware-bound key derivation + XChaCha20-Poly1305.
///
/// The master file server stores only opaque ciphertext bytes and never receives `vault_key`
/// or the local device's `HardwareProvider` secret.
pub fn encrypt_file_for_vault(
    hw: &dyn HardwareProvider,
    vault_key: &[u8; 32],
    filename: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 24];
    getrandom::getrandom(&mut salt).map_err(|e| e.to_string())?;
    getrandom::getrandom(&mut nonce).map_err(|e| e.to_string())?;

    let mut file_key = derive_vault_file_key(hw, vault_key, &salt, filename)?;
    let aad = vault_aad(filename, &salt);
    let ct = aead_seal(&file_key, &nonce, &aad, plaintext).map_err(|e| e.to_string())?;
    file_key.zeroize();

    let mut out = Vec::with_capacity(4 + 16 + 24 + ct.len());
    out.extend_from_slice(VAULT_MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypts an E2E vault file envelope produced by [`encrypt_file_for_vault`].
pub fn decrypt_file_from_vault(
    hw: &dyn HardwareProvider,
    vault_key: &[u8; 32],
    filename: &str,
    envelope: &[u8],
) -> Result<Vec<u8>, String> {
    if envelope.len() < 4 + 16 + 24 + 16 {
        return Err("encrypted vault envelope truncated".to_string());
    }
    if &envelope[..4] != VAULT_MAGIC {
        return Err("invalid E2E file vault header".to_string());
    }
    let salt: [u8; 16] = envelope[4..20].try_into().unwrap();
    let nonce: [u8; 24] = envelope[20..44].try_into().unwrap();
    let ct = &envelope[44..];

    let mut file_key = derive_vault_file_key(hw, vault_key, &salt, filename)?;
    let aad = vault_aad(filename, &salt);
    let pt = aead_open(&file_key, &nonce, &aad, ct)
        .map_err(|_| "vault file decryption failed (wrong vault key, hardware lock, or tampered file)".to_string());
    file_key.zeroize();
    pt
}

fn derive_vault_file_key(
    hw: &dyn HardwareProvider,
    vault_key: &[u8; 32],
    salt: &[u8; 16],
    filename: &str,
) -> Result<[u8; 32], String> {
    let mut bound_root = hw
        .seal_secret(b"eazyconnect-file-vault-v1", vault_key)
        .map_err(|e| e.to_string())?;
    let mut derived = [0u8; 32];
    let mut info = Vec::with_capacity(16 + filename.len());
    info.extend_from_slice(salt);
    info.extend_from_slice(filename.as_bytes());
    let res = hkdf_expand_label(&bound_root, &info, b"eazyconnect-file-key-v1", &mut derived);
    bound_root.zeroize();
    res.map_err(|e| e.to_string())?;
    Ok(derived)
}

fn vault_aad(filename: &str, salt: &[u8; 16]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(24 + filename.len());
    aad.extend_from_slice(b"eazyconnect-vault-aad-v1");
    aad.extend_from_slice(salt);
    aad.extend_from_slice(filename.as_bytes());
    aad
}

/// Persisted BLAKE3 file fingerprint entry for incremental folder synchronization.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncedFileEntry {
    pub blake3_hex: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyncManifest {
    pub files: HashMap<String, SyncedFileEntry>,
}

/// Candidate file identified by delta scanning as new or modified relative to `manifest`.
#[derive(Debug, Clone)]
pub struct PendingSyncFile {
    pub rel_key: String,
    pub full_path: PathBuf,
    pub blake3_hex: String,
    pub size_bytes: u64,
}

/// Walks `folder` recursively and computes fast BLAKE3 hashes, returning only new/changed files.
pub fn scan_folder_delta(
    folder: &Path,
    manifest: &SyncManifest,
) -> Result<Vec<PendingSyncFile>, String> {
    if !folder.exists() || !folder.is_dir() {
        return Err(format!("sync folder '{}' is not a valid directory", folder.display()));
    }
    let mut files = Vec::new();
    collect_files_recursive(folder, folder, &mut files)?;
    files.sort();

    let mut pending = Vec::new();
    for full_path in files {
        let rel = full_path
            .strip_prefix(folder)
            .map_err(|e| e.to_string())?
            .to_string_lossy()
            .replace('\\', "/");
        let meta = fs::metadata(&full_path).map_err(|e| e.to_string())?;
        let data = fs::read(&full_path)
            .map_err(|e| format!("failed to read {}: {e}", full_path.display()))?;
        let digest_hex = blake3::hash(&data).to_hex().to_string();

        let unchanged = manifest
            .files
            .get(&rel)
            .is_some_and(|prev| prev.blake3_hex == digest_hex && prev.size_bytes == meta.len());
        if !unchanged {
            pending.push(PendingSyncFile {
                rel_key: rel,
                full_path,
                blake3_hex: digest_hex,
                size_bytes: meta.len(),
            });
        }
    }
    Ok(pending)
}

fn collect_files_recursive(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = fs::read_dir(dir)
        .map_err(|e| format!("failed to read directory {}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        if path.is_dir() {
            collect_files_recursive(root, &path, out)?;
        } else if path.is_file() {
            out.push(path);
        }
    }
    let _ = root;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cubehash_core::OsBoundHardwareProvider;

    #[test]
    fn test_vault_encryption_and_hardware_lock() {
        let hw1 = OsBoundHardwareProvider::from_host_and_secret(&[0x11u8; 32], b"node-1");
        let hw2 = OsBoundHardwareProvider::from_host_and_secret(&[0x22u8; 32], b"node-2");
        let vault_key = [0x42u8; 32];
        let pt = b"Confidential telemetry & firmware backup";

        let ct = encrypt_file_for_vault(&hw1, &vault_key, "firmware.bin", pt).unwrap();
        assert!(!ct.windows(pt.len()).any(|w| w == pt));

        let dec = decrypt_file_from_vault(&hw1, &vault_key, "firmware.bin", &ct).unwrap();
        assert_eq!(dec, pt);

        // Wrong filename AAD or different device hardware lock must fail cleanly.
        assert!(decrypt_file_from_vault(&hw1, &vault_key, "other.bin", &ct).is_err());
        assert!(decrypt_file_from_vault(&hw2, &vault_key, "firmware.bin", &ct).is_err());
    }

    #[test]
    fn test_incremental_blake3_sync_delta() {
        let unique = format!(
            "eazy_sync_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let dir = std::env::temp_dir().join(unique);
        fs::create_dir_all(dir.join("sub")).unwrap();
        fs::write(dir.join("a.txt"), b"hello").unwrap();
        fs::write(dir.join("sub").join("b.bin"), b"12345").unwrap();

        let mut manifest = SyncManifest::default();
        let batch1 = scan_folder_delta(&dir, &manifest).unwrap();
        assert_eq!(batch1.len(), 2);
        for item in &batch1 {
            manifest.files.insert(
                item.rel_key.clone(),
                SyncedFileEntry {
                    blake3_hex: item.blake3_hex.clone(),
                    size_bytes: item.size_bytes,
                },
            );
        }

        // Unchanged folder yields zero uploads.
        assert!(scan_folder_delta(&dir, &manifest).unwrap().is_empty());

        // Modifying only b.bin queues only sub/b.bin.
        fs::write(dir.join("sub").join("b.bin"), b"12345-updated").unwrap();
        let batch2 = scan_folder_delta(&dir, &manifest).unwrap();
        assert_eq!(batch2.len(), 1);
        assert_eq!(batch2[0].rel_key, "sub/b.bin");

        let _ = fs::remove_dir_all(&dir);
    }
}
