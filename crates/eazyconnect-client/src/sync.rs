use std::fs;
use std::path::{Path, PathBuf};

use cubehash_core::HardwareProvider;
use eazyconnect_core::{
    encrypt_file_for_vault, scan_folder_delta, SyncManifest, SyncedFileEntry,
};
use serde::{Deserialize, Serialize};

use crate::http::MasterHttpClient;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncRunSummary {
    pub scanned_folder: String,
    pub uploaded_count: usize,
    pub uploaded_files: Vec<String>,
    pub total_manifest_entries: usize,
    pub e2e_encrypted: bool,
}

pub fn load_sync_manifest(path: &Path) -> Result<SyncManifest, String> {
    if !path.exists() {
        return Ok(SyncManifest::default());
    }
    let raw = fs::read_to_string(path)
        .map_err(|e| format!("failed to read sync manifest {}: {e}", path.display()))?;
    serde_json::from_str(&raw)
        .map_err(|e| format!("invalid sync manifest {}: {e}", path.display()))
}

pub fn save_sync_manifest(path: &Path, manifest: &SyncManifest) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create manifest dir {}: {e}", parent.display()))?;
    }
    let json = serde_json::to_string_pretty(manifest).map_err(|e| e.to_string())?;
    fs::write(path, json)
        .map_err(|e| format!("failed to save sync manifest {}: {e}", path.display()))
}

pub fn default_sync_manifest_path(config_path: Option<&Path>) -> PathBuf {
    if let Some(cfg) = config_path {
        if let Some(parent) = cfg.parent() {
            return parent.join("sync-manifest.json");
        }
    }
    if let Ok(appdata) = std::env::var("APPDATA") {
        return PathBuf::from(appdata)
            .join("eazyconnect")
            .join("sync-manifest.json");
    }
    PathBuf::from("sync-manifest.json")
}

/// Runs incremental BLAKE3 folder sync against Master Server, optionally encrypting every file
/// client-side via [`encrypt_file_for_vault`] before upload.
pub async fn sync_folder_to_master(
    client: &MasterHttpClient,
    token: &str,
    folder: &Path,
    manifest_path: &Path,
    e2e_vault: Option<(&dyn HardwareProvider, &[u8; 32])>,
) -> Result<SyncRunSummary, String> {
    let mut manifest = load_sync_manifest(manifest_path)?;
    let pending = scan_folder_delta(folder, &manifest)?;
    let mut uploaded_files = Vec::new();

    for item in pending {
        let plain = fs::read(&item.full_path)
            .map_err(|e| format!("failed to read {}: {e}", item.full_path.display()))?;

        let (payload, is_e2e) = match e2e_vault {
            Some((hw, vault_key)) => {
                let sealed = encrypt_file_for_vault(hw, vault_key, &item.rel_key, &plain)?;
                (sealed, true)
            }
            None => (plain, false),
        };

        client
            .upload_bytes(token, &item.rel_key, &payload, is_e2e)
            .await?;

        manifest.files.insert(
            item.rel_key.clone(),
            SyncedFileEntry {
                blake3_hex: item.blake3_hex.clone(),
                size_bytes: item.size_bytes,
            },
        );
        uploaded_files.push(item.rel_key);
    }

    save_sync_manifest(manifest_path, &manifest)?;

    Ok(SyncRunSummary {
        scanned_folder: folder.display().to_string(),
        uploaded_count: uploaded_files.len(),
        uploaded_files,
        total_manifest_entries: manifest.files.len(),
        e2e_encrypted: e2e_vault.is_some(),
    })
}
