use std::fs;
use std::path::{Path, PathBuf};

use eazyconnect_core::{
    default_config_path, parse_sha256_pin_hex, ClientConfig, ClientTlsConfig,
};
use eazyconnect_hw::{hostname, seal_local_secret, unseal_local_secret};

use crate::http::MasterHttpClient;

/// Resolves the effective device `client_id` (CLI/UI override -> persisted config -> OS hostname).
pub fn resolve_client_id(client_id_override: Option<&str>, cfg: &ClientConfig) -> String {
    client_id_override
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .or_else(|| cfg.client_id.clone().filter(|s| !s.trim().is_empty()))
        .unwrap_or_else(hostname)
}

/// Resolves Master URL and client TLS verification policy from explicit overrides or saved config.
pub fn resolve_url_and_tls(
    master_override: Option<&str>,
    tls_pin_override: Option<&str>,
    tls_ca_override: Option<&Path>,
    cfg: &ClientConfig,
) -> Result<(String, ClientTlsConfig), String> {
    let url = master_override
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .or_else(|| cfg.master.clone().filter(|s| !s.trim().is_empty()))
        .ok_or_else(|| {
            "no master URL configured (specify Master URL or run UDP discover / enroll first)"
                .to_string()
        })?;

    let effective_pin = tls_pin_override
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            cfg.tls_pin_hex
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
        });

    let tls = if let Some(pin_hex) = effective_pin {
        ClientTlsConfig::PinnedCertSha256(parse_sha256_pin_hex(pin_hex)?)
    } else if let Some(ca_path) = tls_ca_override
        .map(Path::to_path_buf)
        .or_else(|| {
            cfg.tls_ca_pem_path
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(PathBuf::from)
        })
    {
        let pem = fs::read(&ca_path)
            .map_err(|e| format!("failed to read TLS CA {}: {e}", ca_path.display()))?;
        ClientTlsConfig::CaPem(pem)
    } else {
        ClientTlsConfig::WebPkiRoots
    };

    Ok((url, tls))
}

/// Constructs a verified [`MasterHttpClient`] alongside the resolved URL and TLS config.
pub fn build_http_client_from_cfg(
    master_override: Option<&str>,
    tls_pin_override: Option<&str>,
    tls_ca_override: Option<&Path>,
    insecure_http: bool,
    cfg: &ClientConfig,
) -> Result<(MasterHttpClient, String, ClientTlsConfig), String> {
    let (url, tls) = resolve_url_and_tls(
        master_override,
        tls_pin_override,
        tls_ca_override,
        cfg,
    )?;
    let client = MasterHttpClient::new(&url, tls.clone(), insecure_http)?;
    Ok((client, url, tls))
}

/// Unseals the stored DPAPI bearer token for `client_id`.
pub fn load_bearer_token(client_id: &str, cfg: &ClientConfig) -> Result<String, String> {
    cfg.load_token(client_id)?
        .ok_or_else(|| "no sealed session token stored; run enroll or login first".to_string())
}

/// Returns the sealed E2E file vault key path colocated next to `config.json`.
pub fn vault_key_path(config_path: Option<&Path>) -> Result<PathBuf, String> {
    Ok(match config_path {
        Some(p) => p.with_file_name("vault.key.sealed"),
        None => default_config_path()?.with_file_name("vault.key.sealed"),
    })
}

/// Loads or initializes the 32-byte OS-sealed `--e2e` file vault key.
pub fn load_or_create_vault_key(
    config_path: Option<&Path>,
    client_id: &str,
    override_hex: Option<&str>,
) -> Result<[u8; 32], String> {
    if let Some(hex_str) = override_hex.map(str::trim).filter(|s| !s.is_empty()) {
        return parse_sha256_pin_hex(hex_str);
    }
    let path = vault_key_path(config_path)?;
    if path.exists() {
        let hex_blob = fs::read_to_string(&path).map_err(|e| e.to_string())?;
        let raw = unseal_local_secret(&format!("{client_id}-vault"), hex_blob.trim())?;
        return <[u8; 32]>::try_from(raw.as_slice())
            .map_err(|_| "corrupted sealed vault key length".to_string());
    }
    let mut key = [0u8; 32];
    getrandom::getrandom(&mut key).map_err(|e| e.to_string())?;
    let sealed = seal_local_secret(&format!("{client_id}-vault"), &key)?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
    }
    fs::write(&path, sealed).map_err(|e| e.to_string())?;
    Ok(key)
}
