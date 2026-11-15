use std::fs;
use std::path::{Path, PathBuf};

use eazyconnect_hw::{seal_local_secret, unseal_local_secret};
use serde::{Deserialize, Serialize};

/// Bilingual (`en` / `fa`) user profile metadata compatible with EazyConnect client settings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UserProfile {
    pub name: String,
    pub photo: String,
    pub language: String,
}

/// Client persistent configuration stored safely outside git in `%APPDATA%\eazyconnect\config.json`.
///
/// Bearer tokens are encrypted at rest via host DPAPI (`sealed_token_hex`) instead of plaintext.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientConfig {
    pub master: Option<String>,
    pub client_id: Option<String>,
    pub username: Option<String>,
    pub role: Option<String>,
    #[serde(default = "default_verify")]
    pub verify: bool,
    pub tls_pin_hex: Option<String>,
    pub tls_ca_pem_path: Option<String>,
    pub sealed_token_hex: Option<String>,
    #[serde(default)]
    pub profile: UserProfile,
}

fn default_verify() -> bool {
    true
}

impl ClientConfig {
    pub fn set_token(&mut self, client_id: &str, token: &str) -> Result<(), String> {
        self.sealed_token_hex = Some(seal_local_secret(client_id, token.as_bytes())?);
        Ok(())
    }

    pub fn load_token(&self, client_id: &str) -> Result<Option<String>, String> {
        let Some(hex_blob) = &self.sealed_token_hex else {
            return Ok(None);
        };
        let bytes = unseal_local_secret(client_id, hex_blob)?;
        String::from_utf8(bytes)
            .map(Some)
            .map_err(|_| "unsealed session token is not valid UTF-8".to_string())
    }
}

pub fn default_config_path() -> Result<PathBuf, String> {
    #[cfg(windows)]
    {
        if let Ok(appdata) = std::env::var("APPDATA") {
            return Ok(PathBuf::from(appdata)
                .join("eazyconnect")
                .join("config.json"));
        }
    }
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(xdg).join("eazyconnect").join("config.json"));
    }
    if let Ok(home) = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")) {
        return Ok(PathBuf::from(home).join(".eazyconnect").join("config.json"));
    }
    Err("unable to locate OS user config directory".to_string())
}

pub fn load_client_config(path: Option<&Path>) -> Result<ClientConfig, String> {
    let target = match path {
        Some(p) => p.to_path_buf(),
        None => default_config_path()?,
    };
    if !target.exists() {
        return Ok(ClientConfig {
            verify: true,
            profile: UserProfile {
                name: String::new(),
                photo: String::new(),
                language: "en".to_string(),
            },
            ..Default::default()
        });
    }
    let text = fs::read_to_string(&target)
        .map_err(|e| format!("failed to read config {}: {e}", target.display()))?;
    serde_json::from_str(&text)
        .map_err(|e| format!("invalid config JSON {}: {e}", target.display()))
}

pub fn save_client_config(cfg: &ClientConfig, path: Option<&Path>) -> Result<PathBuf, String> {
    let target = match path {
        Some(p) => p.to_path_buf(),
        None => default_config_path()?,
    };
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create config dir {}: {e}", parent.display()))?;
    }
    let json = serde_json::to_string_pretty(cfg).map_err(|e| e.to_string())?;
    fs::write(&target, json)
        .map_err(|e| format!("failed to save config {}: {e}", target.display()))?;
    Ok(target)
}

pub fn profile_heading(lang: &str) -> &'static str {
    if lang.eq_ignore_ascii_case("fa") {
        "پروفایل کاربری EazyConnect"
    } else {
        "EazyConnect User Profile"
    }
}
