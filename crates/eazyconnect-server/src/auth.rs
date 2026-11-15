use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use eazyconnect_core::{
    http_auth_sign_bytes, AuthChallengeResponse, AuthTokenResponse, DeviceAuthRequest,
    DeviceRecordView,
};
use eazyconnect_hw::{validate_id, DeviceIdentity};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

const TOKEN_TTL_SECS: u64 = 24 * 3600;
const CHALLENGE_TTL_SECS: u64 = 60;

#[derive(Debug, Clone)]
pub enum EnrollmentPolicy {
    OpenLan,
    InviteCode(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredUser {
    pub password_hash: String,
    pub is_admin: bool,
    pub created_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinnedDeviceRecord {
    pub client_id: String,
    pub ed25519_pub: [u8; 32],
    pub enrolled_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredToken {
    pub token_sha256_hex: String,
    pub subject: String,
    pub role: String,
    pub is_admin: bool,
    pub expires_unix: u64,
}

#[derive(Debug, Clone)]
pub struct AuthenticatedPrincipal {
    pub subject: String,
    pub role: String,
    pub is_admin: bool,
}

#[derive(Debug, Clone)]
struct PendingChallenge {
    nonce: [u8; 32],
    expires_unix: u64,
}

pub struct AuthStore {
    data_dir: PathBuf,
    policy: EnrollmentPolicy,
    users: HashMap<String, StoredUser>,
    devices: HashMap<String, PinnedDeviceRecord>,
    tokens: HashMap<String, StoredToken>,
    challenges: HashMap<String, PendingChallenge>,
}

impl AuthStore {
    pub fn load_or_init(
        data_dir: &Path,
        policy: EnrollmentPolicy,
        bootstrap_admin_pass: Option<&str>,
    ) -> Result<Self, String> {
        fs::create_dir_all(data_dir)
            .map_err(|e| format!("failed to create server data dir {}: {e}", data_dir.display()))?;

        let users_path = data_dir.join("users.json");
        let devices_path = data_dir.join("devices.json");
        let tokens_path = data_dir.join("tokens.json");

        let mut users: HashMap<String, StoredUser> = if users_path.exists() {
            let txt = fs::read_to_string(&users_path).map_err(|e| e.to_string())?;
            serde_json::from_str(&txt).map_err(|e| format!("corrupt users.json: {e}"))?
        } else {
            HashMap::new()
        };

        if users.is_empty() {
            let pass_owned;
            let plain_pass = match bootstrap_admin_pass.filter(|s| !s.is_empty()) {
                Some(p) => p,
                None => {
                    let mut rnd = [0u8; 16];
                    getrandom::getrandom(&mut rnd).map_err(|e| e.to_string())?;
                    pass_owned = hex::encode(rnd);
                    let notice_path = data_dir.join("bootstrap-admin.txt");
                    let content = format!(
                        "Initial EazyConnect Master Admin Password (change or create personal admin account):\nusername: admin\npassword: {pass_owned}\n"
                    );
                    fs::write(&notice_path, content)
                        .map_err(|e| format!("failed to write bootstrap-admin.txt: {e}"))?;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ = fs::set_permissions(&notice_path, fs::Permissions::from_mode(0o600));
                    }
                    &pass_owned
                }
            };

            let hash = hash_password(plain_pass)?;
            users.insert(
                "admin".to_string(),
                StoredUser {
                    password_hash: hash,
                    is_admin: true,
                    created_unix: now_unix(),
                },
            );
            write_json_atomic(&users_path, &users)?;
        }

        let devices: HashMap<String, PinnedDeviceRecord> = if devices_path.exists() {
            let txt = fs::read_to_string(&devices_path).map_err(|e| e.to_string())?;
            serde_json::from_str(&txt).map_err(|e| format!("corrupt devices.json: {e}"))?
        } else {
            HashMap::new()
        };

        let mut tokens: HashMap<String, StoredToken> = if tokens_path.exists() {
            let txt = fs::read_to_string(&tokens_path).map_err(|e| e.to_string())?;
            serde_json::from_str(&txt).map_err(|e| format!("corrupt tokens.json: {e}"))?
        } else {
            HashMap::new()
        };
        let now = now_unix();
        tokens.retain(|_, t| t.expires_unix > now);

        Ok(Self {
            data_dir: data_dir.to_path_buf(),
            policy,
            users,
            devices,
            tokens,
            challenges: HashMap::new(),
        })
    }

    pub fn device_count(&self) -> usize {
        self.devices.len()
    }

    pub fn list_devices(&self) -> Vec<DeviceRecordView> {
        let mut out: Vec<DeviceRecordView> = self
            .devices
            .values()
            .map(|d| DeviceRecordView {
                client_id: d.client_id.clone(),
                ed25519_pub_hex: hex::encode(d.ed25519_pub),
                enrolled_unix: d.enrolled_unix,
            })
            .collect();
        out.sort_by(|a, b| a.client_id.cmp(&b.client_id));
        out
    }

    pub fn issue_challenge(&mut self) -> Result<AuthChallengeResponse, String> {
        let now = now_unix();
        self.challenges.retain(|_, c| c.expires_unix > now);

        let mut id_bytes = [0u8; 16];
        let mut nonce = [0u8; 32];
        getrandom::getrandom(&mut id_bytes).map_err(|e| e.to_string())?;
        getrandom::getrandom(&mut nonce).map_err(|e| e.to_string())?;
        let challenge_id = hex::encode(id_bytes);

        self.challenges.insert(
            challenge_id.clone(),
            PendingChallenge {
                nonce,
                expires_unix: now + CHALLENGE_TTL_SECS,
            },
        );
        Ok(AuthChallengeResponse {
            challenge_id,
            nonce_hex: hex::encode(nonce),
        })
    }

    /// Verifies an Ed25519 challenge signature, enforces TOFU identity pinning & enrollment
    /// policy, and issues an opaque CSPRNG session token (stored as SHA-256 hash only).
    pub fn verify_device_challenge(
        &mut self,
        req: &DeviceAuthRequest,
    ) -> Result<AuthTokenResponse, (u16, String)> {
        let client_id = validate_id(&req.client_id).map_err(|e| (400, e))?;
        let pending = self
            .challenges
            .remove(&req.challenge_id)
            .ok_or((401, "unknown or expired auth challenge".to_string()))?;
        if pending.expires_unix < now_unix() {
            return Err((401, "auth challenge expired".to_string()));
        }

        let pub_raw = hex::decode(&req.ed25519_pub_hex)
            .map_err(|_| (400, "invalid ed25519_pub_hex".to_string()))?;
        let pub_arr: [u8; 32] = pub_raw
            .as_slice()
            .try_into()
            .map_err(|_| (400, "ed25519 public key must be 32 bytes".to_string()))?;

        let sig_raw = hex::decode(&req.signature_hex)
            .map_err(|_| (400, "invalid signature_hex".to_string()))?;
        let sig_arr: [u8; 64] = sig_raw
            .as_slice()
            .try_into()
            .map_err(|_| (400, "ed25519 signature must be 64 bytes".to_string()))?;

        let msg = http_auth_sign_bytes(&pending.nonce, &client_id, &req.challenge_id);
        if !DeviceIdentity::verify_signature(&pub_arr, &msg, &sig_arr) {
            return Err((401, "invalid Ed25519 signature".to_string()));
        }

        self.check_or_pin_device_key(&client_id, pub_arr, req.invite_code.as_deref())?;
        self.mint_token(&client_id, "device", false)
            .map_err(|e| (500, e))
    }

    /// Shared identity pinning gate used by both HTTPS enrollment and WSS relay registration.
    pub fn check_or_pin_device_key(
        &mut self,
        client_id: &str,
        ed25519_pub: [u8; 32],
        invite_code: Option<&str>,
    ) -> Result<(), (u16, String)> {
        if let Some(existing) = self.devices.get(client_id) {
            if existing.ed25519_pub != ed25519_pub {
                return Err((
                    403,
                    "identity_mismatch: client_id is pinned to a different Ed25519 key".to_string(),
                ));
            }
            return Ok(());
        }

        if let EnrollmentPolicy::InviteCode(expected) = &self.policy {
            let supplied = invite_code.unwrap_or("");
            let matches: bool = if supplied.len() == expected.len() {
                supplied.as_bytes().ct_eq(expected.as_bytes()).into()
            } else {
                false
            };
            if !matches {
                return Err((
                    403,
                    "enrollment_denied: valid invite code required for new devices".to_string(),
                ));
            }
        }

        self.devices.insert(
            client_id.to_string(),
            PinnedDeviceRecord {
                client_id: client_id.to_string(),
                ed25519_pub,
                enrolled_unix: now_unix(),
            },
        );
        let devices_path = self.data_dir.join("devices.json");
        write_json_atomic(&devices_path, &self.devices).map_err(|e| (500, e))?;
        Ok(())
    }

    pub fn login_password(
        &mut self,
        username: &str,
        password: &str,
    ) -> Result<AuthTokenResponse, (u16, String)> {
        let user_id = validate_id(username).map_err(|e| (400, e))?;
        let user = self
            .users
            .get(&user_id)
            .ok_or((401, "invalid credentials".to_string()))?;

        let parsed = PasswordHash::new(&user.password_hash)
            .map_err(|_| (500, "corrupted stored password hash".to_string()))?;
        if Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_err()
        {
            return Err((401, "invalid credentials".to_string()));
        }

        let role = if user.is_admin { "admin" } else { "user" };
        let is_admin = user.is_admin;
        self.mint_token(&user_id, role, is_admin)
            .map_err(|e| (500, e))
    }

    pub fn create_user(
        &mut self,
        principal: &AuthenticatedPrincipal,
        new_username: &str,
        new_password: &str,
        is_admin: bool,
    ) -> Result<(), (u16, String)> {
        if !principal.is_admin {
            return Err((403, "admin privileges required".to_string()));
        }
        let clean = validate_id(new_username).map_err(|e| (400, e))?;
        if self.users.contains_key(&clean) {
            return Err((400, "user already exists".to_string()));
        }
        if new_password.len() < 8 {
            return Err((400, "password must be at least 8 characters".to_string()));
        }
        let hash = hash_password(new_password).map_err(|e| (500, e))?;
        self.users.insert(
            clean,
            StoredUser {
                password_hash: hash,
                is_admin,
                created_unix: now_unix(),
            },
        );
        write_json_atomic(&self.data_dir.join("users.json"), &self.users).map_err(|e| (500, e))
    }

    pub fn authenticate_bearer(&mut self, token: &str) -> Option<AuthenticatedPrincipal> {
        let clean = token.trim();
        if clean.is_empty() {
            return None;
        }
        let hash_hex = sha256_hex(clean.as_bytes());
        let now = now_unix();
        if let Some(entry) = self.tokens.get(&hash_hex) {
            if entry.expires_unix > now {
                return Some(AuthenticatedPrincipal {
                    subject: entry.subject.clone(),
                    role: entry.role.clone(),
                    is_admin: entry.is_admin,
                });
            }
            self.tokens.remove(&hash_hex);
            let _ = write_json_atomic(&self.data_dir.join("tokens.json"), &self.tokens);
        }
        None
    }

    fn mint_token(
        &mut self,
        subject: &str,
        role: &str,
        is_admin: bool,
    ) -> Result<AuthTokenResponse, String> {
        let mut raw = [0u8; 32];
        getrandom::getrandom(&mut raw).map_err(|e| e.to_string())?;
        let token = format!("ezc_{}", hex::encode(raw));
        let token_sha256_hex = sha256_hex(token.as_bytes());
        let expires_unix = now_unix() + TOKEN_TTL_SECS;

        let now = now_unix();
        self.tokens.retain(|_, v| v.expires_unix > now);
        self.tokens.insert(
            token_sha256_hex.clone(),
            StoredToken {
                token_sha256_hex,
                subject: subject.to_string(),
                role: role.to_string(),
                is_admin,
                expires_unix,
            },
        );
        write_json_atomic(&self.data_dir.join("tokens.json"), &self.tokens)?;

        Ok(AuthTokenResponse {
            token,
            expires_unix,
            role: role.to_string(),
            client_id: subject.to_string(),
        })
    }
}

fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| format!("Argon2id hash failed: {e}"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn write_json_atomic<T: Serialize>(path: &Path, val: &T) -> Result<(), String> {
    let tmp = path.with_extension("json.tmp");
    let json = serde_json::to_string_pretty(val).map_err(|e| e.to_string())?;
    fs::write(&tmp, json).map_err(|e| e.to_string())?;
    fs::rename(&tmp, path).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}
