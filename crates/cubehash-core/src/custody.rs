use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{CubeHashError, Result};
use crate::primitives::{
    constant_time_eq, fill_random, fixed_budget_mix, hmac_sha256_parts, CombiningFn, TimeAlgorithm,
};

/// Abstraction over hardware roots of trust (TPM 2.0, Secure Enclave, HSM, or test enclave).
///
/// Copying serialized cube files to another machine fails unless the target hardware produces
/// the matching `device_hw_id` and unsealing key.
pub trait HardwareProvider {
    /// 128-bit hardware identifier bound to the current device/enclave.
    fn device_hw_id(&self) -> [u8; 16];

    /// Seals a 32-byte secret to this hardware device using `label` for domain separation.
    fn seal_secret(&self, label: &[u8], secret: &[u8; 32]) -> Result<[u8; 32]>;

    /// Unseals a previously sealed 32-byte secret on the matching hardware device.
    fn unseal_secret(&self, label: &[u8], sealed: &[u8; 32]) -> Result<[u8; 32]>;
}

/// Deterministic software enclave simulator useful for tests, cloning simulations, and
/// sandboxed execution without physical TPM access.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct VirtualHardwareEnclave {
    hw_id: [u8; 16],
    enclave_root_key: [u8; 32],
}

impl VirtualHardwareEnclave {
    /// Creates a virtual hardware enclave from explicit device identity and root key.
    pub fn new(hw_id: [u8; 16], enclave_root_key: [u8; 32]) -> Self {
        Self {
            hw_id,
            enclave_root_key,
        }
    }

    /// Generates a fresh randomized virtual hardware enclave.
    pub fn random() -> Result<Self> {
        let mut hw_id = [0u8; 16];
        let mut enclave_root_key = [0u8; 32];
        fill_random(&mut hw_id)?;
        fill_random(&mut enclave_root_key)?;
        Ok(Self {
            hw_id,
            enclave_root_key,
        })
    }

    fn sealing_pad(&self, label: &[u8]) -> [u8; 32] {
        hmac_sha256_parts(&self.enclave_root_key, &[b"cubehash-hw-seal", &self.hw_id, label])
    }
}

impl HardwareProvider for VirtualHardwareEnclave {
    fn device_hw_id(&self) -> [u8; 16] {
        self.hw_id
    }

    fn seal_secret(&self, label: &[u8], secret: &[u8; 32]) -> Result<[u8; 32]> {
        let mut pad = self.sealing_pad(label);
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = secret[i] ^ pad[i];
        }
        pad.zeroize();
        Ok(out)
    }

    fn unseal_secret(&self, label: &[u8], sealed: &[u8; 32]) -> Result<[u8; 32]> {
        // Symmetric XOR mask under domain-separated HMAC pad.
        self.seal_secret(label, sealed)
    }
}

/// Host-bound hardware provider combining OS/machine hardware identity traits with an explicit
/// hardware-sealed device key (e.g., from Windows DPAPI/CNG/TPM or Keychain).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct OsBoundHardwareProvider {
    hw_id: [u8; 16],
    sealing_key: [u8; 32],
}

impl OsBoundHardwareProvider {
    /// Constructs a provider directly from pre-derived enclave root material.
    pub fn from_sealed_parts(hw_id: [u8; 16], sealing_key: [u8; 32]) -> Self {
        Self { hw_id, sealing_key }
    }

    /// Derives a host-bound provider from OS traits and a caller-supplied device secret.
    pub fn from_host_and_secret(device_secret: &[u8; 32], app_context: &[u8]) -> Self {
        Self::from_host_and_secret_with_machine_id(device_secret, app_context, None)
    }

    /// Derives a host-bound provider from explicit hardware machine ID (e.g., Registry
    /// `MachineGuid` or `/etc/machine-id`), OS environment traits, and a hardware-sealed secret.
    pub fn from_host_and_secret_with_machine_id(
        device_secret: &[u8; 32],
        app_context: &[u8],
        machine_id: Option<&[u8]>,
    ) -> Self {
        let mut fingerprint = Vec::with_capacity(160);
        if let Some(mid) = machine_id.filter(|m| !m.is_empty()) {
            fingerprint.extend_from_slice(b"MACHINE_ID=");
            fingerprint.extend_from_slice(mid);
            fingerprint.push(0);
        } else if let Ok(etc_mid) = std::fs::read_to_string("/etc/machine-id") {
            let trimmed = etc_mid.trim();
            if !trimmed.is_empty() {
                fingerprint.extend_from_slice(b"MACHINE_ID=");
                fingerprint.extend_from_slice(trimmed.as_bytes());
                fingerprint.push(0);
            }
        }
        for key in [
            "COMPUTERNAME",
            "HOSTNAME",
            "PROCESSOR_IDENTIFIER",
            "PROCESSOR_ARCHITECTURE",
            "USERNAME",
            "USER",
        ] {
            if let Ok(val) = std::env::var(key) {
                fingerprint.extend_from_slice(key.as_bytes());
                fingerprint.push(b'=');
                fingerprint.extend_from_slice(val.as_bytes());
                fingerprint.push(0);
            }
        }
        fingerprint.extend_from_slice(std::env::consts::OS.as_bytes());
        fingerprint.extend_from_slice(std::env::consts::ARCH.as_bytes());

        let digest = hmac_sha256_parts(device_secret, &[b"host-hw-id", app_context, &fingerprint]);
        let mut hw_id = [0u8; 16];
        hw_id.copy_from_slice(&digest[..16]);

        let sealing_key =
            hmac_sha256_parts(device_secret, &[b"host-hw-seal", &hw_id, &fingerprint]);
        fingerprint.zeroize();

        Self { hw_id, sealing_key }
    }
}

impl HardwareProvider for OsBoundHardwareProvider {
    fn device_hw_id(&self) -> [u8; 16] {
        self.hw_id
    }

    fn seal_secret(&self, label: &[u8], secret: &[u8; 32]) -> Result<[u8; 32]> {
        let mut pad = hmac_sha256_parts(&self.sealing_key, &[b"seal", &self.hw_id, label]);
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = secret[i] ^ pad[i];
        }
        pad.zeroize();
        Ok(out)
    }

    fn unseal_secret(&self, label: &[u8], sealed: &[u8; 32]) -> Result<[u8; 32]> {
        self.seal_secret(label, sealed)
    }
}

/// Hardware-bound local monotonic execution guard (`Section 3.2` & `Section 7`).
///
/// Prevents session cloning and offline replay attacks without requiring external NTP servers.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct LocalClientClockGuard {
    pub device_hw_id: [u8; 16],
    pub local_monotonic_tick: u64,
    pub sealed_hw_secret: [u8; 32],
}

impl LocalClientClockGuard {
    pub(crate) const SEAL_LABEL: &'static [u8] = b"cubehash-local-clock-guard-v1";

    /// Seals a fresh `LocalClientClockGuard` to `hw`.
    pub fn seal_new(hw: &dyn HardwareProvider, raw_hw_secret: &[u8; 32]) -> Result<Self> {
        let sealed_hw_secret = hw.seal_secret(Self::SEAL_LABEL, raw_hw_secret)?;
        Ok(Self {
            device_hw_id: hw.device_hw_id(),
            local_monotonic_tick: 0,
            sealed_hw_secret,
        })
    }

    /// Reference Section 7 check matching `expected_hw_id` without external enclave unsealing.
    /// Prefer [`Self::authorize_local_execution`] in production paths so enclave unsealing is enforced.
    pub fn authorize_hw_id_only(&mut self, expected_hw_id: &[u8; 16]) -> Result<[u8; 32]> {
        if !constant_time_eq(&self.device_hw_id, expected_hw_id) {
            return Err(CubeHashError::UnauthorizedHardware);
        }
        self.local_monotonic_tick = self
            .local_monotonic_tick
            .checked_add(1)
            .ok_or(CubeHashError::ClockRollbackDetected)?;
        Ok(hmac_sha256_parts(
            &self.sealed_hw_secret,
            &[&self.device_hw_id, &self.local_monotonic_tick.to_le_bytes()],
        ))
    }

    /// Verifies device identity, unseals hardware secret, increments monotonic tick,
    /// and returns a tick-bound execution capability token.
    pub fn authorize_local_execution(&mut self, hw: &dyn HardwareProvider) -> Result<[u8; 32]> {
        let observed_hw = hw.device_hw_id();
        if !constant_time_eq(&self.device_hw_id, &observed_hw) {
            return Err(CubeHashError::UnauthorizedHardware);
        }
        let mut unsealed = hw.unseal_secret(Self::SEAL_LABEL, &self.sealed_hw_secret)?;
        self.local_monotonic_tick = self
            .local_monotonic_tick
            .checked_add(1)
            .ok_or(CubeHashError::ClockRollbackDetected)?;
        let token = hmac_sha256_parts(
            &unsealed,
            &[&self.device_hw_id, &self.local_monotonic_tick.to_le_bytes()],
        );
        unsealed.zeroize();
        Ok(token)
    }

    /// Enforces strictly monotonic counter progression to block replay/rollback attempts.
    pub fn verify_and_advance_observed_tick(
        &mut self,
        last_seen_tick: &mut u64,
        incoming_tick: u64,
    ) -> Result<()> {
        if incoming_tick <= *last_seen_tick {
            return Err(CubeHashError::ReplayDetected);
        }
        *last_seen_tick = incoming_tick;
        Ok(())
    }
}

/// Root ownership anchor (`Section 3.1`).
///
/// Intentionally does NOT implement `Serialize` for wire transport — it never crosses the network.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MotherCube {
    master_secret: [u8; 32],
    pub owner_salt: [u8; 16],
}

impl MotherCube {
    /// Generates a new randomized `MotherCube`.
    pub fn generate() -> Result<Self> {
        let mut master_secret = [0u8; 32];
        let mut owner_salt = [0u8; 16];
        fill_random(&mut master_secret)?;
        fill_random(&mut owner_salt)?;
        Ok(Self {
            master_secret,
            owner_salt,
        })
    }

    /// Reconstructs a `MotherCube` from explicit offline backup custody material.
    pub fn from_custody_bytes(master_secret: [u8; 32], owner_salt: [u8; 16]) -> Self {
        Self {
            master_secret,
            owner_salt,
        }
    }

    /// Exports raw root custody material strictly for encrypted offline backup / 3-cube recovery.
    pub fn export_offline_custody(&self) -> ([u8; 32], [u8; 16]) {
        (self.master_secret, self.owner_salt)
    }

    /// Derives a domain-separated key without exposing `master_secret`.
    pub(crate) fn derive_domain_key(&self, label: &[u8], context: &[u8]) -> [u8; 32] {
        hmac_sha256_parts(&self.master_secret, &[label, &self.owner_salt, context])
    }
}

/// Chain anchor cube (`Section 3.1`).
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct MainCube {
    pub chain_id: [u8; 16],
    /// Static custody anchor pattern bound into 3-Cube root derivation.
    pub root_pattern: [u8; 32],
    /// Ratcheting chain accumulator advanced on each committed transaction.
    pub active_chain_state: [u8; 32],
    pub generation: u64,
}

impl MainCube {
    /// Creates a fresh `MainCube` anchor.
    pub fn generate() -> Result<Self> {
        let mut chain_id = [0u8; 16];
        let mut root_pattern = [0u8; 32];
        fill_random(&mut chain_id)?;
        fill_random(&mut root_pattern)?;
        Ok(Self {
            chain_id,
            root_pattern,
            active_chain_state: root_pattern,
            generation: 0,
        })
    }

    /// Reconstructs a `MainCube` from explicit values.
    pub fn from_parts(chain_id: [u8; 16], root_pattern: [u8; 32], generation: u64) -> Self {
        Self {
            chain_id,
            root_pattern,
            active_chain_state: root_pattern,
            generation,
        }
    }
}

/// Algorithmic brain cube determining time algorithm, spiral coefficients, quorum sizing,
/// and non-linear combining function (`Section 3.1` & `Section 7`).
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct AuditorCube {
    pub auditor_secret: [u8; 32],
    pub synthesis_salt: [u8; 16],
    #[zeroize(skip)]
    pub time_algorithm: TimeAlgorithm,
    #[zeroize(skip)]
    pub combining_fn: CombiningFn,
    pub spiral_coeffs: [u32; 3],
    pub quorum_select: usize,
    pub consume_for_next: usize,
}

impl AuditorCube {
    /// Generates a randomized `AuditorCube` with custom policy settings.
    pub fn generate(
        time_algorithm: TimeAlgorithm,
        combining_fn: CombiningFn,
        quorum_select: usize,
        consume_for_next: usize,
    ) -> Result<Self> {
        let mut auditor_secret = [0u8; 32];
        let mut synthesis_salt = [0u8; 16];
        let mut coeff_raw = [0u8; 12];
        fill_random(&mut auditor_secret)?;
        fill_random(&mut synthesis_salt)?;
        fill_random(&mut coeff_raw)?;

        let c0 = (u32::from_le_bytes([coeff_raw[0], coeff_raw[1], coeff_raw[2], coeff_raw[3]]) % 97) + 3;
        let c1 = (u32::from_le_bytes([coeff_raw[4], coeff_raw[5], coeff_raw[6], coeff_raw[7]]) % 97) + 5;
        let c2 = (u32::from_le_bytes([coeff_raw[8], coeff_raw[9], coeff_raw[10], coeff_raw[11]]) % 97) + 7;

        Ok(Self {
            auditor_secret,
            synthesis_salt,
            time_algorithm,
            combining_fn,
            spiral_coeffs: [c0, c1, c2],
            quorum_select,
            consume_for_next,
        })
    }

    /// Reconstructs an `AuditorCube` from explicit parameters (matching Section 7 base fields).
    pub fn from_parts(
        auditor_secret: [u8; 32],
        synthesis_salt: [u8; 16],
        time_algorithm: TimeAlgorithm,
        combining_fn: CombiningFn,
        spiral_coeffs: [u32; 3],
        quorum_select: usize,
        consume_for_next: usize,
    ) -> Self {
        Self {
            auditor_secret,
            synthesis_salt,
            time_algorithm,
            combining_fn,
            spiral_coeffs,
            quorum_select,
            consume_for_next,
        }
    }
}

/// Combined 3-Cube Custody bundle (`MotherCube` + `MainCube` + `AuditorCube`).
///
/// Possession of all three cubes enables full identity and session recovery on replacement hardware,
/// while any strict subset cannot synthesize the root session capability.
#[derive(Clone)]
pub struct ThreeCubeCustody {
    pub mother: MotherCube,
    pub main: MainCube,
    pub auditor: AuditorCube,
}

impl ThreeCubeCustody {
    /// Generates a new randomized 3-Cube custody set.
    pub fn generate(
        time_algorithm: TimeAlgorithm,
        combining_fn: CombiningFn,
        quorum_select: usize,
        consume_for_next: usize,
    ) -> Result<Self> {
        Ok(Self {
            mother: MotherCube::generate()?,
            main: MainCube::generate()?,
            auditor: AuditorCube::generate(
                time_algorithm,
                combining_fn,
                quorum_select,
                consume_for_next,
            )?,
        })
    }

    /// Synthesizes the root custody capability using all three cubes under a fixed step budget.
    pub fn derive_root_capability(&self, budget: usize) -> [u8; 32] {
        let mut mother_part = self.mother.derive_domain_key(b"3cube-root", &self.main.chain_id);
        let mut combined_ctx = Vec::with_capacity(64);
        combined_ctx.extend_from_slice(&self.main.root_pattern);
        combined_ctx.extend_from_slice(&self.auditor.synthesis_salt);
        combined_ctx.extend_from_slice(&self.auditor.auditor_secret);

        let result = fixed_budget_mix(
            self.auditor.time_algorithm,
            &mother_part,
            b"three-cube-custody",
            &combined_ctx,
            budget,
        );
        mother_part.zeroize();
        combined_ctx.zeroize();
        result
    }

    /// Recovers and re-seals a `LocalClientClockGuard` onto replacement hardware (`Section 3.1`).
    pub fn recover_on_new_hardware(
        &self,
        new_hw: &dyn HardwareProvider,
        budget: usize,
    ) -> Result<(LocalClientClockGuard, [u8; 32])> {
        let mut root_cap = self.derive_root_capability(budget);
        let hw_secret = hmac_sha256_parts(&root_cap, &[b"recover-hw-secret", &new_hw.device_hw_id()]);
        let guard = LocalClientClockGuard::seal_new(new_hw, &hw_secret)?;
        let recovery_epoch_key =
            hmac_sha256_parts(&root_cap, &[b"recover-epoch", &self.main.chain_id]);
        root_cap.zeroize();
        Ok((guard, recovery_epoch_key))
    }
}
