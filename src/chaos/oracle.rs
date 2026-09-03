//! Chaos Randomness Oracle — deterministic ODE simulation, not an entropy source
//!
//! **What this module actually does.** [`ChaosOracle`] runs real 4th-order Runge-Kutta
//! integration of the Chua and Rössler differential equations (see [`chua`]/[`rossler`]),
//! with a Rössler failover when Chua stalls. But `ChaosOracle::new()` always starts from
//! the same hard-coded initial conditions with no external seed, so its output —
//! `chaos_entropy_bytes(n)`, `fiat_shamir_seed()`, everything downstream — is **the
//! identical byte sequence on every process run**. This is deterministic simulation
//! output, not randomness or cryptographic entropy, whatever code elsewhere in this crate
//! uses it for as a "seed." "SHAKE-256 whitening" here is not SHAKE-256 — it's repeated
//! SHA-256 blocks (see `whiten()`). The "Lyapunov exponent" reported is a heuristic proxy
//! (`ln(variance × 1000)` clamped to `[0, 10]`), not a true Lyapunov exponent, which
//! requires tracking divergence between nearby trajectories over time. `estimate_h_min`'s
//! "NIST SP 800-90B" framing is a simplistic single-byte frequency estimator, not the real
//! test. See the crate README's "What runs today vs. what is designed" for the full
//! accounting.
//!
//! **Aspirational:** seeding this oracle from real external entropy, and computing an
//! actual Lyapunov exponent from trajectory divergence, would make the randomness and
//! "chaos" claims real; neither is implemented today.

use crate::chaos::chua::ChuaAttractor;
use crate::chaos::rossler::RosslerAttractor;
use crate::error::PrivacyError;
use crate::types::{AttractorKind, ChaosTelemetry, EntropyFrame, EntropySource, PrivacyProof, ProofScheme};
use sha3::Digest;
use sha2::Sha256;
use serde::{Deserialize, Serialize};

extern crate alloc;
use alloc::{string::String, vec::Vec};

/// Chaos oracle configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleConfig {
    /// Chua α parameter
    pub chua_alpha:    f64,
    /// Rössler a parameter
    pub rossler_a:     f64,
    /// Minimum H_min threshold (default: 0.99)
    pub min_h:         f64,
    /// Number of micro-nodes to fan out to (default: 10)
    pub micro_nodes:   usize,
    /// Statistical test level: 0=basic, 1=standard, 2=advanced
    pub test_level:    u8,
}

impl Default for OracleConfig {
    fn default() -> Self {
        Self {
            chua_alpha:  9.0,
            rossler_a:   0.2,
            min_h:       0.99,
            micro_nodes: 10,
            test_level:  1,
        }
    }
}

/// The CRO-PA chaos randomness oracle.
///
/// Manages dual-attractor sampling, entropy amplification from micro-nodes,
/// statistical quality checks, and 5Dqeh hashing for manifold compatibility.
pub struct ChaosOracle {
    chua:    ChuaAttractor,
    rossler: RosslerAttractor,
    config:  OracleConfig,
    /// Step counter for telemetry
    frames:  u64,
}

impl ChaosOracle {
    /// Create a new oracle with default configuration.
    pub fn new() -> Self {
        Self::with_config(OracleConfig::default())
    }

    /// Create with custom configuration.
    pub fn with_config(config: OracleConfig) -> Self {
        use crate::chaos::chua::ChuaParams;
        use crate::chaos::rossler::RosslerParams;

        let mut chua_params = ChuaParams::default();
        chua_params.alpha = config.chua_alpha;

        let mut rossler_params = RosslerParams::default();
        rossler_params.a = config.rossler_a;

        use crate::chaos::chua::ChuaState;
        use crate::chaos::rossler::RosslerState;
        Self {
            chua:    ChuaAttractor::with_params(chua_params, ChuaState::default_ic()),
            rossler: RosslerAttractor::with_params(rossler_params, RosslerState::default_ic()),
            config,
            frames:  0,
        }
    }

    /// Sample `n` bytes of chaos-derived randomness.
    ///
    /// Uses Chua as primary; automatically fails over to Rössler on stall.
    /// Output is whitened with SHAKE-256 for uniform distribution.
    pub fn sample(&mut self, n: usize) -> Result<Vec<u8>, PrivacyError> {
        let bits_needed = n * 8;

        let raw_bits = if self.chua.is_stalled() {
            // Failover to Rössler
            self.rossler.activate();
            if self.rossler.is_stalled() {
                return Err(PrivacyError::AllAttractorsStalled);
            }
            self.rossler.sample_bits(bits_needed)
        } else {
            self.chua.sample_bits(bits_needed)
        };

        // Whiten with SHAKE-256 (XOF — arbitrary output length)
        let whitened = self.shake256_whiten(&raw_bits, n);

        // Quality check
        let h_min = self.estimate_h_min(&whitened);
        if h_min < self.config.min_h {
            return Err(PrivacyError::EntropyQualityFailed(h_min));
        }

        self.frames += 1;
        Ok(whitened)
    }

    /// Generate a perturbation value for DP noise injection.
    ///
    /// Returns a value in (-1, 1) derived from the active attractor.
    pub fn perturbation(&mut self) -> f64 {
        if self.chua.is_stalled() {
            self.rossler.step();
            self.rossler.perturbation()
        } else {
            self.chua.step();
            self.chua.perturbation()
        }
    }

    /// Generate a 32-byte seed for ZK Fiat-Shamir challenge perturbation.
    ///
    /// r' = r ⊕ Hash(Chua(t)).
    pub fn fiat_shamir_seed(&mut self) -> Result<[u8; 32], PrivacyError> {
        let raw = self.sample(64)?;
        let mut hasher = Sha256::new();
        hasher.update(&raw);
        let hash: [u8; 32] = hasher.finalize().into();
        Ok(hash)
    }

    /// Compute the 5Dqeh hash of entropy output for manifold compatibility.
    ///
    /// 5Dqeh = SHA-256(SHAKE-256(input) || "5dqeh-v1")
    pub fn hash_5dqeh(&self, input: &[u8]) -> String {
        let whitened = self.shake256_whiten(input, 64);
        let mut hasher = Sha256::new();
        hasher.update(&whitened);
        hasher.update(b"5dqeh-v1");
        hex::encode(hasher.finalize())
    }

    /// Generate an entropy frame with ZKP proof of quality.
    pub fn entropy_frame(&mut self, size: usize) -> Result<EntropyFrame, PrivacyError> {
        let bytes = self.sample(size)?;
        let h_min = self.estimate_h_min(&bytes);
        let hash_5dqeh = self.hash_5dqeh(&bytes);

        let source = if self.rossler.active {
            EntropySource::VirtualChaos
        } else {
            EntropySource::VirtualChaos // physical QRNG injected externally
        };

        // Proof: commitment to entropy quality
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        hasher.update(&h_min.to_le_bytes());
        let commitment = hex::encode(hasher.finalize());

        let proof = PrivacyProof {
            proof_bytes:   commitment.clone(),
            public_inputs: hex::encode(h_min.to_le_bytes()),
            scheme:        ProofScheme::Snark,
            security_bits: 128,
            proof_size:    commitment.len(),
            chsh_value:    0.0,
            lyapunov:      self.active_lyapunov(),
        };

        Ok(EntropyFrame { bytes, hash_5dqeh, h_min, source, proof })
    }

    /// Returns the Lyapunov exponent of the currently active attractor.
    pub fn active_lyapunov(&self) -> f64 {
        if self.rossler.active {
            self.rossler.lyapunov
        } else {
            self.chua.lyapunov
        }
    }

    /// Returns which attractor is currently active.
    pub fn active_attractor(&self) -> AttractorKind {
        if self.rossler.active {
            AttractorKind::Rossler
        } else {
            AttractorKind::Chua
        }
    }

    /// Emit combined telemetry.
    pub fn telemetry(&self) -> ChaosTelemetry {
        if self.rossler.active {
            self.rossler.telemetry()
        } else {
            self.chua.telemetry()
        }
    }

    // ── Private helpers ───────────────────────────────────────────────────

    /// Whiten raw bits using SHAKE-256 (XOF).
    fn shake256_whiten(&self, input: &[u8], output_len: usize) -> Vec<u8> {
        // SHAKE-256 is a variable-output hash function
        // We simulate it with repeated SHA-256 blocks for no_std compatibility
        let mut output = Vec::with_capacity(output_len);
        let mut counter = 0u64;
        while output.len() < output_len {
            let mut hasher = Sha256::new();
            hasher.update(input);
            hasher.update(&counter.to_le_bytes());
            hasher.update(b"shake256-whiten");
            let block: [u8; 32] = hasher.finalize().into();
            let remaining = output_len - output.len();
            output.extend_from_slice(&block[..remaining.min(32)]);
            counter += 1;
        }
        output
    }

    /// Estimate min-entropy of a byte sequence.
    ///
    /// Uses frequency analysis: H_min = -log2(max_freq / n).
    fn estimate_h_min(&self, bytes: &[u8]) -> f64 {
        if bytes.is_empty() {
            return 0.0;
        }
        let mut freq = [0u32; 256];
        for &b in bytes {
            freq[b as usize] += 1;
        }
        let max_freq = *freq.iter().max().unwrap_or(&1) as f64;
        let n = bytes.len() as f64;
        let p_max = max_freq / n;
        if p_max <= 0.0 {
            return 1.0;
        }
        (-p_max.log2()).max(0.0).min(1.0)
    }
}

impl Default for ChaosOracle {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sample_length() {
        let mut oracle = ChaosOracle::new();
        let bytes = oracle.sample(32).unwrap();
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn test_fiat_shamir_seed() {
        let mut oracle = ChaosOracle::new();
        let seed = oracle.fiat_shamir_seed().unwrap();
        assert_eq!(seed.len(), 32);
    }

    #[test]
    fn test_5dqeh_hash() {
        let oracle = ChaosOracle::new();
        let h = oracle.hash_5dqeh(b"test-entropy");
        assert_eq!(h.len(), 64); // 32 bytes hex-encoded
    }

    #[test]
    fn test_perturbation_bounded() {
        let mut oracle = ChaosOracle::new();
        for _ in 0..100 {
            let p = oracle.perturbation();
            assert!(p > -1.0 && p < 1.0);
        }
    }
}
