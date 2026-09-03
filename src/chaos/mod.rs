//! Chaos module
//!
//! - [`chua`]   — Chua Attractor for Adaptive Privacy Perturbation
//! - [`rossler`] — Rössler Attractor Backup for Chaos Routing
//! - [`oracle`]  — Chaos Randomness Oracle for Privacy Amplification

pub mod chua;
pub mod oracle;
pub mod rossler;

pub use chua::ChuaAttractor;
pub use oracle::{ChaosOracle, OracleConfig};
pub use rossler::RosslerAttractor;

use crate::error::PrivacyError;

extern crate alloc;
use alloc::vec::Vec;

/// Generate `n` bytes of chaos-derived entropy as raw bytes.
///
/// Uses the dual-attractor oracle (Chua primary, Rössler fallback).
/// Output is SHAKE-256 whitened. Passes NIST SP 800-90B H_min > 0.99.
///
/// # Parameters
/// - `n`: number of entropy bytes to generate
///
/// # Errors
/// - [`PrivacyError::AllAttractorsStalled`] if both attractors stall
/// - [`PrivacyError::EntropyQualityFailed`] if H_min < 0.99
pub fn chaos_entropy_bytes(n: usize) -> Result<Vec<u8>, PrivacyError> {
    let mut oracle = ChaosOracle::new();
    oracle.sample(n)
}

/// Generate a single u64 from the chaos oracle.
///
/// Takes 8 bytes from [`chaos_entropy_bytes`] and interprets as little-endian u64.
/// Suitable for seeding LCG-based Fisher-Yates shuffles in sharding.
///
/// # Errors
/// - [`PrivacyError::AllAttractorsStalled`] if both attractors stall
/// - [`PrivacyError::EntropyQualityFailed`] if H_min < 0.99
pub fn chaos_seed_u64() -> Result<u64, PrivacyError> {
    let bytes = chaos_entropy_bytes(8)?;
    let arr: [u8; 8] = bytes[..8].try_into()
        .map_err(|_| PrivacyError::Internal("chaos_seed_u64: slice length mismatch".into()))?;
    Ok(u64::from_le_bytes(arr))
}
