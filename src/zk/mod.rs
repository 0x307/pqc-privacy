//! ZK module — hash-based proof constructions, **not** soundness-checked SNARK/STARK
//!
//! - [`stark`]        — Merkle tree + Horner-method evaluation, not a real zk-STARK
//! - [`snark`]        — hash commit/challenge/response, not a real zk-SNARK (`verify()`
//!   doesn't check witness binding)
//! - [`hybrid`]       — selects between the two above
//! - [`entanglement`] — hash-chain aggregation with a simulated, self-satisfying "CHSH" score
//!
//! Real ML-DSA-65 (FIPS 204) signing appears inside [`snark::aggregate`] and
//! [`entanglement::aggregate_recursive`] — see each module's doc comment and the crate
//! README's "What runs today vs. what is designed" for the full accounting.

pub mod entanglement;
pub mod hybrid;
pub mod snark;
pub mod stark;

pub use entanglement::EntanglementEngine;
pub use hybrid::{HybridZkLayer, ProofContext};

use crate::error::PrivacyError;
use crate::types::PrivacyProof;

/// Generate a ZK proof that a manifold path is a valid geodesic.
///
/// Used by the obfuscation crate to generate DDOP UVI receipts proving that
/// a routing path through the 5D Riemannian manifold is a valid geodesic.
///
/// # Algorithm
/// 1. Compute `stmt_hash = SHA-256(statement_hash)` (normalise to 32 bytes)
/// 2. Compute `wit_hash  = SHA-256(path_witness)`
/// 3. Mix chaos entropy: `seed = SHA-256(chaos_seed || "manifold-path-v1")`
/// 4. Call [`HybridZkLayer::prove`] with [`ProofContext::Hybrid`]
///
/// # Parameters
/// - `statement_hash`: BLAKE3 hash of the path's start/end coordinates (any length)
/// - `path_witness`:   serialized sequence of 5D coordinates along the path
/// - `chaos_seed`:     entropy from the chaos oracle
///
/// # Errors
/// - [`PrivacyError::ProofGenerationFailed`] on SNARK/STARK failure
pub fn zk_prove_manifold_path(
    statement_hash: &[u8],
    path_witness: &[u8],
    chaos_seed: &[u8],
) -> Result<PrivacyProof, PrivacyError> {
    use sha2::{Digest, Sha256};

    // Normalise all inputs to 32-byte arrays via SHA-256
    let stmt: [u8; 32] = Sha256::digest(statement_hash).into();
    let wit:  [u8; 32] = Sha256::digest(path_witness).into();

    // Mix chaos seed with domain separator for manifold path proofs
    let mut seed_hasher = Sha256::new();
    seed_hasher.update(chaos_seed);
    seed_hasher.update(b"manifold-path-v1");
    let seed: [u8; 32] = seed_hasher.finalize().into();

    let mut layer = HybridZkLayer::new();
    layer.prove(stmt, wit, &seed, ProofContext::Hybrid)
}
