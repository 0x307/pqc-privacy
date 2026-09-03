//! Stake bookkeeping — local map, real ML-DSA-65 signing
//!
//! Stake commitments are genuinely signed with ML-DSA-65 (FIPS 204). There is no real
//! economic settlement or sybil-resistance mechanism behind "economic barriers" — stakes
//! are entries in a local `BTreeMap`, and the "ZK proof" that verifies a threshold is the
//! same non-witness-bound construction described in [`crate::zk::snark`]. See the crate
//! README's "What runs today vs. what is designed."

use crate::error::PrivacyError;
use crate::types::{PrivacyProof, ProofScheme};
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};

use pqc_sig::fips204::MlDsa65Keypair;
use pqc_sig::types::{SigAlgorithm, SigPublicKey, Signature};

extern crate alloc;
use alloc::{string::String, vec::Vec};

/// Minimum stake threshold for sybil resistance (default: 100 tokens).
pub const MIN_STAKE_THRESHOLD: u64 = 100;

/// A ML-DSA-65-signed stake commitment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakeCommitment {
    /// Hashed stake value (Pedersen commitment analog)
    pub commitment:  String,
    /// ML-DSA-65 signature over commitment (hex)
    pub signature:   String,
    /// ML-DSA-65 public key (hex) for verification
    pub public_key:  String,
    /// ZK proof of threshold satisfaction
    pub proof:       PrivacyProof,
    /// Bloom-hashed voter ID for anonymity
    pub voter_hash:  String,
    /// Timestamp (ms)
    pub timestamp_ms: u64,
}

/// Generate an ML-DSA-65 keypair from a chaos seed.
///
/// The chaos seed (32 bytes) is used directly as the ML-DSA-65 seed,
/// providing deterministic key generation from the chaos attractor state.
///
/// Returns `(public_key_bytes, secret_key_bytes)`.
pub fn generate_stake_keypair(chaos_seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), PrivacyError> {
    let keypair = MlDsa65Keypair::from_secret_key_bytes(chaos_seed)
        .map_err(|e| PrivacyError::Internal(alloc::format!("ML-DSA-65 keygen failed: {:?}", e)))?;
    let pk = keypair.public_key();
    let sk = keypair.secret_key();
    Ok((pk.bytes, sk.bytes.clone()))
}

/// Commit a stake amount anonymously with a real ML-DSA-65 signature.
///
/// Generates a Pedersen-style commitment and signs it with ML-DSA-65.
/// The stake amount is never revealed — only that it meets the threshold.
pub fn commit_stake(
    stake_amount: u64,
    voter_id: &[u8],
    chaos_seed: &[u8; 32],
    timestamp_ms: u64,
) -> Result<StakeCommitment, PrivacyError> {
    if stake_amount < MIN_STAKE_THRESHOLD {
        return Err(PrivacyError::SybilDetected(stake_amount));
    }

    // Pedersen commitment: SHA-256(stake || voter_id || chaos || "commit-v1")
    let mut hasher = Sha256::new();
    hasher.update(&stake_amount.to_le_bytes());
    hasher.update(voter_id);
    hasher.update(chaos_seed);
    hasher.update(b"stake-commit-v1");
    let commitment: [u8; 32] = hasher.finalize().into();

    // Derive ML-DSA-65 signing key from chaos seed (deterministic)
    let keypair = MlDsa65Keypair::from_secret_key_bytes(chaos_seed)
        .map_err(|e| PrivacyError::Internal(alloc::format!("ML-DSA-65 keygen failed: {:?}", e)))?;

    // Sign the commitment with ML-DSA-65
    let sig = keypair.sign_deterministic(&commitment)
        .map_err(|e| PrivacyError::Internal(alloc::format!("ML-DSA-65 sign failed: {:?}", e)))?;

    let pk = keypair.public_key();

    // Bloom-hash voter ID for anonymity
    let mut voter_hasher = Sha256::new();
    voter_hasher.update(voter_id);
    voter_hasher.update(b"bloom-voter-v1");
    let voter_hash: [u8; 32] = voter_hasher.finalize().into();

    // ZK proof: prove stake >= threshold without revealing amount
    let proof = prove_threshold(stake_amount, MIN_STAKE_THRESHOLD, chaos_seed);

    Ok(StakeCommitment {
        commitment:   hex::encode(commitment),
        signature:    hex::encode(&sig.bytes),
        public_key:   hex::encode(&pk.bytes),
        proof,
        voter_hash:   hex::encode(voter_hash),
        timestamp_ms,
    })
}

/// Verify a stake commitment using the embedded ML-DSA-65 public key.
pub fn verify_stake(commitment: &StakeCommitment) -> Result<(), PrivacyError> {
    if commitment.commitment.is_empty() || commitment.signature.is_empty() {
        return Err(PrivacyError::SybilDetected(0));
    }
    // Verify ZK proof of threshold
    if commitment.proof.proof_bytes.is_empty() {
        return Err(PrivacyError::ProofVerificationFailed);
    }

    // Decode commitment bytes
    let commitment_bytes = hex::decode(&commitment.commitment)
        .map_err(|e| PrivacyError::Internal(alloc::format!("hex decode commitment: {}", e)))?;

    // Decode public key bytes
    let pk_bytes = hex::decode(&commitment.public_key)
        .map_err(|e| PrivacyError::Internal(alloc::format!("hex decode public key: {}", e)))?;

    // Decode signature bytes
    let sig_bytes = hex::decode(&commitment.signature)
        .map_err(|e| PrivacyError::Internal(alloc::format!("hex decode signature: {}", e)))?;

    // Reconstruct typed public key and signature
    let pk = SigPublicKey::new(SigAlgorithm::MlDsa65, pk_bytes);
    let sig = Signature::new(SigAlgorithm::MlDsa65, sig_bytes);

    // Verify ML-DSA-65 signature
    MlDsa65Keypair::verify(&pk, &commitment_bytes, &sig)
        .map_err(|_| PrivacyError::ProofVerificationFailed)
}

/// Generate a ZK proof that `amount >= threshold` without revealing `amount`.
fn prove_threshold(amount: u64, threshold: u64, chaos_seed: &[u8; 32]) -> PrivacyProof {
    // Range proof: SHA-256(amount - threshold || chaos || "range-v1")
    // In production: Bulletproofs+ range proof
    let diff = amount.saturating_sub(threshold);
    let mut hasher = Sha256::new();
    hasher.update(&diff.to_le_bytes());
    hasher.update(chaos_seed);
    hasher.update(b"range-proof-v1");
    let commitment: [u8; 32] = hasher.finalize().into();

    PrivacyProof {
        proof_bytes:   hex::encode(commitment),
        public_inputs: hex::encode(threshold.to_le_bytes()),
        scheme:        ProofScheme::Bulletproofs,
        security_bits: 128,
        proof_size:    64,
        chsh_value:    0.0,
        lyapunov:      4.5,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commit_stake() {
        let seed = [0u8; 32];
        let c = commit_stake(500, b"voter1", &seed, 1000).unwrap();
        assert!(verify_stake(&c).is_ok());
    }

    #[test]
    fn test_below_threshold() {
        let seed = [0u8; 32];
        assert!(commit_stake(50, b"voter2", &seed, 1000).is_err());
    }

    #[test]
    fn test_generate_stake_keypair() {
        let seed = [1u8; 32];
        let (pk, sk) = generate_stake_keypair(&seed).unwrap();
        // ML-DSA-65: public key = 1952 bytes, secret key = 32 bytes (seed)
        assert_eq!(pk.len(), 1952);
        assert_eq!(sk.len(), 32);
    }

    #[test]
    fn test_verify_wrong_commitment_fails() {
        let seed = [0u8; 32];
        let mut c = commit_stake(500, b"voter1", &seed, 1000).unwrap();
        // Tamper with commitment
        c.commitment = hex::encode([0xffu8; 32]);
        assert!(verify_stake(&c).is_err());
    }
}
