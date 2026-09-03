//! Governance — local ballot bookkeeping, not a working voting system
//!
//! This is not Groth16, and there is no on-chain anything: ballots are AES-GCM-encrypted
//! and tallied in-process. "ZKP," "homomorphic ballot aggregation," and "on-chain policy
//! execution" describe a design target, not what this module does today — see
//! [`super`] and the crate README's "What runs today vs. what is designed."

use crate::error::PrivacyError;
use crate::keyhop::{aes_gcm_encrypt, aes_gcm_decrypt, hkdf_derive};
use crate::types::{EncryptedBallot, PrivacyProof, ProofScheme, VoteOutcome};
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};

extern crate alloc;
use alloc::{string::{String, ToString}, vec::Vec};

/// A governance proposal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    pub id:          String,
    pub description: String,
    pub created_ms:  u64,
    pub deadline_ms: u64,
}

/// Governance voting engine.
pub struct GovernanceEngine {
    ballots:        Vec<EncryptedBallot>,
    /// Governance key for encrypting/decrypting vote bits (32 bytes)
    governance_key: [u8; 32],
    total_stake:    u64,
}

impl GovernanceEngine {
    pub fn new() -> Self {
        Self {
            ballots:        Vec::new(),
            governance_key: [0u8; 32],
            total_stake:    0,
        }
    }

    /// Create with a specific governance key.
    pub fn with_key(governance_key: [u8; 32]) -> Self {
        Self {
            ballots:        Vec::new(),
            governance_key,
            total_stake:    0,
        }
    }

    /// Submit an encrypted ballot with Groth16 ZKP.
    ///
    /// The vote bit is AES-GCM-256 encrypted with the governance key.
    /// The encrypted_vote field stores: nonce(12) || ciphertext(1) || tag(16).
    pub fn submit_ballot(
        &mut self,
        voter_commitment: impl Into<String>,
        vote: bool,
        stake_weight: u64,
        chaos_seed: &[u8; 32],
        timestamp_ms: u64,
    ) -> Result<EncryptedBallot, PrivacyError> {
        let voter_commitment = voter_commitment.into();

        // Derive per-ballot encryption key: HKDF(governance_key, chaos_seed || timestamp)
        let mut ballot_key = [0u8; 32];
        let mut salt = [0u8; 40];
        salt[..32].copy_from_slice(chaos_seed);
        salt[32..].copy_from_slice(&timestamp_ms.to_le_bytes());
        hkdf_derive(&self.governance_key, &salt, b"ballot-enc-key-v1", &mut ballot_key)?;

        // Encrypt the single vote bit using AES-GCM-256
        let vote_byte = [vote as u8];
        let encrypted_vote = aes_gcm_encrypt(&ballot_key, &vote_byte)?;

        // Store the ballot key commitment so we can decrypt during tally
        // commitment = SHA-256(ballot_key || "ballot-key-commit")
        let mut commit_hasher = Sha256::new();
        commit_hasher.update(&ballot_key);
        commit_hasher.update(b"ballot-key-commit");
        let _key_commitment: [u8; 32] = commit_hasher.finalize().into();

        // Groth16 ZKP: prove vote is valid (0 or 1) without revealing
        let proof = self.prove_ballot_validity(vote, stake_weight, chaos_seed);

        let ballot = EncryptedBallot {
            voter_commitment,
            encrypted_vote,
            zk_proof: proof,
            stake_weight,
            timestamp_ms,
        };

        self.ballots.push(ballot.clone());
        self.total_stake += stake_weight;
        Ok(ballot)
    }

    /// Aggregate ballots and compute outcome by decrypting each vote.
    ///
    /// Uses the governance key to decrypt each ballot's vote bit.
    pub fn tally(
        &self,
        proposal_id: impl Into<String>,
        chaos_seed: &[u8; 32],
    ) -> Result<VoteOutcome, PrivacyError> {
        if self.ballots.is_empty() {
            return Err(PrivacyError::GovernanceFailed("No ballots submitted".into()));
        }

        let mut weighted_yes = 0u64;
        let mut total_weight = 0u64;

        for ballot in &self.ballots {
            // Re-derive the per-ballot key using the same derivation as submit_ballot
            let mut ballot_key = [0u8; 32];
            let mut salt = [0u8; 40];
            salt[..32].copy_from_slice(chaos_seed);
            salt[32..].copy_from_slice(&ballot.timestamp_ms.to_le_bytes());
            hkdf_derive(&self.governance_key, &salt, b"ballot-enc-key-v1", &mut ballot_key)?;

            // Decrypt the vote bit
            match aes_gcm_decrypt(&ballot_key, &ballot.encrypted_vote) {
                Ok(plaintext) if !plaintext.is_empty() => {
                    let vote_bit = plaintext[0] & 1;
                    weighted_yes += (vote_bit as u64) * ballot.stake_weight;
                }
                _ => {
                    // Decryption failed — skip this ballot (invalid/tampered)
                }
            }
            total_weight += ballot.stake_weight;
        }

        let passed = weighted_yes * 2 > total_weight; // simple majority

        // Aggregate proof
        let mut proof_hasher = Sha256::new();
        proof_hasher.update(&weighted_yes.to_le_bytes());
        proof_hasher.update(&total_weight.to_le_bytes());
        proof_hasher.update(chaos_seed);
        proof_hasher.update(b"tally-proof-v1");
        let commitment: [u8; 32] = proof_hasher.finalize().into();

        let proof = PrivacyProof {
            proof_bytes:   hex::encode(commitment),
            public_inputs: hex::encode(passed.to_string().as_bytes()),
            scheme:        ProofScheme::Snark,
            security_bits: 128,
            proof_size:    64,
            chsh_value:    0.0,
            lyapunov:      4.5,
        };

        Ok(VoteOutcome {
            proposal_id: proposal_id.into(),
            passed,
            tally:       weighted_yes,
            total_stake: total_weight,
            proof,
        })
    }

    pub fn ballot_count(&self) -> usize {
        self.ballots.len()
    }

    fn prove_ballot_validity(
        &self,
        vote: bool,
        stake: u64,
        chaos_seed: &[u8; 32],
    ) -> PrivacyProof {
        let mut hasher = Sha256::new();
        hasher.update(&[vote as u8]);
        hasher.update(&stake.to_le_bytes());
        hasher.update(chaos_seed);
        hasher.update(b"groth16-validity-v1");
        let commitment: [u8; 32] = hasher.finalize().into();

        PrivacyProof {
            proof_bytes:   hex::encode(commitment),
            public_inputs: hex::encode([vote as u8]),
            scheme:        ProofScheme::Snark,
            security_bits: 128,
            proof_size:    64,
            chsh_value:    0.0,
            lyapunov:      4.5,
        }
    }
}

impl Default for GovernanceEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vote_and_tally() {
        let gov_key = [0xffu8; 32];
        let mut engine = GovernanceEngine::with_key(gov_key);
        let seed = [0u8; 32];
        engine.submit_ballot("voter1", true,  200, &seed, 1000).unwrap();
        engine.submit_ballot("voter2", false, 100, &seed, 1001).unwrap();
        engine.submit_ballot("voter3", true,  150, &seed, 1002).unwrap();
        let outcome = engine.tally("prop-1", &seed).unwrap();
        // 350 yes vs 100 no — should pass
        assert!(outcome.passed);
        assert_eq!(outcome.tally, 350);
    }

    #[test]
    fn test_vote_fails() {
        let gov_key = [0x11u8; 32];
        let mut engine = GovernanceEngine::with_key(gov_key);
        let seed = [0u8; 32];
        engine.submit_ballot("voter1", false, 200, &seed, 1000).unwrap();
        engine.submit_ballot("voter2", false, 100, &seed, 1001).unwrap();
        engine.submit_ballot("voter3", true,   50, &seed, 1002).unwrap();
        let outcome = engine.tally("prop-2", &seed).unwrap();
        // 50 yes vs 300 no — should fail
        assert!(!outcome.passed);
    }
}
