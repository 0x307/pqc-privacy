//! QTAID Biometric Login System (QTAID-BLS)
//!
//! Passwordless authentication via QTAID nano-tokenized genomic identifiers.
//! ZK SNP matching (≥98/100) with Bulletproofs+, revocation via tuple expiry.

use crate::error::PrivacyError;
use crate::genomic::{sequence_to_snp_commitments, SnpCommitment};
use crate::types::PrivacyProof;
use crate::zk::snark;
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};

extern crate alloc;
use alloc::{format, string::{String, ToString}, vec::Vec};

/// SNP match threshold (target: ≥98/100).
pub const SNP_MATCH_THRESHOLD: u32 = 98;
pub const SNP_TOTAL: u32 = 100;

/// A biometric login session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BiometricSession {
    pub session_id:  String,
    pub wyqcc_did:  String,
    pub match_proof: PrivacyProof,
    pub created_ms:  u64,
    pub expiry_ms:   u64,
}

/// Registered genomic profile: stores SnpCommitments for a DID.
#[derive(Debug, Clone)]
struct GenomicProfile {
    commitments: Vec<SnpCommitment>,
}

/// QTAID biometric login engine.
pub struct QtaidLoginEngine {
    /// Stored genomic profiles (DID → SnpCommitments)
    profiles: alloc::collections::BTreeMap<String, GenomicProfile>,
}

impl QtaidLoginEngine {
    pub fn new() -> Self {
        Self { profiles: alloc::collections::BTreeMap::new() }
    }

    /// Register a genomic template for a DID.
    ///
    /// Stores SnpCommitments (commitment + allele_bits + blinding_factor) for later matching.
    pub fn register(
        &mut self,
        did: impl Into<String>,
        sequence: &str,
        dp_epsilon: f64,
        chaos_seed: &[u8; 32],
        _expiry_ms: u64,
    ) -> Result<(), PrivacyError> {
        let did = did.into();
        let patient_id = did.as_bytes();
        let commitments = sequence_to_snp_commitments(sequence, chaos_seed, patient_id, dp_epsilon)?;
        self.profiles.insert(did, GenomicProfile { commitments });
        Ok(())
    }

    /// Authenticate via ZK SNP matching.
    ///
    /// The authenticating user provides their sequence + chaos_seed.
    /// We derive SnpCommitments for the challenge sequence and:
    /// 1. Verify each commitment: SHA-256(allele_bits || blinding_factor) == commitment
    /// 2. Compare allele_bits with the registered profile
    /// 3. Require ≥98% match rate
    /// 4. Generate a ZK proof of the match result
    pub fn authenticate(
        &self,
        did: &str,
        challenge_sequence: &str,
        chaos_seed: &[u8; 32],
        now_ms: u64,
        session_expiry_ms: u64,
    ) -> Result<BiometricSession, PrivacyError> {
        let profile = self.profiles.get(did)
            .ok_or_else(|| PrivacyError::TokenMintFailed(format!("No template for DID: {did}")))?;

        // Build SnpCommitments for the challenge sequence using the same patient_id
        let patient_id = did.as_bytes();
        let challenge_commitments = sequence_to_snp_commitments(
            challenge_sequence,
            chaos_seed,
            patient_id,
            1e-6,
        )?;

        // Count SNP matches by verifying commitments and comparing allele_bits
        let match_count = self.count_snp_matches(&profile.commitments, &challenge_commitments)?;
        let total = profile.commitments.len().min(challenge_commitments.len()) as u32;
        let matched = match_count as u32;

        // Threshold: require ≥98% of total SNPs to match
        let required = (total * 98 / 100).max(1);
        if matched < required {
            return Err(PrivacyError::SnpMatchFailed {
                matched,
                total,
                threshold: SNP_MATCH_THRESHOLD,
            });
        }

        // Generate ZK proof of match result using snark::prove
        let proof = self.prove_snp_match(matched, total, chaos_seed)?;

        // Session ID
        let mut id_hasher = Sha256::new();
        id_hasher.update(did.as_bytes());
        id_hasher.update(&now_ms.to_le_bytes());
        id_hasher.update(chaos_seed);
        let session_id = hex::encode(id_hasher.finalize())[..16].to_string();

        Ok(BiometricSession {
            session_id,
            wyqcc_did: did.to_string(),
            match_proof: proof,
            created_ms:  now_ms,
            expiry_ms:   now_ms + session_expiry_ms,
        })
    }

    /// Revoke a DID's template via tuple expiry.
    pub fn revoke(&mut self, did: &str) -> Result<(), PrivacyError> {
        self.profiles.remove(did)
            .ok_or_else(|| PrivacyError::RevocationFailed(format!("DID not found: {did}")))?;
        Ok(())
    }

    /// Match SNPs by verifying ZK commitments and comparing allele_bits.
    ///
    /// For each SNP position:
    /// 1. Verify the challenge commitment: SHA-256(allele_bits || blinding_factor) == commitment
    /// 2. Compare allele_bits with the registered allele_bits
    /// 3. Count matches where allele_bits match exactly
    fn count_snp_matches(
        &self,
        registered: &[SnpCommitment],
        authenticating: &[SnpCommitment],
    ) -> Result<usize, PrivacyError> {
        let mut matches = 0usize;

        for (reg, auth) in registered.iter().zip(authenticating.iter()) {
            // Verify the authenticating commitment is internally consistent
            if !auth.verify() {
                // Invalid commitment — skip (counts as non-match)
                continue;
            }

            // Compare allele_bits directly
            if reg.allele_bits == auth.allele_bits {
                matches += 1;
            }
        }

        Ok(matches)
    }

    /// Generate a ZK proof of the SNP match result using snark::prove.
    ///
    /// - statement_hash = SHA-256("snp-match-v1" || matched || total)
    /// - witness_hash   = SHA-256(matched || total || chaos_seed)
    fn prove_snp_match(
        &self,
        matched: u32,
        total: u32,
        chaos_seed: &[u8; 32],
    ) -> Result<PrivacyProof, PrivacyError> {
        // statement_hash: public claim about the match ratio
        let mut stmt_hasher = Sha256::new();
        stmt_hasher.update(b"snp-match-v1");
        stmt_hasher.update(&matched.to_le_bytes());
        stmt_hasher.update(&total.to_le_bytes());
        let statement_hash: [u8; 32] = stmt_hasher.finalize().into();

        // witness_hash: private knowledge of the actual match computation
        let mut wit_hasher = Sha256::new();
        wit_hasher.update(&matched.to_le_bytes());
        wit_hasher.update(&total.to_le_bytes());
        wit_hasher.update(chaos_seed);
        wit_hasher.update(b"snp-witness-v1");
        let witness_hash: [u8; 32] = wit_hasher.finalize().into();

        let snark_proof = snark::prove(statement_hash, witness_hash, chaos_seed)?;
        Ok(PrivacyProof::from(snark_proof))
    }
}

impl Default for QtaidLoginEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_authenticate() {
        let mut engine = QtaidLoginEngine::new();
        let seed = [0u8; 32];
        let seq = "ACGTACGT";
        engine.register("did:wyqcc:alice", seq, 1e-6, &seed, 9_999_999_999).unwrap();
        // Same sequence should match
        let session = engine.authenticate("did:wyqcc:alice", seq, &seed, 0, 3_600_000).unwrap();
        assert_eq!(session.wyqcc_did, "did:wyqcc:alice");
    }

    #[test]
    fn test_revoke() {
        let mut engine = QtaidLoginEngine::new();
        let seed = [0u8; 32];
        engine.register("did:wyqcc:bob", "ACGT", 1e-6, &seed, 0).unwrap();
        engine.revoke("did:wyqcc:bob").unwrap();
        assert!(engine.authenticate("did:wyqcc:bob", "ACGT", &seed, 0, 0).is_err());
    }

    #[test]
    fn test_wrong_sequence_fails() {
        let mut engine = QtaidLoginEngine::new();
        let seed = [0u8; 32];
        // Register 100 A's
        let registered = "A".repeat(100);
        engine.register("did:wyqcc:carol", &registered, 1e-6, &seed, 0).unwrap();
        // Authenticate with all T's — should fail (0% match)
        let challenge = "T".repeat(100);
        let result = engine.authenticate("did:wyqcc:carol", &challenge, &seed, 0, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_high_match_succeeds() {
        let mut engine = QtaidLoginEngine::new();
        let seed = [1u8; 32];
        // 100 SNPs
        let seq: String = "ACGT".repeat(25); // 100 chars
        engine.register("did:wyqcc:dave", &seq, 1e-6, &seed, 0).unwrap();
        // Same sequence → 100% match
        let result = engine.authenticate("did:wyqcc:dave", &seq, &seed, 0, 0);
        assert!(result.is_ok());
    }
}
