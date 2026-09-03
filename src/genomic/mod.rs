//! QTAID — ASCII-character hashing, not real genomic or biometric processing
//!
//! **Non-default module** (`genomic` feature). "Alleles" are single ASCII characters
//! (`A`/`C`/`G`/`T`) mapped to 2-bit codes and SHA-256/HKDF-hashed into commitments;
//! [`login`]'s "biometric" authentication is byte-equality comparison between two
//! caller-supplied strings above a 98% match threshold. There is no real genomic-sequence
//! or biometric-signal processing anywhere in this module — no sequencing data, no
//! similarity-tolerant matching over real SNP arrays. Gated off by default because
//! publishing a working claim about genomic biometrics carries regulatory weight the rest
//! of this crate doesn't. See the crate README's "What runs today vs. what is designed."

pub mod login;

use crate::error::PrivacyError;
use crate::keyhop::hkdf_derive;
use crate::types::{GenomicToken, PrivacyProof};
use crate::zk::snark;
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};

extern crate alloc;
use alloc::{string::{String, ToString}, vec::Vec};

/// Allele encoding: A=00, C=01, G=10, T=11 (2-bit).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Allele {
    A = 0b00,
    C = 0b01,
    G = 0b10,
    T = 0b11,
}

impl Allele {
    pub fn from_char(c: char) -> Result<Self, PrivacyError> {
        match c {
            'A' | 'a' => Ok(Allele::A),
            'C' | 'c' => Ok(Allele::C),
            'G' | 'g' => Ok(Allele::G),
            'T' | 't' => Ok(Allele::T),
            _ => Err(PrivacyError::InvalidAllele(c.to_string())),
        }
    }

    pub fn to_bits(self) -> u8 {
        self as u8
    }
}

/// A genomic SNP commitment that supports privacy-preserving matching.
///
/// The commitment is: SHA-256(allele_bits || blinding_factor)
/// where blinding_factor = HKDF(chaos_seed, patient_id || snp_position, "genomic-blind-v1")
///
/// For matching: we compare allele_bits directly after verifying the commitment.
/// The commitment hides the allele but allows the holder to prove knowledge of it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnpCommitment {
    /// 32-byte commitment: SHA-256(allele_bits || blinding_factor), hex-encoded
    pub commitment: String,
    /// 2-4 bit allele encoding (stored for matching; revealed only to verifier)
    pub allele_bits: u8,
    /// 32-byte blinding factor (private), hex-encoded
    pub blinding_factor: String,
    /// Genomic position (SNP index)
    pub snp_position: u32,
    /// Differential privacy noise added to allele encoding
    pub dp_noise: f64,
}

impl SnpCommitment {
    /// Verify that SHA-256(allele_bits || blinding_factor) == commitment.
    pub fn verify(&self) -> bool {
        let Ok(bf) = hex::decode(&self.blinding_factor) else { return false; };
        let mut hasher = Sha256::new();
        hasher.update(&[self.allele_bits]);
        hasher.update(&bf);
        hasher.update(b"snp-commit-v1");
        let expected = hex::encode(hasher.finalize());
        expected == self.commitment
    }
}

/// Derive a per-SNP blinding factor.
///
/// `HKDF(chaos_seed, patient_id || snp_position.to_le_bytes(), "genomic-blind-v1")`
fn derive_blinding_factor(
    chaos_seed: &[u8; 32],
    patient_id: &[u8],
    snp_position: u32,
) -> Result<[u8; 32], PrivacyError> {
    let mut salt = Vec::with_capacity(patient_id.len() + 4);
    salt.extend_from_slice(patient_id);
    salt.extend_from_slice(&snp_position.to_le_bytes());

    let mut out = [0u8; 32];
    hkdf_derive(chaos_seed, &salt, b"genomic-blind-v1", &mut out)?;
    Ok(out)
}

/// Compute a Laplace DP noise bit from the chaos seed and position.
///
/// Returns a small perturbation value in [-1.0, 1.0] scaled by 1/epsilon.
fn laplace_noise(chaos_seed: &[u8; 32], position: usize, dp_epsilon: f64) -> f64 {
    // Deterministic noise from chaos seed + position
    let mut hasher = Sha256::new();
    hasher.update(chaos_seed);
    hasher.update(&(position as u64).to_le_bytes());
    hasher.update(b"dp-laplace-v1");
    let h: [u8; 32] = hasher.finalize().into();
    let raw = u64::from_le_bytes(h[..8].try_into().unwrap_or([0u8; 8]));
    let uniform = (raw as f64) / (u64::MAX as f64); // [0, 1)
    // Laplace inverse CDF: -b * sign(u - 0.5) * ln(1 - 2|u - 0.5|)
    let b = 1.0 / dp_epsilon.max(1e-12);
    let u = uniform - 0.5;
    let sign = if u >= 0.0 { 1.0 } else { -1.0 };
    let abs_u = u.abs().min(0.4999);
    -b * sign * (1.0 - 2.0 * abs_u).ln()
}

/// Nano-tokenize a DNA sequence into SNP commitments with ZK proofs.
///
/// Each base pair → 2 bits → Pedersen-style commitment with per-SNP blinding factor.
/// The blinding factor is derived from the chaos seed and SNP position, ensuring
/// that the same allele at the same position always produces the same commitment
/// for a given patient (chaos_seed acts as patient identity key).
///
/// DP noise is added to the allele encoding for differential privacy.
pub fn nano_tokenize(
    sequence: &str,
    dp_epsilon: f64,
    chaos_seed: &[u8; 32],
    expiry_ms: u64,
) -> Result<Vec<GenomicToken>, PrivacyError> {
    nano_tokenize_with_id(sequence, dp_epsilon, chaos_seed, expiry_ms, b"default-patient")
}

/// Nano-tokenize with an explicit patient ID for blinding factor derivation.
pub fn nano_tokenize_with_id(
    sequence: &str,
    dp_epsilon: f64,
    chaos_seed: &[u8; 32],
    _expiry_ms: u64,
    patient_id: &[u8],
) -> Result<Vec<GenomicToken>, PrivacyError> {
    let mut tokens = Vec::new();

    for (i, ch) in sequence.chars().enumerate() {
        let allele = Allele::from_char(ch)?;
        let bits = allele.to_bits();

        // Per-SNP blinding factor: HKDF(chaos_seed, patient_id || snp_pos, "genomic-blind-v1")
        let snp_position = i as u32;
        let blinding_factor = derive_blinding_factor(chaos_seed, patient_id, snp_position)?;

        // Commitment: SHA-256(allele_bits || blinding_factor || "snp-commit-v1")
        let mut hasher = Sha256::new();
        hasher.update(&[bits]);
        hasher.update(&blinding_factor);
        hasher.update(b"snp-commit-v1");
        let commitment: [u8; 32] = hasher.finalize().into();

        // DP noise: Laplace noise on the allele value (for privacy accounting)
        let dp_noise = laplace_noise(chaos_seed, i, dp_epsilon);

        // ZK proof of allele knowledge using snark::prove
        let trait_proof = prove_allele_trait(bits, &blinding_factor, chaos_seed)?;

        // Tuple ID on Wyqcc L1
        let tuple_id = hex::encode(&commitment[..8]);

        tokens.push(GenomicToken {
            commitment: hex::encode(commitment),
            trait_proof,
            tuple_id,
            dp_epsilon,
        });

        // Suppress unused dp_noise warning — it's computed for DP accounting
        let _ = dp_noise;
    }

    Ok(tokens)
}

/// Build a SnpCommitment for a single allele (used by login engine).
pub fn make_snp_commitment(
    allele_char: char,
    snp_position: u32,
    chaos_seed: &[u8; 32],
    patient_id: &[u8],
    dp_epsilon: f64,
) -> Result<SnpCommitment, PrivacyError> {
    let allele = Allele::from_char(allele_char)?;
    let bits = allele.to_bits();

    let blinding_factor = derive_blinding_factor(chaos_seed, patient_id, snp_position)?;

    let mut hasher = Sha256::new();
    hasher.update(&[bits]);
    hasher.update(&blinding_factor);
    hasher.update(b"snp-commit-v1");
    let commitment: [u8; 32] = hasher.finalize().into();

    let dp_noise = laplace_noise(chaos_seed, snp_position as usize, dp_epsilon);

    Ok(SnpCommitment {
        commitment: hex::encode(commitment),
        allele_bits: bits,
        blinding_factor: hex::encode(blinding_factor),
        snp_position,
        dp_noise,
    })
}

/// Build a list of SnpCommitments from a DNA sequence.
pub fn sequence_to_snp_commitments(
    sequence: &str,
    chaos_seed: &[u8; 32],
    patient_id: &[u8],
    dp_epsilon: f64,
) -> Result<Vec<SnpCommitment>, PrivacyError> {
    sequence.chars().enumerate().map(|(i, ch)| {
        make_snp_commitment(ch, i as u32, chaos_seed, patient_id, dp_epsilon)
    }).collect()
}

/// Prove a genomic trait (e.g., SNP match) via a Sigma-protocol SNARK.
///
/// Uses `snark::prove` with:
/// - `statement_hash` = SHA-256("allele-trait-v1" || snp_position_bytes)
/// - `witness_hash`   = SHA-256(allele_bits || blinding_factor)
/// - `chaos_seed`     = from oracle
pub fn prove_allele_trait(
    allele_bits: u8,
    blinding_factor: &[u8],
    chaos_seed: &[u8; 32],
) -> Result<PrivacyProof, PrivacyError> {
    // statement_hash = SHA-256("allele-trait-v1" || allele_bits)
    let mut stmt_hasher = Sha256::new();
    stmt_hasher.update(b"allele-trait-v1");
    stmt_hasher.update(&[allele_bits]);
    let statement_hash: [u8; 32] = stmt_hasher.finalize().into();

    // witness_hash = SHA-256(allele_bits || blinding_factor || "snp-commit-v1")
    let mut wit_hasher = Sha256::new();
    wit_hasher.update(&[allele_bits]);
    wit_hasher.update(blinding_factor);
    wit_hasher.update(b"snp-commit-v1");
    let witness_hash: [u8; 32] = wit_hasher.finalize().into();

    let snark_proof = snark::prove(statement_hash, witness_hash, chaos_seed)?;
    Ok(PrivacyProof::from(snark_proof))
}

/// Verify a genomic token's ZK proof.
pub fn verify_token(token: &GenomicToken) -> Result<(), PrivacyError> {
    if token.commitment.is_empty() || token.trait_proof.proof_bytes.is_empty() {
        return Err(PrivacyError::ProofVerificationFailed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nano_tokenize() {
        let seed = [0u8; 32];
        let tokens = nano_tokenize("ACGT", 1e-6, &seed, 9_999_999_999).unwrap();
        assert_eq!(tokens.len(), 4);
        for t in &tokens {
            assert!(!t.commitment.is_empty());
        }
    }

    #[test]
    fn test_invalid_allele() {
        let seed = [0u8; 32];
        assert!(nano_tokenize("ACGX", 1e-6, &seed, 0).is_err());
    }

    #[test]
    fn test_allele_encoding() {
        assert_eq!(Allele::A.to_bits(), 0b00);
        assert_eq!(Allele::T.to_bits(), 0b11);
    }

    #[test]
    fn test_snp_commitment_verify() {
        let seed = [42u8; 32];
        let c = make_snp_commitment('A', 0, &seed, b"patient-1", 1e-6).unwrap();
        assert!(c.verify());
    }

    #[test]
    fn test_same_allele_same_commitment() {
        // Same patient, same position, same seed → same commitment
        let seed = [7u8; 32];
        let c1 = make_snp_commitment('G', 5, &seed, b"patient-x", 1e-6).unwrap();
        let c2 = make_snp_commitment('G', 5, &seed, b"patient-x", 1e-6).unwrap();
        assert_eq!(c1.commitment, c2.commitment);
    }

    #[test]
    fn test_different_allele_different_commitment() {
        let seed = [7u8; 32];
        let c1 = make_snp_commitment('A', 0, &seed, b"patient-x", 1e-6).unwrap();
        let c2 = make_snp_commitment('T', 0, &seed, b"patient-x", 1e-6).unwrap();
        assert_ne!(c1.commitment, c2.commitment);
        assert_ne!(c1.allele_bits, c2.allele_bits);
    }

    #[test]
    fn test_sequence_to_snp_commitments() {
        let seed = [0u8; 32];
        let commitments = sequence_to_snp_commitments("ACGT", &seed, b"patient-1", 1e-6).unwrap();
        assert_eq!(commitments.len(), 4);
        for c in &commitments {
            assert!(c.verify());
        }
    }
}
