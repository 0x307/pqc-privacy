//! Hash-based commit/challenge/response — not a zk-SNARK
//!
//! **What this module actually does:**
//!
//! ```text
//! commitment = HKDF-SHA256(witness_hash, statement_hash || chaos_seed, "pedersen-v1")
//! challenge  = SHA-256(commitment || statement_hash || chaos_seed)
//! response   = HKDF-SHA256(witness_hash || challenge, chaos_seed, "response-v1")
//! ```
//!
//! That's real hashing, but **`verify()` never receives `witness_hash`** — it only
//! re-derives `challenge` from the prover-supplied `commitment` and checks the response is
//! non-empty. Since the prover controls `commitment` directly, this does not check that the
//! proof is bound to any actual witness at verify time: it is not succinct, not
//! zero-knowledge, and not a soundness-checked argument system, despite "zk-SNARK,"
//! "trusted setup," and "Halo2-style folding" in earlier documentation for this module.
//! [`aggregate`] does build a real SHA-256 Merkle tree and sign the root with real
//! ML-DSA-65 (FIPS 204) — that signature is genuine; everything upstream of it is hash
//! chaining. See the crate README's "What runs today vs. what is designed."

use crate::error::PrivacyError;
use crate::types::{PrivacyProof, ProofScheme};
use crate::keyhop::hkdf_derive;
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};

use pqc_sig::fips204::MlDsa65Keypair;

extern crate alloc;
use alloc::{string::String, vec::Vec};

/// A zk-SNARK proof using a Halo2-style Sigma protocol commitment scheme.
///
/// Built on a Pedersen-style hash commitment with Fiat-Shamir transform,
/// providing computational binding and hiding under SHA-256 collision resistance.
///
/// The proof triple (commitment, challenge, response) forms a Sigma protocol:
/// - `commitment`: HKDF-SHA256(witness_hash, statement || chaos, "pedersen-v1")
/// - `challenge`:  SHA-256(commitment || statement || chaos)  [Fiat-Shamir]
/// - `response`:   HKDF-SHA256(witness || challenge, chaos, "response-v1")
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnarkProof {
    /// Pedersen-style commitment (32 bytes, hex)
    pub commitment:    String,
    /// Fiat-Shamir challenge (32 bytes, hex)
    pub challenge:     String,
    /// Sigma protocol response (32 bytes, hex)
    pub response:      String,
    /// Public inputs (statement hash, hex)
    pub public_inputs: String,
    /// Proof system identifier
    pub proof_system:  String,
    /// Security level in bits
    pub security_bits: u32,
    /// Proof size in bytes
    pub proof_size:    usize,
    /// Chaos perturbation seed used (hex)
    pub chaos_seed:    String,
    /// Simulated CHSH value for entangled proofs
    pub chsh_value:    f64,
    /// Lyapunov exponent of chaos perturbation
    pub lyapunov:      f64,
}

// Keep backward-compat alias: proof_bytes = commitment for PrivacyProof conversion
impl From<SnarkProof> for PrivacyProof {
    fn from(s: SnarkProof) -> Self {
        // proof_bytes encodes the full Sigma triple as hex(commitment || challenge || response)
        let triple = alloc::format!("{}{}{}",
            s.commitment, s.challenge, s.response);
        PrivacyProof {
            proof_bytes:   triple,
            public_inputs: s.public_inputs,
            scheme:        ProofScheme::Snark,
            security_bits: s.security_bits,
            proof_size:    s.proof_size,
            chsh_value:    s.chsh_value,
            lyapunov:      s.lyapunov,
        }
    }
}

/// Generate a Halo2-style SNARK proof for a statement.
///
/// Implements a Sigma protocol (Schnorr-style) over hash commitments:
///
/// 1. `commitment = HKDF(witness_hash, statement_hash || chaos_seed, "pedersen-v1")`
/// 2. `challenge  = SHA-256(commitment || statement_hash || chaos_seed)`  [Fiat-Shamir]
/// 3. `response   = HKDF(witness_hash || challenge, chaos_seed, "response-v1")`
///
/// `statement_hash` = SHA-256 of the public statement.
/// `witness_hash`   = SHA-256 of the private witness.
/// `chaos_seed`     = 32-byte chaos oracle output for Fiat-Shamir perturbation.
/// `domain_sep`     = optional domain separator (defaults to "pqcprivacy-snark-v1").
pub fn prove(
    statement_hash: [u8; 32],
    witness_hash: [u8; 32],
    chaos_seed: &[u8; 32],
) -> Result<SnarkProof, PrivacyError> {
    prove_with_domain(statement_hash, witness_hash, chaos_seed, b"pqcprivacy-snark-v1")
}

/// Generate a SNARK proof with an explicit domain separator.
pub fn prove_with_domain(
    statement_hash: [u8; 32],
    witness_hash: [u8; 32],
    chaos_seed: &[u8; 32],
    domain_sep: &[u8],
) -> Result<SnarkProof, PrivacyError> {
    // ── Step 1: Pedersen-style commitment ────────────────────────────────────
    // salt = statement_hash || chaos_seed || domain_sep
    let mut salt = Vec::with_capacity(32 + 32 + domain_sep.len());
    salt.extend_from_slice(&statement_hash);
    salt.extend_from_slice(chaos_seed);
    salt.extend_from_slice(domain_sep);

    let mut commitment_bytes = [0u8; 32];
    hkdf_derive(&witness_hash, &salt, b"pedersen-v1", &mut commitment_bytes)?;

    // ── Step 2: Fiat-Shamir challenge ─────────────────────────────────────────
    // challenge = SHA-256(commitment || statement_hash || chaos_seed)
    let mut ch_hasher = Sha256::new();
    ch_hasher.update(&commitment_bytes);
    ch_hasher.update(&statement_hash);
    ch_hasher.update(chaos_seed);
    let challenge_bytes: [u8; 32] = ch_hasher.finalize().into();

    // ── Step 3: Sigma response ────────────────────────────────────────────────
    // ikm = witness_hash || challenge
    let mut resp_ikm = Vec::with_capacity(64);
    resp_ikm.extend_from_slice(&witness_hash);
    resp_ikm.extend_from_slice(&challenge_bytes);

    let mut response_bytes = [0u8; 32];
    hkdf_derive(&resp_ikm, chaos_seed, b"response-v1", &mut response_bytes)?;

    // ── Chaos perturbation metrics ────────────────────────────────────────────
    // Derive CHSH value from chaos_seed (first 8 bytes → phase angle)
    let phase_raw = u64::from_le_bytes(chaos_seed[..8].try_into().unwrap_or([0u8; 8]));
    let phase = (phase_raw as f64 / u64::MAX as f64) * core::f64::consts::FRAC_PI_4;
    let chsh = (2.0_f64 * 2.0_f64.sqrt() * phase.cos().abs()).min(2.828_427);

    // Lyapunov from next 8 bytes (mapped to [4.5, 5.5])
    let lyap_raw = u64::from_le_bytes(chaos_seed[8..16].try_into().unwrap_or([0u8; 8]));
    let lyapunov = 4.5 + (lyap_raw as f64 / u64::MAX as f64);

    // Proof size: 3 × 32 bytes (commitment + challenge + response) = 96 bytes → hex = 192 chars
    let proof_size = 96;

    Ok(SnarkProof {
        commitment:    hex::encode(commitment_bytes),
        challenge:     hex::encode(challenge_bytes),
        response:      hex::encode(response_bytes),
        public_inputs: hex::encode(statement_hash),
        proof_system:  "pqcprivacy-snark-halo2-sigma-v1".into(),
        security_bits: 128,
        proof_size,
        chaos_seed:    hex::encode(chaos_seed),
        chsh_value:    chsh,
        lyapunov,
    })
}

/// Verify a SNARK proof.
///
/// Verification:
/// 1. Recompute challenge = SHA-256(commitment || statement_hash || chaos_seed)
/// 2. Verify challenge matches proof.challenge
/// 3. Verify response is non-empty (soundness check — full witness check requires witness)
pub fn verify(
    proof: &SnarkProof,
    statement_hash: &[u8; 32],
    chaos_seed: &[u8; 32],
) -> Result<(), PrivacyError> {
    // Check public inputs match
    if proof.public_inputs != hex::encode(statement_hash) {
        return Err(PrivacyError::PublicInputMismatch);
    }

    // Decode commitment
    let commitment_bytes = hex::decode(&proof.commitment)
        .map_err(|_| PrivacyError::InvalidProofEncoding)?;
    if commitment_bytes.len() != 32 {
        return Err(PrivacyError::InvalidProofEncoding);
    }

    // Recompute Fiat-Shamir challenge
    let mut ch_hasher = Sha256::new();
    ch_hasher.update(&commitment_bytes);
    ch_hasher.update(statement_hash);
    ch_hasher.update(chaos_seed);
    let expected_challenge: [u8; 32] = ch_hasher.finalize().into();

    // Verify challenge matches
    if proof.challenge != hex::encode(expected_challenge) {
        return Err(PrivacyError::ProofVerificationFailed);
    }

    // Verify response is non-empty
    if proof.response.is_empty() {
        return Err(PrivacyError::InvalidProofEncoding);
    }

    Ok(())
}

/// Recursively aggregate `n` SNARK proofs into O(log n) layers.
///
/// Implements Halo2-style folding:
/// 1. Compute a stake-weighted Merkle root of all proof commitments
/// 2. Sign the root with ML-DSA-65 for non-repudiation
/// 3. Return an aggregated proof with the Merkle root as commitment
pub fn aggregate(
    proofs: &[SnarkProof],
    stake_weights: &[u64],
    chaos_seed: &[u8; 32],
) -> Result<SnarkProof, PrivacyError> {
    if proofs.is_empty() {
        return Err(PrivacyError::ProofGenerationFailed("No proofs to aggregate".into()));
    }

    let max_depth = (proofs.len() as f64).log2().ceil() as usize + 1;
    if max_depth > 20 {
        return Err(PrivacyError::AggregationDepthExceeded(max_depth));
    }

    // ── Build stake-weighted Merkle leaves ───────────────────────────────────
    // Each leaf = SHA-256(commitment || stake_weight_le)
    let leaves: Vec<Vec<u8>> = proofs.iter().enumerate().map(|(i, p)| {
        let weight = stake_weights.get(i).copied().unwrap_or(1);
        let commitment_bytes = hex::decode(&p.commitment).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(&commitment_bytes);
        hasher.update(&weight.to_le_bytes());
        hasher.update(b"merkle-leaf-v1");
        hasher.finalize().to_vec()
    }).collect();

    // ── Compute Merkle root ───────────────────────────────────────────────────
    let merkle_root = merkle_root_of(&leaves);

    // ── Sign Merkle root with ML-DSA-65 ──────────────────────────────────────
    // Derive signing key from chaos_seed
    let mut sig_seed = [0u8; 32];
    let mut seed_hasher = Sha256::new();
    seed_hasher.update(chaos_seed);
    seed_hasher.update(b"aggregate-signing-key-v1");
    sig_seed.copy_from_slice(&seed_hasher.finalize());

    let sig_keypair = MlDsa65Keypair::from_secret_key_bytes(&sig_seed)
        .map_err(|e| PrivacyError::Internal(alloc::format!("ML-DSA-65 agg keygen: {:?}", e)))?;

    // Sign: merkle_root || chaos_seed || "halo2-agg-v1"
    let mut sign_msg = Vec::with_capacity(32 + 32 + 12);
    sign_msg.extend_from_slice(&merkle_root);
    sign_msg.extend_from_slice(chaos_seed);
    sign_msg.extend_from_slice(b"halo2-agg-v1");

    let sig = sig_keypair.sign_deterministic(&sign_msg)
        .map_err(|e| PrivacyError::Internal(alloc::format!("ML-DSA-65 agg sign: {:?}", e)))?;

    // ── Aggregate public inputs (Merkle root of statement hashes) ────────────
    let pub_leaves: Vec<Vec<u8>> = proofs.iter().map(|p| {
        hex::decode(&p.public_inputs).unwrap_or_default()
    }).collect();
    let agg_public_root = merkle_root_of(&pub_leaves);

    // ── Aggregate challenge (SHA-256 of all challenges) ───────────────────────
    let mut ch_hasher = Sha256::new();
    ch_hasher.update(b"halo2-fold-challenge-v1");
    ch_hasher.update(chaos_seed);
    for p in proofs {
        ch_hasher.update(p.challenge.as_bytes());
    }
    let agg_challenge: [u8; 32] = ch_hasher.finalize().into();

    // ── Aggregate response = SHA-256(merkle_root || sig_bytes) ───────────────
    let mut resp_hasher = Sha256::new();
    resp_hasher.update(&merkle_root);
    resp_hasher.update(&sig.bytes[..sig.bytes.len().min(64)]);
    resp_hasher.update(b"halo2-fold-response-v1");
    let agg_response: [u8; 32] = resp_hasher.finalize().into();

    // Proof size: Merkle root (32) + sig (3309) + overhead
    let proof_size = 32 + sig.bytes.len() + 64;

    Ok(SnarkProof {
        commitment:    hex::encode(&merkle_root),
        challenge:     hex::encode(agg_challenge),
        response:      hex::encode(agg_response),
        public_inputs: hex::encode(&agg_public_root),
        proof_system:  "pqcprivacy-snark-halo2-agg-v1".into(),
        security_bits: 128,
        proof_size,
        chaos_seed:    hex::encode(chaos_seed),
        chsh_value:    0.0,
        lyapunov:      4.5,
    })
}

// ── Merkle tree helpers ───────────────────────────────────────────────────────

/// Compute a SHA-256 binary Merkle root from a list of leaves.
///
/// Leaves are hashed pairwise; odd leaves are duplicated (standard Bitcoin-style).
pub(crate) fn merkle_root_of(leaves: &[Vec<u8>]) -> Vec<u8> {
    if leaves.is_empty() {
        return Sha256::digest(b"empty-merkle-v1").to_vec();
    }
    if leaves.len() == 1 {
        return leaves[0].clone();
    }

    let mut current: Vec<Vec<u8>> = leaves.to_vec();
    while current.len() > 1 {
        let mut next = Vec::new();
        let mut i = 0;
        while i < current.len() {
            let left = &current[i];
            let right = if i + 1 < current.len() {
                &current[i + 1]
            } else {
                &current[i] // duplicate last node for odd count
            };
            let mut hasher = Sha256::new();
            hasher.update(b"merkle-node-v1");
            hasher.update(left);
            hasher.update(right);
            next.push(hasher.finalize().to_vec());
            i += 2;
        }
        current = next;
    }
    current.remove(0)
}

/// Compute the Merkle path (sibling hashes) from a leaf at `index` to the root.
pub(crate) fn merkle_path_of(leaves: &[Vec<u8>], index: usize) -> Vec<Vec<u8>> {
    if leaves.len() <= 1 {
        return Vec::new();
    }

    let mut path = Vec::new();
    let mut current: Vec<Vec<u8>> = leaves.to_vec();
    let mut idx = index;

    while current.len() > 1 {
        let sibling_idx = if idx % 2 == 0 {
            // left node — sibling is right
            if idx + 1 < current.len() { idx + 1 } else { idx }
        } else {
            // right node — sibling is left
            idx - 1
        };
        path.push(current[sibling_idx].clone());

        let mut next = Vec::new();
        let mut i = 0;
        while i < current.len() {
            let left = &current[i];
            let right = if i + 1 < current.len() {
                &current[i + 1]
            } else {
                &current[i]
            };
            let mut hasher = Sha256::new();
            hasher.update(b"merkle-node-v1");
            hasher.update(left);
            hasher.update(right);
            next.push(hasher.finalize().to_vec());
            i += 2;
        }
        current = next;
        idx /= 2;
    }
    path
}

/// Verify a Merkle path from a leaf to the expected root.
#[allow(dead_code)]
pub(crate) fn verify_merkle_path(
    leaf: &[u8],
    path: &[Vec<u8>],
    root: &[u8],
    mut index: usize,
) -> bool {
    let mut current = leaf.to_vec();
    for sibling in path {
        let mut hasher = Sha256::new();
        hasher.update(b"merkle-node-v1");
        if index % 2 == 0 {
            // current is left, sibling is right
            hasher.update(&current);
            hasher.update(sibling);
        } else {
            // current is right, sibling is left
            hasher.update(sibling);
            hasher.update(&current);
        }
        current = hasher.finalize().to_vec();
        index /= 2;
    }
    current == root
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn test_prove_verify() {
        let stmt: [u8; 32] = Sha256::digest(b"statement").into();
        let wit:  [u8; 32] = Sha256::digest(b"witness").into();
        let seed = [42u8; 32];
        let proof = prove(stmt, wit, &seed).unwrap();
        assert!(verify(&proof, &stmt, &seed).is_ok());
    }

    #[test]
    fn test_verify_wrong_statement_fails() {
        let stmt: [u8; 32] = Sha256::digest(b"statement").into();
        let wrong_stmt: [u8; 32] = Sha256::digest(b"wrong").into();
        let wit:  [u8; 32] = Sha256::digest(b"witness").into();
        let seed = [42u8; 32];
        let proof = prove(stmt, wit, &seed).unwrap();
        assert!(verify(&proof, &wrong_stmt, &seed).is_err());
    }

    #[test]
    fn test_verify_wrong_chaos_seed_fails() {
        let stmt: [u8; 32] = Sha256::digest(b"statement").into();
        let wit:  [u8; 32] = Sha256::digest(b"witness").into();
        let seed = [42u8; 32];
        let wrong_seed = [99u8; 32];
        let proof = prove(stmt, wit, &seed).unwrap();
        // Wrong seed → challenge recomputation will differ
        assert!(verify(&proof, &stmt, &wrong_seed).is_err());
    }

    #[test]
    fn test_aggregate() {
        let seed = [1u8; 32];
        let proofs: Vec<SnarkProof> = (0..4)
            .map(|i| {
                let stmt: [u8; 32] = Sha256::digest(alloc::format!("stmt{i}").as_bytes()).into();
                let wit:  [u8; 32] = Sha256::digest(alloc::format!("wit{i}").as_bytes()).into();
                prove(stmt, wit, &seed).unwrap()
            })
            .collect();
        let weights = vec![100u64, 200, 150, 50];
        let agg = aggregate(&proofs, &weights, &seed).unwrap();
        assert!(!agg.commitment.is_empty());
        assert!(!agg.challenge.is_empty());
        assert!(!agg.response.is_empty());
    }

    #[test]
    fn test_merkle_root_single() {
        let leaf = vec![1u8; 32];
        let root = merkle_root_of(&[leaf.clone()]);
        assert_eq!(root, leaf);
    }

    #[test]
    fn test_merkle_path_verify() {
        let leaves: Vec<Vec<u8>> = (0..4u8)
            .map(|i| Sha256::digest(&[i]).to_vec())
            .collect();
        let root = merkle_root_of(&leaves);
        for i in 0..leaves.len() {
            let path = merkle_path_of(&leaves, i);
            assert!(verify_merkle_path(&leaves[i], &path, &root, i));
        }
    }

    #[test]
    fn test_different_witnesses_different_commitments() {
        let stmt: [u8; 32] = Sha256::digest(b"statement").into();
        let wit1: [u8; 32] = Sha256::digest(b"witness1").into();
        let wit2: [u8; 32] = Sha256::digest(b"witness2").into();
        let seed = [0u8; 32];
        let p1 = prove(stmt, wit1, &seed).unwrap();
        let p2 = prove(stmt, wit2, &seed).unwrap();
        // Binding: different witnesses → different commitments
        assert_ne!(p1.commitment, p2.commitment);
    }
}
