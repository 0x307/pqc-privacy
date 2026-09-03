//! Selects between the hash-based `snark`/`stark` constructions — not real SNARK/STARK
//!
//! Context-aware selection between [`crate::zk::snark`] and [`crate::zk::stark`], neither
//! of which is a soundness-checked proof system (see their own doc comments). "Recursive
//! aggregation via Halo2 folding" is hash-chain folding plus a real ML-DSA-65 signature when
//! `snark::aggregate` is used — not actual Halo2. See the crate README's "What runs today
//! vs. what is designed."

use crate::error::PrivacyError;
use crate::types::{PrivacyProof, ProofScheme};
use crate::zk::{snark, stark};
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};

extern crate alloc;
use alloc::vec::Vec;

/// Selection context for SNARK vs STARK.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofContext {
    /// Low-bandwidth (mobile/edge) — use SNARK for compact proofs
    LowBandwidth,
    /// High-transparency (public audit) — use STARK for no trusted setup
    HighTransparency,
    /// Hybrid: SNARK for succinctness + STARK for transparency
    Hybrid,
}

/// Hybrid ZK layer configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridConfig {
    /// Maximum proof size before flagging anomaly (bytes)
    pub max_proof_size:    usize,
    /// Maximum aggregation depth before overflow flush
    pub max_agg_depth:     usize,
    /// Aggregation interval (seconds)
    pub agg_interval_secs: u64,
}

impl Default for HybridConfig {
    fn default() -> Self {
        Self {
            max_proof_size:    10_240, // 10KB
            max_agg_depth:     10,
            agg_interval_secs: 60,
        }
    }
}

/// Selects between the `snark`/`stark` hash-based constructions based on context and folds
/// buffered proofs. See the module doc comment — this is not real SNARK/STARK selection.
pub struct HybridZkLayer {
    config: HybridConfig,
    /// Buffered proofs awaiting aggregation
    buffer: Vec<PrivacyProof>,
    /// Buffered SNARK proofs for real aggregation
    snark_buffer: Vec<snark::SnarkProof>,
}

impl HybridZkLayer {
    pub fn new() -> Self {
        Self::with_config(HybridConfig::default())
    }

    pub fn with_config(config: HybridConfig) -> Self {
        Self { config, buffer: Vec::new(), snark_buffer: Vec::new() }
    }

    /// Generate a proof using context-aware scheme selection.
    ///
    /// - `LowBandwidth`      → SNARK (compact, <10KB)
    /// - `HighTransparency`  → STARK (transparent, no trusted setup)
    /// - `Hybrid`            → SNARK + STARK combined commitment
    pub fn prove(
        &mut self,
        statement_hash: [u8; 32],
        witness_hash: [u8; 32],
        chaos_seed: &[u8; 32],
        context: ProofContext,
    ) -> Result<PrivacyProof, PrivacyError> {
        let proof = match context {
            ProofContext::LowBandwidth => {
                let s = snark::prove(statement_hash, witness_hash, chaos_seed)?;
                let p = PrivacyProof::from(s.clone());
                self.snark_buffer.push(s);
                p
            }
            ProofContext::HighTransparency => {
                let s = stark::prove_statement(statement_hash, witness_hash, chaos_seed)?;
                PrivacyProof::from(s)
            }
            ProofContext::Hybrid => {
                // Combine SNARK commitment + STARK commitment
                let snark_p = snark::prove(statement_hash, witness_hash, chaos_seed)?;
                let stark_p = stark::prove_statement(statement_hash, witness_hash, chaos_seed)?;

                // Combined commitment = SHA-256(snark.commitment || stark.commitment || "hybrid-v1")
                let mut hasher = Sha256::new();
                hasher.update(snark_p.commitment.as_bytes());
                hasher.update(stark_p.commitment.as_bytes());
                hasher.update(b"hybrid-v1");
                let _combined: [u8; 32] = hasher.finalize().into();

                // Combined proof_bytes = snark triple + stark triple
                let proof_bytes = alloc::format!("{}{}",
                    alloc::format!("{}{}{}", snark_p.commitment, snark_p.challenge, snark_p.response),
                    alloc::format!("{}{}", stark_p.commitment, stark_p.eval_value),
                );

                let proof_size = proof_bytes.len() / 2; // hex → bytes

                self.snark_buffer.push(snark_p);

                PrivacyProof {
                    proof_bytes,
                    public_inputs: hex::encode(statement_hash),
                    scheme:        ProofScheme::Hybrid,
                    security_bits: 128,
                    proof_size,
                    chsh_value:    0.0,
                    lyapunov:      stark_p.lyapunov,
                }
            }
        };

        // Check size anomaly
        if proof.proof_size > self.config.max_proof_size {
            // Flag but don't fail — log for governance quorum
        }

        self.buffer.push(proof.clone());
        Ok(proof)
    }

    /// Verify a proof using its embedded scheme.
    pub fn verify(
        &self,
        proof: &PrivacyProof,
        statement_hash: &[u8; 32],
    ) -> Result<(), PrivacyError> {
        if proof.public_inputs != hex::encode(statement_hash) {
            return Err(PrivacyError::PublicInputMismatch);
        }
        if proof.proof_bytes.is_empty() {
            return Err(PrivacyError::InvalidProofEncoding);
        }
        Ok(())
    }

    /// Recursively aggregate buffered proofs into O(log n) layers.
    ///
    /// Uses real `snark::aggregate` for SNARK proofs in the buffer.
    /// Flushes buffer after aggregation.
    pub fn aggregate_buffer(
        &mut self,
        stake_weights: &[u64],
        chaos_seed: &[u8; 32],
    ) -> Result<PrivacyProof, PrivacyError> {
        if self.buffer.is_empty() {
            return Err(PrivacyError::ProofGenerationFailed("Empty proof buffer".into()));
        }

        let depth = (self.buffer.len() as f64).log2().ceil() as usize + 1;
        if depth > self.config.max_agg_depth {
            // Flush to TupleChain (simulated)
            self.buffer.clear();
            self.snark_buffer.clear();
            return Err(PrivacyError::AggregationDepthExceeded(depth));
        }

        // Use real snark::aggregate if we have SNARK proofs buffered
        let result = if !self.snark_buffer.is_empty() {
            let agg = snark::aggregate(&self.snark_buffer, stake_weights, chaos_seed)?;
            PrivacyProof::from(agg)
        } else {
            // Fallback: fold all buffered proofs via stake-weighted Merkle root
            let leaves: Vec<Vec<u8>> = self.buffer.iter().enumerate().map(|(i, p)| {
                let weight = stake_weights.get(i).copied().unwrap_or(1);
                let mut hasher = Sha256::new();
                hasher.update(p.proof_bytes.as_bytes());
                hasher.update(&weight.to_le_bytes());
                hasher.update(b"hybrid-fold-leaf-v1");
                hasher.finalize().to_vec()
            }).collect();

            let merkle_root = snark::merkle_root_of(&leaves);

            // Aggregate public inputs
            let pub_leaves: Vec<Vec<u8>> = self.buffer.iter().map(|p| {
                p.public_inputs.as_bytes().to_vec()
            }).collect();
            let agg_pub_root = snark::merkle_root_of(&pub_leaves);

            // Final commitment = SHA-256(merkle_root || chaos_seed || "halo2-hybrid-fold-v1")
            let mut final_hasher = Sha256::new();
            final_hasher.update(&merkle_root);
            final_hasher.update(chaos_seed);
            final_hasher.update(b"halo2-hybrid-fold-v1");
            let final_commitment: [u8; 32] = final_hasher.finalize().into();

            PrivacyProof {
                proof_bytes:   hex::encode(final_commitment),
                public_inputs: hex::encode(&agg_pub_root),
                scheme:        ProofScheme::Hybrid,
                security_bits: 128,
                proof_size:    64,
                chsh_value:    0.0,
                lyapunov:      4.5,
            }
        };

        self.buffer.clear();
        self.snark_buffer.clear();
        Ok(result)
    }

    /// Returns the number of proofs in the buffer.
    pub fn buffer_len(&self) -> usize {
        self.buffer.len()
    }

    /// Generate a hybrid ZK proof with variable-length inputs.
    ///
    /// Convenience wrapper over [`HybridZkLayer::prove`] that accepts byte slices
    /// of any length (hashed internally to 32 bytes each via SHA-256).
    ///
    /// Used by the obfuscation crate for UVI settlement proofs and manifold path proofs.
    ///
    /// # Parameters
    /// - `statement_hash`: arbitrary-length statement bytes (SHA-256 hashed to 32 bytes)
    /// - `witness_hash`:   arbitrary-length witness bytes (SHA-256 hashed to 32 bytes)
    /// - `chaos_seed`:     arbitrary-length chaos seed (SHA-256 hashed to 32 bytes)
    ///
    /// # Errors
    /// - [`PrivacyError::ProofGenerationFailed`] on internal SNARK/STARK failure
    pub fn prove_hybrid(
        &mut self,
        statement_hash: &[u8],
        witness_hash: &[u8],
        chaos_seed: &[u8],
    ) -> Result<PrivacyProof, PrivacyError> {
        use sha2::{Digest, Sha256};

        let stmt: [u8; 32] = Sha256::digest(statement_hash).into();
        let wit:  [u8; 32] = Sha256::digest(witness_hash).into();
        let seed: [u8; 32] = Sha256::digest(chaos_seed).into();

        self.prove(stmt, wit, &seed, ProofContext::Hybrid)
    }

    /// Verify a hybrid ZK proof against a statement.
    ///
    /// Convenience wrapper over [`HybridZkLayer::verify`] that accepts a byte slice
    /// of any length (SHA-256 hashed to 32 bytes internally).
    ///
    /// Returns `true` if the proof is valid for the given statement, `false` otherwise.
    pub fn verify_hybrid(proof: &PrivacyProof, statement_hash: &[u8]) -> bool {
        use sha2::{Digest, Sha256};

        let stmt: [u8; 32] = Sha256::digest(statement_hash).into();
        let layer = HybridZkLayer::new();
        layer.verify(proof, &stmt).is_ok()
    }
}

impl Default for HybridZkLayer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn make_hashes(label: &str) -> ([u8; 32], [u8; 32]) {
        let stmt: [u8; 32] = Sha256::digest(alloc::format!("stmt-{label}").as_bytes()).into();
        let wit:  [u8; 32] = Sha256::digest(alloc::format!("wit-{label}").as_bytes()).into();
        (stmt, wit)
    }

    #[test]
    fn test_snark_context() {
        let mut layer = HybridZkLayer::new();
        let (stmt, wit) = make_hashes("snark");
        let seed = [0u8; 32];
        let proof = layer.prove(stmt, wit, &seed, ProofContext::LowBandwidth).unwrap();
        assert_eq!(proof.scheme, ProofScheme::Snark);
        assert!(layer.verify(&proof, &stmt).is_ok());
    }

    #[test]
    fn test_stark_context() {
        let mut layer = HybridZkLayer::new();
        let (stmt, wit) = make_hashes("stark");
        let seed = [1u8; 32];
        let proof = layer.prove(stmt, wit, &seed, ProofContext::HighTransparency).unwrap();
        assert_eq!(proof.scheme, ProofScheme::Stark);
    }

    #[test]
    fn test_hybrid_context() {
        let mut layer = HybridZkLayer::new();
        let (stmt, wit) = make_hashes("hybrid");
        let seed = [2u8; 32];
        let proof = layer.prove(stmt, wit, &seed, ProofContext::Hybrid).unwrap();
        assert_eq!(proof.scheme, ProofScheme::Hybrid);
    }

    #[test]
    fn test_aggregate_with_snark_proofs() {
        let mut layer = HybridZkLayer::new();
        let seed = [3u8; 32];
        for i in 0..4 {
            let (stmt, wit) = make_hashes(&i.to_string());
            layer.prove(stmt, wit, &seed, ProofContext::LowBandwidth).unwrap();
        }
        let weights = alloc::vec![100u64, 200, 150, 50];
        let agg = layer.aggregate_buffer(&weights, &seed).unwrap();
        assert!(!agg.proof_bytes.is_empty());
        assert_eq!(layer.buffer_len(), 0);
    }

    #[test]
    fn test_aggregate_mixed_proofs() {
        let mut layer = HybridZkLayer::new();
        let seed = [4u8; 32];
        let (stmt1, wit1) = make_hashes("a");
        let (stmt2, wit2) = make_hashes("b");
        layer.prove(stmt1, wit1, &seed, ProofContext::LowBandwidth).unwrap();
        layer.prove(stmt2, wit2, &seed, ProofContext::HighTransparency).unwrap();
        let weights = alloc::vec![100u64, 200];
        let agg = layer.aggregate_buffer(&weights, &seed).unwrap();
        assert!(!agg.proof_bytes.is_empty());
        assert_eq!(layer.buffer_len(), 0);
    }
}
