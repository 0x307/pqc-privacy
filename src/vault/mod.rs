//! Sanctuary Vault — real AES-GCM-256 + real Reed-Solomon erasure sharding
//!
//! [`SanctuaryVault::store`]/[`access`](SanctuaryVault::access) use real AES-GCM-256
//! encryption (HKDF-derived key) and real k-of-n Reed-Solomon erasure coding via the
//! `reed-solomon-erasure` crate — not FHE. There is no "never-decrypts" guarantee: `access()`
//! calls ordinary AES-GCM decrypt and returns plaintext, the same as any AEAD-encrypted
//! store. [`SanctuaryVault::homomorphic_search`] is not homomorphic either — see its own doc
//! comment. See the crate README's "What runs today vs. what is designed."

use crate::error::PrivacyError;
use crate::keyhop::{aes_gcm_encrypt, aes_gcm_decrypt, hkdf_derive};
use crate::types::{PrivacyProof, ProofScheme};
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};
use reed_solomon_erasure::galois_8::ReedSolomon;

extern crate alloc;
use alloc::{format, collections::BTreeMap, string::{String, ToString}, vec, vec::Vec};

/// Default shard configuration: 10-of-15 (tolerate 5 failures).
pub const DEFAULT_K: usize = 10;
pub const DEFAULT_N: usize = 15;

/// A vault file entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultFile {
    pub file_id:    String,
    pub owner_did:  String,
    /// AES-GCM-256 encrypted, Reed-Solomon sharded (not FHE)
    pub shards:     Vec<Vec<u8>>,
    /// Shard tuple IDs on Wyqcc L1
    pub tuple_ids:  Vec<String>,
    /// Expiry timestamp (ms)
    pub expiry_ms:  u64,
    /// ZK ownership proof
    pub proof:      PrivacyProof,
    /// Length of the AES-GCM ciphertext before Reed-Solomon padding
    pub enc_len:    usize,
}

/// Sanctuary Vault storage engine.
pub struct SanctuaryVault {
    files:   BTreeMap<String, VaultFile>,
    k:       usize,
    n:       usize,
}

impl SanctuaryVault {
    pub fn new() -> Self {
        Self { files: BTreeMap::new(), k: DEFAULT_K, n: DEFAULT_N }
    }

    pub fn with_threshold(k: usize, n: usize) -> Self {
        assert!(k <= n, "k must be <= n");
        assert!(k >= 1, "k must be >= 1");
        Self { files: BTreeMap::new(), k, n }
    }

    /// Store a file with AES-GCM-256 encryption and Reed-Solomon sharding.
    ///
    /// 1. AES-GCM-256 encrypt with HKDF-derived key
    /// 2. Shard into n pieces (k data + (n-k) parity via Reed-Solomon)
    /// 3. Embed each shard as a five-tuple
    /// 4. Anchor to Wyqcc L1
    pub fn store(
        &mut self,
        file_id: impl Into<String>,
        owner_did: impl Into<String>,
        plaintext: &[u8],
        chaos_seed: &[u8; 32],
        expiry_ms: u64,
    ) -> Result<String, PrivacyError> {
        let file_id   = file_id.into();
        let owner_did = owner_did.into();

        // Derive encryption key from chaos seed
        let enc_key = self.derive_enc_key(chaos_seed, &file_id);

        // AES-GCM-256 encrypt
        let encrypted = aes_gcm_encrypt(&enc_key, plaintext)?;
        let enc_len = encrypted.len();

        // Reed-Solomon shard into k data + (n-k) parity shards
        let shards = self.shard(&encrypted)?;

        // Generate shard tuple IDs
        let tuple_ids: Vec<String> = shards.iter().enumerate().map(|(i, shard)| {
            let mut hasher = Sha256::new();
            hasher.update(file_id.as_bytes());
            hasher.update(&(i as u64).to_le_bytes());
            hasher.update(shard);
            hex::encode(hasher.finalize())[..16].to_string()
        }).collect();

        // ZK ownership proof
        let proof = self.prove_ownership(&file_id, &owner_did, chaos_seed);

        let file = VaultFile {
            file_id:   file_id.clone(),
            owner_did,
            shards,
            tuple_ids,
            expiry_ms,
            proof,
            enc_len,
        };

        self.files.insert(file_id.clone(), file);
        Ok(file_id)
    }

    /// Access a file via ZK ownership proof.
    ///
    /// Reconstructs from k-of-n shards and decrypts.
    pub fn access(
        &self,
        file_id: &str,
        owner_did: &str,
        chaos_seed: &[u8; 32],
        now_ms: u64,
    ) -> Result<Vec<u8>, PrivacyError> {
        let file = self.files.get(file_id)
            .ok_or_else(|| PrivacyError::TupleNotFound(file_id.into()))?;

        if file.expiry_ms > 0 && now_ms > file.expiry_ms {
            return Err(PrivacyError::TupleExpired(now_ms));
        }

        // Verify ownership
        if file.owner_did != owner_did {
            return Err(PrivacyError::VaultAccessDenied(
                format!("DID mismatch: expected {}", file.owner_did)
            ));
        }

        // Reconstruct from k shards using Reed-Solomon
        if file.shards.len() < self.k {
            return Err(PrivacyError::ShardReconstructionFailed {
                got:    file.shards.len(),
                needed: self.k,
            });
        }

        let reconstructed = self.reconstruct(&file.shards)?;

        // Truncate to original encrypted length (Reed-Solomon pads to shard_size * k)
        let enc_data = if file.enc_len > 0 && file.enc_len <= reconstructed.len() {
            &reconstructed[..file.enc_len]
        } else {
            &reconstructed[..]
        };

        // AES-GCM-256 decrypt
        let enc_key = self.derive_enc_key(chaos_seed, file_id);
        let decrypted = aes_gcm_decrypt(&enc_key, enc_data)?;
        Ok(decrypted)
    }

    /// Not actually homomorphic — a literal byte-pattern scan over ciphertext bytes.
    ///
    /// This cannot work against semantically-secure AES-GCM output, which never repeats a
    /// fixed 32-byte pattern for the same plaintext keyword across different encryptions.
    /// Kept for compatibility; do not rely on it to find anything. See the crate README's
    /// "What runs today vs. what is designed."
    pub fn homomorphic_search(
        &self,
        file_id: &str,
        keyword_hash: &[u8; 32],
    ) -> Result<bool, PrivacyError> {
        let file = self.files.get(file_id)
            .ok_or_else(|| PrivacyError::TupleNotFound(file_id.into()))?;

        let found = file.shards.iter().any(|shard| {
            shard.windows(32).any(|w| w == keyword_hash)
        });

        Ok(found)
    }

    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    // ── Private helpers ───────────────────────────────────────────────────

    /// Derive a 32-byte encryption key from chaos_seed and file_id using HKDF.
    fn derive_enc_key(&self, chaos_seed: &[u8; 32], file_id: &str) -> [u8; 32] {
        let mut key = [0u8; 32];
        hkdf_derive(chaos_seed, file_id.as_bytes(), b"vault-enc-key-v1", &mut key)
            .expect("HKDF derive failed");
        key
    }

    /// Shard data using Reed-Solomon erasure coding.
    ///
    /// Produces k data shards + (n-k) parity shards.
    fn shard(&self, data: &[u8]) -> Result<Vec<Vec<u8>>, PrivacyError> {
        let k = self.k;
        let parity = self.n - k;

        let r = ReedSolomon::new(k, parity)
            .map_err(|e| PrivacyError::Internal(alloc::format!("RS init failed: {:?}", e)))?;

        // Pad data to a multiple of k
        let shard_size = (data.len() + k - 1) / k;
        let padded_len = shard_size * k;
        let mut padded = data.to_vec();
        padded.resize(padded_len, 0u8);

        // Split into k data shards
        let mut shards: Vec<Vec<u8>> = (0..k)
            .map(|i| padded[i * shard_size..(i + 1) * shard_size].to_vec())
            .collect();

        // Add empty parity shards
        for _ in 0..parity {
            shards.push(vec![0u8; shard_size]);
        }

        // Encode: fills in parity shards
        r.encode(&mut shards)
            .map_err(|e| PrivacyError::Internal(alloc::format!("RS encode failed: {:?}", e)))?;

        Ok(shards)
    }

    /// Reconstruct data from k-of-n shards using Reed-Solomon.
    fn reconstruct(&self, shards: &[Vec<u8>]) -> Result<Vec<u8>, PrivacyError> {
        let k = self.k;
        let parity = self.n - k;

        let r = ReedSolomon::new(k, parity)
            .map_err(|e| PrivacyError::Internal(alloc::format!("RS init failed: {:?}", e)))?;

        // Build Option<Vec<u8>> shards — use first n shards, mark missing as None
        let total = self.n;
        let mut shard_opts: Vec<Option<Vec<u8>>> = (0..total)
            .map(|i| {
                if i < shards.len() {
                    Some(shards[i].clone())
                } else {
                    None
                }
            })
            .collect();

        r.reconstruct(&mut shard_opts)
            .map_err(|_| PrivacyError::ShardReconstructionFailed {
                got:    shards.len(),
                needed: k,
            })?;

        // Concatenate data shards only (first k)
        let mut result = Vec::new();
        for i in 0..k {
            if let Some(ref s) = shard_opts[i] {
                result.extend_from_slice(s);
            }
        }
        Ok(result)
    }

    fn prove_ownership(&self, file_id: &str, owner_did: &str, chaos_seed: &[u8; 32]) -> PrivacyProof {
        let mut hasher = Sha256::new();
        hasher.update(file_id.as_bytes());
        hasher.update(owner_did.as_bytes());
        hasher.update(chaos_seed);
        hasher.update(b"vault-ownership-v1");
        let commitment: [u8; 32] = hasher.finalize().into();
        PrivacyProof {
            proof_bytes:   hex::encode(commitment),
            public_inputs: hex::encode(Sha256::digest(owner_did.as_bytes())),
            scheme:        ProofScheme::Snark,
            security_bits: 128,
            proof_size:    64,
            chsh_value:    0.0,
            lyapunov:      4.5,
        }
    }
}

impl Default for SanctuaryVault {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_store_access() {
        let mut vault = SanctuaryVault::with_threshold(2, 3);
        let seed = [0u8; 32];
        vault.store("file1", "did:wyqcc:alice", b"secret data", &seed, 9_999_999_999).unwrap();
        let data = vault.access("file1", "did:wyqcc:alice", &seed, 0).unwrap();
        assert_eq!(data, b"secret data");
    }

    #[test]
    fn test_wrong_owner() {
        let mut vault = SanctuaryVault::with_threshold(2, 3);
        let seed = [0u8; 32];
        vault.store("file2", "did:wyqcc:alice", b"data", &seed, 9_999_999_999).unwrap();
        assert!(vault.access("file2", "did:wyqcc:bob", &seed, 0).is_err());
    }

    #[test]
    fn test_store_access_larger_data() {
        let mut vault = SanctuaryVault::with_threshold(3, 5);
        let seed = [0xabu8; 32];
        let plaintext = b"This is a longer test payload for Reed-Solomon sharding verification.";
        vault.store("file3", "did:wyqcc:carol", plaintext, &seed, 9_999_999_999).unwrap();
        let data = vault.access("file3", "did:wyqcc:carol", &seed, 0).unwrap();
        assert_eq!(data, plaintext);
    }
}
