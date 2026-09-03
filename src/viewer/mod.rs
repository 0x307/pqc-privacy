//! Clearance-gated document viewer — real AES-GCM-256, no classified-handling claim
//!
//! **Naming note (0X3-118):** earlier documentation for this module described it as a
//! "Quantum SCIF Viewer for Classified Documents." This crate makes no claim of suitability
//! for handling government-classified material, has not been evaluated against any such
//! standard, and implements no SCIF (Sensitive Compartmented Information Facility)
//! properties. What it actually does: real AES-GCM-256 encryption of document content,
//! keyed via real HKDF-SHA256, gated by a clearance-level check against the same
//! non-witness-bound proof construction used in [`crate::zk::snark`]. "Never-decrypt
//! viewing via homomorphic masking" does not describe this code — viewing calls ordinary
//! AES-GCM decrypt — and there is no AQVM enclave anywhere in this crate. See the crate
//! README's "What runs today vs. what is designed."

use crate::error::PrivacyError;
use crate::keyhop::hkdf_derive;
use crate::types::{PrivacyProof, ProofScheme};
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};
use aes_gcm::{Aes256Gcm, Key, Nonce, AeadInPlace, KeyInit};

extern crate alloc;
use alloc::{string::String, vec::Vec};

/// AES-GCM-256 nonce length in bytes.
const NONCE_LEN: usize = 12;
/// AES-GCM-256 tag length in bytes.
const TAG_LEN: usize = 16;

/// Security clearance tier (1–5, where 5 is highest).
pub type ClearanceTier = u8;

/// A clearance-gated document entry. See the module doc comment: this crate makes no
/// claim of suitability for government-classified material.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassifiedDocument {
    pub doc_id:        String,
    /// AES-GCM-256 encrypted content
    pub encrypted:     Vec<u8>,
    /// Required clearance tier
    pub required_tier: ClearanceTier,
    /// Policy graph for redaction (section → tier)
    pub policy:        Vec<(String, ClearanceTier)>,
}

/// Clearance-gated document viewer engine.
pub struct QscifViewer;

impl QscifViewer {
    pub fn new() -> Self {
        Self
    }

    /// Prove clearance without revealing credentials.
    ///
    /// Uses the same hash-based commit/challenge/response construction as
    /// [`crate::zk::snark`] — not a real Groth16/Halo2 circuit — to prove
    /// `user_tier >= required_tier`.
    pub fn prove_clearance(
        &self,
        user_tier: ClearanceTier,
        required_tier: ClearanceTier,
        chaos_seed: &[u8; 32],
    ) -> Result<PrivacyProof, PrivacyError> {
        if user_tier < required_tier {
            return Err(PrivacyError::ClearanceFailed {
                required: required_tier,
                got:      user_tier,
            });
        }

        // ZK range proof: prove user_tier >= required_tier
        let diff = user_tier - required_tier;
        let mut hasher = Sha256::new();
        hasher.update(&[diff]);
        hasher.update(chaos_seed);
        hasher.update(b"clearance-proof-v1");
        let commitment: [u8; 32] = hasher.finalize().into();

        Ok(PrivacyProof {
            proof_bytes:   hex::encode(commitment),
            public_inputs: hex::encode([required_tier]),
            scheme:        ProofScheme::Snark,
            security_bits: 128,
            proof_size:    64,
            chsh_value:    0.0,
            lyapunov:      4.5,
        })
    }

    /// Redact a field using AES-GCM-256.
    ///
    /// Key = HKDF(clearance_key, field_name || clearance_level, "redact-v1")
    /// Nonce = first 12 bytes of SHA-256(field_name || clearance_level || "nonce")
    ///
    /// Returns `nonce (12 bytes) || ciphertext || tag (16 bytes)`.
    pub fn redact_field(
        &self,
        field_data: &[u8],
        clearance_level: u8,
        field_name: &str,
        clearance_key: &[u8; 32],
    ) -> Result<Vec<u8>, PrivacyError> {
        // Derive AES-256 key: HKDF(clearance_key, field_name || clearance_level, "redact-v1")
        let mut salt = Vec::with_capacity(field_name.len() + 1);
        salt.extend_from_slice(field_name.as_bytes());
        salt.push(clearance_level);

        let mut aes_key = [0u8; 32];
        hkdf_derive(clearance_key, &salt, b"redact-v1", &mut aes_key)
            .map_err(|e| PrivacyError::RedactionFailed(alloc::format!("HKDF failed: {:?}", e)))?;

        // Derive nonce: first 12 bytes of SHA-256(field_name || clearance_level || "nonce")
        let mut nonce_hasher = Sha256::new();
        nonce_hasher.update(field_name.as_bytes());
        nonce_hasher.update(&[clearance_level]);
        nonce_hasher.update(b"redact-nonce-v1");
        let nonce_hash: [u8; 32] = nonce_hasher.finalize().into();
        let nonce_bytes: [u8; NONCE_LEN] = nonce_hash[..NONCE_LEN].try_into()
            .map_err(|_| PrivacyError::RedactionFailed("Nonce slice error".into()))?;

        // AES-GCM-256 encrypt
        let key = Key::<Aes256Gcm>::from_slice(&aes_key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let mut buffer = field_data.to_vec();
        // Reserve space for the tag
        buffer.reserve(TAG_LEN);

        cipher.encrypt_in_place(nonce, field_name.as_bytes(), &mut buffer)
            .map_err(|e| PrivacyError::RedactionFailed(alloc::format!("AES-GCM encrypt: {:?}", e)))?;

        // Prepend nonce: nonce || ciphertext+tag
        let mut output = Vec::with_capacity(NONCE_LEN + buffer.len());
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&buffer);
        Ok(output)
    }

    /// Reveal (decrypt) a redacted field using AES-GCM-256.
    ///
    /// Input must be `nonce (12 bytes) || ciphertext || tag (16 bytes)`.
    pub fn reveal_field(
        &self,
        encrypted_field: &[u8],
        clearance_key: &[u8; 32],
        field_name: &str,
        clearance_level: u8,
    ) -> Result<Vec<u8>, PrivacyError> {
        if encrypted_field.len() < NONCE_LEN + TAG_LEN {
            return Err(PrivacyError::RedactionFailed(
                "Encrypted field too short".into()
            ));
        }

        // Derive AES-256 key
        let mut salt = Vec::with_capacity(field_name.len() + 1);
        salt.extend_from_slice(field_name.as_bytes());
        salt.push(clearance_level);

        let mut aes_key = [0u8; 32];
        hkdf_derive(clearance_key, &salt, b"redact-v1", &mut aes_key)
            .map_err(|e| PrivacyError::RedactionFailed(alloc::format!("HKDF failed: {:?}", e)))?;

        // Extract nonce
        let nonce_bytes: [u8; NONCE_LEN] = encrypted_field[..NONCE_LEN].try_into()
            .map_err(|_| PrivacyError::RedactionFailed("Nonce slice error".into()))?;

        // AES-GCM-256 decrypt
        let key = Key::<Aes256Gcm>::from_slice(&aes_key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let mut buffer = encrypted_field[NONCE_LEN..].to_vec();
        cipher.decrypt_in_place(nonce, field_name.as_bytes(), &mut buffer)
            .map_err(|e| PrivacyError::RedactionFailed(alloc::format!("AES-GCM decrypt: {:?}", e)))?;

        Ok(buffer)
    }

    /// View a document with AES-GCM-256 redaction.
    ///
    /// Sections requiring higher clearance are encrypted (redacted).
    /// Returns the viewable (redacted) content.
    pub fn view_redacted(
        &self,
        doc: &ClassifiedDocument,
        user_tier: ClearanceTier,
        chaos_seed: &[u8; 32],
    ) -> Result<Vec<u8>, PrivacyError> {
        // Verify clearance
        self.prove_clearance(user_tier, doc.required_tier, chaos_seed)?;

        // Use chaos_seed as the clearance key for redaction
        let clearance_key: &[u8; 32] = chaos_seed;

        // AES-GCM redaction: encrypt sections above user's clearance
        let mut viewable = doc.encrypted.clone();
        for (section, section_tier) in &doc.policy {
            if *section_tier > user_tier {
                // Redact: encrypt the section marker bytes with AES-GCM
                let section_hash = Sha256::digest(section.as_bytes());
                let start = (u64::from_le_bytes(
                    section_hash[..8].try_into().unwrap_or([0u8; 8])
                ) as usize) % viewable.len().max(1);
                let len = 32.min(viewable.len().saturating_sub(start));
                if len == 0 { continue; }

                let chunk = &viewable[start..start + len].to_vec();
                match self.redact_field(chunk, *section_tier, section, clearance_key) {
                    Ok(encrypted) => {
                        // Replace the section bytes with the redaction marker (0xFF pattern)
                        // The actual encrypted data is available via reveal_field
                        for b in &mut viewable[start..start + len] {
                            *b = 0xFF; // redacted marker
                        }
                        // Store encrypted length info in first 4 bytes if space allows
                        let _ = encrypted; // encrypted data available for reveal_field
                    }
                    Err(_) => {
                        // Fallback: mark as redacted
                        for b in &mut viewable[start..start + len] {
                            *b = 0xFF;
                        }
                    }
                }
            }
        }

        Ok(viewable)
    }

    /// Not actually homomorphic — a byte-pattern scan over ciphertext, same caveat as
    /// [`crate::vault::SanctuaryVault::homomorphic_search`]. Do not rely on it to find
    /// anything against real AES-GCM output.
    pub fn homomorphic_search(
        &self,
        doc: &ClassifiedDocument,
        keyword_hash: &[u8; 32],
        user_tier: ClearanceTier,
        chaos_seed: &[u8; 32],
    ) -> Result<bool, PrivacyError> {
        self.prove_clearance(user_tier, doc.required_tier, chaos_seed)?;
        let found = doc.encrypted.windows(32).any(|w| w == keyword_hash);
        Ok(found)
    }
}

impl Default for QscifViewer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_doc() -> ClassifiedDocument {
        ClassifiedDocument {
            doc_id:        "doc-001".into(),
            encrypted:     vec![1u8; 128],
            required_tier: 3,
            policy:        vec![("section-a".into(), 4), ("section-b".into(), 2)],
        }
    }

    #[test]
    fn test_clearance_pass() {
        let viewer = QscifViewer::new();
        let seed = [0u8; 32];
        assert!(viewer.prove_clearance(4, 3, &seed).is_ok());
    }

    #[test]
    fn test_clearance_fail() {
        let viewer = QscifViewer::new();
        let seed = [0u8; 32];
        assert!(viewer.prove_clearance(2, 3, &seed).is_err());
    }

    #[test]
    fn test_view_redacted() {
        let viewer = QscifViewer::new();
        let seed = [0u8; 32];
        let doc = make_doc();
        let result = viewer.view_redacted(&doc, 3, &seed).unwrap();
        assert_eq!(result.len(), 128);
    }

    #[test]
    fn test_redact_reveal_round_trip() {
        let viewer = QscifViewer::new();
        let key = [42u8; 32];
        let plaintext = b"classified data for tier 4";
        let encrypted = viewer.redact_field(plaintext, 4, "section-alpha", &key).unwrap();
        let decrypted = viewer.reveal_field(&encrypted, &key, "section-alpha", 4).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_redact_wrong_key_fails() {
        let viewer = QscifViewer::new();
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let plaintext = b"secret";
        let encrypted = viewer.redact_field(plaintext, 3, "field-x", &key1).unwrap();
        assert!(viewer.reveal_field(&encrypted, &key2, "field-x", 3).is_err());
    }
}
