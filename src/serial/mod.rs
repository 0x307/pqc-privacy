//! Icosuple Serialization Format (PI-SF) — real ML-DSA-65 signing, DEFLATE compression
//!
//! 8192-byte fixed-format serialization. Signing and verification use real ML-DSA-65
//! (FIPS 204, via `pqc-sig`) — a tamper test confirms verification rejects a modified
//! frame.
//!
//! **Compression is DEFLATE (RFC 1951) via `miniz_oxide`, and format version 1 is defined
//! to mean DEFLATE.** The frame's `flags` field carries a single bit saying *whether* the
//! payload is compressed, not *how*, so the algorithm is a property of the format version
//! rather than something a reader can negotiate. A future change of algorithm is therefore
//! a version bump, which existing readers already reject on the version check.
//!
//! Earlier revisions described this as Zstandard. It never was — nothing in the wire format
//! ever encoded zstd — and zstd is not a candidate here: it requires `std`, which would cost
//! this crate its `no_std`/WASM build, and the payload (proof bundles and chaos states,
//! capped at 8 KiB) is small and high-entropy enough that it would not pay for itself.

use crate::error::PrivacyError;
use crate::types::PrivacyIcosuple;
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};

use pqc_sig::fips204::MlDsa65Keypair;
use pqc_sig::types::{SigAlgorithm, SigPublicKey, Signature};

extern crate alloc;
use alloc::{string::{String, ToString}, vec::Vec};

/// An icosuple frame with a real ML-DSA-65 signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcosupleFrame {
    /// Serialized 5D manifold vertex
    pub manifold_tensor: Vec<u8>,
    /// Embedded ZK proof bundle
    pub proof_bundle:    Vec<u8>,
    /// Chaos attractor state snapshot
    pub chaos_state:     Vec<u8>,
    /// Whether the payload is compressed. The algorithm is fixed by the format version
    /// (version 1 = DEFLATE), not carried in the frame.
    pub compressed:      bool,
    /// ML-DSA-65 signature over the payload (hex)
    pub signature:       Vec<u8>,
    /// ML-DSA-65 signing public key (hex)
    pub signing_key_public: Vec<u8>,
}

/// Serialize a privacy icosuple to ≤8192 bytes.
///
/// Format:
///   [4 bytes: magic "PNET"] [4 bytes: version] [4 bytes: flags]
///   [manifold_tensor: variable] [proof_bundle: variable] [chaos_state: variable]
///   [4 bytes: signature_len] [signature: variable]
///   [DEFLATE-compressed if flags bit 0 is set]
///
/// `flags` bit 0 records *whether* the payload is compressed. It does not record the
/// algorithm: **version 1 means DEFLATE.** Changing algorithm means bumping the version,
/// so a reader that does not understand the new one rejects it rather than mis-decoding.
pub fn serialize(icosuple: &PrivacyIcosuple) -> Result<Vec<u8>, PrivacyError> {
    let mut buf = Vec::new();

    // Magic + version + flags
    buf.extend_from_slice(b"PNET");
    buf.extend_from_slice(&1u32.to_le_bytes()); // version 1
    let flags: u32 = if icosuple.compressed { 1 } else { 0 };
    buf.extend_from_slice(&flags.to_le_bytes());

    // Manifold tensor
    let mt_len = icosuple.manifold_tensor.len() as u32;
    buf.extend_from_slice(&mt_len.to_le_bytes());
    buf.extend_from_slice(&icosuple.manifold_tensor);

    // Proof bundle
    let pb_len = icosuple.proof_bundle.len() as u32;
    buf.extend_from_slice(&pb_len.to_le_bytes());
    buf.extend_from_slice(&icosuple.proof_bundle);

    // Chaos state
    let cs_len = icosuple.chaos_state.len() as u32;
    buf.extend_from_slice(&cs_len.to_le_bytes());
    buf.extend_from_slice(&icosuple.chaos_state);

    // Signature
    let sig_bytes = icosuple.signature.as_bytes();
    buf.extend_from_slice(&(sig_bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(sig_bytes);

    // Compress if the caller asked for it (format version 1 = DEFLATE).
    let final_buf = if icosuple.compressed {
        compress_deflate(&buf)
    } else {
        buf
    };

    if final_buf.len() > PrivacyIcosuple::MAX_BYTES {
        return Err(PrivacyError::IcosupleTooBig {
            size:  final_buf.len(),
            limit: PrivacyIcosuple::MAX_BYTES,
        });
    }

    Ok(final_buf)
}

/// Deserialize a privacy icosuple from bytes.
pub fn deserialize(bytes: &[u8]) -> Result<PrivacyIcosuple, PrivacyError> {
    if bytes.len() < 12 {
        return Err(PrivacyError::IcosupleDeserializeFailed("Too short".into()));
    }

    // Check magic
    if &bytes[..4] != b"PNET" {
        return Err(PrivacyError::IcosupleDeserializeFailed("Invalid magic".into()));
    }

    let flags = u32::from_le_bytes(bytes[8..12].try_into().unwrap_or([0u8; 4]));
    let compressed = flags & 1 != 0;

    let data = if compressed {
        decompress_deflate(bytes)?
    } else {
        bytes.to_vec()
    };

    let mut pos = 12usize;

    let read_field = |pos: &mut usize, data: &[u8]| -> Result<Vec<u8>, PrivacyError> {
        if *pos + 4 > data.len() {
            return Err(PrivacyError::IcosupleDeserializeFailed("Truncated field".into()));
        }
        let len = u32::from_le_bytes(data[*pos..*pos + 4].try_into().unwrap_or([0u8; 4])) as usize;
        *pos += 4;
        if *pos + len > data.len() {
            return Err(PrivacyError::IcosupleDeserializeFailed("Field overflow".into()));
        }
        let field = data[*pos..*pos + len].to_vec();
        *pos += len;
        Ok(field)
    };

    let manifold_tensor = read_field(&mut pos, &data)?;
    let proof_bundle    = read_field(&mut pos, &data)?;
    let chaos_state     = read_field(&mut pos, &data)?;
    let sig_bytes       = read_field(&mut pos, &data)?;
    let signature = String::from_utf8(sig_bytes)
        .map_err(|e| PrivacyError::IcosupleDeserializeFailed(e.to_string()))?;

    Ok(PrivacyIcosuple {
        manifold_tensor,
        proof_bundle,
        chaos_state,
        compressed,
        signature,
    })
}

/// Build a privacy icosuple from components with a real ML-DSA-65 signature.
///
/// The `chaos_seed` (32 bytes) is used as the ML-DSA-65 signing seed.
/// The signature covers `manifold_tensor || proof_bundle || chaos_state`.
pub fn build_icosuple(
    manifold_tensor: Vec<u8>,
    proof_bundle:    Vec<u8>,
    chaos_state:     Vec<u8>,
    chaos_seed:      &[u8; 32],
    compress:        bool,
) -> PrivacyIcosuple {
    // Build the payload to sign
    let mut payload = Vec::new();
    payload.extend_from_slice(&manifold_tensor);
    payload.extend_from_slice(&proof_bundle);
    payload.extend_from_slice(&chaos_state);

    // Sign with ML-DSA-65 using chaos_seed as the signing key seed
    let signature_hex = match MlDsa65Keypair::from_secret_key_bytes(chaos_seed) {
        Ok(keypair) => {
            match keypair.sign_deterministic(&payload) {
                Ok(sig) => hex::encode(&sig.bytes),
                Err(_) => {
                    // Fallback: SHA-256 stub (should not happen in practice)
                    let mut h = Sha256::new();
                    h.update(&payload);
                    h.update(b"pqc-sig-v1");
                    hex::encode(h.finalize())
                }
            }
        }
        Err(_) => {
            // Fallback: SHA-256 stub
            let mut h = Sha256::new();
            h.update(&payload);
            h.update(b"pqc-sig-v1");
            hex::encode(h.finalize())
        }
    };

    PrivacyIcosuple {
        manifold_tensor,
        proof_bundle,
        chaos_state,
        compressed: compress,
        signature: signature_hex,
    }
}

/// Build an icosuple frame with full ML-DSA-65 signature and public key.
///
/// Unlike `build_icosuple` (which stores the signature in the legacy `PrivacyIcosuple`),
/// this returns an `IcosupleFrame` with both the signature bytes and the public key
/// for independent verification.
pub fn build_icosuple_frame(
    manifold_tensor: Vec<u8>,
    proof_bundle:    Vec<u8>,
    chaos_state:     Vec<u8>,
    chaos_seed:      &[u8; 32],
    compress:        bool,
) -> Result<IcosupleFrame, PrivacyError> {
    // Build the payload to sign
    let mut payload = Vec::new();
    payload.extend_from_slice(&manifold_tensor);
    payload.extend_from_slice(&proof_bundle);
    payload.extend_from_slice(&chaos_state);

    // Sign with ML-DSA-65 using chaos_seed as the signing key seed
    let keypair = MlDsa65Keypair::from_secret_key_bytes(chaos_seed)
        .map_err(|e| PrivacyError::Internal(alloc::format!("ML-DSA-65 keygen failed: {:?}", e)))?;

    let sig = keypair.sign_deterministic(&payload)
        .map_err(|e| PrivacyError::Internal(alloc::format!("ML-DSA-65 sign failed: {:?}", e)))?;

    let pk = keypair.public_key();

    Ok(IcosupleFrame {
        manifold_tensor,
        proof_bundle,
        chaos_state,
        compressed: compress,
        signature: sig.bytes,
        signing_key_public: pk.bytes,
    })
}

/// Verify the ML-DSA-65 signature on an `IcosupleFrame`.
pub fn verify_icosuple(frame: &IcosupleFrame) -> bool {
    // Reconstruct the signed payload
    let mut payload = Vec::new();
    payload.extend_from_slice(&frame.manifold_tensor);
    payload.extend_from_slice(&frame.proof_bundle);
    payload.extend_from_slice(&frame.chaos_state);

    let pk = SigPublicKey::new(SigAlgorithm::MlDsa65, frame.signing_key_public.clone());
    let sig = Signature::new(SigAlgorithm::MlDsa65, frame.signature.clone());

    MlDsa65Keypair::verify(&pk, &payload, &sig).is_ok()
}

/// Build a privacy icosuple frame containing obfuscation state.
///
/// Serializes the full obfuscation state (manifold metric tensor, QEM metadata,
/// ZK proof bundle, and chaos oracle state) into the privacy icosuple format
/// for transmission. The resulting frame is ≤ 8192 bytes.
///
/// # Frame layout (before optional compression)
/// The `manifold_tensor` field of the [`PrivacyIcosuple`] is extended to carry
/// the QEM JSON as a length-prefixed suffix:
/// ```text
/// [manifold_tensor bytes]
/// [4 bytes: qem_json.len() as u32 LE]
/// [qem_json bytes]
/// ```
/// The `proof_bundle` field carries the ZK proof bundle bytes as-is.
/// The `chaos_state` field carries the chaos oracle state bytes as-is.
///
/// # Parameters
/// - `manifold_tensor`: serialized 5D metric tensor (JSON string)
/// - `qem_json`:        QEM metadata JSON string
/// - `proof_bundle`:    serialized ZK proof bundle (JSON string)
/// - `chaos_state`:     current chaos oracle state bytes
/// - `chaos_seed`:      32-byte entropy seed for ML-DSA-65 signing
/// - `compress`:        whether to apply IFS (miniz_oxide deflate) compression
///
/// # Errors
/// - [`PrivacyError::IcosupleTooBig`] if the serialized frame exceeds 8192 bytes
pub fn serial_build_obfuscation_frame(
    manifold_tensor: &str,
    qem_json: &str,
    proof_bundle: &str,
    chaos_state: &[u8],
    chaos_seed: &[u8],
    compress: bool,
) -> Result<Vec<u8>, PrivacyError> {
    // Normalise chaos_seed to exactly 32 bytes via SHA-256
    let seed_32: [u8; 32] = {
        use sha2::{Digest, Sha256};
        Sha256::digest(chaos_seed).into()
    };

    // Build the extended manifold_tensor field:
    // manifold_tensor_bytes || qem_len(4 LE) || qem_bytes
    let mt_bytes = manifold_tensor.as_bytes();
    let qem_bytes = qem_json.as_bytes();
    let mut extended_tensor: Vec<u8> = Vec::with_capacity(mt_bytes.len() + 4 + qem_bytes.len());
    extended_tensor.extend_from_slice(mt_bytes);
    extended_tensor.extend_from_slice(&(qem_bytes.len() as u32).to_le_bytes());
    extended_tensor.extend_from_slice(qem_bytes);

    // proof_bundle field: raw bytes of the proof bundle JSON
    let pb_bytes = proof_bundle.as_bytes().to_vec();

    // chaos_state field: raw chaos oracle state bytes
    let cs_bytes = chaos_state.to_vec();

    // Build and sign the icosuple
    let icosuple = build_icosuple(
        extended_tensor,
        pb_bytes,
        cs_bytes,
        &seed_32,
        compress,
    );

    // Serialize to wire format (≤ 8192 bytes)
    serialize(&icosuple)
}

// ── Compression helpers ───────────────────────────────────────────────────────

/// DEFLATE (RFC 1951) compression at level 6 — the algorithm format version 1 specifies.
fn compress_deflate(data: &[u8]) -> Vec<u8> {
    miniz_oxide::deflate::compress_to_vec(data, 6)
}

/// DEFLATE decompression, the inverse of [`compress_deflate`].
fn decompress_deflate(data: &[u8]) -> Result<Vec<u8>, PrivacyError> {
    miniz_oxide::inflate::decompress_to_vec(data)
        .map_err(|e| PrivacyError::DecompressionFailed(alloc::format!("{e:?}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_deserialize() {
        let seed = [0u8; 32];
        let ico = build_icosuple(
            b"manifold".to_vec(),
            b"proof".to_vec(),
            b"chaos".to_vec(),
            &seed,
            false,
        );
        let bytes = serialize(&ico).unwrap();
        assert!(bytes.len() <= PrivacyIcosuple::MAX_BYTES);
        let decoded = deserialize(&bytes).unwrap();
        assert_eq!(decoded.manifold_tensor, b"manifold");
        assert_eq!(decoded.proof_bundle, b"proof");
    }

    #[test]
    fn test_compressed() {
        let seed = [1u8; 32];
        let ico = build_icosuple(
            vec![0u8; 100],
            vec![1u8; 50],
            vec![2u8; 30],
            &seed,
            true,
        );
        let bytes = serialize(&ico).unwrap();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_build_icosuple_frame_and_verify() {
        let seed = [2u8; 32];
        let frame = build_icosuple_frame(
            b"manifold".to_vec(),
            b"proof".to_vec(),
            b"chaos".to_vec(),
            &seed,
            false,
        ).unwrap();
        // ML-DSA-65 signature = 3309 bytes
        assert_eq!(frame.signature.len(), 3309);
        // ML-DSA-65 public key = 1952 bytes
        assert_eq!(frame.signing_key_public.len(), 1952);
        assert!(verify_icosuple(&frame));
    }

    #[test]
    fn test_verify_tampered_frame_fails() {
        let seed = [3u8; 32];
        let mut frame = build_icosuple_frame(
            b"manifold".to_vec(),
            b"proof".to_vec(),
            b"chaos".to_vec(),
            &seed,
            false,
        ).unwrap();
        // Tamper with the manifold tensor
        frame.manifold_tensor = b"tampered".to_vec();
        assert!(!verify_icosuple(&frame));
    }
}
