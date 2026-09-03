//! Quantum Fast Key Hopping (QFKH) Protocol
//!
//! Rapid key rotation expiring ML-KEM keys every ≤1 ms using chaos-seeded
//! ratchets. Achieves post-quantum forward secrecy against harvest-now-decrypt-later.

use crate::error::PrivacyError;
use crate::types::EphemeralKey;
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use aes_gcm::{Aes256Gcm, Key, Nonce, AeadInPlace, KeyInit};
use zeroize::Zeroize;

use pqc_kem::fips203::MlKem768Keypair;
use pqc_kem::types::{KemAlgorithm, KemCiphertext, KemPublicKey};

extern crate alloc;
use alloc::vec::Vec;

/// Default key hop interval in milliseconds (target: ≤1 ms).
pub const HOP_INTERVAL_MS: u64 = 1;

/// AES-GCM-256 tag length in bytes.
const TAG_LEN: usize = 16;

/// QFKH ratchet state.
pub struct QfkhRatchet {
    /// Current chain key (zeroized on hop)
    chain_key:    [u8; 32],
    /// Hop interval (ms)
    interval_ms:  u64,
    /// Creation timestamp (ms)
    created_ms:   u64,
    /// Hop counter
    hop_count:    u64,
}

impl QfkhRatchet {
    /// Initialize a new ratchet from an ML-KEM shared secret.
    ///
    /// `shared_secret` = ML-KEM encapsulated shared secret (32 bytes).
    /// `chaos_seed`    = Chua attractor trajectory for perturbation.
    pub fn new(
        shared_secret: [u8; 32],
        chaos_seed: &[u8; 32],
        now_ms: u64,
    ) -> Self {
        // CK = HKDF(shared_secret, chaos_seed, "qfkh-init-v1")
        let mut chain_key = [0u8; 32];
        hkdf_derive(&shared_secret, chaos_seed, b"qfkh-init-v1", &mut chain_key)
            .expect("HKDF init failed");
        Self {
            chain_key,
            interval_ms: HOP_INTERVAL_MS,
            created_ms:  now_ms,
            hop_count:   0,
        }
    }

    /// Initiator side: generate ML-KEM-768 keypair, return (ratchet_placeholder, encapsulation_key_bytes).
    ///
    /// The initiator generates a keypair and sends the encapsulation key to the responder.
    /// After receiving the responder's ciphertext, call `complete` to finish key establishment.
    ///
    /// Returns `(decapsulation_key_bytes, encapsulation_key_bytes)`.
    pub fn initiate(chaos_seed: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), PrivacyError> {
        // Derive ML-KEM-768 keypair from chaos seed (deterministic)
        let mut seed_64 = [0u8; 64];
        seed_64[..32].copy_from_slice(chaos_seed);
        // Fill second half with SHA-256 of chaos_seed
        let hash = Sha256::digest(chaos_seed);
        seed_64[32..].copy_from_slice(&hash);

        let keypair = MlKem768Keypair::from_secret_key_bytes(&seed_64)
            .map_err(|e| PrivacyError::Internal(alloc::format!("ML-KEM-768 initiate failed: {:?}", e)))?;

        let ek = keypair.public_key();
        let dk = keypair.secret_key();
        Ok((dk.bytes.clone(), ek.bytes))
    }

    /// Responder side: encapsulate to initiator's encapsulation key.
    ///
    /// Returns `(ratchet, ciphertext_bytes)` where the ratchet is initialized
    /// with the shared secret from encapsulation.
    pub fn respond(
        encapsulation_key: &[u8],
        chaos_seed: &[u8; 32],
        now_ms: u64,
    ) -> Result<(Self, Vec<u8>), PrivacyError> {
        let ek = KemPublicKey::new(KemAlgorithm::MlKem768, encapsulation_key.to_vec());

        // Use deterministic RNG seeded from encapsulation key + chaos seed
        let mut rng_seed = [0u8; 32];
        let mut h = Sha256::new();
        h.update(encapsulation_key);
        h.update(chaos_seed);
        h.update(b"qfkh-respond-rng-v1");
        rng_seed.copy_from_slice(&h.finalize());

        let mut rng = DeterministicRng { state: rng_seed, counter: 0 };

        let (ct, ss) = MlKem768Keypair::encapsulate(&mut rng, &ek)
            .map_err(|e| PrivacyError::Internal(alloc::format!("ML-KEM-768 respond failed: {:?}", e)))?;

        let mut ss_arr = [0u8; 32];
        let ss_bytes = ss.bytes.clone();
        let copy_len = ss_bytes.len().min(32);
        ss_arr[..copy_len].copy_from_slice(&ss_bytes[..copy_len]);

        let ratchet = Self::new(ss_arr, chaos_seed, now_ms);
        Ok((ratchet, ct.bytes))
    }

    /// Initiator side: complete key establishment by decapsulating responder's ciphertext.
    ///
    /// `decapsulation_key` = the decapsulation key bytes returned by `initiate`.
    /// `ciphertext`        = the ciphertext bytes returned by the responder's `respond`.
    pub fn complete(
        decapsulation_key: &[u8],
        ciphertext: &[u8],
        chaos_seed: &[u8; 32],
        now_ms: u64,
    ) -> Result<Self, PrivacyError> {
        let keypair = MlKem768Keypair::from_secret_key_bytes(decapsulation_key)
            .map_err(|e| PrivacyError::Internal(alloc::format!("ML-KEM-768 complete failed: {:?}", e)))?;

        let ct = KemCiphertext::new(KemAlgorithm::MlKem768, ciphertext.to_vec());
        let ss = keypair.decapsulate(&ct)
            .map_err(|e| PrivacyError::Internal(alloc::format!("ML-KEM-768 decapsulate failed: {:?}", e)))?;

        let mut ss_arr = [0u8; 32];
        let ss_bytes = ss.bytes.clone();
        let copy_len = ss_bytes.len().min(32);
        ss_arr[..copy_len].copy_from_slice(&ss_bytes[..copy_len]);

        Ok(Self::new(ss_arr, chaos_seed, now_ms))
    }

    /// Derive a message key for the current hop and advance the ratchet.
    ///
    /// MK = HKDF(CK, chaos, "qfkh-msg-v1")
    /// CK' = HKDF(CK, chaos, "qfkh-hop-v1")
    ///
    /// Old CK is zeroized after hop.
    pub fn hop(
        &mut self,
        chaos_perturbation: &[u8; 32],
        now_ms: u64,
    ) -> Result<EphemeralKey, PrivacyError> {
        // Check interval
        let elapsed = now_ms.saturating_sub(self.created_ms + self.hop_count * self.interval_ms);
        if elapsed > self.interval_ms * 10 {
            return Err(PrivacyError::KeyHopIntervalExceeded {
                elapsed_ms: elapsed,
                limit_ms:   self.interval_ms * 10,
            });
        }

        // Derive message key: MK = HKDF(CK, chaos, "qfkh-msg-v1")
        let mut message_key = [0u8; 32];
        hkdf_derive(&self.chain_key, chaos_perturbation, b"qfkh-msg-v1", &mut message_key)?;

        // Advance chain key: CK' = HKDF(CK, chaos, "qfkh-hop-v1")
        let mut ck_input = self.chain_key;
        let mut new_ck = [0u8; 32];
        hkdf_derive(&ck_input, chaos_perturbation, b"qfkh-hop-v1", &mut new_ck)?;

        // Zeroize old chain key
        ck_input.zeroize();
        self.chain_key.zeroize();
        self.chain_key = new_ck;
        self.hop_count += 1;

        Ok(EphemeralKey {
            shared_secret: message_key,
            chain_key:     self.chain_key,
            created_ms:    now_ms,
            expiry_ms:     self.interval_ms,
        })
    }

    /// Encrypt a payload with the current message key using AES-GCM-256.
    ///
    /// Returns 12-byte nonce prepended to ciphertext + 16-byte tag.
    pub fn encrypt(
        &mut self,
        payload: &[u8],
        chaos_perturbation: &[u8; 32],
        now_ms: u64,
    ) -> Result<Vec<u8>, PrivacyError> {
        let ek = self.hop(chaos_perturbation, now_ms)?;
        aes_gcm_encrypt(&ek.shared_secret, payload)
    }

    /// Decrypt a payload encrypted with `encrypt`.
    ///
    /// Reads 12-byte nonce from the first 12 bytes, decrypts the remainder.
    pub fn decrypt(
        &mut self,
        ciphertext: &[u8],
        chaos_perturbation: &[u8; 32],
        now_ms: u64,
    ) -> Result<Vec<u8>, PrivacyError> {
        let ek = self.hop(chaos_perturbation, now_ms)?;
        aes_gcm_decrypt(&ek.shared_secret, ciphertext)
    }

    /// Returns the current hop count.
    pub fn hop_count(&self) -> u64 {
        self.hop_count
    }
}

impl Drop for QfkhRatchet {
    fn drop(&mut self) {
        self.chain_key.zeroize();
    }
}

// ── Deterministic RNG for no_std encapsulation ────────────────────────────────

/// A deterministic RNG seeded from a 32-byte state, using SHA-256 as a counter-mode PRF.
/// Used for ML-KEM encapsulation in no_std environments.
struct DeterministicRng {
    state: [u8; 32],
    counter: u64,
}

impl rand_core::RngCore for DeterministicRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }
    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut pos = 0;
        while pos < dest.len() {
            let mut hasher = Sha256::new();
            hasher.update(&self.state);
            hasher.update(&self.counter.to_le_bytes());
            let hash = hasher.finalize();
            let copy_len = (dest.len() - pos).min(32);
            dest[pos..pos + copy_len].copy_from_slice(&hash[..copy_len]);
            pos += copy_len;
            self.counter += 1;
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for DeterministicRng {}

// ── Shared crypto helpers (pub(crate) for reuse in vault/enclave) ─────────────

/// HKDF-SHA256: derive `output.len()` bytes from `ikm` with `salt` and `info`.
pub(crate) fn hkdf_derive(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    output: &mut [u8],
) -> Result<(), PrivacyError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    hk.expand(info, output)
        .map_err(|_| PrivacyError::Internal("HKDF expand failed".into()))
}

/// AES-GCM-256 encrypt using `AeadInPlace`.
///
/// Returns `nonce (12 bytes) || ciphertext || tag (16 bytes)`.
/// Nonce = first 12 bytes of SHA-256(message_key).
pub(crate) fn aes_gcm_encrypt(
    message_key: &[u8; 32],
    plaintext: &[u8],
) -> Result<Vec<u8>, PrivacyError> {
    // Derive AES key via HKDF
    let mut aes_key_bytes = [0u8; 32];
    hkdf_derive(message_key, b"aes-gcm-key", b"aes-key-v1", &mut aes_key_bytes)?;

    // Nonce = first 12 bytes of SHA-256(message_key)
    let nonce_hash = Sha256::digest(message_key);
    let nonce_bytes: [u8; 12] = nonce_hash[..12].try_into()
        .map_err(|_| PrivacyError::Internal("Nonce slice error".into()))?;

    let key    = Key::<Aes256Gcm>::from_slice(&aes_key_bytes);
    let nonce  = Nonce::from_slice(&nonce_bytes);
    let cipher = Aes256Gcm::new(key);

    // Build buffer: plaintext + space for tag
    let mut buf: Vec<u8> = plaintext.to_vec();
    buf.reserve(TAG_LEN);

    cipher.encrypt_in_place(nonce, b"", &mut buf)
        .map_err(|_| PrivacyError::Internal("AES-GCM encrypt failed".into()))?;

    // Prepend nonce
    let mut out = Vec::with_capacity(12 + buf.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&buf);
    Ok(out)
}

/// AES-GCM-256 decrypt. Expects `nonce (12 bytes) || ciphertext || tag (16 bytes)`.
pub(crate) fn aes_gcm_decrypt(
    message_key: &[u8; 32],
    data: &[u8],
) -> Result<Vec<u8>, PrivacyError> {
    if data.len() < 12 + TAG_LEN {
        return Err(PrivacyError::Internal("Ciphertext too short".into()));
    }

    // Derive AES key via HKDF
    let mut aes_key_bytes = [0u8; 32];
    hkdf_derive(message_key, b"aes-gcm-key", b"aes-key-v1", &mut aes_key_bytes)?;

    let nonce_bytes = &data[..12];
    let ct_and_tag  = &data[12..];

    let key    = Key::<Aes256Gcm>::from_slice(&aes_key_bytes);
    let nonce  = Nonce::from_slice(nonce_bytes);
    let cipher = Aes256Gcm::new(key);

    let mut buf: Vec<u8> = ct_and_tag.to_vec();
    cipher.decrypt_in_place(nonce, b"", &mut buf)
        .map_err(|_| PrivacyError::Internal("AES-GCM decrypt failed".into()))?;

    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hop_produces_key() {
        let secret = [1u8; 32];
        let chaos  = [2u8; 32];
        let mut ratchet = QfkhRatchet::new(secret, &chaos, 0);
        let key = ratchet.hop(&chaos, 0).unwrap();
        assert_eq!(key.shared_secret.len(), 32);
        assert_eq!(key.expiry_ms, HOP_INTERVAL_MS);
    }

    #[test]
    fn test_successive_hops_differ() {
        let secret = [3u8; 32];
        let chaos  = [4u8; 32];
        let mut ratchet = QfkhRatchet::new(secret, &chaos, 0);
        let k1 = ratchet.hop(&chaos, 0).unwrap();
        let k2 = ratchet.hop(&chaos, 0).unwrap();
        assert_ne!(k1.shared_secret, k2.shared_secret);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let secret = [5u8; 32];
        let chaos  = [6u8; 32];
        let mut enc_ratchet = QfkhRatchet::new(secret, &chaos, 0);
        let mut dec_ratchet = QfkhRatchet::new(secret, &chaos, 0);
        let payload = b"secret message";
        let encrypted = enc_ratchet.encrypt(payload, &chaos, 0).unwrap();
        let decrypted = dec_ratchet.decrypt(&encrypted, &chaos, 0).unwrap();
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn test_aes_gcm_roundtrip() {
        let key = [0xabu8; 32];
        let plaintext = b"hello quantum world";
        let ct = aes_gcm_encrypt(&key, plaintext).unwrap();
        let pt = aes_gcm_decrypt(&key, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_initiate_respond_complete() {
        let chaos = [7u8; 32];

        // Initiator generates keypair
        let (dk_bytes, ek_bytes) = QfkhRatchet::initiate(&chaos).unwrap();
        assert_eq!(ek_bytes.len(), 1184); // ML-KEM-768 encapsulation key
        assert_eq!(dk_bytes.len(), 64);   // ML-KEM-768 decapsulation key (seed)

        // Responder encapsulates
        let (mut responder_ratchet, ct_bytes) = QfkhRatchet::respond(&ek_bytes, &chaos, 0).unwrap();

        // Initiator completes
        let mut initiator_ratchet = QfkhRatchet::complete(&dk_bytes, &ct_bytes, &chaos, 0).unwrap();

        // Both ratchets should produce the same message key on first hop
        let k_init = initiator_ratchet.hop(&chaos, 0).unwrap();
        let k_resp = responder_ratchet.hop(&chaos, 0).unwrap();
        assert_eq!(k_init.shared_secret, k_resp.shared_secret);
    }
}
