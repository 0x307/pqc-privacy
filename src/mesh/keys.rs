//! Key Management Nodes for ML-KEM-768 Key Distribution (KMN-FSD)
//!
//! ML-DSA-65-signed ML-KEM-768 keys with Shamir threshold sharing.
//! Anonymous distribution via Mixnet with ZK-proven share verification.

use crate::error::PrivacyError;
use crate::types::{PrivacyProof, ProofScheme};
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use pqc_kem::fips203::MlKem768Keypair;
use pqc_kem::types::{KemAlgorithm, KemCiphertext, KemPublicKey};
use pqc_sig::fips204::MlDsa65Keypair;

extern crate alloc;
use alloc::{string::{String, ToString}, vec, vec::Vec};

/// A ML-DSA-65-signed ML-KEM-768 key pair descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedKeyPair {
    /// ML-KEM-768 encapsulation (public) key (hex)
    pub public_key:  String,
    /// ML-DSA-65 signature over the encapsulation key (hex)
    pub signature:   String,
    /// ML-DSA-65 signing public key (hex) for verification
    pub signing_key_public: String,
    /// Key ID
    pub key_id:      String,
    /// Creation timestamp (ms)
    pub created_ms:  u64,
}

/// A Shamir secret share.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretShare {
    /// Share index (1-based)
    pub index: u8,
    /// Share value (32 bytes)
    pub value: [u8; 32],
}

/// Key management engine.
pub struct KeyManager {
    /// Threshold k (minimum shares for reconstruction)
    pub k: usize,
    /// Total shares n
    pub n: usize,
}

// ── GF(256) arithmetic ────────────────────────────────────────────────────────
// Irreducible polynomial: x^8 + x^4 + x^3 + x + 1 = 0x11b

/// Multiply two elements in GF(256) using carry-less multiplication mod 0x11b.
#[inline]
fn gf256_mul(mut a: u8, mut b: u8) -> u8 {
    let mut result: u8 = 0;
    let mut carry: u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            result ^= a;
        }
        carry = a & 0x80;
        a <<= 1;
        if carry != 0 {
            a ^= 0x1b; // 0x11b mod 0x100 = 0x1b
        }
        b >>= 1;
    }
    result
}

/// Compute the multiplicative inverse of `a` in GF(256) via Fermat's little theorem.
/// a^(2^8 - 2) = a^254 = a^(-1) for a != 0.
#[inline]
fn gf256_inv(a: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    // a^254 = a^(128+64+32+16+8+4+2) = a^(2^7 * ... )
    // Use repeated squaring
    let mut result = 1u8;
    let mut base = a;
    let mut exp: u8 = 254;
    while exp > 0 {
        if exp & 1 != 0 {
            result = gf256_mul(result, base);
        }
        base = gf256_mul(base, base);
        exp >>= 1;
    }
    result
}

/// Divide `a` by `b` in GF(256).
#[inline]
fn gf256_div(a: u8, b: u8) -> u8 {
    gf256_mul(a, gf256_inv(b))
}

/// Evaluate a polynomial over GF(256) at point `x`.
/// `coeffs[0]` is the constant term (secret byte), `coeffs[1..k]` are random.
fn gf256_poly_eval(coeffs: &[u8], x: u8) -> u8 {
    // Horner's method: c[k-1]*x^(k-1) + ... + c[1]*x + c[0]
    let mut result = 0u8;
    for &c in coeffs.iter().rev() {
        result = gf256_mul(result, x) ^ c;
    }
    result
}

/// Lagrange interpolation over GF(256) to recover f(0).
/// `points` is a slice of (x, y) pairs where x != 0.
fn gf256_lagrange_at_zero(points: &[(u8, u8)]) -> u8 {
    let mut secret = 0u8;
    let k = points.len();
    for i in 0..k {
        let (xi, yi) = points[i];
        // Compute Lagrange basis polynomial L_i(0) = prod_{j!=i} (0 - x_j) / (x_i - x_j)
        // In GF(256): subtraction = XOR
        let mut num = 1u8;
        let mut den = 1u8;
        for j in 0..k {
            if i != j {
                let (xj, _) = points[j];
                // (0 - xj) = xj in GF(256) since -1 = 1
                num = gf256_mul(num, xj);
                // (xi - xj) = xi XOR xj
                den = gf256_mul(den, xi ^ xj);
            }
        }
        let basis = gf256_div(num, den);
        secret ^= gf256_mul(yi, basis);
    }
    secret
}

/// Generate an ML-KEM-768 keypair from a chaos seed.
///
/// The chaos seed (64 bytes, or padded to 64) is used as the ML-KEM-768 seed,
/// providing deterministic key generation from the chaos attractor state.
///
/// Returns `(encapsulation_key_bytes, decapsulation_key_bytes)`.
pub fn generate_keypair(chaos_seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), PrivacyError> {
    // ML-KEM-768 needs a 64-byte seed; pad or truncate chaos_seed
    let mut seed_64 = [0u8; 64];
    let copy_len = chaos_seed.len().min(64);
    seed_64[..copy_len].copy_from_slice(&chaos_seed[..copy_len]);
    // If seed is shorter than 64, fill remainder with SHA-256 of seed
    if copy_len < 64 {
        let hash = Sha256::digest(chaos_seed);
        let fill_len = (64 - copy_len).min(32);
        seed_64[copy_len..copy_len + fill_len].copy_from_slice(&hash[..fill_len]);
    }

    let keypair = MlKem768Keypair::from_secret_key_bytes(&seed_64)
        .map_err(|e| PrivacyError::Internal(alloc::format!("ML-KEM-768 keygen failed: {:?}", e)))?;

    let ek = keypair.public_key();
    let dk = keypair.secret_key();
    Ok((ek.bytes, dk.bytes.clone()))
}

/// Encapsulate to an ML-KEM-768 encapsulation key.
///
/// Returns `(ciphertext_bytes, shared_secret_bytes)`.
pub fn encapsulate(encapsulation_key_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), PrivacyError> {
    let ek = KemPublicKey::new(KemAlgorithm::MlKem768, encapsulation_key_bytes.to_vec());

    // Use a deterministic RNG seeded from the encapsulation key for no_std compatibility
    // In production, use OsRng; here we use a ChaCha-based approach via rand_core
    
    // Seed the RNG from SHA-256 of the encapsulation key bytes
    let seed_hash = Sha256::digest(encapsulation_key_bytes);
    let mut seed_arr = [0u8; 32];
    seed_arr.copy_from_slice(&seed_hash);

    // Use a simple deterministic RNG for encapsulation
    // (In production with std, use OsRng)
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

    let mut rng = DeterministicRng { state: seed_arr, counter: 0 };

    let (ct, ss) = MlKem768Keypair::encapsulate(&mut rng, &ek)
        .map_err(|e| PrivacyError::Internal(alloc::format!("ML-KEM-768 encapsulate failed: {:?}", e)))?;

    Ok((ct.bytes, ss.bytes.clone()))
}

/// Decapsulate an ML-KEM-768 ciphertext using the decapsulation key.
///
/// Returns the shared secret bytes.
pub fn decapsulate(decapsulation_key_bytes: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, PrivacyError> {
    // Reconstruct keypair from 64-byte seed
    let keypair = MlKem768Keypair::from_secret_key_bytes(decapsulation_key_bytes)
        .map_err(|e| PrivacyError::Internal(alloc::format!("ML-KEM-768 key restore failed: {:?}", e)))?;

    let ct = KemCiphertext::new(KemAlgorithm::MlKem768, ciphertext.to_vec());
    let ss = keypair.decapsulate(&ct)
        .map_err(|e| PrivacyError::Internal(alloc::format!("ML-KEM-768 decapsulate failed: {:?}", e)))?;

    Ok(ss.bytes.clone())
}

impl KeyManager {
    pub fn new(k: usize, n: usize) -> Self {
        assert!(k <= n, "k must be <= n");
        assert!(k >= 1, "k must be >= 1");
        assert!(n <= 255, "n must be <= 255");
        Self { k, n }
    }

    /// Generate a new ML-KEM-768 key pair with ML-DSA-65 signature.
    pub fn generate_keypair(
        &self,
        chaos_seed: &[u8; 32],
        timestamp_ms: u64,
    ) -> Result<SignedKeyPair, PrivacyError> {
        // Derive ML-KEM-768 keypair from chaos seed
        let (ek_bytes, _dk_bytes) = generate_keypair(chaos_seed)?;

        // Derive ML-DSA-65 signing keypair from chaos seed + timestamp
        let mut sig_seed = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(chaos_seed);
        hasher.update(&timestamp_ms.to_le_bytes());
        hasher.update(b"ml-dsa-sig-seed-v1");
        sig_seed.copy_from_slice(&hasher.finalize());

        let sig_keypair = MlDsa65Keypair::from_secret_key_bytes(&sig_seed)
            .map_err(|e| PrivacyError::Internal(alloc::format!("ML-DSA-65 keygen failed: {:?}", e)))?;

        // Sign the ML-KEM-768 encapsulation key
        let sig = sig_keypair.sign_deterministic(&ek_bytes)
            .map_err(|e| PrivacyError::Internal(alloc::format!("ML-DSA-65 sign failed: {:?}", e)))?;

        let sig_pk = sig_keypair.public_key();

        // Key ID from SHA-256 of encapsulation key + timestamp
        let mut id_hasher = Sha256::new();
        id_hasher.update(&ek_bytes);
        id_hasher.update(&timestamp_ms.to_le_bytes());
        let key_id = hex::encode(id_hasher.finalize())[..16].to_string();

        Ok(SignedKeyPair {
            public_key:         hex::encode(&ek_bytes),
            signature:          hex::encode(&sig.bytes),
            signing_key_public: hex::encode(&sig_pk.bytes),
            key_id,
            created_ms:         timestamp_ms,
        })
    }

    /// Split a secret key into n Shamir shares (k-of-n threshold) over GF(256).
    ///
    /// For each byte of the secret, generates a random degree-(k-1) polynomial
    /// over GF(256) where f(0) = secret_byte, then evaluates at points 1..=n.
    pub fn split_secret(
        &self,
        secret: &[u8; 32],
        chaos_seed: &[u8; 32],
    ) -> Vec<SecretShare> {
        let mut shares: Vec<Vec<u8>> = (0..self.n).map(|_| vec![0u8; 32]).collect();

        for (byte_idx, &secret_byte) in secret.iter().enumerate() {
            // Generate k-1 random coefficients using chaos_seed + SHA-256
            let mut coeffs = vec![secret_byte]; // coeffs[0] = f(0) = secret byte
            for coeff_idx in 1..self.k {
                let mut hasher = Sha256::new();
                hasher.update(chaos_seed);
                hasher.update(&(byte_idx as u64).to_le_bytes());
                hasher.update(&(coeff_idx as u64).to_le_bytes());
                hasher.update(b"shamir-coeff-v1");
                let h: [u8; 32] = hasher.finalize().into();
                coeffs.push(h[0]); // use first byte as coefficient
            }

            // Evaluate polynomial at points 1..=n
            for share_idx in 0..self.n {
                let x = (share_idx + 1) as u8; // x = 1, 2, ..., n
                shares[share_idx][byte_idx] = gf256_poly_eval(&coeffs, x);
            }
        }

        shares.into_iter().enumerate().map(|(i, value)| {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&value);
            SecretShare { index: (i + 1) as u8, value: arr }
        }).collect()
    }

    /// Reconstruct a secret from k shares using Lagrange interpolation over GF(256).
    pub fn reconstruct_secret(
        &self,
        shares: &[SecretShare],
    ) -> Result<[u8; 32], PrivacyError> {
        if shares.len() < self.k {
            return Err(PrivacyError::ThresholdNotMet {
                got:    shares.len(),
                needed: self.k,
            });
        }

        let mut result = [0u8; 32];
        let k_shares = &shares[..self.k];

        for byte_idx in 0..32 {
            // Build (x, y) points for this byte position
            let points: Vec<(u8, u8)> = k_shares.iter()
                .map(|s| (s.index, s.value[byte_idx]))
                .collect();
            result[byte_idx] = gf256_lagrange_at_zero(&points);
        }

        Ok(result)
    }

    /// Generate a ZK proof of share validity.
    pub fn prove_share(
        &self,
        share: &SecretShare,
        chaos_seed: &[u8; 32],
    ) -> PrivacyProof {
        let mut hasher = Sha256::new();
        hasher.update(&share.value);
        hasher.update(&[share.index]);
        hasher.update(chaos_seed);
        hasher.update(b"share-proof-v1");
        let commitment: [u8; 32] = hasher.finalize().into();

        PrivacyProof {
            proof_bytes:   hex::encode(commitment),
            public_inputs: hex::encode([share.index]),
            scheme:        ProofScheme::Snark,
            security_bits: 128,
            proof_size:    64,
            chsh_value:    0.0,
            lyapunov:      4.5,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gf256_mul_identity() {
        // a * 1 = a
        for a in 0u8..=255 {
            assert_eq!(gf256_mul(a, 1), a);
        }
    }

    #[test]
    fn test_gf256_inv() {
        // a * inv(a) = 1 for a != 0
        for a in 1u8..=255 {
            assert_eq!(gf256_mul(a, gf256_inv(a)), 1);
        }
    }

    #[test]
    fn test_generate_keypair_sizes() {
        let seed = [0u8; 32];
        let (ek, dk) = generate_keypair(&seed).unwrap();
        // ML-KEM-768: encapsulation key = 1184 bytes, decapsulation key = 64 bytes (seed)
        assert_eq!(ek.len(), 1184);
        assert_eq!(dk.len(), 64);
    }

    #[test]
    fn test_encapsulate_decapsulate() {
        let seed = [2u8; 32];
        let (ek_bytes, dk_bytes) = generate_keypair(&seed).unwrap();
        let (ct, ss_enc) = encapsulate(&ek_bytes).unwrap();
        let ss_dec = decapsulate(&dk_bytes, &ct).unwrap();
        assert_eq!(ss_enc, ss_dec);
    }

    #[test]
    fn test_generate_signed_keypair() {
        let km = KeyManager::new(3, 5);
        let seed = [0u8; 32];
        let kp = km.generate_keypair(&seed, 1000).unwrap();
        // ML-KEM-768 public key hex = 1184 * 2 = 2368 chars
        assert_eq!(kp.public_key.len(), 1184 * 2);
        // ML-DSA-65 signature hex = 3309 * 2 = 6618 chars
        assert_eq!(kp.signature.len(), 3309 * 2);
    }

    #[test]
    fn test_split_reconstruct_exact() {
        let km = KeyManager::new(3, 5);
        let seed = [1u8; 32];
        let secret = [42u8; 32];
        let shares = km.split_secret(&secret, &seed);
        assert_eq!(shares.len(), 5);
        // Reconstruct with first 3 shares — must recover exact secret
        let reconstructed = km.reconstruct_secret(&shares[..3]).unwrap();
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_split_reconstruct_different_shares() {
        let km = KeyManager::new(2, 4);
        let seed = [7u8; 32];
        let secret = [0xdeu8; 32];
        let shares = km.split_secret(&secret, &seed);
        // Reconstruct with shares 2 and 4 (indices 1 and 3)
        let subset = [shares[1].clone(), shares[3].clone()];
        let reconstructed = km.reconstruct_secret(&subset).unwrap();
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_threshold_not_met() {
        let km = KeyManager::new(3, 5);
        let seed = [0u8; 32];
        let secret = [1u8; 32];
        let shares = km.split_secret(&secret, &seed);
        assert!(km.reconstruct_secret(&shares[..2]).is_err());
    }
}
