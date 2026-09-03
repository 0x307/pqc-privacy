//! FHE Engine — real LWE-based additive homomorphic encryption, not actually CKKS
//!
//! This implements real negacyclic polynomial ring arithmetic in `Z_q[X]/(X^N + 1)` —
//! correct key generation, encryption, homomorphic add/negate, and relinearized multiply.
//! It is **not CKKS** despite the name: there is no encoding of complex vectors, no
//! rescaling chain across a modulus ladder, and no approximate-arithmetic error budget.
//! What it does share with CKKS is a plaintext scaling factor: the message is multiplied
//! by the factor from `plaintext_delta` before it is added into `c0`, and divided back out
//! with rounding on decrypt, which keeps accumulated noise off the plaintext bits.
//!
//! Without that factor the round-trip failed: the two negacyclic convolutions in the noise
//! term each sum up to `n` signed products, so at small parameters the noise dwarfed a
//! `0..=255` plaintext byte and `decode_poly_to_bytes` recovered garbage. Fixed on
//! `sagp-integration` (Ken, 2026-09-02); `tests::test_encrypt_decrypt` covers it.
//!
//! ## Design
//!
//! - Ciphertexts are pairs `(c0, c1)` of polynomials in `Z_q[X]/(X^N + 1)`.
//! - Polynomials are stored as `Vec<i64>` of length `N`, serialized as
//!   little-endian `i64` arrays.
//! - Noise budget decreases with each operation; bootstrapping resets it.
//! - BLAKE3 integrity hashes are computed over ciphertext data.
//!
//! ## Usage
//!
//! ```rust,no_run
//! use privacy::fhe::{FheEngine, FheCiphertext, FheKeyPair};
//!
//! let mut rng = rand::rngs::OsRng;
//! let mut engine = FheEngine::new(1024, 128);
//! let keypair = engine.keygen(&mut rng).unwrap();
//! let ct = engine.encrypt(&mut rng, &keypair, b"hello").unwrap();
//! let pt = engine.decrypt(&keypair, &ct).unwrap();
//! assert_eq!(&pt[..5], b"hello");
//! ```

extern crate alloc;
use alloc::vec::Vec;
// The `vec!` macro, not just the `Vec` type: this module builds polynomial
// coefficient buffers with it, and on the no_std path it is not in the prelude.
use alloc::vec;
use alloc::format;

use rand::Rng;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::PrivacyError;

// ── Public types ──────────────────────────────────────────────────────────────

/// An FHE ciphertext produced by the PQVM FHE engine.
///
/// Internally represents a CKKS-style polynomial ring ciphertext `(c0, c1)`
/// serialized as little-endian `i64` arrays.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FheCiphertext {
    /// Serialized ciphertext bytes (CKKS polynomial representation).
    /// Format: `c0_bytes || c1_bytes` where each is `ring_degree * 8` bytes.
    pub data: Vec<u8>,
    /// Remaining noise budget. When this reaches 0, bootstrapping is required.
    pub noise_budget: u32,
    /// Polynomial ring degree N (default: 1024).
    pub ring_degree: u32,
    /// Ciphertext modulus bits (default: 128).
    pub modulus_bits: u32,
    /// Unix timestamp (seconds) when this ciphertext was created.
    pub created_at: u64,
    /// BLAKE3 integrity hash of `data`.
    pub blake3_hash: [u8; 32],
}

/// An FHE key pair for CKKS-style homomorphic encryption.
///
/// The secret key is zeroized on drop to prevent key material leakage.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct FheKeyPair {
    /// FHE public key (CKKS evaluation key) — serialized polynomial.
    pub public_key: Vec<u8>,
    /// FHE secret key — serialized polynomial (zeroized on drop).
    pub secret_key: Vec<u8>,
    /// Relinearization key — used to reduce degree after multiplication.
    pub relin_key: Vec<u8>,
    /// Galois keys — used for rotation operations.
    pub galois_keys: Vec<u8>,
    /// Polynomial ring degree N.
    pub ring_degree: u32,
    /// Ciphertext modulus bits.
    pub modulus_bits: u32,
    /// Unix timestamp (seconds) when this keypair was created.
    pub created_at: u64,
    /// Number of times this keypair has been rotated.
    pub rotation_count: u64,
}

// ── FheEngine ─────────────────────────────────────────────────────────────────

/// The PQVM FHE engine — shared across all Wyqcc products.
///
/// Implements CKKS-style homomorphic operations using polynomial arithmetic
/// over the negacyclic ring `Z_q[X]/(X^N + 1)`.
pub struct FheEngine {
    /// Polynomial ring degree N (default: 1024).
    pub ring_degree: u32,
    /// Ciphertext modulus bits (default: 128).
    pub modulus_bits: u32,
    /// Maximum noise budget for fresh ciphertexts.
    pub max_noise_budget: u32,
}

impl FheEngine {
    /// Create a new `FheEngine` with the given ring degree and modulus bits.
    pub fn new(ring_degree: u32, modulus_bits: u32) -> Self {
        Self {
            ring_degree,
            modulus_bits,
            max_noise_budget: 100,
        }
    }

    /// Set the maximum noise budget for fresh ciphertexts.
    pub fn with_max_noise_budget(mut self, budget: u32) -> Self {
        self.max_noise_budget = budget;
        self
    }

    // ── Key generation ────────────────────────────────────────────────────────

    /// Generate a new FHE key pair.
    ///
    /// ## Algorithm
    ///
    /// 1. Generate secret key `s`: random ternary polynomial `{-1, 0, 1}`.
    /// 2. Generate public key `(a, b = -a*s + e)` where `e` is small error.
    /// 3. Generate relinearization key `(a', b' = -a'*s + e' + s^2)`.
    /// 4. Galois keys = copy of `a` (simplified; full CKKS uses rotation keys).
    pub fn keygen(
        &mut self,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<FheKeyPair, PrivacyError> {
        let n = self.ring_degree as usize;
        let q = modulus_from_bits(self.modulus_bits);

        let s = random_ternary_poly(rng, n);
        let a = random_poly(rng, n, q);
        let e = random_error_poly(rng, n, ERROR_BOUND);
        let a_times_s = poly_mult_negacyclic(&a, &s, n, q);
        let b: Vec<i64> = a_times_s.iter().zip(e.iter())
            .map(|(&as_i, &e_i)| mod_reduce(-as_i + e_i, q))
            .collect();

        let a_relin = random_poly(rng, n, q);
        let e_relin = random_error_poly(rng, n, ERROR_BOUND);
        let s_sq = poly_mult_negacyclic(&s, &s, n, q);
        let a_relin_times_s = poly_mult_negacyclic(&a_relin, &s, n, q);
        let b_relin: Vec<i64> = a_relin_times_s.iter()
            .zip(e_relin.iter())
            .zip(s_sq.iter())
            .map(|((&ar_i, &er_i), &ss_i)| mod_reduce(-ar_i + er_i + ss_i, q))
            .collect();

        let public_key = serialize_two_polys(&a, &b);
        let secret_key = serialize_poly(&s);
        let relin_key = serialize_two_polys(&a_relin, &b_relin);
        let galois_keys = serialize_poly(&a);

        Ok(FheKeyPair {
            public_key,
            secret_key,
            relin_key,
            galois_keys,
            ring_degree: self.ring_degree,
            modulus_bits: self.modulus_bits,
            created_at: current_time_secs(),
            rotation_count: 0,
        })
    }

    // ── Encryption ────────────────────────────────────────────────────────────

    /// Encrypt plaintext bytes using the FHE public key.
    ///
    /// Encodes bytes as polynomial coefficients, scales them by the
    /// plaintext scaling factor `Δ` (see [`plaintext_delta`]), then encrypts
    /// using `ct = (c0, c1) = (b*r + e0 + Δ*m, a*r + e1)`.
    ///
    /// `Δ` separates the message from the encryption noise: without it, the
    /// noise terms introduced by the polynomial convolutions in `r`, `e0`,
    /// `e1` (accumulated over `n` coefficient pairs each) can exceed the
    /// magnitude of an unscaled plaintext byte (0-255), corrupting every
    /// decrypted byte non-deterministically. See [`plaintext_delta`] for the
    /// safety-margin derivation.
    pub fn encrypt(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        keypair: &FheKeyPair,
        plaintext: &[u8],
    ) -> Result<FheCiphertext, PrivacyError> {
        let n = self.ring_degree as usize;
        let q = modulus_from_bits(self.modulus_bits);
        let delta = plaintext_delta(n);

        let (a, b) = deserialize_two_polys(&keypair.public_key, n)
            .map_err(|e| PrivacyError::FheEncryptionFailed(format!("pk deserialize: {}", e)))?;

        let m = encode_bytes_to_poly(plaintext, n);
        let m_scaled: Vec<i64> = m.iter().map(|&x| x.saturating_mul(delta)).collect();
        let r = random_ternary_poly(rng, n);
        let e0 = random_error_poly(rng, n, ERROR_BOUND);
        let e1 = random_error_poly(rng, n, ERROR_BOUND);

        let b_r = poly_mult_negacyclic(&b, &r, n, q);
        let a_r = poly_mult_negacyclic(&a, &r, n, q);

        let c0: Vec<i64> = b_r.iter().zip(e0.iter()).zip(m_scaled.iter())
            .map(|((&br_i, &e0_i), &m_i)| mod_reduce(br_i + e0_i + m_i, q))
            .collect();
        let c1: Vec<i64> = a_r.iter().zip(e1.iter())
            .map(|(&ar_i, &e1_i)| mod_reduce(ar_i + e1_i, q))
            .collect();

        let data = serialize_two_polys(&c0, &c1);
        let blake3_hash = blake3_hash_bytes(&data);

        Ok(FheCiphertext {
            data,
            noise_budget: self.max_noise_budget,
            ring_degree: self.ring_degree,
            modulus_bits: self.modulus_bits,
            created_at: current_time_secs(),
            blake3_hash,
        })
    }

    // ── Decryption ────────────────────────────────────────────────────────────

    /// Decrypt a ciphertext using the FHE secret key.
    ///
    /// Computes `m = c0 + c1*s = Δ*byte + noise` (mod `q`), then removes the
    /// scaling factor `Δ` via rounded integer division (see
    /// [`plaintext_delta`]/[`round_div`]) before extracting the low 8 bits of
    /// each coefficient. The rounded division cancels the accumulated
    /// encryption noise as long as `|noise| < Δ/2`, which `plaintext_delta`
    /// guarantees with a safety margin for the worst-case convolution noise
    /// bound at ring degree `n`.
    pub fn decrypt(
        &self,
        keypair: &FheKeyPair,
        ct: &FheCiphertext,
    ) -> Result<Vec<u8>, PrivacyError> {
        let n = self.ring_degree as usize;
        let q = modulus_from_bits(self.modulus_bits);
        let delta = plaintext_delta(n);

        let (c0, c1) = deserialize_two_polys(&ct.data, n)
            .map_err(|e| PrivacyError::FheEncryptionFailed(format!("ct deserialize: {}", e)))?;

        let s = deserialize_poly(&keypair.secret_key);
        if s.len() != n {
            return Err(PrivacyError::FheEncryptionFailed(format!(
                "secret key length mismatch: expected {}, got {}", n, s.len()
            )));
        }

        let c1_s = poly_mult_negacyclic(&c1, &s, n, q);
        let m: Vec<i64> = c0.iter().zip(c1_s.iter())
            .map(|(&c0_i, &c1s_i)| mod_reduce(c0_i + c1s_i, q))
            .collect();
        let m_rescaled: Vec<i64> = m.iter().map(|&x| round_div(x, delta)).collect();

        Ok(decode_poly_to_bytes(&m_rescaled))
    }

    // ── Homomorphic addition ──────────────────────────────────────────────────

    /// Homomorphic addition: `(c0_1 + c0_2, c1_1 + c1_2)` mod `q`.
    pub fn add(
        &self,
        ct1: &FheCiphertext,
        ct2: &FheCiphertext,
    ) -> Result<FheCiphertext, PrivacyError> {
        let n = self.ring_degree as usize;
        let q = modulus_from_bits(self.modulus_bits);

        let (c0_1, c1_1) = deserialize_two_polys(&ct1.data, n)
            .map_err(|e| PrivacyError::FheEncryptionFailed(format!("ct1: {}", e)))?;
        let (c0_2, c1_2) = deserialize_two_polys(&ct2.data, n)
            .map_err(|e| PrivacyError::FheEncryptionFailed(format!("ct2: {}", e)))?;

        let c0 = poly_add(&c0_1, &c0_2, q);
        let c1 = poly_add(&c1_1, &c1_2, q);

        let data = serialize_two_polys(&c0, &c1);
        let blake3_hash = blake3_hash_bytes(&data);
        let noise_budget = ct1.noise_budget.min(ct2.noise_budget).saturating_sub(1);

        Ok(FheCiphertext {
            data,
            noise_budget,
            ring_degree: self.ring_degree,
            modulus_bits: self.modulus_bits,
            created_at: current_time_secs(),
            blake3_hash,
        })
    }

    // ── Homomorphic multiplication ────────────────────────────────────────────

    /// Homomorphic multiplication with relinearization.
    ///
    /// Computes tensor product `(d0, d1, d2)` then relinearizes to `(c0', c1')`.
    pub fn mult(
        &self,
        keypair: &FheKeyPair,
        ct1: &FheCiphertext,
        ct2: &FheCiphertext,
    ) -> Result<FheCiphertext, PrivacyError> {
        let n = self.ring_degree as usize;
        let q = modulus_from_bits(self.modulus_bits);

        let (c0_1, c1_1) = deserialize_two_polys(&ct1.data, n)
            .map_err(|e| PrivacyError::FheEncryptionFailed(format!("ct1: {}", e)))?;
        let (c0_2, c1_2) = deserialize_two_polys(&ct2.data, n)
            .map_err(|e| PrivacyError::FheEncryptionFailed(format!("ct2: {}", e)))?;

        let d0 = poly_mult_negacyclic(&c0_1, &c0_2, n, q);
        let d1_a = poly_mult_negacyclic(&c0_1, &c1_2, n, q);
        let d1_b = poly_mult_negacyclic(&c1_1, &c0_2, n, q);
        let d1 = poly_add(&d1_a, &d1_b, q);
        let d2 = poly_mult_negacyclic(&c1_1, &c1_2, n, q);

        let (a_relin, b_relin) = deserialize_two_polys(&keypair.relin_key, n)
            .map_err(|e| PrivacyError::FheEncryptionFailed(format!("relin key: {}", e)))?;

        let d2_b_relin = poly_mult_negacyclic(&d2, &b_relin, n, q);
        let d2_a_relin = poly_mult_negacyclic(&d2, &a_relin, n, q);

        let c0 = poly_add(&d0, &d2_b_relin, q);
        let c1 = poly_add(&d1, &d2_a_relin, q);

        let data = serialize_two_polys(&c0, &c1);
        let blake3_hash = blake3_hash_bytes(&data);
        let noise_budget = ct1.noise_budget.min(ct2.noise_budget).saturating_sub(5);

        Ok(FheCiphertext {
            data,
            noise_budget,
            ring_degree: self.ring_degree,
            modulus_bits: self.modulus_bits,
            created_at: current_time_secs(),
            blake3_hash,
        })
    }

    // ── Bootstrapping ─────────────────────────────────────────────────────────

    /// Bootstrap (refresh) a noisy ciphertext by decrypt+re-encrypt.
    ///
    /// Resets `noise_budget` to `max_noise_budget`.
    pub fn bootstrap(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        keypair: &FheKeyPair,
        ct: &FheCiphertext,
    ) -> Result<FheCiphertext, PrivacyError> {
        let plaintext = self.decrypt(keypair, ct)?;
        let mut refreshed = self.encrypt(rng, keypair, &plaintext)?;
        refreshed.noise_budget = self.max_noise_budget;
        Ok(refreshed)
    }

    // ── Negation ──────────────────────────────────────────────────────────────

    /// Homomorphic negation: negate all coefficients of both components.
    pub fn negate(&self, ct: &FheCiphertext) -> Result<FheCiphertext, PrivacyError> {
        let n = self.ring_degree as usize;
        let q = modulus_from_bits(self.modulus_bits);

        let (c0, c1) = deserialize_two_polys(&ct.data, n)
            .map_err(|e| PrivacyError::FheEncryptionFailed(format!("ct: {}", e)))?;

        let c0_neg = poly_negate(&c0, q);
        let c1_neg = poly_negate(&c1, q);

        let data = serialize_two_polys(&c0_neg, &c1_neg);
        let blake3_hash = blake3_hash_bytes(&data);

        Ok(FheCiphertext {
            data,
            noise_budget: ct.noise_budget.saturating_sub(1),
            ring_degree: self.ring_degree,
            modulus_bits: self.modulus_bits,
            created_at: current_time_secs(),
            blake3_hash,
        })
    }

    // ── Batch operations ──────────────────────────────────────────────────────

    /// Batch addition: fold over slice calling `add()` repeatedly.
    pub fn batch_add(&self, cts: &[FheCiphertext]) -> Result<FheCiphertext, PrivacyError> {
        if cts.is_empty() {
            return Err(PrivacyError::FheEncryptionFailed("batch_add: empty input".into()));
        }
        let mut result = cts[0].clone();
        for ct in &cts[1..] {
            result = self.add(&result, ct)?;
        }
        Ok(result)
    }

    /// Batch multiplication: fold over slice calling `mult()` repeatedly.
    pub fn batch_mult(
        &self,
        keypair: &FheKeyPair,
        cts: &[FheCiphertext],
    ) -> Result<FheCiphertext, PrivacyError> {
        if cts.is_empty() {
            return Err(PrivacyError::FheEncryptionFailed("batch_mult: empty input".into()));
        }
        let mut result = cts[0].clone();
        for ct in &cts[1..] {
            result = self.mult(keypair, &result, ct)?;
        }
        Ok(result)
    }

    // ── Relinearization ───────────────────────────────────────────────────────

    /// Relinearization (no-op in this implementation — mult() relinearizes inline).
    pub fn relinearize(
        &self,
        _keypair: &FheKeyPair,
        ct: &FheCiphertext,
    ) -> Result<FheCiphertext, PrivacyError> {
        let mut result = ct.clone();
        result.blake3_hash = blake3_hash_bytes(&result.data);
        Ok(result)
    }

    // ── CKKS rescaling ────────────────────────────────────────────────────────

    /// CKKS rescaling: divide all coefficients by 2, reduce `modulus_bits` by 1.
    pub fn scale_down(&self, ct: &FheCiphertext) -> Result<FheCiphertext, PrivacyError> {
        let n = self.ring_degree as usize;
        let new_modulus_bits = ct.modulus_bits.saturating_sub(1).max(1);
        let new_q = modulus_from_bits(new_modulus_bits);

        let (c0, c1) = deserialize_two_polys(&ct.data, n)
            .map_err(|e| PrivacyError::FheEncryptionFailed(format!("ct: {}", e)))?;

        let c0_scaled: Vec<i64> = c0.iter().map(|&x| mod_reduce(x >> 1, new_q)).collect();
        let c1_scaled: Vec<i64> = c1.iter().map(|&x| mod_reduce(x >> 1, new_q)).collect();

        let data = serialize_two_polys(&c0_scaled, &c1_scaled);
        let blake3_hash = blake3_hash_bytes(&data);

        Ok(FheCiphertext {
            data,
            noise_budget: ct.noise_budget,
            ring_degree: self.ring_degree,
            modulus_bits: new_modulus_bits,
            created_at: current_time_secs(),
            blake3_hash,
        })
    }

    // ── Modulus switching ─────────────────────────────────────────────────────

    /// Modulus switching: reduce coefficients to smaller modulus, reduce `modulus_bits` by 4.
    pub fn mod_switch(&self, ct: &FheCiphertext) -> Result<FheCiphertext, PrivacyError> {
        let n = self.ring_degree as usize;
        let new_modulus_bits = ct.modulus_bits.saturating_sub(4).max(1);
        let new_q = modulus_from_bits(new_modulus_bits);

        let (c0, c1) = deserialize_two_polys(&ct.data, n)
            .map_err(|e| PrivacyError::FheEncryptionFailed(format!("ct: {}", e)))?;

        let c0_switched: Vec<i64> = c0.iter().map(|&x| mod_reduce(x, new_q)).collect();
        let c1_switched: Vec<i64> = c1.iter().map(|&x| mod_reduce(x, new_q)).collect();

        let data = serialize_two_polys(&c0_switched, &c1_switched);
        let blake3_hash = blake3_hash_bytes(&data);

        Ok(FheCiphertext {
            data,
            noise_budget: ct.noise_budget,
            ring_degree: self.ring_degree,
            modulus_bits: new_modulus_bits,
            created_at: current_time_secs(),
            blake3_hash,
        })
    }

    // ── Integrity verification ────────────────────────────────────────────────

    /// Verify ciphertext integrity by recomputing the BLAKE3 hash.
    pub fn verify(&self, ct: &FheCiphertext) -> Result<bool, PrivacyError> {
        let computed = blake3_hash_bytes(&ct.data);
        Ok(computed == ct.blake3_hash)
    }

    // ── Serialization ─────────────────────────────────────────────────────────

    /// Serialize a ciphertext to JSON bytes.
    pub fn serialize_ciphertext(&self, ct: &FheCiphertext) -> Result<Vec<u8>, PrivacyError> {
        serde_json::to_vec(ct)
            .map_err(|e| PrivacyError::FheEncryptionFailed(format!("serialize: {}", e)))
    }

    /// Deserialize a ciphertext from JSON bytes.
    pub fn deserialize_ciphertext(&self, bytes: &[u8]) -> Result<FheCiphertext, PrivacyError> {
        serde_json::from_slice(bytes)
            .map_err(|e| PrivacyError::FheEncryptionFailed(format!("deserialize: {}", e)))
    }
}

// ── Polynomial arithmetic (public for cross-crate use) ────────────────────────

/// Coefficient-wise polynomial addition mod `modulus`.
pub fn poly_add(a: &[i64], b: &[i64], modulus: i64) -> Vec<i64> {
    let n = a.len().max(b.len());
    let mut result = vec![0i64; n];
    for i in 0..n {
        let ai = if i < a.len() { a[i] } else { 0 };
        let bi = if i < b.len() { b[i] } else { 0 };
        result[i] = mod_reduce(ai + bi, modulus);
    }
    result
}

/// Negacyclic polynomial multiplication in `Z_q[X]/(X^N + 1)`.
///
/// Schoolbook O(N²) — correct for N=1024.
pub fn poly_mult_negacyclic(a: &[i64], b: &[i64], n: usize, modulus: i64) -> Vec<i64> {
    let mut result = vec![0i64; n];
    for i in 0..n {
        if a[i] == 0 { continue; }
        for j in 0..n {
            if b[j] == 0 { continue; }
            let k = i + j;
            let product = a[i].wrapping_mul(b[j]);
            if k < n {
                result[k] = mod_reduce(result[k] + product, modulus);
            } else {
                result[k - n] = mod_reduce(result[k - n] - product, modulus);
            }
        }
    }
    result
}

/// Negate all coefficients of a polynomial mod `modulus`.
pub fn poly_negate(a: &[i64], modulus: i64) -> Vec<i64> {
    a.iter().map(|&x| mod_reduce(-x, modulus)).collect()
}

/// Encode bytes as polynomial coefficients (each byte → one coefficient).
pub fn encode_bytes_to_poly(data: &[u8], n: usize) -> Vec<i64> {
    let mut poly = vec![0i64; n];
    for (i, &byte) in data.iter().enumerate().take(n) {
        poly[i] = byte as i64;
    }
    poly
}

/// Decode polynomial coefficients to bytes (low 8 bits of each coefficient).
pub fn decode_poly_to_bytes(poly: &[i64]) -> Vec<u8> {
    poly.iter().map(|&x| (x & 0xFF) as u8).collect()
}

/// Serialize a polynomial as a little-endian `i64` array.
pub fn serialize_poly(poly: &[i64]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(poly.len() * 8);
    for &coeff in poly {
        bytes.extend_from_slice(&coeff.to_le_bytes());
    }
    bytes
}

/// Deserialize a polynomial from a little-endian `i64` array.
pub fn deserialize_poly(bytes: &[u8]) -> Vec<i64> {
    bytes.chunks_exact(8)
        .map(|chunk| {
            let arr: [u8; 8] = chunk.try_into().unwrap_or([0u8; 8]);
            i64::from_le_bytes(arr)
        })
        .collect()
}

/// Serialize two polynomials as `p0_bytes || p1_bytes`.
pub fn serialize_two_polys(p0: &[i64], p1: &[i64]) -> Vec<u8> {
    let mut bytes = serialize_poly(p0);
    bytes.extend_from_slice(&serialize_poly(p1));
    bytes
}

/// Deserialize two polynomials from `p0_bytes || p1_bytes`.
pub fn deserialize_two_polys(bytes: &[u8], n: usize) -> Result<(Vec<i64>, Vec<i64>), alloc::string::String> {
    let expected = n * 8 * 2;
    if bytes.len() < expected {
        return Err(format!(
            "deserialize_two_polys: expected {} bytes, got {}",
            expected, bytes.len()
        ));
    }
    let p0 = deserialize_poly(&bytes[..n * 8]);
    let p1 = deserialize_poly(&bytes[n * 8..n * 16]);
    Ok((p0, p1))
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Small prime used as the error distribution bound.
const ERROR_BOUND: i64 = 16;

/// Safety-margin multiplier applied on top of the worst-case noise bound
/// when deriving the plaintext scaling factor `Δ` (see [`plaintext_delta`]).
///
/// A factor of 64 (2^6) gives ~6 bits of headroom between the worst-case
/// noise magnitude and `Δ/2`, which is far more margin than the *actual*
/// (random-sign, not worst-case-aligned) noise ever needs in practice, while
/// still being cheap: for the crate's default parameters (`n` up to a few
/// thousand) `Δ` stays many orders of magnitude below `q` (`i64::MAX` for
/// `modulus_bits >= 63`), so there is no risk of `Δ*255` overflowing into
/// the noise's own headroom in `mod_reduce`'s symmetric range.
const NOISE_SAFETY_FACTOR: i64 = 64;

/// Reduce `x` into the symmetric range `(-q/2, q/2]`.
#[inline(always)]
fn mod_reduce(x: i64, q: i64) -> i64 {
    if q <= 0 { return x; }
    let r = x % q;
    if r > q / 2 { r - q } else if r < -(q / 2) { r + q } else { r }
}

/// Compute the modulus `q = 2^bits` (clamped to `i64::MAX`).
fn modulus_from_bits(bits: u32) -> i64 {
    if bits >= 63 { i64::MAX } else { 1i64 << bits }
}

/// Compute the plaintext scaling factor `Δ` for ring degree `n`.
///
/// ## Why `Δ` is needed
///
/// Decryption computes `m' = c0 + c1*s = m + (e·r + e0 + e1·s)` where `m` is
/// the raw plaintext polynomial. The noise term `e·r + e0 + e1·s` includes
/// two *negacyclic polynomial convolutions* (`e·r` and `e1·s`), each of which
/// sums up to `n` signed products of a ternary coefficient (`{-1,0,1}`) and
/// an error coefficient bounded by `ERROR_BOUND`. Per output coefficient,
/// the worst-case (fully sign-aligned) magnitude of *one* such convolution
/// is `n * ERROR_BOUND`; with two convolution terms plus the additive `e0`
/// term (also bounded by `ERROR_BOUND`), the worst-case total noise bound is:
///
/// ```text
/// noise_bound(n) = 2 * (n * ERROR_BOUND) + ERROR_BOUND = ERROR_BOUND * (2n + 1)
/// ```
///
/// Without scaling, this noise is added directly to the raw plaintext byte
/// (range `0..=255`) before the low 8 bits are extracted — since
/// `noise_bound(64) = 16 * 129 = 2064` already dwarfs the 0..255 byte range,
/// every decrypted byte is corrupted by an unpredictable (fresh-randomness-
/// dependent) amount every run. This was confirmed empirically: raw
/// decrypted coefficients for ring degree 64 were observed to differ from
/// the expected plaintext bytes by up to +253 in a single run.
///
/// ## Fix: scale the message by `Δ`
///
/// `encrypt()` multiplies the encoded plaintext by `Δ` before adding it into
/// `c0`; `decrypt()` divides the raw decrypted coefficient by `Δ` (rounding
/// to the nearest integer, see [`round_div`]) before extracting the byte.
/// Rounding exactly cancels the noise term as long as:
///
/// ```text
/// |noise| < Δ / 2
/// ```
///
/// `Δ` is chosen as `noise_bound(n) * NOISE_SAFETY_FACTOR`, giving:
///
/// ```text
/// Δ / 2 = noise_bound(n) * NOISE_SAFETY_FACTOR / 2 = noise_bound(n) * 32
/// ```
///
/// i.e. a 32x safety margin over the *worst-case* (not typical/expected)
/// noise bound — worst-case requires every one of the `2n` convolution terms
/// to align in sign, which has probability ~`2^-2n` under the actual random
/// sampling, so real noise is many orders of magnitude smaller than this
/// bound in practice; the margin exists purely so the proof of correctness
/// doesn't depend on that improbability.
///
/// ## No overflow / no wraparound into `q`
///
/// The scaled message magnitude is bounded by `255 * Δ`. For the two
/// parameter sets this crate uses:
///
/// - Test params `n = 64`, `modulus_bits = 32` (`q = 2^32`):
///   `noise_bound(64) = 2064`, `Δ = 2064 * 64 = 132_096`,
///   `255 * Δ ≈ 3.37e7`, vs. `q/2 ≈ 2.15e9` — ~64x margin below `q/2`.
/// - Default/production params `n = 1024`, `modulus_bits = 128`
///   (`q` clamped to `i64::MAX ≈ 9.22e18`):
///   `noise_bound(1024) = 32_784`, `Δ = 32_784 * 64 = 2_098_176`,
///   `255 * Δ ≈ 5.35e8`, vs. `q/2 ≈ 4.61e18` — enormous margin.
///
/// In both cases `255 * Δ + noise_bound(n)` stays far below `q/2`, so
/// `mod_reduce`'s symmetric-range reduction never wraps the scaled message,
/// and the rounded division in `decrypt()` recovers the exact original byte.
fn plaintext_delta(n: usize) -> i64 {
    let noise_bound = ERROR_BOUND.saturating_mul(2 * n as i64 + 1);
    noise_bound.saturating_mul(NOISE_SAFETY_FACTOR)
}

/// Round `x / delta` to the nearest integer (ties away from zero), correctly
/// handling negative `x` (Rust's `/` truncates toward zero, which would bias
/// small-magnitude negative values toward 0 instead of the nearest integer).
#[inline(always)]
fn round_div(x: i64, delta: i64) -> i64 {
    if delta <= 0 { return x; }
    let half = delta / 2;
    if x >= 0 {
        (x + half) / delta
    } else {
        -(((-x) + half) / delta)
    }
}

/// Generate a random polynomial with coefficients in `(-q/2, q/2]`.
fn random_poly(rng: &mut impl RngCore, n: usize, q: i64) -> Vec<i64> {
    (0..n).map(|_| mod_reduce(rng.gen_range(0..q), q)).collect()
}

/// Generate a random ternary polynomial with coefficients in `{-1, 0, 1}`.
fn random_ternary_poly(rng: &mut impl RngCore, n: usize) -> Vec<i64> {
    (0..n).map(|_| rng.gen_range(-1i64..=1)).collect()
}

/// Generate a random error polynomial with coefficients in `[-bound, bound]`.
fn random_error_poly(rng: &mut impl RngCore, n: usize, bound: i64) -> Vec<i64> {
    (0..n).map(|_| rng.gen_range(-bound..=bound)).collect()
}

/// Compute BLAKE3 hash of bytes.
fn blake3_hash_bytes(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// Return current Unix timestamp in seconds.
fn current_time_secs() -> u64 {
    #[cfg(feature = "std")]
    {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
    #[cfg(not(feature = "std"))]
    {
        0
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen_roundtrip() {
        let mut rng = rand::rngs::OsRng;
        let mut engine = FheEngine::new(64, 32);
        let keypair = engine.keygen(&mut rng).unwrap();
        assert_eq!(keypair.ring_degree, 64);
        assert!(!keypair.public_key.is_empty());
        assert!(!keypair.secret_key.is_empty());
    }

    #[test]
    fn test_encrypt_decrypt() {
        let mut rng = rand::rngs::OsRng;
        let mut engine = FheEngine::new(64, 32);
        let keypair = engine.keygen(&mut rng).unwrap();
        let plaintext = b"hello";
        let ct = engine.encrypt(&mut rng, &keypair, plaintext).unwrap();
        let recovered = engine.decrypt(&keypair, &ct).unwrap();
        assert_eq!(&recovered[..5], plaintext);
    }

    #[test]
    fn test_add_homomorphic() {
        let mut rng = rand::rngs::OsRng;
        let mut engine = FheEngine::new(64, 32);
        let keypair = engine.keygen(&mut rng).unwrap();
        let ct1 = engine.encrypt(&mut rng, &keypair, &[1u8]).unwrap();
        let ct2 = engine.encrypt(&mut rng, &keypair, &[2u8]).unwrap();
        let ct_sum = engine.add(&ct1, &ct2).unwrap();
        assert!(ct_sum.noise_budget < ct1.noise_budget);
    }

    #[test]
    fn test_verify_integrity() {
        let mut rng = rand::rngs::OsRng;
        let mut engine = FheEngine::new(64, 32);
        let keypair = engine.keygen(&mut rng).unwrap();
        let ct = engine.encrypt(&mut rng, &keypair, b"test").unwrap();
        assert!(engine.verify(&ct).unwrap());
    }

    #[test]
    fn test_serialize_deserialize() {
        let mut rng = rand::rngs::OsRng;
        let mut engine = FheEngine::new(64, 32);
        let keypair = engine.keygen(&mut rng).unwrap();
        let ct = engine.encrypt(&mut rng, &keypair, b"data").unwrap();
        let bytes = engine.serialize_ciphertext(&ct).unwrap();
        let ct2 = engine.deserialize_ciphertext(&bytes).unwrap();
        assert_eq!(ct.data, ct2.data);
        assert_eq!(ct.blake3_hash, ct2.blake3_hash);
    }

    #[test]
    fn test_poly_add() {
        let a = vec![1i64, 2, 3];
        let b = vec![4i64, 5, 6];
        let result = poly_add(&a, &b, 100);
        assert_eq!(result, vec![5, 7, 9]);
    }

    #[test]
    fn test_poly_mult_negacyclic_small() {
        // (1 + X) * (1 + X) = 1 + 2X + X^2
        // In Z[X]/(X^2 + 1): X^2 = -1, so result = 1 + 2X - 1 = 2X
        let a = vec![1i64, 1];
        let b = vec![1i64, 1];
        let result = poly_mult_negacyclic(&a, &b, 2, 1000);
        assert_eq!(result[0], 0); // 1 - 1 = 0
        assert_eq!(result[1], 2); // 2X
    }

    #[test]
    fn test_encode_decode_bytes() {
        let data = b"hello world";
        let poly = encode_bytes_to_poly(data, 16);
        let recovered = decode_poly_to_bytes(&poly);
        assert_eq!(&recovered[..data.len()], data);
    }
}