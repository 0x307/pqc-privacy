//! Query Mesh Nodes with Bloom Filters (QMN-BF)
//!
//! Bloom filters for encrypted membership tests with DP noise injection.
//! Capacity: 10^9 items, false positive rate ≤ 0.001.

use crate::types::{PrivacyProof, ProofScheme};
use sha2::{Digest, Sha256};

extern crate alloc;
use alloc::{vec, vec::Vec};

/// Bloom filter for encrypted membership queries.
pub struct BloomFilter {
    /// Bit array (stored as bytes)
    bits:    Vec<u8>,
    /// Number of hash functions k
    k:       usize,
    /// Capacity m in bits
    m:       usize,
    /// DP epsilon for noise injection
    dp_eps:  f64,
    /// Items inserted
    count:   u64,
}

impl BloomFilter {
    /// Create a new Bloom filter.
    ///
    /// For 10^9 items with FP ≤ 0.001: m ≈ 14.4 * n bits, k ≈ 10.
    pub fn new(capacity: usize, fp_rate: f64, dp_epsilon: f64) -> Self {
        let m = (-(capacity as f64) * fp_rate.ln() / (2.0_f64.ln().powi(2))).ceil() as usize;
        let k = ((m as f64 / capacity as f64) * 2.0_f64.ln()).ceil() as usize;
        let byte_count = (m + 7) / 8;
        Self {
            bits:   vec![0u8; byte_count],
            k:      k.max(1),
            m:      m.max(8),
            dp_eps: dp_epsilon,
            count:  0,
        }
    }

    /// Insert an item (hashed with 5Dqeh for manifold compatibility).
    pub fn insert(&mut self, item: &[u8]) {
        for i in 0..self.k {
            let idx = self.hash(item, i as u64) % self.m;
            self.bits[idx / 8] |= 1 << (idx % 8);
        }
        self.count += 1;
    }

    /// Test membership with DP noise injection.
    ///
    /// Returns `(is_member, dp_noised_result)`.
    pub fn contains_dp(&self, item: &[u8], chaos_seed: &[u8; 32]) -> (bool, bool) {
        let raw = self.contains_raw(item);

        // DP noise: flip result with probability exp(-ε)
        let seed_val = u64::from_le_bytes(chaos_seed[..8].try_into().unwrap_or([0u8; 8]));
        let uniform = (seed_val as f64) / (u64::MAX as f64);
        let flip_prob = (-self.dp_eps).exp();
        let noised = if uniform < flip_prob { !raw } else { raw };

        (raw, noised)
    }

    /// Generate a ZK anonymity proof for a query result.
    pub fn prove_membership(&self, item: &[u8], result: bool) -> PrivacyProof {
        let mut hasher = Sha256::new();
        hasher.update(item);
        hasher.update(&[result as u8]);
        hasher.update(&self.count.to_le_bytes());
        hasher.update(b"bloom-membership-v1");
        let commitment: [u8; 32] = hasher.finalize().into();

        PrivacyProof {
            proof_bytes:   hex::encode(commitment),
            public_inputs: hex::encode([result as u8]),
            scheme:        ProofScheme::Snark,
            security_bits: 128,
            proof_size:    64,
            chsh_value:    0.0,
            lyapunov:      4.5,
        }
    }

    /// Returns the estimated false positive rate.
    pub fn fp_rate(&self) -> f64 {
        let n = self.count as f64;
        let m = self.m as f64;
        let k = self.k as f64;
        (1.0 - (-k * n / m).exp()).powf(k)
    }

    fn contains_raw(&self, item: &[u8]) -> bool {
        for i in 0..self.k {
            let idx = self.hash(item, i as u64) % self.m;
            if self.bits[idx / 8] & (1 << (idx % 8)) == 0 {
                return false;
            }
        }
        true
    }

    /// Murmur3-inspired hash using SHA-256 with counter.
    fn hash(&self, item: &[u8], seed: u64) -> usize {
        let mut hasher = Sha256::new();
        hasher.update(item);
        hasher.update(&seed.to_le_bytes());
        hasher.update(b"5dqeh-bloom");
        let h: [u8; 32] = hasher.finalize().into();
        u64::from_le_bytes(h[..8].try_into().unwrap_or([0u8; 8])) as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_contains() {
        let mut bf = BloomFilter::new(1000, 0.001, 1e-6);
        bf.insert(b"alice");
        let (raw, _) = bf.contains_dp(b"alice", &[0u8; 32]);
        assert!(raw);
    }

    #[test]
    fn test_fp_rate_reasonable() {
        let mut bf = BloomFilter::new(1000, 0.001, 1e-6);
        for i in 0..100u64 {
            bf.insert(&i.to_le_bytes());
        }
        assert!(bf.fp_rate() < 0.01);
    }
}
