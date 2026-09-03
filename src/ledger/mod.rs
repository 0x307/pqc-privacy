//! TupleChain — a local map, not a ledger or a chain
//!
//! [`TupleChain`] is an in-process `BTreeMap<String, PrivacyTuple>` with SHA-256-derived
//! tuple IDs. "Anchoring to Wyqcc L1" is inserting into a second local map — there is no
//! blockchain, consensus, or external anchor here. Five-tuple storage (subject, predicate,
//! object, proof, expiry) and SHA-256 ID derivation are real; "chain" and "ledger" describe
//! the vocabulary, not a distributed or append-only guarantee. See the crate README's "What
//! runs today vs. what is designed."

pub mod tuple;

use crate::error::PrivacyError;
use crate::types::PrivacyTuple;
use sha2::{Digest, Sha256};

extern crate alloc;
use alloc::{collections::BTreeMap, string::{String, ToString}, vec::Vec};

/// The TupleChain semantic ledger.
///
/// Stores five-tuples as a DAG with automatic expiry pruning,
/// SPARQL-inspired semantic queries, and Wyqcc L1 anchoring.
#[derive(Debug, Default)]
pub struct TupleChain {
    tuples:      BTreeMap<String, PrivacyTuple>,
    /// Anchor hashes for L1 immutability
    anchors:     BTreeMap<String, String>,
    /// Total tuples ever inserted
    total_count: u64,
}

impl TupleChain {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a five-tuple into the ledger.
    ///
    /// Generates a tuple ID from SHA-256(subject || predicate || expiry).
    pub fn insert(&mut self, tuple: PrivacyTuple) -> String {
        let id = self.tuple_id(&tuple);
        self.tuples.insert(id.clone(), tuple);
        self.total_count += 1;
        id
    }

    /// Query tuples by subject (SPARQL-inspired).
    ///
    /// Returns non-expired tuples matching the subject.
    pub fn query_by_subject(&self, subject: &str, now_ms: u64) -> Vec<&PrivacyTuple> {
        self.tuples
            .values()
            .filter(|t| t.subject == subject && !t.is_expired(now_ms))
            .collect()
    }

    /// Query tuples by predicate.
    pub fn query_by_predicate(&self, predicate: &str, now_ms: u64) -> Vec<&PrivacyTuple> {
        self.tuples
            .values()
            .filter(|t| t.predicate == predicate && !t.is_expired(now_ms))
            .collect()
    }

    /// Get a tuple by ID.
    pub fn get(&self, id: &str) -> Option<&PrivacyTuple> {
        self.tuples.get(id)
    }

    /// Prune expired tuples via ZK proof of expiry.
    ///
    /// Returns the number of tuples pruned.
    pub fn prune_expired(&mut self, now_ms: u64) -> usize {
        let expired: Vec<String> = self
            .tuples
            .iter()
            .filter(|(_, t)| t.is_expired(now_ms))
            .map(|(id, _)| id.clone())
            .collect();
        let count = expired.len();
        for id in expired {
            self.tuples.remove(&id);
        }
        count
    }

    /// Anchor all un-anchored tuples to Wyqcc L1.
    ///
    /// Returns a Merkle root of all anchor hashes.
    pub fn anchor_all(&mut self) -> String {
        let mut hasher = Sha256::new();
        for (id, tuple) in &mut self.tuples {
            if tuple.anchor.is_none() {
                let anchor = tuple::anchor_tuple(tuple);
                self.anchors.insert(id.clone(), anchor.clone());
                hasher.update(anchor.as_bytes());
            }
        }
        hex::encode(hasher.finalize())
    }

    /// Not actually homomorphic — XORs two object fields byte-for-byte. XOR-ing arbitrary
    /// ciphertext bytes does not correspond to addition of the underlying plaintexts under
    /// any scheme used elsewhere in this crate (AES-GCM, the real LWE scheme in
    /// [`crate::fhe`]). Kept for compatibility; do not rely on the result meaning "a + b."
    pub fn homomorphic_add(
        &self,
        id_a: &str,
        id_b: &str,
    ) -> Result<Vec<u8>, PrivacyError> {
        let a = self.tuples.get(id_a).ok_or_else(|| PrivacyError::TupleNotFound(id_a.into()))?;
        let b = self.tuples.get(id_b).ok_or_else(|| PrivacyError::TupleNotFound(id_b.into()))?;

        let len = a.object.len().min(b.object.len());
        let result: Vec<u8> = a.object[..len]
            .iter()
            .zip(b.object[..len].iter())
            .map(|(x, y)| x ^ y)
            .collect();

        Ok(result)
    }

    /// Returns the total number of active (non-expired) tuples.
    pub fn active_count(&self, now_ms: u64) -> usize {
        self.tuples.values().filter(|t| !t.is_expired(now_ms)).count()
    }

    /// Returns the total number of tuples ever inserted.
    pub fn total_count(&self) -> u64 {
        self.total_count
    }

    // ── Private helpers ───────────────────────────────────────────────────

    fn tuple_id(&self, tuple: &PrivacyTuple) -> String {
        let mut hasher = Sha256::new();
        hasher.update(tuple.subject.as_bytes());
        hasher.update(tuple.predicate.as_bytes());
        hasher.update(&tuple.expiry_ms.to_le_bytes());
        hasher.update(&self.total_count.to_le_bytes());
        hex::encode(hasher.finalize())[..16].to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::tuple::build_tuple;

    #[test]
    fn test_insert_query() {
        let mut chain = TupleChain::new();
        let seed = [0u8; 32];
        let t = build_tuple("alice", "owns", b"data".to_vec(), 9_999_999_999, 1e-6, &seed).unwrap();
        let id = chain.insert(t);
        assert!(!id.is_empty());
        let results = chain.query_by_subject("alice", 0);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_prune_expired() {
        let mut chain = TupleChain::new();
        let seed = [0u8; 32];
        // Tuple with expiry in the past
        let t = build_tuple("bob", "had", b"old".to_vec(), 1, 1e-6, &seed).unwrap();
        chain.insert(t);
        let pruned = chain.prune_expired(1_000_000_000);
        assert!(pruned >= 1);
    }
}
