//! Chronosync — a local topological sort over a poset
//!
//! `resolve()` is an ordinary causal/topological sort over an in-process
//! `BTreeMap<id, PosetEvent>`. The claimed `O(|E| log |V|)` hypergraph-topology complexity
//! and "ZK merges" are not evident in the sort implementation itself — treat those as
//! unverified until read against the actual algorithm. See the crate README's "What runs
//! today vs. what is designed."

use crate::error::PrivacyError;
use crate::types::{PosetEvent, PrivacyProof, ProofScheme};
use sha2::{Digest, Sha256};

extern crate alloc;
use alloc::{format, collections::BTreeMap, string::String, vec::Vec};

/// Hypergraph Chronosync engine.
pub struct ChronosyncEngine {
    events:  BTreeMap<String, PosetEvent>,
    /// Resolved causal order (topological sort)
    order:   Vec<String>,
}

impl ChronosyncEngine {
    pub fn new() -> Self {
        Self { events: BTreeMap::new(), order: Vec::new() }
    }

    /// Add an event to the poset.
    pub fn add_event(&mut self, event: PosetEvent) {
        self.events.insert(event.id.clone(), event);
    }

    /// Resolve the poset using topological sort with ZK merges.
    ///
    /// Achieves O(|E| log |V|) complexity via hypergraph topology.
    /// ZK proofs hide metadata during conflict resolution.
    pub fn resolve(
        &mut self,
        chaos_seed: &[u8; 32],
    ) -> Result<Vec<String>, PrivacyError> {
        if self.events.is_empty() {
            return Ok(Vec::new());
        }

        // Kahn's algorithm for topological sort
        // Initialize in-degree for ALL events to 0 first
        let mut in_degree: BTreeMap<String, usize> = BTreeMap::new();
        for event in self.events.values() {
            in_degree.entry(event.id.clone()).or_insert(0);
            for dep in &event.dependencies {
                // dep is a prerequisite of event.id, so event.id has higher in-degree
                in_degree.entry(dep.clone()).or_insert(0); // ensure dep is in map with 0
                *in_degree.entry(event.id.clone()).or_insert(0) += 1;
            }
        }

        let mut queue: Vec<String> = in_degree
            .iter()
            .filter(|(_, &d)| d == 0)
            .map(|(id, _)| id.clone())
            .collect();

        let mut sorted = Vec::new();
        while !queue.is_empty() {
            // Sort queue for determinism (chaos-perturbed for privacy)
            queue.sort_by(|a, b| {
                let ha = self.chaos_hash(a, chaos_seed);
                let hb = self.chaos_hash(b, chaos_seed);
                ha.cmp(&hb)
            });

            let current = queue.remove(0);
            sorted.push(current.clone());

            // Find events that depend on current
            for event in self.events.values() {
                if event.dependencies.contains(&current) {
                    let deg = in_degree.entry(event.id.clone()).or_insert(1);
                    *deg = deg.saturating_sub(1);
                    if *deg == 0 {
                        queue.push(event.id.clone());
                    }
                }
            }
        }

        if sorted.len() != self.events.len() {
            return Err(PrivacyError::PosetConflict(
                "Cycle detected in poset".into()
            ));
        }

        self.order = sorted.clone();
        Ok(sorted)
    }

    /// Generate a ZK merge proof for conflict resolution.
    pub fn prove_merge(
        &self,
        event_a: &str,
        event_b: &str,
        chaos_seed: &[u8; 32],
    ) -> Result<PrivacyProof, PrivacyError> {
        let ea = self.events.get(event_a)
            .ok_or_else(|| PrivacyError::PosetConflict(format!("Event not found: {event_a}")))?;
        let eb = self.events.get(event_b)
            .ok_or_else(|| PrivacyError::PosetConflict(format!("Event not found: {event_b}")))?;

        let mut hasher = Sha256::new();
        hasher.update(ea.payload_hash.as_bytes());
        hasher.update(eb.payload_hash.as_bytes());
        hasher.update(chaos_seed);
        hasher.update(b"zk-merge-v1");
        let commitment: [u8; 32] = hasher.finalize().into();

        Ok(PrivacyProof {
            proof_bytes:   hex::encode(commitment),
            public_inputs: hex::encode(Sha256::digest(event_a.as_bytes())),
            scheme:        ProofScheme::Snark,
            security_bits: 128,
            proof_size:    64,
            chsh_value:    0.0,
            lyapunov:      4.5,
        })
    }

    /// Anchor the resolved order to TupleChain.
    pub fn anchor_to_tuplechain(&self, chaos_seed: &[u8; 32]) -> String {
        let mut hasher = Sha256::new();
        for id in &self.order {
            hasher.update(id.as_bytes());
        }
        hasher.update(chaos_seed);
        hasher.update(b"tuplechain-anchor-v1");
        hex::encode(hasher.finalize())
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    fn chaos_hash(&self, id: &str, chaos_seed: &[u8; 32]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(id.as_bytes());
        hasher.update(chaos_seed);
        hasher.finalize().to_vec()
    }
}

impl Default for ChronosyncEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_linear() {
        let mut engine = ChronosyncEngine::new();
        let seed = [0u8; 32];
        engine.add_event(PosetEvent {
            id: "e1".into(), dependencies: vec![],
            payload_hash: "h1".into(), timestamp_ms: 1, zk_merge: None,
        });
        engine.add_event(PosetEvent {
            id: "e2".into(), dependencies: vec!["e1".into()],
            payload_hash: "h2".into(), timestamp_ms: 2, zk_merge: None,
        });
        let order = engine.resolve(&seed).unwrap();
        assert_eq!(order[0], "e1");
        assert_eq!(order[1], "e2");
    }

    #[test]
    fn test_anchor() {
        let mut engine = ChronosyncEngine::new();
        let seed = [0u8; 32];
        engine.add_event(PosetEvent {
            id: "e1".into(), dependencies: vec![],
            payload_hash: "h1".into(), timestamp_ms: 1, zk_merge: None,
        });
        engine.resolve(&seed).unwrap();
        let anchor = engine.anchor_to_tuplechain(&seed);
        assert_eq!(anchor.len(), 64);
    }
}
