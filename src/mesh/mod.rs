//! Mesh module — a local model of a mesh network, not a working one
//!
//! **What this module actually does.** There is no networking code anywhere in this
//! crate — no socket, no HTTP client, nothing that dials the `endpoint` string stored on a
//! [`MeshNode`]. [`DW3BMesh::route_query`] looks a node up in a local `BTreeMap` and
//! returns a locally-built packet; nothing is sent over a wire. This is the same kind of
//! local simulation as `aethel-core`'s `htss.rs` hypercube routing: real code, exercised by
//! tests, but modeling a distributed system rather than running one.
//!
//! One exception: the cryptography *inside* a single [`mixnet`] Sphinx packet is real —
//! genuine ML-KEM-768 encapsulation and AES-GCM-256 encryption per layer. The "mesh" that's
//! said to carry that packet between nodes is what's simulated.
//!
//! - [`mixnet`]     — Sphinx packet construction (real onion-layer crypto, no transport)
//! - [`bloom`]      — local Bloom filter
//! - [`stake`]      — local stake bookkeeping, ML-DSA-65-signed commitments
//! - [`index`]      — local Merkle Patricia Trie-style index
//! - [`cdn`]        — local cache simulation
//! - [`governance`] — local ballot bookkeeping, not a working voting system
//! - [`keys`]       — local key-distribution bookkeeping, ML-DSA-65-signed
//! - [`micro`]      — local entropy-elasticity bookkeeping
//!
//! [`DW3BMesh`] is the in-process facade over all of the above. See the crate README's
//! "What runs today vs. what is designed" for the full accounting.

pub mod bloom;
pub mod cdn;
pub mod governance;
pub mod index;
pub mod keys;
pub mod micro;
pub mod mixnet;
pub mod stake;

use crate::error::PrivacyError;
use crate::types::{MeshNode, NodeKind, SphinxPacket};

extern crate alloc;
use alloc::{format, collections::BTreeMap, string::String, vec::Vec};

/// DW3B Mesh Anonymity Abstraction Layer.
///
/// Encapsulates all node types into a unified high-level privacy API.
/// Provides GRPC-style facade with QSTP tunneling.
pub struct DW3BMesh {
    nodes:   BTreeMap<String, MeshNode>,
    /// QSTP tunnel key (hex)
    qstp_key: String,
}

impl DW3BMesh {
    pub fn new(qstp_key: impl Into<String>) -> Self {
        Self {
            nodes:    BTreeMap::new(),
            qstp_key: qstp_key.into(),
        }
    }

    /// Register a node with the mesh.
    pub fn register_node(&mut self, node: MeshNode) {
        self.nodes.insert(node.id.clone(), node);
    }

    /// Route a query anonymously through the mesh.
    ///
    /// Selects appropriate node type based on query kind,
    /// wraps in Sphinx packet, and routes via QSTP tunnel.
    pub fn route_query(
        &self,
        data: &[u8],
        node_kind: NodeKind,
        chaos_seed: &[u8; 32],
    ) -> Result<SphinxPacket, PrivacyError> {
        // Find a node of the requested kind
        let _node = self.nodes.values()
            .find(|n| n.kind == node_kind)
            .ok_or_else(|| PrivacyError::NodeUnreachable(format!("{node_kind:?}")))?;

        // Wrap in Sphinx packet
        let config = mixnet::SphinxConfig {
            hops:       7,
            lambda:     10.0,
            chaos_seed: *chaos_seed,
        };
        mixnet::build_sphinx_packet(data.to_vec(), &config, false)
    }

    /// Returns all nodes of a given kind.
    pub fn nodes_of_kind(&self, kind: NodeKind) -> Vec<&MeshNode> {
        self.nodes.values().filter(|n| n.kind == kind).collect()
    }

    /// Returns total node count.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Returns the QSTP tunnel key.
    pub fn qstp_key(&self) -> &str {
        &self.qstp_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_and_route() {
        let mut mesh = DW3BMesh::new("qstp-key-hex");
        mesh.register_node(MeshNode {
            id:       "mixnet-1".into(),
            kind:     NodeKind::Mixnet,
            endpoint: "127.0.0.1:9001".into(),
            stake:    1000,
            pubkey:   "deadbeef".into(),
        });
        let seed = [0u8; 32];
        let pkt = mesh.route_query(b"query", NodeKind::Mixnet, &seed).unwrap();
        assert_eq!(pkt.hops, 7);
    }

    #[test]
    fn test_node_not_found() {
        let mesh = DW3BMesh::new("key");
        let seed = [0u8; 32];
        assert!(mesh.route_query(b"q", NodeKind::Governance, &seed).is_err());
    }
}
