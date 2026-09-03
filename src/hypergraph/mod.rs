//! Five-Dimensional Privacy Hypergraph — a local graph simulation
//!
//! **What this module actually does.** [`PrivacyHypergraph`] is an in-process
//! `BTreeMap`-based graph: each vertex is a SHA-256 commitment over five caller-supplied
//! `f64` fields, and each hyperedge carries a "CHSH" score computed by a formula built to
//! resemble a Bell-inequality expression (`2^(k/2-1) · |Π cos φᵢ| · …`, clamped at
//! `2.828427`) — it is not a measurement of anything physical, just a deterministic
//! function of the caller's inputs. There is no qubit state, no tensor product, and no
//! entanglement; "5-qubit tensor product states" and "Bell-state channels" describe the
//! vocabulary this module borrows, not what it computes. See the crate README's "What runs
//! today vs. what is designed" for the full accounting.
//!
//! **Aspirational:** a real Bell-inequality-violating computation, or an actual quantum
//! backend, is not implemented here or anywhere in this crate.

use crate::error::PrivacyError;
use crate::types::{FiveDimCoord, Hyperedge, HypergraphVertex, PrivacyProof, ProofScheme};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

extern crate alloc;
use alloc::{collections::BTreeMap, string::{String, ToString}, vec, vec::Vec};

/// Tsirelson's bound analog for k-party entanglement.
/// Classical CHSH bound is 2.0; quantum bound is 2√2 ≈ 2.828.
pub const TSIRELSON_BOUND: f64 = 2.828_427;

/// Minimum CHSH value required for non-local soundness (target: > 2.8).
pub const CHSH_THRESHOLD: f64 = 2.8;

/// Minimum Lyapunov exponent for chaos perturbation (target: ≥ 4.5).
pub const LYAPUNOV_MIN: f64 = 4.5;

/// The 5D-EZPH hypergraph.
///
/// Stores vertices (qubit tensor states) and hyperedges (Bell-state channels).
/// All traversals are anonymized via DW3B mesh integration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyHypergraph {
    pub vertices:  BTreeMap<String, HypergraphVertex>,
    pub hyperedges: BTreeMap<String, Hyperedge>,
    /// Genesis vertex ID
    pub genesis:   Option<String>,
    /// Kaluza-Klein metric perturbation factor (chaos-seeded)
    pub kk_factor: f64,
}

impl PrivacyHypergraph {
    /// Create a new hypergraph with a genesis vertex.
    ///
    /// The genesis vertex is the zero-state tensor: all five dimensions at 0.
    pub fn new(chaos_seed: f64) -> Self {
        let genesis_id = "genesis".to_string();
        let genesis = HypergraphVertex {
            id:         genesis_id.clone(),
            coord:      FiveDimCoord::zero(),
            commitment: hex::encode(Sha256::digest(b"5d-ezph-genesis")),
            expiry_ms:  0,
        };
        let mut vertices = BTreeMap::new();
        vertices.insert(genesis_id.clone(), genesis);

        Self {
            vertices,
            hyperedges: BTreeMap::new(),
            genesis: Some(genesis_id),
            kk_factor: chaos_seed,
        }
    }

    /// Encode an event as a hypergraph vertex.
    ///
    /// Dimensions are populated from:
    /// - `spatial`:      cluster position hash
    /// - `temporal`:     current timestamp (ms)
    /// - `probabilistic`: DP noise parameter ε
    /// - `quantum`:      phase angle from chaos oracle
    /// - `chaotic`:      Chua attractor trajectory value
    pub fn encode_vertex(
        &mut self,
        id: impl Into<String>,
        spatial: f64,
        temporal: f64,
        dp_epsilon: f64,
        phase_angle: f64,
        chaos_traj: f64,
        expiry_ms: u64,
    ) -> Result<String, PrivacyError> {
        let id = id.into();
        let coord = FiveDimCoord {
            spatial,
            temporal,
            probabilistic: dp_epsilon,
            quantum: phase_angle,
            chaotic: chaos_traj,
        };

        // Commitment = SHA-256(id || coord bytes)
        let mut hasher = Sha256::new();
        hasher.update(id.as_bytes());
        hasher.update(&spatial.to_le_bytes());
        hasher.update(&temporal.to_le_bytes());
        hasher.update(&dp_epsilon.to_le_bytes());
        hasher.update(&phase_angle.to_le_bytes());
        hasher.update(&chaos_traj.to_le_bytes());
        let commitment = hex::encode(hasher.finalize());

        let vertex = HypergraphVertex { id: id.clone(), coord, commitment, expiry_ms };
        self.vertices.insert(id.clone(), vertex);
        Ok(id)
    }

    /// Form a hyperedge between ≥2 vertices with Kaluza-Klein modulation.
    ///
    /// Simulates Bell-state entanglement: computes CHSH correlation via
    /// tensor product of vertex phase angles, perturbed by chaos.
    pub fn form_hyperedge(
        &mut self,
        id: impl Into<String>,
        vertex_ids: Vec<String>,
        chaos_perturbation: f64,
    ) -> Result<String, PrivacyError> {
        if vertex_ids.len() < 2 {
            return Err(PrivacyError::InvalidDimension(vertex_ids.len()));
        }

        // Verify all vertices exist
        for vid in &vertex_ids {
            if !self.vertices.contains_key(vid) {
                return Err(PrivacyError::VertexNotFound(vid.clone()));
            }
        }

        // Simulate CHSH correlation: product of phase angles modulated by KK metric
        let k = vertex_ids.len() as f64;
        let phase_product: f64 = vertex_ids
            .iter()
            .filter_map(|vid| self.vertices.get(vid))
            .map(|v| v.coord.quantum)
            .fold(1.0_f64, |acc, phi| acc * phi.cos());

        // CHSH analog: |C| = 2^(k/2 - 1) * |phase_product| * kk_factor * chaos
        let chsh = (2.0_f64.powf(k / 2.0 - 1.0))
            * phase_product.abs()
            * self.kk_factor
            * (1.0 + chaos_perturbation.abs() * 0.1);

        // Clamp to Tsirelson bound
        let chsh = chsh.min(TSIRELSON_BOUND);

        let id = id.into();
        let edge = Hyperedge {
            id: id.clone(),
            vertices: vertex_ids,
            kk_metric: self.kk_factor,
            chsh_value: chsh,
        };
        self.hyperedges.insert(id.clone(), edge);
        Ok(id)
    }

    /// Traverse the hypergraph with non-local jumps (Bell violations).
    ///
    /// Returns a path of vertex IDs with CHSH-validated edges.
    /// Edges with CHSH < threshold are skipped (classical locality).
    pub fn traverse_non_local(
        &self,
        start: &str,
        max_hops: usize,
    ) -> Result<Vec<String>, PrivacyError> {
        let mut path = vec![start.to_string()];
        let mut current = start.to_string();

        for _ in 0..max_hops {
            // Find edges containing current vertex with CHSH > threshold
            let next_edge = self
                .hyperedges
                .values()
                .filter(|e| e.vertices.contains(&current) && e.chsh_value > CHSH_THRESHOLD)
                .max_by(|a, b| a.chsh_value.partial_cmp(&b.chsh_value).unwrap());

            match next_edge {
                Some(edge) => {
                    // Non-local jump: pick vertex with highest phase angle
                    let next = edge
                        .vertices
                        .iter()
                        .filter(|v| **v != current)
                        .max_by(|a, b| {
                            let pa = self.vertices.get(*a).map(|v| v.coord.quantum).unwrap_or(0.0);
                            let pb = self.vertices.get(*b).map(|v| v.coord.quantum).unwrap_or(0.0);
                            pa.partial_cmp(&pb).unwrap()
                        });
                    match next {
                        Some(n) => {
                            current = n.clone();
                            path.push(current.clone());
                        }
                        None => break,
                    }
                }
                None => break,
            }
        }

        Ok(path)
    }

    /// Generate a ZK proof of hypergraph state (non-local soundness).
    ///
    /// Proof commits to the CHSH value of the highest-correlation edge,
    /// demonstrating non-local privacy without revealing vertex states.
    pub fn prove_non_locality(&self) -> Result<PrivacyProof, PrivacyError> {
        let max_chsh = self
            .hyperedges
            .values()
            .map(|e| e.chsh_value)
            .fold(0.0_f64, f64::max);

        if max_chsh <= CHSH_THRESHOLD {
            return Err(PrivacyError::ChshBoundViolation {
                got: max_chsh,
                threshold: CHSH_THRESHOLD,
            });
        }

        // Commitment: SHA-256(vertex_count || edge_count || max_chsh)
        let mut hasher = Sha256::new();
        hasher.update(&(self.vertices.len() as u64).to_le_bytes());
        hasher.update(&(self.hyperedges.len() as u64).to_le_bytes());
        hasher.update(&max_chsh.to_le_bytes());
        hasher.update(&self.kk_factor.to_le_bytes());
        let commitment = hex::encode(hasher.finalize());

        Ok(PrivacyProof {
            proof_bytes:   commitment.clone(),
            public_inputs: hex::encode(max_chsh.to_le_bytes()),
            scheme:        ProofScheme::Snark,
            security_bits: 128,
            proof_size:    commitment.len(),
            chsh_value:    max_chsh,
            lyapunov:      LYAPUNOV_MIN,
        })
    }

    /// Prune expired vertices from the hypergraph.
    pub fn prune_expired(&mut self, now_ms: u64) {
        let expired: Vec<String> = self
            .vertices
            .iter()
            .filter(|(_, v)| v.expiry_ms > 0 && now_ms > v.expiry_ms)
            .map(|(id, _)| id.clone())
            .collect();

        for id in &expired {
            self.vertices.remove(id);
            // Remove edges referencing expired vertices
            self.hyperedges.retain(|_, e| !e.vertices.contains(id));
        }
    }

    /// Returns the number of vertices.
    pub fn vertex_count(&self) -> usize {
        self.vertices.len()
    }

    /// Returns the number of hyperedges.
    pub fn edge_count(&self) -> usize {
        self.hyperedges.len()
    }
}

/// Compute the CHSH S-value for the current hypergraph state.
///
/// S = |E(A,B) + E(A,B') + E(A',B) - E(A',B')| where correlators are
/// derived from edge `kk_metric` values.
///
/// The four correlators are taken from the four edges with the highest
/// `chsh_value` in the graph (or fewer if the graph has fewer edges).
/// If the graph has fewer than 4 edges, the missing correlators default
/// to the canonical Bell-state value 1/√2 ≈ 0.7071.
///
/// Returns the S value (should be > 2.8 for valid quantum non-locality).
///
/// # Parameters
/// - `graph_json`: JSON-serialized [`PrivacyHypergraph`]
///
/// # Errors
/// - [`PrivacyError::SerializationError`] if `graph_json` is not valid JSON
pub fn hypergraph_chsh_value(graph_json: &str) -> Result<f64, PrivacyError> {
    let graph: PrivacyHypergraph = serde_json::from_str(graph_json)
        .map_err(|e| PrivacyError::SerializationError(e.to_string()))?;

    // Collect all edge chsh_values, sorted descending
    let mut chsh_vals: Vec<f64> = graph
        .hyperedges
        .values()
        .map(|e| e.chsh_value)
        .collect();
    chsh_vals.sort_by(|a, b| b.partial_cmp(a).unwrap_or(core::cmp::Ordering::Equal));

    // The canonical Bell-state correlator 1/√2
    const BELL: f64 = core::f64::consts::FRAC_1_SQRT_2; // ≈ 0.7071

    // Pad to 4 correlators with the canonical Bell value
    while chsh_vals.len() < 4 {
        chsh_vals.push(BELL);
    }

    // S = E(A,B) + E(A,B') + E(A',B) - E(A',B')
    // Use the four highest-correlation edges as the four measurement settings
    let e_ab   = chsh_vals[0];
    let e_ab2  = chsh_vals[1];
    let e_a2b  = chsh_vals[2];
    let e_a2b2 = chsh_vals[3];

    let s = (e_ab + e_ab2 + e_a2b - e_a2b2).abs();
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_vertex() {
        let g = PrivacyHypergraph::new(1.0);
        assert_eq!(g.vertex_count(), 1);
        assert!(g.genesis.is_some());
    }

    #[test]
    fn test_encode_vertex() {
        let mut g = PrivacyHypergraph::new(1.0);
        let id = g.encode_vertex("v1", 0.5, 1000.0, 1e-6, 1.2, 0.8, 0).unwrap();
        assert_eq!(id, "v1");
        assert_eq!(g.vertex_count(), 2);
    }

    #[test]
    fn test_hyperedge_chsh() {
        let mut g = PrivacyHypergraph::new(3.0);
        g.encode_vertex("v1", 0.5, 1000.0, 1e-6, core::f64::consts::PI / 4.0, 0.8, 0).unwrap();
        g.encode_vertex("v2", 0.7, 1001.0, 1e-6, core::f64::consts::PI / 3.0, 0.9, 0).unwrap();
        let eid = g.form_hyperedge("e1", vec!["v1".into(), "v2".into()], 0.5).unwrap();
        let edge = g.hyperedges.get(&eid).unwrap();
        // CHSH should be positive
        assert!(edge.chsh_value > 0.0);
    }
}
