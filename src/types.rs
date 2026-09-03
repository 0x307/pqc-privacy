//! Shared types across the PQCPrivacy crate.
//!
//! These types form the common vocabulary of the framework — from
//! five-dimensional manifold coordinates to privacy proofs, icosuples,
//! and telemetry structs.

extern crate alloc;
use alloc::{string::String, vec::Vec};

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ── Five-Dimensional Manifold Coordinates ─────────────────────

/// The five dimensions of the 5D-EZPH hypergraph vertex.
///
/// - `spatial`:      position embedding in the anonymity mesh
/// - `temporal`:     expiry clock (Unix ms)
/// - `probabilistic`: differential privacy noise distribution parameter
/// - `quantum`:      phase angle for Bell-state analog modulation
/// - `chaotic`:      Chua/Rössler attractor trajectory coordinate
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FiveDimCoord {
    pub spatial:      f64,
    pub temporal:     f64,
    pub probabilistic: f64,
    pub quantum:      f64,
    pub chaotic:      f64,
}

impl FiveDimCoord {
    pub fn zero() -> Self {
        Self { spatial: 0.0, temporal: 0.0, probabilistic: 0.0, quantum: 0.0, chaotic: 0.0 }
    }
}

/// A hypergraph vertex — a 5-qubit tensor product state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HypergraphVertex {
    pub id:    String,
    pub coord: FiveDimCoord,
    /// Serialized proof commitment (base64url)
    pub commitment: String,
    /// Expiry timestamp (Unix ms); 0 = no expiry
    pub expiry_ms: u64,
}

/// A hyperedge connecting ≥2 vertices via Bell-state channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hyperedge {
    pub id:       String,
    pub vertices: Vec<String>,
    /// Kaluza-Klein metric perturbation factor
    pub kk_metric: f64,
    /// Simulated CHSH correlation value
    pub chsh_value: f64,
}

// ── Zero-Knowledge Proof Types ───────────────────────

/// Proof system selector for the hybrid ZK layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofScheme {
    /// zk-SNARK (Groth16/Halo2) — compact, trusted-setup
    Snark,
    /// zk-STARK — transparent, post-quantum, larger proofs
    Stark,
    /// Hybrid: SNARK for succinctness + STARK for transparency
    Hybrid,
    /// Bulletproofs+ — for range proofs (genomic traits)
    Bulletproofs,
}

/// A privacy-preserving zero-knowledge proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyProof {
    /// Serialized proof bytes (base64url)
    pub proof_bytes:   String,
    /// Public inputs (hex-encoded)
    pub public_inputs: String,
    /// Proof scheme used
    pub scheme:        ProofScheme,
    /// Security level in bits
    pub security_bits: u32,
    /// Approximate proof size in bytes
    pub proof_size:    usize,
    /// Simulated CHSH correlation (for entangled proofs)
    pub chsh_value:    f64,
    /// Lyapunov exponent of chaos perturbation applied
    pub lyapunov:      f64,
}

impl PrivacyProof {
    /// Returns `true` if the proof achieves non-local soundness (CHSH > 2.8).
    pub fn is_non_local(&self) -> bool {
        self.chsh_value > 2.8
    }
}

// ── Chaos Telemetry ──────────────────────────────────

/// Telemetry emitted by chaos attractor modules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChaosTelemetry {
    pub lyapunov:  f64,
    pub h_min:     f64,
    pub passed:    bool,
    pub attractor: AttractorKind,
}

/// Which chaos attractor is active.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttractorKind {
    /// Chua double-scroll (primary)
    Chua,
    /// Rössler 3D flow (backup)
    Rossler,
}

// ── Differential Privacy ─────────────────────────────────────

/// Noise mechanism for differential privacy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DpMechanism {
    Laplace,
    Gaussian,
}

/// A DP noise frame exported by the DPE-RB engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpNoiseFrame {
    pub renyi_alpha: u32,
    pub bound:       f64,
    pub mechanism:   DpMechanism,
    /// Epsilon consumed by this frame
    pub epsilon:     f64,
    /// Chaos-modulated noise scale
    pub noise_scale: f64,
}

// ── TupleChain Five-Tuple ─────────────────────────────────────

/// The five-tuple semantic ledger entry.
///
/// `(subject, predicate, object, proof, expiry)`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyTuple {
    pub subject:   String,
    pub predicate: String,
    /// Serialized object value (may be FHE ciphertext)
    pub object:    Vec<u8>,
    /// Embedded ZK proof
    pub proof:     PrivacyProof,
    /// Expiry timestamp (Unix ms) with Laplace noise applied
    pub expiry_ms: u64,
    /// Wyqcc L1 anchor hash (hex)
    pub anchor:    Option<String>,
}

impl PrivacyTuple {
    /// Returns `true` if the tuple has expired.
    pub fn is_expired(&self, now_ms: u64) -> bool {
        self.expiry_ms > 0 && now_ms > self.expiry_ms
    }
}

// ── QFKH Key Material ─────────────────────────────────────────

/// An ephemeral QFKH session key — zeroized on drop.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct EphemeralKey {
    /// ML-KEM encapsulated shared secret (32 bytes)
    pub shared_secret: [u8; 32],
    /// Chain key for ratchet derivation
    pub chain_key:     [u8; 32],
    /// Creation timestamp (Unix ms)
    pub created_ms:    u64,
    /// Expiry interval (ms); default ≤1 ms
    pub expiry_ms:     u64,
}

impl EphemeralKey {
    pub fn is_expired(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.created_ms) >= self.expiry_ms
    }
}

// ── Genomic Token ────────────────────────────────────────

/// A nano-tokenized genomic allele commitment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenomicToken {
    /// Pedersen commitment to 2–4 bit allele encoding
    pub commitment:  String,
    /// ZK proof of trait (Bulletproofs+)
    pub trait_proof: PrivacyProof,
    /// Expiry-bound tuple ID on Wyqcc L1
    pub tuple_id:    String,
    /// DP noise parameter applied (ε)
    pub dp_epsilon:  f64,
}

// ── Mesh Node Types ──────────────────────────────────────────

/// DW3B mesh node type selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeKind {
    /// Mixnet/Tor with Sphinx packets
    Mixnet,
    /// Query nodes with Bloom filters
    Query,
    /// Stake anonymity nodes
    Stake,
    /// Index nodes with Merkle Patricia Tries
    Index,
    /// CDN nodes with iced caching
    Cdn,
    /// Governance nodes for ZKP-voting
    Governance,
    /// Key management nodes
    KeyManagement,
    /// Physical/virtual micro-nodes for entropy
    Micro,
}

/// A DW3B mesh node descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshNode {
    pub id:       String,
    pub kind:     NodeKind,
    pub endpoint: String,
    /// Stake weight (for sybil resistance)
    pub stake:    u64,
    /// PQC public key (hex)
    pub pubkey:   String,
}

// ── Sphinx Packet ────────────────────────────────────────────

/// A layered Sphinx packet for anonymous routing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SphinxPacket {
    /// Layered-encrypted payload
    pub payload:   Vec<u8>,
    /// Number of hops (5–9)
    pub hops:      u8,
    /// Poisson decoy flag
    pub is_decoy:  bool,
    /// Chaos perturbation seed (hex)
    pub chaos_seed: String,
}

// ── Privacy Icosuple ─────────────────────────────────────────

/// An 8192-byte privacy icosuple — the canonical serialization unit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyIcosuple {
    /// Serialized 5D manifold vertex (tensor representation)
    pub manifold_tensor: Vec<u8>,
    /// Embedded ZK proof bundle
    pub proof_bundle:    Vec<u8>,
    /// Chaos attractor state snapshot
    pub chaos_state:     Vec<u8>,
    /// Whether the serialized payload is compressed. The algorithm is fixed by the
    /// serialization format version (version 1 = DEFLATE), not carried per-frame.
    pub compressed:      bool,
    /// PQC signature over the icosuple (hex)
    pub signature:       String,
}

impl PrivacyIcosuple {
    /// Maximum serialized size in bytes.
    pub const MAX_BYTES: usize = 8192;
}

// ── Capability Advertisement ──────────────────────────────────

/// A JSON-LD capability descriptor for UNI advertisement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityDescriptor {
    pub node_id:      String,
    pub capabilities: Vec<PrivacyCapability>,
    /// Chaos-perturbed freshness nonce
    pub nonce:        String,
    /// PQC signature (hex)
    pub signature:    String,
}

/// A single privacy capability offered by a UNI node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyCapability {
    pub kind:           CapabilityKind,
    pub scheme:         String,
    pub security_level: u32,
    pub recursion:      bool,
}

/// Capability type for UNI advertisement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CapabilityKind {
    Fhe,
    Zk,
    Dp,
    Mpc,
}

// ── Governance Vote ──────────────────────────────────────────

/// An encrypted governance ballot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedBallot {
    pub voter_commitment: String,
    pub encrypted_vote:   Vec<u8>,
    pub zk_proof:         PrivacyProof,
    pub stake_weight:     u64,
    pub timestamp_ms:     u64,
}

/// Outcome of a governance vote.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteOutcome {
    pub proposal_id: String,
    pub passed:      bool,
    pub tally:       u64,
    pub total_stake: u64,
    pub proof:       PrivacyProof,
}

// ── Entropy Frame ────────────────────────────────────────────

/// An entropy frame from physical/virtual micro-nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyFrame {
    /// Raw entropy bytes (≥256 bits)
    pub bytes:     Vec<u8>,
    /// 5Dqeh hash of the frame (hex)
    pub hash_5dqeh: String,
    /// Min-entropy estimate
    pub h_min:     f64,
    /// Source kind
    pub source:    EntropySource,
    /// ZKP proof of quality
    pub proof:     PrivacyProof,
}

/// Source label for an entropy frame. Neither variant is backed by a real hardware entropy
/// source or true randomness in this crate today — see [`crate::mesh::micro`] and the crate
/// README's "What runs today vs. what is designed". `PhysicalQrng` is a label a caller can
/// select, not a driver for actual QRNG hardware; `VirtualChaos` reflects the deterministic
/// Chua/Rössler simulation in [`crate::chaos`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntropySource {
    /// Label only — no physical QRNG hardware integration exists in this crate
    PhysicalQrng,
    /// Deterministic Chua/Rössler simulation (see [`crate::chaos`]), not true randomness
    VirtualChaos,
}

// ── Poset Event ───────────────────────────────────────────────

/// A causal event in the Hypergraph Chronosync poset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PosetEvent {
    pub id:           String,
    pub dependencies: Vec<String>,
    pub payload_hash: String,
    pub timestamp_ms: u64,
    pub zk_merge:     Option<PrivacyProof>,
}

// ── Utility ───────────────────────────────────────────────────────────────────

/// Returns the current Unix timestamp in milliseconds.
/// In no_std environments, callers must provide this via injection.
#[cfg(feature = "std")]
pub fn unix_now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(not(feature = "std"))]
pub fn unix_now_ms() -> u64 {
    0 // caller must inject time in no_std
}
