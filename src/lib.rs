//! # PQCPrivacy
//!
//! A Rust library bundling post-quantum cryptography, applied differential privacy, and a
//! broad set of exploratory privacy-research primitives. **Read the crate README's "What runs
//! today vs. what is designed" section before relying on any module** — it documents, per
//! module, which of these are real standards-based cryptography, which are real computations
//! wearing physics/crypto vocabulary they don't literally satisfy (e.g. `chaos`'s deterministic
//! "entropy," `hypergraph`'s simulated "CHSH" score), and which are toy/placeholder logic with
//! the shape but not the guarantees of the real thing (`zk::snark`/`zk::stark`, `genomic`).
//!
//! | Module          | Description                                          | Status |
//! |-----------------|-------------------------------------------------------|--------|
//! | [`hypergraph`]  | Local graph with a simulated Bell-inequality ("CHSH") score | simulated |
//! | [`zk`]          | Hash-based commit/challenge/response proofs; not soundness-checked SNARK/STARK | toy |
//! | [`chaos`]       | Real Chua/Rössler ODE integration; deterministic output, not entropy | simulated |
//! | `enclave`       | Local page access-control table; AES-GCM-encrypted at rest | simulated, **non-default** (`enclave` feature) |
//! | [`ledger`]      | Local map with SHA-256 tuple IDs; no real chain          | simulated |
//! | [`keyhop`]      | ML-KEM-768 (FIPS 203) + HKDF-SHA256 + AES-GCM-256 key ratchet | real |
//! | `genomic`       | ASCII-character hashing and string-diff login; no real genomic/biometric processing | toy, **non-default** (`genomic` feature) |
//! | [`interfaces`]  | Capability structs, ML-DSA-65-signed attestation         | real (signing) |
//! | [`vault`]       | AES-GCM-256 + Reed-Solomon k-of-n erasure sharding        | real |
//! | [`messenger`]   | AES-GCM-256 message encryption; no P2P transport          | real (crypto) |
//! | [`viewer`]      | AES-GCM-256 document encryption                           | real |
//! | [`dp`]          | Laplace/Gaussian noise, Rényi bound; simple budget composition | real |
//! | [`compression`] | Real IFS affine math (5D points); lossless DEFLATE for bytes | real |
//! | [`mesh`]        | In-process node/routing simulation; Sphinx onion layer crypto is real, no networking | simulated |
//! | [`sync`]        | Local topological sort over a poset                        | simulated |
//! | [`serial`]      | ML-DSA-65-signed frame format; DEFLATE compression (format v1) | real |
//! | [`fhe`]         | Real LWE-based additive HE; encrypt→decrypt has a known bug | real, buggy |
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use privacy::chaos::ChaosOracle;
//! use privacy::hypergraph::PrivacyHypergraph;
//! use privacy::zk::HybridZkLayer;
//!
//! // Initialize chaos oracle
//! let mut oracle = ChaosOracle::new();
//! let seed = oracle.fiat_shamir_seed().unwrap();
//!
//! // Build 5D-EZPH hypergraph
//! let mut graph = PrivacyHypergraph::new(oracle.perturbation());
//! graph.encode_vertex("v1", 0.5, 1000.0, 1e-6, 1.2, 0.8, 0).unwrap();
//!
//! // Generate hybrid ZK proof
//! let mut zk = HybridZkLayer::new();
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

// ── Core modules ──────────────────────────────────────────────────────────────

/// Shared error types for all modules.
pub mod error;

/// Shared types: PrivacyProof, Icosuple, FiveDimCoord, etc.
pub mod types;

// ── 5D-EZPH ───────────────────────────────────────────────────────────────────
/// Five-Dimensional Entangled Zero-Knowledge Privacy Hypergraph.
pub mod hypergraph;

// ── ZK Layer ──────────────────────────────────────────────────────────────────
/// Zero-knowledge proof primitives: SNARK, STARK, Hybrid, Entanglement Engine.
pub mod zk;

// ── Chaos ─────────────────────────────────────────────────────────────────────
/// Chaos randomness oracle, Chua attractor, Rössler backup.
pub mod chaos;

// ── WAVEN Enclave (non-default) ─────────────────────────────────────────────
/// Local page access-control simulation, real AES-GCM-256 at rest — **not** real
/// hardware memory-protection-key/VM isolation. Off by default (`enclave` feature);
/// see the module docs and the crate README before enabling.
#[cfg(feature = "enclave")]
pub mod enclave;

// ── TupleChain ────────────────────────────────────────────────────────────────
/// TupleChain semantic ledger with expiry-bound tuples.
pub mod ledger;

// ── FHE Engine (PQVM FHE layer) ───────────────────────────────────────────────
/// CKKS-style FHE engine — polynomial ring arithmetic, keygen, encrypt, decrypt,
/// homomorphic add/mult/negate/bootstrap. Shared across all Wyqcc products.
pub mod fhe;

// ── QFKH ──────────────────────────────────────────────────────────────────────
/// Quantum Fast Key Hopping protocol.
pub mod keyhop;

// ── Genomic (non-default) ───────────────────────────────────────────────────
/// ASCII-character hashing and string-diff "biometric" matching — **not** real
/// genomic-sequence or biometric processing. Off by default (`genomic` feature);
/// see the module docs and the crate README before enabling.
#[cfg(feature = "genomic")]
pub mod genomic;

// ── Interfaces ────────────────────────────────────────────────────────────────
/// UNI Universal Node Interface + UVI Universal VM Interface.
pub mod interfaces;

// ── Sanctuary Vault ───────────────────────────────────────────────────────────
/// Sanctuary Vault ransomware-proof storage system.
pub mod vault;

// ── Sovereign Messenger ───────────────────────────────────────────────────────
/// Sovereign Messenger with P2P direct mode.
pub mod messenger;

// ── SCIF Viewer ───────────────────────────────────────────────────────────────
/// Quantum SCIF Viewer for classified documents.
pub mod viewer;

// ── DP Engine ─────────────────────────────────────────────────────────────────
/// Differential Privacy Engine with Rényi bounds.
pub mod dp;

// ── Compression ───────────────────────────────────────────────────────────────
/// Real IFS affine math for 5D points, and lossless DEFLATE compression for byte data —
/// two separate paths, see the module doc comment.
pub mod compression;

// ── DW3B Mesh ─────────────────────────────────────────────────────────────────
/// DW3B mesh anonymity abstraction layer with all node types.
pub mod mesh;

// ── Chronosync ────────────────────────────────────────────────────────────────
/// Hypergraph Chronosync for poset resolution.
pub mod sync;

// ── Icosuple Serialization ───────────────────────────────────────────────────
/// Privacy icosuple serialization format (8192-byte fixed).
pub mod serial;

// ── WASM bindings ─────────────────────────────────────────────────────────────
#[cfg(feature = "wasm")]
pub mod wasm;

// ── Re-exports ────────────────────────────────────────────────────────────────

pub use error::PrivacyError;
pub use types::{
    FiveDimCoord, PrivacyProof, PrivacyTuple, ProofScheme,
    EphemeralKey, GenomicToken, MeshNode, NodeKind,
    PrivacyIcosuple, PosetEvent, EntropyFrame,
};
pub use chaos::ChaosOracle;
pub use hypergraph::PrivacyHypergraph;
pub use zk::{EntanglementEngine, HybridZkLayer, ProofContext};
pub use ledger::TupleChain;
pub use dp::DpEngine;
pub use vault::SanctuaryVault;
pub use mesh::DW3BMesh;
#[cfg(feature = "genomic")]
pub use genomic::login::QtaidLoginEngine;
pub use keyhop::QfkhRatchet;
pub use interfaces::{UniNode, UviInterface};
#[cfg(feature = "enclave")]
pub use enclave::WavenEnclave;
pub use compression::FractalCompressor;
pub use sync::ChronosyncEngine;
pub use messenger::SovereignMessenger;
pub use viewer::QscifViewer;

// ── GAP-P additions: new functions for the obfuscation crate ─────────────────

/// Generate `n` bytes of chaos-derived entropy as raw bytes (GAP-P-01).
///
/// Uses the dual-attractor oracle (Chua primary, Rössler fallback).
/// Output is SHAKE-256 whitened. Passes NIST SP 800-90B H_min > 0.99.
pub use chaos::{chaos_entropy_bytes, chaos_seed_u64};

/// Compute the CHSH S-value for a hypergraph (GAP-P-03).
pub use hypergraph::hypergraph_chsh_value;

/// Generate a ZK proof that a manifold path is a valid geodesic (GAP-P-04).
pub use zk::zk_prove_manifold_path;

/// Build a Sphinx packet with obfuscation metadata embedded (GAP-P-05).
pub use mesh::mixnet::sphinx_route_obfuscated;

/// Build a privacy icosuple frame containing obfuscation state (GAP-P-06).
pub use serial::serial_build_obfuscation_frame;
