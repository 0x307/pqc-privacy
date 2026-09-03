//! Unified error types for the PQCPrivacy crate.
//!
//! All modules surface errors through [`PrivacyError`], enabling
//! composable error handling across the full framework.

extern crate alloc;
use alloc::string::{String, ToString};

use thiserror::Error;

/// Top-level error type for the PQCPrivacy framework.
#[derive(Debug, Error)]
pub enum PrivacyError {
    // ── Hypergraph ─────────────────────────────────────────
    #[error("Hypergraph vertex not found: {0}")]
    VertexNotFound(String),
    #[error("Hyperedge formation failed: CHSH bound not satisfied (got {got:.4}, need >{threshold:.4})")]
    ChshBoundViolation { got: f64, threshold: f64 },
    #[error("Manifold dimension out of range: {0}")]
    InvalidDimension(usize),

    // ── ZK Primitives ────────────────────────────
    #[error("ZK proof generation failed: {0}")]
    ProofGenerationFailed(String),
    #[error("ZK proof verification failed")]
    ProofVerificationFailed,
    #[error("Public inputs do not match proof")]
    PublicInputMismatch,
    #[error("Invalid proof encoding")]
    InvalidProofEncoding,
    #[error("Recursive aggregation depth exceeded: {0}")]
    AggregationDepthExceeded(usize),
    #[error("Entanglement CHSH violation not achieved: {0:.4}")]
    EntanglementFailed(f64),

    // ── Chaos ────────────────────────────────────
    #[error("Chaos attractor stalled (Lyapunov exponent {0:.4} < 4.5)")]
    AttractorStalled(f64),
    #[error("Chaos oracle entropy quality check failed: H_min={0:.4}")]
    EntropyQualityFailed(f64),
    #[error("Both Chua and Rössler attractors stalled")]
    AllAttractorsStalled,

    // ── Differential Privacy ─────────────────────────────
    #[error("Privacy budget exhausted: ε={epsilon:.6} > limit={limit:.6}")]
    PrivacyBudgetExhausted { epsilon: f64, limit: f64 },
    #[error("Rényi composition overflow at α={alpha}")]
    RenyiCompositionOverflow { alpha: u32 },
    #[error("Invalid sensitivity value: {0}")]
    InvalidSensitivity(f64),

    // ── TupleChain Ledger ─────────────────────────────────
    #[error("Tuple expired at timestamp {0}")]
    TupleExpired(u64),
    #[error("Tuple not found: {0}")]
    TupleNotFound(String),
    #[error("Homomorphic operation failed: {0}")]
    HomomorphicOpFailed(String),
    #[error("Ledger anchor failed: {0}")]
    AnchorFailed(String),

    // ── QFKH Key Hopping ──────────────────────────────────
    #[error("Key hop interval exceeded: {elapsed_ms}ms > {limit_ms}ms")]
    KeyHopIntervalExceeded { elapsed_ms: u64, limit_ms: u64 },
    #[error("Ratchet state corrupted")]
    RatchetCorrupted,
    #[error("Key zeroization failed")]
    ZeroizationFailed,

    // ── Genomic / QTAID ──────────────────────────────
    #[error("SNP match below threshold: {matched}/{total} < {threshold}")]
    SnpMatchFailed { matched: u32, total: u32, threshold: u32 },
    #[error("Genomic token minting failed: {0}")]
    TokenMintFailed(String),
    #[error("Biometric revocation failed: {0}")]
    RevocationFailed(String),
    #[error("Invalid allele encoding: {0}")]
    InvalidAllele(String),

    // ── Mesh / DW3B ──────────────────────────────────
    #[error("Mesh node unreachable: {0}")]
    NodeUnreachable(String),
    #[error("Sphinx packet construction failed: {0}")]
    SphinxFailed(String),
    #[error("Bloom filter false positive rate exceeded: {0:.4}")]
    BloomFpExceeded(f64),
    #[error("Sybil attack detected: stake below threshold {0}")]
    SybilDetected(u64),
    #[error("Governance vote failed: {0}")]
    GovernanceFailed(String),
    #[error("Key distribution threshold not met: {got}/{needed}")]
    ThresholdNotMet { got: usize, needed: usize },
    #[error("Entropy elasticity scaling failed: {0}")]
    EntropyScalingFailed(String),

    // ── Sanctuary Vault ──────────────────────────────────
    #[error("FHE encryption failed: {0}")]
    FheEncryptionFailed(String),
    #[error("Shard reconstruction failed: {got}/{needed} shards")]
    ShardReconstructionFailed { got: usize, needed: usize },
    #[error("Vault access denied: {0}")]
    VaultAccessDenied(String),

    // ── Messenger ─────────────────────────────────────────
    #[error("P2P connection failed: {0}")]
    P2pConnectionFailed(String),
    #[error("Metadata obliteration failed: {0}")]
    MetadataObliterationFailed(String),

    // ── SCIF Viewer ───────────────────────────────────────
    #[error("Clearance proof failed: tier {required} required, got {got}")]
    ClearanceFailed { required: u8, got: u8 },
    #[error("FHE redaction failed: {0}")]
    RedactionFailed(String),

    // ── Interfaces UNI/UVI ────────────────────────────
    #[error("IBC routing failed: {0}")]
    IbcRoutingFailed(String),
    #[error("WASM circuit execution failed: {0}")]
    WasmExecutionFailed(String),
    #[error("Capability not found: {0}")]
    CapabilityNotFound(String),

    // ── Enclave / WAVEN ───────────────────────────────────
    #[error("Memory page access denied: key={key}, page={page}")]
    PageAccessDenied { key: u8, page: usize },
    #[error("Enclave attestation failed: {0}")]
    AttestationFailed(String),

    // ── Compression ───────────────────────────────────────
    #[error("Fractal IFS compression failed: {0}")]
    CompressionFailed(String),
    #[error("Decompression failed: {0}")]
    DecompressionFailed(String),

    // ── Serialization ────────────────────────────────────
    #[error("Icosuple serialization failed: size {size} > limit {limit}")]
    IcosupleTooBig { size: usize, limit: usize },
    #[error("Icosuple deserialization failed: {0}")]
    IcosupleDeserializeFailed(String),

    // ── Chronosync ────────────────────────────────────────
    #[error("Poset resolution conflict: {0}")]
    PosetConflict(String),
    #[error("Causal consistency violation: {0}")]
    CausalViolation(String),

    // ── Generic ───────────────────────────────────────────────────────────
    #[error("Encoding error: {0}")]
    EncodingError(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<serde_json::Error> for PrivacyError {
    fn from(e: serde_json::Error) -> Self {
        PrivacyError::SerializationError(e.to_string())
    }
}
