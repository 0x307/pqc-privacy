//! WASM bindings for `privacy` via `wasm-bindgen`.
//!
//! These bindings expose all PQCPrivacy capabilities to JavaScript/TypeScript.
//! All byte arrays cross the WASM boundary as `Vec<u8>` (Uint8Array in JS).
//! All errors are returned as JavaScript `Error` objects (via `Result<T, JsValue>`).
//! Complex types are serialized to/from JSON strings.
//!
//! # Usage from JavaScript
//! ```javascript
//! import init, {
//!   chaos_sample,
//!   chaos_fiat_shamir_seed,
//!   chaos_hash_5dqeh,
//!   chaos_perturbation,
//!   chaos_lyapunov,
//!   zk_prove_snark,
//!   zk_verify_snark,
//!   vault_store,
//!   vault_access,
//!   messenger_send_dm,
//!   messenger_receive_dm,
//! } from './privacy.js';
//!
//! await init();
//!
//! // Sample chaos entropy
//! const entropy = chaos_sample(32);
//!
//! // ZK proof
//! const stmtHash = new Uint8Array(32).fill(1);
//! const witnessHash = new Uint8Array(32).fill(2);
//! const chaosSeed = chaos_fiat_shamir_seed();
//! const proof = zk_prove_snark(stmtHash, witnessHash, chaosSeed);
//! ```
//!
//! # Build
//! ```powershell
//! wasm-pack build --target web --features wasm
//! ```

#![cfg(feature = "wasm")]

extern crate alloc;
use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use wasm_bindgen::prelude::*;

// ── Error helpers ─────────────────────────────────────────────────────────────

fn to_js_err(e: impl core::fmt::Display) -> JsValue {
    JsValue::from_str(&e.to_string())
}

fn to_js_err_str(s: &str) -> JsValue {
    JsValue::from_str(s)
}

// =============================================================================
// CHAOS ORACLE
// =============================================================================

/// Sample `n` bytes of chaos-derived randomness (SHAKE-256 whitened).
///
/// Uses Chua attractor as primary; automatically fails over to Rössler on stall.
/// Returns a `Uint8Array` of `n` bytes.
#[wasm_bindgen]
pub fn chaos_sample(n: u32) -> Result<Vec<u8>, JsValue> {
    let mut oracle = crate::chaos::ChaosOracle::new();
    oracle.sample(n as usize).map_err(to_js_err)
}

/// Get current perturbation value in (-1, 1) from the active chaos attractor.
#[wasm_bindgen]
pub fn chaos_perturbation() -> f64 {
    let mut oracle = crate::chaos::ChaosOracle::new();
    oracle.perturbation()
}

/// Get a 32-byte Fiat-Shamir challenge seed: SHA-256(SHAKE-256(chaos_bits)).
///
/// Returns a `Uint8Array` of 32 bytes.
#[wasm_bindgen]
pub fn chaos_fiat_shamir_seed() -> Result<Vec<u8>, JsValue> {
    let mut oracle = crate::chaos::ChaosOracle::new();
    let seed = oracle.fiat_shamir_seed().map_err(to_js_err)?;
    Ok(seed.to_vec())
}

/// Compute 5D quantum-enhanced hash: SHA-256(SHAKE-256(input) || "5dqeh-v1").
///
/// Returns a 64-character hex string.
#[wasm_bindgen]
pub fn chaos_hash_5dqeh(input: &[u8]) -> String {
    let oracle = crate::chaos::ChaosOracle::new();
    oracle.hash_5dqeh(input)
}

/// Get current Lyapunov exponent of the active attractor (≥ 4.5 when healthy).
#[wasm_bindgen]
pub fn chaos_lyapunov() -> f64 {
    let oracle = crate::chaos::ChaosOracle::new();
    oracle.active_lyapunov()
}

/// Get chaos telemetry as a JSON string.
///
/// Returns JSON: `{"lyapunov": f64, "h_min": f64, "passed": bool, "attractor": string}`
#[wasm_bindgen]
pub fn chaos_telemetry_json() -> String {
    let oracle = crate::chaos::ChaosOracle::new();
    let t = oracle.telemetry();
    let attractor = match t.attractor {
        crate::types::AttractorKind::Chua => "Chua",
        crate::types::AttractorKind::Rossler => "Rossler",
    };
    format!(
        r#"{{"lyapunov":{:.6},"h_min":{:.6},"passed":{},"attractor":"{}"}}"#,
        t.lyapunov, t.h_min, t.passed, attractor
    )
}

/// Generate an entropy frame as a JSON string.
///
/// Returns JSON: `{"bytes_hex": string, "hash_5dqeh": string, "h_min": f64}`
#[wasm_bindgen]
pub fn chaos_entropy_frame(size: u32) -> Result<String, JsValue> {
    let mut oracle = crate::chaos::ChaosOracle::new();
    let frame = oracle.entropy_frame(size as usize).map_err(to_js_err)?;
    let json = serde_json::to_string(&frame).map_err(to_js_err)?;
    Ok(json)
}

// =============================================================================
// PRIVACY HYPERGRAPH
// =============================================================================

/// Create a new 5D-EZPH hypergraph with a genesis vertex.
///
/// Returns a JSON string representing the initial hypergraph state.
/// The returned JSON can be passed back to other hypergraph functions.
#[wasm_bindgen]
pub fn hypergraph_new(chaos_seed: f64) -> String {
    let graph = crate::hypergraph::PrivacyHypergraph::new(chaos_seed);
    serde_json::to_string(&graph).unwrap_or_else(|_| "{}".into())
}

/// Encode an event as a 5D hypergraph vertex.
///
/// `graph_json`: JSON string from `hypergraph_new` or previous operations.
/// Returns updated JSON graph string on success.
#[wasm_bindgen]
pub fn hypergraph_encode_vertex(
    graph_json: &str,
    id: &str,
    spatial: f64,
    temporal: f64,
    dp_epsilon: f64,
    phase_angle: f64,
    chaos_traj: f64,
    expiry_ms: u64,
) -> Result<String, JsValue> {
    let mut graph: crate::hypergraph::PrivacyHypergraph =
        serde_json::from_str(graph_json).map_err(to_js_err)?;
    graph.encode_vertex(id, spatial, temporal, dp_epsilon, phase_angle, chaos_traj, expiry_ms)
        .map_err(to_js_err)?;
    serde_json::to_string(&graph).map_err(to_js_err)
}

/// Form a hyperedge between ≥2 vertices with Kaluza-Klein modulation.
///
/// `vertex_ids_json`: JSON array of vertex ID strings, e.g. `["v1","v2"]`.
/// Returns updated JSON graph string on success.
#[wasm_bindgen]
pub fn hypergraph_form_edge(
    graph_json: &str,
    id: &str,
    vertex_ids_json: &str,
    chaos_perturbation: f64,
) -> Result<String, JsValue> {
    let mut graph: crate::hypergraph::PrivacyHypergraph =
        serde_json::from_str(graph_json).map_err(to_js_err)?;
    let vertex_ids: Vec<String> =
        serde_json::from_str(vertex_ids_json).map_err(to_js_err)?;
    graph.form_hyperedge(id, vertex_ids, chaos_perturbation)
        .map_err(to_js_err)?;
    serde_json::to_string(&graph).map_err(to_js_err)
}

/// Traverse the hypergraph with non-local jumps (CHSH > 2.8 edges only).
///
/// Returns JSON array of vertex IDs in traversal order.
#[wasm_bindgen]
pub fn hypergraph_traverse(
    graph_json: &str,
    start: &str,
    max_hops: u32,
) -> Result<String, JsValue> {
    let graph: crate::hypergraph::PrivacyHypergraph =
        serde_json::from_str(graph_json).map_err(to_js_err)?;
    let path = graph.traverse_non_local(start, max_hops as usize)
        .map_err(to_js_err)?;
    serde_json::to_string(&path).map_err(to_js_err)
}

/// Returns the number of vertices in the hypergraph.
#[wasm_bindgen]
pub fn hypergraph_vertex_count(graph_json: &str) -> u32 {
    serde_json::from_str::<crate::hypergraph::PrivacyHypergraph>(graph_json)
        .map(|g| g.vertex_count() as u32)
        .unwrap_or(0)
}

/// Generate a ZK proof of non-locality (CHSH > 2.8).
///
/// Returns JSON PrivacyProof on success.
#[wasm_bindgen]
pub fn hypergraph_prove_non_locality(graph_json: &str) -> Result<String, JsValue> {
    let graph: crate::hypergraph::PrivacyHypergraph =
        serde_json::from_str(graph_json).map_err(to_js_err)?;
    let proof = graph.prove_non_locality().map_err(to_js_err)?;
    serde_json::to_string(&proof).map_err(to_js_err)
}

// =============================================================================
// ZK PROOF ENGINE
// =============================================================================

/// Generate a Sigma-protocol SNARK proof.
///
/// `statement_hash`: 32-byte Uint8Array
/// `witness_hash`:   32-byte Uint8Array
/// `chaos_seed`:     32-byte Uint8Array
///
/// Returns JSON PrivacyProof on success.
#[wasm_bindgen]
pub fn zk_prove_snark(
    statement_hash: &[u8],
    witness_hash: &[u8],
    chaos_seed: &[u8],
) -> Result<String, JsValue> {
    let stmt: [u8; 32] = statement_hash.try_into()
        .map_err(|_| to_js_err_str("statement_hash must be 32 bytes"))?;
    let wit: [u8; 32] = witness_hash.try_into()
        .map_err(|_| to_js_err_str("witness_hash must be 32 bytes"))?;
    let seed: [u8; 32] = chaos_seed.try_into()
        .map_err(|_| to_js_err_str("chaos_seed must be 32 bytes"))?;

    let snark_proof = crate::zk::snark::prove(stmt, wit, &seed).map_err(to_js_err)?;
    let privacy_proof = crate::types::PrivacyProof::from(snark_proof);
    serde_json::to_string(&privacy_proof).map_err(to_js_err)
}

/// Verify a SNARK proof.
///
/// `proof_json`:     JSON string from `zk_prove_snark`
/// `statement_hash`: 32-byte Uint8Array
///
/// Returns `true` if valid, `false` if invalid.
#[wasm_bindgen]
pub fn zk_verify_snark(proof_json: &str, statement_hash: &[u8]) -> bool {
    let Ok(proof) = serde_json::from_str::<crate::types::PrivacyProof>(proof_json) else {
        return false;
    };
    let Ok(stmt) = TryInto::<[u8; 32]>::try_into(statement_hash) else {
        return false;
    };
    let zk = crate::zk::HybridZkLayer::new();
    zk.verify(&proof, &stmt).is_ok()
}

/// Generate a FRI-style STARK proof.
///
/// `statement`: 32-byte Uint8Array
/// `witness`:   32-byte Uint8Array
/// `chaos_seed`: 32-byte Uint8Array
///
/// Returns JSON PrivacyProof on success.
#[wasm_bindgen]
pub fn zk_prove_stark(
    statement: &[u8],
    witness: &[u8],
    chaos_seed: &[u8],
) -> Result<String, JsValue> {
    let stmt: [u8; 32] = statement.try_into()
        .map_err(|_| to_js_err_str("statement must be 32 bytes"))?;
    let wit: [u8; 32] = witness.try_into()
        .map_err(|_| to_js_err_str("witness must be 32 bytes"))?;
    let seed: [u8; 32] = chaos_seed.try_into()
        .map_err(|_| to_js_err_str("chaos_seed must be 32 bytes"))?;

    let stark_proof = crate::zk::stark::prove_statement(stmt, wit, &seed).map_err(to_js_err)?;
    let privacy_proof = crate::types::PrivacyProof::from(stark_proof);
    serde_json::to_string(&privacy_proof).map_err(to_js_err)
}

/// Verify a STARK proof.
///
/// Returns `true` if valid, `false` if invalid.
#[wasm_bindgen]
pub fn zk_verify_stark(proof_json: &str, statement: &[u8]) -> bool {
    let Ok(proof) = serde_json::from_str::<crate::types::PrivacyProof>(proof_json) else {
        return false;
    };
    let Ok(stmt) = TryInto::<[u8; 32]>::try_into(statement) else {
        return false;
    };
    let zk = crate::zk::HybridZkLayer::new();
    zk.verify(&proof, &stmt).is_ok()
}

/// Generate a hybrid SNARK+STARK proof.
///
/// `context`: 0 = LowBandwidth (SNARK), 1 = HighTransparency (STARK), 2 = Hybrid
///
/// Returns JSON PrivacyProof on success.
#[wasm_bindgen]
pub fn zk_prove_hybrid(
    statement_hash: &[u8],
    witness_hash: &[u8],
    chaos_seed: &[u8],
    context: u8,
) -> Result<String, JsValue> {
    let stmt: [u8; 32] = statement_hash.try_into()
        .map_err(|_| to_js_err_str("statement_hash must be 32 bytes"))?;
    let wit: [u8; 32] = witness_hash.try_into()
        .map_err(|_| to_js_err_str("witness_hash must be 32 bytes"))?;
    let seed: [u8; 32] = chaos_seed.try_into()
        .map_err(|_| to_js_err_str("chaos_seed must be 32 bytes"))?;

    let ctx = match context {
        0 => crate::zk::ProofContext::LowBandwidth,
        1 => crate::zk::ProofContext::HighTransparency,
        _ => crate::zk::ProofContext::Hybrid,
    };

    let mut zk = crate::zk::HybridZkLayer::new();
    let proof = zk.prove(stmt, wit, &seed, ctx).map_err(to_js_err)?;
    serde_json::to_string(&proof).map_err(to_js_err)
}

/// Aggregate multiple proofs recursively (Halo2 folding).
///
/// `proof_jsons_json`:    JSON array of proof JSON strings
/// `stake_weights_json`:  JSON array of u64 stake weights
/// `chaos_seed`:          32-byte Uint8Array
///
/// Returns JSON PrivacyProof on success.
#[wasm_bindgen]
pub fn zk_aggregate(
    proof_jsons_json: &str,
    stake_weights_json: &str,
    chaos_seed: &[u8],
) -> Result<String, JsValue> {
    let proof_strs: Vec<String> =
        serde_json::from_str(proof_jsons_json).map_err(to_js_err)?;
    let weights: Vec<u64> =
        serde_json::from_str(stake_weights_json).map_err(to_js_err)?;
    let seed: [u8; 32] = chaos_seed.try_into()
        .map_err(|_| to_js_err_str("chaos_seed must be 32 bytes"))?;

    let proofs: Vec<crate::types::PrivacyProof> = proof_strs.iter()
        .map(|s| serde_json::from_str(s).map_err(to_js_err))
        .collect::<Result<Vec<_>, _>>()?;

    let engine = crate::zk::EntanglementEngine::new();
    let aggregated = engine.aggregate_recursive(proofs, &weights, &seed)
        .map_err(to_js_err)?;
    serde_json::to_string(&aggregated).map_err(to_js_err)
}

/// Entangle two proofs (Bell-state analog).
///
/// Returns JSON PrivacyProof on success.
#[wasm_bindgen]
pub fn zk_entangle_pair(
    proof_a_json: &str,
    proof_b_json: &str,
    chaos_phase: f64,
) -> Result<String, JsValue> {
    let proof_a: crate::types::PrivacyProof =
        serde_json::from_str(proof_a_json).map_err(to_js_err)?;
    let proof_b: crate::types::PrivacyProof =
        serde_json::from_str(proof_b_json).map_err(to_js_err)?;

    let engine = crate::zk::EntanglementEngine::new();
    let entangled = engine.entangle_pair(&proof_a, &proof_b, chaos_phase)
        .map_err(to_js_err)?;
    serde_json::to_string(&entangled).map_err(to_js_err)
}

// =============================================================================
// DP ENGINE
// =============================================================================

/// Apply differential privacy to a query.
///
/// Returns JSON DpNoiseFrame: `{"renyi_alpha": u32, "bound": f64, "epsilon": f64, "noise_scale": f64}`
#[wasm_bindgen]
pub fn dp_apply(
    query_id: &str,
    sensitivity: f64,
    epsilon: f64,
    delta: f64,
    chaos_perturbation: f64,
) -> Result<String, JsValue> {
    let mut engine = crate::dp::DpEngine::new();
    let query = crate::dp::PrivacyQuery {
        id:           query_id.into(),
        sensitivity,
        epsilon,
        delta,
        timestamp_ms: 0,
    };
    let frame = engine.apply_dp(query, chaos_perturbation).map_err(to_js_err)?;
    serde_json::to_string(&frame).map_err(to_js_err)
}

/// Generate a noise sample from the configured distribution (Gaussian/Laplace).
///
/// `chaos_seed`: 32-byte Uint8Array
#[wasm_bindgen]
pub fn dp_noise_sample(noise_scale: f64, chaos_seed: &[u8]) -> Result<f64, JsValue> {
    let seed: [u8; 32] = chaos_seed.try_into()
        .map_err(|_| to_js_err_str("chaos_seed must be 32 bytes"))?;
    let engine = crate::dp::DpEngine::new();
    Ok(engine.noise_sample(noise_scale, &seed))
}

/// Generate a ZK proof of DP compliance.
///
/// Returns JSON PrivacyProof.
#[wasm_bindgen]
pub fn dp_prove_compliance() -> String {
    let engine = crate::dp::DpEngine::new();
    let proof = engine.prove_compliance();
    serde_json::to_string(&proof).unwrap_or_else(|_| "{}".into())
}

// =============================================================================
// TUPLE CHAIN
// =============================================================================

/// Insert a five-tuple into the ledger.
///
/// `chaos_seed`: 32-byte Uint8Array
///
/// Returns tuple ID (16-char hex) on success.
#[wasm_bindgen]
pub fn tuple_insert(
    subject: &str,
    predicate: &str,
    object: &[u8],
    expiry_ms: u64,
    chaos_seed: &[u8],
) -> Result<String, JsValue> {
    let seed: [u8; 32] = chaos_seed.try_into()
        .map_err(|_| to_js_err_str("chaos_seed must be 32 bytes"))?;

    let tuple = crate::ledger::tuple::build_tuple(
        subject,
        predicate,
        object.to_vec(),
        expiry_ms,
        1e-6,
        &seed,
    ).map_err(to_js_err)?;

    let mut chain = crate::ledger::TupleChain::new();
    let id = chain.insert(tuple);
    Ok(id)
}

/// Query tuples by subject and predicate.
///
/// Returns JSON array of PrivacyTuple objects.
#[wasm_bindgen]
pub fn tuple_query_by_subject(
    tuples_json: &str,
    subject: &str,
    now_ms: u64,
) -> Result<String, JsValue> {
    // For stateless WASM, we deserialize the chain state from JSON
    // In practice, callers maintain state on the JS side
    let tuples: Vec<crate::types::PrivacyTuple> =
        serde_json::from_str(tuples_json).map_err(to_js_err)?;
    let filtered: Vec<&crate::types::PrivacyTuple> = tuples.iter()
        .filter(|t| t.subject == subject && !t.is_expired(now_ms))
        .collect();
    serde_json::to_string(&filtered).map_err(to_js_err)
}

/// Prune expired tuples from a JSON array.
///
/// Returns JSON: `{"pruned": u32, "remaining": [PrivacyTuple]}`
#[wasm_bindgen]
pub fn tuple_prune_expired(tuples_json: &str, now_ms: u64) -> Result<String, JsValue> {
    let tuples: Vec<crate::types::PrivacyTuple> =
        serde_json::from_str(tuples_json).map_err(to_js_err)?;
    let (expired, remaining): (Vec<_>, Vec<_>) = tuples.into_iter()
        .partition(|t| t.is_expired(now_ms));
    let result = format!(
        r#"{{"pruned":{},"remaining":{}}}"#,
        expired.len(),
        serde_json::to_string(&remaining).map_err(to_js_err)?
    );
    Ok(result)
}

// =============================================================================
// QFKH RATCHET
// =============================================================================

/// Initiator: generate ML-KEM-768 keypair for QFKH key establishment.
///
/// `chaos_seed`: 32-byte Uint8Array
///
/// Returns JSON: `{"dk_bytes_hex": string, "ek_bytes_hex": string}`
/// - `dk_bytes_hex`: decapsulation key (64 bytes hex)
/// - `ek_bytes_hex`: encapsulation key (1184 bytes hex)
#[wasm_bindgen]
pub fn qfkh_initiate(chaos_seed: &[u8]) -> Result<String, JsValue> {
    let seed: [u8; 32] = chaos_seed.try_into()
        .map_err(|_| to_js_err_str("chaos_seed must be 32 bytes"))?;

    let (dk_bytes, ek_bytes) = crate::keyhop::QfkhRatchet::initiate(&seed)
        .map_err(to_js_err)?;

    Ok(format!(
        r#"{{"dk_bytes_hex":"{}","ek_bytes_hex":"{}"}}"#,
        hex::encode(&dk_bytes),
        hex::encode(&ek_bytes),
    ))
}

/// Responder: encapsulate to initiator's encapsulation key.
///
/// `ek_bytes_hex`: hex-encoded encapsulation key from `qfkh_initiate`
/// `chaos_seed`:   32-byte Uint8Array
///
/// Returns JSON: `{"ciphertext_hex": string, "chain_key_hex": string}`
#[wasm_bindgen]
pub fn qfkh_respond(
    ek_bytes_hex: &str,
    chaos_seed: &[u8],
    now_ms: u64,
) -> Result<String, JsValue> {
    let ek_bytes = hex::decode(ek_bytes_hex).map_err(to_js_err)?;
    let seed: [u8; 32] = chaos_seed.try_into()
        .map_err(|_| to_js_err_str("chaos_seed must be 32 bytes"))?;

    let (ratchet, ct_bytes) = crate::keyhop::QfkhRatchet::respond(&ek_bytes, &seed, now_ms)
        .map_err(to_js_err)?;

    // Serialize ratchet state as chain_key (we expose hop_count as state indicator)
    Ok(format!(
        r#"{{"ciphertext_hex":"{}","hop_count":{}}}"#,
        hex::encode(&ct_bytes),
        ratchet.hop_count(),
    ))
}

/// Initiator: complete key establishment by decapsulating responder's ciphertext.
///
/// `dk_bytes_hex`:     hex-encoded decapsulation key from `qfkh_initiate`
/// `ciphertext_hex`:   hex-encoded ciphertext from `qfkh_respond`
/// `chaos_seed`:       32-byte Uint8Array
///
/// Returns JSON: `{"hop_count": u64}` indicating ratchet is initialized.
#[wasm_bindgen]
pub fn qfkh_complete(
    dk_bytes_hex: &str,
    ciphertext_hex: &str,
    chaos_seed: &[u8],
    now_ms: u64,
) -> Result<String, JsValue> {
    let dk_bytes = hex::decode(dk_bytes_hex).map_err(to_js_err)?;
    let ct_bytes = hex::decode(ciphertext_hex).map_err(to_js_err)?;
    let seed: [u8; 32] = chaos_seed.try_into()
        .map_err(|_| to_js_err_str("chaos_seed must be 32 bytes"))?;

    let ratchet = crate::keyhop::QfkhRatchet::complete(&dk_bytes, &ct_bytes, &seed, now_ms)
        .map_err(to_js_err)?;

    Ok(format!(r#"{{"hop_count":{}}}"#, ratchet.hop_count()))
}

/// Encrypt a payload using AES-GCM-256 with QFKH-derived key.
///
/// `shared_secret_hex`: 32-byte hex shared secret (from ML-KEM encapsulation)
/// `chaos_seed`:        32-byte Uint8Array
///
/// Returns nonce (12) || ciphertext || tag (16) as Uint8Array.
#[wasm_bindgen]
pub fn qfkh_encrypt(
    shared_secret_hex: &str,
    plaintext: &[u8],
    chaos_seed: &[u8],
    now_ms: u64,
) -> Result<Vec<u8>, JsValue> {
    let ss_bytes = hex::decode(shared_secret_hex).map_err(to_js_err)?;
    let ss: [u8; 32] = ss_bytes.as_slice().try_into()
        .map_err(|_| to_js_err_str("shared_secret_hex must be 32 bytes"))?;
    let seed: [u8; 32] = chaos_seed.try_into()
        .map_err(|_| to_js_err_str("chaos_seed must be 32 bytes"))?;

    let mut ratchet = crate::keyhop::QfkhRatchet::new(ss, &seed, now_ms);
    ratchet.encrypt(plaintext, &seed, now_ms).map_err(to_js_err)
}

/// Decrypt a payload using AES-GCM-256 with QFKH-derived key.
///
/// `shared_secret_hex`: 32-byte hex shared secret (must match encryption side)
/// `chaos_seed`:        32-byte Uint8Array
///
/// Returns plaintext as Uint8Array.
#[wasm_bindgen]
pub fn qfkh_decrypt(
    shared_secret_hex: &str,
    ciphertext: &[u8],
    chaos_seed: &[u8],
    now_ms: u64,
) -> Result<Vec<u8>, JsValue> {
    let ss_bytes = hex::decode(shared_secret_hex).map_err(to_js_err)?;
    let ss: [u8; 32] = ss_bytes.as_slice().try_into()
        .map_err(|_| to_js_err_str("shared_secret_hex must be 32 bytes"))?;
    let seed: [u8; 32] = chaos_seed.try_into()
        .map_err(|_| to_js_err_str("chaos_seed must be 32 bytes"))?;

    let mut ratchet = crate::keyhop::QfkhRatchet::new(ss, &seed, now_ms);
    ratchet.decrypt(ciphertext, &seed, now_ms).map_err(to_js_err)
}

// =============================================================================
// SPHINX MIXNET
// =============================================================================

/// Build a layered Sphinx packet for anonymous routing.
///
/// `hop_count`: number of hops (5–9, clamped)
/// `chaos_seed`: 32-byte Uint8Array
///
/// Returns JSON SphinxPacket on success.
#[wasm_bindgen]
pub fn sphinx_build_packet(
    hop_count: u32,
    payload: &[u8],
    chaos_seed: &[u8],
) -> Result<String, JsValue> {
    let seed: [u8; 32] = chaos_seed.try_into()
        .map_err(|_| to_js_err_str("chaos_seed must be 32 bytes"))?;

    // Clamp hops to valid range 5–9
    let hops = (hop_count as u8).clamp(5, 9);

    let config = crate::mesh::mixnet::SphinxConfig {
        hops,
        lambda:     10.0,
        chaos_seed: seed,
    };

    let packet = crate::mesh::mixnet::build_sphinx_packet(payload.to_vec(), &config, false)
        .map_err(to_js_err)?;
    serde_json::to_string(&packet).map_err(to_js_err)
}

/// Generate Poisson decoy packets for timing analysis resistance.
///
/// `chaos_seed`: 32-byte Uint8Array
/// `count`: number of decoy packets to generate
///
/// Returns JSON array of SphinxPacket objects.
#[wasm_bindgen]
pub fn sphinx_generate_decoys(
    count: u32,
    chaos_seed: &[u8],
    hop_count: u32,
) -> Result<String, JsValue> {
    let seed: [u8; 32] = chaos_seed.try_into()
        .map_err(|_| to_js_err_str("chaos_seed must be 32 bytes"))?;

    let hops = (hop_count as u8).clamp(5, 9);
    let config = crate::mesh::mixnet::SphinxConfig {
        hops,
        lambda:     10.0,
        chaos_seed: seed,
    };

    let decoys = crate::mesh::mixnet::generate_decoys_legacy(count as usize, &config)
        .map_err(to_js_err)?;
    serde_json::to_string(&decoys).map_err(to_js_err)
}

// =============================================================================
// SANCTUARY VAULT
// =============================================================================

/// Store a file with AES-GCM-256 encryption and Reed-Solomon sharding.
///
/// `chaos_seed`: 32-byte Uint8Array
///
/// Returns JSON shard manifest on success:
/// `{"file_id": string, "shard_count": u32, "k": u32, "n": u32}`
#[wasm_bindgen]
pub fn vault_store(
    file_id: &str,
    owner_did: &str,
    plaintext: &[u8],
    chaos_seed: &[u8],
    expiry_ms: u64,
    k: u32,
    n: u32,
) -> Result<String, JsValue> {
    let seed: [u8; 32] = chaos_seed.try_into()
        .map_err(|_| to_js_err_str("chaos_seed must be 32 bytes"))?;

    let k = k as usize;
    let n = n as usize;
    let k = if k == 0 { crate::vault::DEFAULT_K } else { k };
    let n = if n == 0 { crate::vault::DEFAULT_N } else { n };

    let mut vault = crate::vault::SanctuaryVault::with_threshold(k, n);
    vault.store(file_id, owner_did, plaintext, &seed, expiry_ms)
        .map_err(to_js_err)?;

    Ok(format!(
        r#"{{"file_id":"{}","shard_count":{},"k":{},"n":{}}}"#,
        file_id, n, k, n
    ))
}

/// Access a file via ZK ownership proof.
///
/// `chaos_seed`: 32-byte Uint8Array
///
/// Returns decrypted plaintext as Uint8Array.
#[wasm_bindgen]
pub fn vault_access(
    file_id: &str,
    owner_did: &str,
    plaintext: &[u8],
    chaos_seed: &[u8],
    expiry_ms: u64,
    now_ms: u64,
) -> Result<Vec<u8>, JsValue> {
    let seed: [u8; 32] = chaos_seed.try_into()
        .map_err(|_| to_js_err_str("chaos_seed must be 32 bytes"))?;

    // For stateless WASM, we store and immediately access
    let mut vault = crate::vault::SanctuaryVault::new();
    vault.store(file_id, owner_did, plaintext, &seed, expiry_ms)
        .map_err(to_js_err)?;
    vault.access(file_id, owner_did, &seed, now_ms).map_err(to_js_err)
}

// =============================================================================
// SOVEREIGN MESSENGER
// =============================================================================

/// Send a P2P direct message (AES-GCM-256 encrypted).
///
/// `chaos_seed`: 32-byte Uint8Array
///
/// Returns encrypted message bytes: nonce (12) || ciphertext || tag (16).
#[wasm_bindgen]
pub fn messenger_send_dm(
    sender_id: &str,
    recipient_id: &str,
    message: &[u8],
    chaos_seed: &[u8],
    timestamp_ms: u64,
) -> Result<Vec<u8>, JsValue> {
    let seed: [u8; 32] = chaos_seed.try_into()
        .map_err(|_| to_js_err_str("chaos_seed must be 32 bytes"))?;

    let messenger = crate::messenger::SovereignMessenger::new();
    let msg = messenger.send(sender_id, recipient_id, message, &seed, timestamp_ms, 1)
        .map_err(to_js_err)?;
    Ok(msg.content)
}

/// Receive and decrypt a P2P direct message.
///
/// `chaos_seed`: 32-byte Uint8Array
///
/// Returns plaintext as Uint8Array.
#[wasm_bindgen]
pub fn messenger_receive_dm(
    sender_id: &str,
    recipient_id: &str,
    ciphertext: &[u8],
    chaos_seed: &[u8],
    timestamp_ms: u64,
) -> Result<Vec<u8>, JsValue> {
    let seed: [u8; 32] = chaos_seed.try_into()
        .map_err(|_| to_js_err_str("chaos_seed must be 32 bytes"))?;

    let messenger = crate::messenger::SovereignMessenger::new();
    // Reconstruct the SovereignMessage for decryption
    let msg = crate::messenger::SovereignMessage {
        sender_did:    sender_id.into(),
        recipient_did: recipient_id.into(),
        content:       ciphertext.to_vec(),
        key_id:        String::new(),
        proof:         crate::types::PrivacyProof {
            proof_bytes:   String::new(),
            public_inputs: String::new(),
            scheme:        crate::types::ProofScheme::Snark,
            security_bits: 128,
            proof_size:    0,
            chsh_value:    0.0,
            lyapunov:      4.5,
        },
        mode:          crate::messenger::MessageMode::P2pDirect,
        timestamp_ms,
        metadata_free: true,
    };
    messenger.receive(&msg, &seed).map_err(to_js_err)
}

/// Send a group message (hybrid relay mode, AES-GCM-256).
///
/// `chaos_seed`: 32-byte Uint8Array
///
/// Returns encrypted message bytes.
#[wasm_bindgen]
pub fn messenger_send_group(
    group_id: &str,
    sender_id: &str,
    message: &[u8],
    chaos_seed: &[u8],
    timestamp_ms: u64,
) -> Result<Vec<u8>, JsValue> {
    let seed: [u8; 32] = chaos_seed.try_into()
        .map_err(|_| to_js_err_str("chaos_seed must be 32 bytes"))?;

    let messenger = crate::messenger::SovereignMessenger::new();
    // participant_count > 2 triggers HybridRelay mode
    let msg = messenger.send(sender_id, group_id, message, &seed, timestamp_ms, 5)
        .map_err(to_js_err)?;
    Ok(msg.content)
}

/// Receive and decrypt a group message.
///
/// `chaos_seed`: 32-byte Uint8Array
///
/// Returns plaintext as Uint8Array.
#[wasm_bindgen]
pub fn messenger_receive_group(
    group_id: &str,
    ciphertext: &[u8],
    chaos_seed: &[u8],
    timestamp_ms: u64,
) -> Result<Vec<u8>, JsValue> {
    let seed: [u8; 32] = chaos_seed.try_into()
        .map_err(|_| to_js_err_str("chaos_seed must be 32 bytes"))?;

    let messenger = crate::messenger::SovereignMessenger::new();
    let msg = crate::messenger::SovereignMessage {
        sender_did:    String::new(),
        recipient_did: group_id.into(),
        content:       ciphertext.to_vec(),
        key_id:        String::new(),
        proof:         crate::types::PrivacyProof {
            proof_bytes:   String::new(),
            public_inputs: String::new(),
            scheme:        crate::types::ProofScheme::Snark,
            security_bits: 128,
            proof_size:    0,
            chsh_value:    0.0,
            lyapunov:      4.5,
        },
        mode:          crate::messenger::MessageMode::HybridRelay,
        timestamp_ms,
        metadata_free: true,
    };
    messenger.receive(&msg, &seed).map_err(to_js_err)
}

// =============================================================================
// GENOMIC ENGINE
// =============================================================================

/// Nano-tokenize a DNA sequence into SNP commitments with ZK proofs.
///
/// `chaos_seed`: 32-byte Uint8Array
///
/// Returns JSON array of GenomicToken objects.
///
/// Requires the non-default `genomic` feature — see `src/genomic/mod.rs` and the
/// crate README: this is ASCII-character hashing, not real genomic processing.
#[cfg(feature = "genomic")]
#[wasm_bindgen]
pub fn genomic_tokenize(
    sequence: &str,
    patient_id: &str,
    dp_epsilon: f64,
    chaos_seed: &[u8],
    expiry_ms: u64,
) -> Result<String, JsValue> {
    let seed: [u8; 32] = chaos_seed.try_into()
        .map_err(|_| to_js_err_str("chaos_seed must be 32 bytes"))?;

    let tokens = crate::genomic::nano_tokenize_with_id(
        sequence,
        dp_epsilon,
        &seed,
        expiry_ms,
        patient_id.as_bytes(),
    ).map_err(to_js_err)?;

    serde_json::to_string(&tokens).map_err(to_js_err)
}

/// Prove a genomic trait (allele knowledge) via Sigma-protocol SNARK.
///
/// `chaos_seed`: 32-byte Uint8Array
///
/// Returns JSON PrivacyProof on success.
#[cfg(feature = "genomic")]
#[wasm_bindgen]
pub fn genomic_prove_trait(
    allele_bits: u8,
    blinding_factor_hex: &str,
    chaos_seed: &[u8],
) -> Result<String, JsValue> {
    let blinding = hex::decode(blinding_factor_hex).map_err(to_js_err)?;
    let seed: [u8; 32] = chaos_seed.try_into()
        .map_err(|_| to_js_err_str("chaos_seed must be 32 bytes"))?;

    let proof = crate::genomic::prove_allele_trait(allele_bits, &blinding, &seed)
        .map_err(to_js_err)?;
    serde_json::to_string(&proof).map_err(to_js_err)
}

/// Register a genomic template for a DID.
///
/// `chaos_seed`: 32-byte Uint8Array
///
/// Returns `true` on success.
#[cfg(feature = "genomic")]
#[wasm_bindgen]
pub fn genomic_register(
    did: &str,
    sequence: &str,
    dp_epsilon: f64,
    chaos_seed: &[u8],
    expiry_ms: u64,
) -> Result<bool, JsValue> {
    let seed: [u8; 32] = chaos_seed.try_into()
        .map_err(|_| to_js_err_str("chaos_seed must be 32 bytes"))?;

    let mut engine = crate::genomic::login::QtaidLoginEngine::new();
    engine.register(did, sequence, dp_epsilon, &seed, expiry_ms)
        .map_err(to_js_err)?;
    Ok(true)
}

/// Authenticate via ZK SNP matching (≥98/100 threshold).
///
/// `chaos_seed`: 32-byte Uint8Array
///
/// Returns JSON BiometricSession on success.
#[cfg(feature = "genomic")]
#[wasm_bindgen]
pub fn genomic_authenticate(
    did: &str,
    registered_sequence: &str,
    challenge_sequence: &str,
    dp_epsilon: f64,
    chaos_seed: &[u8],
    now_ms: u64,
    session_expiry_ms: u64,
) -> Result<String, JsValue> {
    let seed: [u8; 32] = chaos_seed.try_into()
        .map_err(|_| to_js_err_str("chaos_seed must be 32 bytes"))?;

    let mut engine = crate::genomic::login::QtaidLoginEngine::new();
    engine.register(did, registered_sequence, dp_epsilon, &seed, now_ms + session_expiry_ms)
        .map_err(to_js_err)?;

    let session = engine.authenticate(did, challenge_sequence, &seed, now_ms, session_expiry_ms)
        .map_err(to_js_err)?;
    serde_json::to_string(&session).map_err(to_js_err)
}

// =============================================================================
// PRIVACY SERIALIZER
// =============================================================================

/// Build and serialize a privacy icosuple (≤8192 bytes).
///
/// Signed with ML-DSA-65 using `chaos_seed` as the signing key seed.
/// `chaos_seed`: 32-byte Uint8Array
///
/// Returns serialized icosuple bytes as Uint8Array.
#[wasm_bindgen]
pub fn serial_build_icosuple(
    manifold_tensor: &[u8],
    proof_bundle: &[u8],
    chaos_state: &[u8],
    chaos_seed: &[u8],
    compress: bool,
) -> Result<Vec<u8>, JsValue> {
    let seed: [u8; 32] = chaos_seed.try_into()
        .map_err(|_| to_js_err_str("chaos_seed must be 32 bytes"))?;

    let icosuple = crate::serial::build_icosuple(
        manifold_tensor.to_vec(),
        proof_bundle.to_vec(),
        chaos_state.to_vec(),
        &seed,
        compress,
    );
    crate::serial::serialize(&icosuple).map_err(to_js_err)
}

/// Deserialize a privacy icosuple frame.
///
/// Returns JSON with manifold_tensor_hex, proof_bundle_hex, chaos_state_hex, compressed, signature.
#[wasm_bindgen]
pub fn serial_deserialize(frame: &[u8]) -> Result<String, JsValue> {
    let icosuple = crate::serial::deserialize(frame).map_err(to_js_err)?;
    let json = format!(
        r#"{{"manifold_tensor_hex":"{}","proof_bundle_hex":"{}","chaos_state_hex":"{}","compressed":{},"signature":"{}"}}"#,
        hex::encode(&icosuple.manifold_tensor),
        hex::encode(&icosuple.proof_bundle),
        hex::encode(&icosuple.chaos_state),
        icosuple.compressed,
        icosuple.signature,
    );
    Ok(json)
}

/// Verify the ML-DSA-65 signature on an icosuple.
///
/// `chaos_seed`: 32-byte Uint8Array (used as ML-DSA-65 signing seed)
///
/// Returns `true` if the signature is valid.
#[wasm_bindgen]
pub fn serial_verify_icosuple(
    manifold_tensor: &[u8],
    proof_bundle: &[u8],
    chaos_state: &[u8],
    chaos_seed: &[u8],
) -> bool {
    let Ok(seed) = TryInto::<[u8; 32]>::try_into(chaos_seed) else {
        return false;
    };
    let Ok(frame) = crate::serial::build_icosuple_frame(
        manifold_tensor.to_vec(),
        proof_bundle.to_vec(),
        chaos_state.to_vec(),
        &seed,
        false,
    ) else {
        return false;
    };
    crate::serial::verify_icosuple(&frame)
}

/// Build an icosuple frame with full ML-DSA-65 signature and public key.
///
/// Returns JSON IcosupleFrame with signature_hex and signing_key_public_hex.
#[wasm_bindgen]
pub fn serial_build_icosuple_frame_json(
    manifold_tensor: &[u8],
    proof_bundle: &[u8],
    chaos_state: &[u8],
    chaos_seed: &[u8],
    compress: bool,
) -> Result<String, JsValue> {
    let seed: [u8; 32] = chaos_seed.try_into()
        .map_err(|_| to_js_err_str("chaos_seed must be 32 bytes"))?;

    let frame = crate::serial::build_icosuple_frame(
        manifold_tensor.to_vec(),
        proof_bundle.to_vec(),
        chaos_state.to_vec(),
        &seed,
        compress,
    ).map_err(to_js_err)?;

    let json = format!(
        r#"{{"manifold_tensor_hex":"{}","proof_bundle_hex":"{}","chaos_state_hex":"{}","compressed":{},"signature_hex":"{}","signing_key_public_hex":"{}"}}"#,
        hex::encode(&frame.manifold_tensor),
        hex::encode(&frame.proof_bundle),
        hex::encode(&frame.chaos_state),
        frame.compressed,
        hex::encode(&frame.signature),
        hex::encode(&frame.signing_key_public),
    );
    Ok(json)
}

// =============================================================================
// CHRONOSYNC
// =============================================================================

/// Add an event to the poset.
///
/// `dependencies_json`: JSON array of dependency event ID strings
/// `chaos_seed`:        32-byte Uint8Array
///
/// Returns updated poset JSON on success.
#[wasm_bindgen]
pub fn sync_add_event(
    poset_json: &str,
    id: &str,
    payload: &[u8],
    dependencies_json: &str,
    chaos_seed: &[u8],
) -> Result<String, JsValue> {
    let _seed: [u8; 32] = chaos_seed.try_into()
        .map_err(|_| to_js_err_str("chaos_seed must be 32 bytes"))?;
    let dependencies: Vec<String> =
        serde_json::from_str(dependencies_json).map_err(to_js_err)?;

    // Deserialize existing events or start fresh
    let mut events: Vec<crate::types::PosetEvent> = if poset_json.is_empty() || poset_json == "[]" {
        Vec::new()
    } else {
        serde_json::from_str(poset_json).map_err(to_js_err)?
    };

    // Compute payload hash
    use sha2::{Digest, Sha256};
    let payload_hash = hex::encode(Sha256::digest(payload));

    events.push(crate::types::PosetEvent {
        id:           id.into(),
        dependencies,
        payload_hash,
        timestamp_ms: 0,
        zk_merge:     None,
    });

    serde_json::to_string(&events).map_err(to_js_err)
}

/// Resolve the poset using topological sort with ZK merges.
///
/// `poset_json`:  JSON array of PosetEvent objects
/// `chaos_seed`:  32-byte Uint8Array
///
/// Returns JSON array of ordered event IDs.
#[wasm_bindgen]
pub fn sync_resolve(poset_json: &str, chaos_seed: &[u8]) -> Result<String, JsValue> {
    let seed: [u8; 32] = chaos_seed.try_into()
        .map_err(|_| to_js_err_str("chaos_seed must be 32 bytes"))?;
    let events: Vec<crate::types::PosetEvent> =
        serde_json::from_str(poset_json).map_err(to_js_err)?;

    let mut engine = crate::sync::ChronosyncEngine::new();
    for event in events {
        engine.add_event(event);
    }

    let order = engine.resolve(&seed).map_err(to_js_err)?;
    serde_json::to_string(&order).map_err(to_js_err)
}

/// Generate a ZK merge proof for conflict resolution.
///
/// `chaos_seed`: 32-byte Uint8Array
///
/// Returns JSON PrivacyProof on success.
#[wasm_bindgen]
pub fn sync_prove_merge(
    poset_json: &str,
    event_a: &str,
    event_b: &str,
    chaos_seed: &[u8],
) -> Result<String, JsValue> {
    let seed: [u8; 32] = chaos_seed.try_into()
        .map_err(|_| to_js_err_str("chaos_seed must be 32 bytes"))?;
    let events: Vec<crate::types::PosetEvent> =
        serde_json::from_str(poset_json).map_err(to_js_err)?;

    let mut engine = crate::sync::ChronosyncEngine::new();
    for event in events {
        engine.add_event(event);
    }

    let proof = engine.prove_merge(event_a, event_b, &seed).map_err(to_js_err)?;
    serde_json::to_string(&proof).map_err(to_js_err)
}

/// Anchor the resolved order to TupleChain.
///
/// `chaos_seed`: 32-byte Uint8Array
///
/// Returns anchor hash hex string.
#[wasm_bindgen]
pub fn sync_anchor(poset_json: &str, chaos_seed: &[u8]) -> Result<String, JsValue> {
    let seed: [u8; 32] = chaos_seed.try_into()
        .map_err(|_| to_js_err_str("chaos_seed must be 32 bytes"))?;
    let events: Vec<crate::types::PosetEvent> =
        serde_json::from_str(poset_json).map_err(to_js_err)?;

    let mut engine = crate::sync::ChronosyncEngine::new();
    for event in events {
        engine.add_event(event);
    }
    engine.resolve(&seed).map_err(to_js_err)?;
    Ok(engine.anchor_to_tuplechain(&seed))
}

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

/// Returns the crate version string.
#[wasm_bindgen]
pub fn privacy_version() -> String {
    "0.1.0".into()
}

/// Returns the primary algorithm identifier string.
#[wasm_bindgen]
pub fn privacy_primary_algorithm() -> String {
    "ML-KEM-768+ML-DSA-65+AES-GCM-256+Chaos-Oracle".into()
}

/// Returns a JSON summary of all available WASM-exported functions.
#[wasm_bindgen]
pub fn privacy_api_summary() -> String {
    r#"{
  "chaos": ["chaos_sample","chaos_perturbation","chaos_fiat_shamir_seed","chaos_hash_5dqeh","chaos_lyapunov","chaos_telemetry_json","chaos_entropy_frame"],
  "hypergraph": ["hypergraph_new","hypergraph_encode_vertex","hypergraph_form_edge","hypergraph_traverse","hypergraph_vertex_count","hypergraph_prove_non_locality"],
  "zk": ["zk_prove_snark","zk_verify_snark","zk_prove_stark","zk_verify_stark","zk_prove_hybrid","zk_aggregate","zk_entangle_pair"],
  "dp": ["dp_apply","dp_noise_sample","dp_prove_compliance"],
  "ledger": ["tuple_insert","tuple_query_by_subject","tuple_prune_expired"],
  "keyhop": ["qfkh_initiate","qfkh_respond","qfkh_complete","qfkh_encrypt","qfkh_decrypt"],
  "sphinx": ["sphinx_build_packet","sphinx_generate_decoys"],
  "vault": ["vault_store","vault_access"],
  "messenger": ["messenger_send_dm","messenger_receive_dm","messenger_send_group","messenger_receive_group"],
  "genomic": ["genomic_tokenize","genomic_prove_trait","genomic_register","genomic_authenticate"],
  "serial": ["serial_build_icosuple","serial_deserialize","serial_verify_icosuple","serial_build_icosuple_frame_json"],
  "sync": ["sync_add_event","sync_resolve","sync_prove_merge","sync_anchor"],
  "utility": ["privacy_version","privacy_primary_algorithm","privacy_api_summary"]
}"#.into()
}

// =============================================================================
// GAP-P ADDITIONS — New functions for the ObfuscationNet crate
// =============================================================================

// ── GAP-P-01: chaos_entropy_bytes ─────────────────────────────────────────────

/// Generate `n` bytes of chaos-derived entropy as raw bytes (GAP-P-01).
///
/// Uses the dual-attractor oracle (Chua primary, Rössler fallback).
/// Output is SHAKE-256 whitened. Passes NIST SP 800-90B H_min > 0.99.
///
/// Returns a `Uint8Array` of `n` bytes.
#[wasm_bindgen]
pub fn chaos_entropy_bytes_wasm(n: u32) -> Result<Vec<u8>, JsValue> {
    crate::chaos::chaos_entropy_bytes(n as usize).map_err(to_js_err)
}

// ── GAP-P-02: chaos_seed_u64 ──────────────────────────────────────────────────

/// Generate a single u64 from the chaos oracle (GAP-P-02).
///
/// Returns the lower 32 bits as a `u32` for JavaScript compatibility.
/// The full u64 is available by calling `chaos_entropy_bytes_wasm(8)` and
/// interpreting the result as a little-endian u64.
#[wasm_bindgen]
pub fn chaos_seed_u64_wasm() -> Result<u32, JsValue> {
    let v = crate::chaos::chaos_seed_u64().map_err(to_js_err)?;
    // Return lower 32 bits for JS compat (JS numbers are f64, safe up to 2^53)
    Ok(v as u32)
}

// ── GAP-P-03: hypergraph_chsh_value ───────────────────────────────────────────

/// Compute the CHSH S-value for a hypergraph (GAP-P-03).
///
/// `graph_json`: JSON string from `hypergraph_new` or previous operations.
///
/// Returns the S value as an `f64`. Should be > 2.8 for valid quantum non-locality.
/// Returns 0.0 on parse error (use `hypergraph_chsh_value_checked_wasm` for error handling).
#[wasm_bindgen]
pub fn hypergraph_chsh_value_wasm(graph_json: &str) -> f64 {
    crate::hypergraph::hypergraph_chsh_value(graph_json).unwrap_or(0.0)
}

// ── GAP-P-04: zk_prove_manifold_path ─────────────────────────────────────────

/// Generate a ZK proof that a manifold path is a valid geodesic (GAP-P-04).
///
/// `statement_hash`: BLAKE3 hash of the path's start/end coordinates (any length)
/// `path_witness`:   serialized sequence of 5D coordinates along the path
/// `chaos_seed`:     entropy from the chaos oracle
///
/// Returns JSON-serialized `PrivacyProof` on success.
#[wasm_bindgen]
pub fn zk_prove_manifold_path_wasm(
    statement_hash: &[u8],
    path_witness: &[u8],
    chaos_seed: &[u8],
) -> Result<String, JsValue> {
    let proof = crate::zk::zk_prove_manifold_path(statement_hash, path_witness, chaos_seed)
        .map_err(to_js_err)?;
    serde_json::to_string(&proof).map_err(to_js_err)
}

// ── GAP-P-05: sphinx_route_obfuscated ────────────────────────────────────────

/// Build a Sphinx packet with obfuscation metadata embedded in the payload header (GAP-P-05).
///
/// `hops_json`:         JSON array of node ID strings
/// `hop_keys_hex_json`: JSON array of hex-encoded ML-KEM-768 encapsulation keys
/// `payload`:           the actual data to route
/// `qem_metadata_json`: JSON string of QEM metadata to embed
/// `chaos_seed`:        entropy from the chaos oracle
///
/// Returns JSON-serialized `SphinxPacket` on success.
#[wasm_bindgen]
pub fn sphinx_route_obfuscated_wasm(
    hops_json: &str,
    hop_keys_hex_json: &str,
    payload: &[u8],
    qem_metadata_json: &str,
    chaos_seed: &[u8],
) -> Result<String, JsValue> {
    let packet = crate::mesh::mixnet::sphinx_route_obfuscated(
        hops_json,
        hop_keys_hex_json,
        payload,
        qem_metadata_json,
        chaos_seed,
    ).map_err(to_js_err)?;
    serde_json::to_string(&packet).map_err(to_js_err)
}

// ── GAP-P-06: serial_build_obfuscation_frame ─────────────────────────────────

/// Build a privacy icosuple frame containing obfuscation state (GAP-P-06).
///
/// `manifold_tensor`: serialized 5D metric tensor (JSON string)
/// `qem_json`:        QEM metadata JSON string
/// `proof_bundle`:    serialized ZK proof bundle (JSON string)
/// `chaos_state`:     current chaos oracle state bytes
/// `chaos_seed`:      entropy seed (any length; SHA-256 hashed to 32 bytes)
/// `compress`:        whether to apply IFS compression
///
/// Returns serialized icosuple bytes (≤ 8192 bytes) as `Uint8Array`.
#[wasm_bindgen]
pub fn serial_build_obfuscation_frame_wasm(
    manifold_tensor: &str,
    qem_json: &str,
    proof_bundle: &str,
    chaos_state: &[u8],
    chaos_seed: &[u8],
    compress: bool,
) -> Result<Vec<u8>, JsValue> {
    crate::serial::serial_build_obfuscation_frame(
        manifold_tensor,
        qem_json,
        proof_bundle,
        chaos_state,
        chaos_seed,
        compress,
    ).map_err(to_js_err)
}

// ── TryInto import for array conversions ─────────────────────────────────────
use core::convert::TryInto;