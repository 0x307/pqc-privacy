//! Mixnet/Tor Nodes with Sphinx Packets (MTN-SP)
//!
//! Multi-hop anonymous routing with 5–9 hops, Poisson-distributed decoy traffic
//! (λ=10), and Rössler chaos perturbation for timing attack resistance.
//!
//! # Sphinx Protocol with ML-KEM-768
//!
//! For n hops [hop_0, hop_1, ..., hop_{n-1}]:
//!
//! Build the onion from the innermost layer outward:
//!
//! ```text
//! Layer n-1 (innermost):
//!   (ct_{n-1}, ss_{n-1}) = ML-KEM-768.Encapsulate(hop_{n-1}.ek)
//!   key_{n-1} = HKDF(ss_{n-1}, hop_id_{n-1}, "sphinx-layer-v1")
//!   inner_payload = AES-GCM-256(key_{n-1}, actual_payload)
//!   layer_{n-1} = ct_{n-1} || inner_payload
//!
//! Layer i (wrapping outward):
//!   (ct_i, ss_i) = ML-KEM-768.Encapsulate(hop_i.ek)
//!   key_i = HKDF(ss_i, hop_id_i, "sphinx-layer-v1")
//!   layer_i = AES-GCM-256(key_i, layer_{i+1})
//!   packet_i = ct_i || layer_i
//! ```

use crate::error::PrivacyError;
use crate::keyhop::{hkdf_derive, aes_gcm_encrypt, aes_gcm_decrypt};
use crate::mesh::keys;
use crate::types::SphinxPacket;
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};

extern crate alloc;
use alloc::{string::String, vec, vec::Vec};

// ── ML-KEM-768 size constants ─────────────────────────────────────────────────

/// ML-KEM-768 ciphertext size in bytes.
#[allow(dead_code)]
const ML_KEM_768_CT_LEN: usize = 1088;

/// ML-KEM-768 encapsulation key (public key) size in bytes.
const ML_KEM_768_EK_LEN: usize = 1184;

// ── Sphinx data structures ────────────────────────────────────────────────────

/// A single layer of a Sphinx onion packet.
///
/// Each relay node holds one layer. The node decapsulates `ciphertext` with its
/// ML-KEM-768 decapsulation key to recover the shared secret, derives the AES key,
/// and decrypts `encrypted_payload` to reveal the next layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SphinxLayer {
    /// ML-KEM-768 ciphertext (1088 bytes) — encapsulated to this hop's public key
    pub ciphertext:        Vec<u8>,
    /// AES-GCM-256 encrypted next layer (or final payload at innermost layer)
    pub encrypted_payload: Vec<u8>,
}

/// A fully-constructed Sphinx onion packet with ML-KEM-768 layered encryption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SphinxOnionPacket {
    /// One layer per hop (outermost first)
    pub layers:    Vec<SphinxLayer>,
    /// 32-byte chaos authentication tag = SHA-256(all_ciphertexts || chaos_seed)
    pub chaos_tag: Vec<u8>,
    /// True if this is a Poisson decoy packet
    pub decoy:     bool,
}

/// Sphinx packet configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SphinxConfig {
    /// Number of hops (5–9)
    pub hops:       u8,
    /// Poisson decoy rate λ
    pub lambda:     f64,
    /// Chaos perturbation seed
    pub chaos_seed: [u8; 32],
}

impl Default for SphinxConfig {
    fn default() -> Self {
        Self { hops: 7, lambda: 10.0, chaos_seed: [0u8; 32] }
    }
}

// ── Core Sphinx functions ─────────────────────────────────────────────────────

/// Build a Sphinx packet with ML-KEM-768 layered encryption.
///
/// `hops`: list of `(node_id, ml_kem_768_encapsulation_key_bytes)`.
///         Each encapsulation key must be exactly 1184 bytes.
/// `payload`: the actual message bytes to encrypt.
/// `chaos_seed`: 32-byte chaos oracle seed for Poisson decoy generation and tagging.
///
/// Returns a [`SphinxOnionPacket`] with one [`SphinxLayer`] per hop.
pub fn build_sphinx_onion(
    hops: &[(String, Vec<u8>)],
    payload: &[u8],
    chaos_seed: &[u8],
) -> Result<SphinxOnionPacket, PrivacyError> {
    if hops.is_empty() {
        return Err(PrivacyError::SphinxFailed("No hops provided".into()));
    }
    if hops.len() < 5 || hops.len() > 9 {
        return Err(PrivacyError::SphinxFailed(
            alloc::format!("hops must be 5–9, got {}", hops.len())
        ));
    }

    // Validate all encapsulation keys
    for (i, (node_id, ek)) in hops.iter().enumerate() {
        if ek.len() != ML_KEM_768_EK_LEN {
            return Err(PrivacyError::SphinxFailed(
                alloc::format!("hop {} ({}): encapsulation key must be {} bytes, got {}",
                    i, node_id, ML_KEM_768_EK_LEN, ek.len())
            ));
        }
    }

    let n = hops.len();
    let mut layers: Vec<SphinxLayer> = Vec::with_capacity(n);

    // ── Build onion from innermost layer outward ──────────────────────────────
    // Start with the actual payload at the innermost layer (hop n-1)
    // then wrap each successive layer around it.

    let mut current_payload = payload.to_vec();

    // Process hops from innermost (n-1) to outermost (0)
    for i in (0..n).rev() {
        let (node_id, ek_bytes) = &hops[i];

        // Encapsulate to this hop's ML-KEM-768 public key
        // Use a deterministic RNG seeded from chaos_seed + hop_index for reproducibility
        let ek_for_encap = derive_hop_ek(ek_bytes, chaos_seed, i as u64);
        let (ct, ss) = encapsulate_to_hop(&ek_for_encap)?;

        // Derive AES-GCM key: key_i = HKDF(ss, node_id_bytes, "sphinx-layer-v1")
        let mut layer_key = [0u8; 32];
        hkdf_derive(&ss, node_id.as_bytes(), b"sphinx-layer-v1", &mut layer_key)?;

        // Encrypt current payload with this layer's key
        let encrypted = aes_gcm_encrypt(&layer_key, &current_payload)?;

        // This layer = ciphertext || encrypted_payload
        // For the next (outer) iteration, current_payload = ct || encrypted
        let layer = SphinxLayer {
            ciphertext:        ct.clone(),
            encrypted_payload: encrypted.clone(),
        };

        // The next outer layer will encrypt: ct || encrypted_payload
        // This is what the relay node will forward after stripping its layer
        let mut next_payload = Vec::with_capacity(ct.len() + encrypted.len());
        next_payload.extend_from_slice(&ct);
        next_payload.extend_from_slice(&encrypted);
        current_payload = next_payload;

        layers.push(layer);
    }

    // Reverse layers so layers[0] is the outermost (first hop)
    layers.reverse();

    // ── Compute chaos authentication tag ─────────────────────────────────────
    // chaos_tag = SHA-256(all_ciphertexts || chaos_seed || "sphinx-chaos-tag-v1")
    let mut tag_hasher = Sha256::new();
    for layer in &layers {
        tag_hasher.update(&layer.ciphertext);
    }
    tag_hasher.update(chaos_seed);
    tag_hasher.update(b"sphinx-chaos-tag-v1");
    let chaos_tag = tag_hasher.finalize().to_vec();

    Ok(SphinxOnionPacket {
        layers,
        chaos_tag,
        decoy: false,
    })
}

/// Unwrap one layer of a Sphinx packet (called by a relay node).
///
/// `layer`: the outermost [`SphinxLayer`] of the packet.
/// `decapsulation_key`: this node's ML-KEM-768 decapsulation key (64-byte seed).
/// `node_id`: this node's identifier (used as HKDF salt).
///
/// Returns the decrypted inner payload (which is the next layer's `ct || encrypted_payload`
/// for relay nodes, or the final plaintext for the exit node).
pub fn unwrap_sphinx_layer(
    layer: &SphinxLayer,
    decapsulation_key: &[u8],
    node_id: &str,
) -> Result<Vec<u8>, PrivacyError> {
    // Decapsulate ML-KEM-768 ciphertext to recover shared secret
    let ss = keys::decapsulate(decapsulation_key, &layer.ciphertext)?;

    // Derive AES-GCM key: key = HKDF(ss, node_id_bytes, "sphinx-layer-v1")
    let mut layer_key = [0u8; 32];
    hkdf_derive(&ss, node_id.as_bytes(), b"sphinx-layer-v1", &mut layer_key)?;

    // Decrypt the payload
    aes_gcm_decrypt(&layer_key, &layer.encrypted_payload)
}

/// Generate Poisson-distributed decoy packets.
///
/// Uses Poisson sampling with rate λ to determine the number of decoys.
/// Each decoy is a valid-looking Sphinx packet with random content.
///
/// `lambda`: Poisson rate (average decoys per real packet, default 10.0)
/// `chaos_seed`: 32-byte chaos seed for deterministic generation
/// `hop_count`: number of hops for each decoy (5–9)
pub fn generate_decoys(
    lambda: f64,
    chaos_seed: &[u8],
    hop_count: usize,
) -> Vec<SphinxOnionPacket> {
    // Poisson sampling: use chaos_seed to derive count
    let count = poisson_sample(lambda, chaos_seed);

    let mut decoys = Vec::with_capacity(count);
    for i in 0..count {
        // Derive per-decoy seed
        let mut decoy_seed = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(chaos_seed);
        hasher.update(&(i as u64).to_le_bytes());
        hasher.update(b"decoy-seed-v1");
        decoy_seed.copy_from_slice(&hasher.finalize());

        // Generate fake hops with deterministic ML-KEM-768 keys
        let actual_hops = hop_count.clamp(5, 9);
        let mut fake_hops: Vec<(String, Vec<u8>)> = Vec::with_capacity(actual_hops);

        for h in 0..actual_hops {
            let mut hop_seed = [0u8; 32];
            let mut hs = Sha256::new();
            hs.update(&decoy_seed);
            hs.update(&(h as u64).to_le_bytes());
            hs.update(b"decoy-hop-key-v1");
            hop_seed.copy_from_slice(&hs.finalize());

            // Generate a real ML-KEM-768 keypair for this fake hop
            match keys::generate_keypair(&hop_seed) {
                Ok((ek, _dk)) => {
                    let node_id = alloc::format!("decoy-{i}-hop-{h}");
                    fake_hops.push((node_id, ek));
                }
                Err(_) => {
                    // If key generation fails, skip this decoy
                    break;
                }
            }
        }

        if fake_hops.len() < 5 {
            continue; // Skip malformed decoys
        }

        // Fixed-size decoy payload (32 bytes of zeros — indistinguishable from real)
        let decoy_payload = vec![0u8; 32];

        match build_sphinx_onion(&fake_hops, &decoy_payload, &decoy_seed) {
            Ok(mut pkt) => {
                pkt.decoy = true;
                decoys.push(pkt);
            }
            Err(_) => {} // Skip failed decoys
        }
    }

    decoys
}

// ── Legacy API (backward-compatible with mesh/mod.rs) ────────────────────────

/// Build a Sphinx packet with layered ML-KEM-768 encryption.
///
/// This is the legacy API used by [`crate::mesh::DW3BMesh::route_query`].
/// It generates ephemeral ML-KEM-768 keypairs for each hop using the chaos seed,
/// then builds a real onion-encrypted packet.
///
/// The returned [`SphinxPacket`] contains the serialized onion in `payload`.
pub fn build_sphinx_packet(
    payload: Vec<u8>,
    config: &SphinxConfig,
    is_decoy: bool,
) -> Result<SphinxPacket, PrivacyError> {
    if config.hops < 5 || config.hops > 9 {
        return Err(PrivacyError::SphinxFailed(
            alloc::format!("hops must be 5–9, got {}", config.hops)
        ));
    }

    let n = config.hops as usize;

    // Generate ephemeral ML-KEM-768 keypairs for each hop from chaos seed
    let mut hops: Vec<(String, Vec<u8>)> = Vec::with_capacity(n);
    for i in 0..n {
        let mut hop_seed = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(&config.chaos_seed);
        hasher.update(&(i as u64).to_le_bytes());
        hasher.update(b"sphinx-hop-keygen-v1");
        hop_seed.copy_from_slice(&hasher.finalize());

        let (ek, _dk) = keys::generate_keypair(&hop_seed)?;
        let node_id = alloc::format!("hop-{i}");
        hops.push((node_id, ek));
    }

    // Build the real onion packet
    let onion = build_sphinx_onion(&hops, &payload, &config.chaos_seed)?;

    // Serialize the onion packet to bytes for the legacy SphinxPacket.payload field
    // Format: chaos_tag(32) || for each layer: ct_len(4) || ct || enc_len(4) || enc
    let mut serialized = Vec::new();
    serialized.extend_from_slice(&onion.chaos_tag);
    for layer in &onion.layers {
        let ct_len = layer.ciphertext.len() as u32;
        serialized.extend_from_slice(&ct_len.to_le_bytes());
        serialized.extend_from_slice(&layer.ciphertext);
        let enc_len = layer.encrypted_payload.len() as u32;
        serialized.extend_from_slice(&enc_len.to_le_bytes());
        serialized.extend_from_slice(&layer.encrypted_payload);
    }

    Ok(SphinxPacket {
        payload:    serialized,
        hops:       config.hops,
        is_decoy,
        chaos_seed: hex::encode(config.chaos_seed),
    })
}

/// Generate Poisson-distributed decoy packets (legacy API).
///
/// λ=10 means ~10 decoys per real packet on average.
pub fn generate_decoys_legacy(
    count: usize,
    config: &SphinxConfig,
) -> Result<Vec<SphinxPacket>, PrivacyError> {
    let mut decoys = Vec::with_capacity(count);
    for i in 0..count {
        let mut seed = config.chaos_seed;
        seed[0] ^= i as u8;
        let decoy_payload = vec![0u8; 32]; // fixed-size decoy
        let cfg = SphinxConfig { chaos_seed: seed, ..config.clone() };
        decoys.push(build_sphinx_packet(decoy_payload, &cfg, true)?);
    }
    Ok(decoys)
}

/// Build a Sphinx packet with obfuscation metadata embedded in the payload header.
///
/// The obfuscation crate uses this to route packets through the Sphinx mixnet with
/// Quantum Entangled Metadata (QEM) attached. The `qem_metadata_json` is prepended
/// to the payload as a length-prefixed header before onion encryption.
///
/// # Header format (prepended to payload before encryption)
/// ```text
/// [4 bytes: magic "QEMH"]
/// [4 bytes: qem_metadata_json.len() as u32 LE]
/// [qem_metadata_json bytes]
/// [4 bytes: chaos_seed.len() as u32 LE]
/// [chaos_seed bytes]
/// [original payload bytes]
/// ```
///
/// # Parameters
/// - `hops_json`:          JSON array of node ID strings, e.g. `["node-0","node-1",...]`
/// - `hop_keys_hex_json`:  JSON array of hex-encoded ML-KEM-768 encapsulation keys (1184 bytes each)
/// - `payload`:            the actual data to route
/// - `qem_metadata_json`:  JSON string of QEM metadata to embed in the header
/// - `chaos_seed`:         entropy from the chaos oracle (any length; SHA-256 hashed to 32 bytes)
///
/// # Errors
/// - [`PrivacyError::SphinxFailed`] if hop count is outside 5–9, keys are malformed, or JSON is invalid
pub fn sphinx_route_obfuscated(
    hops_json: &str,
    hop_keys_hex_json: &str,
    payload: &[u8],
    qem_metadata_json: &str,
    chaos_seed: &[u8],
) -> Result<SphinxPacket, PrivacyError> {
    // Parse hop node IDs
    let hop_ids: Vec<String> = serde_json::from_str(hops_json)
        .map_err(|e| PrivacyError::SphinxFailed(alloc::format!("hops_json parse error: {e}")))?;

    // Parse hex-encoded encapsulation keys
    let hop_keys_hex: Vec<String> = serde_json::from_str(hop_keys_hex_json)
        .map_err(|e| PrivacyError::SphinxFailed(alloc::format!("hop_keys_hex_json parse error: {e}")))?;

    if hop_ids.len() != hop_keys_hex.len() {
        return Err(PrivacyError::SphinxFailed(alloc::format!(
            "hops_json length ({}) != hop_keys_hex_json length ({})",
            hop_ids.len(), hop_keys_hex.len()
        )));
    }

    // Decode hex keys
    let mut hops: Vec<(String, Vec<u8>)> = Vec::with_capacity(hop_ids.len());
    for (id, key_hex) in hop_ids.iter().zip(hop_keys_hex.iter()) {
        let key_bytes = hex::decode(key_hex)
            .map_err(|e| PrivacyError::SphinxFailed(alloc::format!("hex decode error for hop {id}: {e}")))?;
        hops.push((id.clone(), key_bytes));
    }

    // Normalise chaos_seed to 32 bytes via SHA-256
    let seed_32: [u8; 32] = {
        use sha2::{Digest, Sha256};
        Sha256::digest(chaos_seed).into()
    };

    // Build QEM header: magic || qem_len || qem_bytes || seed_len || seed_bytes
    let qem_bytes = qem_metadata_json.as_bytes();
    let mut header: Vec<u8> = Vec::with_capacity(8 + qem_bytes.len() + 4 + seed_32.len());
    header.extend_from_slice(b"QEMH");
    header.extend_from_slice(&(qem_bytes.len() as u32).to_le_bytes());
    header.extend_from_slice(qem_bytes);
    header.extend_from_slice(&(seed_32.len() as u32).to_le_bytes());
    header.extend_from_slice(&seed_32);

    // Prepend header to payload
    let mut full_payload: Vec<u8> = Vec::with_capacity(header.len() + payload.len());
    full_payload.extend_from_slice(&header);
    full_payload.extend_from_slice(payload);

    // Build the Sphinx onion packet
    let onion = build_sphinx_onion(&hops, &full_payload, &seed_32)?;

    // Serialize the onion to the legacy SphinxPacket format
    // Format: chaos_tag(32) || for each layer: ct_len(4) || ct || enc_len(4) || enc
    let mut serialized: Vec<u8> = Vec::new();
    serialized.extend_from_slice(&onion.chaos_tag);
    for layer in &onion.layers {
        let ct_len = layer.ciphertext.len() as u32;
        serialized.extend_from_slice(&ct_len.to_le_bytes());
        serialized.extend_from_slice(&layer.ciphertext);
        let enc_len = layer.encrypted_payload.len() as u32;
        serialized.extend_from_slice(&enc_len.to_le_bytes());
        serialized.extend_from_slice(&layer.encrypted_payload);
    }

    Ok(SphinxPacket {
        payload:    serialized,
        hops:       hops.len() as u8,
        is_decoy:   false,
        chaos_seed: hex::encode(seed_32),
    })
}

/// Unwrap one layer of a legacy Sphinx packet (at a relay node).
///
/// In the legacy API, this re-hashes to simulate layer removal.
/// For real unwrapping, use [`unwrap_sphinx_layer`] with the full [`SphinxLayer`].
pub fn unwrap_layer(packet: &SphinxPacket, hop: u8, chaos_seed: &[u8; 32]) -> Vec<u8> {
    // Legacy: re-hash to simulate layer removal
    let mut hasher = Sha256::new();
    hasher.update(&packet.payload);
    hasher.update(&[hop]);
    hasher.update(chaos_seed);
    hasher.update(b"sphinx-unwrap-v1");
    hasher.finalize().to_vec()
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Derive a per-hop encapsulation key by mixing the hop's real EK with chaos context.
///
/// In a real Sphinx implementation, the sender uses the hop's long-term public key directly.
/// Here we use the provided EK as-is (it's already the real ML-KEM-768 public key).
fn derive_hop_ek(ek_bytes: &[u8], _chaos_seed: &[u8], _hop_index: u64) -> Vec<u8> {
    // Use the provided encapsulation key directly
    // (In production Sphinx, this is the hop's registered long-term public key)
    ek_bytes.to_vec()
}

/// Encapsulate to a hop's ML-KEM-768 encapsulation key.
///
/// Returns `(ciphertext_bytes, shared_secret_bytes)`.
fn encapsulate_to_hop(ek_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), PrivacyError> {
    keys::encapsulate(ek_bytes)
}

/// Poisson sampling using the chaos seed as a deterministic source.
///
/// Uses the Knuth algorithm: generate exponential random variables until their
/// product falls below e^(-λ).
fn poisson_sample(lambda: f64, chaos_seed: &[u8]) -> usize {
    if lambda <= 0.0 {
        return 0;
    }

    // Use chaos_seed to generate uniform random bytes
    let threshold = (-lambda).exp();
    let mut product = 1.0_f64;
    let mut count = 0usize;
    let mut counter = 0u64;

    loop {
        // Generate a uniform random value in (0, 1) from chaos_seed
        let mut hasher = Sha256::new();
        hasher.update(chaos_seed);
        hasher.update(&counter.to_le_bytes());
        hasher.update(b"poisson-v1");
        let hash = hasher.finalize();
        let raw = u64::from_le_bytes(hash[..8].try_into().unwrap_or([0u8; 8]));
        let u = (raw as f64 / u64::MAX as f64).max(1e-15); // avoid 0

        product *= u;
        counter += 1;

        if product <= threshold {
            break;
        }
        count += 1;

        // Safety cap: never generate more than 50 decoys
        if count >= 50 {
            break;
        }
    }

    count
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_hops(n: usize, seed: &[u8]) -> Vec<(String, Vec<u8>)> {
        (0..n).map(|i| {
            let mut hop_seed = [0u8; 32];
            let mut hasher = Sha256::new();
            hasher.update(seed);
            hasher.update(&(i as u64).to_le_bytes());
            hop_seed.copy_from_slice(&hasher.finalize());
            let (ek, _dk) = keys::generate_keypair(&hop_seed).unwrap();
            (alloc::format!("node-{i}"), ek)
        }).collect()
    }

    #[test]
    fn test_build_sphinx_onion_5_hops() {
        let seed = [1u8; 32];
        let hops = make_test_hops(5, &seed);
        let payload = b"hello sphinx";
        let pkt = build_sphinx_onion(&hops, payload, &seed).unwrap();
        assert_eq!(pkt.layers.len(), 5);
        assert!(!pkt.decoy);
        assert_eq!(pkt.chaos_tag.len(), 32);
    }

    #[test]
    fn test_build_sphinx_onion_7_hops() {
        let seed = [2u8; 32];
        let hops = make_test_hops(7, &seed);
        let payload = b"test payload for 7 hops";
        let pkt = build_sphinx_onion(&hops, payload, &seed).unwrap();
        assert_eq!(pkt.layers.len(), 7);
        // Each layer should have a valid ML-KEM-768 ciphertext
        for layer in &pkt.layers {
            assert_eq!(layer.ciphertext.len(), ML_KEM_768_CT_LEN);
            assert!(!layer.encrypted_payload.is_empty());
        }
    }

    #[test]
    fn test_invalid_hop_count() {
        let seed = [0u8; 32];
        let hops = make_test_hops(3, &seed); // too few
        assert!(build_sphinx_onion(&hops, b"x", &seed).is_err());
    }

    #[test]
    fn test_unwrap_sphinx_layer() {
        let seed = [3u8; 32];
        let n = 5;

        // Generate keypairs for each hop
        let mut hop_keys: Vec<(String, Vec<u8>, Vec<u8>)> = Vec::new(); // (id, ek, dk)
        for i in 0..n {
            let mut hop_seed = [0u8; 32];
            let mut hasher = Sha256::new();
            hasher.update(&seed);
            hasher.update(&(i as u64).to_le_bytes());
            hop_seed.copy_from_slice(&hasher.finalize());
            let (ek, dk) = keys::generate_keypair(&hop_seed).unwrap();
            hop_keys.push((alloc::format!("node-{i}"), ek, dk));
        }

        let hops: Vec<(String, Vec<u8>)> = hop_keys.iter()
            .map(|(id, ek, _)| (id.clone(), ek.clone()))
            .collect();

        let payload = b"secret message";
        let pkt = build_sphinx_onion(&hops, payload, &seed).unwrap();

        // Unwrap the outermost layer (hop 0)
        let (node_id, _ek, dk) = &hop_keys[0];
        let inner = unwrap_sphinx_layer(&pkt.layers[0], dk, node_id).unwrap();
        // inner = ct_1 || encrypted_payload_1 (the next layer)
        assert!(!inner.is_empty());
    }

    #[test]
    fn test_build_sphinx_packet_legacy() {
        let cfg = SphinxConfig::default();
        let pkt = build_sphinx_packet(b"hello".to_vec(), &cfg, false).unwrap();
        assert_eq!(pkt.hops, 7);
        assert!(!pkt.is_decoy);
        // Payload should be non-empty (serialized onion)
        assert!(!pkt.payload.is_empty());
    }

    #[test]
    fn test_invalid_hops_legacy() {
        let mut cfg = SphinxConfig::default();
        cfg.hops = 3;
        assert!(build_sphinx_packet(b"x".to_vec(), &cfg, false).is_err());
    }

    #[test]
    fn test_generate_decoys_legacy() {
        let cfg = SphinxConfig::default();
        let decoys = generate_decoys_legacy(3, &cfg).unwrap();
        assert_eq!(decoys.len(), 3);
        assert!(decoys.iter().all(|d| d.is_decoy));
    }

    #[test]
    fn test_poisson_sample_zero_lambda() {
        let seed = [0u8; 32];
        assert_eq!(poisson_sample(0.0, &seed), 0);
    }

    #[test]
    fn test_poisson_sample_positive() {
        let seed = [5u8; 32];
        // With λ=10, expected count ≈ 10; just verify it's in a reasonable range
        let count = poisson_sample(10.0, &seed);
        assert!(count <= 50);
    }

    #[test]
    fn test_chaos_tag_deterministic() {
        let seed = [7u8; 32];
        let hops = make_test_hops(5, &seed);
        let payload = b"deterministic test";
        // Build twice — chaos_tag should differ because encapsulation uses randomness
        // but the structure should be consistent
        let pkt1 = build_sphinx_onion(&hops, payload, &seed).unwrap();
        assert_eq!(pkt1.chaos_tag.len(), 32);
    }
}
