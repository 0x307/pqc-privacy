//! Integration tests for the `privacy` crate.
//!
//! Tests the main public APIs across every module.
//! Each test exercises a complete round-trip through the relevant module.

#[cfg(test)]
mod tests {
    // ── Chaos Oracle ──────────────────────────────────────────────────────────

    #[test]
    fn test_chaos_oracle_entropy() {
        use privacy::chaos::ChaosOracle;
        let mut oracle = ChaosOracle::new();
        let bytes = oracle.sample(32).expect("chaos sample failed");
        assert_eq!(bytes.len(), 32);
        // Verify entropy quality — not all zeros
        assert!(bytes.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_chaos_oracle_fiat_shamir_seed() {
        use privacy::chaos::ChaosOracle;
        let mut oracle = ChaosOracle::new();
        let seed = oracle.fiat_shamir_seed().expect("fiat_shamir_seed failed");
        assert_eq!(seed.len(), 32);
    }

    #[test]
    fn test_chaos_oracle_hash_5dqeh() {
        use privacy::chaos::ChaosOracle;
        let oracle = ChaosOracle::new();
        let hash = oracle.hash_5dqeh(b"test input");
        // Should be a 64-char hex string (32 bytes)
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // ── ZK SNARK ─────────────────────────────────────────────────────────────

    #[test]
    fn test_zk_snark_prove_verify() {
        use privacy::zk::snark;
        use privacy::zk::HybridZkLayer;

        let statement: [u8; 32] = *b"test statement hash 32 bytes!!!!";
        let witness:   [u8; 32] = *b"test witness hash 32 bytes!!!!!!";
        let chaos_seed: [u8; 32] = *b"test chaos seed 32 bytes!!!!!!!!";

        let proof = snark::prove(statement, witness, &chaos_seed)
            .expect("snark::prove failed");

        let zk = HybridZkLayer::new();
        let privacy_proof = privacy::types::PrivacyProof::from(proof);
        let valid = zk.verify(&privacy_proof, &statement);
        assert!(valid.is_ok(), "snark verify failed: {:?}", valid);
    }

    #[test]
    fn test_zk_stark_prove_verify() {
        use privacy::zk::stark;
        use privacy::zk::HybridZkLayer;

        let statement: [u8; 32] = *b"stark statement hash 32 bytes!!!";
        let witness:   [u8; 32] = *b"stark witness hash 32 bytes!!!!!";
        let chaos_seed: [u8; 32] = *b"stark chaos seed 32 bytes!!!!!!!";

        let proof = stark::prove_statement(statement, witness, &chaos_seed)
            .expect("stark::prove_statement failed");

        let zk = HybridZkLayer::new();
        let privacy_proof = privacy::types::PrivacyProof::from(proof);
        let valid = zk.verify(&privacy_proof, &statement);
        assert!(valid.is_ok(), "stark verify failed: {:?}", valid);
    }

    // ── QFKH Key Hopping ─────────────────────────────────────────────────────

    #[test]
    fn test_qfkh_key_establishment() {
        use privacy::keyhop::QfkhRatchet;

        let chaos_seed: [u8; 32] = *b"test chaos seed 32 bytes!!!!!!!!";

        // Initiator generates keypair
        let (dk_bytes, ek_bytes) = QfkhRatchet::initiate(&chaos_seed)
            .expect("initiate failed");
        assert_eq!(ek_bytes.len(), 1184, "ML-KEM-768 encapsulation key should be 1184 bytes");
        assert_eq!(dk_bytes.len(), 64,   "ML-KEM-768 decapsulation key seed should be 64 bytes");

        // Responder encapsulates
        let (mut responder_ratchet, ct_bytes) = QfkhRatchet::respond(&ek_bytes, &chaos_seed, 0)
            .expect("respond failed");

        // Initiator completes
        let mut initiator_ratchet = QfkhRatchet::complete(&dk_bytes, &ct_bytes, &chaos_seed, 0)
            .expect("complete failed");

        // Both ratchets should produce the same message key on first hop
        let k_init = initiator_ratchet.hop(&chaos_seed, 0).expect("initiator hop failed");
        let k_resp = responder_ratchet.hop(&chaos_seed, 0).expect("responder hop failed");
        assert_eq!(k_init.shared_secret, k_resp.shared_secret,
            "initiator and responder should derive the same message key");
    }

    #[test]
    fn test_qfkh_encrypt_decrypt() {
        use privacy::keyhop::QfkhRatchet;

        let shared_secret: [u8; 32] = [0x42u8; 32];
        let chaos_seed:    [u8; 32] = [0x13u8; 32];

        let mut enc_ratchet = QfkhRatchet::new(shared_secret, &chaos_seed, 0);
        let mut dec_ratchet = QfkhRatchet::new(shared_secret, &chaos_seed, 0);

        let plaintext = b"Hello, quantum-secure world!";
        let ciphertext = enc_ratchet.encrypt(plaintext, &chaos_seed, 0)
            .expect("encrypt failed");
        let decrypted = dec_ratchet.decrypt(&ciphertext, &chaos_seed, 0)
            .expect("decrypt failed");

        assert_eq!(plaintext, decrypted.as_slice());
    }

    // ── Differential Privacy Engine ───────────────────────────────────────────

    #[test]
    fn test_dp_engine_noise() {
        use privacy::dp::{DpEngine, PrivacyQuery};

        let mut engine = DpEngine::new();
        // epsilon must be ≤ EPSILON_MAX * 1000 = 1e-6 * 1000 = 1e-3
        let query = PrivacyQuery {
            id:           "test-query".into(),
            sensitivity:  1.0,
            epsilon:      1e-7,
            delta:        1e-10,
            timestamp_ms: 0,
        };
        let frame = engine.apply_dp(query, 0.01)
            .expect("dp apply failed");
        assert!(frame.epsilon > 0.0, "epsilon should be positive");
        assert!(frame.noise_scale > 0.0, "noise_scale should be positive");
    }

    // ── Sanctuary Vault ───────────────────────────────────────────────────────

    #[test]
    fn test_vault_store_access() {
        use privacy::vault::SanctuaryVault;

        let mut vault = SanctuaryVault::with_threshold(2, 3);
        let seed = [0xabu8; 32];
        let plaintext = b"sovereign data payload";

        vault.store("file-1", "did:wyqcc:alice", plaintext, &seed, 9_999_999_999)
            .expect("vault store failed");

        let recovered = vault.access("file-1", "did:wyqcc:alice", &seed, 0)
            .expect("vault access failed");

        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn test_vault_wrong_owner_denied() {
        use privacy::vault::SanctuaryVault;

        let mut vault = SanctuaryVault::with_threshold(2, 3);
        let seed = [0u8; 32];
        vault.store("file-2", "did:wyqcc:alice", b"secret", &seed, 9_999_999_999)
            .expect("vault store failed");

        let result = vault.access("file-2", "did:wyqcc:bob", &seed, 0);
        assert!(result.is_err(), "wrong owner should be denied");
    }

    // ── Hypergraph ────────────────────────────────────────────────────────────

    #[test]
    fn test_hypergraph_encode_and_traverse() {
        use privacy::hypergraph::PrivacyHypergraph;

        let mut graph = PrivacyHypergraph::new(0.5);
        graph.encode_vertex("v1", 0.5, 1000.0, 1e-6, 1.2, 0.8, 0)
            .expect("encode_vertex v1 failed");
        graph.encode_vertex("v2", 0.3, 2000.0, 1e-6, 0.9, 0.6, 0)
            .expect("encode_vertex v2 failed");

        // PrivacyHypergraph::new() creates a genesis vertex, so count is 3 (genesis + v1 + v2)
        assert!(graph.vertex_count() >= 2);

        let path = graph.traverse_non_local("v1", 5)
            .expect("traverse_non_local failed");
        assert!(!path.is_empty(), "traversal path should not be empty");
    }

    // ── Compression ───────────────────────────────────────────────────────────

    #[test]
    fn test_byte_compression_round_trip() {
        use privacy::compression::FractalCompressor;

        let compressor = FractalCompressor::new();
        // Repetitive enough that DEFLATE should win, so this exercises the compressed
        // path rather than the stored fallback.
        let data = b"round-trip verification. round-trip verification. round-trip verification. \
                     round-trip verification. round-trip verification. round-trip verification.";

        let blob = compressor.compress_bytes(data).expect("compress_bytes failed");
        assert!(!blob.stored, "expected this input to compress");
        assert!(blob.payload.len() < data.len(), "expected the payload to be smaller");

        let decompressed =
            FractalCompressor::decompress_bytes(&blob).expect("decompress_bytes failed");

        assert_eq!(decompressed, data);
    }

    // ── Ledger ────────────────────────────────────────────────────────────────

    #[test]
    fn test_tuplechain_insert_query() {
        use privacy::ledger::TupleChain;
        use privacy::types::{PrivacyTuple, PrivacyProof, ProofScheme};

        let mut chain = TupleChain::new();

        let proof = PrivacyProof {
            proof_bytes:   "deadbeef".into(),
            public_inputs: "".into(),
            scheme:        ProofScheme::Snark,
            security_bits: 128,
            proof_size:    4,
            chsh_value:    0.0,
            lyapunov:      4.5,
        };

        let tuple = PrivacyTuple {
            subject:   "subject-1".into(),
            predicate: "predicate-1".into(),
            object:    b"object-1".to_vec(),
            proof,
            expiry_ms: 9_999_999_999,
            anchor:    None,
        };

        let tuple_id = chain.insert(tuple);
        assert!(!tuple_id.is_empty());

        let results = chain.query_by_subject("subject-1", 0);
        assert_eq!(results.len(), 1, "should find 1 tuple by subject");
        assert_eq!(results[0].predicate, "predicate-1");
    }

    // ── Mesh ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_dw3b_mesh_register_route() {
        use privacy::mesh::DW3BMesh;
        use privacy::types::{MeshNode, NodeKind};

        let mut mesh = DW3BMesh::new("test-qstp-key");
        let chaos_seed: [u8; 32] = [0x55u8; 32];

        let node = MeshNode {
            id:       "node-1".into(),
            kind:     NodeKind::Mixnet,
            endpoint: "127.0.0.1:9000".into(),
            stake:    1000,
            pubkey:   hex::encode([0u8; 32]),
        };
        mesh.register_node(node);

        let packet = mesh.route_query(b"test payload", NodeKind::Mixnet, &chaos_seed)
            .expect("route_query failed");
        assert!(!packet.payload.is_empty());
    }

    // ── Serial ────────────────────────────────────────────────────────────────

    #[test]
    fn test_icosuple_build_and_verify() {
        use privacy::serial::{build_icosuple_frame, verify_icosuple};

        let chaos_seed: [u8; 32] = [0x33u8; 32];
        let manifold_tensor = b"manifold data".to_vec();
        let proof_bundle    = b"proof data".to_vec();
        let chaos_state     = b"chaos state".to_vec();

        let frame = build_icosuple_frame(
            manifold_tensor,
            proof_bundle,
            chaos_state,
            &chaos_seed,
            false,
        ).expect("build_icosuple_frame failed");

        assert!(!frame.signature.is_empty());
        assert!(!frame.signing_key_public.is_empty());

        let valid = verify_icosuple(&frame);
        assert!(valid, "icosuple signature should verify successfully");
    }
}
