use privacy::chaos::ChaosOracle;
use privacy::zk::snark;
use privacy::keyhop::QfkhRatchet;
use privacy::vault::SanctuaryVault;

fn main() {
    // 1. Chaos oracle output, used as a seed throughout the examples below.
    let mut oracle = ChaosOracle::new();
    let seed = oracle.fiat_shamir_seed().unwrap();

    // 2. Hash-based commit/challenge/response proof (not a real zk-SNARK — see README).
    let statement = [0u8; 32];
    let witness = [1u8; 32];
    let proof = snark::prove(statement, witness, &seed).unwrap();
    snark::verify(&proof, &statement, &seed).unwrap();

    // 3. QFKH key establishment (real ML-KEM-768, FIPS 203).
    let chaos_seed = [0x42u8; 32];
    let (dk, ek) = QfkhRatchet::initiate(&chaos_seed).unwrap();
    let (mut responder, ct) = QfkhRatchet::respond(&ek, &chaos_seed, 0).unwrap();
    let mut initiator = QfkhRatchet::complete(&dk, &ct, &chaos_seed, 0).unwrap();
    let _ = (&mut responder, &mut initiator);

    // 4. Sanctuary Vault (real AES-GCM-256 + real Reed-Solomon erasure coding).
    let mut vault = SanctuaryVault::with_threshold(2, 3);
    vault.store("file-1", "did:wyqcc:alice", b"secret data", &chaos_seed, 9_999_999_999).unwrap();
    let data = vault.access("file-1", "did:wyqcc:alice", &chaos_seed, 0).unwrap();
    assert_eq!(data, b"secret data");

    println!("quickstart OK");
}
