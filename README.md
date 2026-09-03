# `privacy` — PQCPrivacy Crate

A Rust library bundling post-quantum cryptography, applied differential privacy, and a
broad set of exploratory privacy-research primitives, compiled natively or to
`wasm32-unknown-unknown`.

> Author: Kenneth Harper

---

## Overview

The parts of this crate you can rely on are ordinary, standards-based cryptography: **real
ML-KEM-768 key encapsulation (FIPS 203)** and **real ML-DSA-65 signatures (FIPS 204)** via the
`pqc-kem`/`pqc-sig` sibling crates, **real AES-GCM-256** authenticated encryption, **real
HKDF-SHA256** key derivation, and **real Reed-Solomon erasure coding** for k-of-n data
sharding. Those are used throughout for key establishment, signing, and encrypting data.

The rest of the crate is a large, honestly-labeled mix: real numerical simulations dressed in
physics vocabulary they don't literally satisfy (chaos-attractor "entropy," Bell-inequality
"CHSH" scores), and placeholder logic (hash-chain "SNARK"/"STARK" proofs, ASCII-string
"genomic" processing) that has the shape of the real thing but not its guarantees. None of that
is hidden — see the next section for exactly which is which, module by module.

---

## What runs today vs. what is designed

**Real, standards-anchored cryptography** (the part with actual security guarantees):

- **`keyhop`** (QFKH) — real ML-KEM-768 encapsulate/decapsulate (FIPS 203, via `pqc-kem`),
  real HKDF-SHA256 ratchet, real AES-GCM-256 message encryption. Chain keys are zeroized and
  replaced on every hop. The "≤1 ms hop interval" is a constant compared against a
  caller-supplied timestamp — nothing in the code enforces sub-millisecond timing.
- **`serial`** (Icosuple format) — real ML-DSA-65 signing and verification (FIPS 204, via
  `pqc-sig`); a tamper test confirms verification correctly rejects a modified frame.
  Compression is real DEFLATE (RFC 1951) via `miniz_oxide`, and **format version 1 is
  defined to mean DEFLATE**: the frame's flags record whether the payload is compressed,
  not how, so a change of algorithm is a version bump rather than something a reader
  negotiates. Earlier revisions called this Zstandard; it never was, and zstd is not a
  candidate — it requires `std`, which would cost the `no_std`/WASM build.
- **`vault`** (Sanctuary Vault) — real AES-GCM-256 encryption (HKDF-derived key) and real
  k-of-n Reed-Solomon erasure sharding via the `reed-solomon-erasure` crate. Its
  `homomorphic_search` is **not** homomorphic: it's a literal byte-pattern scan over ciphertext
  bytes, which cannot work against semantically-secure AES-GCM output and shouldn't be relied
  on.
- **`mesh::mixnet`**'s Sphinx-style onion packet — each layer is real: ML-KEM-768 encapsulation
  per hop, HKDF-derived per-layer keys, AES-GCM-256 layer encryption, built innermost-out. (The
  "mesh" wrapper around it is not real networking — see below.)
- **`messenger`, `viewer`** — real AES-GCM-256 for message/document content. `viewer` was
  previously documented as a "Quantum SCIF Viewer for Classified Documents" — that framing is
  gone (0X3-118): this crate makes no claim of suitability for handling government-classified
  material and implements no SCIF property. What it actually does is clearance-gated AES-GCM
  document encryption.
- **`dp`** (Differential Privacy) — real, standard mechanism math: Laplace inverse-CDF
  sampling, Gaussian noise via Box-Muller with `σ² = 2ln(1.25/δ)/ε²`, and a Rényi-divergence
  bound `D_α ≈ αε²/2` for the Gaussian mechanism. Budget tracking is a simple running sum, not
  full moments-accountant composition. The noise generator is seeded from the chaos oracle
  (see below) and is explicitly commented as deterministic "for reproducibility in tests" —
  swap in a real CSPRNG before relying on this for actual privacy budgets.
- **`compression`** — two separate, deliberately unconflated things. `compress`/`decompress`
  implement a real Iterated Function System (IFS): genuine 5×5 affine contraction-map math
  applied to 5-dimensional points, which is dimension reduction on a coordinate.
  `compress_bytes`/`decompress_bytes` are real **lossless** byte compression — DEFLATE
  (RFC 1951) via `miniz_oxide` — returning a `CompressedBlob` whose round-trip is exact and
  verified against a SHA-256 of the input. They are not fractal and don't claim to be:
  fractal compression is lossy and only pays off on self-similar signals, which arbitrary
  bytes are not. Since no algorithm compresses every input, incompressible data (ciphertext,
  keys, already-compressed bytes) falls back to being stored verbatim and is flagged in
  `CompressedBlob::stored`, so the output never meaningfully grows; `CompressedBlob::ratio`
  reports what actually happened. Earlier versions claimed a "100:1" ratio here and stored
  every chunk verbatim, making the output strictly larger than the input — both the claim and
  that implementation are gone.
- **`interfaces`** — capability advertisement is a plain struct/`Vec`, but capability
  attestation is signed with real ML-DSA-65.

**Real code, but not what the name implies** (genuine computation, wearing vocabulary from a
field it doesn't operate in):

- **`chaos`** (`oracle`, `chua`, `rossler`) — real 4th-order Runge-Kutta numerical integration
  of the actual Chua and Rössler differential equations. But `ChaosOracle::new()` always starts
  from the same hard-coded initial conditions with no external seed, so
  `chaos_entropy_bytes(n)` returns **the identical byte sequence on every process run** — this
  is deterministic simulation output, not randomness, despite doc comments invoking NIST SP
  800-90B min-entropy. "SHAKE-256 whitening" is not SHAKE-256; it's repeated SHA-256 blocks (the
  source says so directly). The "Lyapunov exponent" is a heuristic proxy — `ln(variance ×
  1000)` clamped to `[0, 10]` — not a true Lyapunov exponent, which requires tracking the
  divergence of nearby trajectories over time.
- **`hypergraph`** (5D-EZPH) — a real graph data structure (`BTreeMap` of vertices/hyperedges),
  where each vertex is a SHA-256 commitment over five `f64` fields. Its "CHSH" value is a formula
  invented to resemble a Bell-inequality expression (`2^(k/2-1) · |Π cos φᵢ| · …`, clamped at
  2.828427), computed from caller-supplied floats — not a measurement of anything physical.
  `zk::entanglement`'s CHSH score follows the same pattern, and its own source comments admit the
  phase angle is chosen specifically to land the score above 2.8 by construction.
- **`ledger`** (TupleChain) — a real in-process `BTreeMap` with SHA-256-derived tuple IDs.
  "Anchoring to Wyqcc L1" is inserting into a second local map — there is no blockchain,
  consensus, or external chain here.
- **`mesh`** (DW3B, all node types) — confirmed by grep across the whole crate: there is no
  `TcpStream`, `UdpSocket`, HTTP client, or any other networking code anywhere in this repo.
  Every "node," "route," and "endpoint" is an in-process data structure lookup. The onion-layer
  cryptography inside a Sphinx packet is real (see above); the mesh that's said to carry it is
  not.

**Toy / placeholder — implements the shape, not the guarantee:**

- **`zk::snark`, `zk::stark`** — not zero-knowledge proof systems. `snark` is a hash-based
  commit/challenge/response construction, and its `verify()` never receives the witness — it
  only re-derives the challenge from the prover-supplied commitment, so it does not check that
  the proof is actually bound to any witness. `stark` similarly builds a Merkle tree and calls a
  Horner-method byte evaluation "FRI-style," with no finite field, no low-degree testing, and no
  constraint system. Where these build a Merkle root and sign it with ML-DSA-65 (in `aggregate`),
  that signature is real; everything upstream of it is not a soundness-checked proof.
**Non-default — off by default, mirroring `aethel-core`'s `puf`/`enclave` gates (0X3-118):**

- **`genomic`, `genomic::login`** (`genomic` feature) — no genomic-sequence or biometric
  processing. "Alleles" are single ASCII characters (`A`/`C`/`G`/`T`) mapped to 2-bit codes and
  hashed; "biometric login" is byte-equality comparison between two caller-supplied strings
  above a 98% match threshold — ordinary string diffing, not signal processing over sequencing
  data. Gated off by default: publishing a working claim about genomic biometrics by default
  carries regulatory weight the rest of this crate doesn't.
- **`enclave`** (WAVEN, `enclave` feature) — a real, working access-control table (`BTreeMap` of
  pages to permissions) with data genuinely AES-GCM encrypted. There is no actual hardware
  memory-protection-key integration, page fault handling, or WASM VM isolation underneath it.
  Gated off by default because it describes a hardware property this crate cannot provide on
  its own — the same reason `aethel-core` gates its own `enclave` feature.

**Real cryptography, working:**

- **`fhe`** — a genuine LWE/ring-LWE-style additive homomorphic encryption scheme: correct
  negacyclic polynomial ring arithmetic in `Z_q[X]/(X^N+1)`, correct key generation, encryption,
  homomorphic add/negate, and relinearized multiply, with a working encrypt-decrypt round-trip.
  It is **not actually CKKS** despite the name — no complex-vector encoding, no modulus-ladder
  rescaling chain, no approximate-arithmetic error budget. It does use a plaintext scaling
  factor to keep accumulated noise off the message, which is the one CKKS idea it borrows.

---

## Standards-Based Cryptography

| Algorithm | Standard | Used in |
|-----------|----------|---------|
| **ML-KEM-768** | FIPS 203 | `keyhop` (QFKH), `mesh::mixnet` Sphinx onion layers |
| **ML-DSA-65** | FIPS 204 | `serial` (Icosuple signatures), `interfaces` (capability attestation), `zk` proof-bundle signing |
| **AES-GCM-256** | NIST SP 800-38D | `vault`, `keyhop`, `mesh::mixnet`, `messenger`, `viewer`, `enclave` (non-default) |
| **HKDF-SHA256** | RFC 5869 | Key derivation throughout |
| **Reed-Solomon erasure coding** | — | `vault` k-of-n sharding (default 10-of-15), via the `reed-solomon-erasure` crate |
| **SHA-256 / SHA3-256** | FIPS 180-4 / FIPS 202 | Commitments, Merkle trees, tuple/shard IDs |
| **Differential privacy (Laplace, Gaussian, Rényi bound)** | Standard DP mechanism formulas | `dp` |

`zk::snark`/`zk::stark` and `genomic`'s SNP-commitment hashing also use SHA-256/HKDF as
building blocks, but the constructions they're part of are not soundness-checked proof systems
or real genomic processing — see [above](#what-runs-today-vs-what-is-designed).

---

## Architecture

```
privacy/
├── src/
│   ├── lib.rs              # Crate root + re-exports
│   ├── error.rs            # Unified PrivacyError
│   ├── types.rs            # Shared types (PrivacyProof, Icosuple, etc.)
│   ├── wasm.rs              # WASM bindings (wasm-bindgen, #[cfg(feature="wasm")])
│   ├── hypergraph/         # 5D-EZPH — simulated CHSH scoring over a local graph
│   ├── zk/                 # Hash-based proof constructions (not SNARK/STARK — see above)
│   │   ├── snark.rs        # Commit/challenge/response
│   │   ├── stark.rs        # Merkle tree + Horner-method evaluation
│   │   ├── hybrid.rs       # Selects between the two
│   │   └── entanglement.rs # Hash chaining + simulated CHSH + real ML-DSA-65 signing
│   ├── chaos/              # Real Chua/Rössler ODE integration, deterministic output
│   │   ├── chua.rs         # Chua attractor (primary)
│   │   ├── rossler.rs      # Rössler backup
│   │   └── oracle.rs       # Combines both, "whitens" via repeated SHA-256
│   ├── enclave/            # [non-default: `enclave`] WAVEN — local page access-control table
│   ├── ledger/              # TupleChain — local map, no real chain
│   ├── keyhop/              # QFKH — real ML-KEM-768 + HKDF + AES-GCM
│   ├── genomic/             # [non-default: `genomic`] QTAID — ASCII string hashing
│   ├── interfaces/          # UNI/UVI — capability structs + real ML-DSA-65 attestation
│   ├── vault/               # Sanctuary Vault — real AES-GCM-256 + real Reed-Solomon
│   ├── messenger/           # Real AES-GCM-256 message encryption, no P2P transport
│   ├── viewer/               # Real AES-GCM-256 document encryption
│   ├── dp/                  # Real Laplace/Gaussian/Rényi DP mechanism math
│   ├── compression/         # Real IFS/affine fractal compression
│   ├── mesh/                # In-process node/routing simulation, no networking
│   ├── sync/                 # Local topological sort over a poset
│   └── serial/               # Icosuple format — real ML-DSA-65 signing, DEFLATE (v1)
├── tests/
│   └── integration_test.rs # 15 integration tests
├── wit/
│   └── privacy.wit         # WIT interface definition
├── build.ps1               # Native build script
└── build-wasm.ps1          # WASM build script
```

---

## Building

### Prerequisites

```powershell
# Install Rust (if not already installed)
rustup update stable

# Install WASM target
rustup target add wasm32-unknown-unknown

# Install wasm-pack (for WASM builds)
cargo install wasm-pack
```

### Native Build

```powershell
# From workspace root or privacy/
powershell -ExecutionPolicy Bypass -File privacy/build.ps1

# With tests
powershell -ExecutionPolicy Bypass -File privacy/build.ps1 -Test

# Check only (fast)
powershell -ExecutionPolicy Bypass -File privacy/build.ps1 -Check
```

Or directly with cargo:

```powershell
cd privacy
cargo build --release
cargo test
```

Build scripts are PowerShell only; on macOS/Linux use the plain `cargo` commands above and
`wasm-pack build --target web --release -- --no-default-features --features wasm` for WASM.

### WASM Build

```powershell
# From workspace root or privacy/
powershell -ExecutionPolicy Bypass -File privacy/build-wasm.ps1
```

This produces `privacy/dist/` containing:
- `privacy_bg.wasm` — compiled WebAssembly binary
- `privacy.js` — JS glue module (ESM)
- `privacy.d.ts` — TypeScript type definitions
- `privacy.wit` — WIT interface file
- `package.json` — npm package manifest

Or directly with cargo:

```powershell
cd privacy
cargo build --target wasm32-unknown-unknown --features wasm --release
```

---

## Usage

### Rust (Native)

Copy-paste tested against this crate as [`examples/readme_quickstart.rs`](examples/readme_quickstart.rs)
— run it yourself with `cargo run --example readme_quickstart`.

```rust
use privacy::chaos::ChaosOracle;
use privacy::zk::snark;
use privacy::keyhop::QfkhRatchet;
use privacy::vault::SanctuaryVault;

// 1. Chaos oracle output, used as a seed below. Deterministic across runs — see
//    "What runs today vs. what is designed" — not a source of real entropy.
let mut oracle = ChaosOracle::new();
let seed = oracle.fiat_shamir_seed().unwrap();

// 2. Hash-based commit/challenge/response proof (not a soundness-checked zk-SNARK).
let statement = [0u8; 32];
let witness = [1u8; 32];
let proof = snark::prove(statement, witness, &seed).unwrap();
snark::verify(&proof, &statement, &seed).unwrap();

// 3. QFKH key establishment — real ML-KEM-768 (FIPS 203).
let chaos_seed = [0x42u8; 32];
let (dk, ek) = QfkhRatchet::initiate(&chaos_seed).unwrap();
let (mut responder, ct) = QfkhRatchet::respond(&ek, &chaos_seed, 0).unwrap();
let mut initiator = QfkhRatchet::complete(&dk, &ct, &chaos_seed, 0).unwrap();

// 4. Sanctuary Vault — real AES-GCM-256 + real Reed-Solomon erasure coding.
let mut vault = SanctuaryVault::with_threshold(2, 3);
vault.store("file-1", "did:wyqcc:alice", b"secret data", &chaos_seed, 9_999_999_999).unwrap();
let data = vault.access("file-1", "did:wyqcc:alice", &chaos_seed, 0).unwrap();
assert_eq!(data, b"secret data");
```

### JavaScript / TypeScript (WASM)

Signatures below match [`src/wasm.rs`](src/wasm.rs) as written — not copy-paste tested (no JS
runtime in this environment), but checked against the actual exported function signatures
rather than written from memory.

```javascript
import init, {
  chaos_fiat_shamir_seed,
  zk_prove_snark,
  zk_verify_snark,
  qfkh_initiate,
  qfkh_respond,
  qfkh_complete,
  vault_store,
} from './privacy.js';

await init();

// Chaos oracle output (deterministic — see above)
const chaosSeed = chaos_fiat_shamir_seed();

// Hash-based proof (not a soundness-checked zk-SNARK)
const stmtHash = new Uint8Array(32).fill(1);
const witnessHash = new Uint8Array(32).fill(2);
const proofJson = zk_prove_snark(stmtHash, witnessHash, chaosSeed);
const valid = zk_verify_snark(proofJson, stmtHash); // returns a plain bool in the WASM binding

// QFKH key establishment (real ML-KEM-768)
const { dk_bytes_hex, ek_bytes_hex } = JSON.parse(qfkh_initiate(chaosSeed));
const { ciphertext_hex } = JSON.parse(qfkh_respond(ek_bytes_hex, chaosSeed, 0n));
const { hop_count } = JSON.parse(qfkh_complete(dk_bytes_hex, ciphertext_hex, chaosSeed, 0n));

// Vault (real AES-GCM-256 + Reed-Solomon). Note: the WASM `vault_store` binding creates a
// fresh in-memory vault per call — there is no `vault_access`-only path that reads back a
// previously stored file across separate calls; each binding is a self-contained operation.
const manifestJson = vault_store(
  'file-1', 'did:wyqcc:alice',
  new TextEncoder().encode('secret'),
  chaosSeed, 9999999999n, 0, 0,
);
console.log(JSON.parse(manifestJson));
```

---

## WIT Interface Summary

The [`wit/privacy.wit`](wit/privacy.wit) file defines the component model interface:

```wit
package pqcprivacy:privacy@0.1.0;

interface chaos {
  chaos-sample: func(n: u32) -> list<u8>;
  chaos-fiat-shamir-seed: func() -> list<u8>;
  chaos-hash-5dqeh: func(input: list<u8>) -> string;
  chaos-lyapunov: func() -> f64;
  chaos-telemetry-json: func() -> string;
}

interface zk {
  zk-prove-snark: func(statement: list<u8>, witness: list<u8>, seed: list<u8>) -> string;
  zk-verify-snark: func(proof-json: string, statement: list<u8>) -> bool;
  zk-prove-stark: func(statement: list<u8>, witness: list<u8>, seed: list<u8>) -> string;
  zk-verify-stark: func(proof-json: string, statement: list<u8>) -> bool;
}

interface vault {
  vault-store: func(file-id: string, owner: string, data: list<u8>, seed: list<u8>, expiry: u64) -> string;
  vault-access: func(file-id: string, owner: string, seed: list<u8>, now: u64) -> list<u8>;
}

// ... (see wit/privacy.wit for full interface)
```

Note: this file documents the flat `wasm-bindgen` API surface in WIT-style pseudocode; it is
not compiled as a real WASM Component Model world (see the file's own header comment). The
`vault-access` signature shown here (no `data` parameter) does not match the actual WASM
binding's `vault_access(file_id, owner_did, plaintext, chaos_seed, expiry_ms, now_ms)`, which
re-stores the plaintext on every call — see the [Usage](#usage) note above. Treat `wit/privacy.wit`
as approximate documentation, not a source of truth for exact argument lists.

---

## Test Results

```
cargo test --lib:
  136 unit tests — 135 passing, 1 failing
  (fhe::tests::test_encrypt_decrypt — known bug, see
  "What runs today vs. what is designed" above)

cargo test --doc:
  2 doc-tests — all passing

cargo test --test integration_test:
  15 integration tests — all passing
```

---

## Features

| Feature | Description |
|---------|-------------|
| `default` | Enables `std` feature |
| `std` | Standard library support (sha2/std, serde/std, etc.) |
| `wasm` | WASM target: wasm-bindgen, js-sys, getrandom/js, instant/wasm-bindgen |
| `genomic` | Compiles the `genomic` module (ASCII-hash "QTAID" tokenization and string-diff "biometric" login — see [above](#what-runs-today-vs-what-is-designed)). Off by default. |
| `enclave` | Compiles the `enclave` module (local page access-control table, no real hardware isolation — see [above](#what-runs-today-vs-what-is-designed)). Off by default. |

---

## Contributing

See [`CONTRIBUTING.md`](./CONTRIBUTING.md).

## Maintainer and Support

Ed Johnson is the named maintainer. This is a best-effort, single-maintainer project — see
[`STABILITY.md`](./STABILITY.md) for the release cadence and support posture, and
[`SECURITY.md`](./SECURITY.md) to report a vulnerability.

---

## License

Dual-licensed under [MIT](./LICENSE-MIT) or [Apache-2.0](./LICENSE-APACHE), at your option.
