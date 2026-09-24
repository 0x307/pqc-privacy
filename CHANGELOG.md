# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to the breaking-change and deprecation rules in
[`STABILITY.md`](./STABILITY.md) rather than strict SemVer prior to `1.0.0` — see that
document for what counts as breaking inside `0.x`.

## [0.1.3] - 2026-09-23

Documentation and metadata only. No change to the API, the wire formats or behaviour.

- The README opens with the crate's tier, MSRV, license and audit status, and ends with the
  0x307 crate family: the six crates with their tiers, the runnable examples in
  [0x307/examples](https://github.com/0x307/examples), and one audit statement shared by all
  of them. The same section is in the crate docs, so it renders on docs.rs.
- `Cargo.toml` sets `documentation` (docs.rs) and `homepage` (0x307.com/crates).
- `STABILITY.md` states when a version is yanked.
- The README is titled `pqc-privacy`, the published name, instead of `privacy` (the library's
  import name, which is unchanged).
- This repository now carries the 0.1.1 and 0.1.2 manifest changes; before this release it
  still showed the 0.1.0 manifest although the source matched.
- `Cargo.lock` moves from pqc-sig 0.4.0, now yanked, to 0.4.1. This lockfile only governs this
  repository's own builds; a crate that depends on this one resolves pqc-sig itself.

## [0.1.2] - 2026-09-10

- Requires pqc-sig 0.4. The 0.3.x releases of pqc-sig were yanked.

## [0.1.1] - 2026-09-04

- The crates.io description and keywords name what the crate ships (ML-KEM-768, ML-DSA-65,
  AES-GCM-256, Reed-Solomon sharding, onion routing, differential privacy) instead of the
  original research framing. No code change.

## [0.1.0] - 2026-09-03

- Initial publish. Requires pqc-sig 0.3, which closes the no_std dependency chain.

0.0.1, 0.1.0 and 0.1.1 are yanked.
