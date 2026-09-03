# Security Policy

## Reporting a vulnerability

Email **security@0x307.com**. This address is monitored and routes to a human — not a
mailing list nobody reads.

Please do not open a public GitHub issue for a suspected vulnerability. Include as much
detail as you can: affected version, reproduction steps, and impact if known.

## Response window

Reports are acknowledged within **5 business days**. This is a best-effort
project with a single maintainer and no on-call rotation — see
[`STABILITY.md`](./STABILITY.md) for the full support posture. The response window above is
the one committed number in that posture; everything else is best-effort.

## Supported versions

This project ships `0.x`. Security fixes land on the latest published minor version. Older
`0.x` minors are not backported to, consistent with the stated stability policy.

## Dependency scanning

Dependencies are scanned with [`cargo-deny`](https://embarkstudios.github.io/cargo-deny/)
against the [`deny.toml`](./deny.toml) in this repo — advisories, licenses, bans, and
sources. It runs on every push to `main`, on pull requests, and on a weekly schedule
(Mondays 06:00 UTC), and a failure files a tracking issue rather than only turning a run
red. To reproduce locally:

```
cargo deny --config deny.toml check
```

`deny.toml` sets `all-features = true` on purpose. It scans the **full opt-in surface**,
not just the default build: a feature you *can* enable is one whose advisories you should
know about *before* you enable it, not after.

### Known and accepted advisories

**The `cargo-deny` workflow is expected to fail, and a red run there is the correct,
intended state — not a broken build.** The advisory below is known, accepted, and
deliberately *not* suppressed: `advisories.ignore` in `deny.toml` is empty, so nothing is
hidden from the tool. That is what keeps a genuinely *new* advisory visible instead of
letting it land silently on top of an already-accepted one. The `CI` workflow is separate
and is the one that must stay green.

| Advisory | Crate | Reachable via |
|---|---|---|
| [RUSTSEC-2024-0384](https://rustsec.org/advisories/RUSTSEC-2024-0384) | `instant` v0.1.13 | `reed-solomon-erasure`'s `std` feature (default build) |

**Why this is an accept and not a shrug:**

- **No safe upgrade exists.** `reed-solomon-erasure` v6.0.0 pins `parking_lot = "0.11.2"`
  exactly in its own `Cargo.toml`, and `parking_lot` 0.11's WASM time support depends on the
  unmaintained `instant` crate. `parking_lot` 0.12+ dropped `instant` in favor of `web-time`,
  but this crate has no way to force that upgrade — it isn't our dependency declaration to
  change, and `reed-solomon-erasure` (last published 2021) has no newer release that bumps
  it. `cargo deny` itself reports "No safe upgrade is available!" for this advisory.
- **This is a maintenance-capacity advisory, not a known vulnerability.** No CVE, no exploit
  — the crate author recommends migrating callers to `web-time`, which is `parking_lot`'s
  call to make, not ours.
- **Reachable only via `reed-solomon-erasure`'s real erasure-coding implementation**, used by
  `vault` for genuine k-of-n Reed-Solomon sharding (see the README's "What runs today vs.
  what is designed"). Dropping `reed-solomon-erasure` to avoid this advisory would mean
  losing real, working cryptographic-adjacent functionality to route around a
  maintenance-status advisory with no exploit — not a trade worth making.

**Revisit trigger:** if `reed-solomon-erasure` publishes a release that bumps its
`parking_lot` dependency past 0.11 (dropping `instant`), update to it and this entry goes
away. Anything failing beyond this one advisory — a new RUSTSEC ID, a license, a ban, or a
source — is *not* covered by this acceptance and needs its own decision recorded here.

Decision recorded 2026-09-01 (0X3-119), following the `pqc-kem`/P1-06 accept-and-document
pattern.
