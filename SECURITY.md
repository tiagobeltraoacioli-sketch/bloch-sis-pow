# Security Policy

## Status

Bloch-SIS is **pre-mainnet**. The chain currently runs a **zero-security testnet**
regime of the Module-SIS PoW (relaxed residual): it is trivially forgeable,
unaudited, and has no live network. **Do not deploy it or attach value.** The
security and privacy posture we are building toward — and its open gates — is in
[`docs/THREAT-MODEL.md`](./docs/THREAT-MODEL.md) and [`ROADMAP.md`](./ROADMAP.md).

## Reporting a vulnerability

**Do not open a public issue, discussion, or merge request for a sensitive
security or privacy finding.**

- Use the repository's **private security advisory** flow, or
- contact a maintainer directly via an encrypted channel with `[bloch-security]`
  in the subject.

Include: affected component, version/commit, reproduction (a PoC is ideal),
impact (what can an attacker do, under what assumptions), a suggested fix if you
have one, and whether you want public credit.

We aim to acknowledge within a few days and to coordinate a fix + disclosure
timeline with you (typically: acknowledge ≤ 2 days, fix and coordinated
disclosure as fast as the severity warrants). Good-faith research is welcome; we
will not pursue reporters acting in good faith.

## In scope

- Consensus (GhostDAG-Q, reorg), the Module-SIS PoW, hybrid Falcon‖ML-DSA
  signatures, serialization/deserialization.
- The Coherence privacy layer (shielded pool, spend proofs) and network-layer
  metadata privacy (Dandelion++).
- Node, wallet, keystore, RPC, and the attestation layer (L1–L3).
- **Privacy findings are explicitly in scope** — deanonymization, metadata leaks,
  address linkability, and any way the protocol could surveil or link users (it
  is designed not to; see the privacy-first positioning in the roadmap).

## Out of scope

- The **known** zero-security testnet PoW regime (forgeable by design — this is
  the S1 hardness gate, not a bug).
- Gaps already documented as unaudited / claim-gated in the threat model (the
  documented gap is not a new finding — but a concrete exploit of it is).
- Denial of service requiring implausible resources; issues only in third-party
  infrastructure.

## Development security practices

- **Supply chain:** `Cargo.lock` committed; the PQ-crypto fork is vendored
  (`crates/pqcrypto-internals`) so the workspace is self-contained. `cargo deny
  check` (`deny.toml`) enforces permissive licenses (no copyleft), no external
  git deps, and RUSTSEC advisories — run in CI.
- **Secret scanning:** `gitleaks` runs in CI to catch committed credentials.
  Rotate any credential that ever touches a shell or history.
- **Reproducible builds:** the node image is byte-reproducible (L1); releases
  should be signed. The OS images (Postern OS) are reproducible by construction.
- **Least privilege:** the node runs hardened (L2 container hardening / the NixOS
  `services.bloch` systemd sandbox); keystores are encrypted (Argon2 + AEAD).
- **Attestable integrity:** the immutable OS profile binds a dm-verity roothash
  into `getattestation`, verifiable against the reproducible image (L1→L3).
- **Fuzzing:** coverage-guided fuzz targets (`fuzz/`, cargo-fuzz) for the
  untrusted-input parsers (`Block::from_bitcoin_bytes`,
  `Transaction::from_stratum_bytes`); new parsers of untrusted bytes get a target.

## No claims before their gate

We do not claim any security or privacy property before its audit gate clears
(S1/S2 for security, P2/C4 for privacy). No "100% private" claim, ever, before an
external audit.
