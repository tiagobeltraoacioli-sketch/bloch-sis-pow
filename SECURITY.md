# Security Policy

> **Genesis-3-era document — sealed 2026-08-12.** Bloch's proof-of-work
> chain halts by consensus rule at the terminal height (50,000) and
> Genesis-4 relaunches as proof of stake; the ownerless thesis was
> retracted (`docs/adr/ADR-036-retract-ownerless-adopt-foundation.md`).
>
> The reporting flow, disclosure timeline and development practices below are
> current and unaffected. The **Status** section and the PoW/AuxPoW/difficulty
> entries in scope describe the chain only for the blocks it has left.

## Status

The live network is the **Genesis-3 mainnet** (chain-id `0xB10C_0004`, launched
2026-07-29): standard **SHA-256d proof-of-work** (double SHA-256,
Bitcoin-compatible, little-endian target compare from height 0), mined by real
ASICs, with **Bitcoin merged mining (AuxPoW) active since height 8,500**.
(Earlier versions of this policy described the retired Module-SIS/testnet
chains; that regime no longer exists on the live network.) The network is
**unaudited**, nascent, low-hashrate, and **51%-attackable** — running a live
mainnet is a designation, not a security claim, and no security property is
claimed. **No external security audit has been contracted to date**; if any
other page or document suggests otherwise, this statement is the accurate
one. The posture we are building toward — and its open gates — is in
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

- Consensus (GhostDAG, reorg), the SHA-256d PoW and AuxPoW (merged-mining)
  verification, difficulty retargeting, hybrid Falcon‖ML-DSA signatures,
  serialization/deserialization.
- The Coherence privacy layer (shielded pool, spend proofs) and network-layer
  metadata privacy (Dandelion++).
- Node, wallet, keystore, RPC, and the attestation layer (L1–L3).
- **Privacy findings are explicitly in scope** — deanonymization, metadata leaks,
  address linkability, and any way the protocol could surveil or link users (it
  is designed not to; see the privacy-first positioning in the roadmap).

## Out of scope

- The **known** low-hashrate exposure — the network being 51%-attackable with
  modest rented SHA-256d hashrate is a documented, disclosed gap, not a bug
  (a concrete exploit beyond it — e.g. accepting blocks below target, or
  forging AuxPoW commitments without the work — is in scope).
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
