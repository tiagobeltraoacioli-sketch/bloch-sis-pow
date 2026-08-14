# ADR-002: DKG Protocol Family for FFG Committee BLS Keypairs

**Status:** **SUPERSEDED** — Genesis-4 uses **no BLS and no DKG**. Every validator signs individually with the hybrid ML-DSA-65 ‖ Falcon-1024 suite; there is no threshold key, no 21-validator FFG committee and no hashrate-weighted election. Superseded in substance by `docs/specs/BLOCH-POS-SHA3-LATTICE-MIGRATION.md` and `crates/bloch-pos-committee/`. The chain this ADR governs — Genesis-3, proof of work — stopped permanently at height **39,918** on 2026-08-13. The live chain is **Genesis-4, proof of stake** (30 s slots, 32-slot epochs, finality by epoch, hybrid ML-DSA-65 ‖ Falcon-1024, no mining). The decision, context and consequences below are **not** rewritten: this is a decision log and what was decided, when, is the record. Read it as history, not as guidance.

*Original status line, retained:* **Status:** Accepted
**Date:** 2026-04-29
**Deciders:** BLOCH Founder
**Sprint:** 2.1 (CommitteeRegistry + Dual DKG)

## Context

The FFG protocol (RFC-001) requires that the 21-validator committee jointly hold a BLS12-381 aggregate public key, with each validator holding a BLS share for threshold signing (14-of-21).

This requires a Distributed Key Generation (DKG) ceremony — a protocol where N participants jointly generate a public key without any single party knowing the corresponding private key in full. Each participant ends up with a "share" of the secret key.

Three serious DKG protocol families are candidates:

1. **Pedersen VSS-based DKG** (1991) — based on Pedersen's verifiable secret sharing.
2. **Gennaro et al. DKG** (1999) — a refinement of Pedersen DKG that addresses "rushing adversary" attacks where corrupted parties can bias the output by waiting to see honest contributions.
3. **Centralized trusted dealer** — a single party generates the key and distributes shares.

PoBRS (already in production, 7-of-12 oracle pool) currently uses **Pedersen VSS-based DKG** via `blst` and `blsful` crates with a Rust-native implementation in `src/pobrs/bls.rs`.

## Decision

**Adopt Pedersen VSS-based DKG, generalized from PoBRS implementation, parameterized for 21-of-21 keygen with 14-of-21 threshold.**

## Rationale

### Reuse of audited code path

PoBRS's Pedersen DKG has been in production since Sprint 1.5 L1, has been exercised by oracle attestation traffic, and will be part of the upcoming FFG audit (Sprint 2.5). Reusing the same code path means:

- One audit covers both PoBRS (7-of-12) and FFG (21-of-21) DKG
- Bug fixes propagate to both
- Operational tooling (DKG ceremony orchestration) is identical
- BLOCH Labs audit firms (Trail of Bits, Kudelski) can scope a single DKG primitive

Generalization required: parameterize the existing `bls_dkg::run()` to accept (N, threshold) instead of hardcoded (12, 7). Sprint 2.1 effort: ~3 days.

### Industry standard posture

Pedersen DKG is the industry baseline. Implementations exist in:
- Filecoin's `drand` (League of Entropy, production since 2019)
- Ethereum's beacon chain (via the BLS standard committee work)
- Threshold Cryptography Library (TCB-Crypto)

Auditors recognize the protocol shape and can focus on implementation correctness rather than protocol soundness analysis.

### Gennaro DKG improvements not warranted

Gennaro et al. (1999) showed Pedersen DKG admits a rushing adversary — a corrupted party could observe honest contributions before submitting their own, biasing the output distribution. The Gennaro fix adds a commit-then-reveal phase, costing one extra round of communication.

For BLOCH's threat model:
- The 21 committee members are hashrate-elected, not arbitrary parties. A miner with enough hashrate to be in committee already has alignment with chain integrity.
- The bias from rushing adversary is small (few bits of entropy, statistically detectable on-chain via output verification).
- The added round is a real operational cost — DKG is already 3 rounds; making it 4 increases ceremony failure probability.

Gennaro DKG is the "academically purer" choice; Pedersen DKG is the "production-pragmatic" choice. Bitcoin, Filecoin, and Ethereum all live with Pedersen DKG variants. BLOCH does the same.

### Centralized dealer rejected

A trusted dealer is the simplest implementation but contradicts BLOCH's fair-launch thesis. Founder generating the keys and distributing them is:

- Cryptographically equivalent to "founder is god" — entire FFG committee trusts founder's HSM
- Fatal for MFSA/MiCA review — regulators will flag this immediately
- Inconsistent with BLOCH's narrative of post-quantum decentralized consensus

Rejected without further consideration.

## Consequences

### Positive
- Lowest engineering risk (reuse of audited PoBRS DKG)
- Lowest audit cost (one audit covers two systems)
- Industry-standard posture for regulatory review
- Founder retains zero key control — pure fair-launch mechanics

### Negative
- Theoretical rushing adversary concern remains. Mitigation: monitor on-chain DKG output entropy; if bias detected, hard-fork to Gennaro DKG in V2.
- Pedersen DKG requires honest majority during ceremony itself (BFT during DKG). If 8+ of 21 validators are byzantine during DKG, ceremony fails or produces compromised key. Mitigation: hashrate election prefers known-honest miners; DKG retry mechanism on failure.

### Neutral
- 3 rounds of communication per DKG ceremony (~30 seconds wall clock with ~1s round-trip latency between geo-distributed validators).
- Each ceremony produces ~10KB of state distributed to participants; aggregate pubkey 48 bytes.

## Implementation notes

Generalization of `src/pobrs/bls.rs::dkg` module:

```rust
// Current PoBRS signature:
pub fn run_dkg(
    participants: &[BlsPubkey],   // 12 oracle pubkeys
    threshold: usize,             // 7
) -> Result<DkgOutput, DkgError>;

// Sprint 2.1 generalization:
pub fn run_dkg<const N: usize>(
    participants: &[BlsPubkey; N],
    threshold: usize,
) -> Result<DkgOutput, DkgError>;
```

The existing PoBRS code path uses `Vec<>` internally; the const generic on the API surface is purely for type-safety in callers. FFG will instantiate with N=21, threshold=14.

DKG ceremony orchestration runs in `src/ffg/dkg.rs` (new module), reusing the protocol primitives from PoBRS.

## References

- Pedersen, T. P. (1991). "Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing."
- Gennaro, R., Jarecki, S., Krawczyk, H., Rabin, T. (1999). "Secure Distributed Key Generation for Discrete-Log Based Cryptosystems."
- BLOCH RFC-001 §6 (Committee Management)
- BLOCH ADR-001 (FFG Signature Primitive — ML-DSA-65 over Falcon)
