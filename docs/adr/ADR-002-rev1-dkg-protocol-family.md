# ADR-002-rev1: DKG Protocol Family

**Sprint:** 2.1.C
**Status:** Proposed (ratified for commit pre-2026-05-15)
**SUPERSEDED BY:** ADR-002-rev2 (2026-04-30) — see rev2 section 3.3 for rationale
**Date:** 2026-04-29
**Author:** BLOCH Core
**Supersedes:** ADR-002 (Pedersen-VSS DKG, 2026-04-29 morning) — superseded same day after discovery that the rationale "reuses PoBRS audited code" was incorrect (PoBRS contains only `verify_aggregate_signature`, no DKG primitives).
**Related:** ADR-001 (FFG epoch=6, 21-of-21, supermajority 14), ADR-003 (Refuse <21 — pre-condition), ADR-005 (Committee era — DKG schedule consumer), ADR-007 (Bonding contract — bonded set as DKG participant source from era 2 onward), ADR-009 (open — DKG-not-completed fallback)

---

## 1. Context

ADR-001 specified the FFG hybrid signature scheme (BLS12-381 aggregate + ML-DSA-65 individual). The aggregate BLS signature requires a **collective public key** known to verifiers and a private share held by each of the 21 committee members. This collective key cannot be produced by any single party — its generation is the **Distributed Key Generation (DKG)** problem.

The original ADR-002 (drafted same morning as Sprint 2.1.A) proposed implementing a Pedersen-VSS-based DKG in-house, with the rationale "reuses PoBRS audited code." Investigation during Sprint 2.1.A (2026-04-29) revealed this rationale is false:

- `src/pobrs/bls.rs` (236 lines) contains only `verify_aggregate_signature`. No DKG primitives, no VSS, no commitment schemes.
- The audited PoBRS code does not transfer to FFG DKG needs.
- Building Pedersen-VSS DKG from scratch requires ~3000-5000L of cryptographic code with substantial audit cost.

This rev1 supersedes ADR-002 entirely. It also formalizes the architectural pivot of 2026-04-29 (decision D2): adopt **real DKG now** rather than a transitional trusted dealer, by wrapping an existing audited library.

## 2. Decision Drivers

- **D1.** FFG aggregate signing requires a collective BLS12-381 key. No alternative cryptographic primitive avoids DKG without sacrificing post-quantum aggregate properties or auditability.
- **D2.** The BLOCH team has 1 cryptographer-equivalent. Implementing Pedersen-VSS or GJKR DKG from scratch is a 6-12 month engagement with ~$200-400k audit cost. Wrapping an audited library is 2-4 weeks of engagement.
- **D3.** Mainnet target is Q2 2027 (revised from Q4 2026/Q1 2027). DKG cannot be the long pole.
- **D4.** Committee rotation per ADR-005 (era = 24 epochs, ~24h) needs DKG running ~1×/day. The implementation must amortize, not be a one-time event.
- **D5.** Genesis is a one-time event. Trusted dealer for genesis is acceptable if combined with HSM ceremony; subsequent eras need real DKG.
- **D6.** Network strategy must evolve: in-band (DKG messages as tx types) is simpler for Sprint 2.1.C bootstrap; out-of-band libp2p is more efficient long-term.
- **D7.** A single bug in the BLS12-381 adapter compromises the collective key for the entire era. This is the most critical surface in Sprint 2.1.C.

## 3. Considered Options

### 3.1 DKG protocol family

| Option | Algorithm | Crate / source | Assessment |
|--------|-----------|----------------|------------|
| A1 | Pedersen-VSS in-house | None (write from scratch) | **Rejected** — 6-12 month engagement; no audit budget |
| A2 | GJKR-99 in-house | None (write from scratch) | Rejected — same reasoning as A1 |
| **A3** | **Gennaro 2007 wrapped** | **`gennaro-dkg` v0.9.0-rc2 (mikelodder7), Kudelski audit** | **Selected** — proven, audited, 5-round protocol |
| A4 | FROST DKG | `frost-core` | Rejected — Schnorr-based, incompatible with FFG aggregate BLS |
| A5 | Trusted dealer transitional | None | Rejected for steady state — only acceptable for genesis |

Gennaro 2007 is a refinement of GJKR-99 that fixes the rushing adversary attack present in the 1999 paper. The protocol runs in 5 rounds:

1. **Round 1 (Commit):** each participant generates a random polynomial of degree t-1, broadcasts Pedersen commitments.
2. **Round 2 (Share):** each participant sends private shares to other participants over authenticated channels.
3. **Round 3 (Complaint):** participants who received invalid shares broadcast complaints.
4. **Round 4 (Justify):** complained-against participants reveal their shares publicly to refute.
5. **Round 5 (Reveal):** non-disqualified participants reconstruct the collective public key.

For BLOCH: n = 21 participants, threshold t = 14 (supermajority).

### 3.2 Curve adapter strategy

| Option | Approach | Assessment |
|--------|----------|------------|
| B1 | Use `gennaro-dkg`'s default curve (Stark-friendly) | Rejected — incompatible with BLS12-381 used by FFG |
| **B2** | **Adapter `EntlG1`/`EntlScalar` wrapping `bls12_381` crate** | **Selected** — bridges `vsss_rs::elliptic_curve::Group` trait to `bls12_381::G1Projective` |
| B3 | Fork `gennaro-dkg` to use BLS12-381 directly | Deferred — option open for BLOCH Labs in v2 if maintenance burden justifies |

The adapter approach is the **most critical engineering surface in Sprint 2.1.C**. A bug in `EntlG1::add_assign`, `EntlG1::eq`, or `EntlScalar::invert` compromises the collective key. Mitigations are detailed in §5.3 (R5).

### 3.3 Network protocol for DKG messages

| Option | Approach | Sprint | Assessment |
|--------|----------|--------|------------|
| **C1** | **In-band: DKG messages as tx types** | **2.1.C** | **Selected for v1** — simpler bootstrap; participants discovered via committee state |
| **C2** | **Out-of-band: libp2p direct messaging** | **2.1.D+** | **Selected for v2** — more efficient; doesn't consume block space |
| C3 | Hybrid: in-band commitments, out-of-band shares | Future | Deferred — adds complexity without clear v1 win |

Per Sprint 2.1.C plan, the in-band protocol consumes ~100-500KB per DKG ceremony (105 messages × ~1-5KB each). This is amortized over 24 hours and is acceptable as a bootstrap mechanism.

### 3.4 Genesis approach

| Option | Approach | Assessment |
|--------|----------|------------|
| D1 | DKG at genesis with self-bootstrapping participants | Rejected — chicken-and-egg: no chain to coordinate before genesis |
| **D2** | **21 founder-declared hardcoded keys at genesis (era 1); Phragmén-elected DKG from era 2 onward** | **Selected** — accepts era-1 centralization in exchange for clean architectural separation |
| D3 | External MPC ceremony à la Zcash/Filecoin | Deferred — over-engineered for current scale; reconsider pre-mainnet if budget permits |

Genesis 21 keys are generated **offline, air-gapped, in HSM ceremony** before mainnet launch (ADR-007 covers ceremony procedure — *open*). They are placeholders during Sprints 2.1.C-D, replaced with production keys during the pre-mainnet hardening window.

## 4. Decision Outcome

**Consolidated decision:** A3 + B2 + C1→C2 transition + D2.

### 4.1 Cargo.toml additions

```toml
[dependencies]
gennaro-dkg = "=0.9.0-rc2"
vsss-rs = { version = "4.3", default-features = false, features = ["std"] }
# bls12_381 already present (PoBRS deps)
# serde-big-array already present
# bincode 2 already present
```

Pinned versions to avoid silent upgrade affecting consensus determinism. Updates require explicit ADR amendment.

### 4.2 Module structure

```
src/ffg/dkg/
├── mod.rs                 // Re-exports + DkgConfig, CeremonyResult, CeremonyState, CeremonyMessage
├── bls_adapter.rs         // EntlG1, EntlScalar wrapping bls12_381 (CRITICAL)
├── ceremony.rs            // CeremonyOrchestrator: 5-round state machine
├── network.rs             // In-band (Sprint 2.1.C) / libp2p stub (Sprint 2.1.D+)
├── genesis_bootstrap.rs   // GENESIS_PARTICIPANTS const + genesis_dkg_config()
└── tests/                 // Unit + integration (mock network)
```

### 4.3 Core types (in `src/ffg/dkg/mod.rs`)

```rust
//! Distributed Key Generation (DKG) for FFG committee.
//!
//! Implements Gennaro 2007 (refinement of GJKR-99) over BLS12-381,
//! via wrap of the audited `gennaro-dkg` crate (mikelodder7).
//!
//! See ADR-002-rev1 for full specification.

use serde::{Serialize, Deserialize};
use crate::ffg::committee_types::{BlsPubkey, MlDsaPubkey};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DkgConfig {
    /// Number of participants. v1: always 21.
    pub n: u32,
    /// Reconstruction threshold. v1: always 14.
    pub t: u32,
    /// Unique ceremony identifier (sha256 over context).
    #[serde(with = "serde_big_array::BigArray")]
    pub ceremony_id: [u8; 32],
    /// Epoch at which the ceremony starts (era_start + DKG_OVERLAP_OFFSET = era_start + 12).
    pub run_epoch: u64,
    /// Epoch at which the resulting committee activates (era N+1 epoch 0).
    pub target_epoch: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CeremonyResult {
    pub config: DkgConfig,
    pub aggregate_pubkey: BlsPubkey,
    pub participant_pubkeys: Vec<BlsPubkey>,
    pub completed_at_round: u8,
    /// Bitmask of participants who completed (21 bits, padded to 3 bytes).
    pub completion_mask: [u8; 3],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CeremonyState {
    pub config: DkgConfig,
    pub current_round: u8,
    pub round_start_epoch: u64,
    pub messages: Vec<CeremonyMessage>,
    /// Indices of participants who have been disqualified.
    pub dropped: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CeremonyMessage {
    pub round: u8,
    pub sender_idx: u8,
    pub payload: Vec<u8>,  // bincode-encoded gennaro-dkg round message
}
```

### 4.4 New errors (extend `src/ffg/errors.rs`)

```rust
/// DKG-specific error variants.
/// Follows BLOCH convention: manual `impl Display` (no `thiserror` derive).
pub enum DkgError {
    AdapterMismatch(String),
    InvalidCeremonyId,
    RoundOutOfOrder { expected: u8, got: u8 },
    InvalidShare { sender_idx: u8 },
    ComplaintUnjustified { complainer_idx: u8 },
    InsufficientCompletion { completed: u32, threshold: u32 },
    UnderlyingDkg(String),
    Storage(StorageError),
}

impl fmt::Display for DkgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AdapterMismatch(s) => write!(f, "BLS12-381 adapter mismatch: {}", s),
            Self::InvalidCeremonyId => write!(f, "ceremony_id does not match active state"),
            Self::RoundOutOfOrder { expected, got } => {
                write!(f, "DKG round out of order: expected {}, got {}", expected, got)
            }
            Self::InvalidShare { sender_idx } => {
                write!(f, "invalid DKG share from participant {}", sender_idx)
            }
            Self::ComplaintUnjustified { complainer_idx } => {
                write!(f, "unjustified complaint from participant {}", complainer_idx)
            }
            Self::InsufficientCompletion { completed, threshold } => {
                write!(f, "DKG insufficient completion: {}/{} required", completed, threshold)
            }
            Self::UnderlyingDkg(s) => write!(f, "underlying gennaro-dkg error: {}", s),
            Self::Storage(e) => write!(f, "DKG storage error: {}", e),
        }
    }
}

impl std::error::Error for DkgError {}
```

### 4.5 New column families (extend `src/storage/mod.rs`)

```rust
pub(crate) const CF_FFG_DKG_STATE:    &str = "ffg_dkg_state";
pub(crate) const CF_FFG_DKG_RESULT:   &str = "ffg_dkg_result";
pub(crate) const CF_FFG_DKG_MESSAGES: &str = "ffg_dkg_msgs";

// Add 3 ColumnFamilyDescriptors in Storage::open()
ColumnFamilyDescriptor::new(CF_FFG_DKG_STATE,    Options::default()),
ColumnFamilyDescriptor::new(CF_FFG_DKG_RESULT,   Options::default()),
ColumnFamilyDescriptor::new(CF_FFG_DKG_MESSAGES, Options::default()),
```

Total CFs after Sprint 2.1.C: 24 → 27.

### 4.6 BLS12-381 adapter contract

`EntlG1` and `EntlScalar` MUST satisfy:

1. **Determinism.** All operations produce bit-identical results across x86_64, aarch64, and any LLVM-supported target. Equality (`eq`) compares affine coordinates, never projective (which carry random Z components).
2. **Compatibility.** `EntlG1::generator()` returns the same point as `bls12_381::G1Projective::generator()`. Round-tripping via `to_bytes`/`from_bytes` is identity.
3. **Trait completeness.** All required methods of `vsss_rs::elliptic_curve::Group` and `vsss_rs::elliptic_curve::PrimeField` are implemented; no `unimplemented!()` remains in production builds.
4. **Property-tested.** At minimum: associativity, identity, inverse, distributivity, scalar-zero, generator-times-zero, encoding round-trip, and group operations consistency (`(a + b).to_affine() == a.to_affine() + b.to_affine()`).

### 4.7 DKG lifecycle

```
era N starts at epoch K = N × 24
  ↓
era N + DKG_OVERLAP_OFFSET = epoch K + 12
  → Genesis or current era's CommitteeRegistry triggers
    new CeremonyState in CF_FFG_DKG_STATE.
  ↓
epochs K+12 .. K+24 (12 epochs ≈ 6h):
  Round 1 starts. Participants exchange messages
  in-band via DkgRoundMessageTx (Sprint 2.1.C) or
  libp2p (Sprint 2.1.D+). State advances per
  CeremonyOrchestrator. Messages persisted in
  CF_FFG_DKG_MESSAGES.
  ↓
Round 5 completion within window:
  CeremonyResult written to CF_FFG_DKG_RESULT.
  PendingCommittee in CF_FFG_PENDING_COMMITTEE
  references the result.
  ↓
era N+1 starts at epoch K+24:
  CommitteeRegistry::activate() consumes
  CeremonyResult → updates active committee.
```

If Round 5 does not complete by epoch K+24 (DKG failure), see §5.3 R1 and ADR-009 (open).

### 4.8 Sprint 2.1.C phase mapping

| Phase | Tag | Component | Deliverable |
|-------|-----|-----------|-------------|
| α (alpha) | `v0.2.1.c.alpha-deps` | §4.1, §4.2, §4.3, §4.5 | Cargo deps, module skeleton, types, CFs. Build green, 0 functional code. |
| β (beta) | `v0.2.1.c.beta-adapter` | §4.6 | `EntlG1`, `EntlScalar` complete. ~50 unit tests, ~30 property tests. |
| γ (gamma) | `v0.2.1.c.gamma-ceremony` | §4.7 partial | `CeremonyOrchestrator` 5 rounds. Mock in-process network. Happy + 3 failure paths. |
| δ (delta) | `v0.2.1.c.delta-genesis` | §4.7 + integration | `GENESIS_PARTICIPANTS` const, `genesis_dkg_config()`, `CommitteeRegistry::activate` integration. Full flow integration test. |
| ε (epsilon) | `v0.2.1.c-dkg` (final) | §4.7 in-band network | `DkgRoundMessageTx` type, mempool validation, block executor integration. |

## 5. Consequences

### 5.1 Positive

- **Audit surface bounded.** ~500-800L of adapter code + ~600-1000L of orchestration; the cryptographic core (`gennaro-dkg`) is already audited (Kudelski).
- **Ratio of build:audit cost favorable.** Wrapping vs in-house: ~10× faster build, ~5× lower audit cost.
- **Extensible.** Replacing `gennaro-dkg` with an BLOCH Labs fork in v2 is a swap of the wrapped library; the orchestrator remains.
- **Standard cryptography.** Gennaro 2007 is well-studied; integrators and auditors are familiar with the protocol.
- **Network strategy progressive.** In-band v1 → libp2p v2 keeps Sprint 2.1.C complexity bounded.

### 5.2 Negative

- **External dependency.** `gennaro-dkg = "=0.9.0-rc2"` is a release candidate. If the crate is abandoned or has a critical bug not yet patched, BLOCH must fork. Mitigation: track upstream actively; vendor the source in `vendor/` after v1.0.0 stable release.
- **Adapter is critical surface.** A subtle bug in `EntlG1` (e.g., non-deterministic equality) breaks consensus silently. Mitigation: §4.6 adapter contract + cross-platform property tests.
- **Genesis centralization trade-off.** Era 1 with 21 founder-declared keys is a centralization concession. Justified by chicken-and-egg, but visible in narrative. Mitigation: explicit hardening ceremony + transparent reporting.
- **In-band consumes block space.** ~100-500KB per DKG ceremony. Acceptable v1; migration to libp2p in Sprint 2.1.D+.

### 5.3 Open risks

- **R1.** DKG fails to complete within the 12-epoch window. Causes: malicious participants, network partition, software bug in adapter or orchestrator. Mitigation: 6-epoch grace period (extends current era); full fallback specified in ADR-009 (open).
- **R2.** `gennaro-dkg` upstream introduces breaking change between rc2 and 1.0.0. Mitigation: pinned version + fork-ready vendor strategy.
- **R3.** Genesis 21 keys leak before mainnet. Catastrophic — attacker can forge `FinalityCertificate`, revert finalized blocks, censor transactions. Mitigation: HSM-grade key generation (Yubico, Thales, AWS CloudHSM); multi-party ceremony (founder + 2+ independent observers); air-gapped offline machine; geographically split key shards; key rotation after era 1 via Phragmén-elected DKG in era 2. Procedure to be specified in pre-mainnet ceremony ADR (open).
- **R4.** In-band DKG message flood DoS. 105 txs × ~5KB each = ~500KB during ceremony window. Mitigation: dedicated DKG mempool (DKG txs do not compete with normal txs); migrate to libp2p in Sprint 2.1.D+.
- **R5.** Determinism failure in BLS12-381 adapter. The `bls12_381` crate has feature flags (`bits`, `groups`, `pairings`, `alloc`, `nightly`, `experimental`); if `EntlG1` inherits non-deterministic behavior (e.g., random Z-coordinates in projective equality check), consensus breaks. Mitigation: `bls12_381::G1Projective::eq()` uses affine internally — deterministic; property tests must include `(a + b).to_affine() == c.to_affine()`; cross-check x86 vs ARM in testbed before each tag.

## 6. Implementation Plan

Sprint 2.1.C delivers this ADR in 5 incremental phases (see §4.8). Each phase has its own tag, build green, and tests passing before the next phase starts.

**Hard deadline:** Sprint 2.1.C kickoff 2026-05-15; estimated end ~2026-06-12.

**Critical path:**

- α (Day 1) — boilerplate + deps + CFs + types. Low risk.
- β (Days 2-8) — adapter. **Highest risk in entire sprint.** Allow 1 week with buffer.
- γ (Days 9-13) — ceremony orchestrator. Medium risk; mock network simplifies testing.
- δ (Days 14-16) — genesis bootstrap + integration. Low risk if α-γ are clean.
- ε (Days 17-22) — in-band network. Medium risk; mempool/executor changes touch consensus path.

If β slips by more than 5 days, escalate: consider reducing scope of γ-ε to ε-only (pure in-band, skip libp2p stub).

## 7. Future Work

- **Sprint 2.1.D:** migrate network from in-band to libp2p out-of-band. Reduces block space pressure.
- **ADR-007 ceremony procedure (open):** HSM-grade genesis key generation. Required pre-mainnet.
- **ADR-009 (open):** DKG-not-completed fallback protocol. Required pre-mainnet.
- **v2 ADR (open):** Evaluate BLOCH Labs fork of `gennaro-dkg` if upstream maintenance becomes a liability.
- **v2 research:** Single-Slot Finality with ML-DSA-65 aggregate signatures (no DKG required for ML-DSA — academic paper potential).

## 8. References

- ADR-001 — FFG signature scheme (BLS12-381 + ML-DSA-65 hybrid)
- ADR-005 — Committee era and rotation (DKG schedule consumer)
- ADR-007 — Bonding contract (open) — bonded set as DKG participant source from era 2
- ADR-009 — DKG-not-completed fallback (open)
- Gennaro, Jarecki, Krawczyk, Rabin (1999). *Secure Distributed Key Generation for Discrete-Log Based Cryptosystems*. Journal of Cryptology.
- Gennaro, Jarecki, Krawczyk, Rabin (2007). Same title, vol. 20. Refinement closing the rushing adversary attack.
- Kate, Huang, Goldberg (2012). *Distributed Key Generation in the Wild*. IACR ePrint 2012/377.
- Buterin & Griffith (2017). *Casper FFG paper*.
- `gennaro-dkg` crate: https://github.com/mikelodder7/gennaro-dkg (Kudelski-audited)
- `vsss-rs` crate: https://docs.rs/vsss-rs
- BLS12-381 spec: https://hackmd.io/@benjaminion/bls12-381
- Sprint 2.1 architectural decision document (BLOCH Core, 2026-04-29)
