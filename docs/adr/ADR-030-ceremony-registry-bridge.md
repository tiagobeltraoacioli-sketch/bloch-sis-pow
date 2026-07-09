# ADR-030 — DKG Ceremony → CommitteeRegistry Bridge

**Status:** Accepted
**Date:** 2026-05-02
**Sprint:** 2.1.C-rev2 (Phase δ)
**Author:** BLOCH Founder
**Related:** ADR-002-rev2 (DKG protocol family), ADR-004 (DKG epoch overlap), ADR-005 (committee era rotation), ADR-011 (FFG activation block height), ADR-022 (hash-to-curve and BLS group layout)
**Supersedes:** prior `bootstrap.rs` placeholder pre-ADR-011 (the historic 21-hardcoded-keys design referenced in ADR-002-rev1 §3.4 D2/R3)

---

## 1. Context

By the end of Sprint 2.1.C-rev1 (Phase γ Day 10, 2026-05-01), BLOCH had:

- A complete 5-round Gennaro DKG ceremony state machine
  (`src/ffg/dkg/ceremony.rs`, ~1300 LoC) with `R5KeyDerivedPhase` producing
  `collective_public_key()` and per-participant shares.
- A `CommitteeRegistry` (`src/ffg/committee_registry.rs`) wrapping
  `FfgStorage` with `commit_pending → activate → get_committee` lifecycle
  (ADR-004 epoch overlap).
- A `DkgResult` struct (`src/ffg/committee_types.rs`) and `PendingCommittee`
  struct, both serde-stable.

What was missing was the **glue** — the marshalling of cryptographic
ceremony output into the on-chain `PendingCommittee` record consumed by
`CommitteeRegistry::commit_pending`. The Phase α scaffold (`bootstrap.rs`
~50 LoC stub) was written before ADR-011 cancelled the genesis-21-hardcoded-keys
plan, so it referenced obsolete lore (V1 wallet hashes, 21-key constants)
and a function `genesis_bootstrap()` that returned `NotImplemented`.

Phase δ replaces that stub with the real bridge.

### Why a two-stage bridge

The marshalling has two distinct concerns that benefit from being separated:

1. **Cryptographic concern** — extracting the threshold pubkey and
   participant identity pubkeys from the ceremony into a `DkgResult`.
   Touches G1 points and BLS-spec encoding.
2. **Election-context concern** — combining the `DkgResult` with election-
   time facts (validator IDs, hashrates, snapshot root, block heights) to
   build a `PendingCommittee`. Touches only scalars and identifiers.

Splitting into two functions:

- Lets each be unit-tested independently (length guards in stage 1 don't
  require election context; election-context guards in stage 2 don't
  require driving a ceremony).
- Keeps the cryptographic boundary clean: stage 1 is the "where the curve
  arithmetic happens" file, stage 2 is the "where the on-chain record
  shape is built" file.
- Makes future refactoring of either side independent (e.g. if BLS
  serialisation changes, only stage 1 moves; if `Committee` gains a
  field, only stage 2 moves).

## 2. Decision

### 2.1 Two-stage architecture in `src/ffg/dkg/bootstrap.rs`

```rust
pub fn ceremony_to_dkg_result(
    ceremony: &Ceremony,
    ceremony_id: [u8; 32],
    bls_pubkeys: Vec<BlsPubkey>,
    mldsa_pubkeys: Vec<MlDsaPubkey>,
) -> Result<DkgResult, DkgError>;

pub fn dkg_result_to_pending_committee(
    dkg_result: DkgResult,
    validator_ids: Vec<u32>,
    hashrates: Vec<u64>,
    snapshot_root: [u8; 32],
    activated_at_height: BlockHeight,
    started_at_height: BlockHeight,
    dkg_epoch: u64,
    target_activation_epoch: u64,
) -> Result<PendingCommittee, DkgError>;
```

Both functions return `DkgError` (specifically `Internal(String)` for
all guard failures) for consistency with the rest of `dkg::types`. No
new error type was introduced.

### 2.2 `aggregate_bls_pubkey` semantics — Gennaro threshold pubkey

`DkgResult.aggregate_bls_pubkey` is set to:

```text
ceremony.collective_public_key()?.to_compressed()
```

i.e. the **Gennaro DKG collective threshold public key** (`Σ A_{i,0}` over
`final_qual`), serialised as 48 bytes per BLS spec compressed encoding.

This is the single key against which a threshold signature aggregate is
verified at FFG attestation time. It is **NOT** a simple sum of individual
identity BLS pubkeys; the per-member `bls_pubkey` field carries those
separately.

The doc string on `DkgResult.aggregate_bls_pubkey` ("Aggregated BLS public
key (sum of participant pubkeys)") was historically ambiguous. Stage 1's
function-level documentation explicitly resolves it in favour of the
threshold-pubkey interpretation, with a one-line revisit point if FFG
signature verification semantics ever change to pure aggregation.

The same value is propagated **unchanged** by stage 2 into
`Committee.bls_aggregate_pubkey`. Stage 2 does not recompute it; the
threshold-pubkey identity is preserved end-to-end.

### 2.3 QUAL ≠ committee membership

If a dealer is disqualified during the ceremony (R3 complaint, R4 missing
justification, or R5 inconsistent Feldman), they are excluded from
`final_qual` and contribute nothing to the collective polynomial
`F = Σ_{i ∈ final_qual} f_i`. They remain valid `n`-participants of
the share-distribution scheme, however, because per Gennaro spec the
collective polynomial produces well-defined shares `F(j)` for **all** `j ∈
{1..n}` regardless of QUAL membership.

The bridge therefore **does not filter** non-QUAL participants out of
the committee. A 4-node ceremony with one disqualified dealer still
produces a 4-member `PendingCommittee` (verified by
`byzantine_survivor_set_at_threshold_boundary` integration test in
Day δ.4).

Whether a non-QUAL slot should be slashed, marked degraded, or excluded
from a future re-election is a **slashing-layer / registry-layer concern
(ADR-007)**, not a bridge concern.

### 2.4 `completed_at_round = 5` (Gennaro 5-round, not 3-round)

The doc comment on `DkgResult.completed_at_round` previously read
`(1, 2, or 3 for Pedersen DKG)`, a stale artefact from the early Phase α
scaffolding when the DKG was envisioned as Pedersen 3-round. Phase γ
implemented Gennaro's 5-round protocol (R1..R5 = commit, share,
complaint, justify, key-derive). Day δ.1 corrected the doc to
`(1..5 for the Gennaro 5-round protocol; R5 = key-derived)` and stage 1
hard-codes the value `5` because the bridge can only run on a ceremony
that reached `R5KeyDerivedPhase`.

### 2.5 Guard ordering — cheap-first

Both bridge functions order their input-validation guards so that
constant-time / no-storage checks run before any ceremony-state
introspection or storage I/O. This lets unit tests for individual guards
be written without setting up a successful ceremony or RocksDB instance.

Stage 1 order:
1. `bls_pubkeys.len() == ceremony.n()`
2. `mldsa_pubkeys.len() == ceremony.n()`
3. `ceremony.is_protocol_successful()`
4. `ceremony.collective_public_key()?` (defends against future divergence
   between guard 3 and `collective_public_key`'s own preconditions)

Stage 2 order:
1. `target_activation_epoch > dkg_epoch` (ADR-004 alignment;
   duplicates the check in `CommitteeRegistry::commit_pending` so a bad
   bridge call fails before any storage involvement).
2. `dkg_result.participant_mldsa_pubkeys.len() == participant_bls_pubkeys.len()`
   (defends against a hand-constructed `DkgResult`).
3. `validator_ids.len() == n`.
4. `hashrates.len() == n`.
5. `n <= 255` (committee_index is `u8`; BLOCH committees are sized 21
   per ADR-005, so this is a defensive bound).

## 3. Consequences

### Positive

- The consensus layer now has a **declarative path** from a successful
  DKG ceremony to an on-chain committee. No glue code is duplicated at
  call sites.
- The cryptographic boundary is cleanly cordoned off in stage 1; stage 2
  is purely structural.
- Unit testing is feasible without driving full ceremonies: stage 1
  guards test on `Ceremony::Idle`, stage 2 guards test on synthetic
  `DkgResult`. End-to-end coverage is provided separately by Day δ.3.
- The historical `genesis_bootstrap` placeholder and pre-ADR-011 lore
  (21-hardcoded-keys, V1 wallet hashes) are removed from the codebase.

### Negative / open

- A ceremony with non-QUAL slots produces a `PendingCommittee` that
  includes those slots as `Active`. The threshold sigs against the
  collective key still verify (because every committee member has a
  valid `F(j)` share), but **a non-QUAL slot has no recourse to its
  own share data** — it can compute `F(j)` only via Lagrange from
  others. This is acceptable for committee bootstrap but should be
  noted by the slashing-layer ADR (ADR-007 follow-up): a member that
  cannot re-derive its own share independently is a long-term
  liveness risk if other committee members later become unreachable.
- Phase ε (in-band DKG transaction types — `DkgTxKind` enum,
  Round{1..5}Tx tx validation, mempool policy) remains stubbed in
  `src/ffg/dkg/network.rs`. The Phase ε design is unaffected by
  Phase δ; it is deferred to a separate sprint.

### Neutral

- ADR-029 number remains reserved per ADR-025 forward-reference; this
  closure ADR takes ADR-030.
- The 8-parameter signature of `dkg_result_to_pending_committee` is
  verbose. A wrapper struct was considered (see §4.3) but rejected.

## 4. Alternatives Considered

### 4.1 Single-stage bridge

**Considered:** A single function
`ceremony_to_pending_committee(ceremony, ceremony_id, validator_ids,
hashrates, ...)` that performs both stages internally.

**Rejected because:** mixes cryptographic and election concerns. A
single 12-parameter function is harder to unit test (every guard
requires both a ceremony and election context), and tightly couples
the BLS encoding choice to the on-chain record shape. The two-stage
design lets either side change independently.

### 4.2 `aggregate_bls_pubkey` as `Σ` of identity BLS pubkeys

**Considered:** Compute `aggregate_bls_pubkey` as the BLS-additive sum
of `participant_bls_pubkeys` rather than from
`collective_public_key()`.

**Rejected because:** BLOCH's threshold-signature scheme verifies an
aggregate against the **collective threshold pubkey**, not the sum of
identity pubkeys. A FROST-style aggregation scheme would use the
identity-sum interpretation, but BLOCH is Gennaro-DKG-based per
ADR-002-rev2.

The doc-string ambiguity ("sum of participant pubkeys") is a historical
artefact predating ADR-002-rev2. If FFG signature verification
semantics ever change, this is the one line to revisit (and it is
documented as such in stage 1's function doc).

### 4.3 Wrapper struct for stage 2 election context

**Considered:** Replace the 5 election-context arguments
(`validator_ids`, `hashrates`, `snapshot_root`, `activated_at_height`,
`started_at_height`) with a single struct
`ElectionContext { ... }`.

**Rejected because:** the call site (consensus layer) already has all
these fields as separate variables — wrapping them just to unwrap them
on the other side adds boilerplate without reducing the conceptual
parameter count. If a future sprint introduces additional election-
context fields, the struct can be added then.

### 4.4 Filter non-QUAL members from `Committee.members`

**Considered:** Stage 2 detects non-QUAL participants via
`ceremony.final_qual()` (cross-checked from stage 1) and excludes
them from the resulting `Committee.members` Vec.

**Rejected because:** stage 2 has no access to the `Ceremony` (it
operates on `DkgResult`, which is post-ceremony). Carrying the QUAL
set through `DkgResult` is technically possible but mixes DKG
correctness state with election-outcome state. Slashing or membership
adjustment is an explicit slashing-layer concern (ADR-007 follow-up).

## 5. Implementation

| Day  | Commit    | Subject                                                  |
| ---- | --------- | -------------------------------------------------------- |
| δ.1  | `402c004` | Stage 1 bridge `ceremony_to_dkg_result`                  |
| δ.2  | `5d3f574` | Stage 2 bridge `dkg_result_to_pending_committee`         |
| δ.3  | `70c6122` | E2E integration test (full pipeline, real RocksDB)       |
| δ.4  | `7b92459` | Edge cases (Byzantine + registry failure modes)          |
| δ.5  | (this)    | Closure ADR                                              |

### Test coverage map

**Unit tests in `src/ffg/dkg/bootstrap.rs` (7):**

Stage 1 (Day δ.1):
1. `rejects_bls_pubkeys_wrong_length`
2. `rejects_mldsa_pubkeys_wrong_length`
3. `rejects_pre_r5_protocol_not_successful`

Stage 2 (Day δ.2):
4. `rejects_target_epoch_not_greater_than_dkg_epoch`
5. `rejects_validator_ids_length_mismatch`
6. `rejects_hashrates_length_mismatch`
7. `happy_path_constructs_pending_committee` (asserts every output
   field of `PendingCommittee` for a synthetic `DkgResult`)

**Integration tests in `tests/`:**

`sprint_2_1_c_rev2_full_pipeline.rs` (Day δ.3, 1 test):
8. `full_pipeline_ceremony_to_activated_committee` — drives 4-node
   honest mock ceremony R1..R5 → both bridges → `commit_pending` →
   `activate` → `get_committee` against real RocksDB; asserts
   cross-perspective collective-pubkey invariance, per-member field
   mapping via marker bytes, `is_in_committee` 4 positives + 1
   negative.

`sprint_2_1_c_rev2_edge_cases.rs` (Day δ.4, 4 tests):
9. `byzantine_survivor_set_at_threshold_boundary` — `inject_bad_feldman(4)`
   → `final_qual = {1,2,3}` (boundary), bridge succeeds, committee has
   4 members.
10. `byzantine_protocol_failure_below_threshold` —
    `inject_bad_feldman(3)+(4)` → `final_qual = {1,2}` < threshold,
    stage 1 rejects.
11. `registry_activate_target_epoch_mismatch` — pending with `target=12`,
    `activate(10, 13)` errors; subsequent correct activate still works.
12. `registry_double_activate_rejected` — full pipeline through
    `activate(10, 12)`, second `activate(10, 12)` errors.

**Total Phase δ test coverage: 12 tests.**
- 7 unit (in lib `ffg::dkg::bootstrap` module)
- 5 integration (in `tests/`)

## 6. References

- ADR-002-rev2 — DKG protocol family (gennaro-dkg fork).
- ADR-004 — DKG epoch overlap (`target_activation_epoch = dkg_epoch + 2`).
- ADR-005 — Committee era rotation (committee size 21, era length 24
  epochs).
- ADR-007 — Bonding contract and slashing (future ADR for non-QUAL
  member handling).
- ADR-011 — FFG activation at block 210k; supersedes
  ADR-002-rev1 §3.4 D2/R3 genesis ceremony.
- ADR-022 — Hash-to-curve and BLS group layout (G1 min-pk, 48-byte
  compressed).

## 7. Phase ε deferral (informational)

`src/ffg/dkg/network.rs` remains stubbed with `validate_dkg_tx` returning
`NotImplemented` and a placeholder `DkgTxKind` enum. Phase ε design
(in-band tx types carrying ceremony messages) is independent of Phase δ
and is deferred to its own sprint, to be scheduled together with the
mainnet activation block-height calibration (ADR-011 §3.2).
