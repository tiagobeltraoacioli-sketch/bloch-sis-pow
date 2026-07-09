# ADR-031 — Sprint 2.1.D Deferrals (Bonding Closure)

**Status:** Accepted
**Date:** 2026-05-02
**Sprint:** 2.1.D (closure)
**Author:** BLOCH Founder
**Related:** ADR-005 (committee era rotation, §4.3 cap=1), ADR-007 (bonding contract + slashing), ADR-011 (FFG activation block height), ADR-013 (open — tiered slashing)

---

## 1. Context

Sprint 2.1.D ("bonding lifecycle"), per ADR-007 §6, was scoped to deliver
the bonding **registry, transaction types, and lifecycle state machine**
for BLOCH validators. Slashing, soft-eviction, and authorization signature
verification were explicitly listed as Sprint 2.1.E work.

Over Days α–ζ (2026-05-02), the sprint produced:

- 6 new column families in `crate::storage` (CF_BONDING_*: META, REGISTRY,
  BY_UID, BY_PUBKEY, HISTORY, PARTICIPATION).
- `crate::bonding::types` — `BondId`, `BondStatus`, `SlashReason`,
  `BondRecord`, `SlashEvent`, `ParticipationRecord`, plus 8 ADR-mandated
  constants (`MIN_BOND_AMOUNT`, `UNBONDING_PERIOD_BLOCKS`,
  `MIN_PRE_ACTIVATION_BONDING_BLOCKS`, `EQUIVOCATION_SLASH_BPS`,
  `INACTIVITY_THRESHOLD_NUMERATOR/DENOMINATOR`,
  `SLASH_HISTORY_RETENTION_BLOCKS`, `FFG_ACTIVATION_HEIGHT`).
- `crate::bonding::storage::BondingStorage<'a>` — full CRUD per CF +
  schema versioning + `next_bond_id` atomic counter.
- `crate::bonding::tx` — 4 transaction types (`BondValidatorTx`,
  `IncreaseBondTx`, `UnbondValidatorTx`, `WithdrawBondTx`) + opaque
  `FundingProof` enum, each with `validate_shape()` syntactic checks.
- `crate::bonding::registry::BondingRegistry<'a>` — high-level state
  machine: `submit_bond`, `activate_eligible_bonds`, `increase_bond`,
  `initiate_unbond`, `finalize_era_exits`,
  `process_unbonding_completions`, `withdraw`, plus
  `has_active_position` / `has_pubkey_registered` cap=1 queries.
- 78 unit tests + 7 integration tests (cumulative across α–ζ).

This ADR captures items consciously **deferred** during the sprint, with
their target sprint and rationale, so future contributors can locate
the gaps without forensic git archaeology.

## 2. Decision Drivers

- **D1.** Sprint 2.1.D had a defined scope (registry + tx types +
  lifecycle); slashing semantics were always Sprint 2.1.E per ADR-007 §6.
- **D2.** Authorization signature verification requires integration with
  `crate::crypto::bls` and a canonical message format that is itself
  consensus-critical; rushing it to fit Sprint 2.1.D would risk a
  brittle integration that gets reworked in 2.1.E anyway.
- **D3.** Funding proof concrete implementation requires synchronisation
  with the consensus team's UTXO/balance reference design (per ADR-007
  §5.3 R4); the opaque `FundingProof::Placeholder` was always a known
  placeholder.
- **D4.** WriteBatch atomicity for multi-CF writes (registry + uid index
  + pubkey index) is best-practice but not strictly necessary while the
  chain is not running.
- **D5.** Capturing deferrals in a new ADR (vs amending ADR-007) is
  cheaper and keeps ADR-007 stable as the reference document.

## 3. Deferrals

### 3.1 Authorization signature verification → Sprint 2.1.E

- **What:** `UnbondValidatorTx.authorization` and
  `WithdrawBondTx.authorization` are 96-byte BLS signatures that must
  be verified against the bond's stored `bls_pubkey`. Today, only the
  shape check (rejection of all-zero) is enforced via
  `validate_shape()`.
- **Why deferred:** Requires `crate::crypto::bls::verify_g2_compressed`
  integration and a canonical signing message format
  (e.g., `b"unbond_v1" || bond_id (8B BE) || at_block (8B BE)`). The
  message format is a hash-and-sign design choice that affects future
  hardware-wallet compatibility; rushing it creates churn risk.
- **Sprint 2.1.E plan:** Add `BondingRegistry::verify_unbond_authorization`
  / `verify_withdraw_authorization` helpers; call from `initiate_unbond`
  and `withdraw`. Rejection error variant `BondingError::InvalidAuthorization`
  already exists.

### 3.2 Funding proof concrete implementation → Sprint 2.1.E

- **What:** `BondValidatorTx.funding_proof` and
  `IncreaseBondTx.funding_proof` are `FundingProof::Placeholder { commitment }`
  with no on-chain verification. Real funding (UTXO consumption or
  balance debit) is not enforced.
- **Why deferred:** Per ADR-007 §5.3 R4, the funding mechanism requires
  consensus-team coordination to choose between UTXO (Bitcoin-style),
  balance-reference (account model), or hybrid. The choice has
  downstream effects on block executor design.
- **Sprint 2.1.E plan:** Add `FundingProof::Utxo { txid, output_idx, ... }`
  variant + verifier that consumes the UTXO during `submit_bond`/
  `increase_bond` execution. Existing `FundingProof::Placeholder`
  variant remains for tests / migration.

### 3.3 WriteBatch atomicity → Sprint 2.1.E

- **What:** `BondingRegistry::submit_bond` performs three sequential
  `put_cf` operations (registry + UID index + pubkey index). If a
  process crashes mid-call, the database may have orphan index entries
  pointing to non-existent records, or vice versa.
- **Why deferred:** No real submissions exist (chain not running);
  development-time inconsistencies are recoverable by devnet reset.
- **Sprint 2.1.E plan:** Wrap multi-CF writes in `rocksdb::WriteBatch`.
  The defensive `None`-handling in `has_active_position` (orphan-tolerant)
  remains correct under the new path, just unreachable.
- **Affected methods:** `submit_bond`, `withdraw` (3 deletes).

### 3.4 `apply_equivocation_slash` + `soft_evict` → Sprint 2.1.E

- **What:** ADR-007 §4.5 (slashing semantics) and §4.6 (soft eviction
  trigger). These transition `InCommittee → Slashed` and update
  `ParticipationRecord` for soft eviction.
- **Why deferred:** Always Sprint 2.1.E per ADR-007 §6.
- **Sprint 2.1.E plan:** New methods on `BondingRegistry`:
  `apply_equivocation_slash(bond_id, evidence_hash, at_block)` and
  `soft_evict(bond_id, epoch)`. Integration with `ParticipationTracker`
  for inactivity threshold computation (cross-multiplication, no float).

### 3.5 Operator identity full model → Sprint 2.1.E

- **What:** `OperatorUid([u8; 32])` is currently a minimalist opaque
  identifier. ADR-005 §4.2 (rev1) anticipates a richer model:
  jurisdiction metadata, miner-pubkey-to-UID mapping
  (anti-fragmentation per §4.3), key rotation policy.
- **Why deferred:** Day α scope decision (planning session 2026-05-02)
  to keep `OperatorUid` minimal in 2.1.D. Cap=1 enforcement works
  byte-wise on the 32-byte UID.
- **Sprint 2.1.E plan:** New module `crate::ffg::operator_identity` (or
  similar) with `OperatorIdentity` struct wrapping `OperatorUid` plus
  metadata. Backward-compatible: 32-byte `OperatorUid` becomes the
  primary key inside the richer struct.

### 3.6 Iterator streaming optimization → optional Sprint 2.1.E

- **What:** `BondingStorage::iter_all_bonds` returns `Vec<BondRecord>`
  by collecting all records into memory. `BondingRegistry::activate_eligible_bonds`,
  `finalize_era_exits`, and `process_unbonding_completions` use it.
- **Why deferred:** For Sprint 2.1.D scale (~21 active committee + ~50–200
  candidate bonds), full collection is fine. Memory cost is small.
- **Sprint 2.1.E plan (conditional):** If profiling shows pressure with
  >10k bonds, switch to a streaming iterator interface. Otherwise,
  leave as-is.

## 4. Decision

Each deferral above is **explicitly accepted** as Sprint 2.1.D's exit
state. No work blocks Sprint 2.1.E from starting; each deferral has a
clear interface/integration contract documented above.

ADR-007 remains the reference document for bonding semantics. This ADR
exists as a checklist for Sprint 2.1.E onboarding.

## 5. Consequences

### 5.1 Positive

- Sprint 2.1.D closes with a clean, tested, consensus-critical
  state machine. 78 unit + 7 integration tests, 0 failing.
- ADR-007 stays stable; no in-place edits.
- Sprint 2.1.E onboarding has a checklist.

### 5.2 Negative

- The bonding subsystem cannot be exercised in production without
  Sprint 2.1.E completion (no real funding, no real authorization, no
  slashing). This is consistent with ADR-007 §6 and was always the plan.
- `submit_bond`'s 3-put non-atomicity is theoretically observable to
  attackers if Sprint 2.1.E is delayed and devnet starts running. Risk
  is low because the orphan paths are defensively handled in
  `has_active_position`/`has_pubkey_registered`.

### 5.3 Open risks

- **R1.** If Sprint 2.1.E priority shifts to other components (oracle
  network, L2 bridge), bonding remains in Sprint 2.1.D state for an
  extended period. Mitigation: document state explicitly (this ADR);
  re-confirm scope at Sprint 2.1.E kickoff.
- **R2.** Authorization message format (§3.1) chosen in 2.1.E may
  conflict with later wallet/HSM integration plans. Mitigation: get
  ADR-007 amendment + counsel review before locking in the format.

## 6. Implementation Plan

### Sprint 2.1.E

1. Authorization verification (§3.1).
2. Funding proof concrete impl (§3.2) — coordinated with consensus team.
3. WriteBatch atomicity (§3.3).
4. `apply_equivocation_slash` + `soft_evict` (§3.4) — also covers
   `ParticipationTracker` integration.
5. Operator identity full model (§3.5) — at minimum, jurisdiction
   metadata for ADR-005 §4.3 anti-fragmentation.
6. Optional: streaming iterator (§3.6) if needed.

### Tag

`v0.5.0-sprint-2.1.d-bonding-closed` on the `sprint-2.1-d-bonding`
branch (HEAD after Day ζ commit).

Note: this is distinct from `v0.3.1-sprint-2.1.d-closed` (tokenomics v2
mechanical, Sprint 2.1.D in an earlier numbering). The unfortunate name
collision reflects that the project's "Sprint 2.1.D" identifier was
reused after the tokenomics work moved to Sprint 2.1.D-tokenomics in
informal notes.

## 7. References

- ADR-005 — Committee era rotation (§4.3 rev1: cap=1)
- ADR-007 — Bonding contract + slashing
- ADR-011 — FFG activation block height
- Sprint 2.1.D commits: 5ffe836 (α), 2c1fb38 (β), 3994f5c (γ),
  21839b6 (δ), 670ebe9 (ε), and the Day ζ commit closing this ADR.
