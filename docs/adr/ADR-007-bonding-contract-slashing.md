# ADR-007: Bonding Contract, Slashing, and Participation Tracking

**Sprint:** 2.1.D (bonding registry + tx types) / 2.1.E (slashing + eviction triggers)
**Status:** Proposed (founder ratified 2026-04-29)
**Date:** 2026-04-29
**Author:** BLOCH Core
**Related:** ADR-001 (FFG signature scheme), ADR-002-rev1 (DKG protocol family), ADR-005 (committee era + cap=1 + missed attestation definition), ADR-006 (block time + finality), ADR-009 (open — DKG/activation failure recovery), ADR-010 (tokenomics), ADR-011 (FFG activation block height — bonding lifecycle source of truth), ADR-012 (open — reward policy and counsel review)

---

## 1. Context

ADR-005 defines the committee era (24 epochs ≈ 24h), the Phragmén-based selection function, the cap of 1 seat per operator UID, and the canonical definition of "missed attestation" for slashing/eviction purposes. ADR-011 establishes that FFG activates at block 210,000, that bonding is accepted from D0 in `Pending` state, and that the activation transition at block 210,000 atomically promotes eligible bonds to `Active`.

This ADR specifies the bonding contract itself: how operators submit, increase, and withdraw bonds; how stake is tracked across the bond lifecycle; how slashing executes deterministically; and how participation records feed the eviction triggers in ADR-005 §4.6.

The bonding contract is consensus-critical: a bug in stake accounting, slashing computation, or unbonding queue management can either drain the protocol's economic security (under-slashing) or expropriate honest validators (over-slashing). This ADR optimizes for **deterministic simplicity**: no float arithmetic, no off-chain coordination, no subjective judgments. Every state transition is computable from on-chain state alone.

This ADR explicitly defers reward distribution policy to **ADR-012 (open — counsel review required)**. Here, only neutral participation tracking is implemented; what is paid to whom under what conditions is the subject of ADR-012.

## 2. Decision Drivers

- **D1.** Stake security must be material enough to deter equivocation. With 21 committee seats and the 14-of-21 supermajority threshold, capturing the chain requires bribing or compromising 14 operators. The aggregate slashable stake must be high enough that the cost of this attack exceeds any plausible benefit.
- **D2.** Min stake must be low enough to allow genuine decentralization. Setting min stake to 1M+ BLOCH makes the validator set permissioned by capital. Setting it too low (e.g., 100 BLOCH) allows Sybil at zero economic cost.
- **D3.** Unbonding period must exceed the largest plausible reorg window. Per ADR-006, hard finality is ~30 minutes; pre-activation reorgs can be deeper. A 21-day unbonding period is the established Cosmos/Polkadot pattern, sufficient for slashing detection windows.
- **D4.** Slashing magnitude must be calibrated by trade-off. Too low (1%) makes equivocation a tolerable risk for sophisticated attackers. Too high (50%+) creates over-deterrence and discourages honest operators from running validators (a stuck key bug becomes existential). The Cosmos Hub default of 5% for double-signing is a tested midpoint.
- **D5.** Inactivity threshold must use integer math. Per ADR-005 correction §4.1, `f32 = 0.40` is forbidden; the threshold is expressed as `(NUMERATOR=40, DENOMINATOR=100)` and compared via cross-multiplication.
- **D6.** Cap of 1 seat per UID must be enforced atomically. Per ADR-005 §4.3 (rev1), the cap covers active bonding **OR** alternate **OR** committee — no submission of a second bond under the same UID may succeed if any of these positions is held.
- **D7.** Slash history retention window must allow for late-discovered evidence. Cosmos retains slash history for ~3 years (`525_600` blocks ≈ 1 year; BLOCH adopts a multi-year retention to allow forensic forensics post-mortem).
- **D8.** Reward distribution policy is **not** specified here. ADR-012 covers it, with explicit counsel review for SEC/MiCA compliance. ADR-007 records participation neutrally.

## 3. Considered Options

### 3.1 Min stake amount

| Option | Amount | Fraction of supply (1B) | Assessment |
|--------|--------|-------------------------|------------|
| A1 | 10,000 BLOCH | 0.001% | Rejected — Sybil at trivial cost |
| A2 | 50,000 BLOCH | 0.005% | Marginal; below Cosmos/Polkadot equivalent |
| **A3** | **100,000 BLOCH** | **0.01%** | **Selected — matches Cosmos floor; allows ~10,000 operators in theory** |
| A4 | 500,000 BLOCH | 0.05% | Rejected — permissioned by capital |
| A5 | 1,000,000 BLOCH | 0.1% | Rejected — too high for fair-launch tier |

### 3.2 Unbonding period

| Option | Duration | Blocks @ 150s | Assessment |
|--------|----------|---------------|------------|
| B1 | 7 days | 4,032 | Rejected — too short for late-discovered slashing |
| B2 | 14 days | 8,064 | Marginal |
| **B3** | **21 days** | **12,096** | **Selected — Cosmos pattern; standard expectation** |
| B4 | 28 days | 16,128 | Rejected — capital opportunity cost too high |

### 3.3 Equivocation slashing percentage

| Option | Percentage | BPS | Assessment |
|--------|-----------|-----|------------|
| C1 | 1% | 100 | Rejected — under-deterrence for sophisticated attackers |
| C2 | 3% | 300 | Marginal |
| **C3** | **5%** | **500** | **Selected — Cosmos default; tested midpoint** |
| C4 | 10% | 1000 | Conservative; rejected as default but reserved for tiered slashing in ADR-013 |
| C5 | 50%+ | 5000+ | Rejected — over-deterrence, existential risk for honest stuck-key bugs |

### 3.4 Inactivity threshold

| Option | Threshold | Representation | Assessment |
|--------|-----------|----------------|------------|
| D1 | 30% | NUM=30, DEN=100 | Marginal — borderline noisy validators get evicted |
| **D2** | **40%** | **NUM=40, DEN=100** | **Selected — ADR-005 §4.1 (rev1) consensus** |
| D3 | 50% | NUM=50, DEN=100 | Rejected — too lenient; allows persistent under-participation |

### 3.5 Tracking strategy

| Option | Approach | Assessment |
|--------|----------|------------|
| E1 | Off-chain only | Rejected — non-deterministic, cannot drive on-chain slashing |
| E2 | On-chain participation count, off-chain reward calculation | Marginal — splits state across consensus and oracle |
| **E3** | **Fully on-chain participation tracking; reward policy in ADR-012** | **Selected — deterministic, auditable, slashing-compatible** |

## 4. Decision Outcome

**Consolidated decision:** A3 + B3 + C3 + D2 + E3.

### 4.1 Constants (in `src/bonding/types.rs`)

```rust
/// Smallest unit of BLOCH accounting. 1 BLOCH = 10^8 base units (Bitcoin convention).
pub const BLOCH_BASE_UNIT: u128 = 100_000_000;

/// Minimum bond amount: 100,000 BLOCH = 10^13 base units.
pub const MIN_BOND_AMOUNT: u128 = 100_000 * BLOCH_BASE_UNIT;

/// Unbonding period: 21 days @ 150s block time = 12,096 blocks.
pub const UNBONDING_PERIOD_BLOCKS: u64 = 12_096;

/// Pre-activation bonding minimum duration before promotion to Active
/// (per ADR-011 §4.4 — prevents last-minute strategic bonding).
/// 4,032 blocks @ 150s ≈ 7 days.
pub const MIN_PRE_ACTIVATION_BONDING_BLOCKS: u64 = 4_032;

/// Equivocation slash: 5% of bonded amount, expressed in basis points.
pub const EQUIVOCATION_SLASH_BPS: u32 = 500;

/// Inactivity threshold (40%) per ADR-005 §4.1 (rev1).
/// Float forbidden in consensus; cross-multiplication is the only valid comparison.
pub const INACTIVITY_THRESHOLD_NUMERATOR: u32 = 40;
pub const INACTIVITY_THRESHOLD_DENOMINATOR: u32 = 100;

/// Slash history retention: ~3 years at 150s.
pub const SLASH_HISTORY_RETENTION_BLOCKS: u64 = 630_720;
```

### 4.2 Core types (in `src/bonding/types.rs`)

```rust
use serde::{Serialize, Deserialize};
use crate::ffg::operator::OperatorIdentity;
use crate::ffg::committee_types::{BlsPubkey, MlDsaPubkey};

/// Unique bond identifier. Monotonically increasing u64 assigned at submission.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct BondId(pub u64);

/// Lifecycle states of a bond.
///
/// Transitions:
///   Pending      → Active           (at FFG_ACTIVATION_HEIGHT, if eligible)
///   Active       → InCommittee      (at era boundary, if Phragmén-selected)
///   Active       → Exiting          (operator submits UnbondValidator tx)
///   InCommittee  → Exiting          (voluntary exit, end of era)
///   InCommittee  → Slashed          (equivocation evidence committed)
///   Active       → Slashed          (equivocation evidence committed)
///   Exiting      → Unbonding{ until_block }  (era end after exit declaration)
///   Unbonding    → Withdrawable     (after UNBONDING_PERIOD_BLOCKS)
///   Slashed      → Unbonding{ until_block }  (after slash penalty subtracted)
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum BondStatus {
    /// Pre-activation: bond submitted, BLOCH locked, but no rewards/slashing apply yet.
    /// Pending bonds are not eligible for Phragmén until FFG activation (ADR-011).
    Pending,
    /// Post-activation: bond is in the bonded set, eligible for Phragmén selection.
    Active,
    /// Selected by Phragmén for the active committee or alternate set.
    /// Subject to equivocation/inactivity slashing per ADR-005 §4.6.
    InCommittee { era: u64 },
    /// Operator declared exit; will become Unbonding at end of current era.
    Exiting { exit_declared_block: u64 },
    /// Stake-out clock running. Funds locked until `until_block`.
    Unbonding { until_block: u64 },
    /// Post-equivocation: penalty applied, remainder enters Unbonding.
    Slashed { reason: SlashReason, slashed_at_block: u64, original_amount: u128 },
    /// Unbonding period elapsed; operator may submit WithdrawBond tx.
    Withdrawable,
}

/// Slashing reason. Reserved variants enable ADR-013 (tiered slashing).
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SlashReason {
    /// Double-signing evidence: validator signed two distinct blocks at the same
    /// height in a way that violates ADR-001 finality semantics.
    Equivocation,
    /// Placeholder for future tiered slashing categories (ADR-013 open).
    Reserved,
}

/// Slash event record. Persisted in CF_BONDING_HISTORY for 3-year retention.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlashEvent {
    pub bond_id: BondId,
    pub reason: SlashReason,
    pub at_block: u64,
    pub at_epoch: u64,
    pub at_era: u64,
    pub amount_slashed: u128,
    pub remaining_after: u128,
    /// Hash of the evidence that justified the slash (e.g., the two
    /// double-signed block headers concatenated and SHA-256'd).
    pub evidence_hash: [u8; 32],
}

/// Active bond record. One per BondId.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BondRecord {
    pub bond_id: BondId,
    pub operator_identity: OperatorIdentity,  // ADR-005 §4.2
    pub bls_pubkey: BlsPubkey,
    pub mldsa_pubkey: MlDsaPubkey,
    pub bonded_amount: u128,
    pub bonded_since_block: u64,
    pub status: BondStatus,
    /// Append-only history of slash events on this bond (typically empty).
    pub slash_events: Vec<SlashEvent>,
}

/// Per-epoch participation record. One per (bond_id, epoch) pair, retained
/// for SLASH_HISTORY_RETENTION_BLOCKS / blocks_per_epoch periods.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParticipationRecord {
    pub epoch: u64,
    pub bond_id: BondId,
    /// Attestations classified per ADR-005 §4.6: missed (count toward inactivity),
    /// late (do not count), or on-time (do not count).
    pub attestations_missed: u32,
    pub attestations_late: u32,
    pub attestations_on_time: u32,
    /// Total expected attestations in the epoch (typically equals BLOCKS_PER_EPOCH = 6).
    pub attestations_expected: u32,
    pub blocks_signed: u32,
    /// True if validator participated in the era's DKG ceremony successfully.
    pub dkg_participated: bool,
    /// Set if validator was slashed during this epoch.
    pub slashed_in_epoch: bool,
    /// Set if validator was soft-evicted during this epoch.
    pub soft_evicted_in_epoch: bool,
}
```

### 4.3 Transaction types (in `src/consensus/tx_types.rs`)

```rust
/// Submit a new bond. Pre-activation: creates Pending bond.
/// Post-activation: creates Active bond directly.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BondValidatorTx {
    pub operator_identity: OperatorIdentity,
    pub bls_pubkey: BlsPubkey,
    pub mldsa_pubkey: MlDsaPubkey,
    pub amount: u128,
    /// Funding source: a UTXO or balance reference, signed by the operator.
    pub funding_proof: FundingProof,
}

/// Increase the stake on an existing Active or Pending bond.
/// Forbidden on InCommittee, Exiting, Unbonding, Slashed, or Withdrawable bonds.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IncreaseBondTx {
    pub bond_id: BondId,
    pub additional_amount: u128,
    pub funding_proof: FundingProof,
}

/// Initiate unbonding. Bond transitions Active → Exiting (or InCommittee → Exiting,
/// which only takes effect at end of current era per ADR-005 §4.6 voluntary exit).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnbondValidatorTx {
    pub bond_id: BondId,
    /// Signature by the bond's BLS key proving authorization.
    pub authorization: [u8; 96],
}

/// Withdraw stake after unbonding period. Only valid for Withdrawable bonds.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WithdrawBondTx {
    pub bond_id: BondId,
    pub destination: Address,
    pub authorization: [u8; 96],
}
```

### 4.4 Bonding registry interface

```rust
// src/bonding/registry.rs

pub struct BondingRegistry<'a> { db: &'a Storage }

impl<'a> BondingRegistry<'a> {
    pub fn open(storage: &'a Storage) -> Result<Self, BondingError>;

    /// Submit new bond. Enforces cap=1 per UID (ADR-005 §4.3 rev1):
    /// rejects if has_active_position(uid) is true.
    pub fn submit_bond(
        &mut self,
        tx: &BondValidatorTx,
        at_block: u64,
    ) -> Result<BondId, BondingError>;

    /// True if UID holds any of: Pending, Active, InCommittee, Exiting, Unbonding,
    /// Withdrawable (anything except fully withdrawn). Slashed counts as still-held
    /// for cap purposes until Withdrawable.
    pub fn has_active_position(&self, uid: &OperatorUid) -> Result<bool, BondingError>;

    /// Promote eligible Pending bonds at FFG activation.
    /// Eligibility: status = Pending, bonded_amount >= MIN_BOND_AMOUNT,
    /// bonded_since_block + MIN_PRE_ACTIVATION_BONDING_BLOCKS <= activation_height.
    /// Per ADR-011 §4.4. Atomic: all promotions succeed or block is invalid.
    pub fn activate_eligible_bonds(
        &mut self,
        activation_height: u64,
    ) -> Result<u32, BondingError>;

    /// Apply equivocation slash. 5% of bonded_amount, deducted before transitioning
    /// to Slashed. Records SlashEvent in CF_BONDING_HISTORY.
    pub fn apply_equivocation_slash(
        &mut self,
        bond_id: BondId,
        evidence_hash: [u8; 32],
        at_block: u64,
    ) -> Result<u128, BondingError>;

    /// Increase bond. Forbidden on locked statuses.
    pub fn increase_bond(
        &mut self,
        tx: &IncreaseBondTx,
        at_block: u64,
    ) -> Result<(), BondingError>;

    /// Initiate unbonding.
    pub fn initiate_unbond(
        &mut self,
        tx: &UnbondValidatorTx,
        at_block: u64,
    ) -> Result<(), BondingError>;

    /// Finalize era: transition Exiting bonds → Unbonding{ until = current_block + UNBONDING_PERIOD_BLOCKS }.
    /// Called by CommitteeRegistry::activate at era boundaries.
    pub fn finalize_era_exits(&mut self, at_block: u64) -> Result<u32, BondingError>;

    /// Transition bonds with Unbonding{ until_block } where until_block <= current_block
    /// to Withdrawable. Called once per block.
    pub fn process_unbonding_completions(&mut self, at_block: u64) -> Result<u32, BondingError>;

    /// Withdraw stake.
    pub fn withdraw(
        &mut self,
        tx: &WithdrawBondTx,
        at_block: u64,
    ) -> Result<u128, BondingError>;

    /// Phragmén input: snapshot of all Active bonds with stake metadata.
    /// Called by CommitteeRegistry at era boundary.
    pub fn to_phragmen_input(&self) -> Result<PhragmenInput, BondingError>;

    /// Aggregate metric for ADR-005 §5.1 audit (Nakamoto coefficient measurement).
    pub fn active_bond_count(&self) -> Result<u32, BondingError>;
}
```

### 4.5 Slashing semantics

Equivocation evidence is a tx of type `SlashingEvidenceTx` (defined in ADR-001 area) containing two distinct block headers signed by the same BLS key at the same height. Mempool validation:

1. Verify both BLS signatures are valid under the validator's `committee_root`.
2. Verify the two headers are distinct (different block hashes).
3. Verify height matches.
4. Verify the validator was in the active committee at that height (`CommitteeRegistry::is_in(epoch, validator_idx)`).
5. Verify no prior slash event for the same evidence (`evidence_hash` not already in history).

If valid, the evidence is included in a block. Block executor applies:

```rust
// Pseudocode
let bond_id = state.committee_registry.bond_id_for(epoch, validator_idx)?;
let original = state.bonding_registry.get(bond_id)?.bonded_amount;
let slash_amount = original * EQUIVOCATION_SLASH_BPS as u128 / 10_000;
let remaining = original - slash_amount;

state.bonding_registry.apply_equivocation_slash(
    bond_id,
    evidence_hash,
    block.height,
)?;

// The 5% slashed BLOCH is burned (sent to a non-spendable address per consensus rule).
// ADR-013 (open) may revisit: tiered slashing where some fraction is burned, some
// rewarded to evidence submitter, some sent to endowment.
state.economy.burn(slash_amount);

state.committee_registry.evict_immediate(epoch, validator_idx, bond_id)?;
// alternates[0] takes the seat (ADR-005 §4.6).
```

Slashed validator's bond transitions: `InCommittee` → `Slashed { reason: Equivocation, ... }` → after the era ends → `Unbonding { until_block: era_end + UNBONDING_PERIOD_BLOCKS }`.

### 4.6 Inactivity classification and soft eviction

At each epoch boundary, for each `InCommittee` bond:

```rust
let part = state.participation_tracker.get(bond_id, epoch)?;
let missed = part.attestations_missed;
let expected = part.attestations_expected;

// Cross-multiplication, no float (ADR-005 §4.1).
if (missed as u64) * (INACTIVITY_THRESHOLD_DENOMINATOR as u64)
    > (expected as u64) * (INACTIVITY_THRESHOLD_NUMERATOR as u64)
{
    state.committee_registry.soft_evict(epoch, bond_id)?;
    state.participation_tracker.mark_soft_evicted(bond_id, epoch)?;
    // Soft eviction is not a slash — bond remains in Active state on next era.
    // Repeated soft evictions across multiple eras may trigger ADR-013 tiered actions.
}
```

The classification of an attestation as missed/late/on-time is per ADR-005 §4.6 (rev1) — deterministic, on-chain only.

### 4.7 New column families (extend `src/storage/mod.rs`)

```rust
pub(crate) const CF_BONDING_REGISTRY:  &str = "bonding_registry";   // BondId → BondRecord
pub(crate) const CF_BONDING_BY_UID:    &str = "bonding_by_uid";     // OperatorUid → BondId
pub(crate) const CF_BONDING_BY_PUBKEY: &str = "bonding_by_pk";      // BlsPubkey → BondId
pub(crate) const CF_BONDING_HISTORY:   &str = "bonding_history";    // BondId → Vec<SlashEvent>
pub(crate) const CF_PARTICIPATION:     &str = "participation";      // (epoch, bond_id) → ParticipationRecord
```

Total CFs after Sprint 2.1.D: 27 (post-Sprint 2.1.C) → 32.

### 4.8 New errors (extend `src/ffg/errors.rs` or new `src/bonding/errors.rs`)

```rust
/// Bonding-specific error variants. BLOCH convention: manual Display, no thiserror.
pub enum BondingError {
    BondNotFound(BondId),
    UidAlreadyHasPosition(OperatorUid),
    BelowMinBond { provided: u128, required: u128 },
    InsufficientPreActivationBonding { since: u64, required: u64 },
    InvalidStatusTransition { from: BondStatus, to_action: &'static str },
    BondLocked(BondStatus),
    UnbondingNotComplete { until: u64, current: u64 },
    InvalidAuthorization,
    InsufficientBondedSetForActivation { active: u32, required: u32 },
    Storage(StorageError),
}

impl fmt::Display for BondingError { /* ... per BLOCH convention ... */ }
impl std::error::Error for BondingError {}
```

## 5. Consequences

### 5.1 Positive

- **Deterministic execution.** All transitions, slashing, and eviction logic compute from on-chain state alone. No oracle, no off-chain coordination, no float arithmetic.
- **ADR-011 alignment.** `Pending` state cleanly accommodates the pre-activation period; `activate_eligible_bonds` is the single transition function. No dual-mode logic across the bonding contract.
- **Cap=1 is enforceable.** `has_active_position()` covers all six "held" statuses — no key fragmentation loophole.
- **Slash semantics are recoverable.** A slashed bond loses 5% but the operator can re-bond after unbonding completes. Honest operators with bugs (stuck keys, network outages causing false equivocation appearance) are not existentially destroyed.
- **Audit surface is bounded.** ~600-900L of registry code + ~200-300L of tx executor integration. No external cryptographic dependencies (those are in ADR-002-rev1's DKG module).

### 5.2 Negative

- **No reward distribution defined.** Operators bonding from D0 face up to 1 year of locked capital with no yield (pre-activation). Mitigation: ADR-011's redirection of pre-activation 30% reward share to the endowment seed implicitly compensates the entire ecosystem (boost mode robustness), but does not directly compensate early bonders. ADR-012 will address this — likely via post-activation bonus distribution to the first cohort, scaled by `bonded_since_block` (earlier bonders get higher bonus).
- **Slash burns 5%, not redirected.** Burning is the simplest semantic but loses economic value. ADR-013 (open) may revisit this for tiered slashing.
- **Strategic last-minute bonding mitigated but not fully prevented.** `MIN_PRE_ACTIVATION_BONDING_BLOCKS = 4032` (~7 days) prevents only the most egregious cases. A coordinated bonding wave 8 days before activation is still possible. Mitigation: foundation incentives for early bonding (months 1-9), publicly announced.
- **Slash history retention costs storage.** ~3 years × 1 slash/era × 365 eras/year × ~500 bytes/event = ~550KB worst case. Acceptable.

### 5.3 Open risks

- **R1.** Insufficient bonded set at FFG activation (< 21 active bonds at block 210,000). Per ADR-011 §4.5 step 2, this halts activation pending recovery. Mitigation: foundation monitoring, incentives, and ADR-009 fallback protocol.
- **R2.** Equivocation evidence forgery. An attacker submits two block headers signed by a victim's BLS key, claiming the victim equivocated. Mitigation: signature verification is mandatory in §4.5 mempool validation; if signatures are valid, the equivocation is real (the BLS key did sign two distinct headers at the same height, which is the equivocation definition).
- **R3.** Stuck-key bug causing false-positive inactivity → soft eviction → repeated soft eviction → potential ADR-013 escalation. Mitigation: documentation for operators on stuck-key recovery; first-time soft eviction is recoverable (returns to `Active` for next era).
- **R4.** `funding_proof` design (referenced in §4.3) requires UTXO model integration that is not yet specified. Mitigation: `FundingProof` interface is held opaque in this ADR; concrete implementation is a separate Sprint 2.1.D task synchronized with consensus team.
- **R5.** Race condition between `submit_bond` and `has_active_position`. If two `BondValidatorTx` for the same UID are in the same block, the second must fail. Mitigation: cap=1 check is atomic within block executor (sequential execution, mempool deduplication by UID).
- **R6.** Cross-era voluntary exit timing edge case. Operator submits `UnbondValidatorTx` mid-era; the bond enters `Exiting`. If the operator is also slashed in the same era before era end, the slash takes precedence (status `Slashed`, then `Unbonding` after the slash penalty). Mitigation: explicit ordering in §4.5 — `apply_equivocation_slash` overrides `Exiting`.

## 6. Implementation Plan

### Sprint 2.1.D — Registry, types, transactions

- [ ] Create `src/bonding/{mod,types,errors,registry}.rs`.
- [ ] Implement `BondingRegistry` struct with all interface methods from §4.4.
- [ ] Add 5 column families to `src/storage/mod.rs` per §4.7.
- [ ] Implement transaction types and mempool validation per §4.3.
- [ ] Block executor integration: `apply_bonding_transaction()`.
- [ ] Unit tests: full lifecycle (Pending → Active → InCommittee → Exiting → Unbonding → Withdrawable), all error paths, cap=1 enforcement, schema versioning.
- [ ] Property tests: stake conservation across all transitions, cap=1 invariant, unbonding clock monotonicity.

### Sprint 2.1.E — Slashing and inactivity

- [ ] Implement `apply_equivocation_slash` with evidence verification.
- [ ] Implement `ParticipationTracker` with on-chain classification per ADR-005 §4.6.
- [ ] Implement soft eviction trigger at epoch boundary per §4.6.
- [ ] Integrate eviction with `CommitteeRegistry`: alternate promotion (FIFO).
- [ ] Test scenarios: forced equivocation, simulated 40%+ inactivity, voluntary exit, cross-trigger interactions (R6).

### Sprint 2.2 — Testnet validation

- [ ] Devnet end-to-end: 50 validators bonding pre-activation, FFG activation transition (lowered for testing), Phragmén selection, real slashing scenarios.
- [ ] Adversarial: cap=1 bypass attempts, last-minute bonding, double-equivocation evidence (R2), stuck-key simulation (R3).

### Sprint 2.3 — ADR-012 integration (counsel review)

- [ ] ADR-012 specifies reward distribution policy referencing ADR-007 participation records.
- [ ] Counsel review: SEC opinion on bonding-as-investment-contract analysis.
- [ ] MiCA opinion on slashing-as-consumer-protection analysis.

## 7. Future Work

- **ADR-009 (open):** activation/DKG failure recovery (R1 fallback).
- **ADR-012 (open):** reward distribution policy with counsel review.
- **ADR-013 (open):** tiered slashing — equivocation tiers, soft eviction escalation, slash redistribution (vs pure burn).
- **Post-mainnet:** hardware-backed key custody recommendations for operators (HSM integration playbook).

## 8. References

- ADR-001 — FFG signature scheme
- ADR-002-rev1 — DKG protocol family
- ADR-005 — Committee era + cap=1 + missed attestation definition (§4.6 rev1)
- ADR-006 — Block time + dual finality
- ADR-009 (open) — Activation/DKG failure recovery
- ADR-010 — Tokenomics (reward source)
- ADR-011 — FFG activation block height (Pending → Active transition)
- ADR-012 (open) — Reward distribution policy + counsel review
- ADR-013 (open) — Tiered slashing
- Cosmos SDK staking module — reference for unbonding period and slash percentage defaults
- Polkadot `pallet-staking` — reference for slash history retention
- Sprint 2.1 architectural decision document (BLOCH Core, 2026-04-29)
