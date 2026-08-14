# ADR-005: Committee Era, Selection Function, and Rotation Criteria

**Sprint:** 2.1.C / 2.1.D
**Status:** **SUPERSEDED** — Committee eras, operator UIDs and the hashrate-based selection function do not exist under Genesis-4. Rotation is per-epoch partition of the active stake set. The chain this ADR governs — Genesis-3, proof of work — stopped permanently at height **39,918** on 2026-08-13. The live chain is **Genesis-4, proof of stake** (30 s slots, 32-slot epochs, finality by epoch, hybrid ML-DSA-65 ‖ Falcon-1024, no mining). The decision, context and consequences below are **not** rewritten: this is a decision log and what was decided, when, is the record. Read it as history, not as guidance.

*Original status line, retained:* **Status:** Proposed (revision 1 — 6 corrections applied, ready for commit pre-2026-05-15)
**Date:** 2026-04-29 (rev1 same day)
**Author:** BLOCH Core
**Related:** ADR-001 (FFG epoch=6, 21-of-21, supermajority 14), ADR-002 (PoBRS — *requires amendment*), ADR-003 (Refuse <21 — pre-condition for §4.4), ADR-004 (CommitteeRegistry enforce), ADR-009 (open — Emergency Reconfigure, see §4.5)
**Partial supersede:** Selection/rotation section previously scoped under ADR-002

**Changelog rev1 (2026-04-29):**
1. §4.1 — `INACTIVITY_THRESHOLD: f32 = 0.40` replaced by integer pair `(NUMERATOR=40, DENOMINATOR=100)`. Float in consensus is forbidden (IEEE-754 non-determinism breaks block hashing).
2. §4.2 — `OperatorUid([u8; 32])` confirmed with native serde derives (no BigArray; helper only required for N > 32).
3. §4.3 — Cap=1 hard explicitly defined: active bonding OR alternate OR committee seat (closes the key-fragmentation loophole).
4. §4.4 — Cross-reference to ADR-003 (refuse <21) added as pre-condition.
5. §4.5 — Emergency reconfigure edge case documented and delegated to ADR-009 (open).
6. §4.6 — Canonical definition of "missed attestation" (vs late) added to remove slashing ambiguity.

---

## 1. Context

ADR-001 established the BLOCH FFG model: fixed committee of 21 seats with 14-of-21 supermajority, epoch = 6 PoW blocks, finality ~2h via Casper FFG (2 epochs). Sprint 2.0 closed the FFG stubs (`src/ffg/{mod,types,errors,signature}.rs`). Sprint 2.1.A+B (closed 2026-04-29) delivered:

- `committee_types.rs` with `BlsPubkey`/`MlDsaPubkey` newtypes
- `ffg/storage.rs` with `FfgStorage` + 3 column families (META/COMMITTEE/PENDING)
- `ffg/committee_registry.rs` with `finalize_genesis` / `commit_pending` / `activate` / `get` / `is_in`
- `PendingCommittee` struct and `DkgHandle: Serialize`
- ADR-004 enforce activated

What **remains to be specified** before Sprint 2.1.C:

1. **Rotation cadence** of the entire committee (era).
2. **Selection function** for the 21 seats from the bonded set.
3. **Operator identity** and anti-correlation cap.
4. **Alternate set** for filling intra-era evictions.
5. **Eviction triggers** during the era.
6. **DKG overlap** between committee N and N+1.

This ADR resolves (1)–(6).

## 2. Decision Drivers

- **D1.** Fair-launch thesis (Kaspa/Litecoin/Monero analog) requires effective stake distribution, not pure top-N by stake.
- **D2.** Founder premine of 17% (ADR-010-A) creates political risk of committee capture — on-chain mitigation is mandatory.
- **D3.** Real DKG (Sprint 2.1.C) costs ~10–20MB of on-chain communication + heavy BLS computation; per-epoch rotation is infeasible.
- **D4.** MiCA (Malta MFSA preferred) and SEC counsel plans require evidence of effective decentralization — Nakamoto coefficient is an auditable metric.
- **D5.** OFAC tier-blocking + jurisdictional plan are already in the roadmap; jurisdiction metadata must be on-chain even if only as tiebreaker in v1.
- **D6.** Sunk cost of Casper-style FFG already implemented: discarding it for HotStuff is infeasible.
- **D7.** Anti-corruption: bribing 14-of-21 must be economically prohibitive within the window of one era.

## 3. Considered Options

### 3.1 Rotation cadence (era)

| Option | Era | Reference | Assessment |
|--------|-----|-----------|------------|
| A1 | Per block | Tendermint/Cosmos | Infeasible — real DKG cannot run in seconds |
| A2 | Per epoch (~1h) | — | Amortized DKG cost unacceptable |
| A3 | 12 epochs (~12h) | — | Aggressive on decentralization; DKG 2x/day |
| **A4** | **24 epochs (~24h)** | **Polkadot, Sui** | **Sweet spot validated in production** |
| A5 | 168 epochs (~7d) | Cardano | Conservative; lag in stake updates |

### 3.2 Selection function

| Option | Mechanism | Expected Nakamoto coef. | Assessment |
|--------|-----------|-------------------------|------------|
| B1 | Top-N by stake | ~7 | Concentrating; stakers ranked 22+ never enter |
| **B2** | **Phragmén/PJR over bonded** | **~14–17** | **Distributes weight across the 21 seats** |
| B3 | VRF stake-weighted | ~10–12 | Good unpredictability, loses balancing |
| B4 | Algorand-style sortition | N/A | Incompatible with persistent per-era DKG |

### 3.3 Operator anti-correlation cap

| Option | Policy | Assessment |
|--------|--------|------------|
| C1 | No cap | Large operator captures via key fragmentation |
| **C2** | **1 seat per operator UID** | **Maximum diversity; on-chain auditable** |
| C3 | 2 seats per UID | Balance between diversity and flexibility |

### 3.4 Alternate set

| Option | Size | Assessment |
|--------|------|------------|
| D1 | 0 (no alternates) | Eviction → full reconfiguration intra-era |
| D2 | 3 | Insufficient for multiple evictions |
| **D3** | **7** | **~33% buffer; covers typical evictions** |
| D4 | 14+ | High capital lockup cost from idle bonding |

### 3.5 DKG overlap

| Option | Start of committee N+1 DKG | Assessment |
|--------|---------------------------|------------|
| E1 | No overlap (start at boundary) | Dead window for finality |
| **E2** | **`era_start + 12 epochs` (mid-era)** | **Committee N+1 ready at the boundary** |
| E3 | `era_start + 6 epochs` (~1/4) | Long DKG window; more buffer |

### 3.6 Intra-era eviction triggers

| Trigger | Detection | Action |
|---------|-----------|--------|
| Equivocation | `DoubleFinalization` (errors.rs) | Hard slash + immediate eviction |
| Inactivity | Missed attestations > 40% in epoch | Soft eviction at end of epoch |
| Voluntary exit | Tx `exit_validator` | Eviction at end of current era |

## 4. Decision Outcome

**Consolidated decision:** A4 + B2 + C2 + D3 + E2 + triggers from §3.6.

### 4.1 Constants (add to `src/ffg/types.rs`)

```rust
/// Number of FFG epochs per committee era.
pub const EPOCHS_PER_ERA: u64 = 24;

/// Size of the alternate set (reserve validators).
pub const ALTERNATE_SET_SIZE: usize = 7;

/// Offset (in epochs) of the start of committee N+1 DKG within era N.
pub const DKG_OVERLAP_OFFSET: u64 = 12;

/// Cap of seats per operator UID.
pub const MAX_SEATS_PER_OPERATOR: u32 = 1;

/// Inactivity threshold for soft eviction (40%).
///
/// Represented as integer NUMERATOR/DENOMINATOR pair — float in consensus
/// code is forbidden (IEEE-754 is non-deterministic across platforms,
/// breaking block hash). Comparisons use cross-multiplication:
///
/// ```ignore
/// // soft_evict if missed * DEN > expected * NUM
/// if missed_attestations as u64 * INACTIVITY_THRESHOLD_DENOMINATOR as u64
///     > expected_attestations as u64 * INACTIVITY_THRESHOLD_NUMERATOR as u64 {
///     soft_evict(idx);
/// }
/// ```
pub const INACTIVITY_THRESHOLD_NUMERATOR: u32 = 40;
pub const INACTIVITY_THRESHOLD_DENOMINATOR: u32 = 100;
```

### 4.2 New types

```rust
// src/ffg/operator.rs (new file)
use serde::{Serialize, Deserialize};

/// Self-declared operator identity.
/// Separated from validation keys (BLS, ML-DSA) to allow key rotation
/// without losing identity — and to enforce the per-UID cap.
///
/// **Serde convention:** [u8; 32] uses native serde derives (no BigArray).
/// The BigArray helper is only required for arrays with N > 32 (see
/// `BlsPubkey([u8; 48])` and `MlDsaPubkey([u8; 1952])` in `committee_types.rs`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct OperatorUid(pub [u8; 32]);

/// Self-declared jurisdiction (ISO 3166-1 alpha-2).
/// Auditable; used as tiebreaker in Phragmén.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Jurisdiction(pub [u8; 2]);

/// Client version — N/A in v1 (single client), reserved for v2+.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientVersion(pub String);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperatorIdentity {
    pub uid: OperatorUid,
    pub jurisdiction: Jurisdiction,
    pub client_version: ClientVersion,
}
```

### 4.3 Bonding contract — invariant

The bonding contract MUST:

1. Receive `OperatorIdentity` upon stake submission.
2. Maintain mapping `OperatorUid → Vec<ValidatorPubkey>`.
3. Reject a second bonding submission with the same UID **if any active
   bonding, alternate, or committee seat already exists**. Cap=1 is hard:
   none of the three positions may coexist with a new submission under
   the same UID. This closes the loophole where a large operator could
   apply with N distinct keys to the bonded set, wait for Phragmén to
   select one for committee and another for alternate, and still submit
   a third key during the era.
4. On-chain verification via `BondingRegistry::has_active_position(&uid) -> bool`,
   which returns true if the UID holds any of the three positions.

### 4.4 Selection algorithm (Phragmén stub)

> **Pre-condition (ADR-003 — Refuse <21):** if `bonded_set.len() < 21`,
> this function is not executed. The `CommitteeRegistry` refuses rotation
> and extends committee N for one more era (with log warning and metric),
> preserving Byzantine tolerance. Phragmén assumes at least 21 eligible
> candidates (after cap=1 filter).

```rust
// src/ffg/selection.rs (new file, Sprint 2.1.D)

pub struct PhragmenInput {
    pub bonded_set: Vec<(OperatorUid, Stake, Jurisdiction, BlsPubkey, MlDsaPubkey)>,
}

pub struct PhragmenOutput {
    pub committee: [Seat; 21],
    pub alternates: [Seat; 7],
    pub committee_root: [u8; 32],  // hash of the active set
}

/// Algorithm:
/// 1. Sort bonded_set descending by stake.
/// 2. Iterate selecting the seat that minimizes max-stake-per-seat (Phragmén core).
/// 3. Filter: reject candidate whose UID already holds a seat (cap=1).
/// 4. Tiebreaker: jurisdiction least represented in the partial committee.
/// 5. Repeat until 21 seats + 7 alternates are filled.
/// 6. Hash the set ordered by validator_index → committee_root.
pub fn run_phragmen(input: PhragmenInput) -> Result<PhragmenOutput, SelectionError>;
```

### 4.5 Dual DKG schedule

```
era N:
  epoch 0 ────────────── 12 ─────────────── 24 (= era N+1 epoch 0)
  │                       │                      │
  │                       │                      └─ ACTIVATION committee N+1
  │                       └─ START DKG committee N+1 (PendingCommittee)
  └─ ACTIVATION committee N (previously PendingCommittee)
```

`CommitteeRegistry::activate()` at the era boundary consumes the `PendingCommittee` whose DKG completed in the previous 12 epochs. If DKG did not complete, committee N extends for another 6 epochs (grace period); if still not complete, fallback liveness mode (to be specified in ADR-007 — *open*).

> **Edge case — intra-era emergency reconfigure.** If during era N the
> alternates are exhausted (R2 in §5.3) and `emergency_reconfigure()` is
> triggered, era N is shortened arbitrarily and the
> `DKG_OVERLAP_OFFSET = 12` no longer makes sense for era N+1 (which
> now starts earlier than expected). Handling this case is the
> responsibility of **ADR-009 (open)** — Emergency Reconfigure
> Protocol — which must define: (a) whether era N+1 inherits the last
> valid `PendingCommittee` without a new DKG, (b) whether era N+1's
> DKG is rescheduled with a reduced offset, or (c) whether era N+1
> starts in degraded mode until normal DKG completes.

### 4.6 Eviction triggers — behavior

**Canonical definition of "missed attestation"** (necessary to avoid
ambiguity in slashing/eviction):

A validator is considered "missed" for an epoch E if, at the end of
processing the boundary block of E+1, **none** of the conditions below
are true for its BLS key in the `FinalityCertificate` of E:

1. Signature present and valid under the active `committee_root` for E.
2. Signature present and valid, but the block that included it arrived
   after the boundary of E+1 — in this case it counts as **late**
   (not missed), with no direct penalty, only a record in
   `ParticipationRecord`.

Cases explicitly classified as **missed** (count toward inactivity
numerator):

- No submission observed in E or E+1.
- Submission present but BLS verify fails.
- Submission for a wrong `committee_root` (validator desynced from
  era / DKG result).

Cases explicitly classified as **late** (do not count):

- Submission delayed by demonstrable mempool congestion.
- Submission arrived after the boundary of E+1 but within 6 blocks.

This definition is deterministic (depends only on on-chain state at
the commit of the boundary block of E+1) and therefore compatible
with automatic slashing. Implementation in
`ParticipationTracker::classify(epoch, validator_idx)`.

| Trigger | When applied | Action in `CommitteeRegistry` | Successor |
|---------|--------------|-------------------------------|-----------|
| Equivocation | At any time | `slash + remove_seat(idx)` immediate | `alternates[0]` (FIFO) |
| Inactivity > 40% | At end of each epoch | `soft_evict(idx)` at epoch commit | `alternates[0]` (FIFO) |
| Voluntary exit | At end of current era | `mark_exiting(idx)` → not eligible in N+1 | Phragmén N+1 |

`alternates[0]` is validator #22 from the Phragmén selection. When
consumed, `alternates[1..7]` shift forward. If alternates are
exhausted within the era → emergency reconfiguration via
`CommitteeRegistry::emergency_reconfigure()` (future ADR).

### 4.7 FinalityCertificate — new field

```rust
pub struct FinalityCertificate {
    // ... existing fields (Sprint 2.0) ...
    pub committee_root: [u8; 32],  // NEW in Sprint 2.1.C
}
```

Light clients use `committee_root` to verify exactly which set of 21 validators signed the certificate, without needing the full state of the `CommitteeRegistry`.

## 5. Consequences

### 5.1 Positive

- **Expected Nakamoto coefficient: 14–17.** Phragmén + per-UID cap doubles the coefficient vs. pure top-N.
- **Robust anti-corruption.** Bribing 14-of-21 over 24h costs > slash bonded in any plausible scenario.
- **Amortized DKG.** ~1 DKG/day is computationally tolerable; PendingCommittee column family already exists.
- **MiCA/SEC auditability.** UID + jurisdiction + committee_root are all on-chain verifiable by counsel/regulators.
- **Operational stability.** A 24h window is compatible with SRE shifts and on-call rotations.
- **Light client friendly.** `committee_root` enables SPV-like verification.

### 5.2 Negative

- **Phragmén has computational cost.** Naïve implementation is O(N²) over the bonded set. For N ~ 100 validators this is acceptable; for N > 1000 it requires optimization (Polkadot has an optimized version — reference: `pallet-election-provider-multi-phase`).
- **Self-declared UID is trust-on-first-use.** A malicious operator can declare a fake UID, bypassing the cap. Mitigation: social convention + public dashboards + slashing on evidence of discovered Sybil. Cryptographic-economic solution deferred to v2.
- **Jurisdiction is tiebreaker, not constraint.** The committee may end up with 21 identical jurisdictions if Phragmén has no tiebreaker need. Acceptable in v1.
- **24h era lags stake updates.** A staker entering at the start of era N+1 waits until era N+2 to potentially enter the committee. Acceptable given D3.
- **Bonded but inactive alternate set** = idle capital for 7 operators. Mitigation: alternates receive a fraction of the reward (to be specified in tokenomics ADR).

### 5.3 Open risks

- **R1.** DKG fails to complete within 12 epochs → grace period + fallback. ADR-007 (*open*) must specify the fallback.
- **R2.** Alternates exhausted intra-era → emergency reconfigure. Future ADR must specify.
- **R3.** Phragmén oscillation: small stake delta can swap 5+ seats era-to-era. Mitigation: hysteresis (incumbent bonus) — *open*, candidate for ADR-008.
- **R4.** Per-UID cap in v1 is trust-on-first-use; strong Sybil resistance deferred to v2.

## 6. Implementation Plan

### Sprint 2.1.C (next, starts 2026-05-15)

- [ ] Create `src/ffg/operator.rs` with `OperatorUid`, `Jurisdiction`, `ClientVersion`, `OperatorIdentity`.
- [ ] Add constants in `src/ffg/types.rs` (§4.1).
- [ ] Extend `CommitteeRegistry` with `era` (not just epoch) and `era_boundary_at(epoch) -> bool`.
- [ ] Implement real DKG (replaces Sprint 2.0 stub). Schedule per §4.5.
- [ ] Amend ADR-002 with cross-reference to this ADR-005.

### Sprint 2.1.D

- [ ] Create `src/ffg/selection.rs` with `run_phragmen()` (§4.4).
- [ ] Create `src/bonding/registry.rs` with cap-per-UID enforce (§4.3).
- [ ] Add `committee_root` to `FinalityCertificate` (§4.7).
- [ ] Implement `mldsa_keys.rs` (already planned for Sprint 2.1.D).

### Sprint 2.1.E (new, before 2.2)

- [ ] Implement eviction triggers (§4.6) with tests.
- [ ] `CommitteeRegistry::soft_evict()`, `slash_and_remove()`, `mark_exiting()`.
- [ ] Test scenarios: forced equivocation, simulated 40%+ inactivity, voluntary exit.

### Future work (open ADRs)

- ADR-007: DKG-not-completed fallback (R1).
- ADR-008: Phragmén hysteresis / incumbent bonus (R3).
- ADR-009: Emergency reconfigure protocol (R2 + edge case from §4.5).
- Tokenomics ADR: alternates reward share.

## 7. Validation Metrics

This decision will be validated by:

- Nakamoto coefficient ≥ 14 within the first 30 days of mainnet (internal audit).
- Zero rotation failures due to incomplete DKG within the first 60 days.
- Average DKG time < 6 epochs (50% of overlap window).
- Alternates consumed < 3 per era on average (alternate buffer adequate).

## 8. References

- ADR-001 — FFG epoch=6, committee 21, supermajority 14
- ADR-002 — PoBRS (requires amendment to reference this ADR)
- ADR-004 — CommitteeRegistry enforce
- ADR-010-A — Founder premine (17%, 30-year lock)
- Polkadot NPoS / Phragmén — `pallet-staking`, `pallet-election-provider-multi-phase`
- Cosmos Hub validator set — top-N model (reference anti-pattern)
- Casper FFG paper (Buterin & Griffith, 2017)
- Sprint 2.1 architectural decision document (BLOCH Core, 2026-04-29)
