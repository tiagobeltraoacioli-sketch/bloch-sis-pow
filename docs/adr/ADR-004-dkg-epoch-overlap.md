# ADR-004: DKG Epoch Overlap Pattern

**Status:** Accepted
**Date:** 2026-04-29
**Deciders:** BLOCH Founder
**Sprint:** 2.1 (CommitteeRegistry + Dual DKG)

## Context

The FFG protocol elects a new committee at epoch boundaries. The DKG ceremony for the BLS aggregate keypair takes ~30 seconds wall clock with geo-distributed validators. The implementation question: **when does DKG run relative to the epoch the committee will serve?**

Two patterns:

1. **N → N+1**: DKG runs during epoch N (using the snapshot at start of N), committee is active in epoch N+1. **Tight: if DKG fails, no committee in N+1.**
2. **N → N+2**: DKG runs during epoch N (using snapshot at start of N), committee is active in epoch N+2. **Buffer: epoch N+1 has the previously-elected committee (one extra epoch); DKG can retry on failure.**

## Decision

**Adopt N → N+2 pattern: DKG runs in epoch N, committee activates in epoch N+2. Provides 1 epoch (~1h) of buffer for DKG retry on failure.**

## Rationale

### DKG failure modes are real and recoverable

DKG ceremonies fail for legitimate reasons:
- Network partition during round 2 of 3 (one validator unreachable)
- TEE crash on a validator's HSM
- Software bug in DKG primitive (will be caught in audit but Day-1 risk)
- Slow validator times out before round completion

Frequency estimate from PoBRS production data (2 years, 7-of-12 DKG):
- DKG failure rate: ~0.5% per ceremony
- Recovery time: ~30 seconds (retry from round 1)

For 21-of-21 DKG, failure rate likely 1-3% (more participants = more chances of one being slow). With N → N+1, every 1-3% of epochs would have no committee. Unacceptable.

With N → N+2, DKG can retry up to 5-6 times within the 1-epoch (1h) buffer. Effective failure rate drops to <0.001%.

### Trade-off: latency of committee transition

N → N+1: when an event triggers committee change (e.g., a slashed validator must be replaced), new committee active in next epoch (~1h delay).
N → N+2: same event, new committee active in 2 epochs (~2h delay).

This 1-hour latency penalty is acceptable because:
- Slashed validator's vote is rejected immediately (within current epoch); their replacement happens at the next election regardless of pattern
- Operational events (validator exit, key rotation) are infrequent
- 2-hour transition is consistent with FFG's overall ~3h finality posture

### Aligns with state machine

Per RFC-001, the FFG state machine processes:
- BLS-justify in epoch N
- BLS-finalize for epoch N at epoch N+1
- ML-DSA-confirm for epoch N at epoch N+2

The state machine already has a "look at N-2" pattern. Extending DKG handoff to use the same N → N+2 pattern keeps the protocol coherent: every transition is "produce in N, observe in N+2."

### Genesis special case

For epoch 0 (genesis), there's no previous epoch to elect from. Founder-bootstrap committee runs for ~2 epochs while DKG for epoch 2's committee runs in epoch 0. Epoch 1 uses the founder-bootstrap committee; epoch 2 transitions to organic.

This is documented in BLOCH Genesis spec (separate document, in progress). For ADR-004 purposes, the N → N+2 pattern handles bootstrap cleanly because the buffer absorbs DKG ceremony time.

## Consequences

### Positive
- Failure tolerance: DKG retries within 1-epoch buffer
- Symmetric with other FFG state machine patterns (N → N+2)
- Operational confidence: alarm fires on DKG failure, but chain continues uninterrupted
- Audit-friendly: clean state machine, no special-casing for "DKG failed during transition"

### Negative
- 1-hour additional latency for committee transitions (acceptable per analysis)
- Memory cost: must track 2 elected committees simultaneously (current + pending)
- Slight code complexity: pending committee state until activation epoch

### Neutral
- DKG state stored in CF_FFG_PENDING_COMMITTEE; activated at epoch boundary
- Committee snapshots queryable for any past epoch (audit trail)

## Implementation notes

```rust
// src/ffg/committee_registry.rs

pub struct CommitteeRegistry<'a> {
    storage: &'a PobrsStorage<'a>,
    cf_committee: ColumnFamily,         // current + historical
    cf_pending_committee: ColumnFamily, // future committee (epoch N+2 awaiting activation)
    cf_meta: ColumnFamily,
}

impl<'a> CommitteeRegistry<'a> {
    /// Trigger DKG for committee that will activate in epoch (current + 2).
    /// Called at start of every epoch.
    pub fn begin_dkg_for_epoch(&self, target_epoch: u64) -> Result<DkgHandle, RegistryError>;

    /// Mark a DKG ceremony as completed.
    /// Stores result in CF_FFG_PENDING_COMMITTEE for activation later.
    pub fn complete_dkg(&self, target_epoch: u64, result: DkgResult) -> Result<(), RegistryError>;

    /// Activate the pending committee at epoch boundary.
    /// Moves from CF_FFG_PENDING_COMMITTEE to CF_FFG_COMMITTEE.
    pub fn activate_committee(&self, epoch: u64) -> Result<Vec<CommitteeMember>, RegistryError>;

    /// On DKG failure during epoch N (DKG was for epoch N+2):
    /// - retry until end of epoch N
    /// - if retries exhausted, the previously-elected committee continues serving in N+2
    ///   (effectively a 2-epoch term extension)
    pub fn handle_dkg_failure(&self, target_epoch: u64) -> Result<(), RegistryError>;
}
```

State machine timing:

```
Epoch N:
  - Start: snapshot active
  - Mid: DKG for epoch N+2 begins
  - Continuous: BLS votes for current epoch N

Epoch N+1:
  - Start: DKG for N+2 must be complete (or last retry running)
  - Continuous: BLS votes for epoch N+1
  - End: Pending committee for N+2 verified, persisted

Epoch N+2:
  - Start: Pending committee activates as current committee
  - Continuous: BLS votes for epoch N+2 (new committee operational)
  - Mid: DKG for epoch N+4 begins
```

## References

- BLOCH RFC-001 §6 (Committee Management)
- BLOCH ADR-002 (Pedersen VSS DKG)
- BLOCH ADR-003 (Minimum Committee Policy)
- Casper FFG paper (Buterin & Griffith, 2017) — committee handoff patterns
