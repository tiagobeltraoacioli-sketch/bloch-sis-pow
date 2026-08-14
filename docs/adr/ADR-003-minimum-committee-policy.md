# ADR-003: Minimum Committee Policy When Fewer Than 21 Candidates

**Status:** **SUPERSEDED** — The 21-validator FFG committee elected by **hashrate snapshot** does not exist under Genesis-4. Committees are a shuffled partition of the active stake-weighted validator set into 32 per-epoch committees (`crates/bloch-pos-committee/src/committees.rs`); there is no hashrate to snapshot. The chain this ADR governs — Genesis-3, proof of work — stopped permanently at height **39,918** on 2026-08-13. The live chain is **Genesis-4, proof of stake** (30 s slots, 32-slot epochs, finality by epoch, hybrid ML-DSA-65 ‖ Falcon-1024, no mining). The decision, context and consequences below are **not** rewritten: this is a decision log and what was decided, when, is the record. Read it as history, not as guidance.

*Original status line, retained:* **Status:** Accepted
**Date:** 2026-04-29
**Deciders:** BLOCH Founder
**Sprint:** 2.1 (CommitteeRegistry + Dual DKG)

## Context

The FFG committee election protocol (RFC-001 §6) selects 21 validators per epoch by hashrate snapshot of the prior 2016-block window. The implementation question: **what happens if fewer than 21 distinct miners produced blocks in the snapshot window?**

This is a genuine edge case to address because:

- Genesis epochs may have very few miners (bootstrap)
- Post-attack scenarios (mining centralization, geographic outage) might temporarily reduce active miner count
- Permanent low-miner scenarios are existential to chain — chain ungovernable without committee

Two options:

1. **(a) Refuse to elect** — `MinimumCommitteeError`, previous committee continues. **Risk: if it happens twice in a row, FFG halts (committee from 2 epochs ago is now stale).**
2. **(b) Reduced committee with null slots** — fill with `null` validators (status=Inactive); threshold scales: `min(14, ceil(2/3 * N))` where N = actual count. **Risk: 14-of-15 ≈ 93% supermajority is fragile; one offline validator halts.**

## Decision

**Adopt Option (a): refuse to elect, error out cleanly. Coordinate mainnet launch with ≥21 known mining pool partners to ensure baseline is met.**

## Rationale

### Reduced committee math is unsafe

Option (b) supermajority math:
- N=20: threshold = 14 → 70% required, 6 dropouts halt. Borderline.
- N=15: threshold = 14 → 93.3% required, 1 dropout halts. Brittle.
- N=10: threshold = 14 → impossible. Forced to drop to threshold = ceil(2/3 × 10) = 7. But now 30% byzantine tolerance is gone.

The "safe" reduced-committee math drops byzantine tolerance below the design assumption (1/3). FFG's slashing logic is calibrated for 1/3 byzantine; if effective tolerance drops below this, slashing assumptions break and the chain loses its security argument.

### "FFG halts after 2 missed elections" is acceptable

In Option (a), if elections fail in epochs N and N+1, the committee from epoch N-1 expires (stale state) and FFG can't progress. The chain is effectively halted from FFG's perspective — but **block production continues** under PoW + GhostDAG-Q. The chain has reduced finality guarantee but isn't dead.

This is the right failure mode: degraded service, not catastrophic security violation.

Recovery path: bring miners back online; once 21 candidates re-emerge, election succeeds and FFG resumes.

### Mainnet bootstrapping guarantees the baseline

BLOCH mainnet launch will be coordinated with ≥21 known mining pool partners (per BLOCH Labs business development). Each partner commits to:
- Continuous mining for 2016+ blocks before joining committee eligibility
- Geographic and ASN diversity (no single pool >20% hashrate)
- Hardware redundancy (HSM + uplink failover)

This guarantees the baseline of 21 candidates from genesis. Below-baseline scenarios become rare.

### Operational early warning

The CommitteeRegistry emits a metric `bloch_committee_election_candidates` at every election. If this drops below 25 (5 buffer above 21), an alert fires. Operators have time to coordinate before FFG halts.

## Consequences

### Positive
- Strong safety property: byzantine tolerance never silently degrades
- Clean failure mode: operator-visible, not silently corrupting
- Aligns with FFG's design assumption (1/3 byzantine across exactly 21 members)
- Audit-friendly: no edge-case threshold math to reason about

### Negative
- Chain finality halts during below-baseline events
- Recovery requires operator coordination (re-bootstrap miners)
- Mainnet launch requires upfront commitment from ≥21 partners (business cost)

### Neutral
- Documented in operator runbook as "P0 alert condition"
- Genesis epoch handled by founder-bootstrap committee (founders run 21 nodes for first ~2016 blocks; transition to organic miners thereafter — separate ADR if needed)

## Implementation notes

```rust
// src/ffg/election.rs
pub const MIN_COMMITTEE_SIZE: usize = 21;

pub fn elect_committee(
    epoch: u64,
    snapshot: HashrateSnapshot,
) -> Result<Vec<CommitteeMember>, ElectionError> {
    let candidates = snapshot.distinct_miners();

    if candidates.len() < MIN_COMMITTEE_SIZE {
        // Emit metric for operator alert
        metrics::committee_election_below_baseline(candidates.len());
        return Err(ElectionError::InsufficientCandidates {
            available: candidates.len(),
            required: MIN_COMMITTEE_SIZE,
        });
    }

    // Proceed with normal election logic
    select_top_n(candidates, MIN_COMMITTEE_SIZE, &snapshot.tiebreak_seed)
}
```

The `ElectionError` propagates to the daemon's epoch-boundary handler (Sprint 2.3 — state machine). The previous committee continues until next election succeeds. After 2 consecutive failures, an alert escalates ("FFG halt — operator action required").

## References

- BLOCH RFC-001 §6 (Committee Management)
- BLOCH ADR-002 (DKG Protocol — Pedersen VSS)
- Critical Path Doc §1.2.2 (Election algorithm)
