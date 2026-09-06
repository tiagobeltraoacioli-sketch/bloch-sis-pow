<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# The leak-recovery flag day — `LEAK_RECOVERY_ACTIVATION_EPOCH = 2700`

**ARMED 2026-09-06 by founder decision.** Chain was at ~epoch 2075 when the
constant was set; epoch 2700 lands ≈2026-09-12 (90 epochs/day), leaving ≈6 days
for the coordinated fleet rollout. This document is the versioned runbook the
tripwire test (`leak_recovery_armed_epoch_matches_the_runbook`,
`transition.rs`) checks the constant against. Changing the epoch again is a new
flag day and requires updating BOTH in one commit.

## What activates, in one paragraph

From the first vote tally at which `votes.epoch >= 2700`, `finality.rs` stops
using the unfloored, leak-adjusted quorum denominator — the arithmetic of the
2026-08-24 incident, in which three disjoint partitions of 4/64 validators each
finalized different roots at the same epoch — and applies BOTH halves of the
leak mechanism: the **denominator floor**
(`MIN_QUORUM_DENOMINATOR_NUM/DEN` of the unleaked total, so a shrunken
partition can never vote itself a supermajority) and the **leak recovery**
(the accumulator decreases again once finality resumes, so ejection is no
longer permanent). Below 2700 the shipped arithmetic is byte-identical to what
every binary has run since Genesis-4 launch; the change is invisible until the
armed epoch and total at it.

Measured effect (prova.rs, scenario 0 pair): with the gates open, all three
incident partitions fail to finalize over the full horizon — the exact
behaviour the floor buys. `s0_three_partitions_finalize_three_different_roots`
describes the pre-2700 arithmetic; `s0_cure_the_denominator_floor_stops_all
_three_partitions` describes the post-2700 arithmetic.

## Why this epoch

- **Strictly in the future at tag time** (tripwire requirement 1): armed at
  ~epoch 2075, binds at 2700 — 625 epochs of margin. An epoch already past
  would arm silently against the whole history.
- **After the rollout completes** (requirement 2): ≈6 days at 90 epochs/day.
  The fleet is 64 validators on 7 hosts; the 2026-08-30/31 migration moved all
  64 in under two days, so 6 days is 3× the demonstrated rollout time.
- **Matches this runbook** (requirement 3): 2700, here and in
  `params.rs::LEAK_RECOVERY_ACTIVATION_EPOCH`.

## Deployment deadline — the one hard rule

**Every validator MUST be running a binary carrying this constant BEFORE
epoch 2700.** At the boundary, an armed binary and an un-armed binary compute
different quorum denominators and therefore justify different checkpoints: a
fleet split across the two DIVERGES. There is no partial rollout; this is a
flag day.

Rollout order (same procedure as `LEAKED-ROSTER-FLAG-DAY.md`, which rolled
E=1400 successfully):

1. Build the release binary from the armed commit; record its hash.
2. Distribute to all 7 hosts; verify the hash on each box.
3. Restart the validators host by host (`bloch-nNN` units), confirming each
   node rejoins, replays, and attests before moving to the next host.
4. All 64 restarted and attesting = rollout complete. Confirm well before
   epoch 2700 (target: ≥1 day of margin).
5. At epoch 2700, watch the first boundaries: finalized epoch must keep
   advancing; `leaked` accumulators begin to DECREASE for recovering
   validators (the recovery half), and no minority partition may justify.

## What to watch afterwards

- Finality continuity across the 2700 boundary (finalized epoch advancing).
- Leak accumulators shrinking for validators that resumed attesting.
- No divergence between nodes (same finalized root at the same epoch on
  independent nodes — the 2026-08-24 failure mode this closes).

## Relationship to the other constants

`LEAKED_ROSTER_ACTIVATION_EPOCH` (1400, long bound) armed the half that
REMOVES weight; this flag day arms the half that GIVES IT BACK plus the floor
that makes partitions safe. The two were designed to move together; from 2700
they finally do. `ANCESTRY_SEED_ACTIVATION_EPOCH` remains `u64::MAX` (inert)
and keeps its own tripwire.
