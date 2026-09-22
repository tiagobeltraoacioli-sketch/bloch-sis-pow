# Wave 48 FC-07: disjoint finality quorum decision

Date: 2026-09-18. Branch: `codex/audit-fc07-partition-floor`. Starting
point: `6edf07f`. Scope: local adversarial proof and audit evidence only. No
consensus rule, activation epoch, state root, node, validator, deployment, or
live state changed.

## Recovered finding and current rule

The exact source was recovered from repository history at
`a79c88b:docs/audit/deep-audit-2026-09-16/A2-consensus-finality-forkchoice.md`.
FC-07 states that the one-half minimum quorum denominator still permits
disjoint sets holding at least one third of unleaked stake to finalize
conflicting checkpoints after an extended partition, without any validator
double-voting or surrounding.

The current rule is live. `LEAK_RECOVERY_ACTIVATION_EPOCH` is 2,880, and the
finality fold computes

```text
denominator = max(leak_adjusted_stake, unleaked_stake / 2)
justify iff 3 * attesting_stake >= 2 * denominator
```

The floor was an explicit owner choice after the safety/liveness trade-off was
documented. Slashing evidence is now active at epoch 2,884, unlike the older
audit snapshot, but activation does not help this attack: the two validator
sets are disjoint and each key signs on only one branch, so there is no
slashable double vote or surround vote.

## Executable attack proof

The new regression drives two independent `FinalityState` folds over the same
three-validator, equal-stake registry. Validator 0 votes only on the left
branch, validator 1 only on the right, and validator 2 remains absent from
both. The post-2,880 floor and leak-recovery rules are rehearsed directly.

Both branches finalize epoch 18 on different roots. Every epoch outcome on
both branches reports an empty equivocator set. The result is symmetric and
requires no shared signer, pinning the exact accountable-safety gap rather
than merely checking the floor constant or one branch's arithmetic.

The older “about 25 epochs” figure in the finding comes from the pre-floor
4-of-64 incident shape. The focused one-third boundary crosses the current
floor sooner; epoch 18 is the measured schedule under the checked-in leak
constants.

## Why there is no inactive candidate

Let `f` be the denominator floor as a fraction of unleaked stake and `p` the
stake present on one partition. After the absent stake leaks far enough, a
partition at or below the floor can justify when

```text
p >= 2f / 3
```

With `f = 1/2`, the minimum recoverable partition is therefore `p = 1/3`.
Preventing two disjoint partitions from both qualifying requires the minimum
to be strictly greater than one half, hence `f > 3/4`. Exactly three quarters
is insufficient because two disjoint halves meet the equality threshold.

Raising the floor above three quarters would buy quorum intersection but make
the chain unable to recover through the inactivity leak whenever half or less
of stake remains available. Choosing a particular higher
fraction, its rounding rule, and its interaction with weak-subjectivity
checkpoints and emergency recovery is a protocol-owner safety/liveness
decision. A `u64::MAX` gate around an unspecified fraction would be dead code,
not a reviewable candidate, so this wave adds none.

FC-07 moves from `OPEN` to `PROTOCOL DECISION`, not `IMPLEMENTED` or `UNARMED
CANDIDATE`. A future proposal must state the tolerated outage fraction, prove
quorum intersection under integer rounding and validator-set changes, model
partitions and delayed recovery, replay historical boundaries, and define a
coordinated activation and weak-subjectivity policy.

## Validation

- `cargo test -p bloch-pos-committee disjoint_one_third_partitions_finalize_conflicting_checkpoints_without_equivocation --offline`:
  one adversarial two-branch regression passed.
- `cargo test -p bloch-pos-committee the_quorum_floor_is_the_one_the_owner_chose --offline`:
  the current owner-choice tripwire passed.
- `cargo test -p bloch-pos-committee inactivity_leak_recovers_finality --offline`:
  the existing 60/40 liveness control passed.
- `cargo test -p bloch-pos-committee --lib --offline`: 448 passed, four
  ignored scale tests, zero failed.
- `git diff --check`: passed.

The builds emitted inherited unused-import, unused-doc-comment, and dead-code
warnings. These proofs do not make the accepted residual safe or authorize a
protocol change.
