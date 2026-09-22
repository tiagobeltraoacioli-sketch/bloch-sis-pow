# Internal audit remediation, forty-fifth wave — supply accounting

Base: `4e15334`; branch `codex/audit-st06-tx14`. This wave contains local
source and regression evidence only. It does not arm a consensus gate, select
an activation epoch, migrate committed state, deploy a binary or rewrite
genesis.

## ST-06: delegator issuance counter

The finding is reproduced in the inactive rewards-v2 settlement path. For an
active delegation, `rewards::distribute` divides newly minted issuance into an
operator share and a delegator share. `close_epoch` credited the latter to the
committed `delegator_issuance_rewards` ledger, but advanced `issued_sat` only
for the operator share and split dust. Consequently accounted holdings grew by
more than committed issuance, and the unconditional step-11b conservation
guard would refuse that boundary with `SupplyNotConserved`.

The candidate now advances `issued_sat` for every nonzero delegator ledger
credit. The split is exhaustive: credited shares plus dust equal
`payout.delegators`; operator issuance is already counted separately. A
forced-gate regression proves all of the following on the production
`close_epoch` implementation:

- the delegator receives a nonzero committed issuance reward;
- accounted holdings growth equals the `issued_sat` delta;
- the issuance delta includes the delegator credit; and
- the same conservation predicate used by `compute_post_state` accepts the
  boundary.

Historical behavior is preserved. `REWARDS_V2_ACTIVATION_EPOCH` remains
`u64::MAX`, its inert-gate tripwire still passes, and below the gate the
delegation basis passed to `rewards::distribute` is zero. The test explicitly
proves that the pre-gate delegator ledger remains empty. No existing chain
state or pre-activation root changes.

ST-06 is therefore `UNARMED CANDIDATE`, not `IMPLEMENTED`: this removes the
known conservation halt from the already gated design, but does not authorize
rewards-v2 activation. Activation still requires coordinated replay,
mixed-binary and economic qualification of all four rules sharing that gate.

## TX-14: genesis principal and burn semantics

No silent consensus correction is safe for the historical genesis offset.
Genesis-4 bonded 1,600,000 BLOCH outside the committed `issued_sat` counter.
Adding that amount retroactively changes committed state from slot zero;
subtracting it from another allocation changes ownership. Either operation is
a relaunch or an explicit state migration, not an audit patch.

The current tree nevertheless contains concrete containment and observability:

- `accounted_supply_sat` totals held value independently of issuance;
- `supply_gap_sat` exposes the signed difference, and a regression proves the
  opening positive gap is exactly the launch cohort's bonds;
- `GENESIS_UNFUNDED_BONDED_CEILING_SAT` freezes the historical offset, while
  `CommittedState::genesis` and `Manifest::check_bonds_are_funded` refuse an
  opening that exceeds it; and
- the block invariant rejects any later holdings growth not matched by
  issuance or explicitly admitted unfunded bonding.

Burns are not absent from the accounting model. They reduce accounted
holdings by omission while `issued_sat` remains a gross, monotone lifetime
issuance counter. The fee-market regression now proves an actual fee burn
leaves `issued_sat` unchanged and lowers both holdings and `supply_gap_sat` by
the exact burned amount. Turning `issued_sat` into circulating supply would
change the meaning of a committed historical field and requires an explicit
protocol/migration decision.

TX-14 moves only to `PARTIAL`. The tree detects and bounds the two effects but
does not erase the historical genesis principal or maintain a separate
committed cumulative-burn/circulating-supply counter.

## Validation

- `cargo test -p bloch-pos-committee rewards_v2_settles_delegator_issuance_share -- --nocapture`
  — 1 passed.
- `cargo test -p bloch-pos-committee 'rewards_v2_' -- --nocapture` — 8 passed.
- `cargo test -p bloch-pos-committee fees_are_charged_by_the_market_and_compound_only_at_the_boundary -- --nocapture`
  — 1 passed.
- `cargo test -p bloch-pos-committee the_genesis_supply_gap_is_exactly_the_cohorts_bonds -- --nocapture`
  — 1 passed.
- `cargo test -p bloch-pos-committee --lib` — 434 passed, zero failed,
  four ignored scale tests.

The commands emitted only pre-existing workspace/compiler warnings. The
post-wave ledger retains all 200 findings: 69 implemented, 90 partial, 25
open, seven base-changed, four protocol decisions, two verified positives,
two unarmed candidates and one finding refuted by the original audit.
