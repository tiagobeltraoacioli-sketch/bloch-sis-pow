# Wave 46: TX-08 fee-to-stake candidate reconciliation

Date: 2026-09-18. Base: `436c2ef`. Scope: local source, tests, and audit
ledger only. No activation epoch, consensus behavior, node, validator,
release, deployment, or live state was changed.

## Recovered finding

The original A1 finding records that a proposer can convert liquid coin into
bonded consensus weight through self-paid tips. Below the candidate gate, the
full producer fee share accrues without a per-block ceiling and compounds into
`ValidatorRecord::staked_sat` at the epoch boundary.

The remediation ledger had left TX-08 open even though the current source
already carries a complete, deliberately inactive candidate under
`FEE_STAKE_DECOUPLE_ACTIVATION_EPOCH`.

## Existing inactive candidate

When the gate is active, three coordinated rules bind:

- producer fee credit is capped at 100 BLCH per block and excess is burned by
  omission;
- the operator fee share settles into the committed
  `validator_fee_rewards` ledger instead of increasing its bond; and
- the duty roster caps combined own and delegated stake, preventing the same
  concentration from re-entering through the validator's own bond.

The gate remains `u64::MAX`. Closed-gate controls prove current blocks retain
the historical uncapped/compounding behavior. Forced-gate tests prove the cap,
withdrawable settlement, and combined weight rule. Empty candidate state adds
no pre-gate state-root leaves.

TX-08 therefore moves from open to unarmed candidate, not implemented. An
activation requires full historical replay, mixed-version qualification,
economic review of the 100 BLCH ceiling and excess burn, withdrawal-ledger
qualification, and an explicit protocol-owner epoch decision.

## Validation

`cargo test -p bloch-pos-committee decoupled_ --offline` passed all three
candidate regressions. Existing compiler warnings are inherited. The
closed-gate `fee_stake_gate_is_inert` tripwire remains in the suite and the
constant remains `u64::MAX`.
