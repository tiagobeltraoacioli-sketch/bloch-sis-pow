# Wave 45: lifecycle metering/runbook reconciliation

Date: 2026-09-18. Base: `4e15334`. Scope: local source, tests, and audit
ledger only. No activation epoch, consensus rule, node, validator, release, or
deployed configuration was changed.

## Finding

ST-12 observed that activating the ADR-041 lifecycle also activates capacity
metering for `ExitV2`, `RandaoRecommit`, and `SlashingEvidence`. The standalone
`STAKING_TX_METERING_ACTIVATION_EPOCH` remains inert, but
`staking_tx_charge` deliberately opens when `WITHDRAWAL_ACTIVATION_EPOCH`
opens. The historical flag-day document did not list that effect.

The production lifecycle boundary is already epoch 2,884. Changing the
coupling now would be a consensus change and would alter historical replay.
The safe remediation is to make the actual rule explicit and pin it.

## Remediation

- `docs/VALIDATOR-OPENING.md`, the current validator-opening checklist, now
  states that the lifecycle boundary makes all lifecycle variants consume the
  existing block gas and byte budgets.
- The documentation also states the limits of the rule: it charges no money
  fee and does not introduce a transaction-count cap.
- `lifecycle_gate_also_activates_staking_capacity_metering` proves that the
  same transaction shape has zero gas/bytes immediately before epoch 2,884
  and non-zero gas with exact byte accounting at epoch 2,884.
- The regression also pins the standalone metering gate at `u64::MAX`, so the
  evidence does not silently claim that gate was armed.

ST-12 is implemented because the finding was a documentation omission about
existing behavior, and both the current operator document and an executable
boundary regression now describe that behavior. This does not close TX-10's
independent transaction-count concern.

## Validation

`cargo test -p bloch-pos-committee lifecycle_gate_also_activates_staking_capacity_metering --offline`
passed with one matching test. Existing workspace warnings remain unrelated to
this change. `git diff --check` is the scoped whitespace gate.
