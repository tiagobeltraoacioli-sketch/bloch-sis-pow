# Wave 46: TX-09 Rewards V2 candidate reconciliation

Date: 2026-09-18. Base: `1438557`. Scope: local source, tests, and audit
ledger only. No activation epoch, consensus behavior, node, validator,
release, deployment, or live state was changed.

## Recovered finding

TX-09 combines four economic divergences below `REWARDS_V2`: delegators earn
no issuance, inactivity leak does not reduce issuance weight, participation
credit is insufficiently scoped, and withholding a scheduled proposal has no
issuance cost.

The current source already stages the intended rules under one deliberately
inactive gate. The remaining concrete blocker in that candidate was ST-06:
delegator issuance credits increased holdings without advancing `issued_sat`.
Wave 45 repaired that accounting while keeping the gate closed.

## Inactive candidate behavior

With the test-only gate open, the transition:

- uses the leak-adjusted consensus roster as the issuance basis;
- derives reward credit from admitted votes with the required source and
  target epoch and excludes in-epoch equivocators;
- resolves delegated stake and validator commission, credits delegators into
  a committed ledger, and advances gross issuance for those credits; and
- records scheduled proposal production so withholding loses a measurable
  portion of the epoch's credit.

Below the gate, current historical behavior remains unchanged. The
`REWARDS_V2_ACTIVATION_EPOCH` tripwire remains `u64::MAX`, and candidate-only
state stays empty.

TX-09 moves from open to unarmed candidate, not implemented. Activation still
requires historical replay, state-growth and performance measurement, economic
review of credit weights and commission behavior, mixed-version rehearsal,
and an explicit protocol-owner epoch decision.

## Validation

The post-integration committee library suite passed 436 tests with four
ignored scale tests and zero failures. It includes eight `rewards_v2_`
regressions, the repaired delegator issuance/conservation test, and the inert
gate tripwire. Existing compiler warnings are inherited.
