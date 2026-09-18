# Internal audit remediation, twenty-sixth wave — 2026-09-18

Base: `994cacd`; implementation commit `d8437a4`; branch
`fix/internal-audit-20260917`. This is local source/test evidence, not proof of
a fleet rollout or a finalized-chain event.

## Protocol prose follows the executable rule

FC-14 collected source documentation that described a different protocol from
the one the transition executes. The scheduler and committee APIs now state
that the F6 seed look-ahead is conditional on
`ANCESTRY_SEED_ACTIVATION_EPOCH`, which remains inert in this source. Below the
gate, the transition still selects the legacy `epoch - 1` boundary; reference
helpers that always model the post-gate rule no longer present themselves as
the unconditional production entry point.

The finality module header now describes the live partition committee instead
of the retired sampled 8/128 design. Inactivity-leak prose now says what the
code does: it discounts quorum weight in a separate accumulator and does not
debit `ValidatorRecord::staked_sat`, burn bonded coins or change supply.
Comments and test diagnostics that still named the missed epoch-2700 deadline
now identify the epoch-2880 replacement schedule.

Slashing documentation was reconciled earlier in this branch: evidence has a
source activation schedule at epoch 2884, while deployment and economic
settlement remain explicitly outside source evidence.

## Regression and validation

`spec_reconcile` now reads the relevant source modules and fails if seed prose
loses the activation-gate qualification, if finality again presents the 8/128
sampler as live, or if the leak is described as a coin burn. All 11
reconciliation tests pass. The real leak-denominator regression, the
comment/constants scanner, banned-language gate and diff-integrity check also
pass; details are in `VALIDATION-WAVE-26.txt`.

FC-14 is implemented locally. The ledger retains all 200 rows: 63 implemented,
77 partial, 46 open, seven base-changed, four protocol decisions, one unarmed
candidate, one refuted by the original audit and one verified positive.
