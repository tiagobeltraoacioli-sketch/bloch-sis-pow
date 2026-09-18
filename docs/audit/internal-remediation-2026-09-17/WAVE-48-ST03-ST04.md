# Wave 48 ST-03/ST-04: inactive slashing-economics candidate

Date: 2026-09-18. Branch: `codex/audit-st03-st04`. Starting point:
`6edf07f`. Scope: local source, tests, documentation and audit evidence only.
No activation epoch, consensus behavior, binary, deployment, validator or live
state changed.

## Recovered findings and current behavior

The exact findings were recovered from
`a79c88b:docs/audit/deep-audit-2026-09-16/A3-consensus-staking-lifecycle.md`.

ST-03 identifies a dimensional mismatch in correlation amplification. The
window numerator is the raw operator and activated-delegation loss, while its
denominator is the total effective consensus roster after the genesis-cohort
cap and inactivity leak. With the audit's representative values, a raw
5,700,000 BLCH bond loses 285,000 BLCH at the 5% base penalty, but the effective
total is about 414,000 BLCH. The next penalty therefore computes
`500 + 3 * 10,000 * 285,000 / 414,000`, then saturates at 10,000 bps. An
unrelated later offender loses 100% even though the first effective offender
need represent only one third of consensus weight.

ST-04 identifies self-slashing as an accelerated exit. A voluntary exit at E
sets exit E+32 and withdrawal E+32+2048. Slashing sets exit E+1 and withdrawal
E+2048, and its marker is not counted by the four-per-epoch voluntary churn
budget. A slash can also replace a same-epoch voluntary exit marker with E+1,
making the voluntary counter fall again. The fast withdrawal creates a direct
economic incentive; cap-free E+1 ejection also permits a key owner to remove a
large roster cohort at one boundary.

These are live source rules after the ADR-041 slashing-evidence activation at
epoch 2884. Changing them therefore requires replay-safe versioning and a
coordinated release, not an ungated edit.

## Candidate, deliberately inactive

`SLASHING_ECONOMICS_V2_ACTIVATION_EPOCH` is fixed at `u64::MAX`. The shared
epoch helper treats that sentinel as inactive even for a synthetic
`u64::MAX` epoch, and a closed-gate regression pins the historical withdrawal
lock. Production execution and replay are unchanged.

When rehearsed, the ST-03 candidate takes the offender's effective weight and
the total effective weight from the same frozen consensus roster. It records

`effective_window_loss = offender_effective_stake * penalty_bps / 10,000`

and later divides that window by the matching effective total. The audit
fixture then records 6,900 effective sat-units instead of 285,000 raw units,
so the next penalty is 1,000 bps rather than 10,000 bps. The candidate does
not change the raw amount actually burned or the whistleblower reward.

A future activation boundary does not reinterpret older raw-loss window
entries as effective losses. Those entries remain committed for historical
state-root continuity, but V2 pricing starts at the activation epoch. A
regression injects a large pre-boundary raw entry and proves it is excluded.

For ST-04, the same gate changes a new slash's withdrawal floor to
`E + EXIT_DELAY_EPOCHS + WITHDRAWAL_DELAY_EPOCHS`. Self-slashing therefore
cannot release residue earlier than a voluntary exit requested at E. An
already-longer lock is still never shortened.

ST-03 and ST-04 move from `OPEN` to `UNARMED CANDIDATE`, not `IMPLEMENTED`.
The gate names one coherent economics version so an operator cannot activate
only one half accidentally, but this wave does not propose an epoch.

## Explicit residuals and activation requirements

The candidate intentionally retains E+1 ejection and does not charge it to the
voluntary-exit budget. Bounding evidence inclusion can leave a proven
equivocator on duty; charging ejections to voluntary churn can let ordinary
exits buy temporary slash immunity. Selecting a separate ejection queue,
evidence deferral rule or halt-recovery mechanism is protocol policy and is
not invented here. Consequently, cap-free mass ejection and the same-epoch
voluntary-marker refund remain residual ST-04 risks even under the candidate.

Before activation, reviewers must approve the effective-loss economics,
simulate correlated batches across cohort-cap and inactivity-leak regimes,
model mass self-slashing and roster-halt recovery, replay the complete chain
through the proposed boundary, rehearse mixed-version refusal behavior, and
coordinate a fleet flag day. Operational inventory and deployment evidence
remain external.

## Validation

- `cargo test --locked -p bloch-pos-committee effective_exposure_candidate_prevents_raw_bond_amplification --offline`: one ST-03 arithmetic and activation-boundary regression passed.
- `cargo test --locked -p bloch-pos-committee slashing_economics --offline`: three gate, legacy-lock and ST-04 candidate regressions passed.
- `cargo test --locked -p bloch-pos-committee --offline`: 643 passed, six ignored, zero failed across unit, integration and doc tests.
- `git diff --check`: passed.

The focused runs emitted inherited unused-import, dead-code and rustdoc
warnings. Workspace-wide `cargo fmt --all -- --check` remains red on extensive
pre-existing formatting differences; this wave does not reformat unrelated
files. Focused tests are candidate evidence, not evidence that activation is
safe.
