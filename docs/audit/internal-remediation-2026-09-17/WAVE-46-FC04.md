# Wave 46: FC-04 RANDAO-grinding candidate reconciliation

Date: 2026-09-18. Base: `ad7fcf8`. Scope: local source, tests, and audit
ledger only. No activation epoch, consensus behavior, node, validator,
release, deployment, or live state was changed.

## Finding and candidate split

FC-04 has two coupled causes. The next epoch's schedule is derived too close
to the end of the current epoch, letting trailing proposers observe how their
reveal changes the next schedule before deciding whether to publish. The same
withholding has no dedicated proposer-reward cost in the live reward rules.

The current source stages both mitigations, under separate inactive gates:

- `ANCESTRY_SEED_ACTIVATION_EPOCH` changes epoch E's seed from the E-1 closing
  mix to the already-frozen E-2 boundary. Historical replay remains on the
  legacy rule while the constant is `u64::MAX`.
- `REWARDS_V2_ACTIVATION_EPOCH` records scheduled proposal production and
  makes a withheld proposal lose a measurable share of issuance credit. The
  gate remains `u64::MAX`.

The first removes the one-epoch-late information advantage; the second makes
withholding economically non-free. They are complementary. Activating only
the reward rule does not remove schedule look-ahead, and activating only the
seed rule does not price other withholding incentives.

FC-04 moves from open to unarmed candidate. This is not activation approval.
It requires joint historical replay, schedule/grinding simulation, review of
the Rewards V2 credit weights, mixed-version rehearsal, and an explicit plan
for coordinating both consensus gates.

## Validation

The post-integration committee library suite passed 436 tests with four
ignored scale tests and zero failures. It includes closed/open seed-boundary
regressions, deterministic-chain comparison guards, the withheld-proposal
Rewards V2 regression, and inert-gate tripwires for both constants.
