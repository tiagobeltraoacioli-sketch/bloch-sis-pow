# Wave 46: FC-08 sub-epoch duty-view reconciliation

Date: 2026-09-18. Base: `0aa8e23`. Scope: local source, tests, and audit
ledger only. No activation epoch, consensus behavior, node, validator,
release, deployment, or live state was changed.

## Finding split

At the first slots of epoch E, a validator may not yet have received the last
block of E-1. Under the live `back = 1` rule, that tail block can affect both
the committee seed and the latest source checkpoint. An attestation produced
from the lagging view may therefore name the wrong committee slot or carry a
stale source.

The current tree addresses only the seed half:

- the inactive `ANCESTRY_SEED_ACTIVATION_EPOCH` candidate reads the E-2
  boundary, frozen before E-1 starts; and
- peer-side judgment derives committee membership from the attestation's own
  branch instead of the receiver's moving head.

The source-checkpoint half remains. Consensus currently requires an
attestation's slot epoch to equal the state epoch. It cannot include a valid
late E-1 attestation in E, so the standard late-inclusion recovery path is not
available. Adding it changes admission, tally windows, state retention,
rewards, and block validity and needs its own gate and specification.

FC-08 moves from open to partial, not to implemented or an activation-ready
candidate. The seed mitigation remains `u64::MAX`, and the source half still
requires design, historical replay, mixed-version and reward/finality tests.

## Evidence

The post-integration committee library suite passed 436 tests with four
ignored scale tests and zero failures. Existing seed-boundary, ancestry-anchor
and branch-judgment regressions are retained. No late-inclusion behavior was
added or claimed.
