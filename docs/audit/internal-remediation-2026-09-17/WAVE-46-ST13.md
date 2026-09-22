# Wave 46 ST-13: inactive activation-queue candidate

Date: 2026-09-18. Branch: `codex/audit-st13-activation-queue`. Starting
point: `436c2ef`. Scope: local source, tests, and audit evidence only. No
activation epoch, node, validator, deployment, public endpoint, or live state
changed.

## Recovered finding and current behavior

The exact source was recovered from repository history at
`a79c88b:docs/audit/deep-audit-2026-09-16/A3-consensus-staking-lifecycle.md`.
ST-13 records two facts: applicants can grind the public-key hash used for
same-epoch ordering, and the queue is unbounded, although every entry requires
at least 25,000 BLOCH to remain bonded through the activation and withdrawal
timelines.

The current tree makes the boundaries more precise:

- funded validator admission has been live since epoch 2,884;
- activation requires an eight-epoch delay and finalized funding, and admits
  at most four validators per epoch;
- funded candidates sort by `(deposit_epoch, pubkey_hash)`;
- `deposit_history` and validator records are permanent. Boundary processing
  scans the history, so a pending-only limit would not bound long-term state or
  scan work;
- the registry index's `u32` exhaustion check is not a practical resource
  policy. Node mempool bounds constrain one reference producer, not a block
  assembled elsewhere.

## Candidate, deliberately inactive

`ACTIVATION_QUEUE_V2_ACTIVATION_EPOCH` remains `u64::MAX`. Its test-only
rehearsal binds both halves of one candidate:

1. Registration stops once the permanent registry reaches 4,096 entries.
   The check covers the live funded path and the separately disabled legacy
   deposit path. A lifetime ceiling, rather than a pending-entry ceiling,
   bounds both permanent records and deposit history. At the minimum bond it
   represents 102.4 million BLOCH, and permits 64 times the 64-validator
   genesis cohort. Those figures explain the candidate; they do not establish
   that 4,096 is the correct production policy.
2. Funded applicants from the same deposit epoch are ordered by
   `SHA3-256(DS_SORTITION || seed_for_epoch(activation_epoch) || pubkey_hash ||
   ROLE_ACTIVATION_QUEUE)`. The dedicated role byte separates this permutation
   from proposer and committee draws. The seed is fixed at the boundary before
   activation, at least eight epochs after the applicant committed its key, so
   choosing a numerically low key hash no longer buys priority.

Below the gate, the ordering helper returns the raw public-key hash and neither
registration path consults the ceiling. Existing blocks and historical replay
therefore retain their current verdict and activation schedule.

ST-13 moves from `OPEN` to `UNARMED CANDIDATE`, not `IMPLEMENTED`. Activation
still requires a protocol-owner choice of lifetime cap and exhaustion policy,
complete historical replay, boundary CPU/memory measurements, and mixed-version
fleet rehearsal. FC-04 remains relevant because trailing proposers can influence
the beacon seed; an applicant can also fund many distinct keys and sample their
priorities at real economic cost. The permanently disabled legacy-unfunded
scheduler retains raw-hash ordering and would need the same redesign before
that unsafe transaction format could ever be reconsidered.

## Validation

- `cargo test -p bloch-pos-committee activation_priority_is_seeded_not_raw_pubkey_order --offline`:
  one targeted unit test passed.
- `cargo test -p bloch-pos-committee activation_queue_v2_is_inert_and_caps_the_permanent_registry_when_rehearsed --offline`:
  one targeted unit test passed at the exact 4,096-entry boundary.
- `cargo test -p bloch-pos-committee --test spec_reconcile f06_domain_and_state_tags_all_published --offline`:
  one domain-registry test passed.
- `cargo test -p bloch-pos-committee --lib activation_ --offline`: 11 passed,
  including the existing funded multiblock activation/replay flow.
- `cargo test -p bloch-pos-committee --lib --offline`: 438 passed, four
  ignored, zero failed.
- `git diff --check`: passed.

The builds emitted inherited unused-import, unused-doc-comment and dead-code
warnings. No warning or local candidate is deployment evidence.
