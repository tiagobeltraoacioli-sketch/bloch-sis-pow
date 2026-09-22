<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Coordinated leak-recovery replacement — epoch 2880

Candidate schedule selected by the operator on 2026-09-13: **Monday,
2026-09-14 at 21:31:19 UTC (18:31:19 America/Sao_Paulo)**, epoch 2880.
The ADR-041 lifecycle follows at epoch 2884, 22:35:19 UTC (19:35:19 local).
These are release targets, not claims of completed deployment. Qualification
and complete fleet readiness are prerequisites; postpone the coordinated
schedule before the boundary if they are not satisfied.

## Why the old date cannot be reused

The epoch-2700 deadline, selected on September 6, was missed by the legacy
signing fleet. Seven-host inspection on September 13 found the same older
binary throughout. A keyless replay of 63,683 canonical input blocks with the
epoch-2700 candidate accepted only 63,234, stopping at slot 86,431. It did not
know the operator-approved epoch-2713 checkpoint. Reusing 2700 would change
already committed history and does not implement the approved recovery.

The replacement keeps historical arithmetic before 2880 and applies the same
leak-recovery and **one-half denominator floor** policy prospectively. It does
not select a new genesis, erase signing watermarks, change the floor to another
fraction, or enable legacy unfunded deposit/delegation. Exact-history control
replay and release qualification are recorded in the
[activation preflight](audit/VALIDATOR-ACTIVATION-PREFLIGHT-2026-09-13.md).
The test `leak_recovery_armed_epoch_matches_the_runbook` pins this replacement.

## Rules at the boundary

At the configured boundary, quorum accounting uses the approved denominator
floor and finalized progress can recover previously leaked balances. Both are
committed consensus behavior; this cannot be changed by a runtime option.
Every validator and serving archival must carry the same schedule beforehand.
A fleet divided between old and new schedules can compute different roots.

The `prova.rs` scenario tests show that the floor prevents the particular
small partitions in the August 24 reproduction from justifying independently.
They do **not** prove that every partition becomes safe. The residual
conflicting-quorum limitation of the founder-selected one-half floor remains
as documented in `finality.rs`. Scheduling evidence penalties at lifecycle
epoch 2884 on 2026-09-14 does not turn a local finalized label into a universal
settlement guarantee.

## Release and rollout

1. Verify exact replay against the approved history and qualify the candidate
   with the actual finite schedule. Include the corrected post-replay
   duplicate-instance observation and durable signing protection.
2. Record the source revision, complete patch, build provenance and binary
   digest. Distribute an immutable artifact and verify it on each host.
3. Recover canary 35 first. Preserve its own key and signing protection,
   stop every old instance before replacement, and retain conflicting public
   history. Never borrow a donor's key or signing journal.
4. Validate canary recovery and duties, then migrate in the approved batches
   of 11, 11, 11, 11, 10 and 10, retaining the seven-server placement. Before
   each batch, recheck available effective stake, including already absent
   validators. Healthy nodes retain their canonical histories.
5. Activate the existing correct key for validator 63 on HOST-006; leave its
   inactive classic copy fenced. The placement becomes ten validators on
   HOST-006 and nine on each other host.
6. Verify all 64 signers and both archivals, independent finalized checkpoints,
   and at least three epochs of consistent progress. Complete this before
   epoch 2880. A scheduled constant alone is not fleet readiness.
7. Watch finality and roots across 2880, then across lifecycle epoch 2884.
   Keep the real withdrawal delay unchanged. Broad external-validator opening
   requires the controlled withdrawal-and-spend evidence specified by ADR-041.

## Incomplete rollout or disagreement

Do not let a partially upgraded fleet cross either finite boundary. If the
qualification or available time is insufficient, prepare and verify a common
later schedule and replace every installed candidate **before** its existing
boundary. Record the new decision and each node's acceptance. Never assume a
pre-boundary binary is a safe rollback after a boundary has been crossed.
