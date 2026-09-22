# Wave 79 integration checkpoint

Date: 2026-09-19. Branch: `fix/internal-audit-20260917`. Comparison base:
`6a30397`. Four agents continued audit remediation across pre-allocation wallet
limits, pending-attestation crypto preflight, validator-lifecycle proof
recovery and cross-pipeline executable-proof parity. No release, deployment or
production mutation occurred.

## Ledger result

All 200 finding rows and unique IDs remain intact: 71 `IMPLEMENTED`, 98
`PARTIAL`, 15 `UNARMED CANDIDATE`, 5 `PROTOCOL DECISION`, 7 `BASE CHANGED`,
1 `OPEN`, 1 `REFUTED IN AUDIT` and 2 `VERIFIED POSITIVE`. CR-07,
EN-08/NET-04 and INF-03/INF-04 remain `PARTIAL`; this wave narrows their
residuals without changing classification. SR-03 remains the sole open
finding.

## Integrated changes

CR-07 now counts aggregate and derived HD-wallet records with a non-retaining
Serde preflight before full record allocation, mnemonic parsing, KDF,
decryption or derivation. A cross-review found and repaired positional-struct
compatibility; keyed and sequence JSON now receive identical early limits.

EN-08/NET-04 preflight all seven pending-only attestation capacity limits
before hybrid signature verification. Known-root messages still authenticate,
no message is accepted or held without a valid signature, and panic-sentinel
regressions prove every saturated branch stops before crypto.

The previously known-red funded-admission rehearsal now matches the hardened
admission contract. It proves exact per-slot verification exhaustion and
recovery, canonical duplicate classification without mempool reinsertion,
monotonic logical clocks, deterministic slashing admission and cheap-first
payout refusal reasons. Its full two-node lifecycle, CLI payout, finalization,
history replay and RANDAO proof passed with shipping activation source
unchanged.

INF-03/INF-04 make GitLab execute both the finite activation rehearsal and the
full funded-admission rehearsal already required by GitHub. Exact ordered
contracts and bidirectional removal fixtures bind both pipelines; the posture
selftest now contains 106 adversarial cases.

## Validation

- Outside the restricted local-socket sandbox, `bloch-pos-node` passed 556
  unit tests with 19 ignored finite/performance rehearsals. All integration
  targets passed: 131 tests passed and 6 performance tests were ignored.
- The complete `bloch-crypto` suite passed 200 library tests with 2 ignored,
  6 integration tests, and 2 ignored documentation tests. Committee gossip
  passed 27/27 tests.
- `scripts/rehearse-validator-admission.py` passed the funded invalid-state and
  full two-node lifecycle proofs, full-history replay and the short RANDAO
  proof. Its measured local duration was approximately 16 minutes against a
  120-minute CI job timeout.
- The finite activation boundary/replay and unarmed-compatibility rehearsal
  passed outside the sandbox with shipping source unchanged.
- The test-posture guard passed 106 adversarial cases; the scanner-posture
  guard passed 79 two-direction fixtures. Both real guards passed for eight
  crates/jobs and eight security jobs on each pipeline.
- The activation parser's 4 tests, pinned-toolchain parser/consumers, relevant
  Python compilation, ledger arithmetic, unambiguous conflict-marker scan and
  `git diff --check` passed.
- Workspace-wide `cargo fmt --check` retains the inherited formatting backlog
  and is not claimed green.

## Commits

- `9c6771a` — preflight pending attestation capacity before crypto.
- `3744ec7` — preflight HD-wallet record limits before materialization.
- `70f2c63` — prove every pending preflight terminates before crypto.
- `86ae5d8` — gate the finite activation rehearsal on GitLab.
- `837a41d` — preserve positional Serde compatibility under wallet limits.
- `a0a0f37` — clarify pending-pool and lookup snapshot contracts.
- `0f929c4` — recover the full funded-admission lifecycle rehearsal.
- `b7fba27` — gate the funded-admission rehearsal on GitLab.

## Launch boundary

The new MW binary is **not ready to launch**. The canonical Linux image still
needs two independently authenticated builds and comparison; hosted CI is not
evidenced green; release and rollback artifacts are unsigned; SR-03 lacks a
fresh independently signed weak-subjectivity envelope; rollback has not been
rehearsed on a scratch systemd host; and no staged canary or fleet digest
evidence exists. These external gates remain mandatory before readiness or
production rollout.
