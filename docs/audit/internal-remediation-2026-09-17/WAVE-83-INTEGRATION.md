# Wave 83 integration checkpoint

Date: 2026-09-19. Branch: `fix/internal-audit-20260917`. Comparison base:
`f57ed91`. Four agents continued remediation across wallet secret lifetime,
orphan retention and GitHub workflow authority. No release, deployment,
production mutation or remote push occurred.

## Ledger result

All 200 finding rows and unique IDs remain intact: 71 `IMPLEMENTED`, 98
`PARTIAL`, 15 `UNARMED CANDIDATE`, 5 `PROTOCOL DECISION`, 7 `BASE CHANGED`,
1 `OPEN`, 1 `REFUTED IN AUDIT` and 2 `VERIFIED POSITIVE`. CR-07, EN-08/NET-04
and INF-03/INF-04/INF-11 remain `PARTIAL`; this wave narrows their residuals
without changing classification. SR-03 remains the sole open finding.

## Integrated changes

CR-07 removes another complete secret copy from the historical legacy-keystore
load path. Canonical private/public hex strings borrow the already-zeroizing
decrypted JSON buffer. Escaped historical JSON remains compatible through an
owned fallback whose drop explicitly wipes both strings. Format, API, KDF,
AAD, authentication and decoded key behavior are unchanged.

EN-08/NET-04 add canonical-encoded byte budgets to the combined waiting and
ready-to-promote orphan queues: 16 MiB globally and 4 MiB per normalized gossip
source, alongside the existing 256/32 entry limits. Lengths are computed
without a second frame-sized allocation, cached and carried unchanged through
promotion. Local work remains globally bounded. Global eviction touches only
waiting FIFO entries, and preflight refuses admissions that cannot fit beside
immutable deferred work before displacing anything. The byte budget is a
stable payload-retention proxy, not an exact decoded heap/RSS bound.

INF-03/INF-04/INF-11 require the complete reviewed GitHub trigger mapping and
exact token authority. Nested filters, extra/duplicate events, scalar/flow
replacements and plain or quoted permission overrides on required jobs fail
closed. This is a local structural proof; hosted event delivery, repository
rules and runner policy remain external.

## Validation

- The complete `bloch-crypto` suite passed 206 library tests with 2 ignored,
  6 integration tests, and 2 ignored documentation tests: 212 passed, 4
  ignored, no failures.
- The orphan-byte filter passed 21/21 tests with 562 filtered; the pre-existing
  global count/FIFO compatibility regression passed 1/1 with 582 filtered.
  `cargo check -p bloch-pos-node --tests --offline` passed. The codec length
  parity regression also passed independently.
- Independent reviews found and required fixes for oversized-entry queue
  flushing, impossible admission beside immutable deferred work, FIFO success
  coverage, count-cap ordering, a missing cap-order assertion and heap/RSS
  wording before approval.
- Test posture passed 132/132 adversarial cases; scanner posture passed 93/93.
  Real guards covered every live crate on both pipelines and 8+8 security
  jobs. Relevant Python compilation, reviewed digest and diff checks passed.
- No complete node binary suite was rerun after the Wave 83 byte-retention
  change. No hosted CI, long rehearsal, workspace-wide formatting or release
  result is claimed in this wave.

## Commits

- `a70a0cf` — borrow decrypted historical-keystore secret strings.
- `b27b2a0` + `b9c78ec` — bind GitHub triggers/token scope and normalize its
  audit report.
- `e3d2118` — bound combined orphan retention by canonical encoded bytes.

## Launch boundary

The new MW binary is **not ready to launch**. The canonical Linux image still
needs two independently authenticated builds and comparison; hosted CI is not
evidenced green; release and rollback artifacts are unsigned; SR-03 lacks a
fresh independently signed weak-subjectivity envelope; rollback has not been
rehearsed on a scratch systemd host; and no staged canary or fleet digest
evidence exists. These external gates remain mandatory before readiness or
production rollout.
