# Wave 81 integration checkpoint

Date: 2026-09-19. Branch: `fix/internal-audit-20260917`. Comparison base:
`b6a99fb`. Four agents continued remediation across wallet secret-memory use,
deferred block authentication and fail-closed CI execution contracts. No
release, deployment or production mutation occurred.

## Ledger result

All 200 finding rows and unique IDs remain intact: 71 `IMPLEMENTED`, 98
`PARTIAL`, 15 `UNARMED CANDIDATE`, 5 `PROTOCOL DECISION`, 7 `BASE CHANGED`,
1 `OPEN`, 1 `REFUTED IN AUDIT` and 2 `VERIFIED POSITIVE`. CR-07, EN-08/NET-04
and INF-03/INF-04/INF-11 remain `PARTIAL`; the corrections narrow their
residuals without changing classification. SR-03 remains the sole open
finding.

## Integrated changes

CR-07 now Base64-decodes encrypted HD-wallet ciphertext directly into a
`Zeroizing<Vec<u8>>` and uses AES-GCM in-place authentication/decryption.
Successful restore reuses the same allocation for plaintext; authentication
or validation failure drops and wipes the buffer. Exact empty-plaintext/tag
boundaries and pointer stability are pinned. CR-08 was deliberately unchanged:
the current `rand_chacha` state is opaque and not `Zeroize`, and the required
by-value `SeedableRng` seed cannot be honestly erased by a local wrapper.

EN-08/NET-04 extend authenticated replay to future and orphan block promotion.
A private move-only proof binds block id, proposal root, signature hash and
current registry-key hash. Future→orphan→connected promotion reruns all mutable
admission, body and transition checks while avoiding two redundant gossip
hybrid verifications. A missing or mismatched binding verifies normally. A
controlled synthetic swap to a second fixture's real registry key proves the
old proof cannot authorize release: fresh verification runs, rejects and
stores no block.

INF-03/INF-04/INF-11 close several execution-contract bypasses. GitLab clears
all inherited Rust flag channels and every required security job inherits the
reviewed global setup. Required test/security job keys must occur exactly once
in plain YAML form. Reviewed GitHub `defaults`/`env` and GitLab
`default`/`variables` blocks have the same uniqueness rule, preventing quoted
late duplicates from replacing the effective job or environment while an
honest plain block remains as a decoy.

## Validation

- The complete `bloch-crypto` suite passed 204 library tests with 2 ignored,
  6 integration tests, and 2 ignored documentation tests: 210 passed, 4
  ignored, no failures.
- `cargo check -p bloch-pos-node --tests --offline` passed with inherited
  warnings. Both new deferred-block regressions passed 1/1 outside the socket
  sandbox, with 576 tests filtered in each command.
- Independent cross-review found no blocking semantic or security issue. It
  corrected the proof description from one-use to move-only/revalidated and
  replaced a directly corrupted fingerprint control with a synthetic swap to
  a genuinely different fixture registry key.
- The test-posture selftest passed 123/123 cases and its real guard covered all
  eight live crates on both pipelines. The scanner-posture selftest passed
  87/87 cases and its real guard covered 8 GitHub plus 8 GitLab security jobs.
- Relevant Python compilation, reviewed digests, real guards and scoped
  `git diff --check` passed. No full node suite, hosted CI, long rehearsal or
  workspace-wide formatting claim is made in this wave.

## Commits

- `c48df20` — clear inherited Rust compiler flags in GitLab.
- `28e8735` — preserve the reviewed environment for required GitLab jobs.
- `13a3bd2` — require unique plain security-job keys in both pipelines.
- `068068e` — require unique plain required-test job keys.
- `49b9390` — protect global GitHub/GitLab execution-context keys.
- `b0c388b` — decrypt HD-wallet secrets in place in a zeroizing buffer.
- `7176e90` — reuse authenticated deferred blocks across promotion.

## Launch boundary

The new MW binary is **not ready to launch**. The canonical Linux image still
needs two independently authenticated builds and comparison; hosted CI is not
evidenced green; release and rollback artifacts are unsigned; SR-03 lacks a
fresh independently signed weak-subjectivity envelope; rollback has not been
rehearsed on a scratch systemd host; and no staged canary or fleet digest
evidence exists. These external gates remain mandatory before readiness or
production rollout.
