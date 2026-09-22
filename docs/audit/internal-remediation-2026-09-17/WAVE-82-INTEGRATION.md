# Wave 82 integration checkpoint

Date: 2026-09-19. Branch: `fix/internal-audit-20260917`. Comparison base:
`f438c75`. Four agents continued remediation across legacy wallet decryption,
orphan retention fairness and workflow execution authority. No release,
deployment or production mutation occurred.

## Ledger result

All 200 finding rows and unique IDs remain intact: 71 `IMPLEMENTED`, 98
`PARTIAL`, 15 `UNARMED CANDIDATE`, 5 `PROTOCOL DECISION`, 7 `BASE CHANGED`,
1 `OPEN`, 1 `REFUTED IN AUDIT` and 2 `VERIFIED POSITIVE`. CR-07,
EN-08/NET-04 and INF-03/INF-04/INF-11 remain `PARTIAL`; this wave narrows
their residuals without changing classification. SR-03 remains the sole open
finding.

## Integrated changes

CR-07 applies the Wave 81 in-place AES-GCM pattern to historical
`Keypair::load_encrypted`. The Base64-decoded ciphertext is immediately owned
by `Zeroizing<Vec<u8>>`, authenticated and decrypted in its existing
allocation. Nonce/tag validation still precedes Argon2 and is repeated before
fixed-size AES conversion. Format, API, KDF, AAD and historical ciphertext
compatibility are unchanged.

EN-08/NET-04 add a 32-entry retention share per normalized gossip source
across the combined waiting and ready-to-promote orphan queues. The global
256-entry FIFO cap remains outermost; `Gossip(None)` is one collective bucket
and local production is exempt. Deduplication precedes quota accounting,
overflow remains `Ignore`, and exact internal counter deltas cover attributed,
combined, unattributed and local boundaries. The report explicitly records
that a newly refused entry does not itself arm `needs_sync` and may depend on
later regossip or other sync progress.

INF-03/INF-04/INF-11 bind GitHub workflow authority as data, not merely the
jobs beneath it. The test workflow must retain `push` and `pull_request`, must
not add `pull_request_target`, and grants exactly `contents: read`. Both
test/security meta-guards require one plain `on` and `permissions` key, so a
quoted duplicate appended later cannot replace the effective trigger or token
policy behind an honest decoy.

## Validation

- The complete `bloch-crypto` suite passed 205 library tests with 2 ignored,
  6 integration tests, and 2 ignored documentation tests: 211 passed, 4
  ignored, no failures.
- At the Wave 82 baseline, the complete node binary suite passed 558 tests
  with 19 ignored and no failures. After the orphan-share change, both focused
  fairness/global-cap regressions passed 1/1 outside the socket sandbox, with
  577 tests filtered in each command; `cargo check --tests` passed.
- Two independent reviews found no production bypass. They required exact
  counter assertions, removal of an unrun-result placeholder, and correction
  of an inaccurate `needs_sync` recovery claim before the network commit.
- Test posture passed 128/128 adversarial cases; scanner posture passed 89/89.
  Real guards covered every live crate on both pipelines and 8+8 security
  jobs. Relevant Python compilation, reviewed digest and diff checks passed.
- No hosted CI, long rehearsal, workspace-wide formatting or release result
  is claimed in this wave.

## Commits

- `7a11a21` — bind GitHub workflow triggers and token authority.
- `3a2c40b` — decrypt historical wallet keystores in place.
- `b86a2fd` — reserve combined orphan capacity per gossip source.

## Launch boundary

The new MW binary is **not ready to launch**. The canonical Linux image still
needs two independently authenticated builds and comparison; hosted CI is not
evidenced green; release and rollback artifacts are unsigned; SR-03 lacks a
fresh independently signed weak-subjectivity envelope; rollback has not been
rehearsed on a scratch systemd host; and no staged canary or fleet digest
evidence exists. These external gates remain mandatory before readiness or
production rollout.
