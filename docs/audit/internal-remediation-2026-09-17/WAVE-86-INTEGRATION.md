# Wave 86 integration checkpoint

Date: 2026-09-19. Branch: `fix/internal-audit-20260917`. Comparison base:
`a228c91`. Four agents continued remediation across master-seed lifetime,
queue byte accounting and CI YAML authority. No release, deployment,
production mutation or remote push occurred.

## Ledger result

All 200 finding rows and unique IDs remain intact: 71 `IMPLEMENTED`, 98
`PARTIAL`, 15 `UNARMED CANDIDATE`, 5 `PROTOCOL DECISION`, 7 `BASE CHANGED`,
1 `OPEN`, 1 `REFUTED IN AUDIT` and 2 `VERIFIED POSITIVE`. CR-07, EN-08/NET-04
and INF-03/INF-04/INF-11 remain `PARTIAL`; this wave narrows their residuals
without changing classification. SR-03 remains the sole open finding.

## Integrated changes

CR-07 wraps the repository's two consumers of the BIP39-derived 64-byte master
seed immediately in `Zeroizing<[u8; 64]>`: wallet V1/V2 key generation and
the CLI disclosure derivation. The array is moved without cloning. Public API,
schema, KDF, derivation and output bytes remain unchanged.

EN-08/NET-04 reuse each transport source reservation's exact bounded wire
charge for later aggregate queue bookkeeping. Gossip and sync attach the
private hint only after decoded canonical size equals raw input; legacy does
the same class/size proof before attachment. Reserve, failed-send cleanup and
release therefore cancel the identical integer without one or two additional
payload serializations. Source-free/local work retains canonical fallback.
The receive boundary still re-encodes once, and all caps/verdicts remain
unchanged.

INF-03/INF-04/INF-11 reject YAML merge keys in the supported CI subset. A
real YAML parser showed `<<: *runner_policy` could inject hidden root runner
authority while both textual guards reviewed honest decoys. Plain merge keys
at root or required-job scope now fail closed; quoted/explicit/flow forms were
already excluded, while block-scalar text and ordinary scalar values remain
data.

## Validation

- The complete `bloch-crypto` suite passed 209 library tests with 2 ignored,
  6 integration tests, and 2 ignored documentation tests: 215 passed, 4
  ignored, no failures. The new master-seed regression passed 1/1; disclosure
  passed 12/12; the `postern-wallet` feature check passed.
- `cargo check -p bloch-pos-node --tests --offline` passed. Four focused queue
  accounting regressions each passed 1/1 with 585 filtered: retained devnet
  release, source-free fallback, malformed/trailing sync quota release and
  failed-delivery count/byte cleanup.
- Independent reviews required source reservations to attach only after the
  raw/canonical equality and corrected an inaccurate pre-existing comment
  about release ordering. Both changes landed before the network commit.
- Test posture passed 167/167 adversarial cases; scanner posture passed
  128/128. Real guards covered every live crate on both pipelines and 8+8
  security jobs. Relevant Python compilation, digest and diff checks passed.
- No complete node binary suite was rerun after the Wave 86 queue-accounting
  change. No hosted CI, long rehearsal, workspace-wide formatting or release
  result is claimed in this wave.

## Commits

- `efcf8b7` — zeroize both internal master-seed consumers.
- `e25773c` — reject YAML merge authority in CI guards.
- `e362dfe` — reuse validated queue wire charges symmetrically.

## Launch boundary

The new MW binary is **not ready to launch**. The canonical Linux image still
needs two independently authenticated builds and comparison; hosted CI is not
evidenced green; release and rollback artifacts are unsigned; SR-03 lacks a
fresh independently signed weak-subjectivity envelope; rollback has not been
rehearsed on a scratch systemd host; and no staged canary or fleet digest
evidence exists. These external gates remain mandatory before readiness or
production rollout.
