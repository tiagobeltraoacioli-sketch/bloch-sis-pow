# Wave 54 integration checkpoint

Date: 2026-09-18. Branch: `fix/internal-audit-20260917`. Comparison base:
`db7b737`. Four agents implemented and reviewed vault secret encapsulation,
libp2p pre-decode admission, keystore KDF resource bounds and scanner-gate
inheritance refusal. No consensus gate was armed, no release binary was built
or signed, and no deployment, credential, fund, registry or live node changed.

## Ledger result

All 200 finding rows and classifications remain intact:

- 71 `IMPLEMENTED`;
- 98 `PARTIAL`;
- 15 `UNARMED CANDIDATE`;
- 5 `PROTOCOL DECISION`;
- 7 `BASE CHANGED`;
- 1 `OPEN`;
- 1 `REFUTED IN AUDIT`; and
- 2 `VERIFIED POSITIVE`.

This wave narrows BV-09, NET-22, KS-11 and INF-11. All remain `PARTIAL`
because their lower-level, operational or external-evidence residuals remain.
SR-03 is still the sole open finding.

## Integrated changes

BV-09 makes the three secret-bearing `VaultKeys` fields private and exposes
borrow-only accessors. A compile-fail contract prevents direct downstream
cloning of the owned PQ vector, and identity checks prove the accessors do not
allocate secret copies. Bitcoin `SecretKey` remains `Copy`, and explicit byte
copying and third-party/compiler/OS behavior remain outside the guarantee.

NET-22 reserves existing per-peer and aggregate first-hop capacity from the
bounded libp2p topic and frame length before decoding block, attestation or
transaction payloads. Decode/canonicality failures release the guard; a
forwarded event carries it without a second source charge. Libp2p transport
allocation still precedes the application callback.

KS-11 reduces ordinary unauthenticated-header combined Argon2 work from one
GiB-pass to 256 MiB-pass. Production's 64 MiB times three remains accepted,
as does the exact 64 MiB times four boundary. Only the explicit legacy
recovery path retains the older finite ceiling.

INF-11 refuses `extends:` and `inherit:` in required GitLab scanner jobs and
job-level reusable-workflow `uses:` in required GitHub jobs. Normal step-level
actions remain accepted. The textual guard still does not claim complete YAML,
dynamic shell, external-include, hosted-CI or branch-protection proof.

## Integration hygiene

One agent accidentally invoked workspace-wide formatting while intending to
format three files. The complete mechanical Rust diff was identified before
any commit and reversed. The intended vault work was reconstructed from the
Wave 53 base in an isolated worktree; KS-11 was reapplied as two small reviewed
hunks. The integrated tree contains no workspace-formatting churn.

## Validation

- `bloch-pos-node` passed 517 unit tests with 19 ignored finite/performance
  rehearsals. All integration targets passed: 118 tests passed and 6
  performance tests were explicitly ignored.
- The first node run inside the restricted sandbox failed only at 148 local
  socket binds with `Operation not permitted`; the authorized loopback-capable
  rerun passed all 517 tests.
- `bloch-pq-vault` passed 45/45 plus two compile-fail doctests;
  `pq-shield-api` passed 19/19.
- The scanner-posture guard passed 26 two-direction fixtures and all 16
  required checked-in jobs. The test-posture guard passed 37 fixtures and both
  checked-in pipelines across eight live crates.
- Ledger arithmetic remained exactly 200 rows with the published status
  counts. Conflict-marker scanning and `git diff --check` passed.
- Workspace-wide `cargo fmt --check` retains the inherited formatting backlog
  and is not claimed green.

## Launch boundary

The new MW binary is **not ready to launch**. The canonical Linux image still
needs two independently authenticated builds and comparison; hosted CI is not
evidenced green; release and rollback artifacts are unsigned; SR-03 lacks a
fresh independently signed weak-subjectivity envelope; rollback has not been
rehearsed on a scratch systemd host; and no staged canary or fleet digest
evidence exists. These external gates remain mandatory before readiness or
production rollout.
