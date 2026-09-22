# Wave 72 integration checkpoint

Date: 2026-09-19. Branch: `fix/internal-audit-20260917`. Comparison base:
`eef995e`. Four agents continued audit remediation across wallet signature
format selection, transitive CI runtime integrity, native compiler identity and
orphan promotion fairness. Consensus validity, historical compatibility, wire
and persistent formats were not changed; no release or deployment action
occurred.

## Ledger result

All 200 finding rows and classifications remain intact: 71 `IMPLEMENTED`, 98
`PARTIAL`, 15 `UNARMED CANDIDATE`, 5 `PROTOCOL DECISION`, 7 `BASE CHANGED`,
1 `OPEN`, 1 `REFUTED IN AUDIT` and 2 `VERIFIED POSITIVE`. This wave narrows
CR-10/CR-02, EN-08/NET-04, INF-11 and KS-09; each remains `PARTIAL`. SR-03
remains the sole open finding.

## Integrated changes

CR-10/CR-02 make the public non-consensus wallet `Keypair::verify` API try the
known enveloped/enveloped and raw/raw representations explicitly before its
retained historical mixed-format fallback. A genuine raw signature beginning
`B1 0C` passes the explicit raw route even though generic magic sniffing
misclassifies it. Consensus and indexer callers were not changed.

EN-08/NET-04 move connected-orphan promotion into a persistent FIFO worklist
and execute at most one promotion per slot-loop control turn. Breadth-first
ordering and the original caller verdict remain intact. Blocked and ready
orphan queues share one 256-entry hard cap and cross-queue deduplication; a
full ready tail drops fresh remote work locally as `Ignore`, without peer
guilt. Duties and `stop_at_slot` remain gated until the ready tail drains.

INF-11 expands exact SHA-256 integrity from the direct test commands to 14
local executables, including three transitively loaded helpers, and binds four
exact parent/load relationships. A replaced, missing, symlinked, newly
introduced or orphaned helper fails closed. System interpreters, Cargo/rustup,
packages, hosted runners and repository rulesets remain external.

KS-09 asks the locked cc-rs implementation which C compiler it actually
selects for the effective host and target, resolves a bare command through the
build path, and hashes the selected executable bytes into the private build
environment fingerprint. A missing or unreadable required compiler stops the
build. The path and command remain absent from `getbuildinfo`.

## Validation

- Outside the restricted local-socket sandbox, `bloch-pos-node` passed 549
  unit tests with 19 ignored finite/performance rehearsals. All integration
  targets passed: 126 tests passed and 6 performance tests were explicitly
  ignored.
- The complete `bloch-crypto` library suite passed 192 tests with 2 ignored,
  including the focused genuine magic-prefix keypair regression.
- Four focused orphan-promotion regressions and the full node test build check
  passed, covering sliced FIFO replay, hard-cap sharing, cross-queue dedup and
  the final duty gate.
- The selected-native-tool identity tests passed 2/2, and the focused
  `getbuildinfo` environment-fingerprint regression passed.
- The scanner-posture guard passed 74 two-direction fixtures and all required
  checked-in jobs. The test-posture guard passed 83 cases and both checked-in
  pipelines.
- Python compilation, ledger arithmetic, unambiguous conflict-marker scanning
  and `git diff --check` passed.
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
