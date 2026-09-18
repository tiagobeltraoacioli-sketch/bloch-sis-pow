# Wave 55 integration checkpoint

Date: 2026-09-18. Branch: `fix/internal-audit-20260917`. Comparison base:
`da2eb46`. Four agents implemented and reviewed strict modern crypto-envelope
verification, a published block-count RPC snapshot, per-source metrics
admission and aliased scanner-job refusal. No consensus gate was armed, no
release binary was built or signed, and no deployment, credential, fund,
registry or live node changed.

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

This wave narrows CR-10, EN-18, NET-21 and INF-11. All remain `PARTIAL` due
their historical, distributed, operational or parser-boundary residuals.
SR-03 is still the sole open finding.

## Integrated changes

CR-10 adds `verify_enveloped`, which requires explicit suite envelopes on
both key and signature and never falls back to legacy raw classification.
Modern `SignedAnchor` and `SignedRecoveryContextV1` verification use it. The
generic verifier and historical consensus behavior remain unchanged.

EN-18 answers `getblockcount` from one complete small JSON generation rather
than reserving the engine queue. The engine publishes that generation after a
canonical apply, an accepted reorg and a cache restore, including a no-tail
restart. The engine fallback and published path share one formatter. A racing
reader may see the preceding complete generation, never mixed fields.

NET-21 retains the metrics listener's global 16-worker ceiling and adds a
four-worker ceiling per normalized source IP. One RAII permit releases both
counts on every worker exit. Overload retains its 503 response but makes the
best-effort write nonblocking so a saturated client cannot stall the accept
loop. IP fairness is not authentication or distributed-Sybil resistance.

INF-11 refuses YAML aliases and GitLab `!reference` values inside required
scanner jobs, covering hidden `script`, `steps` and list entries while keeping
ordinary step actions and shell globs valid. Top-level/external configuration
and full YAML/shell semantics remain outside the textual guard.

## Validation

- `bloch-pos-node` passed 519 unit tests with 19 ignored finite/performance
  rehearsals. All integration targets passed: 118 tests passed and 6
  performance tests were explicitly ignored.
- `bloch-crypto` passed 186 tests with 2 ignored network-dependent cases.
  `bloch-pq-vault` passed 45/45 plus two compile-fail doctests.
- The scanner-posture guard passed 28 two-direction fixtures and all 16
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
