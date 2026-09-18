# Wave 57 integration checkpoint

Date: 2026-09-18. Branch: `fix/internal-audit-20260917`. Comparison base:
`ab06afc`. Four agents implemented and reviewed opt-in Falcon canonicality,
production-bound ordinary Argon2 work, panic-safe RPC admission and pinned
GitHub security-workflow triggers. No existing consensus verifier, wire or
persistent format changed; no release or deployment action occurred.

## Ledger result

All 200 finding rows and classifications remain intact: 71 `IMPLEMENTED`, 98
`PARTIAL`, 15 `UNARMED CANDIDATE`, 5 `PROTOCOL DECISION`, 7 `BASE CHANGED`,
1 `OPEN`, 1 `REFUTED IN AUDIT` and 2 `VERIFIED POSITIVE`. This wave narrows
CR-02, KS-11, NET-22 and INF-11; each remains `PARTIAL`. SR-03 remains the
sole open finding.

## Integrated changes

CR-02 adds opt-in `falcon::verify_canonical`. It mirrors PQClean's compact
coefficient framing, requires exact input consumption, then delegates the
signature mathematics to the existing backend. A locally emitted compact
signature passes; its legacy 1280-byte zero-padded equivalent still passes the
historical verifier but fails the strict API. No consumer or consensus path
was migrated.

KS-11 reduces ordinary combined Argon2 work from 256 to 192 MiB-pass, exactly
the shipped 64 MiB times three production profile. The ordinary one-allocation
ceiling remains 128 MiB. More expensive valid legacy/custom parameters require
the explicit finite recovery opt-in.

NET-22 replaces separate RPC per-IP and global worker accounting with one RAII
permit held through the entire worker lifetime. Normal return, early return and
unwind release both the normalized-IP charge and the global 64-worker charge.
The existing 8-per-IP and 64-global policy is unchanged.

INF-11 requires the GitHub security workflow to retain explicit mapping-form
`push:` and `pull_request:` triggers and rejects privileged
`pull_request_target:`. Required job bodies can therefore no longer remain
green in the guard after ordinary PR execution is silently removed.

## Validation

- `bloch-pos-node` passed 521 unit tests with 19 ignored finite/performance
  rehearsals. All integration targets passed: 118 tests passed and 6
  performance tests were explicitly ignored.
- `bloch-crypto` passed 187 library tests and all 6 integration tests, with 2
  library and 2 doctest cases ignored.
- The scanner-posture guard passed 32 two-direction fixtures and all 16
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
