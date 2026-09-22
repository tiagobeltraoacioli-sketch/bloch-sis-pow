# Wave 56 integration checkpoint

Date: 2026-09-18. Branch: `fix/internal-audit-20260917`. Comparison base:
`4747cd6`. Four agents implemented and reviewed official-key ML-DSA evidence,
tighter ordinary Argon2 allocation, strict RPC Host-authority parsing and
GitLab pipeline-level scanner-guard refusal. No production crypto, consensus,
wire or persistent format changed; no release or deployment action occurred.

## Ledger result

All 200 finding rows and classifications remain intact: 71 `IMPLEMENTED`, 98
`PARTIAL`, 15 `UNARMED CANDIDATE`, 5 `PROTOCOL DECISION`, 7 `BASE CHANGED`,
1 `OPEN`, 1 `REFUTED IN AUDIT` and 2 `VERIFIED POSITIVE`. This wave narrows
CR-11, KS-11, NET-22 and INF-11; each remains `PARTIAL`. SR-03 remains the
sole open finding.

## Integrated changes

CR-11 imports a minimized, hash-pinned NIST ACVP ML-DSA-65 key-generation
fixture and proves that its official public/secret key encodings parse and
interoperate with the production empty-context signer/verifier. The evidence
is deliberately not described as a key-generation or signing KAT: the official
seed is not fed to the backend and the randomized local signature has no NIST
expected byte value.

KS-11 reduces the ordinary unauthenticated-header one-pass Argon2 allocation
ceiling from 256 MiB to 128 MiB. Production remains 64 MiB times three and the
combined ordinary ceiling remains 256 MiB-pass. Only the explicit legacy
recovery path retains the finite historical hard caps.

NET-22 parses the complete HTTP `Host` authority before comparing its name to
the allowlist. Bracketed IPv6 must close exactly and may carry only a decimal
u16 port; hostname/IPv4 authorities likewise accept only an optional decimal
u16 port. Malformed allowed-name prefixes now fail closed. `Host` remains a
browser-origin control rather than client authentication.

INF-11 refuses top-level GitLab `include:` and `workflow:` configuration. This
prevents a required-job file from moving effective configuration outside the
local proof or suppressing the entire pipeline with workflow rules while all
registered job bodies remain unchanged.

## Validation

- `bloch-pos-node` passed 520 unit tests with 19 ignored finite/performance
  rehearsals. All integration targets passed: 118 tests passed and 6
  performance tests were explicitly ignored.
- The full isolated `bloch-crypto` run passed 186 library tests and all 6
  integrations, with 2 library and 2 doctest cases ignored. The integrated
  ACVP target passed 3/3.
- The scanner-posture guard passed 30 two-direction fixtures and all 16
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
