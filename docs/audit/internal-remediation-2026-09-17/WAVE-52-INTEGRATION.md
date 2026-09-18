# Wave 52 integration checkpoint

Date: 2026-09-18. Branch: `fix/internal-audit-20260917`. Comparison base:
`c8ab7c8`. Four agents implemented and cross-reviewed vault secret ownership,
keystore KDF resource policy, build provenance and RPC isolation. No consensus
gate was armed, no release binary was built or signed, and no deployment,
credential, fund, public endpoint or live node was changed.

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

This wave narrows BV-09, KS-09, KS-11, NET-01 and EN-18. Each remains
`PARTIAL`; local source hardening is not release, fleet or product-adoption
evidence. SR-03 remains the sole open finding.

## Integrated changes

BV-09 removes `Clone` from the secret-bearing `VaultKeys` aggregate and fixes
that boundary with a compile-fail doctest. Public fields, explicit byte copies,
`SecretKey: Copy`, dependency internals and process/OS memory remain outside
the destructor's guarantee. The source-breaking change has no repository
consumer, but unknown external Rust consumers must adapt.

KS-11 adds a default 256 MiB one-allocation ceiling beside the existing 1
GiB-pass combined Argon2 budget. Production remains 64 MiB × 3. An explicit
legacy recovery override retains the finite historical hard caps and therefore
must be used only with an independently authenticated file.

KS-09 adds a domain-separated build-environment fingerprint over verbose
rustc/Cargo identity, host, target, profile and selected Rust/C code-generation
variables. Exact Cargo/cc-rs/bindgen host/target forms are watched even while
absent so a later override invalidates incremental output. Values are not
directly exposed. Referenced toolchain/SDK/native contents and hermetic signed
provenance remain outside this fingerprint.

NET-01/EN-18 move four validator-registry RPC reads to the existing immutable
published `CommittedState`. The engine fallback and snapshot backend share the
same response helpers, preserving codes, order and JSON shapes. Chain/block,
mempool, transaction-status/submission and serialization work that requires
engine-owned data still crosses the bounded consensus queue.

## Independent review corrections

Build-provenance review found missing Cargo release overrides and an
incremental-stamp hole for newly introduced target-specific variables. Both
were closed by an explicit absent-variable watch set and canonical
present/absent framing. It also clarified that a public digest does not prevent
guessing low-entropy values.

Vault review found no live `VaultKeys::clone` consumer and no code blocker. It
identified stale documentation and the unrecorded downstream source break;
both were corrected. Keystore review found the default cap before Argon2
construction, override hard caps and new-sealing boundary sound. RPC review
found no response-compatibility or snapshot-consistency blocker.

## Validation

- `bloch-pos-node` passed 513 unit tests with 19 ignored rehearsals. All
  integration targets passed: 118 tests passed and 6 performance tests were
  explicitly ignored, including three-process cold start and the 80-test
  recovery fence.
- The complete RPC unit group passed 61/61 outside the socket-restricted
  sandbox; the focused build-identity group passed 7/7.
- Keystore internals passed 33/33, the at-rest CLI suite passed 5/5, and the
  focused default-memory regression passed.
- `bloch-pq-vault` passed 42/42 plus its non-Clone compile-fail doctest. The
  dependent PQ shield service still compiled in the independent review.
- Ledger arithmetic, comment/constant validation, conflict-marker scanning and
  `git diff --check` passed at integration.
- Workspace-wide `cargo fmt --check` still has the inherited formatting
  backlog and is not claimed green.

## Launch boundary

The new binary is **not ready to launch**. The canonical Linux image still
needs two independently authenticated builds and comparison; hosted CI is not
evidenced green; release and rollback artifacts are unsigned; SR-03 lacks a
fresh independently signed weak-subjectivity envelope; rollback has not been
rehearsed on a scratch systemd host; and no staged canary or fleet digest
evidence exists. These external gates remain mandatory before readiness or
production rollout.
