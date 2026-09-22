# Internal audit remediation, eighth wave — 2026-09-17

Base: `3ae823b`, branch `fix/internal-audit-20260917`. This is a local source
checkpoint. It does not publish a binary, deploy a service, restart a validator,
rotate a credential or activate a consensus rule.

## Restart memory and canonical lookups

Warm cache restore now moves the fully validated canonical prefix into the engine
instead of cloning every retained envelope. Cache serialization borrows committed
state, streams the ordered eUTXO sequence and appends directly to the cache buffer.
The on-disk format, checksum and fallback rules are unchanged. Full-log loading,
engine history retention and production peak RSS remain open; see
[cache memory copies](CACHE-MEMORY-COPIES.md).

Canonical root and slot lookups use canonical membership and binary search over
strictly increasing slots. A guarded linear fallback preserves compatibility if a
future retention policy omits an envelope. Fork/reorg/gap regressions preserve the
existing answers. Remaining RPC work and response construction still execute on
the engine thread; see [canonical RPC lookups](CANONICAL-RPC-LOOKUPS.md).

## Network admission and rejection diagnostics

Count admission now reserves the same class shares as the byte budget. Transaction
floods cannot consume the attestation and block count headroom, and attestation
floods cannot consume the final block share. Per-source and aggregate regressions
cover tiny frames, release, cloned reservations and libp2p's first channel. This is
backlog admission, not strict scheduling, peer authentication or Sybil resistance.

Repeated block, attestation, transaction, sync and connection rejection diagnostics
are bounded by five static monotonic windows. Suppressed calls increment a
cumulative metric without formatting attacker-controlled details. Consensus
verdicts and counters still run. Admitted stderr writes can still block, and unique
invalid signatures still consume verification work; see
[rejection logging](REJECTION-LOGGING.md).

## Wallet, vectors, indexer and operator sources

The asynchronous wallet client refuses redirects, redacts endpoint URLs from
transport failures, correlates monotonically allocated JSON-RPC IDs and separates
legacy depth status from Genesis-4 checkpoint status. Both retained CLI callers
share a bounded, deadline-aware HTTP/1 parser that rejects ambiguous framing,
malformed chunks and reflected peer errors. It is HTTP-only and not a complete
Genesis-4 wallet adapter.

Pinned official NIST ACVP ML-DSA-65 verification samples and Falcon round-3
submission vectors now exercise the compiled backends and production wrappers.
They do not qualify key generation/signing, every architecture or certification.

The reference indexer tightens malformed record handling and log mutation checks;
its selected-chain provenance and whole-state persistence limitations remain. The
repository workflow no longer assumes a personal checkout, stale architecture or
fixed provider/model. Toolchain/Nix/operator comments and release-integrity failure
guidance reflect the current tree. Nix evaluation, workflow-host execution and
fleet inventory were unavailable locally.

## Validation and status

The corrected integrated node suite passed 581 tests with 25 ignored. Committee
passed 615 with seven ignored; crypto passed 189 with two ignored, including the
external verification fixtures. The reference indexer passed 22, retained CLI
passed two, and release-integrity selftests passed 14. The first broad node run
correctly exposed a stale libp2p test expectation after count shares changed; the
test was made policy-aware and the complete node suite then passed. Socket tests
were run with local loopback access after the sandbox refused binds.

Exact commands and limitations are recorded in `VALIDATION-WAVE-8.txt`. Workspace
format checking still reports the inherited repository-wide formatting backlog.
No JavaScript runtime, Nix evaluator, hosted CI, Linux release builder or production
fleet was available.

The ledger retains all 200 rows: 53 implemented locally, 68 partial, 66 open,
seven base-changed, four protocol decisions, one unarmed candidate and one refuted
by the original audit. Partial mitigations are not audit closure.
