# Internal audit remediation, twenty-fifth wave — 2026-09-17

Base: `bccb2fc`; implementation commit `738bac8`; branch
`fix/internal-audit-20260917`. This is local source/test evidence, not a fleet
deployment claim.

## Arithmetic and consensus-path observability

FC-13 is an aggregate informational item. Two concrete notes are remediated in
this wave. First, the retained committee helper no longer narrows a `u64`
boundary epoch with `as usize`; a checked conversion makes an unrepresentable
index return `None`. A regression uses boundary epoch `2^32`, which would wrap
onto slice entry zero on a 32-bit target.

Second, the epoch-boundary divergence detector no longer writes to stderr from
inside `close_epoch`. Even rate-limited terminal I/O can block the consensus
fold. The path now performs only a saturating relaxed atomic update, and the
node exports that process counter as
`bloch_pos_boundary_vote_drops_total` through its existing Prometheus endpoint.
The flag-day runbook now queries the metric instead of grepping stderr.

## Validation and remaining scope

The checked-index regression, release-presence boundary guard and node metric
registry test pass. Comment/constants, banned-language and diff-integrity gates
pass. Details are in `VALIDATION-WAVE-25.txt`.

FC-13 moves from open to partial. The grouped finding still includes separate
design/compatibility notes: the seed-history fallback contract, biased
exhaustion fallback, infallible canonical-encoding length casts and invariants
that remain debug-only by construction. The ledger retains all 200 rows: 62
implemented locally, 77 partial, 47 open, seven base-changed, four protocol
decisions, one unarmed candidate, one refuted by the original audit and one
verified positive.
