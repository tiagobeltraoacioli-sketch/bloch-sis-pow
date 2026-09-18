# Internal audit remediation, twenty-ninth wave — 2026-09-18

Base: `d206bde`; implementation commit `33d3115`; branch
`fix/internal-audit-20260917`.

## Authenticate before attacker-sized body work

TX-16 observed that gossip admission recomputed the transaction and
attestation Merkle roots and decoded the transaction body before checking the
proposer's hybrid signature. Although body size was bounded, an unauthenticated
peer could repeatedly purchase work proportional to that bound.

Admission now performs its cheap header and clock checks, resolves the
proposer identity and authenticates the fixed-size signed header before any
Merkle traversal or transaction decoding. The signature commits to the two
body roots, so only a registered proposer can make the node inspect the body
those roots name. Unknown or branch-ambiguous identities retain the existing
bounded parking behavior; they do not enter fork choice.

After authentication, admission checks both roots and decodes every
transaction. The accepted path retains that decoded vector for its
registry-growth decision instead of decoding the same bytes a second time.
The consensus transition still repeats the authoritative commitment,
signature and execution checks against the parent's committed state; this
wave changes invalid-message precedence and network cost, not the valid block
set.

## Validation

A regression combines a forged signature under a genesis identity with a
malformed body whose bytes disagree with the signed root. It requires the
signature refusal and counter to win, so restoring body work above
authentication fails the test. The complete 19-test `ingest_admission_tests`
module passes, including unknown/deposit-added identity parking, future-slot
handling, orphan bounds, replay and pruning cases.

The first test invocation inside the restricted runner failed before the test
body because its fixture could not bind an ephemeral loopback socket. The same
compiled test and then the full module passed with local socket access; this
was a harness-permission limitation, not a code failure.

TX-16 is implemented locally. This is not a benchmark or a fleet-deployment
claim. The ledger retains all 200 rows: 64 implemented, 79 partial, 43 open,
seven base-changed, four protocol decisions, one unarmed candidate, one
refuted by the original audit and one verified positive.
