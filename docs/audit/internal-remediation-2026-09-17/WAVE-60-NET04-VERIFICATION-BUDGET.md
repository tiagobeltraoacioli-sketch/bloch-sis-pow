# Wave 60 NET-04 / EN-07: aggregate gossip-verification budget

Date: 2026-09-18. Base: `fc96e52`. Scope: node-local block, attestation and
transaction admission verification, two focused regressions and this evidence
note. No wire encoding, protocol identifier, consensus rule, block validity,
persisted format or deployment changed.

## Correction

The node already bounded simultaneous network backlog and memoized exact
cryptographic failures. Those controls did not bound sustained unique-input
CPU: as the consensus thread drained events, an unauthenticated sender could
keep replacing each completed item with a distinct well-shaped signature and
buy another hybrid verification indefinitely.

Network admission now shares a ceiling of 1,024 new hybrid verification calls
per 30-second wall slot across incoming blocks, attestations and ordinary
transaction admission. Exact known failures are checked before this allowance,
so cheap cached rejections neither run cryptography nor consume capacity. A new
wall slot resets the counter.

Exhaustion is represented separately from an invalid signature:

- blocks return `Verdict::Ignore`, so a forwarding peer is not scored for this
  node's local overload and sync may retry from the applied head;
- attestation policy's provisional bad-signature result is translated to
  `Ignore`, never `Reject`;
- transaction submission receives the existing retryable RPC shape with the
  next wall slot, rather than the permanent-invalid code.

The node's own proposal authentication uses the ordinary unbudgeted verifier,
and consensus execution uses its independent verifier. Lifecycle authorization
retains its separate two-per-identity and 256-total-per-slot admission budget.
The new ceiling is therefore relay/mempool shedding only and cannot change the
validity of a block.

## Regressions

`slot_budget_counts_unique_crypto_not_cached_failures_and_renews` proves with a
one-call allowance that:

- one unique failure executes the underlying verifier;
- its exact cached replay costs no call and no additional allowance;
- a distinct input in the same slot is limited before cryptography;
- the ordinary verifier remains usable for the local/non-admission path; and
- the next wall slot receives a fresh allowance.

`local_verification_exhaustion_never_becomes_a_peer_reject` proves that a
bad-signature policy result becomes `Ignore` only when local budget exhaustion
was recorded, while a genuine bad signature remains `Reject` otherwise.

Validation on this checkout:

- `cargo test -p bloch-pos-node slot_budget_counts_unique_crypto_not_cached_failures_and_renews --offline -- --nocapture`:
  1 passed in the node unit target;
- `cargo test -p bloch-pos-node local_verification_exhaustion_never_becomes_a_peer_reject --offline -- --nocapture`:
  1 passed in the node unit target;
- all integration targets selected zero tests and passed;
- `git diff --check`: passed.

The root integration agent will run the broad suite. No workspace-wide
formatter was run because the pre-existing workspace is not formatter-clean.

## Residual

NET-04 and EN-07 remain **PARTIAL**. The allowance is aggregate, not fair: an
attacker can consume it before honest messages and delay their relay/admission
until the next slot. A Sybil can still consume transport/source allowances,
and the legacy devnet transport has no authenticated peer identity or penalty
path. Up to 1,024 unique hybrid calls per slot plus the independently bounded
lifecycle calls remain available to remote input, and libp2p allocates bounded
frames before application admission. Fleet firewall and exposure policy were
not inspected or changed.
