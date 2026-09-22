# Wave 57 CR-02: opt-in canonical Falcon verification

Base: `ab06afc`; branch `agent/wave57-crypto`.

## Scope

The production Falcon-1024 backend accepts both its variable-length compact
detached signature and an alternate representation padded with zeroes to 1,280
bytes. Changing the historical verifier in place would change validation
semantics for existing consumers and may require a coordinated consensus
activation.

This wave adds `falcon::verify_canonical` as an opt-in API. It first checks the
Falcon compact coefficient framing, including the exact number of consumed
bytes, forbidden negative zeroes, coefficient bounds and zero-valued unused
bits. It then delegates the cryptographic verification to the existing
PQClean-backed verifier. The historical `falcon::verify` remains byte-for-byte
and behaviorally unchanged.

The regression proves that a locally emitted compact signature passes both
entry points, while the same signature padded with zeroes to the backend's
accepted 1,280-byte form still passes the historical verifier but fails the
canonical verifier. Truncated and tampered signatures also fail the new entry
point.

No production consumer was migrated. There is no consensus, protocol, wire,
funded-format or deployment change.

## Validation

- `cargo test -p bloch-crypto --lib crypto::falcon::tests::canonical_verifier_rejects_the_legacy_zero_padded_variant`:
  1/1 passed.
- `cargo test -p bloch-crypto` with local-socket permission: 187 library tests
  passed (2 ignored), all 6 integration tests passed, and 2 doctests were
  ignored.

## Evidence boundary and residual risk

The compact framing check is a length-only Rust mirror of PQClean Falcon-1024
`comp_decode`; signature math remains in the compiled backend. The regression
demonstrates the specific 1,280-byte zero-padding ambiguity with locally
generated material. It is not an external vector, an independent
implementation comparison or a production-consumer migration.

CR-02 remains `PARTIAL`. Consensus and other identity-sensitive consumers
still use the compatibility verifier. Closing the finding requires a complete
consumer inventory, an explicit policy for historical data, coordinated
activation where consensus is affected, mixed-version/replay qualification
and deployment evidence. This wave does not claim external review or
deployment.
