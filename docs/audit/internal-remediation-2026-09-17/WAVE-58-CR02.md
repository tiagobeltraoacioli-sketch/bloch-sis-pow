# Wave 58 CR-02: canonical enveloped verification seam

Base: `0c78e38`; branch `agent/wave58-crypto`.

## Scope

Wave 57 added an opt-in canonical verifier for raw Falcon-1024 primitives.
Modern callers otherwise had to parse and split the hybrid suite themselves to
use that policy safely.

This wave adds `verify_enveloped_canonical`, an opt-in hybrid-level seam. It
requires explicit suite envelopes exactly like `verify_enveloped`, preserves
suite equality and dispatch, verifies both cryptographic legs, and selects the
canonical Falcon verifier for suite `0x0001`. Suite `0x0002` retains its
existing exact-length ML-DSA verification. The internal hybrid verifier now
accepts a private Falcon-verification function so the compatibility and
canonical policies share all parsing, ML-DSA verification and AND-combiner
logic.

The regression uses deterministically seeded local cryptographic material. A
compact enveloped hybrid signature passes both APIs. Extending only its Falcon
half with zeroes to the backend's accepted 1,280-byte representation continues
to pass `verify_enveloped` but fails `verify_enveloped_canonical`. A raw key is
also rejected by the canonical enveloped API, and a valid fixed-length
suite-`0x0002` envelope remains accepted.

No consumer was migrated. The generic verifier, compatibility enveloped
verifier and raw primitive verifier retain their policies. There is no
consensus, protocol, wire, funded-format or deployment change.

## Validation

- `cargo test -p bloch-crypto --lib crypto::kat::canonical_enveloped_verifier_rejects_padded_falcon_half`:
  1/1 passed.
- `cargo test -p bloch-crypto` with local-socket permission: 188 library tests
  passed (2 ignored), all 6 integration tests passed, and 2 doctests were
  ignored.

## Evidence boundary and residual risk

This regression proves local end-to-end policy composition over the two
currently supported enveloped suites. Its key and signatures are local seeded
fixtures, not external vectors or an independent implementation comparison.
The strict path still delegates signature math and compact framing to the
existing repository primitives.

CR-02 remains `PARTIAL`. No production or consensus consumer uses the new
entry point. A complete consumer inventory, historical-data policy,
coordinated activation for consensus-sensitive paths, mixed-version/replay
qualification, external review and deployment evidence remain outstanding.
