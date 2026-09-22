# Wave 61 CR-02/CR-10: canonical selective-disclosure verification

Base: `8bf7bfc`; branch `fix/internal-audit-20260917`.

## Scope and inventory result

The active crypto-consumer inventory found `DisclosureBundle` version 1 as the
next safe modern boundary. Its wire contract documents every public key and
signature as suite-enveloped, it is an opt-in off-chain wallet artifact, and
its producer emits envelopes. Its verifier nevertheless called generic
`crypto::verify`, retaining both legacy raw fallback and Falcon's accepted
zero-padded representation.

Changing `DisclosureBundle::verify` would silently invalidate previously
distributed audit files. This wave instead adds `verify_canonical`, which
shares every version, bound, base64, ordering, address/network, digest and
per-entry check with the compatibility method, but dispatches signatures
through `verify_enveloped_canonical`. The historical `verify` method and
`watch_summary` remain unchanged.

The regression reconstructs a valid one-entry bundle signature over its exact
canonical digest. The ordinary enveloped compact encoding passes both APIs.
Stripping only the signature envelope continues to pass the compatibility API
through its generic raw fallback but fails canonical verification. Extending
only the Falcon half to its fixed padded length likewise passes compatibility
and fails canonical verification.

No CLI, watch-only consumer, consensus rule, existing bundle, signed preimage
or serialized format changed.

## Validation

- `cargo test -p bloch-crypto --lib wallet::disclosure::tests::canonical_verify_rejects_raw_and_padded_signature_encodings --offline`: 1/1 passed.
- `cargo test -p bloch-crypto --lib wallet::disclosure::tests --offline`:
  all 12 disclosure tests passed.
- Full `bloch-crypto` regression is recorded by wave integration.

## Evidence boundary and residual risk

This is a source-level inventory and a local cryptographic regression, not an
external vector, corpus of field bundles or independent implementation. The
compatibility API intentionally retains both ambiguous encodings so existing
files remain readable.

CR-02 and CR-10 remain `PARTIAL`. A product/CLI policy must explicitly select
canonical verification for newly issued bundles, while archival handling may
still need compatibility mode. Generic transaction and consensus consumers
require a historical-data policy, coordinated activation, mixed-version and
replay qualification, external review and deployment evidence.
