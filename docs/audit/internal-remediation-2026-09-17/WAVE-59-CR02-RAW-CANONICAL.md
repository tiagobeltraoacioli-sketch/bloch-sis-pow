# Wave 59 CR-02: canonical raw-hybrid verification seam

Base: `9a0dd11`; branch `fix/internal-audit-20260917`.

## Scope

Waves 57 and 58 provided canonical Falcon verification for primitive and
explicitly enveloped signatures. A format with trusted metadata declaring both
objects to be raw legacy `ML-DSA-65 || Falcon-1024` still had only the
compatibility-policy `verify_legacy_hybrid_raw` entry point.

This wave adds `verify_legacy_hybrid_raw_canonical`, an opt-in counterpart that
requires the exact raw legacy public-key shape, performs no magic-byte sniffing
or envelope fallback, verifies both hybrid legs, and selects the canonical
Falcon verifier. It therefore rejects the alternate 1,280-byte zero-padded
Falcon representation while leaving the historical raw verifier unchanged.

The regression constructs raw hybrid material directly from both upstream
primitives. Its compact signature passes both policies. Extending only the
Falcon half to the padded length continues to pass the compatibility API but
fails the canonical API. Enveloped keys, enveloped signatures and a different
message also fail the new raw-only entry point.

No consumer was migrated. There is no consensus, protocol, wire, funded-format
or deployment change.

## Validation

- `cargo test -p bloch-crypto --lib crypto::kat::canonical_raw_verifier_rejects_padded_falcon_half_without_sniffing`: 1/1 passed.
- `cargo test -p bloch-crypto --lib crypto::kat::canonical_`: 2/2 passed.

## Evidence boundary and residual risk

The new entry point is useful only where independently trusted metadata already
fixes the raw legacy layout. It deliberately does not infer format from attacker
controlled bytes and is not a retry path after another verification policy
fails. Its regression uses local upstream primitives, not an external vector or
independent implementation.

CR-02 remains `PARTIAL`. No production or consensus consumer selects a
canonical verification policy. Closure still requires a complete consumer
inventory, historical-data policy, coordinated activation for consensus paths,
mixed-version and replay qualification, independent review and deployment
evidence.
