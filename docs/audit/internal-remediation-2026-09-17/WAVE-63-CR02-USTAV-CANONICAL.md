# Wave 63 CR-02/CR-10: explicit Ustav verification policies

Base: `cef4b8e`; branch `fix/internal-audit-20260917`.

## Scope and inventory result

The next active generic-verifier consumer was the `bloch-ustav` reference
transition host. Before signature verification it already required both the
public key and signature to carry explicit suite envelopes, admitted only
suite `0x0001`, checked exact public-key shape and validated Falcon public-key
coefficients. Its final call nevertheless used generic `crypto::verify`, whose
legacy raw fallback was unreachable only because of the preceding checks.

This wave makes that invariant explicit. `BlochVerifier` now dispatches through
`verify_enveloped`; this preserves its accepted set and padded-Falcon
compatibility while removing reliance on the generic format guess. A new
`CanonicalBlochVerifier` is an opt-in policy with identical message-length,
suite, size and public-key checks, but dispatches through
`verify_enveloped_canonical`.

The adversarial regression creates a real hybrid signature that fits the
backend's fixed padded representation. Compact encoding passes both policies;
the same mathematical signature extended with zeroes still passes
`BlochVerifier` but fails `CanonicalBlochVerifier`. Removing the signature
envelope fails both, proving the compatibility verifier has no raw fallback at
this boundary.

`bloch-ustav` is explicitly not node- or consensus-wired. Existing examples
and callers retain `BlochVerifier`; no default, ledger format, signed message,
wire encoding, historical data, consensus rule or deployment changed.

## Validation

- `cargo test -p bloch-ustav --test crypto_kernel canonical_verifier_rejects_padded_falcon_without_raw_fallback --offline`: 1/1 passed.
- `cargo test -p bloch-ustav --offline`: all 5 crypto-kernel tests and the
  chameleon integration test passed; the library and doctest targets contain
  no tests.

## Evidence boundary and residual risk

The fixture uses the repository's real ML-DSA/Falcon backend and demonstrates
the alternate Falcon representation end to end. It is locally generated, not
an external vector or independent implementation. It does not provide a
genuine valid legacy raw signature whose first bytes collide with envelope
magic; that rare historical fixture remains unavailable.

CR-02 and CR-10 remain `PARTIAL`. Ustav users must explicitly choose the
canonical verifier, and making it the default would be a product/protocol
decision requiring compatibility and replay qualification. Generic historical
and consensus consumers still need a data policy, coordinated activation,
external review and deployment evidence.
