# Wave 60 CR-02: canonical verification at versioned vault boundaries

Base: `fc96e52`; branch `fix/internal-audit-20260917`.

## Scope

The repository inventory found two modern domain boundaries whose formats
already require explicit suite envelopes but whose public verification APIs
exposed only the compatibility policy:

- `SignedAnchor` / Bitcoin anchor verification;
- `SignedRecoveryContextV1` verification and checked restore.

Changing their existing methods in place could reject a previously accepted
artifact whose compact Falcon half was transformed into PQClean's valid
zero-padded representation. This wave therefore adds opt-in canonical entry
points while preserving all existing methods:

- `verify_anchor_canonical` and `verify_bitcoin_anchor_canonical`;
- `SignedRecoveryContextV1::verify_canonical` and
  `verify_and_restore_canonical`.

Each entry point retains the boundary's version, independently trusted key,
domain, address/network and funded-context checks, but dispatches signature
verification through `verify_enveloped_canonical`. There is no raw/enveloped
guessing. Shared private helpers keep the compatibility and canonical paths on
the same identity and message checks.

Regressions prove that locally emitted compact signatures pass both policies.
Padding only the Falcon half to the supported maximum continues to pass each
historical compatibility method but fails the new canonical method. Canonical
checked restore refuses the padded recovery record before releasing a secret.

No existing consumer was migrated. No serialized bytes, signed preimage,
consensus rule, funded format or deployment behavior changed.

## Validation

- `cargo test -p bloch-pq-vault canonical_anchor_policy_rejects_padded_falcon_encoding --offline`: 1/1 passed.
- `cargo test -p bloch-pq-vault canonical_signed_context_rejects_padded_falcon_encoding --offline`: 1/1 passed.
- `cargo test -p bloch-pq-vault --offline`: all 47 unit tests and 2
  compile-fail doctests passed.

## Evidence boundary and residual risk

The inventory was source-level and the new regressions use local cryptographic
material. They are not external vectors, production artifacts or independent
implementation evidence. Existing compatibility methods intentionally still
accept a padded signature so historical data is not silently invalidated.

CR-02 remains `PARTIAL`. Production callers must explicitly select the
canonical policy, and consensus-sensitive generic verification still requires
a historical-data policy, coordinated activation, mixed-version/replay
qualification, external review and deployment evidence. CR-10's generic
legacy raw magic ambiguity also remains unchanged.
