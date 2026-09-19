# Wave 64 CR-10: genuine magic-prefixed legacy signature fixture

Base: `97ceeaf`; branch `fix/internal-audit-20260917`.

## Scope

CR-10 described a 1-in-65,536 ambiguity: a genuine raw legacy hybrid
signature can begin with the two-byte suite-envelope magic `B1 0C`. Generic
`crypto::verify` then treats the following random signature bytes as a suite
identifier instead of treating the object as raw, potentially refusing a
valid historical signature. Earlier waves added explicit raw and strict
enveloped APIs, but the repository had no genuine cryptographic fixture for
the collision.

This wave generated that fixture with the real pinned ML-DSA-65 backend. A
one-off release-mode search varied only a deterministic signing RNG seed. It
tested 1,000 candidates in about 131 ms, then found the collision at counter
23,156 in about 3.0 seconds. The search code is not committed and never runs in
CI.

The permanent regression stores only compact reproducibility inputs:

- hybrid key seed: 32 bytes of `0x64`;
- message: `BLOCH-CR10-MAGIC-PREFIX-FIXTURE-v1`;
- signing RNG derivation: SHA3-256 of
  `bloch/cr10/signing-rng/v1 || 23156u64-LE`;
- pinned derived RNG seed:
  `5d051b8c445a2f169a9a0104877500c39332cb493ec6de2723cb37dfbb233042`.

The normal test reconstructs the full hybrid signature once through
`crypto::sign`, strips only the suite headers to obtain genuine legacy raw
objects, and proves:

1. the raw signature begins with `B1 0C`;
2. `verify_legacy_hybrid_raw` verifies it cryptographically;
3. the canonical raw verifier also accepts its compact Falcon encoding;
4. generic `verify` refuses it after misclassifying the coincidental prefix;
5. the two following bytes decode to a non-live suite, demonstrating that they
   are signature material rather than trusted format metadata.

No verifier, default, consumer, consensus rule, historical byte, wire format
or deployment behavior changed. This wave adds evidence only.

## Validation

- `cargo test -p bloch-crypto --lib crypto::kat::valid_magic_prefixed_raw_signature_requires_explicit_legacy_policy --offline`: 1/1 passed.
- `cargo test -p bloch-crypto --lib crypto::kat --offline`: 18 passed and
  the pre-existing external-NIST-vector placeholder remained ignored.

## Evidence boundary and residual risk

The fixture uses repository-pinned primitives and deterministic RNG plumbing;
it is genuine for this backend and reproducible without a probabilistic CI
search. It is not an external NIST vector or independent implementation.

CR-10 remains `PARTIAL`: the fixture proves the historical ambiguity and the
explicit raw API proves the local escape hatch, but generic consensus callers
still lack trusted per-object format metadata. Changing their default requires
a complete historical-data inventory, coordinated activation,
mixed-version/replay qualification, external review and deployment evidence.
