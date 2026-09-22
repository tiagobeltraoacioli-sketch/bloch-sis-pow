# Wave 71 CR-10/CR-02: explicit native-funding signature self-check

Base: `7a85a56`; branch `fix/internal-audit-20260917`.

## Inventory result and scope

The remaining generic-verifier calls are now consensus/history/indexer paths,
tests, public compatibility APIs, deliberate final fallbacks from prior waves, and
one local producer self-check in `native-funding-plan`. No additional untouched
read-only consumer has trustworthy format context without entering those excluded
areas.

This wave therefore addresses the next safe local operational residual. The
`native-funding-plan` tool is offline, has no network or broadcast support, and
verifies a signature it has just produced before writing the signed conversion.
Its format context is unambiguous:

- the legacy wallet and `TransferV2` witness carry the raw 3,745-byte hybrid key;
- `Plan::native_key` is the same key with the suite-1 envelope;
- `Keypair::sign` returns a suite-enveloped signature.

The self-check now verifies the expected enveloped key/signature pair first, then
tries the explicit raw legacy-hybrid layout, and finally retains the former generic
verification as a deliberate compatibility fallback. The emitted transaction and
default workflow are unchanged.

## Genuine native-conversion fixture

A one-off optimized search over deterministic ML-DSA signing RNG seeds found a
valid signature for an actual `native-funding-plan` signing root at counter
105,369. The search utility is not committed or run in CI. The permanent test
drives the real `plan` and `sign_checked` functions with:

- hybrid key seed: 32 bytes of `0x71`;
- inclusion epoch: 5,000;
- signing root:
  `c12158dd9805338f49702e9a92ea0c0e57522113731dcdd3391c4b9168f28e68`;
- RNG derivation domain: `bloch/native-funding/cr10/signing-rng/v1`;
- signing RNG seed:
  `64038e4870402819c277e50da7cb01cbc1705c30b5ac906c331bfba4447ac9fd`.

The actual enveloped signature written by `sign_checked` passes both the new policy
and canonical verification. After removing its suite header, the genuine raw
signature begins `B1 0C`: generic autodetection rejects it and the explicit raw
route accepts it.

No consensus/admission verifier, transaction wire, signing root, persistence,
indexer, network behavior, release or deployment changed.

## Validation

- `cargo test -p bloch-pos-node --example native-funding-plan explicit_policy_handles_native_output_and_magic_prefixed_raw_signature --offline`: 1/1 passed.
- `cargo test -p bloch-pos-node --example native-funding-plan --offline`: 6 passed,
  0 failed, 1 ignored opt-in CLI integration.
- `cargo check -p bloch-pos-node --example native-funding-plan --offline`: passed.
- `NATIVE_FUNDING_BIN=... cargo test -p bloch-pos-node --example native-funding-plan real_cli_prepares_signs_and_refuses_changed_intent --offline -- --ignored`:
  1/1 passed against the separately built executable.

## Evidence boundary and residual risk

The fixture is genuine for the pinned backend, not an external vector. The generic
fallback remains last to preserve any previously accepted mixed artifact passed to
the local policy. The normal producer path is now fully explicit.

The residual generic calls outside deliberate fallbacks are consensus,
history-sensitive or indexer boundaries and remain untouched. CR-10 and CR-02 stay
`PARTIAL`; removing those calls requires protocol/history analysis rather than
another local tooling migration.
