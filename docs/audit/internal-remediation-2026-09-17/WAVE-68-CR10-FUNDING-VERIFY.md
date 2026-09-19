# Wave 68 CR-10/CR-02: explicit legacy-conversion verification

Base: `99287b4`; branch `fix/internal-audit-20260917`.

## Inventory result and scope

After the wallet, pool and offline deposit-funding migrations, the remaining
generic-verifier sites are mostly consensus/history/indexer paths, broad
compatibility APIs, tests, and a small number of operational utilities. This wave
changes exactly one read-only offline boundary:
`verify-funding-signature`.

The companion producer `native-funding-plan` proves the format contract. A legacy
conversion `TransferV2` stores the 3,745-byte raw hybrid public key, while its
freshly produced signature carries the suite-1 envelope. The verifier now checks
that expected mixed representation explicitly by adding the trusted suite-1 public
key envelope and calling `verify_enveloped`.

For compatibility with artifacts produced or rewritten by earlier tooling, the
policy then tries:

1. both objects explicitly enveloped;
2. both objects explicitly raw legacy hybrid;
3. the former generic verifier as a final fallback.

The final fallback preserves the previously accepted set. The explicit raw route
also fixes CR-10's false refusal for a genuine raw signature beginning with the
envelope magic.

## Genuine TransferV2 fixture

A one-off optimized search over deterministic ML-DSA signing RNG seeds found a
valid signature for a real `TransferV2::checked_signing_root(5000)` at counter
22,059. The search utility is not committed or run in CI. The permanent test
reconstructs the transaction root and complete hybrid signature through production
implementations using:

- hybrid key seed: 32 bytes of `0x68`;
- signing root:
  `6c690b661375f5a344d69bffc8a07dd982c4b918d46ff4a217bac549ca0f9ea7`;
- RNG derivation domain: `bloch/verify-funding/cr10/signing-rng/v1`;
- signing RNG seed:
  `734f85162b4137e79ac48f14791dbf61a8802295ef8c65bd87d9e68a3aa41a7e`.

The producer's expected raw-key/enveloped-signature representation passes the new
explicit policy, and the fully enveloped form passes canonical verification. After
removing the signature envelope, the genuine raw signature begins `B1 0C`:
generic autodetection rejects it and the explicit raw policy accepts it.

No consensus or admission verifier, transaction encoding, signing root, producer,
default CLI invocation, historical data, indexer, network behavior, release or
deployment changed.

## Validation

- `cargo test -p bloch-pos-node --example verify-funding-signature explicit_policy_handles_expected_mixed_and_magic_prefixed_raw_formats --offline`: 1/1 passed.
- `cargo test -p bloch-pos-node --example verify-funding-signature --offline`: 1/1 passed.
- `cargo check -p bloch-pos-node --example verify-funding-signature --offline`: passed.
- `cargo test -p bloch-pos-node --example native-funding-plan --offline`: 5
  passed, 0 failed, 1 ignored opt-in CLI roundtrip.

## Evidence boundary and residual risk

The fixture is genuine for the pinned backend, not an external vector. The final
generic fallback intentionally preserves unusual historical mixed representations
other than the producer's documented raw-key/enveloped-signature pair. Removing it
requires an inventory of retained unsigned/signed conversion files.

Consensus, historical replay and indexer consumers remain untouched. CR-10 and
CR-02 therefore remain `PARTIAL`; this is a local offline-tool policy, not a
protocol migration.
