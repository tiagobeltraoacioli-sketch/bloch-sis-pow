# Wave 72 CR-10/CR-02: explicit wallet Keypair verification

Base: `eef995e`; branch `fix/internal-audit-20260917`.

## Inventory result and scope

The remaining textual calls to generic hybrid verification now fall into four
groups:

1. consensus or history-sensitive validation (`HybridVerifier` and transaction
   regressions);
2. indexer observation;
3. tests that intentionally exercise the compatibility API;
4. deliberate final fallbacks behind explicit policies added in prior waves.

One non-consensus product boundary remained unmigrated:
`wallet::Keypair::verify`. It is a broad public compatibility API and has no
in-repository production caller that could provide stronger external format
metadata. Its implementation nevertheless can recognize the two matching formats
without changing its contract.

`Keypair::verify` now tries:

1. both key and signature explicitly enveloped;
2. both explicitly raw legacy hybrid;
3. the former generic autodetecting verifier as a deliberate final fallback for
   mixed raw/enveloped inputs.

Because the old verifier remains last, every previously accepted input remains
accepted. The explicit raw attempt additionally repairs the valid magic-prefix
false refusal.

## Genuine magic-prefix regression

The regression reconstructs the genuine backend fixture originally pinned in Wave
64 rather than storing opaque signature bytes:

- hybrid key seed: 32 bytes of `0x64`;
- message: `BLOCH-CR10-MAGIC-PREFIX-FIXTURE-v1`;
- deterministic signing counter: 23,156;
- RNG derivation domain: `bloch/cr10/signing-rng/v1`;
- signing RNG seed:
  `5d051b8c445a2f169a9a0104877500c39332cb493ec6de2723cb37dfbb233042`.

The enveloped signature passes `Keypair::verify` and canonical verification. After
removing both suite headers, the genuine raw signature begins `B1 0C`: generic
autodetection rejects it and the migrated public wallet API accepts it through the
explicit raw route.

No consensus verifier, wire/persistence format, indexer, signing behavior, release
or deployment changed.

## Validation

- `cargo test -p bloch-crypto --lib wallet::legacy_keystore_tests::keypair_verify_accepts_genuine_magic_prefixed_raw_signature_explicitly --offline`: 1/1 passed.
- `cargo test -p bloch-crypto --lib --offline`: 192 passed, 0 failed, 2 ignored
  (run outside the filesystem sandbox so HTTP tests could bind loopback sockets).

## Evidence boundary and residual risk

The fixture is genuine for the pinned backend, not an external vector. The final
generic fallback remains necessary because this intentionally broad API does not
receive trustworthy format metadata for mixed historical inputs.

All remaining production generic references are now either consensus/history/
indexer boundaries or deliberate compatibility fallbacks behind explicit format
attempts. CR-10 and CR-02 remain `PARTIAL` until protocol-sensitive consumers are
handled through activation/history analysis rather than local API migration.
