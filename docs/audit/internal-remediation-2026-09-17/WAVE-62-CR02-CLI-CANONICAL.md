# Wave 62 CR-02/CR-10: explicit canonical disclosure policy in the wallet CLI

Base: `d30afca`; branch `fix/internal-audit-20260917`.

## Scope

Wave 61 exposed `DisclosureBundle::verify_canonical`, but no product surface
could select it. The wallet CLI's `verify-bundle` and `watch` commands always
used compatibility verification, including legacy raw-signature fallback and
Falcon's alternate padded representation.

This wave adds an explicit `--canonical` option to both commands. The flag
routes verification through `verify_canonical`; omitting it retains the
historical `verify` path so archived disclosure files remain readable. A
shared policy helper prevents the offline and watch-only commands from
drifting. The `disclose` producer also runs a canonical self-check before it
writes a newly created bundle, failing closed if an implementation regression
ever emits an encoding the strict verifier rejects.

The adversarial regression pins the product boundary rather than only the
library method. It proves the default parse result is compatibility mode and
`--canonical` selects strict mode. A fresh enveloped bundle passes both. After
only the signature envelope is removed, compatibility still accepts the raw
fallback while the canonical CLI policy returns the entry-specific signature
error.

No default changed. No consensus, wire format, signed preimage, historical
file, RPC or deployment behavior changed. No release was built or published.

## Validation

- `cargo test -p bloch-crypto --features wallet-cli --lib wallet::cli::audit_cli_input_tests::canonical_bundle_flag_is_opt_in_and_rejects_raw_signature_fallback --offline`: 1/1 passed.
- `cargo test -p bloch-crypto --features wallet-cli --lib wallet::cli::audit_cli_input_tests --offline`: all 5 CLI input tests passed.
- `cargo test -p bloch-crypto --features wallet-cli --lib wallet::disclosure::tests --offline`: all 12 disclosure tests passed.
- `cargo check -p bloch-crypto --features wallet-cli --bin postern-wallet --offline`: passed.

## Evidence boundary and residual risk

This proves local CLI argument routing and one adversarial raw-signature case.
It is not a corpus test of historical bundle files, external-vector evidence,
an independent implementation or deployment evidence. Compatibility remains
the default because changing it would be a product migration decision.

CR-02 and CR-10 remain `PARTIAL`. Product owners still need a rollout policy
for making canonical verification the default for newly exchanged bundles,
plus an explicit archival compatibility workflow. Consensus-sensitive generic
consumers still require historical-data policy, coordinated activation,
mixed-version/replay qualification, external review and deployment evidence.
