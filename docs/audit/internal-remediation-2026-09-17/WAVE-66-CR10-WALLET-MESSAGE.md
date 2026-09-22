# Wave 66 CR-10/CR-02: explicit wallet-message verification policies

Base: `514ed42`; branch `fix/internal-audit-20260917`.

## Inventory result and scope

The remaining generic-verifier call sites divide into consensus/history-sensitive
transaction, validator, transport and indexer paths; compatibility wrappers
(`Keypair::verify` and vault recovery); examples/tests; and one low-risk current
product boundary: `postern-wallet verify-message`. The wallet command already has
its own signed-message domain and receives the public key and signature as distinct
inputs, but previously sent them directly through format autodetection.

This wave migrates exactly that product boundary. The compatible
`Keypair::verify_message` policy now tries, in order:

1. explicitly enveloped verification;
2. explicit raw legacy-hybrid verification;
3. the former generic verifier as a final fallback for historical mixed-format
   records whose original storage metadata is unavailable.

The last fallback preserves the complete previously accepted set. The explicit raw
attempt repairs the CR-10 false refusal for a genuine raw signature whose first two
bytes happen to be the envelope magic `B1 0C`.

`postern-wallet verify-message --canonical` is opt-in and routes to
`verify_enveloped_canonical`: both objects must have suite envelopes and the
signature must have canonical Falcon encoding. The command's default remains the
compatible policy.

## Genuine wallet-message fixture

A one-off optimized search over deterministic ML-DSA signing RNG seeds found a
valid signature for the exact wallet-message digest at counter 44,970. The search
is not committed or run in CI. The permanent regression reconstructs the complete
hybrid signature with the real backend from:

- hybrid key seed: 32 bytes of `0x66`;
- message: `wave-66-message`;
- digest: `signed_message_digest(message)`;
- RNG derivation domain: `bloch/wallet-message/cr10/signing-rng/v1`;
- signing RNG seed:
  `350dedd0a2e98668324887e0a2ee89384f8f4d4e4fba79224f3eba885ac2bd74`.

The enveloped form passes both policies. After removing both suite headers, the
raw signature begins `B1 0C`: generic autodetection rejects it, the compatible
wallet policy accepts it through the explicit raw API, and canonical policy rejects
the legacy raw objects.

No consensus rule, message domain, signing behavior, default verification policy,
historical record or wire format changed. No release or deployment occurred.

## Validation

- `cargo test -p bloch-crypto --features wallet-cli --lib wallet::cli::audit_cli_input_tests::canonical_message_flag_routes_genuine_magic_prefixed_fixture --offline`: 1/1 passed.
- `cargo test -p bloch-crypto --features wallet-cli --lib wallet::cli::audit_cli_input_tests --offline`: 6/6 passed.
- `cargo check -p bloch-crypto --features wallet-cli --bin postern-wallet --offline`: passed.
- `cargo test -p bloch-crypto --features wallet-cli --lib --offline`: 197 passed,
  0 failed, 2 ignored (rerun outside the filesystem sandbox so the HTTP tests
  could bind loopback sockets).

## Evidence boundary and residual risk

The deterministic fixture is genuine for the pinned backend, not an external test
vector. The compatible policy intentionally retains generic autodetection only for
mixed raw/enveloped historical records. Removing that fallback or making
`--canonical` the default requires an inventory/migration of exported message
proofs and an announced compatibility policy.

The remaining current generic consumers are either consensus/history-sensitive,
compatibility APIs without trusted format metadata, or operational tooling that
needs its own format-lifecycle analysis. CR-10 and CR-02 therefore remain
`PARTIAL`; this wave does not claim a protocol-wide migration.
