# Wave 67 CR-10/CR-02: explicit offline deposit-funding verification

Base: `0a8e268`; branch `fix/internal-audit-20260917`.

## Inventory result and scope

The remaining generic-verifier call sites include consensus or historical replay
paths (legacy transaction/EUVM validation and current validator admission), an
indexer that observes historical signatures, compatibility APIs without retained
format metadata, test vectors, and offline operational tools.

This wave changes exactly one low-risk boundary: the human-operated, offline
`sign-deposit-funding` example. It neither broadcasts nor applies a transaction.
Its canonical transaction fields carry the public key and signature separately,
and the documented current workflow uses suite-tagged public keys.

Both possession and funding signature checks now share an explicit compatible
policy, in this order:

1. strict enveloped verification;
2. explicit raw legacy-hybrid verification;
3. the former generic verifier as a last fallback for previously accepted mixed
   raw/enveloped artifacts.

The final fallback preserves the historical accepted set of this tool. Trying the
trusted raw layout first fixes CR-10's false refusal when a genuine raw signature
begins with the envelope magic. Current enveloped artifacts remain compatible with
canonical verification, as pinned by the regression, but this wave does not add a
new CLI mode or change a transaction format.

## Genuine deposit-domain fixture

A one-off optimized search over deterministic ML-DSA signing RNG seeds found a
valid signature for a real `FundedDeposit::possession_root` at counter 85,528. The
search utility is not committed or run in CI. The permanent test reconstructs the
full transaction root and hybrid signature through the production implementations:

- funding key seed: 32 bytes of `0x67`;
- validator key seed: 32 bytes of `0x68`;
- possession root:
  `3982ce6fabe71afda53af24bf206546f2c462d64ec4d882a273cbcfeeabf7279`;
- RNG derivation domain: `bloch/deposit-funding/cr10/signing-rng/v1`;
- signing RNG seed:
  `a5478420173088fc02f628995681944cd45bf41ac24fc5c6caf1cade222054bf`.

The enveloped signature passes both the new compatible tool policy and the strict
canonical crypto API. With both suite headers removed, its signature begins
`B1 0C`: generic autodetection rejects it, while the tool's explicit raw policy
accepts it.

No consensus rule, admission rule, signing root, canonical transaction encoding,
default CLI invocation, historical data or network behavior changed. No release or
deployment occurred. `pqcrypto-internals` is a dev-only dependency used solely to
reconstruct the deterministic adversarial signature in tests.

## Validation

- `cargo test -p bloch-pos-node --example sign-deposit-funding explicit_policy_accepts_genuine_magic_prefixed_raw_deposit_signature --offline`: 1/1 passed.
- `cargo test -p bloch-pos-node --example sign-deposit-funding --offline`: 3 passed,
  0 failed, 1 ignored opt-in CLI roundtrip.
- `cargo check -p bloch-pos-node --example sign-deposit-funding --offline`: passed.
- `DEPOSIT_FUNDING_BIN=... cargo test -p bloch-pos-node --example sign-deposit-funding --offline -- --include-ignored`:
  4/4 passed, including the real encrypted-wallet CLI roundtrip.

## Evidence boundary and residual risk

The fixture is genuine and reproducible for the pinned backend, not an external
vector. Mixed-format historical artifacts still reach generic autodetection by
design. Removing that fallback or adding a canonical-only operational mode requires
an inventory of retained partial/signed deposit files and coordination with the
human custody workflow.

Consensus/history-sensitive call sites remain untouched. CR-10 and CR-02 therefore
remain `PARTIAL`; this wave establishes a local operational boundary, not a
protocol-wide format migration.
