# Wave 69 CR-10/CR-02: explicit offline payout inspection

Base: `8e0ebd6`; branch `fix/internal-audit-20260917`.

## Inventory result and scope

The remaining generic signature-verifier calls are dominated by consensus,
historical replay, indexer and broad compatibility boundaries. The safest current
operational boundary is the read-only/offline `validator-payout inspect` path.

Before signature verification, this path already requires the witness public key
to have the exact suite-1 enveloped length and header, and requires its SHA3-256 to
equal the independently observed withdrawal credential. That supplies trusted
format context which generic autodetection previously ignored.

Payout inspection now applies this policy:

1. verify an enveloped signature against the validated enveloped key explicitly;
2. for a retained legacy raw signature, remove only the already validated public
   key envelope and verify both raw hybrid objects explicitly;
3. call the former generic verifier only as a deliberate final fallback, preserving
   the historical accepted set for unusual mixed payout artifacts.

The same inspection routine runs before unlocking and after signing, but no signing,
wire or consensus behavior is changed by this policy migration.

## Genuine payout-domain fixture

A one-off optimized search over deterministic ML-DSA signing RNG seeds found a
valid signature for a real payout `TransferV2::checked_signing_root(5000)` at
counter 19,830. The search utility is not committed or run in CI. The permanent
test reconstructs the payout, its fee/reservation and the complete hybrid signature
through production implementations using:

- suite-1 key seed: 32 bytes of `0x69`;
- validator index: 71; observed payout value: 2,500,000,000,000 sat;
- signing root:
  `14dd03330118a6495e0880801a40438e67a880adfa80e78b5adbf8807b5fcdb4`;
- RNG derivation domain: `bloch/validator-payout/cr10/signing-rng/v1`;
- signing RNG seed:
  `669adde213cc9d27054989bc755943b83364b48aa4b146f492421402b7b997ea`.

The enveloped signature passes both the payout policy and canonical verification.
After removing its suite header, the genuine raw signature begins `B1 0C`:
generic autodetection rejects it, the explicit raw route accepts it, and the full
read-only `inspect` routine succeeds.

No consensus/admission verifier, transaction encoding, signing root, persistence,
indexer, RPC/network behavior, release or deployment changed.

## Validation

- `cargo test -p bloch-pos-node --bin bloch-pos validator_payout::audit_signature_policy_tests::explicit_policy_accepts_genuine_magic_prefixed_raw_payout_signature --offline`: 1/1 passed.
- `cargo test -p bloch-pos-node --test validator_payout_cli --offline`: 6/6 passed.
- `cargo check -p bloch-pos-node --bin bloch-pos --offline`: passed.

## Evidence boundary and residual risk

The fixture is genuine for the pinned backend, not an external vector. Generic
autodetection remains reachable only after the expected enveloped and raw layouts
fail, preserving previously accepted exotic mixed artifacts. Removing it requires
an inventory and migration policy for retained payout files.

Consensus, historical replay and indexer consumers remain untouched. CR-10 and
CR-02 remain `PARTIAL`; this wave establishes one local operational policy and does
not claim protocol-wide format migration.
