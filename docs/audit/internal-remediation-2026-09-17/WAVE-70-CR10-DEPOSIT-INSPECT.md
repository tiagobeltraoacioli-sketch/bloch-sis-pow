# Wave 70 CR-10/CR-02: explicit offline deposit inspection

Base: `e3fb033`; branch `fix/internal-audit-20260917`.

## Inventory result and scope

Most remaining generic-verifier references are consensus, replay, indexer, tests,
or deliberate compatibility fallbacks introduced in prior waves. The next safe
operational boundary is the read-only/offline `validator-deposit inspect` command.
It previously displayed whether signatures were present without authenticating
them, while the signing path separately used generic autodetection before opening
a keystore.

`FundedDeposit::validate_shape` and its documented wire contract require both
public keys to have the exact suite-1 envelope. That supplies trusted format
context. Inspection now authenticates each non-empty funding or possession
signature using this order:

1. explicit enveloped verification;
2. explicit raw legacy-hybrid verification after removing only the validated
   suite-1 public-key header;
3. the former generic verifier as a deliberate final fallback for previously
   retained unusual mixed artifacts.

Unsigned drafts remain inspectable. A present invalid signature now makes the
read-only command fail instead of merely printing `present: true`. The same
inspection runs before any signing keystore is opened, replacing the duplicated
generic-only check.

## Genuine deposit-domain fixture

The regression reuses the genuine backend fixture first pinned for this exact
`FundedDeposit::possession_root` in Wave 67. It is reconstructed, not stored as an
opaque signature:

- funding key seed: 32 bytes of `0x67`;
- validator key seed: 32 bytes of `0x68`;
- possession root:
  `3982ce6fabe71afda53af24bf206546f2c462d64ec4d882a273cbcfeeabf7279`;
- deterministic signing counter: 85,528;
- RNG derivation domain: `bloch/deposit-funding/cr10/signing-rng/v1`;
- signing RNG seed:
  `a5478420173088fc02f628995681944cd45bf41ac24fc5c6caf1cade222054bf`.

The enveloped signature passes canonical verification. After removing its suite
header, the genuine raw signature begins `B1 0C`: generic autodetection with the
enveloped transaction key rejects it, explicit raw verification accepts it, and
the complete read-only inspection succeeds. Mutating the signature is refused.

This compatibility policy does not alter the consensus rule that a completed
admission requires enveloped signatures. No consensus/admission verifier, wire,
root, persistence, indexer, network behavior, release or deployment changed.

## Validation

- `cargo test -p bloch-pos-node --bin bloch-pos validator_deposit::audit_signature_policy_tests::inspect_accepts_genuine_magic_prefixed_raw_deposit_authorization --offline`: 1/1 passed.
- `cargo test -p bloch-pos-node --test validator_deposit_cli --offline`: 1/1 passed.
- `cargo check -p bloch-pos-node --bin bloch-pos --offline`: passed.

## Evidence boundary and residual risk

The deterministic fixture is genuine for the pinned backend, not an external
vector. Generic autodetection remains only after the two known layouts fail so the
offline tool does not silently narrow its former accepted set. Removing that
fallback requires an inventory and migration policy for retained partial deposit
files.

Consensus, historical replay and indexer consumers remain untouched. CR-10 and
CR-02 remain `PARTIAL`; this is one local inspection policy, not a protocol-wide
format migration.
