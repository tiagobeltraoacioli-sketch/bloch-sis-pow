# Wave 74 CR-07: authenticate newly imported HD-wallet keys

Base: `76e6cfb`; branch `fix/internal-audit-20260917`.

## Scope decision

The remaining CR-07 areas were reviewed as three separate risks:

- validating private/public/address consistency for imported keypairs;
- reducing opaque secret copies inside external cryptographic implementations;
- adding aggregate resource limits beyond the existing bounded file read.

Opaque backend state cannot be erased reliably from this crate, and a new fixed
wallet-entry ceiling could reject a valid historical backup. The bounded safe
increment is therefore admission-time authentication for newly imported keys.
It changes neither historical file loading nor the persistent representation.

## Change

`HdWallet::try_import_keypair` (and its `import_keypair` wrapper) now performs
two checks before mutating the wallet:

1. recompute the address from the supplied public key and its encoded network;
2. sign a private, domain-separated wallet-import challenge and verify the
   resulting proof with the supplied public key.

The proof is discarded immediately. Signing uses the existing wallet
compatibility path, so both modern enveloped keys and valid legacy raw hybrid
keys remain importable. Index exhaustion and the empty-wallet invariant are
still checked first, avoiding cryptographic work for structurally invalid
states.

Previously, a caller could construct a `Keypair` whose public key/address pair
was consistent but whose private key belonged to another address. Import and
save succeeded; the unusable backup was discovered only when signing later.
The new boundary rejects that state without adding an address or imported index.

No consensus, wire format, wallet schema, historical load policy, indexer,
release, or deployment state changed.

## Adversarial regression

The focused regression attempts both malformed combinations:

- a matching private/public pair with another key's address;
- a matching public/address pair with another key's private key.

Both fail with the wallet unchanged. The same test then admits one enveloped
keypair and one explicitly raw legacy hybrid keypair, pinning compatibility for
the two supported import shapes.

## Validation

- `cargo test -p bloch-crypto --lib hd_wallet::audit_wallet_boundaries::import_rejects_inconsistent_key_material_without_mutating_wallet --offline`: 1/1 passed.
- `cargo test -p bloch-crypto --lib hd_wallet::tests::loads_legacy_random_key_wallet --offline`: 1/1 passed.
- `cargo test -p bloch-crypto --lib hd_wallet::audit_wallet_boundaries --offline`: 6/6 passed.
- `cargo test -p bloch-crypto --lib --offline`: 194 passed, 0 failed, 2 ignored
  (run outside the filesystem sandbox so HTTP tests could bind loopback sockets).

## Residual risk

CR-07 remains `PARTIAL`. Historical imported records keep their established load
policy; proving private/public correspondence while loading every old record
would add nondeterministic signing work and a new failure mode to recovery. Opaque
copies inside cryptographic backends and stronger aggregate resource accounting
also remain open.
