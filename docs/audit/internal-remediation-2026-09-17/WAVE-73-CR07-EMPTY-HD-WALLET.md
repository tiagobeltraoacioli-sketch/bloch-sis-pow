# Wave 73 CR-07: reject empty HD wallet state

Base: `42eeab0`; branch `fix/internal-audit-20260917`.

## Inventory result and scope

The CR-10/CR-02 inventory after Wave 72 found no further bounded product or
tooling migration. Remaining generic hybrid-verifier references are consensus or
history-sensitive validation, indexer observation, compatibility tests, or
deliberate final fallbacks behind explicit-format attempts.

The selected bounded CR-07 residual was HD-wallet structural validation. Wallets
created or recovered by the implementation always contain the primary derived
address at index zero. A syntactically valid but malformed wallet document with
an empty `addresses` array nevertheless passed structural validation. Once loaded,
both address derivation and key import used `unwrap_or(0)` for the missing maximum
index and silently assigned index one. That skipped the primary index and made an
invalid state look like a normal wallet mutation.

## Change

- `validate_wallet_structure` rejects an empty address list before KDF and key
  decryption.
- `new_address` and `try_import_keypair` independently reject an empty in-memory
  wallet instead of synthesizing index zero as the previous maximum.
- The failure paths do not add an address or mark an imported index.

This does not alter the wallet format. Valid current and legacy wallet documents
remain accepted; `create` and `recover` already guarantee a non-empty address
list. No consensus, wire, persistence schema, indexer, release, or deployment
state changed.

## Adversarial regressions

The focused tests cover both boundaries:

- hostile wallet metadata with an empty address vector is rejected;
- a deliberately constructed empty in-memory wallet cannot derive or import a
  key and remains unchanged after both attempts.

## Validation

- `cargo test -p bloch-crypto --lib hd_wallet::audit_wallet_boundaries::empty_wallet_state_is_refused_without_synthesizing_index_one --offline`: 1/1 passed.
- `cargo test -p bloch-crypto --lib hd_wallet::audit_wallet_boundaries --offline`: 5/5 passed.
- `cargo test -p bloch-crypto --lib --offline`: 193 passed, 0 failed, 2 ignored
  (run outside the filesystem sandbox so HTTP tests could bind loopback sockets).

## Residual risk

CR-07 remains `PARTIAL`. This closes only the empty-wallet structural ambiguity.
Imported-key authenticity, unavoidable opaque secret copies, and stronger total
resource bounds remain open and require separately scoped compatibility and API
work. CR-10/CR-02 retain the protocol/history/indexer and deliberate compatibility
fallback boundaries recorded by Wave 72.
