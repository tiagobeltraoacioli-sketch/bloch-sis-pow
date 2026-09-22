# Wave 131 — CR-07 zeroize wallet secret owners

Date: 2026-09-19
Comparison base: `dec64340`

## Residual addressed

The two constructors of the current single-key `Wallet` received an owned
secret-key `Vec<u8>` from an existing public compatibility API and kept that
allocation under ordinary ownership until final `KeyMaterial` construction:

- `Wallet::from_seed_versioned`, after `generate_keypair_from_seed`; and
- `Wallet::load_encrypted_with_file_limit`, after
  `EncryptedKeyfile::decrypt`.

`KeyMaterial` already has `ZeroizeOnDrop`, but that final owner did not cover
the repository-controlled interval between either API return and the wallet
construction, including unwind during address derivation.

## Change and compatibility

A private `wallet_secret_owner` helper now immediately moves each returned
`Vec<u8>` into `Zeroizing<Vec<u8>>`, without cloning or reallocating it. Both
constructors retain that owner until all address fields are ready and transfer
the same allocation with `mem::take` only in the final `KeyMaterial`
construction. The final wallet retains its existing `ZeroizeOnDrop` behavior.

The public key-generation and decryption APIs, wallet/keyfile schema, KDF, RNG,
key and address bytes, serialization and failure behavior are unchanged.

## Validation

```text
cargo test -p bloch-crypto \
  wallet_secret_owner_preserves_allocation_and_wipes_while_live \
  --offline -- --nocapture
# 1 passed; 0 failed; 220 filtered out

cargo test -p bloch-crypto from_seed_is_deterministic \
  --offline -- --nocapture
# 1 passed; 0 failed; 220 filtered out

cargo test -p bloch-crypto \
  current_wallet_custom_file_budget_preserves_authenticated_roundtrip \
  --offline -- --nocapture
# 1 passed; 0 failed; 220 filtered out

cargo test -p bloch-crypto \
  wallet_master_seed_consumer_uses_exact_zeroizing_array \
  --offline -- --nocapture
# 1 passed; 0 failed; 220 filtered out

cargo test -p bloch-crypto --features wallet-cli --offline
# library: 228 passed; 0 failed; 2 ignored
# wallet binary: 0 tests
# integration: 6 passed; 0 failed
# documentation: 2 ignored
# total: 234 passed; 0 failed; 4 ignored
```

The complete suite ran outside the restricted sandbox so its HTTP tests could
bind loopback sockets. Compiler output contained only the existing workspace
profile/patch warnings.

The ownership regression pins the exact `Zeroizing<Vec<u8>>` return type and
proves that moving into the helper preserves the allocation pointer, capacity
and bytes. It also demonstrates zeroization while the owner is live; it does
not inspect storage after `Drop`. The behavior regressions cover deterministic
derivation, key-byte parity and authenticated encrypted round-trip.

## Residual boundary

CR-07 remains `PARTIAL`. Both public compatibility APIs necessarily return
their secret-key `Vec<u8>` before these repository callers can move it into the
RAII owner. External callers remain responsible for their returned owners.
This change does not claim to erase cryptographic/cipher backend state,
allocator/compiler/register copies, caller input, external storage, or process
aborts that skip destructors.
