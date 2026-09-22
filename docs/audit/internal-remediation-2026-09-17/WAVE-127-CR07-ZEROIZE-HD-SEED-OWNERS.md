# Wave 127 — CR-07 zeroize HD seed owners

Date: 2026-09-19
Comparison base: `71a7d262`

## Residual addressed

The three HD-wallet seed consumers (`HdWallet::create`, `HdWallet::recover`
and `HdWallet::load_internal`) obtained the 64-byte BIP39 seed through
`Mnemonic::to_seed`. In create and recover, the returned array was converted
directly to an ordinary `Vec<u8>` that remained live across fallible key and
address derivation. Load protected the resulting vector, but the array
returned by `bip39` was still an ordinary repository-visible temporary during
the array-to-vector conversion.

## Change and compatibility

A private `hd_seed_owner` helper now immediately moves the `[u8; 64]` returned
by `Mnemonic::to_seed` into `Zeroizing<[u8; 64]>`, then makes the single copy
required by the existing `HdWallet.seed: Vec<u8>` representation directly
into `Zeroizing<Vec<u8>>`. All three production consumers use that helper.

Create and recover retain the protected vector across every fallible
derivation and transfer its allocation with `mem::take` only in the final
wallet construction, after the ordinary fields have been evaluated. Load
preserves its existing authenticated-validation lifetime and final transfer.

The public API, wallet schema, BIP39 passphrase/PBKDF2 behavior, KDF, RNG,
address/key derivation and serialized bytes are unchanged. The correction does
not remove the required array-to-vector copy.

## Validation

```text
cargo test -p bloch-crypto \
  hd_seed_has_exact_zeroizing_ownership_and_bip39_bytes \
  --offline -- --nocapture
# 1 passed; 0 failed; 219 filtered out

cargo test -p bloch-crypto \
  same_mnemonic_reproduces_same_addresses \
  --offline -- --nocapture
# 1 passed; 0 failed; 219 filtered out

cargo test -p bloch-crypto \
  create_save_load_roundtrip \
  --offline -- --nocapture
# 1 passed; 0 failed; 219 filtered out

cargo test -p bloch-crypto hd_wallet::tests --offline -- --nocapture
# library: 11 passed; 0 failed; 209 filtered out
# integration: 0 tests selected

cargo test -p bloch-crypto --features wallet-cli --offline
# library: 227 passed; 0 failed; 2 ignored
# wallet binary: 0 tests
# integration: 6 passed; 0 failed
# documentation: 2 ignored
# total: 233 passed; 0 failed; 4 ignored
```

The complete suite ran outside the restricted sandbox so its HTTP tests could
bind loopback sockets. Compiler output contained only the existing workspace
profile/patch warnings.

The structural regression pins both zeroizing owner types, checks the exact
official BIP39 empty-passphrase seed vector, and demonstrates explicit
zeroization while the returned vector owner is live. The behavior regressions
cover deterministic recovery and create/save/load compatibility. No test reads
storage after `Drop`.

## Residual boundary

CR-07 remains `PARTIAL`. `bip39::Mnemonic::to_seed` necessarily returns its
array by value before this repository can move it into the RAII owner. This
change does not claim to erase BIP39/PBKDF2 backend state, the mnemonic or
passphrase owners, compiler/register copies, the final wallet field before its
existing `HdWallet` drop, external storage, or process-abort paths that skip
destructors.
