# Wave 122 — CR-07 zeroize HD generation entropy

Date: 2026-09-19
Comparison base: `035239b`

## Residual addressed

`HdWallet::create` filled a repository-owned `[u8; 32]` with the OS RNG and
borrowed it to `bip39::Mnemonic::from_entropy`. The array then remained an
ordinary stack owner until the function returned. It had no explicit cleanup
contract despite containing the complete 256 bits from which the new HD
wallet's 24-word mnemonic is derived.

Wave 90 addressed the separate `wallet::SeedPhrase::generate` producer. A
consumer search confirms this HD-wallet path is the remaining production
`Mnemonic::from_entropy` call with freshly generated entropy; other calls in
the module use constant test fixtures.

## Change and compatibility

A private `fresh_hd_entropy` helper now creates
`Zeroizing<[u8; 32]>` and lets the same `rand::rng().fill_bytes` call fill that
final owner in place. `HdWallet::create` borrows the exact slice for
`Mnemonic::from_entropy` and explicitly drops the entropy immediately after
successful mnemonic construction, before master-key derivation.

The public API, RNG source and call order, 256-bit entropy length, BIP39
English mnemonic/checksum behavior, KDF, wallet schema and downstream key
bytes are unchanged. No entropy clone is introduced.

## Validation

```text
cargo test -p bloch-crypto \
  hd_entropy_has_exact_zeroizing_ownership \
  --offline -- --nocapture
# 1 passed; 0 failed; 218 filtered out

cargo test -p bloch-crypto create_save_load_roundtrip \
  --offline -- --nocapture
# 1 passed; 0 failed; 218 filtered out

cargo test -p bloch-crypto hd_wallet::tests --offline -- --nocapture
# library: 10 passed; 0 failed; 209 filtered out
# integration: 0 tests selected

cargo test -p bloch-crypto --features wallet-cli --offline
# library: 226 passed; 0 failed; 2 ignored
# wallet binary: 0 tests
# integration: 6 passed; 0 failed
# documentation: 2 ignored
# total: 232 passed; 0 failed; 4 ignored
```

The complete suite ran outside the restricted sandbox so its HTTP tests could
bind loopback sockets. Compiler output contained only the existing workspace
profile/patch warnings.

The structural regression pins the helper's exact zeroizing array type and
length and supports explicit zeroization while the owner is live. It does not
assert any particular random value. The create/save/load regression exercises
the production RNG-to-BIP39 path, and the full HD module covers recovery and
legacy compatibility. No test reads storage after `Drop`.

## Residual boundary

CR-07 remains `PARTIAL`. This correction covers only the HD create entropy
array owned by this repository. It does not erase OS/RNG internals, the
`bip39::Mnemonic` backend representation, the later mnemonic/seed/key owners,
allocator/compiler/register copies, or external storage. Process aborts that
skip destructors remain outside Rust RAII guarantees.
