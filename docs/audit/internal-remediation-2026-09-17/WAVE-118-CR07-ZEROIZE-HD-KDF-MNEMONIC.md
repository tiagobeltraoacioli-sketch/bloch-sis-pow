# Wave 118 — CR-07 zeroize HD KDF mnemonic copies

Date: 2026-09-19
Comparison base: `d49136e`

## Residual addressed

The HD-wallet `create` and `recover` paths previously called
`derive_master_key(&mnemonic.to_string(), ...)`. Each call rendered the full
canonical recovery phrase into a repository-owned `String`, borrowed it for
Argon2, and then discarded that ordinary owner without a type-level cleanup
contract. The load path already wrapped the same canonical representation in
`Zeroizing<String>` because it also needs the bytes for its authenticated
mnemonic comparison.

A complete production KDF-consumer search found these three paths. The save
path is separate: it moves its rendered mnemonic directly into
`MnemonicPayload`, whose derived `ZeroizeOnDrop` implementation clears that
owner.

## Change and compatibility

A private `canonical_mnemonic_for_kdf` helper now returns
`Zeroizing<String>` and serves create, recover and load. Create and recover
explicitly drop the protected canonical phrase immediately after master-key
derivation, before BIP39 seed and address work. Load preserves its existing
longer lifetime through the authenticated plaintext comparison.

The helper renders the same parsed `bip39::Mnemonic` with the same canonical
formatter. Master-key framing, salts, Argon2 parameters and bytes are
unchanged. Public APIs, wallet schema, RNG flow, encryption and derived
keys/addresses are unchanged. The save path is untouched and no clone is
introduced.

## Validation

```text
cargo test -p bloch-crypto \
  canonical_kdf_mnemonic_has_exact_zeroizing_ownership \
  --offline -- --nocapture
# 1 passed; 0 failed; 217 filtered out

cargo test -p bloch-crypto \
  master_key_kdf_output_has_zeroizing_ownership_and_stable_bytes \
  --offline -- --nocapture
# 1 passed; 0 failed; 217 filtered out

cargo test -p bloch-crypto hd_wallet::tests --offline -- --nocapture
# library: 9 passed; 0 failed; 209 filtered out
# integration: 0 tests selected

cargo test -p bloch-crypto --features wallet-cli --offline
# library: 225 passed; 0 failed; 2 ignored
# wallet binary: 0 tests
# integration: 6 passed; 0 failed
# documentation: 2 ignored
# total: 231 passed; 0 failed; 4 ignored
```

The complete suite ran outside the restricted sandbox so its HTTP tests could
bind loopback sockets. Compiler output contained only the existing workspace
profile/patch warnings.

The new regression pins the helper's exact `Zeroizing<String>` return type,
the canonical 24-word BIP39 rendering for fixed entropy, and explicit
zeroization while the owner is live. The existing V1/V3 master-key KAT pins
the exact downstream KDF bytes. The complete HD module covers create/load,
mnemonic recovery and legacy V1/V2 compatibility. No test reads storage after
`Drop`.

## Residual boundary

CR-07 remains `PARTIAL`. This correction covers only the canonical mnemonic
copies owned by the three HD master-key consumers. It does not erase the
caller-owned mnemonic/password/passphrase, the parsed `Mnemonic` backend
representation, HD create entropy, create/recover BIP39 seed owners, Argon2 or
other backend state, allocator/compiler/register copies, or external storage.
Process aborts that skip destructors remain outside Rust RAII guarantees.
