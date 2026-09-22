# Wave 114 — CR-07 zeroize HD master-key output

Date: 2026-09-19
Comparison base: `5ba556c`

## Residual addressed

The private HD-wallet `derive_master_key` helper previously asked Argon2 to
fill an ordinary `Vec<u8>` and returned that owner. `load_internal` wrapped the
result in `Zeroizing` only after the helper returned. `create` and `recover`
kept the ordinary key alive while later seed and address derivation could
fail, so those early returns discarded the repository-owned KDF output without
a type-level cleanup contract.

A complete consumer search found three production callers (`create`,
`recover`, and `load_internal`) and two in-module fixture callers.

## Change and compatibility

`derive_master_key` now creates and returns `Zeroizing<Vec<u8>>`, with the
owner allocated before `Argon2::hash_password_into`. `load_internal` receives
that owner directly instead of wrapping an ordinary return value. `create` and
`recover` retain the protected owner across every later fallible operation and
transfer its allocation with `mem::take` only as the final field expression of
the completed `HdWallet` construction; the wallet's existing `Drop`
implementation clears that retained field.

The helper remains private. Its mnemonic/passphrase/password framing, V1
constant salt, V2/V3 mnemonic-bound salt, Argon2id version, memory/time/lane
parameters and 32-byte output are unchanged. Public APIs, wallet schema,
encryption-key bytes, key/address derivation and compatibility behavior are
unchanged. No clone is introduced.

## Validation

```text
cargo test -p bloch-crypto \
  master_key_kdf_output_has_zeroizing_ownership_and_stable_bytes \
  --offline -- --nocapture
# 1 passed; 0 failed; 216 filtered out

cargo test -p bloch-crypto hd_wallet::tests --offline -- --nocapture
# library: 8 passed; 0 failed; 209 filtered out
# integration: 0 tests selected

cargo check -p bloch-crypto --features wallet-cli --offline
# passed

cargo test -p bloch-crypto --features wallet-cli --offline
# library: 224 passed; 0 failed; 2 ignored
# wallet binary: 0 tests
# integration: 6 passed; 0 failed
# documentation: 2 ignored
# total: 230 passed; 0 failed; 4 ignored
```

The complete suite ran outside the restricted sandbox so its three HTTP tests
could bind loopback sockets. The preceding sandboxed attempt reached 221
library passes and 2 ignored tests; its only three failures were `EPERM` at the
socket bind. The unrestricted run passed all three.

The new regression pins the private helper's zeroizing return type, verifies
fixed V1 and V3 Argon2 known-answer vectors, and supports explicit zeroization
while the owner is live. The complete HD module covers create/save/load,
mnemonic recovery, legacy random-key loading, and genuine V1/V2
load-new-address-save-load compatibility. No test reads storage after `Drop`.

## Residual boundary

CR-07 remains `PARTIAL`. This correction covers only the repository's HD
master-key KDF output owner. It does not erase the caller's password or
passphrase, the `Mnemonic` representation, create/recover canonical mnemonic
strings, their BIP39 seed/entropy owners, salt-digest allocation, Argon2 or
other cryptographic backend state, allocator/compiler/register copies, or
external storage. Process aborts that skip destructors remain outside Rust
RAII guarantees.
