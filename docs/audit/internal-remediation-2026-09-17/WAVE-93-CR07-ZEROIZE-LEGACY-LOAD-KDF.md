# Wave 93 — CR-07 zeroize the legacy load KDF buffer by ownership

Date: 2026-09-19
Comparison base: `edf1e8d`

## Residual addressed

The legacy encrypted-keystore loader bounded and validated the untrusted KDF
parameters before starting Argon2id, then wrapped the successfully returned
derived key in `Zeroizing`. However, the private `derive_key_with_params`
helper itself allocated the 32-byte Argon2 output as an ordinary `Vec<u8>`.
An Argon2 error or unwind after that allocation but before return therefore did
not carry a type-level cleanup contract. A repository search found exactly one
caller of this private helper: `Keypair::load_encrypted_with_file_limit`.

## Change and compatibility

`derive_key_with_params` now creates its output directly as a
`Zeroizing<Vec<u8>>`, Argon2id writes into that final owner, and the helper
returns the owner without an intermediate clone. The sole caller receives it
directly, borrows the same bytes for AES-GCM decryption, and drops the owner
immediately after decryption succeeds. Error propagation from decryption and
unwinds also retain RAII cleanup.

The validation order, KDF bounds, Argon2id algorithm/version/parameters,
password and salt bytes, 32-byte output, AES-GCM inputs, JSON parsing, public
API, ciphertext and keystore schema are unchanged.

## Validation

```text
cargo test -p bloch-crypto \
  legacy_load_kdf_returns_exact_zeroizing_owner \
  --offline -- --nocapture
# 1 passed; 0 failed; 214 filtered out

cargo test -p bloch-crypto wallet::legacy_keystore_tests \
  --offline -- --nocapture
# 11 passed; 0 failed; 204 filtered out

cargo test -p bloch-crypto --offline
# library: 213 passed; 0 failed; 2 ignored
# integration: 6 passed; 0 failed
# documentation: 2 ignored
# total: 219 passed; 0 failed; 4 ignored
```

The complete suite ran outside the restricted sandbox so its HTTP tests could
bind loopback sockets. Compiler output contained only the existing workspace
profile/patch warnings.

The focused regression statically pins the private helper's zeroizing return
type, compares its output with an independently invoked Argon2id derivation
using the exact same parameters and input bytes, and supports explicit
zeroization while the owner is live. It does not inspect storage after `Drop`.

## Residual boundary

CR-07 remains `PARTIAL`. This change owns only the repository's derived-key
buffer in the legacy load path. It does not claim to erase the caller-owned
password, Argon2 or AES internals and cipher key schedule, decrypted plaintext
(covered separately by its existing zeroizing owner), allocator/compiler/
register copies, ciphertext, public salt and nonce, or external copies.
Process aborts that skip destructors remain outside Rust RAII guarantees.
