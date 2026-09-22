# Wave 92 — CR-07 zeroize legacy keystore save temporaries by ownership

Date: 2026-09-19
Comparison base: `db508a2`

## Residual addressed

Legacy `Keypair::save_encrypted` already zeroized its structured hex payload
on drop, but two derived secret buffers used manual cleanup:

- the 32-byte Argon2id encryption key returned as an ordinary `Vec<u8>`; and
- the serialized private/public-key JSON plaintext returned as another
  ordinary `Vec<u8>`.

Both called `zeroize()` only after AES-GCM encryption succeeded. An early
`Result` return or unwind between creation and those calls did not carry a
type-level cleanup contract. A repository-wide search found exactly one caller
of the private legacy `derive_key` helper: this save path.

## Change and compatibility

The private `derive_key` helper now creates and returns
`Zeroizing<Vec<u8>>`; Argon2id writes directly into that final owner. The JSON
serialization result is likewise moved immediately into
`Zeroizing<Vec<u8>>`. AES-GCM continues borrowing the same key and plaintext
bytes. The redundant manual success-only wipes were removed.

Both buffers are now wiped on normal return, error propagation and unwind.
The public API, password policy, Argon2id parameters, salt and nonce generation,
JSON field order/bytes, AES-GCM input, ciphertext, Base64 and keystore schema
are unchanged.

## Validation

```text
cargo test -p bloch-crypto \
  legacy_save_temporaries_have_zeroizing_ownership_and_exact_json \
  --offline -- --nocapture
# 1 passed; 0 failed; 213 filtered out

cargo test -p bloch-crypto wallet::legacy_keystore_tests \
  --offline -- --nocapture
# 10 passed; 0 failed; 204 filtered out

cargo test -p bloch-crypto --offline
# library: 212 passed; 0 failed; 2 ignored
# integration: 6 passed; 0 failed
# documentation: 2 ignored
# total: 218 passed; 0 failed; 4 ignored
```

The complete suite ran outside the restricted sandbox so its HTTP tests could
bind loopback sockets. Compiler output contained only the existing workspace
profile/patch warnings.

The regression statically pins the private KDF helper's zeroizing return type,
proves the plaintext owner has drop behavior, preserves exact serialized bytes
and supports explicit zeroization while live. It does not inspect storage
after `Drop`.

## Residual boundary

CR-07 remains `PARTIAL`. This change owns only the repository's derived-key
and plaintext buffers in the legacy save path. It does not claim to erase the
caller-owned password or keypair, Argon2/AES internals or cipher key schedule,
allocator/compiler/register copies, OS/RNG state, ciphertext, public salt and
nonce, or external copies. Process aborts that skip destructors remain outside
Rust RAII guarantees.
