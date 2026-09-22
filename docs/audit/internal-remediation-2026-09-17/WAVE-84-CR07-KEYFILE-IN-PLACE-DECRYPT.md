# Wave 84 CR-07: in-place encrypted-keyfile decryption

Base: `ff48c1d`; branch `fix/internal-audit-20260917`.

## Residual addressed

The HD-wallet and historical legacy-keystore loaders already reused their
Base64-decoded AES-GCM ciphertext allocation for plaintext. The distinct
`wallet::encryption::EncryptedKeyfile` v1 production loader still used
allocating `Aead::decrypt`; its v2 seed-bearing variant did the same. During a
successful unlock, the decoded ciphertext and a second full plaintext buffer
therefore coexisted.

## Change

Both `EncryptedKeyfile::decrypt` and `EncryptedKeyfile::decrypt_v2` now decode
ciphertext directly into `Zeroizing<Vec<u8>>` and authenticate/decrypt it with
AES-GCM's in-place API. The v1 path transfers that allocation into its existing
caller-owned `Vec<u8>` return value. The v2 path keeps the decrypted aggregate
under `Zeroizing` while validating and splitting the retained master-seed and
secret outputs. Authentication failure returns through `?` while the decoded
buffer is still owned by `Zeroizing`, so its drop path wipes the allocation.

Version, algorithm, salt, nonce, tag and KDF validation remain in their prior
order before credential work. The encrypted JSON schema, Base64 representation,
Argon2 parameters, AES-GCM nonce/tag sizes, v1 and v2 AAD domains, public APIs,
return types and error variants are unchanged.

This correction does not claim to avoid JSON-string or Base64-decoding
allocations. It removes the additional AES-GCM plaintext allocation during
authentication.

## Regression

`keyfile_decryption_reuses_ciphertext_allocation_at_tag_boundary` exercises the
production in-place primitive under both v1 and v2 AAD domains. It proves that:

- a valid empty plaintext represented by exactly the 16-byte GCM tag succeeds;
- a non-empty v2-shaped secret payload succeeds;
- successful decryption preserves both the allocation pointer and capacity;
- the tag is removed and plaintext bytes are unchanged; and
- a tampered tag returns `WrongPassword` while the same allocation remains
  owned by `Zeroizing<Vec<u8>>` until drop.

Existing v1/v2 round-trip, wrong-password, cross-version AAD, corrupt nonce,
short-tag and KDF-bound regressions continue to cover the unchanged public
behavior.

## Validation

- `cargo test -p bloch-crypto keyfile_decryption_reuses_ciphertext_allocation_at_tag_boundary --offline -- --nocapture`: 1 passed, 0 failed; 208 library tests filtered out.
- `cargo test -p bloch-crypto --offline` outside the sandbox because the HTTP regressions bind loopback sockets: library 207 passed, 0 failed, 2 ignored; integration tests 6 passed, 0 failed; doc tests 2 ignored (213 passed and 4 ignored total).
- `git diff --check` on the wallet source and this report: passed.

## Residual risk

CR-07 remains `PARTIAL`. JSON deserialization and Base64 decoding still
allocate before authenticated decryption. The v2 authenticated aggregate must
still be split into the independently retained master-seed and secret buffers;
the v1 API intentionally returns its caller-owned secret `Vec<u8>`. Compiler
temporaries, opaque cryptographic backend/register state and caller-created
copies remain outside this correction. CR-08's opaque `rand_chacha` state is
unchanged because the dependency exposes neither its state nor a zeroizing drop
implementation.
