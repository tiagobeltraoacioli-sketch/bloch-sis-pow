# Wave 81 CR-07: in-place HD-wallet secret decryption

Wallet baseline: `eefe430`; branch `fix/internal-audit-20260917`.

## Residual addressed

HD-wallet restore decoded each Base64 ciphertext into one `Vec<u8>` and then
asked AES-GCM to allocate a second `Vec<u8>` for the authenticated plaintext.
For the mnemonic and every stored keypair, both allocations coexisted even
though the ciphertext allocation was no longer needed after authentication.

## Change

`decrypt_with_key` now wraps the decoded ciphertext in `Zeroizing<Vec<u8>>`
and uses AES-GCM's `AeadInPlace` operation. Successful authentication reuses
that allocation for plaintext and returns it to the existing zeroizing caller;
validation and authentication failures wipe the decoded buffer on drop.

The encrypted-wallet JSON schema, Base64 representation, nonce and tag sizes,
empty associated data, key derivation, public APIs and legacy ciphertext
compatibility are unchanged. Existing key/nonce/tag validation still runs
before the fixed-size nonce conversion or AEAD call.

This correction does not claim to avoid the Base64-decoded ciphertext
allocation, nor the earlier JSON string allocation: the encrypted-payload caps
still apply after JSON deserialization and before Base64/KDF/decrypt.

## Regression

The production in-place helper is exercised with both a non-empty wallet
secret and the exact AES-GCM lower boundary: an empty plaintext represented by
the 16-byte authentication tag. The test proves that the returned plaintext
keeps the decoded ciphertext's allocation address and that one byte below the
tag boundary is rejected with the existing deterministic error. A tampered-tag
case also proves the allocation remains owned by `Zeroizing<Vec<u8>>` after
the AEAD error; production `?` propagation then drops that local wrapper and
therefore invokes its wipe-on-drop implementation.

## Validation

- `cargo test -p bloch-crypto wallet_secret_decryption_reuses_the_ciphertext_allocation_at_tag_boundary -- --nocapture`: 1 passed, 0 failed.
- `cargo test -p bloch-crypto` outside the sandbox (the HTTP regressions bind loopback sockets): library 204 passed, 0 failed, 2 ignored; integration tests 6 passed, 0 failed; doc tests 2 ignored (210 passed and 4 ignored in total).
- `git diff --check` on the wallet source and this report: passed.

## Residual risk

CR-07 remains `PARTIAL`. Base64 decoding and JSON deserialization still
allocate before this in-place step; hex decoding must allocate binary key
material retained by the live wallet. Compiler temporaries, crypto-backend
state and caller-created copies remain outside this correction.

CR-08 is intentionally unchanged. `rand_chacha` 0.9 keeps `ChaCha20Rng` state
private and provides no `Zeroize` implementation, while `SeedableRng` accepts
the seed by value. Erasing that opaque state or claiming removal of the
required by-value seed without a backend fork/replacement would not be a safe,
evidence-backed local correction.
