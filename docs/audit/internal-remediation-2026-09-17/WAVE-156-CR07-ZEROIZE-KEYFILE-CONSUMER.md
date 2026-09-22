# Wave 156 — CR-07 zeroize the keyfile loader consumer

Date: 2026-09-19
Comparison base: `f4e6d45e`

## Residual addressed

The v1 `EncryptedKeyfile` decrypt path authenticated its decoded ciphertext
in-place under `Zeroizing<Vec<u8>>`, then transferred the successful secret
into the public compatibility API's ordinary `Vec<u8>` return. The repository's
only production consumer of that API, `Wallet::load_encrypted_with_file_limit`,
immediately wrapped the returned allocation again before constructing its final
zeroizing `KeyMaterial`. That internal success boundary did not need to pass
through the public caller-owned representation.

Wave 84 already removed the second AES plaintext allocation and protected
authentication failures. This correction keeps the repository-owned success
path protected while preserving the public return contract.

## Correction and invariants

`EncryptedKeyfile::decrypt_zeroizing` is a `pub(super)` path that contains the
unchanged v1 validation, KDF, AAD and in-place decrypt sequence and returns the
authenticated allocation directly as `Zeroizing<Vec<u8>>`.

The public `EncryptedKeyfile::decrypt` method retains its exact signature and
delegates to that path, transferring the allocation into the required `Vec<u8>`
only at the public compatibility boundary. The internal `Wallet` loader calls
the protected path and uses `mem::take` only while constructing the final
`KeyMaterial`. Neither transfer clones or reallocates the secret.

Validation order, error variants, Base64, schema, Argon2 parameters,
AES-256-GCM AAD, nonce/tag handling, RNG operations, public API and output
bytes are unchanged. The v2 decrypt API already returns independently retained
zeroizing secrets and is untouched.

## Adversarial coverage

- `v1_internal_decrypt_preserves_public_bytes_under_zeroizing_ownership` pins
  the internal method's exact zeroizing return type, compares secret, public
  key and network with the unchanged public API, and exercises explicit live
  zeroization.
- `keyfile_decryption_reuses_ciphertext_allocation_at_tag_boundary` continues
  to prove pointer/capacity reuse, exact tag-boundary behavior and wiping
  ownership on authentication failure.
- `current_wallet_custom_file_budget_preserves_authenticated_roundtrip`
  exercises the internal loader with the exact file-byte boundary and checks
  the final secret/public/network-compatible wallet state.

## Validation

```text
cargo test -p bloch-crypto --offline \
  v1_internal_decrypt_preserves_public_bytes_under_zeroizing_ownership \
  -- --nocapture
# 1 passed; 0 failed; 228 filtered out

cargo test -p bloch-crypto --offline \
  keyfile_decryption_reuses_ciphertext_allocation_at_tag_boundary -- --nocapture
# 1 passed; 0 failed; 228 filtered out

cargo test -p bloch-crypto --offline \
  current_wallet_custom_file_budget_preserves_authenticated_roundtrip \
  -- --nocapture
# 1 passed; 0 failed; 228 filtered out

cargo test -p bloch-crypto --features wallet-cli --offline
# 242 passed; 0 failed; 4 ignored
```

The complete wallet-CLI suite ran outside the sandbox so its loopback HTTP
fixtures could bind. The total is 236 passing unit tests plus six passing
integration tests; two unit tests and two doctests remain intentionally
ignored.

## Residual boundary

- The public v1 compatibility API intentionally still returns its caller-owned
  secret `Vec<u8>`; external callers remain responsible for its lifetime.
- JSON deserialization and Base64 decoding still allocate before authenticated
  decryption. AES/KDF backend state, allocator/compiler/register copies and
  aborts that skip destructors remain outside the claim.
- No post-`Drop` memory observation is claimed. The internal return type and
  explicit live-zeroize regression are structural ownership evidence.
