# Wave 153 — CR-07 zeroize the HD decrypt return owner

Date: 2026-09-19
Comparison base: `1d6a6bf5`

## Residual addressed

The private HD-wallet decrypt helper decoded and authenticated ciphertext under
`Zeroizing<Vec<u8>>`, but removed the successful plaintext allocation from
that wrapper with `mem::take` and returned an ordinary `Vec<u8>`. Its two
production callers immediately wrapped the returned mnemonic JSON and keypair
JSON again, leaving a repository-owned success-return interval without wiping
ownership.

Wave 81 already made decryption in-place and protected validation and
authentication failures. This correction closes only the successful private
helper return boundary.

## Correction and invariants

`decrypt_with_key` now returns `Zeroizing<Vec<u8>>` directly. The authenticated
plaintext remains in the same decoded allocation and under the same wiping
owner across the helper return. The mnemonic and per-address keypair callers
receive that owner directly instead of constructing a second wrapper. There is
no clone, copy or reallocation in the ownership transfer.

Base64 decoding, nonce and authentication-tag guards and their order,
AES-256-GCM with empty AAD, authentication errors and plaintext bytes are
unchanged. No public API, wallet schema, serialization, KDF, RNG operation or
output changes. Historical v1/v2 files and current v3 files follow the same
decrypt paths as before.

## Adversarial coverage

- `hd_decrypt_return_has_exact_zeroizing_ownership_and_bytes` pins the private
  helper's exact `Result<Zeroizing<Vec<u8>>, String>` return type, checks a
  successful authenticated plaintext byte for byte, and exercises explicit
  live zeroization.
- `wallet_secret_decryption_reuses_the_ciphertext_allocation_at_tag_boundary`
  continues to prove in-place allocation reuse for empty and non-empty
  plaintext, exact tag-boundary rejection, unchanged authentication failure,
  and zeroizing ownership on the error path.
- The complete HD module covers mnemonic and keypair callers, malformed keys,
  create/save/load, and historical v1/v2 round trips.

## Validation

```text
cargo test -p bloch-crypto --offline \
  hd_decrypt_return_has_exact_zeroizing_ownership_and_bytes -- --nocapture
# 1 passed; 0 failed; 227 filtered out

cargo test -p bloch-crypto --offline \
  wallet_secret_decryption_reuses_the_ciphertext_allocation_at_tag_boundary \
  -- --nocapture
# 1 passed; 0 failed; 227 filtered out

cargo test -p bloch-crypto --offline hd_wallet::
# 30 passed; 0 failed; 198 filtered out

cargo test -p bloch-crypto --features wallet-cli --offline
# 241 passed; 0 failed; 4 ignored
```

The complete wallet-CLI suite ran outside the sandbox so its loopback HTTP
fixtures could bind. The total is 235 passing unit tests plus six passing
integration tests; two unit tests and two doctests remain intentionally
ignored.

## Residual boundary

- Base64 decoding still creates the required decoded allocation before the
  repository immediately places it under `Zeroizing`; JSON deserialization
  and escaped-string fallback allocations remain as previously documented.
- This change does not cover AES/SHA/KDF backend state, caller-owned inputs,
  allocator/compiler/register copies or aborts that skip destructors.
- No post-`Drop` memory observation is claimed. The exact return type and
  explicit live-zeroize regression are structural ownership evidence.
