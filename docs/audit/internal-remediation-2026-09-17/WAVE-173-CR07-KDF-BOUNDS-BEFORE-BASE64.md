# Wave 173 — CR-07 KDF bounds before keyfile Base64

Date: 2026-09-19
Comparison base: `3596a546`

## Reproduced residual

Both v1 and v2 `EncryptedKeyfile` decrypt paths checked the existing KDF
parameter ceilings only after decoding the salt, nonce, ciphertext and public
key Base64 fields. An untrusted keyfile that was already certain to fail its
cheap KDF policy could therefore make the decoder allocate output proportional
to its encoded payload before the established KDF refusal.

An adversarial regression first failed on the uncorrected v1 path: an
out-of-bounds `m_cost` paired with an invalid 64 KiB ciphertext encoding
returned the Base64 decoder error instead of the KDF-bounds error. This pinned
the former validation order before the production change.

## Correction

Move the existing, byte-identical `m_cost`, `t_cost` and `p_cost` ceiling
checks in both decrypt paths to immediately after version and algorithm
validation and before any Base64 decode. No ceiling, accepted parameter,
Argon2 construction, password handling, Base64 representation, AES operation,
schema, public API or valid output changes.

Malformed files that violate both policies now receive the cheaper KDF-policy
diagnostic first. Files whose KDF parameters are within policy retain the
previous Base64, fixed-length, authentication and plaintext validation order.

## Adversarial regression

`kdf_bounds_precede_payload_base64_decoding_for_both_versions` constructs real
low-cost v1 and v2 keyfiles, then combines an out-of-bounds `m_cost` with a
64 KiB invalid ciphertext sentinel. For both versions it requires the KDF
`WalletError::Parse` variant and its complete exact diagnostic, proving the
decoder was not reached regardless of the decoder crate's own error wording.

Focused validation:

- Before correction: `FAILED`, with the v1 KDF-order assertion failing.
- After correction:
  `cargo test -p bloch-crypto --offline kdf_bounds_precede_payload_base64_decoding_for_both_versions -- --nocapture`
  - `1 passed; 0 failed; 231 filtered out` in the library target.

Full relevant validation:

- `cargo test -p bloch-crypto --features wallet-cli --offline`
  - library target: `240 passed; 0 failed; 2 ignored`;
  - ACVP integration: `3 passed; 0 failed`;
  - Falcon integration: `2 passed; 0 failed`;
  - transaction integration: `1 passed; 0 failed`;
  - doc tests: `0 failed; 2 ignored`;
  - aggregate: `246 passed; 0 failed; 4 ignored`.

## Boundary and residuals

- JSON/Serde has already allocated the encoded strings before these object-
  level decrypt methods run; this change does not avoid those allocations.
- Payloads with in-policy KDF parameters retain their existing Base64 decoder
  allocations. No new ciphertext or public-key size policy is introduced.
- The regression's invalid-character sentinel proves control-flow ordering;
  it does not claim to measure heap or RSS. A valid large Base64 field on the
  former path would have allocated decoder output before reaching the same
  KDF refusal.
- Public callers can construct `EncryptedKeyfile` objects directly and remain
  responsible for bounding their own deserialization/input transport.
- Backend, allocator, compiler and register copies remain outside observable
  repository ownership. `CR-07` remains `PARTIAL`.
