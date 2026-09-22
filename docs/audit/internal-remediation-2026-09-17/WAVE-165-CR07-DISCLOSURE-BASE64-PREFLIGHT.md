# Wave 165 — CR-07 disclosure Base64 preflight

## Scope

- Comparison base: `7bfe20e1`.
- Files in this correction:
  - `crates/bloch-crypto/src/wallet/disclosure.rs`
  - this report.
- Finding: `CR-07` remains `PARTIAL`.

## Reproduced residual

`DisclosureBundle::verify` decoded each caller-supplied `pubkey_b64` and
`sig_b64` string before enforcing the existing 8 KiB public-key and 16 KiB
signature decoded-size policies. A caller-constructed bundle could therefore
make the Base64 decoder allocate output proportional to an oversized encoded
field before the verifier rejected its decoded length.

This is a decoder-output allocation boundary. It does not prevent the input
`String` from already existing, and JSON or CLI deserialization allocates that
string before `verify` is called.

## Correction

- Derive private encoded limits from the existing decoded policies using the
  exact padded-standard-Base64 formula `4 * ceil(decoded_limit / 3)`.
- Check each encoded field before calling the decoder.
- Retain the decoded-length checks as authoritative. In particular, an
  unpadded-looking string can fit the encoded threshold while decoding to one
  byte beyond the policy and is still rejected by the existing post-decode
  check.
- Keep accepted disclosure schema, digest construction, signature
  verification, public API, KDF/RNG behavior and valid outputs unchanged.
  Oversized invalid fields remain `DisclosureError::Invalid`, with a more
  specific pre-decode diagnostic.

## Regression coverage

The new adversarial regression proves that:

- an encoded string exactly at each derived threshold passes the preflight;
- an over-threshold public-key field made only of invalid Base64 characters is
  rejected with the preflight diagnostic, before the decoder diagnostic;
- the same property holds for the signature field after a valid public-key
  path reaches that branch.

Focused validation:

- `cargo test -p bloch-crypto --offline oversized_base64_fields_fail_before_decode_at_exact_encoded_boundaries -- --nocapture`
  - `1 passed; 0 failed; 230 filtered out` in the library target.
- `cargo test -p bloch-crypto --offline canonical_verify_rejects_raw_and_padded_signature_encodings -- --nocapture`
  - `1 passed; 0 failed; 230 filtered out` in the library target.
- `cargo test -p bloch-crypto --offline create_verify_roundtrip_and_addresses_match_derivation -- --nocapture`
  - `1 passed; 0 failed; 230 filtered out` in the library target.

Full relevant validation:

- `cargo test -p bloch-crypto --features wallet-cli --offline`
  - library: `238 passed; 0 failed; 2 ignored`;
  - ACVP integration: `3 passed; 0 failed`;
  - Falcon integration: `2 passed; 0 failed`;
  - transaction integration: `1 passed; 0 failed`;
  - doc tests: `0 failed; 2 ignored`;
  - aggregate: `244 passed; 0 failed; 4 ignored`.

## Residual boundary

- Serde/JSON and the CLI file reader materialize the encoded fields before
  verification; this correction does not bound those earlier input buffers.
- The caller still owns the encoded strings, and the Base64 backend and
  compiler may create opaque internal copies for accepted inputs.
- The post-decode caps remain necessary and are intentionally unchanged.
- This correction does not claim complete disclosure-memory bounding or close
  `CR-07`; its scope is the avoidable decoder output allocation for fields
  already beyond the established policy.
