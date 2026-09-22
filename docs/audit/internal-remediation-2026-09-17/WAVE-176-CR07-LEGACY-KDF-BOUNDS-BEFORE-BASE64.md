# Wave 176 — CR-07 legacy KDF bounds before Base64

Date: 2026-09-19
Comparison base: `7d3efbde`

## Reproduced residual

Wave 173 moved the v1/v2 `EncryptedKeyfile` KDF-policy checks ahead of their
Base64 decoders. The separate legacy `Keypair` loader still decoded its salt,
nonce and ciphertext before `derive_key_with_params` rejected an excessive
Argon2 cost or a non-32-byte output policy. A file certain to fail that cheap
policy could therefore make the decoder allocate output proportional to its
encoded ciphertext first.

The adversarial regression combines each invalid KDF shape with a 64 KiB
invalid Base64 ciphertext. Before this correction the legacy loader returns a
decoder error; the required exact KDF diagnostic proves the cheaper policy was
not yet consulted.

## Correction

Extract the existing legacy `KdfParams` checks into a private validator and
call it immediately after the keystore version check, before decoding any
Base64 field. `derive_key_with_params` calls the same validator again so future
non-file callers retain defense in depth.

The memory, time and parallelism ceilings, required 32-byte output, diagnostic
text, Argon2 parameters, AES operation, password handling, schema, public API
and valid serialized bytes are unchanged. Only error precedence changes for a
file that violates both the KDF policy and a later encoding policy.

## Regression coverage

`legacy_loader_checks_every_kdf_bound_before_base64` covers, independently:

- `memory_cost == MAX_M_COST_KIB + 1`;
- `time_cost == MAX_T_COST + 1`;
- `parallelism == MAX_P_COST + 1`;
- `output_len == 31`.

Every case must return the complete pre-existing KDF diagnostic instead of the
large sentinel's Base64 error. The same test then constructs an authentic
legacy keystore with a valid inexpensive Argon2 parameter set and requires an
exact private key, public key and address roundtrip. The operational maximum
memory/time ceilings are deliberately not executed as a test workload; their
boundary comparisons are direct, while a 1 GiB/16-pass KDF would add resource
cost without strengthening the ordering proof.

Focused validation:

- `cargo test -p bloch-crypto --features wallet-cli --offline legacy_loader_checks_every_kdf_bound_before_base64 -- --nocapture`
  - library target: `1 passed; 0 failed; 242 filtered out`;
  - remaining targets: `0 failed`.

Full relevant validation:

- `cargo test -p bloch-crypto --features wallet-cli --offline`
  - library: `241 passed; 0 failed; 2 ignored`;
  - integration targets: `6 passed; 0 failed`;
  - doc tests: passed.

The complete suite ran outside the restricted sandbox because three HTTP RPC
tests bind localhost sockets.

## Boundaries and residuals

- The bounded file read and Serde parsing have already allocated the encoded
  JSON strings before this object-level validation. This change prevents only
  subsequent Base64 decoder-output allocation when KDF policy already refuses
  the file.
- In-policy files retain their existing Base64 allocations and validation
  order. No new ciphertext, public-key or JSON size policy is introduced.
- The regression proves control-flow order, not heap or RSS measurements.
- The public compatibility types, backend/allocator/compiler/register copies
  and caller-owned inputs remain unchanged. `CR-07` remains `PARTIAL`.
