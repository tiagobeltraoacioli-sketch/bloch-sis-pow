# Wave 181 — CR-07 fixed-field Base64 preflight

Date: 2026-09-19
Comparison base: `185f57e6`

## Reproduced residual

The current v1/v2 keyfile decryptors decoded attacker-controlled salt and
nonce strings before enforcing their existing fixed decoded sizes. The legacy
`Keypair` loader likewise decoded its nonce before enforcing the existing
12-byte requirement. An oversized encoded field could therefore allocate
decoder output even though its shape was already certain to fail.

`base64::STANDARD` requires canonical padding and trailing bits, so the fixed
decoded sizes have one accepted encoded length: a 16-byte v1/v2 salt is 24
Base64 bytes, and every 12-byte nonce is 16 Base64 bytes.

The legacy salt is intentionally excluded. Although legacy save produces a
32-byte salt, legacy load historically accepts other Argon2-valid salt lengths;
requiring the save-produced 44-byte encoding would be a compatibility change,
not a preflight of an existing loader invariant.

## Correction

After the existing version, algorithm and KDF-policy checks, but before the
first Base64 decode:

- v1 and v2 require exactly 24 encoded bytes for salt and 16 for nonce;
- the legacy loader requires exactly 16 encoded bytes for nonce only.

The existing decoded salt/nonce length checks remain in place and authoritative.
Exact-length strings retain the former decoder, decoded-length, KDF, AES and
authentication order. No ciphertext or public-key cap was added, and no
schema, wire bytes, KDF parameters, RNG use, accepted valid keyfile or public
API changed.

## Adversarial coverage

`fixed_base64_lengths_precede_decode_for_both_keyfile_versions` covers both
fields in both current schema versions. Authentic exact-length v1 and v2 files
round-trip, exact-length invalid-character sentinels reach the Base64 decoder,
and one-byte-over sentinels receive the exact preflight diagnostic.

`legacy_nonce_base64_length_precedes_decode_without_restricting_salt` performs
the same exact/one-over nonce checks through the file loader. Its authentic
roundtrip deliberately uses an 8-byte Argon2-valid salt, pinning that no new
legacy salt policy was introduced.

Focused validation:

- `cargo test -p bloch-crypto --features wallet-cli --offline fixed_base64_lengths_precede_decode_for_both_keyfile_versions -- --nocapture`
  - library target: `1 passed; 0 failed; 244 filtered out`;
  - remaining targets: `0 failed`.
- `cargo test -p bloch-crypto --features wallet-cli --offline legacy_nonce_base64_length_precedes_decode_without_restricting_salt -- --nocapture`
  - library target: `1 passed; 0 failed; 244 filtered out`;
  - remaining targets: `0 failed`.

Full relevant validation:

- `cargo test -p bloch-crypto --features wallet-cli --offline`
  - library: `243 passed; 0 failed; 2 ignored`;
  - integration targets: `6 passed; 0 failed`;
  - doc tests: `0 failed; 2 ignored`;
  - aggregate: `249 passed; 0 failed; 4 ignored`.

The complete suite ran outside the restricted sandbox because HTTP RPC
fixtures bind localhost sockets.

## Boundaries and residuals

- Serde has already allocated the encoded JSON strings before these
  object-level guards run. The change prevents only decoder-output allocation
  for fixed fields whose encoded length is already incompatible.
- Exact-length invalid data still reaches the Base64 decoder. Ciphertext and
  public-key strings retain their existing allocation and validation paths.
- Legacy salt lengths remain governed solely by the existing Base64 decoder
  and Argon2 backend; save continues to produce 32 random bytes.
- The tests prove control-flow and byte compatibility, not heap/RSS or latency.
  Backend, allocator, compiler/register and caller-owned copies remain outside
  the change. `CR-07` remains `PARTIAL`.
