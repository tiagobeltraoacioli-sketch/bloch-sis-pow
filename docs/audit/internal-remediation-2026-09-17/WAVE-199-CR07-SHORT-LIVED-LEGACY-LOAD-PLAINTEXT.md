# Wave 199 — CR-07 short-lived legacy-load plaintext

Date: 2026-09-19
Comparison base: `aa231776`

## Reproduced residual

The legacy `Keypair` loader already reused its decoded ciphertext allocation
for authenticated plaintext under `Zeroizing<Vec<u8>>`, borrowed canonical key
strings from that allocation, wiped historical escaped-string fallbacks and
returned the decoded private key under zeroizing ownership. After parsing and
hex decoding completed, however, the complete plaintext JSON owner remained
lexically live while the public key's address was derived and authenticated
and the final `Keypair` was assembled.

That plaintext contains the full private-key hex string. Its remaining
lifetime was repository-owned and was not required by address authentication.
Wave 83 covered borrowed parsing, Wave 93 covered the legacy load KDF owner and
Wave 187 covered the separate HD-wallet load path; none established this
legacy plaintext lifetime boundary.

## Correction and invariants

A private `decode_legacy_keystore_payload` helper now consumes the zeroizing
plaintext owner. It preserves the existing borrowed canonical parse and wiping
`Cow::Owned` fallback, decodes private and public hex in the same order, then
explicitly drops the parsed view and plaintext before returning only the
zeroizing binary private key and public key. The production loader moves its
plaintext directly into this helper without cloning or reallocating it and
resumes address authentication only after the helper has returned.

Canonical and historical escaped JSON compatibility, Serde and hex error
text/order, address authentication, key bytes, file schema, Base64, Argon2,
AES-GCM, RNG behavior and public APIs are unchanged. Error and unwind paths
retain RAII cleanup.

## Regression coverage

`legacy_decrypted_key_strings_borrow_plaintext_and_preserve_escaped_json` now
also pins the consuming helper's ownership signature and wiping return type.
It retains the pointer-range proof that canonical strings borrow the original
plaintext, verifies exact private/public bytes through the consuming helper
for canonical and escaped payloads, and checks that invalid private or public
hex retains the existing decoder error.

The complete `wallet::legacy_keystore_tests` module additionally covers real
save/load, both networks, address and signing compatibility, KDF and nonce
bounds, in-place decryption, wrong/corrupt input behavior and file limits.

## Validation

- `cargo test -p bloch-crypto --features wallet-cli --offline legacy_decrypted_key_strings_borrow_plaintext_and_preserve_escaped_json -- --nocapture`
  - library target: `1 passed; 0 failed; 246 filtered out`;
  - remaining targets: `0 failed`.
- `cargo test -p bloch-crypto --features wallet-cli --offline wallet::legacy_keystore_tests -- --nocapture`
  - library target: `14 passed; 0 failed; 233 filtered out`;
  - remaining targets: `0 failed`.
- `cargo test -p bloch-crypto --features wallet-cli --offline`
  - library: `245 passed; 0 failed; 2 ignored`;
  - integration targets: `6 passed; 0 failed`;
  - doc tests: `0 failed; 2 ignored`;
  - aggregate: `251 passed; 0 failed; 4 ignored`.
- Diff/whitespace checks:
  - `git diff --check -- crates/bloch-crypto/src/wallet/mod.rs`: clean;
  - the untracked report was checked separately with
    `git diff --no-index --check /dev/null`: clean.

The complete suite ran outside the restricted sandbox because its HTTP
fixtures bind localhost sockets. An initial sandbox run reached `242 passed;
3 failed; 2 ignored` in the library target, with all three failures occurring
at `TcpListener::bind` with `EPERM`; the unrestricted run above passed all
three unchanged fixtures.

## Boundary and residuals

This is a structural lifetime reduction for one repository-owned plaintext
allocation with existing wiping `Drop` behavior. It does not inspect bytes
after `Drop` or claim measured heap, RSS or latency savings. The plaintext
necessarily remains live through authenticated decryption, Serde parsing and
hex decoding. The decoded private key retained by the returned `Keypair`, the
caller-owned password and keypair, file/ciphertext/Base64/Serde allocations,
historical escaped-string fallback while parsing, Argon2/AES/backend state,
allocator, compiler and register copies retain their required or opaque
lifetimes. Process aborts that skip destructors and external copies remain
outside Rust RAII guarantees. `CR-07` remains `PARTIAL`.
