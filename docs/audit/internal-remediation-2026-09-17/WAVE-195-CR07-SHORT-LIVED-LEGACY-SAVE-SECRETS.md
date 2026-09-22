# Wave 195 — CR-07 short-lived legacy-save secret owners

Date: 2026-09-19
Comparison base: `17e7545e`

## Reproduced residual

Wave 92 placed the legacy `Keypair::save_encrypted` Argon2 key and serialized
private/public-key JSON under wiping ownership.  Their lexical scope still
extended beyond their last cryptographic use: the derived key, structured
private-key hex payload and zeroizing plaintext stayed live while public
metadata and Base64 were assembled, the final JSON was rendered, and the
atomic write/fsync completed.

The repository has one production consumer of this public compatibility path:
the wallet CLI's `Cmd::New`.  Downstream callers retain the same public method.

## Correction and invariants

A private `encrypt_legacy_keystore_payload` helper now owns the structured hex
payload and serialized plaintext.  It explicitly drops the structured payload
after serialization, borrows the zeroizing JSON into the unchanged AES-GCM
operation, and returns only ciphertext.  Returning from the helper drops the
plaintext before public metadata assembly; the caller explicitly drops the
zeroizing derived key immediately afterward, before final serialization and
file I/O.  Error and unwind paths retain the existing RAII cleanup.

Password policy, Argon2 parameters, salt and nonce generation/order, payload
JSON bytes and field order, AES-GCM key/nonce/plaintext, ciphertext, Base64,
keystore schema, errors and public APIs are unchanged.  There is no format,
KDF, RNG, accepted-input or output change.

## Regression coverage

`legacy_save_temporaries_have_zeroizing_ownership_and_exact_json` retains the
Wave 92 type assertions and additionally pins the private helper signature and
structured payload's wiping type.  With fixed key, nonce and key bytes it
proves exact historical JSON and AES-GCM ciphertext parity, decrypts through
the production in-place helper, and verifies the original plaintext bytes.

The full `wallet::legacy_keystore_tests` module additionally covers the real
save/load roundtrip, weak-password policy, nonce/KDF bounds, borrowed decrypted
payload behavior, signing compatibility and both networks.

## Validation

- `cargo test -p bloch-crypto --features wallet-cli --offline legacy_save_temporaries_have_zeroizing_ownership_and_exact_json -- --nocapture`
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
- `git diff --check -- crates/bloch-crypto/src/wallet/mod.rs docs/audit/internal-remediation-2026-09-17/WAVE-195-CR07-SHORT-LIVED-LEGACY-SAVE-SECRETS.md`
  - clean, with the untracked report checked separately for trailing
    whitespace.

The complete suite ran outside the restricted sandbox because its HTTP
fixtures bind localhost sockets.

## Boundary and residuals

This is a lifetime reduction for repository-owned buffers that already had
wiping `Drop` behavior.  It does not inspect bytes after `Drop` or claim exact
heap/RSS or latency savings.  The caller-owned password and `Keypair`, public
salt and nonce, ciphertext, Argon2/AES/key-schedule backend state, allocator,
compiler and register copies retain their required or opaque lifetimes.
Process aborts that skip destructors and external copies remain outside Rust
RAII guarantees.  `CR-07` remains `PARTIAL`.
