# Wave 203 — CR-07 short-lived HD-address save secrets

Date: 2026-09-19
Comparison base: `c519e089`

## Reproduced residual

Wave 191 confined the HD wallet's save-side mnemonic payload and plaintext to
a private encryption helper, but explicitly left the per-address save owners
unchanged. For every address, `HdWallet::save` constructed a zeroizing
`KeypairPayload` containing the private-key hex and a zeroizing serialized JSON
plaintext. Both remained lexically live after encryption while the public
address and label were cloned and the encrypted address record was assembled
and appended.

Those owners already wiped on normal return, error and unwind, but their last
cryptographic use was the AES-GCM call. The remaining lifetime was
repository-owned and unnecessary.

## Correction and invariants

A private `encrypt_keypair_for_save` helper now owns each structured keypair
payload and serialized plaintext. It explicitly drops the structured payload
after serialization, borrows the zeroizing JSON into the unchanged encryption
helper and returns only the encrypted record. Returning from this boundary
drops the plaintext before `HdWallet::save` clones public address/label
metadata or appends the record.

Private/public hex rendering, JSON type and field order, AES-GCM inputs, nonce
generation and RNG call order, ciphertext distribution, per-address ordering,
labels, addresses, wallet schema, errors and public APIs are unchanged. There
is no format, KDF, RNG, accepted-input or output change.

## Regression coverage

`hd_save_keypair_helper_preserves_plaintext_bytes_and_short_lived_ownership`
pins the private helper signature and both wiping owner types. With a fixed
keypair and AES key, it encrypts through the production helper, decrypts
through the production in-place path and proves byte-for-byte equality with
the historical `KeypairPayload` JSON. It also parses the plaintext through the
borrowing compatibility type, proves both canonical fields are borrowed and
recovers the exact private and public bytes.

The focused save/load set covers new HD wallets, legacy V1 files and V2 files
across a save/load cycle, plus the separate legacy `Keypair` roundtrip selected
by the shared test filter.

## Validation

- `cargo test -p bloch-crypto --features wallet-cli --offline hd_save_keypair_helper_preserves_plaintext_bytes_and_short_lived_ownership -- --nocapture`
  - library target: `1 passed; 0 failed; 247 filtered out`;
  - remaining targets: `0 failed`.
- `cargo test -p bloch-crypto --features wallet-cli --offline save_load_roundtrip -- --nocapture`
  - library target: `4 passed; 0 failed; 244 filtered out`;
  - remaining targets: `0 failed`.
- `cargo test -p bloch-crypto --features wallet-cli --offline`
  - library: `246 passed; 0 failed; 2 ignored`;
  - integration targets: `6 passed; 0 failed`;
  - doc tests: `0 failed; 2 ignored`;
  - aggregate: `252 passed; 0 failed; 4 ignored`.
- Diff/whitespace checks:
  - `git diff --check -- crates/bloch-crypto/src/hd_wallet/mod.rs`: clean;
  - the untracked report was checked separately with
    `git diff --no-index --check /dev/null`: clean.

The complete suite ran outside the restricted sandbox because its HTTP
fixtures bind localhost sockets.

## Boundary and residuals

This is a structural lifetime reduction for repository-owned buffers that
already had wiping `Drop` behavior. It does not inspect bytes after `Drop` or
claim measured heap, RSS or latency savings. Each plaintext necessarily
remains live through serialization and AES-GCM inside the helper. The live HD
wallet's required `Keypair` secrets, mnemonic, seed and master key, ciphertext,
Base64 and final wallet JSON owners, AES/backend state, allocator, compiler and
register copies retain their required or opaque lifetimes. Caller-owned
mnemonic, passphrase and password copies are unchanged; process aborts that
skip destructors and external copies remain outside Rust RAII guarantees.
`CR-07` remains `PARTIAL`.
