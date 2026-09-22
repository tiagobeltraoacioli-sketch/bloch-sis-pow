# Wave 187 — CR-07 short-lived authenticated HD mnemonic owners

Date: 2026-09-19
Comparison base: `803ac608`

## Reproduced residual

`HdWallet::load_internal` decrypted the authenticated mnemonic JSON into a
`Zeroizing<Vec<u8>>` and parsed a `BorrowedMnemonicPayload` from it.  It also
held the canonical mnemonic KDF copy in a `Zeroizing<String>`.  Although all
three owners already had wiping drop behavior, their lexical lifetime extended
through the complete address-decryption and derived-key verification loop after
the mnemonic comparison had succeeded.

The loop is explicitly count/work-bounded under `load_bounded`; the historical
compatibility loaders remain bounded only by their file-byte budget and may
still process many records.  Neither the authenticated plaintext, its borrowed
or Serde-owned parsed view, nor the canonical KDF string is needed once equality
is established.

## Correction and invariants

A private helper now consumes the decrypted `Zeroizing<Vec<u8>>` by value,
parses the same borrowing-compatible payload and performs the byte-identical
mnemonic comparison.  Returning from the helper drops the parsed view first and
then the plaintext owner.  `load_internal` explicitly drops the canonical
`Zeroizing<String>` immediately afterward, before entering the address loop.

The parsed `bip39::Mnemonic`, derived seed and master encryption key retain their
existing lifetimes because they are required by the returned wallet or by every
address check.  Decryption, JSON parsing, comparison, seed derivation, address
order and errors remain unchanged.  No schema, file bytes, KDF, RNG, public API,
accepted input or wallet output changed.

## Regression coverage

`authenticated_mnemonic_check_consumes_its_zeroizing_plaintext_owner` pins the
helper's by-value `Zeroizing<Vec<u8>>` input, successful canonical comparison,
the historical escaped-JSON `Cow::Owned` compatibility path and the exact
mnemonic-mismatch error.

Existing focused regressions additionally prove that:

- `create_save_load_roundtrip` preserves exact-limit and ordinary HD load/save,
  address and mnemonic behavior, plus wrong-password/passphrase refusal; and
- `decrypted_secret_strings_borrow_plaintext_and_preserve_escaped_json`
  preserves borrowed canonical parsing and owned escaped compatibility.

## Validation

- `cargo test -p bloch-crypto --features wallet-cli --offline authenticated_mnemonic_check_consumes_its_zeroizing_plaintext_owner -- --nocapture`
  - library target: `1 passed; 0 failed; 245 filtered out`;
  - remaining targets: `0 failed`.
- `cargo test -p bloch-crypto --features wallet-cli --offline create_save_load_roundtrip -- --nocapture`
  - library target: `1 passed; 0 failed; 245 filtered out`;
  - remaining targets: `0 failed`.
- `cargo test -p bloch-crypto --features wallet-cli --offline decrypted_secret_strings_borrow_plaintext_and_preserve_escaped_json -- --nocapture`
  - library target: `1 passed; 0 failed; 245 filtered out`;
  - remaining targets: `0 failed`.
- `cargo test -p bloch-crypto --features wallet-cli --offline`
  - library: `244 passed; 0 failed; 2 ignored`;
  - integration targets: `6 passed; 0 failed`;
  - doc tests: `0 failed; 2 ignored`;
  - aggregate: `250 passed; 0 failed; 4 ignored`.
- `git diff --check -- crates/bloch-crypto/src/hd_wallet/mod.rs docs/audit/internal-remediation-2026-09-17/WAVE-187-CR07-SHORT-LIVED-HD-MNEMONIC-OWNERS.md`

The first complete-suite attempt inside the restricted sandbox reached all
non-socket tests but the three HTTP fixtures failed to bind localhost with
`EPERM`.  The single complete rerun outside that sandbox produced the clean
result above.

## Boundary and residuals

This is a lifetime reduction for already-wiping repository owners.  It does not
observe bytes after `Drop`, prove allocator or register erasure, or erase the
caller-owned mnemonic/passphrase/password.  The `bip39::Mnemonic` object, the
final wallet seed and master key, cryptographic/KDF/cipher backend state, and
allocator/compiler copies retain their required or opaque lifetimes.  The
change does not claim an RSS or latency reduction.  `CR-07` remains `PARTIAL`.
