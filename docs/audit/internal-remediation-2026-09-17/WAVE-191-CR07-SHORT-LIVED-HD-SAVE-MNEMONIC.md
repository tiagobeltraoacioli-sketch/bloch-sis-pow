# Wave 191 — CR-07 short-lived HD-save mnemonic plaintext

Date: 2026-09-19
Comparison base: `49abbbd9`

## Reproduced residual

`HdWallet::save` serialized the complete mnemonic into a
`Zeroizing<Vec<u8>>`, encrypted it, and then retained that already-unused
plaintext owner through every per-address encryption, final wallet
serialization and the atomic write/fsync.  Its wiping ownership covered normal
return, error propagation and unwind, but its lexical lifetime was longer than
its sole consumer required.

This residual is distinct from the earlier HD-load lifetime reduction.  Wave
80 deliberately retained owned zeroizing payloads on the save side; Waves
90/118/122/127 protected entropy, canonical KDF copies and seed owners; Wave
187 shortened authenticated mnemonic owners only while loading.

## Correction and invariants

A private `encrypt_mnemonic_for_save` helper now owns the save-side mnemonic
payload and serialized plaintext.  It explicitly drops the structured
`MnemonicPayload` after serialization, borrows the zeroizing JSON into the
existing encryption helper, and returns only the encrypted record.  Returning
from this boundary drops the serialized plaintext before `HdWallet::save`
starts its address loop or writes the final file.  Error and unwind paths retain
the same RAII cleanup.

The mnemonic rendering, JSON type and field order, AES-GCM helper, nonce/RNG
call order, master key, ciphertext distribution, file schema, errors and public
API are unchanged.  There is no KDF, RNG, format or accepted-input change.

## Regression coverage

`hd_save_mnemonic_helper_preserves_plaintext_bytes_and_short_lived_ownership`
pins the helper signature and the wiping types, encrypts a fixed mnemonic with
a fixed test key, decrypts it through the production helper and proves that the
plaintext bytes exactly equal the historical `MnemonicPayload` serialization.
It also parses the result through the borrowing-compatible production payload.

The existing `create_save_load_roundtrip` and V1/V2
`*_save_load_roundtrip` regressions cover ordinary creation plus compatibility
save/load behavior after the ownership-boundary change.

## Validation

- `cargo test -p bloch-crypto --features wallet-cli --offline hd_save_mnemonic_helper_preserves_plaintext_bytes_and_short_lived_ownership -- --nocapture`
  - library target: `1 passed; 0 failed; 246 filtered out`;
  - remaining targets: `0 failed`.
- `cargo test -p bloch-crypto --features wallet-cli --offline save_load_roundtrip -- --nocapture`
  - library target: `4 passed; 0 failed; 243 filtered out`;
  - remaining targets: `0 failed`.
- `cargo test -p bloch-crypto --features wallet-cli --offline`
  - library: `245 passed; 0 failed; 2 ignored`;
  - integration targets: `6 passed; 0 failed`;
  - doc tests: `0 failed; 2 ignored`;
  - aggregate: `251 passed; 0 failed; 4 ignored`.
- `git diff --check -- crates/bloch-crypto/src/hd_wallet/mod.rs docs/audit/internal-remediation-2026-09-17/WAVE-191-CR07-SHORT-LIVED-HD-SAVE-MNEMONIC.md`
  - clean, with the untracked report checked separately for trailing
    whitespace.

The complete clean suite ran outside the restricted sandbox because its HTTP
fixtures bind localhost sockets.  An earlier concurrent complete attempt
observed the unrelated randomized legacy-keystore roundtrip fail its address
comparison after `244 passed`; that exact test had already passed in the
four-roundtrip focus and passed again immediately in isolation (`1 passed; 246
filtered out`).  The final complete run above was clean.

## Boundary and residuals

This is a lifetime reduction for repository-owned buffers that already had
wiping `Drop` behavior.  It does not inspect bytes after `Drop` or claim exact
heap/RSS or latency savings.  The wallet's required `bip39::Mnemonic`, master
key, per-address structured/plaintext owners, AES/backend state, allocator,
compiler and register copies retain their existing lifetimes or opaque cleanup
behavior.  Caller-owned mnemonic, passphrase and password copies are unchanged;
process aborts that skip destructors remain outside Rust RAII guarantees.
`CR-07` remains `PARTIAL`.
