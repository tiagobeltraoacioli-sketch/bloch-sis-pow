# Wave 85 CR-07: zeroize the BIP39 passphrase salt copy

Base: `3a45d9f`; branch `fix/internal-audit-20260917`.

## Residual addressed

`SeedPhrase::to_seed_bytes_versioned` constructs the BIP39 PBKDF2 salt as the
exact byte string `"mnemonic" || passphrase`. The caller owns the original
passphrase, but the derivation path copied it into an ordinary heap `Vec<u8>`.
That temporary was dropped without wiping after either the legacy V1/SHA-256
or standard V2/SHA-512 derivation.

The optional BIP39 passphrase is the wallet's sensitive “25th word”. This copy
was local and removable without changing how the seed is derived or returned.

## Change

A private `bip39_salt(&str)` helper now constructs the same bytes directly in
`Zeroizing<Vec<u8>>`. It borrows the caller's passphrase and appends its bytes
directly; it does not create an intermediate owned `String`. Both seed versions
use that helper, so the salt allocation is wiped when PBKDF2 returns or unwinds.

The mnemonic representation, public seed APIs, returned `[u8; 64]`, PBKDF2
iteration count, PRFs, salt bytes, derivation versions and every wallet/file
format remain unchanged.

## Regression

`bip39_passphrase_salt_is_exact_and_zeroizing_for_both_seed_versions` proves:

- the helper emits exactly `b"mnemoniccorrect horse battery staple"` for the
  fixture passphrase;
- its concrete owner is `Zeroizing<Vec<u8>>` and has drop behavior;
- direct PBKDF2-HMAC-SHA512 and PBKDF2-HMAC-SHA256 over those exact bytes equal
  the production V2 and V1 results respectively; and
- the buffer implements structural zeroization when explicitly wiped.

The explicit wipe assertion is structural evidence for the same type used in
production. It does not inspect freed storage or claim to observe memory after
`Drop`. Existing official BIP39, external-crate parity, passphrase and V1/V2 KAT
regressions remain unchanged and pass in the full suite.

## Validation

- `cargo test -p bloch-crypto bip39_passphrase_salt_is_exact_and_zeroizing_for_both_seed_versions --offline -- --nocapture`: 1 passed, 0 failed; 209 library tests filtered out.
- `cargo test -p bloch-crypto --offline` outside the sandbox because the HTTP regressions bind loopback sockets: library 208 passed, 0 failed, 2 ignored; integration tests 6 passed, 0 failed; doc tests 2 ignored (214 passed and 4 ignored total).
- `git diff --check` on the wallet source and this report: passed.

## Residual risk

CR-07 remains `PARTIAL`. The caller still owns the original passphrase, and
PBKDF2/HMAC internals, compiler temporaries and register state are opaque.
SeedPhrase parsing and external cryptographic implementations may retain their
own copies. Wallet JSON/Base64 parsing, retained live key material and
caller-created copies remain outside this correction. CR-08's opaque
`rand_chacha` state is unchanged because the dependency exposes neither its
state nor a zeroizing drop implementation.
