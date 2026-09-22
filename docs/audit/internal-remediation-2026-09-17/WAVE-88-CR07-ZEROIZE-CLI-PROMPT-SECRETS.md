# Wave 88 — CR-07 zeroize CLI prompt secrets

Date: 2026-09-19
Comparison base: `7a91290`

## Residual addressed

The private `postern-wallet` prompt helper returned an ordinary `String` for
two sensitive call paths:

- the disclosure command's mnemonic input, which is parsed into the
  zeroizing canonical `SeedPhrase`; and
- `load_kp`'s encrypted-keystore password.

Both allocations remained ordinary caller locals. Error branches terminate
through `process::exit`, which does not run destructors, so merely wrapping the
return without shortening its lifetime would not cover failed parse/decrypt
paths.

## Change and compatibility

`prompt_password` now moves the `String` returned by `rpassword` directly into
`Zeroizing<String>` through a private ownership helper, without cloning or
changing its bytes. The disclosure path stores the parse result and drops the
prompt owner before handling success or error. `load_kp` likewise stores the
decrypt result and drops the password owner before either branch. Thus both
successful and failed operations wipe these CLI-owned allocations before any
possible `process::exit`.

`Zeroizing<String>` deref coercion preserves the existing `&str` input to
`SeedPhrase::parse` and `Keypair::load_encrypted`. CLI arguments, prompts,
schema, KDF parameters, mnemonic normalization, derivation and output bytes
are unchanged. `prompt_new_password` remains outside this focused correction.

The regression proves that the private owner has drop behavior, preserves the
exact input string and supports explicit zeroization while live. It does not
inspect memory after `Drop`.

## Validation

```text
cargo test -p bloch-crypto --features wallet-cli \
  cli_prompt_secret_owner_preserves_content_and_zeroizes_while_live \
  --offline -- --nocapture
# 1 passed; 0 failed; 218 filtered out

cargo check -p bloch-crypto --no-default-features --features wallet-cli \
  --bin postern-wallet --offline
# passed

cargo test -p bloch-crypto --features wallet-cli --offline
# 223 passed; 0 failed; 4 ignored
```

The crate library contributed 217 passes and 2 ignored tests, the three
integration targets contributed 6 passes, the wallet binary had no unit tests,
and the documentation target contributed 2 ignored tests.

## Residual boundary

CR-07 remains `PARTIAL`. This change owns only the `String` returned to this
CLI helper. It does not claim to erase terminal, OS or `rpassword` internal
buffers, the separate canonical `SeedPhrase`, `bip39::Mnemonic`, cryptographic
backend state, compiler/register copies, or caller-owned outputs. The two
direct prompts inside `prompt_new_password` still return ordinary `String`s
and require a separate review because their comparison/retry/return lifetimes
differ.
