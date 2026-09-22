# Wave 89 — CR-07 zeroize new-password confirmation and save lifetime

Date: 2026-09-19
Comparison base: `46de03c`

## Residual addressed

Wave 88 placed the existing password/mnemonic prompt helper under zeroizing
ownership, but the new-keystore flow used two direct `rpassword` calls. Its
primary and confirmation values were ordinary `String`s across validation,
comparison and retry. The one confirmed value then remained live while
`Cmd::New` handled the save result, including an error branch that terminates
through `process::exit` without running destructors.

A consumer search found exactly one `prompt_new_password` caller: `Cmd::New`.
Its return is borrowed once by the legacy `Keypair::save_encrypted` path; no
callee needs to own or retain the prompt allocation.

## Change and compatibility

Both direct prompt results now move immediately into `Zeroizing<String>` via
the Wave 88 ownership helper, without cloning. Password-policy rejection uses
the existing loop `continue`, which drops the primary owner. A private
confirmation helper consumes both owners: mismatch returns `None` and drops
both, while an exact match returns only the primary and drops the confirmation.

`prompt_new_password` therefore returns `Zeroizing<String>`. `Cmd::New`
borrows it unchanged for `save_encrypted`, stores that result, and explicitly
drops the password before either the success or fatal error branch. This also
covers save failures despite `process::exit` not running destructors.

The helper and call path are private. Prompt text, validation order and policy,
retry behavior, Argon2/AES inputs, keystore schema, ciphertext behavior and CLI
output are unchanged.

## Validation

```text
cargo test -p bloch-crypto --features wallet-cli \
  new_password_confirmation_preserves_only_an_exact_zeroizing_owner \
  --offline -- --nocapture
# 1 passed; 0 failed; 219 filtered out

cargo check -p bloch-crypto --no-default-features --features wallet-cli \
  --bin postern-wallet --offline
# passed

cargo test -p bloch-crypto --features wallet-cli --offline
# 224 passed; 0 failed; 4 ignored
```

The crate library contributed 218 passes and 2 ignored tests, the three
integration targets contributed 6 passes, the wallet binary had no unit tests,
and the documentation target contributed 2 ignored tests.

The regression proves the confirmed owner has drop behavior and exact content,
that mismatch yields no surviving owner, and that the live returned owner can
be explicitly zeroized. It does not inspect storage after `Drop`.

## Residual boundary

CR-07 remains `PARTIAL`. This change owns only the two `String`s returned to
this CLI flow. It does not claim to erase terminal, OS or `rpassword` internal
buffers; Argon2, AES, allocator, compiler or register copies; the generated
keypair; serialized ciphertext; or caller-owned outputs. Backend and external
copies require their own contracts rather than an inference from this wrapper.
