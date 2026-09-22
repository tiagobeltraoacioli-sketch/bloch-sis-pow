# Wave 83 CR-07: borrow decrypted legacy-keystore secrets

Base: `f57ed91`; branch `fix/internal-audit-20260917`.

## Residual addressed

Wave 82 made legacy AES-GCM decryption reuse its zeroizing ciphertext buffer,
but the next parsing step still deserialized the private-key hex into a new
owned `String`. For ordinary keystores written by this repository, that copied
the complete secret out of the already-zeroizing plaintext allocation before
hex decoding it.

## Change

The legacy loader now deserializes private- and public-key hex through a
load-only `Cow<str>` payload. Canonical unescaped strings borrow directly from
the zeroizing decrypted JSON buffer, eliminating the intermediate Serde
`String` allocation. Historical JSON using escape sequences remains compatible
through `Cow::Owned`; a custom `Drop` implementation explicitly zeroizes both
owned fallbacks, including the private-key copy.

The save payload remains owned and zeroizing because it must construct newly
encoded key strings. The encrypted JSON schema, AES/KDF bytes, public API,
address authentication, hex-decoded returned keys and historical escaped JSON
compatibility are unchanged.

## Regression

The regression serializes the canonical legacy payload and proves both parsed
string views point inside the original zeroizing plaintext allocation. It also
parses equivalent escaped private/public hex, proves those values use the owned
compatibility path, verifies their decoded bytes and pins that the payload has
drop behavior for wiping the owned fallback.

## Validation

- `cargo test -p bloch-crypto legacy_decrypted_key_strings_borrow_plaintext_and_preserve_escaped_json -- --nocapture`: 1 passed, 0 failed.
- `cargo test -p bloch-crypto` outside the sandbox (the HTTP regressions bind loopback sockets): library 206 passed, 0 failed, 2 ignored; integration tests 6 passed, 0 failed; doc tests 2 ignored (212 passed and 4 ignored in total).
- `git diff --check` on the source and report: passed.

## Residual risk

CR-07 remains `PARTIAL`. Legacy JSON and Base64 parsing still allocate before
authenticated decryption; escaped JSON necessarily allocates a temporary owned
string, though the secret fallback is wiped. Hex decoding allocates the binary
private key retained by the returned `Keypair`. Compiler temporaries, opaque
backend state and caller-created copies remain outside this correction. CR-08's
opaque `rand_chacha` state remains unchanged because the dependency exposes
neither its state nor a zeroizing drop implementation.
