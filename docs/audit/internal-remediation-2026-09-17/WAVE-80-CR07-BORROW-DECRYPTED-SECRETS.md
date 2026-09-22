# Wave 80 CR-07: borrow decrypted wallet secrets

Base: `9fda65f`; branch `fix/internal-audit-20260917`.

## Residual addressed

HD-wallet restore decrypts the mnemonic and each keypair into zeroizing JSON
buffers. The previous Serde payload types then allocated new `String` copies
of the mnemonic, private-key hex and public-key hex before comparison or hex
decoding. The private string was explicitly zeroized later, but the copy and
its transient memory footprint were unnecessary for the canonical JSON emitted
by this repository.

The parsed mnemonic was also rendered to a fresh canonical `String` once for
the master-key KDF and again for the authenticated mnemonic comparison. Both
copies carried the complete recovery phrase.

## Change

Restore now deserializes secret strings as borrowed `Cow<str>` values. Ordinary
unescaped mnemonic and hex strings point directly into their already-zeroizing
decrypted plaintext buffer, eliminating the intermediate Serde `String`
allocations. JSON with equivalent escape sequences remains compatible through
`Cow::Owned`; custom `Drop` implementations explicitly zeroize the owned
mnemonic and private-key fallback.

The caller mnemonic is rendered once into `Zeroizing<String>` and reused for
both master-key derivation and the byte-exact authenticated comparison. The
comparison semantics, JSON schema, ciphertext, key bytes and compatibility
entry points are unchanged. The save path retains its owned zeroizing payload
types because serialization necessarily owns the newly encoded hex strings.

## Regression

The regression serializes ordinary mnemonic/keypair payloads, deserializes
them through the production borrowed types and proves both secret views point
inside the original zeroizing plaintext allocations. It also supplies escaped
mnemonic, private-key and public-key JSON strings, proves they take the owned
compatibility path and verifies their decoded values remain unchanged.

## Validation

- `cargo test -p bloch-crypto decrypted_secret_strings_borrow_plaintext_and_preserve_escaped_json --offline`: passed.
- `cargo test -p bloch-crypto --offline`: library 203 passed, 0 failed, 2 ignored; integration tests 6 passed, 0 failed; doc tests 2 ignored. The complete run used the approved unsandboxed test prefix because three HTTP regressions bind loopback sockets.
- `git diff --check` on the wallet source and this report: passed.

## Residual risk

CR-07 remains `PARTIAL`. AES-GCM must still allocate the decrypted plaintext,
hex decoding must allocate the binary key retained by the live wallet, and the
parsed mnemonic plus one zeroizing canonical representation remain live during
restore. Escaped JSON necessarily requires a temporary owned string, although
the secret fallback is wiped. Compiler temporaries, opaque crypto-backend state,
caller-created copies and CR-08's opaque ChaCha state remain outside this
correction.
