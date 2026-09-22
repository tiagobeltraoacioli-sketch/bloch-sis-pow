# Wave 82 CR-07: in-place legacy-keystore decryption

Base: `f438c75`; branch `fix/internal-audit-20260917`.

## Residual addressed

The historical `Keypair::load_encrypted` compatibility loader still decoded
its Base64 ciphertext into one `Vec<u8>` and asked AES-GCM to allocate a second
`Vec<u8>` for plaintext containing the hex-encoded private key. Both buffers
coexisted until parsing completed. The HD-wallet equivalent stopped making
that duplicate allocation in Wave 81, but this separately reachable legacy
loader retained it.

## Change

The loader now decodes ciphertext directly into `Zeroizing<Vec<u8>>` and uses
AES-GCM `AeadInPlace` to authenticate and decrypt into the same allocation.
Successful decryption passes that allocation to the existing parsing path;
nonce/tag validation, KDF failure and authentication failure all leave it
owned by the zeroizing wrapper until drop.

The existing nonce and minimum-tag checks still execute before Argon2, and the
private helper repeats those safety checks before fixed-size AES conversion.
The JSON schema, Base64 representation, nonce/tag sizes, empty associated data,
Argon2 parameters, error semantics, public API and historical ciphertext
compatibility are unchanged.

This correction does not claim to avoid the encrypted JSON string or Base64
decode allocation. Limits still apply after JSON deserialization. It removes
the additional AES plaintext allocation after those steps.

## Regression

The production helper is tested with a non-empty secret and the exact AES-GCM
lower boundary: empty plaintext encoded as the 16-byte authentication tag. In
both cases the plaintext retains the ciphertext allocation address. A 15-byte
buffer is rejected before AES, and a tampered ciphertext remains owned by
`Zeroizing<Vec<u8>>` when authentication fails so propagation drops the wipe-on-
drop wrapper.

## Validation

- `cargo test -p bloch-crypto legacy_keystore_decryption_reuses_ciphertext_allocation_at_tag_boundary -- --nocapture`: 1 passed, 0 failed.
- `cargo test -p bloch-crypto` outside the sandbox (the HTTP regressions bind loopback sockets): library 205 passed, 0 failed, 2 ignored; integration tests 6 passed, 0 failed; doc tests 2 ignored (211 passed and 4 ignored in total).
- `git diff --check` on the source and report: passed.

## Residual risk

CR-07 remains `PARTIAL`. Legacy JSON deserialization and Base64 decoding still
allocate before this step. Deserializing the authenticated payload still owns
a temporary private-key hex string, and hex decoding must allocate the binary
key retained by the returned `Keypair`. Compiler temporaries, opaque backend
state and caller-created copies remain outside this correction. CR-08's opaque
`rand_chacha` state likewise remains unchanged because the dependency exposes
neither its state nor a zeroizing drop implementation.
