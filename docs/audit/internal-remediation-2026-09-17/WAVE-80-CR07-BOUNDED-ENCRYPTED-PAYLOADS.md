# Wave 80 CR-07: bounded encrypted HD-wallet payloads

Base: `f787b25`; branch `fix/internal-audit-20260917`.

## Residual addressed

The ordinary HD-wallet loaders already bounded input bytes, address records and
derived-key checks. After JSON deserialization, however, an attacker-controlled
Base64 nonce or ciphertext could still consume most of the 64 MiB file budget.
`decrypt_with_key` would then allocate another large buffer while decoding it,
run the master-key KDF and, for ciphertext, ask AES-GCM to allocate plaintext.
Repeating that shape across admitted records created avoidable transient memory
amplification after the file itself had passed the bounded policy.

## Change

Ordinary bounded restore now admits at most:

- 64 encoded bytes for each AES-GCM nonce;
- 4 KiB of encoded mnemonic ciphertext; and
- 64 KiB of encoded ciphertext per encrypted keypair.

Repository-produced payloads are substantially smaller: the nonce is a
12-byte value encoded as 16 Base64 bytes, the mnemonic is one 24-word JSON
field, and the keypair is the fixed supported hybrid private/public key JSON.
The ceilings retain generous format headroom without changing the schema,
cryptography or serialized output.

Validation runs after the bounded JSON value has been deserialized, but before
mnemonic parsing, Argon2, Base64 decoding or AES-GCM decryption. It therefore
does **not** claim to prevent allocation of the original JSON strings; it
prevents the subsequent decode/plaintext allocations and expensive credential
work for an excess payload. The existing explicit compatibility loaders and
custom public trusted-recovery reader retain their historical policy.

The ordinary public metadata reader applies the same payload-shape policy
before returning the parsed wallet, so a normal listing cannot hand an
oversized encrypted field onward as if it met the interactive wallet profile.

## Adversarial regression

The regression admits nonce, mnemonic-ciphertext and keypair-ciphertext strings
at their exact encoded ceilings, then rejects one additional byte for each
class with deterministic field/index-specific errors. It writes a wallet with
an oversized keypair ciphertext and proves both bounded production entry points
return the resource error ahead of deliberately invalid mnemonic credentials.
The explicit trusted public reader still accepts the same structurally valid
file, pinning the compatibility escape hatch.

## Validation

- `cargo test -p bloch-crypto bounded_payload_caps_accept_exact_limits_and_reject_before_credentials --offline`: passed.
- `cargo test -p bloch-crypto --offline`: library 201 passed, 0 failed, 2 ignored; integration tests 6 passed, 0 failed; doc tests 2 ignored. The complete run used the approved unsandboxed test prefix because three HTTP regressions bind loopback sockets.
- `git diff --check` on the wallet source and this report: passed.

## Residual risk

CR-07 remains `PARTIAL`. The original encoded strings are allocated by JSON
deserialization before this validation. Historical compatibility APIs and
explicit trusted recovery can still accept broader payloads. The bounded JSON
preflight/full parse remains two byte-proportional passes, and opaque
crypto-backend/register or caller-owned secret copies remain outside this
correction.
