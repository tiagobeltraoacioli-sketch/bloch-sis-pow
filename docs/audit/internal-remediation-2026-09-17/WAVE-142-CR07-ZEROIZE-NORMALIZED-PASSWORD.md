# Wave 142 — CR-07 zeroize the normalized password copy

Date: 2026-09-19
Comparison base: `3b408c57`

## Residual addressed

The shared password-strength validator trimmed and lowercased its borrowed
password into an ordinary owned `String` before comparing it with the breached
password denylist. That repository-created normalization copy contained the
password and was released without wiping after either acceptance or rejection.

All four repository callers converge on this validator: v1 keyfile encryption,
v2 keyfile encryption, legacy `Keypair::save_encrypted`, and the wallet CLI's
new-password precheck. The CLI precheck followed by legacy save can invoke the
same normalization twice, but each invocation now owns its copy under wiping
drop.

## Correction and invariants

The private `normalized_password_for_denylist` helper moves the direct result
of `password.trim().to_lowercase()` into `Zeroizing<String>` without cloning it.
The owner remains live for the denylist comparison and wipes on every return or
unwind path.

The minimum-length gate still runs first. Rust's existing Unicode `trim` and
`to_lowercase` operations, the denylist, accepted and rejected inputs, error
variants and messages are unchanged. No public API, keyfile schema, ciphertext,
KDF parameter, RNG operation, key material or output byte changes.

## Adversarial coverage

`denylist_normalization_has_zeroizing_ownership_and_preserves_policy` pins the
private helper's return type to `Zeroizing<String>`, confirms that the type
needs drop, checks exact whitespace trimming, ASCII denylist normalization and
the existing Unicode lowercasing behavior, and exercises explicit live
zeroization. It also proves that the normalized denylisted input is rejected
while a distinct mixed-case password with surrounding whitespace remains
accepted.

The existing denylist and exact minimum-length boundary tests continue to pin
the behavioral policy.

## Validation

```text
cargo test -p bloch-crypto \
  denylist_normalization_has_zeroizing_ownership_and_preserves_policy \
  --offline -- --nocapture
# 1 passed; 0 failed; 223 filtered out

cargo test -p bloch-crypto weak_password_ --offline -- --nocapture
# 3 passed; 0 failed; 221 filtered out

cargo test -p bloch-crypto --features wallet-cli --offline
# 237 passed; 0 failed; 4 ignored
```

The first sandboxed full-suite attempt reached 228 passing unit tests, then
three localhost HTTP fixtures failed with `EPERM` while binding their test
listeners; two unit tests were ignored. The same complete command passed
outside the sandbox: 231 unit tests, six integration tests and zero doctests
passed; two unit tests and two doctests were ignored.

## Residual boundary

- The caller retains its original borrowed password; terminal, OS and
  `rpassword` ownership remains outside this helper.
- Rust's Unicode normalization implementation, allocator/compiler/register
  copies and aborts that skip destructors are not claimed to be erased.
- Argon2 and cipher backend state remains opaque to this change.
- CR-08 remains unchanged: `rand_chacha` does not expose a supported wipe of
  its internal `ChaCha20Rng` state, and caller-owned seed copies remain outside
  the scoped RNG helper.
