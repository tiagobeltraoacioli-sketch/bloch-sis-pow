# Wave 108 — BV-09 zeroize recovery-secret output

Date: 2026-09-19
Comparison base: `a1e5663`

## Residual addressed

The V1 recovery-secret derivation previously expanded HKDF into an ordinary
repository-owned `[u8; 32]`. The checked restoration path then copied that
array into `Zeroizing`, leaving the original derivation owner without a
type-level cleanup contract. The same ordinary intermediate was also used by
the public convenience function that returns `(r, H(r))`.

## Change and compatibility

A private `derive_recovery_secret_zeroizing` helper now creates its
`Zeroizing<[u8; 32]>` output before `HKDF-Expand` and expands directly into
that owner. `restore_recovery_secret_v1` receives the owner directly, so both
its success and mismatch paths remain under RAII cleanup. `derive_recovery`
borrows the protected owner while hashing and makes only the final array copy
required by its existing public return type.

The public `derive_recovery_secret`, `derive_recovery` and restoration APIs
retain their exact signatures. The HKDF algorithm, salt, info framing, input
bytes, output bytes and recovery hash are unchanged. This does not change a
public API, format, KDF, RNG flow, consensus rule or dependency.

## Validation

```text
cargo test -p bloch-pq-vault \
  recovery_secret_internal_owner_is_exact_and_zeroizing \
  --offline -- --nocapture
# 1 passed; 0 failed; 47 filtered out

cargo test -p bloch-pq-vault preimage::tests --offline -- --nocapture
# 11 passed; 0 failed; 37 filtered out

cargo test -p bloch-pq-vault --offline
# unit: 48 passed; 0 failed; 0 ignored
# documentation: 2 passed; 0 failed; 0 ignored
# total: 50 passed; 0 failed; 0 ignored

cargo test --manifest-path services/pq-shield-api/Cargo.toml --offline
# library: 19 passed; 0 failed; 0 ignored
# binary: 0 tests
# documentation: 0 tests
# total: 19 passed; 0 failed; 0 ignored
```

The new regression pins the private helper's zeroizing return type, verifies a
fixed HKDF known-answer vector and supports explicit zeroization while the
owner is live. The existing preimage regressions cover deterministic and
key-bound derivation, exact V1 restoration, mismatch refusal and all three
versioned recovery contexts. No test claims to inspect storage after `Drop`.

## Residual boundary

BV-09 remains bounded by its public compatibility surface. The two public
derivation functions must still return caller-owned copyable arrays, and this
change does not erase those arrays or any copies made by callers. It also does
not claim to erase the borrowed PQ key, HKDF/SHA backend internals, vault-key
objects, compiler/register copies or external storage. Process aborts that
skip destructors remain outside Rust RAII guarantees.
