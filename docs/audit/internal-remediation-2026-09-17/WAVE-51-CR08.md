# Wave 51 CR-08: scoped-only deterministic RNG override

Date: 2026-09-18. Starting point: `2abb416`. Scope: the patched
`pqcrypto-internals` entropy shim and deterministic crypto KAT callers. No
key, signature, wire format, consensus rule, production binary or deployment
was changed.

## Removed misuse surface

Bloch key generation already used `with_seeded_rng_scope`, which owns the
cleanup guard and removes its override on normal return or unwind. The lower
level `with_seeded_rng` constructor and `SeededRngGuard` type nevertheless
remained public. A downstream caller could `mem::forget` that guard and leave a
thread consuming deterministic bytes during later cryptographic operations.

Both are now private implementation details. The scoped closure API is the only
public way to activate deterministic PQClean entropy. Current and Genesis-3
KATs were migrated to it without changing their pinned bytes. A compile-fail
doctest fixes the public boundary, while internal unit tests retain direct
access to exercise nested, forgotten and out-of-order cleanup behavior.
Removing the manual API is intentionally breaking for any consumer outside
this repository; the repository workspace was fully inventoried, but no claim
is made about unknown downstream users of this internal fork.

## Status and residual

CR-08 remains `PARTIAL`. This closes the repository's public manual-guard path,
but Rust cannot promise erasure of opaque `rand_chacha` internal state, caller
seed copies or compiler-created temporaries. Abort and process-memory threat
models also remain outside scoped destructor guarantees. No claim of hardware
memory isolation or post-crash erasure is made.

## Validation

- `cargo test --locked -p pqcrypto-internals --offline`: 17 passed, 1 helper
  ignored; both vendor-pin tests and doctests passed.
- `cargo test --locked -p bloch-crypto --offline` outside the socket-restricted
  sandbox: 185 passed, 2 ignored; both ACVP tests, both Falcon submission tests
  and the dual-AND transaction test also passed.
- `cargo test --locked -p bloch --test kat_mldsa65 --offline`: 4 passed for the
  migrated Genesis-3 KAT consumer.
- Repository search finds no external call to the private manual guard.
