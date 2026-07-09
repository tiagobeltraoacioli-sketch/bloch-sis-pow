# pqcrypto-internals — GroundState fork

This is a **drop-in replacement** for the upstream
[`pqcrypto-internals`](https://github.com/rustpq/pqcrypto) crate
(version 0.2.11), with **one single change**: the
`PQCRYPTO_RUST_randombytes` function checks a thread-local seeded RNG
before falling back to OS entropy.

This enables deterministic keypair generation from a 32-byte seed,
which is required for BIP39-style wallet recovery in
[GroundState](https://github.com/Groundstate100/groundstate) (see
audit finding C-2).

## Why

FIPS 204 Algorithm 6 (ML-DSA KeyGen_internal) is inherently
deterministic from a 32-byte seed. The PQClean C implementation
correctly implements this, but reads the seed from `randombytes()`
without exposing a seeded entry point. Rather than forking PQClean's
C code, we override the Rust shim that provides randomness to the
C layer.

## What changes

Only `src/lib.rs`. The C files (`cfiles/`), the build system
(`build.rs`), and all other artifacts are **identical to upstream
0.2.11**.

Two new dependencies:
- `rand_chacha = "0.9"` (no-std) — for the ChaCha20-based CSPRNG
- `rand_core = "0.9"` (no-std) — trait interface

## How to use

```rust
use pqcrypto_internals::with_seeded_rng;
use pqcrypto_mldsa::mldsa65;

let seed: [u8; 32] = derive_from_bip39(&phrase);
let (pk, sk) = {
    let _guard = with_seeded_rng(&seed);
    mldsa65::keypair()
};
// pk, sk are deterministic in `seed`.
```

The guard is RAII — when it drops, the thread-local is cleared and
all subsequent `randombytes()` calls revert to OS entropy. Upstream
behavior is preserved byte-for-byte when no guard is active.

## Consumed by

Via `[patch.crates-io]` in
[`Groundstate100/groundstate`](https://github.com/Groundstate100/groundstate):

```toml
[patch.crates-io]
pqcrypto-internals = { git = "https://github.com/Groundstate100/pqcrypto-fork", branch = "main" }
```

## Upstream reconciliation

An issue is open at rustpq/pqcrypto proposing a
`keypair_from_seed()` API natively in `pqcrypto-mldsa`. If accepted,
this fork is retired.

## License

MIT OR Apache-2.0 (same as upstream).
