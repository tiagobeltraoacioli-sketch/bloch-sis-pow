# pqcrypto-internals — GroundState fork

Local fork based on `pqcrypto-internals` 0.2.11 (rustpq/pqcrypto), used through
the workspace path patch. It preserves the C randombytes entry point while
supporting deterministic wallet key generation from an existing ChaCha20 byte
stream. This wrapper is not a claim of direct FIPS 204 seed-to-key equivalence:
the supplied wallet seed first keys ChaCha, which supplies PQClean's entropy.

## Local modifications and provenance (CR-09)

The fork is **not** limited to `src/lib.rs`. This checkout contains:

- Rust randombytes overrides, scoped/legacy guards, failure handling and tests.
- Cargo metadata/dependency changes for the RNG and vendored-file tests.
- Build-script handling that excludes freestanding OpenBSD libc headers on
  WASI, where the sysroot supplies libc. Native builds retain their own paths.
- Local provenance documentation and a vendored-source hash manifest/test.

`VENDOR.toml` pins only the files under `cfiles/` and `include/`. Its test checks
file contents and the file set against this repository's recorded baseline.
It does not prove equivalence to an authenticated upstream release, cover
`build.rs` or `Cargo.toml`, or establish algorithm conformance. No external
upstream comparison or new cryptographic known-answer certification is claimed
by the CR-09 correction. See `NOTICE` for attribution and licensing basis.

## Scoped deterministic generation (CR-08)

```rust,ignore
let (pk, sk) = pqcrypto_internals::with_seeded_rng_scope(&seed, || {
    pqcrypto_mldsa::mldsa65::keypair()
});
```

The closure API owns its cleanup guard. Normal return and Rust unwinding remove
its override and any nested legacy overrides, even if a nested guard is
forgotten or returned. An outer stream resumes at its prior position. Scope
cleanup identifies its entry rather than assuming stack length is unchanged.
The scope is synchronous: it does not cover later polling of a returned future.
Other threads are unaffected; no active override means OS entropy is used.

The legacy `with_seeded_rng` guard API remains compatible. Dropping its guard
removes exactly its entry, including out-of-order drops. Destruction after the
RNG thread-local has already been destroyed is safe; late entropy requests use
the OS. Forgetting a standalone legacy guard still leaves the override active
until thread exit; a new scope does not remove overrides created before it.
Do not put signing operations under deterministic key-generation scopes.

CR-08 remains **partial**: `rand_chacha` 0.9 exposes no guaranteed zeroization
of its opaque RNG state. Removing an entry drops it but does not promise to
wipe its internal key, buffered output or compiler copies. This patch does not
use layout-dependent unsafe wiping or replace the derivation stream. Aborts
and forced termination do not execute scope destructors.

## Validation

Regressions cover scope return/unwinding, forgotten nested guards, returned
guards, outer-stream resumption, out-of-order removal and TLS destruction.
Existing first-party wallet derivation golden tests remain the compatibility
check for the unchanged byte stream; the vendor pin test is a separate source
integrity check.

## License

MIT OR Apache-2.0, as declared in the crate manifest.
