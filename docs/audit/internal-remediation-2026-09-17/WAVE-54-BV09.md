# Wave 54 BV-09: private vault secret fields

Base: `db7b737`; branch `agent/wave54-bv09`.

## Scope

`VaultKeys` already wiped its owned secret storage on drop and no longer
implemented `Clone`, but its three secret-bearing fields remained public. A
downstream caller could clone the PQ `Vec`, copy either classical `SecretKey`,
or replace the owned values without any explicit secret-access boundary.

This wave makes `hot_sk`, `recovery_sk`, and `pq_secret` private. Explicit
borrow-only accessors provide the material needed by signing and recovery
operations:

- `hot_secret_key() -> &SecretKey`
- `recovery_secret_key() -> &SecretKey`
- `pq_secret_key() -> &[u8]`

Repository consumers use the borrowed PQ accessor. A compile-fail doctest
pins that an external caller cannot clone the owned PQ vector through direct
field access, while a unit regression checks that every accessor borrows the
aggregate's existing storage rather than allocating another owned secret.

This is a Rust source-API hardening: downstream code that directly accessed
these fields must migrate to the accessors. It changes no derivation, key byte,
signature, funded vault format, historical consensus rule, or deployment.

## Validation

- `cargo test -p bloch-pq-vault`: 45 unit tests and 2 compile-fail doctests
  pass.
- `cargo test --manifest-path services/pq-shield-api/Cargo.toml`: 19 unit tests
  pass (plus empty binary/doc-test targets).

## Residual risk

BV-09 remains `PARTIAL`. The upstream Bitcoin `SecretKey` type is `Copy`, so a
caller that deliberately dereferences a borrowed key can still create copies
that this crate cannot wipe. A caller can also explicitly copy bytes from the
PQ slice. Compiler temporaries, registers, allocator behavior, BIP32 state,
third-party crypto internals, process memory and OS crash/swap handling remain
outside the owned-storage guarantee. No external consumer migration or fleet
adoption is claimed.
