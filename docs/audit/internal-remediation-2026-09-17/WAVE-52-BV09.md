# Wave 52 BV-09: non-cloneable vault key aggregate

Date: 2026-09-18. Starting point: `c8ab7c8`. Scope: the Rust ownership
surface of `bloch-pq-vault::VaultKeys`, focused tests and ledger wording. No
derivation, key bytes, signature, funded script, wire format, service,
deployment or protocol rule changed.

## Local hardening

Earlier remediation added `Zeroize` and `Drop` to clear the PQ secret vector
and best-effort erase the two owned secp256k1 keys. `VaultKeys` still derived
`Clone`, however, so one ordinary method call duplicated all three private
keys into a second independently owned aggregate. Dropping or explicitly
zeroizing the first object could not affect that copy.

`VaultKeys` no longer implements `Clone`. Repository search found no production
consumer of that method; the only call was the old regression demonstrating
that the duplicate survived. The explicit-wipe regression remains and a
compile-fail doctest now prevents accidental restoration of whole-object
cloning. This is intentionally a Rust API hardening change, not a migration or
reinterpretation of any existing vault.

## Validation

- `cargo test --locked -p bloch-pq-vault --offline`: 42 unit tests passed;
- the new non-Clone compile-fail doctest passed;
- repository search found no remaining `VaultKeys::clone` consumer;
- `git diff --check` passed for the scoped files.

## Honest residual boundary

BV-09 remains `PARTIAL`. The secret fields remain public for compatibility and
a caller can still make an explicit byte copy. The secp256k1 `SecretKey` type is
`Copy`, so registers, compiler temporaries and caller-held copies cannot be
wiped by this aggregate's destructor. BIP32 and cryptographic-library internal
state, the HKDF input borrow, allocator behavior, process memory, swap, crash
and OS/hardware capture are also outside this local guarantee. Removing one
convenience duplication path is not proof that all secret material is erased.

Ledger aggregate counts are unchanged. No production adoption or external
audit evidence is claimed.
