# Wave 94 — CR-07 zeroize hybrid key-generation temporaries

Date: 2026-09-19
Comparison base: `cb859d0`

## Residual addressed

Both public hybrid key generators assembled `ML-DSA-65 secret || Falcon-1024
secret` in an ordinary repository-owned `Vec<u8>`, then copied that body into
the final suite-enveloped `Vec<u8>` returned by the existing API. The Falcon
secret `Vec<u8>` received from the local Falcon wrapper also remained an
ordinary owner throughout this assembly. These additional pre-envelope owners
had no type-level cleanup contract.

The duplicated pattern existed in exactly two production functions:
`crypto::generate_keypair` and `crypto::generate_keypair_from_seed`.

## Change and compatibility

A private `hybrid_secret_body` helper now concatenates the two secret halves
directly into `Zeroizing<Vec<u8>>`. Both key generators move the Falcon secret
returned to them immediately into `Zeroizing<Vec<u8>>` without cloning, then
borrow both halves into the helper and borrow its result into the unchanged
suite-envelope encoder.

The public functions still return the same `(Vec<u8>, Vec<u8>)` types. Their
RNG flow, key-generation calls and order, suite ID, envelope format, component
order and output bytes are unchanged. The final returned secret-key allocation
remains caller-owned as required by the public API.

## Validation

```text
cargo test -p bloch-crypto \
  hybrid_keygen_secret_body_has_exact_zeroizing_ownership \
  --offline -- --nocapture
# 1 passed; 0 failed; 215 filtered out

cargo test -p bloch-crypto \
  golden_seed_to_keypair_is_byte_stable \
  --offline -- --nocapture
# 1 passed; 0 failed; 215 filtered out

cargo test -p bloch-crypto \
  crypto::tests::sign_verify_roundtrip \
  --offline -- --nocapture
# 1 passed; 0 failed; 215 filtered out

cargo test -p bloch-crypto --offline
# library: 214 passed; 0 failed; 2 ignored
# integration: 6 passed; 0 failed
# documentation: 2 ignored
# total: 220 passed; 0 failed; 4 ignored
```

The complete suite ran outside the restricted sandbox so its HTTP tests could
bind loopback sockets. Compiler output contained only the existing workspace
profile/patch warnings.

The structural regression pins the private helper's zeroizing return type,
checks exact concatenation order and bytes, and supports explicit zeroization
while the owner is live. The existing golden seeded-keypair KAT pins the exact
public and secret outputs; the random round-trip exercises the other producer.
No test claims to inspect storage after `Drop`.

## Residual boundary

CR-07 remains `PARTIAL`. This change covers only the additional secret owners
inside the two hybrid key generators. It does not claim to erase the final
caller-owned secret-key `Vec`, callers of the public Falcon wrapper, opaque
ML-DSA/Falcon backend objects or RNG state, allocator/compiler/register copies,
or external copies. Process aborts that skip destructors remain outside Rust
RAII guarantees.
