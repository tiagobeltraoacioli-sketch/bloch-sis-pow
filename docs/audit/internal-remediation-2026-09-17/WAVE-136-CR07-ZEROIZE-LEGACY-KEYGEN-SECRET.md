# Wave 136 — CR-07 zeroize legacy keygen secret owner

Date: 2026-09-19
Comparison base: `9b0e006a`

## Residual addressed

The legacy public `wallet::generate_keypair` constructor received the final
secret-key `Vec<u8>` from `crypto::generate_keypair`, derived the address from
the public key, and only then moved the secret into `Keypair`. `Keypair`
already wipes its private key on drop, but the repository-controlled interval
between the key-generation return and final construction used an ordinary
owner, including unwind during address construction.

## Change and compatibility

The constructor now immediately moves the returned private-key vector into the
existing private `wallet_secret_owner`, a `Zeroizing<Vec<u8>>` owner introduced
and allocation-tested in Wave 131. After deriving the unchanged address, it
transfers the same vector allocation with `mem::take` only in the final
`Keypair` construction. No clone or reallocation is introduced, and the final
`Keypair` retains its existing private-key wipe on drop.

The public `generate_keypair(bool) -> Keypair` API, RNG and hybrid keygen call,
suite envelope, public/private key bytes, address bytes and prefixes, signing
behavior, keystore format and failure behavior are unchanged.

## Validation

```text
cargo test -p bloch-crypto \
  legacy_keygen_preserves_address_and_signing_on_both_networks \
  --offline -- --nocapture
# 1 passed; 0 failed; 222 filtered out

cargo test -p bloch-crypto \
  wallet_secret_owner_preserves_allocation_and_wipes_while_live \
  --offline -- --nocapture
# 1 passed; 0 failed; 222 filtered out

cargo test -p bloch-crypto save_load_roundtrip_still_works \
  --offline -- --nocapture
# 1 passed; 0 failed; 222 filtered out

cargo test -p bloch-crypto --features wallet-cli --offline
# library: 230 passed; 0 failed; 2 ignored
# wallet binary: 0 tests
# integration: 6 passed; 0 failed
# documentation: 2 ignored
# total: 236 passed; 0 failed; 4 ignored
```

The complete suite ran outside the restricted sandbox so its HTTP tests could
bind loopback sockets. Compiler output contained only the existing workspace
profile/patch warnings.

The new regression exercises both network choices, checks that the returned
address is still derived from the exact public key, and signs/verifies a fixed
message through the resulting keypair. The existing Wave 131 ownership test
pins that moving a vector into `wallet_secret_owner` preserves its pointer,
capacity and contents and demonstrates zeroization while live. No test reads
storage after `Drop`.

## Residual boundary

CR-07 remains `PARTIAL`. The public crypto key-generation API necessarily
returns its secret-key vector before this repository constructor can move it
into the RAII owner. This correction covers only that constructor's ownership
window. Direct callers and returned secret owners, cryptographic/RNG backend
state, allocator/compiler/register copies, external storage and process-abort
paths that skip destructors remain outside the guarantee.
