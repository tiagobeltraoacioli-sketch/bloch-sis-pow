# Wave 133 — CR-07 zeroize discarded diversified secret

Date: 2026-09-19
Comparison base: `ffe8952e`

## Residual addressed

`crypto::diversified_address` derives a complete diversified hybrid keypair
because the address commits to its public half. The function previously used
`let (pk, _)`, so the repository itself discarded the returned secret-key
`Vec<u8>` with ordinary `Vec` destruction. Its allocation was released without
an explicit zeroization contract.

Wave 87 protected the per-index sub-seed consumed by
`diversified_keypair`. Wave 94 protected the additional pre-envelope secret
temporaries inside hybrid key generation. Neither covered this final
caller-owned secret-key vector when `diversified_address` was itself the
caller and intentionally discarded it.

## Change and compatibility

`diversified_address` now binds the secret output, immediately moves its
allocation into `Zeroizing<Vec<u8>>` without cloning, derives the address from
the unchanged public key, and drops the zeroizing owner before returning.

The public APIs, diversified-seed domain and index encoding, key-generation
order, KDF/RNG behavior, suite envelope, public and secret key bytes, address
format and address bytes are unchanged.

## Validation

```text
cargo test -p bloch-crypto \
  diversified_address_matches_public_half_and_owns_discarded_secret \
  --offline -- --nocapture
# 1 passed; 0 failed; 221 filtered out

cargo test -p bloch-crypto \
  diversified_addresses_are_distinct_deterministic_and_valid \
  --offline -- --nocapture
# 1 passed; 0 failed; 221 filtered out

cargo test -p bloch-crypto --features wallet-cli --offline
# library: 229 passed; 0 failed; 2 ignored
# wallet binary: 0 tests
# integration: 6 passed; 0 failed
# documentation: 2 ignored
# total: 235 passed; 0 failed; 4 ignored
```

The complete suite ran outside the restricted sandbox so its HTTP tests could
bind loopback sockets. Compiler output contained only the existing workspace
profile/patch warnings.

The new table-driven regression covers mainnet and testnet at index zero, a
nontrivial interior index and `u32::MAX`. For each case it compares the public
helper result with the address derived directly from the public half of the
same diversified keypair. It also pins that `Zeroizing<Vec<u8>>` has drop
behavior. This is structural evidence for the production owner type; no test
reads storage after `Drop`.

## Residual boundary

CR-07 remains `PARTIAL`. This correction covers only the final secret-key
vector intentionally discarded inside `diversified_address`. Callers of the
public `diversified_keypair` API remain responsible for their returned secret
owner. This change does not claim to erase cryptographic/RNG backend state,
allocator/compiler/register copies, caller inputs, external storage, or
process-abort paths that skip destructors.
