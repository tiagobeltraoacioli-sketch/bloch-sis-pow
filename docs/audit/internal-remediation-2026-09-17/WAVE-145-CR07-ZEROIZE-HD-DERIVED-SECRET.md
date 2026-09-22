# Wave 145 — CR-07 zeroize the HD-derived secret owner

Date: 2026-09-19
Comparison base: `1f3509dd`

## Residual addressed

The private `derive_at` helper received the secret-key `Vec` returned by
`crypto::diversified_keypair` into an ordinary local owner. It then derived the
address from the public key before transferring the secret into `Keypair`,
whose `Drop` implementation wipes the final private-key owner. The intermediate
window was repository-owned but not yet protected by wiping drop.

All four production paths converge on `derive_at`: new HD-wallet creation,
mnemonic recovery, new-address derivation, and the loader's authenticated
mnemonic/index rederivation check.

## Correction and invariants

The private `hd_private_key_owner` helper moves the returned allocation directly
into `Zeroizing<Vec<u8>>`. `derive_at` computes the same address from the same
public key, then uses `mem::take` only when constructing the final `Keypair`.
There is no clone or reallocation in either ownership transfer.

The same diversified derivation, seed, index, network selection, private/public
bytes and address remain in use. No public API, wallet schema, serialization,
KDF, RNG operation or output changes. The existing `Keypair` drop behavior
continues to wipe the final owner.

## Adversarial coverage

- `hd_private_key_owner_preserves_allocation_and_wipes_while_live` pins the
  helper's exact `Zeroizing<Vec<u8>>` type, proves pointer, capacity and content
  identity across the move, and exercises explicit live zeroization.
- `hd_derivation_keeps_private_public_and_address_bytes` spans indices 0, 1
  and 7 and both mainnet and testnet cases, comparing the complete
  private/public bytes with the unchanged diversified-key primitive and the
  exact derived address.

Existing create/recover/new-address/load authentication regressions exercise
the four production consumers.

## Validation

```text
cargo test -p bloch-crypto \
  hd_private_key_owner_preserves_allocation_and_wipes_while_live \
  --offline -- --nocapture
# 1 passed; 0 failed; 225 filtered out

cargo test -p bloch-crypto \
  hd_derivation_keeps_private_public_and_address_bytes \
  --offline -- --nocapture
# 1 passed; 0 failed; 225 filtered out

cargo test -p bloch-crypto hd_wallet:: --offline
# 28 passed; 0 failed; 198 filtered out

cargo test -p bloch-crypto --features wallet-cli --offline
# 239 passed; 0 failed; 4 ignored
```

The complete wallet-CLI suite ran outside the sandbox so its localhost HTTP
fixtures could bind. Its total is 233 passing unit tests plus six passing
integration tests; two unit tests and two doctests are ignored.

## Residual boundary

- The public `crypto::diversified_keypair` API still returns caller-owned
  vectors for compatibility; this change owns only the HD wallet's private
  consumer immediately after return.
- PQ backend state, allocator/compiler/register copies and aborts that skip
  destructors remain outside the claim.
- No post-`Drop` memory observation is claimed; the ownership type and explicit
  live-zeroize regression provide structural evidence.
