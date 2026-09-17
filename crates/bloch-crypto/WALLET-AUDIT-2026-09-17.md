# Wallet audit follow-up — 2026-09-17

These changes are local release candidates. No funded keys, address encoding,
protocol domains, network gates or deployed wallet files were changed.

| Finding | Change | Remaining limitation |
| --- | --- | --- |
| CR-05 | `Wallet::build_tx` rejects recipient addresses from another network before constructing outputs. Both directions are tested with identical address payload hashes. | The historical checksum does not bind the network prefix. Its encoding remains unchanged for compatibility; this is a wallet-boundary mitigation. |
| CR-06 | `DisclosureKeyConvention` and `create_with_convention` explicitly support HD v3's diversified index zero. Existing `create`/`keypair_at` preserve the single-key wallet convention. Tests compare both with actual HD derivation and verify their disclosure signatures. | Consumers must select the family recorded by their wallet. The unchanged disclosure format proves control of included addresses, not common-seed origin or the selected derivation convention. |
| CR-07 | Checked arithmetic for empty-wallet amount/fee and aggregate UTXO sums; checked `new_address` index increment; a 4,096-address per-call recovery-work limit; malformed AES key lengths return errors. HD KDF input and serialized plaintext payloads use zeroizing ownership. | This is not a complete hostile-wallet-file or secret-memory audit. The historical void `import_keypair` API still requires a separate exhaustion/error-return migration. |
| BV-09 | `VaultKeys` clears its owned PQ secret vector on drop; clones each own their wiping path. Temporary V2/V3 PQ seeds and the BTC identity helper's discarded PQ secret are zeroizing. | Classical `SecretKey` values are Copy and use the library's explicitly best-effort erase. Caller copies, BIP32 intermediate objects, registers, allocator/OS copies and third-party crypto internals are outside this guarantee. |
| BV-19 | `derive_vault_keys_versioned` is a fallible restoration entry point requiring the stored V1/V2/V3 family. Valid outputs match the existing functions, including pinned V1 compatibility tests. | The old unversioned V1 convenience function retains its historical panic-on-invalid-input contract; untrusted seed input must use the fallible API. |

## Compatibility and integration notes

- Never switch an existing wallet's index-zero convention or a funded vault's
  derivation version to make a disclosure/address comparison pass. Select the
  existing family explicitly; migration of funds is a separate operation.
- `VaultKeys` now implements Drop. Code moving public Vec fields out of it must
  borrow/clone the public material instead. The field types and key bytes are
  unchanged. Taking secret ownership out manually also transfers responsibility
  for wiping that allocation to the caller.
- The HD recovery call rejects counts above 4,096 before allocating or running
  the password KDF. Loading existing wallet files remains supported; no stored
  address count or index is rewritten by this change.
- The explicit wipe regression checks owned buffers while they are still
  allocated. It deliberately does not read freed memory or claim to prove
  erasure of compiler-created copies.
- `zeroize` is added as a direct dependency to the vault/BTC-wallet crates using
  the already-resolved workspace version. No cryptographic dependency upgrade
  or new seed domain accompanies these ownership changes.
