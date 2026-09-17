# Wallet audit follow-up — 2026-09-17

These changes are local release candidates. No funded keys, address encoding,
protocol domains, network gates or deployed wallet files were changed.

| Finding | Change | Remaining limitation |
| --- | --- | --- |
| CR-05 | `Wallet::build_tx` rejects recipient addresses from another network before constructing outputs. Both directions are tested with identical address payload hashes. | The historical checksum does not bind the network prefix. Its encoding remains unchanged for compatibility; this is a wallet-boundary mitigation. |
| CR-06 | `DisclosureKeyConvention` and `create_with_convention` explicitly support HD v3's diversified index zero. Existing `create`/`keypair_at` preserve the single-key wallet convention. Tests compare both with actual HD derivation and verify their disclosure signatures. | Consumers must select the family recorded by their wallet. The unchanged disclosure format proves control of included addresses, not common-seed origin or the selected derivation convention. |
| CR-07 | Checked arithmetic for empty-wallet amount/fee and aggregate UTXO sums; checked `new_address` index increment; a 4,096-address per-call recovery-work limit; malformed AES key lengths return errors. HD KDF input and serialized plaintext payloads use zeroizing ownership. | This is not a complete hostile-wallet-file or secret-memory audit. Both import entry points now return errors at index exhaustion (see the Wave 5 source API change below). |
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

## Wave 5: hostile metadata and imported-index exhaustion (CR-07)

`try_import_keypair` returns an error before modifying an exhausted wallet.
`import_keypair` also returns `Result<(), String>` instead of the historical
unit return. This is an explicit source API change: downstream callers must
handle the result. Neither entry point panics or wraps at exhaustion, and no
failed import is silently treated as successful. The historical founder-import CLI uses the
fallible method and exits before saving on failure. Import consumes its supplied
keypair even on error; its independent backup must be retained.

HD restore rejects duplicate indices, unsupported file versions/networks and
derived-address/network mismatches before the expensive KDF. Imported and
pre-v3 keys may retain their existing cross-network addresses. Versions 1/2/3 and their
existing KDF parameters, stored keys and funded addresses remain unchanged; a
maximum index remains readable, though adding an address requires available
index space. The subsequent authenticity check below validates claimed-derived
keys; imported key-pair authenticity remains a separate concern.
No arbitrary total-wallet size/address-count limit is added by this change.

## Follow-up: derived-key authenticity and explicit raw verification

CR-07: HD restore now regenerates each entry explicitly marked `derived` using
its existing mnemonic/passphrase/index derivation, and compares both stored
public and private key bytes. It rejects mismatched claims instead of replacing
stored keys or accepting an address whose mnemonic backup would recover a
different key. Entries marked imported (including missing flags in legacy files)
retain their original keys. This does not authenticate imported key pairs; a
malformed imported key remains a separate validation concern. Regenerating
claimed-derived keys adds per-key unlock work and retains the existing Falcon
cross-platform derivation caveat. Load-time encryption keys, derived seed and
decoded private buffers now use zeroizing guards on error paths as well as
success; no guarantee is made about dependency/compiler copies.

CR-10: `crypto::verify_legacy_hybrid_raw` is an explicit raw-format verifier for
callers with trusted format context. It never sniffs signature magic bytes and
requires a raw-length hybrid public key. The existing `verify` and all consensus
callers remain unchanged. Do not retry failed untrusted envelope verification
through the raw API: format selection belongs to authenticated context. The
regression uses fresh real signatures from the existing primitive libraries;
it is not an independently sourced standard known-answer vector and does not
claim a generated valid magic-collision fixture. Historical automatic signature
classification remains a consensus compatibility issue, so CR-10 is partial.

## Bounded wallet file reads (CR-07, partial)

HD, current single-key and legacy keystore loaders now read at most 64 MiB plus
one sentinel byte before parsing or KDF work. They reject oversized input using
actual bytes read, not a potentially stale metadata length. Existing load method
signatures remain unchanged. Explicit `load_with_file_limit` (HD) and
`load_encrypted_with_file_limit` (both single-key APIs) accept a recovery budget
between 1 byte and 512 MiB for authenticated large backups; they never truncate
and accept a prefix. Existing encryption formats and key derivations are unchanged.

The limit is an input-byte budget, not a total memory or execution-time guarantee:
JSON/decoded allocations, per-address derivation and KDF work remain additional.
Special files can still block on reads. No claim of arbitrary hostile-file safety
or imported private/public key authenticity follows from this bound.

## Keyfile KDF output cleanup on errors

Both v1 and v2 encrypt/decrypt paths now hold their locally derived AES key in
`Zeroizing<[u8; 32]>`. Wrong-password, AEAD, and KDF early returns therefore use
the same owned-buffer cleanup as success. Existing wrong-password and public-key/
network AAD tampering regressions exercise these error paths. This does not prove
absence of compiler copies or erasure of AES dependency-internal expanded keys.
Ciphertexts, KDF parameters, AAD and funded key derivations are unchanged.
