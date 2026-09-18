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

## Transaction-builder hostile inputs (CR-07, partial)

The CLI's legacy `TxBuilder` rejects transaction IDs whose decoded length is not
exactly 32 bytes; the previous copy panicked for short IDs and silently truncated
long ones. It checks selected-value addition, requires a 20-byte destination hash,
and refuses duplicate outpoints before signing. The current `Wallet::build_tx`
also refuses duplicate outpoints. Distinct output indices of one transaction
remain valid inputs. Regressions cover every refusal and successful distinct-index
selection. These checks do not authenticate RPC UTXOs, establish key ownership or
replace node validation. Existing valid transaction encoding/signing is unchanged.

## Optional network client and standalone CLI input checks

With the `node` feature, balance aggregation now refuses `u64` overflow and RPC
output indices must fit `u32`; larger indices cannot silently identify a different
outpoint. The `wallet-cli` parser refuses any malformed UTXO row instead of silently
filtering it, checks amount-plus-fee addition, and verifies the recipient network
before converting its address to an untagged hash. CLI amounts now use
exact decimal input without floating point. Negative/nonfinite/out-of-range values,
more than eight fractional digits, exponent notation and zero-satoshi payments
are refused; zero fees remain accepted. These validations do not authenticate RPC
state, alter chain IDs or modify valid transaction/signature formats.

The retained Genesis-3 `bloch-cli` send caller receives the same checked index,
complete-row, aggregate-value and network validation. It now shares exact decimal parsing with the standalone wallet rather than
truncating a floating-point value; ambiguous sub-satoshi or exponent input is
explicitly rejected. Unit tests compile and exercise that legacy binary directly; this does
not modify Genesis-3 consensus or republish a retired node.

## Exact CLI amount compatibility

Both CLI entry points retain their existing fee defaults but parse original
amount/fee tokens as decimal strings with at most eight fractional digits.
`90071992.54740993` now represents exactly `9007199254740993` satoshis, beyond
floating-point integer precision. `184467440737.09551615` reaches `u64::MAX`
exactly; one more satoshi is refused. Signed/exponent notation and more than eight
fractional digits are no longer accepted or rounded/truncated. Supply ordinary
decimal notation instead. This is an input-syntax tightening, not a transaction,
consensus, key or address-format change.

## HTTP response budgets and peer error redaction

The optional `WalletClient` retains its 30-second request timeout and now limits
successful response bodies to 64 MiB. It rejects oversized advertised lengths and
counts actual chunks before appending them, including responses without a length.
The buffer grows with received data instead of allocating the full budget up front.
This bounds input bytes, not all transport or parsed JSON allocations. Responses
above the cap are refused; callers with large accounts need bounded RPC queries.
HTTP failures report status only, without downloading or echoing the peer body.
JSON-RPC failures retain a numeric code but omit arbitrary peer message/data fields.
Successful result schemas and transaction formats remain unchanged. Loopback HTTP
regressions exercise chunked over-limit/exact-limit reads, advertised oversize, and
both HTTP and JSON-RPC error redaction.

## RPC correlation and G4 status compatibility

Each HTTP client now assigns monotonically increasing numeric request IDs with
checked atomic allocation. Exhaustion fails before sending a request; IDs never
wrap or repeat within that client. Responses must identify JSON-RPC 2.0 and echo
the exact integer ID. Missing results, malformed errors and envelopes containing
both a result and a non-null error are refused. A null result remains valid, and
`error: null` remains accepted beside a successful result for compatibility.
These checks correlate responses; they do not authenticate a dishonest RPC node.

`TxStatus` retains G3 `Confirmed` and depth-based `Final` variants and adds
separate G4 `Included`, `Justified` and `Finalized` variants. No confirmation depth
is invented for G4. `Finalized` represents the queried node's statement, not an
independently verified checkpoint. The public enum addition requires downstream
exhaustive matches to handle the new variants; repository callers were checked.
Malformed/missing status fields now return an error; unknown future strings remain
`Unknown`. Existing valid G3 status responses remain supported.

This status support does not make the legacy wallet transaction client a complete
G4 wallet adapter. G4 balance/UTXO requests use 32-byte script hashes and expose
`balance_sat`, `vout`, `value_sat` and `script_hash`; the existing wallet methods
use address-based G3 schemas and transaction types. A separate reviewed adapter
is required rather than silently aliasing fields or truncating amounts/hashes.

## HTTP endpoint and initialization boundaries

`WalletClient` refuses redirects, including 307/308 responses that could otherwise
replay a signed transaction or query body to a different endpoint. Configure the
final RPC URL directly. Transport errors remove attached URLs before display so
query credentials and endpoint paths are not reflected. A loopback regression
checks that a redirect target is never contacted and connection errors omit a
synthetic query token. Existing HTTP/HTTPS endpoint acceptance is unchanged.

New `try_new` allows callers to handle HTTP transport initialization failure.
The existing `new` signature remains compatible and retains its documented panic
contract; this is not complete elimination of constructor panics. The two
standalone CLI callers now share the bounded synchronous transport described
below. They remain HTTP-only compatibility tools, separate from the asynchronous
`WalletClient` implementation and its HTTPS support.

## Shared bounded CLI HTTP transport

Both standalone wallet and retained Genesis-3 CLI now use `wallet::http_rpc` for
synchronous HTTP RPC. Response framing is parsed as bytes before JSON/UTF-8:
valid UTF-8 split across HTTP chunks is reconstructed, while malformed lengths,
size overflow, truncation, ambiguous Content-Length/Transfer-Encoding and trailing
bytes are rejected. Chunk extensions and trailers are not supported and are
explicitly refused. Normal G3 length-delimited, chunked or connection-close JSON
responses remain accepted. Requests explicitly ask the peer to close the connection.

The transport bounds decoded bodies to 64 MiB and received wire bytes to that
budget plus 64 KiB; HTTP headers have a separate 64 KiB ceiling. Memory for parsed
JSON and temporary decoding buffers is additional. One monotonic 30-second
budget covers name resolution, connect, each write and each read, so a slow drip
cannot reset an idle timeout. The OS DNS worker can outlive a caller timeout;
this does not claim resolver cancellation or a hard scheduler wall-clock bound.

HTTP and JSON errors do not echo arbitrary peer bodies; RPC error codes remain
available. Legacy API-key authentication remains supported and control characters
are refused before connecting. The standalone caller still supports HTTP, not TLS;
non-root paths now fail instead of being silently discarded. JSON-RPC 2.0 and the
matching request ID are required. CLI response-schema/transaction semantics remain
G3; this is not a complete G4 wallet migration.

The retained G3 server's actual `rpc_handler` wraps successful dispatch results in
`jsonrpc: "2.0"`, echoed `id`, and `result`; authentication/rate-limit failures use
structured JSON-RPC errors and non-success HTTP status. Bare JSON and string-valued
outer errors formerly tolerated by the legacy CLI are now deliberately refused.
This redacts transport/envelope errors, not successful application result fields.
