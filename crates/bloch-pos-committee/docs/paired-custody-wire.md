# Paired custody binary transport

The default-off `native-dex-rehearsal` feature exposes
`native_dex::paired_custody::wire::{encode, decode, apply_encoded}`. This is a
local transport for the existing paired reserve creation operation. It does
not add an RPC method, wallet connection, block transaction tag, closing
operation or consensus activation.

## Version 1 format

The format preserves the bytes previously returned by
`paired_custody::Request::canonical_bytes`. Integers use little-endian encoding;
hashes and domains are raw fixed-width byte arrays.

| Field | Encoding |
| --- | --- |
| Magic | Eight ASCII bytes `BLCHPAIR` |
| Version | `u16`, exactly 1 |
| Network domain | 32 bytes, nonzero and equal to the host's expected domain |
| Expiry height | `u64` |
| Prepaid native work | `u64` |
| BLCH section length | `u64` |
| BLCH intent and witnesses | Canonical `PosTransaction::TransferV2` bytes |
| Native section length | `u64` |
| Native intent and witnesses | Canonical `transfer_wire` envelope |
| Custody seed | 32 bytes |
| BLCH reserve amount | `u64` |
| Native reserve amount | `u64` |

The fixed framing occupies 122 bytes, in addition to the two sections. The
entire message is bounded by `MAX_ENVELOPE_BYTES`; each section is also bounded
before its decoder allocates. The BLCH preflight accepts exactly one key,
bounded key/signature lengths, nonempty funding and reserve outputs, and the
rehearsal's input/output count limits. The native section retains its own
bounded, zero-delta transfer format. Oversized declared counts do not cause
proportional allocations or iteration through nonexistent entries.

The decoder rejects unknown headers, versions and BLCH operations, truncation,
trailing bytes, domain mismatches and noncanonical representations. Its final
re-encoding must exactly match the supplied bytes. An envelope cannot select a
different authenticated network or silently fall back to another operation.

## Authorization and execution

`decode` validates representation, not signatures, available funding or bridge
backing. A syntactically valid request can still be expired, underfunded,
unbalanced or signed by the wrong owner. `apply_encoded` decodes against the
domain already held by the complete `State`, then calls the existing sealed
`execute_paired_custody` dispatcher. Both PQ signature checks, per-asset
conservation, reserve locks, replay protection and atomic commit remain there.

The same complete witness-bearing bytes determine the existing fee quote.
There is no additional fee for passing through this decoder, nor an alternate
free execution path. Typed and encoded requests produce the same transaction
identities, reserves, receipts, fees and state root.

Restore the complete authenticated paired state before replaying messages.
Neither decoded requests nor native-only snapshots authorize extracting or
spending a reserve outside that state.

## Verification

```sh
cargo +1.94.1 test --locked -p bloch-pos-committee --features native-dex-rehearsal --lib native_dex
cargo +1.94.1 test --locked -p bloch-ustav --test paired_custody_crypto
```

The cryptographic integration tests compare typed and encoded execution using
real hybrid PQ signatures, reject malformed frames and tampered witnesses,
and reject replay after complete state restoration. These are local test
assets and UTXOs; the tests do not deposit external USDT or transfer live BLCH.
