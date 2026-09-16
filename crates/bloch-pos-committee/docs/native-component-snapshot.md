# Canonical native component snapshot v1

`NativeState::encode_snapshot` and `NativeState::restore_snapshot` provide a
bounded binary transport for the opaque native component behind the opt-in
`native-dex-rehearsal` feature. They do not change consensus state roots, attach
restored components, enable populated-state imports or arm activation gates.
The node's optional `native-component-snapshots` feature persists this transport
as a derived sidecar and restores it only after complete canonical replay.
These methods do not provide an accelerated base-state restart format.

Restore takes bytes, a borrowed corresponding `CommittedState`, an independently
authenticated native component commitment and the native key verifier. It
clones the base projection for custody validation without modifying its caller.
A commitment carried by an untrusted snapshot or a bare RPC report is not an
authenticated trust anchor. The component commitment remains distinct from a
canonical state root, block ID, rehearsal journal root and finality proof.

## Encoding

The header is the eight ASCII bytes `BLCHNS01` followed by little-endian `u16`
version `1`. The payload contains, in order:

1. Native domain (32 bytes), pool-ledger root (32 bytes), and complete pool-ledger
   snapshot: version, gateway snapshot and root, pool snapshots, LP positions and
   custody records.
2. Base reserve records, paired reserve records, and BLCH/native pool records,
   including their initial reserves and all LP positions.

The nested gateway snapshot includes native registrations/charters, token supply
and policy counters, unspent outputs, routes/committees, source import identities
and native release history. Nested snapshots retain their own existing versions
and roots. No compiled programs, mutable ledger internals or derived indexes are
accepted from the transport.

All integers use fixed-width little-endian encoding. Byte arrays retain their
fixed length; collection counts are `u32`. Booleans and optional-value tags are
exactly `0` or `1`. Module tags `1` through `6` represent Supply, TransferPolicy,
ComplianceKycGate, Vesting, Governance and Custody respectively. The codec lists
every field explicitly; Rust layout, debug strings and map hashing are unused.
Ordered source maps retain their canonical ordering. Trailing bytes, duplicate
or nonordered identities, unknown tags and alternate encodings are refused.

## Resource and restoration checks

Wire input/output is limited to 64 MiB; individual collections to 65,536 items;
declared collection payload allocations to 128 MiB. Decode checks counts against
remaining input and charges the allocation budget before reserving storage.
These are transport limits, not expanded ledger admission limits. Existing
stricter limits for tokens, keys, routes, pools and custody still apply during
semantic restore. Collection payload accounting excludes allocator metadata,
the caller's input/base state and the restored ledger's compiled/index storage;
it is not a promise about total process RSS.

Export checks the owned snapshot payload size before cloning nested ledger state.
The native component must have zero rehearsal fee escrow; nonzero escrow is
rejected rather than silently imported or lost. Restore uses existing native,
gateway and pool validators, validates reserves against the supplied base UTXOs,
rebuilds lock/reverse indexes and checks their resulting native commitment.
Finally, re-encoding must reproduce the exact supplied bytes.

Tests cover deterministic populated round trips, truncation at every byte,
invalid versions/trailing bytes, resource budgets, domain/commitment mismatches,
duplicate outputs, supply corruption, reconstructed custody/LP locks, gateway
import and release history, and replay refusal. Separate real block-transition
tests exercise restored populated fixtures, branches and subsequent execution.
Populated fixture creation remains test-only; this API is not a deployment or
asset-issuance interface.
