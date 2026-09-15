# Durable local DEX candidate journal

Enable `bloch-ustav/native-dex-host` explicitly to use `dex_journal::Journal`.
The default adapter and the default live node do not enable this host. It
persists existing pool candidates and reconstructs the complete combined State
by replay, rather than introducing an independent balance database or snapshot
serialization format.

## Ownership and commit ordering

The Journal owns a State and an exclusively locked regular file. Its path and
containing directory must be operator-controlled; they are not RPC parameters.
Locks are advisory and do not defend against another process that deliberately
ignores them. Creation uses `create_new`, Unix mode 0600, file synchronization
and parent-directory synchronization. This host is tested on Unix filesystems.

Both append and replay use fixed production `BlochVerifier` checks for the
ML-DSA-65/Falcon-1024 suite, including PQ public-key admission for BLCH signatures.
The API does not accept a caller-supplied permissive verifier.

Append checks resource limits and increasing host height, reexecutes the
candidate through an opaque prepared operation with an exclusive State borrow,
writes the length and exact validated candidate bytes,
and calls `sync_all`. Only after synchronization succeeds does it install the
new in-memory State and return success. Invalid signatures, incorrect roots or
other candidate failures leave the file and state unchanged. Any write or sync
error poisons the handle: further appends fail until it is dropped and reopened.

A sync failure is an uncertain disk outcome: a full record might be present even
though the caller received an error. The in-memory checkpoint remains the last
confirmed one. The host must reconcile the file against independently accepted
chain context; it must not treat a complete disk record alone as authorization.

## Anchors and recovery

`create(path, anchor_state, anchor_height)` begins a new journal.
`open(path, anchor_state, anchor_height, expected_head, recovery)` requires both
the authenticated anchor State and a separately trusted expected final height
and combined root. The journal cannot establish these trust anchors itself.
Returning its own checkpoint next to an untrusted file does not authenticate it.

Replay verifies the anchor header, bounded records, strictly increasing heights,
all signatures, parent commitments and computed final roots. The resulting
height/root must match `expected_head`. Removing complete records therefore
cannot silently restore an older accepted state. A checkpoint at the wrong
anchor, a complete corrupt record or an invalid length fails closed.

`TailRecovery::Reject` reports any incomplete final length or body.
`DiscardIncomplete` permits truncation of that physical final fragment only
after the fully replayed prefix matches the trusted expected head; truncation
is then synchronized. It never skips a complete invalid candidate, malformed
length or mismatch with the expected head. An incomplete initial header is not
repairable through this API. Startup failures leave no usable Journal instance.

## Format and limits

The 48-byte header contains `BLCHDJ01`, an eight-byte little-endian anchor height
and the 32-byte anchor root. Each record is a four-byte little-endian candidate
length followed by the unchanged `BLCHPCAN` bytes. Candidate validation supplies
the ordered body commitment and independently verified resulting state; the log
does not duplicate a second state encoding or accept receipt claims.

The append path no longer makes an outer full-State clone before the candidate
executor creates its staged State. It retains the original plus one complete
staged State, rather than the original plus two complete clones. This removes a
redundant copy; no measured RSS or throughput improvement is claimed. Internal
ledger planning and replay costs still need production-scale calibration.

The journal is limited to 64 MiB and 4,096 records, checked before allocating
payload buffers. Individual records retain the candidate limit of 263,316 bytes.
The complete file is streamed, one bounded candidate at a time. Replay is linear
in record count and requires the original authenticated anchor. Checkpoint
rotation/compaction is not implemented.

The optional [admission queue](dex-admission.md) assembles signed operations
against one journal checkpoint and commits through this same durable boundary.
Its previews and pending frames do not change the journal.

## Validation and remaining integration

Real PQ integration tests cover durable append/reopen, dependent appends after
restart, exclusive locking, permissions, invalid candidates, corrupt records,
removed complete records, resource limits and partial trailing writes. Fault
injection checks every partial-write boundary and sync failure, including refusal
of subsequent writes through a poisoned handle.

This local host does not select a canonical chain, implement fork choice/reorg
selection, obtain checkpoints from consensus, advance the base fee record or
settle producer rewards. Journal height is host context, not a new consensus
height field. Nodes, wallet signing and finalized bridge authorization remain
separate integration work. Persisting a candidate does not authorize USDT minting
or an external payout.

```sh
cargo +1.94.1 test --locked -p bloch-ustav --features native-dex-host --lib --test blch_add_crypto
```
