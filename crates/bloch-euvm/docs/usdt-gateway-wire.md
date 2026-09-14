# Native gateway transport v1

`ustav::gateway::wire` provides bounded binary `encode`, `decode` and
`apply_encoded` for imports and withdrawals. It is a transport adapter for the
reference gateway, not an RPC server, a transaction type accepted by Genesis4,
or an external-finality verifier. Asset registration and route enablement remain
explicit separately authorized setup operations.

## Canonical envelope

Fields are concatenated without padding. Integers are little-endian; counts and
blob lengths are u32. Fixed hashes and addresses retain their raw byte order.
This envelope encoding is distinct from the big-endian ABI-word IDs shared with
the source vault; it does not change those IDs or any authorization digest.

1. Eight ASCII bytes `USTVUSDT`, u16 version 1, u8 operation, native domain32.
2. Operation 1 (import): route32, nonce u64, sender20, amount u64,
   recipient-key-hash32, source-transaction32, source-block32, event-index u32,
   certificate-valid-until u64.
   Operation 2 (withdraw): route32, nonce u64, recipient20.
3. Complete native transaction and witnesses in the same field order as each
   leg of [pair transport](native-pairs-wire.md). The internal codec is shared;
   owners, module redeemers and eligibility proofs are preserved.
4. Committee approval count, then length-prefixed signature bytes for each
   configured signer slot. Empty slots represent absent signers, not reordered
   or compacted certificates.

There is no trailing extension field. Unknown versions/operations, oversized
counts, malformed witness shapes, noncanonical proof ordering and trailing
bytes are rejected. The envelope limit is three native witness budgets (3 MiB);
size is checked before decoding allocations, and each count/blob is bounded
before iteration or copying. Native limits and the 16-member committee ceiling
still apply independently.

## Dispatch and state

The dispatcher charges `100 + ceil(encoded_bytes / 32)` gas before dispatching
the remainder to the gateway. It checks the domain against the sealed ledger.
The host supplies authenticated height, verifier and gas budget; they never
come from the envelope. Receipt gas includes decoding and transition work.
All state changes go through `GatewayLedger::import` or `withdraw`, preserving
source inventory, native supply, nullifiers and the full-signature scope. A
withdrawal returns the deterministic release record alongside its receipt.

This dispatcher targets a standalone gateway. A host using `PoolLedger` must
use `PoolLedger::apply_encoded_gateway`, which accepts the same envelope and
retains the outer reserve lock checks and complete gas accounting. It must not
extract a mutable inner gateway or persist only its state.

The host must persist the complete gateway state and authenticate its root
against accepted consensus state. A snapshot and expected root supplied by the
same untrusted peer do not establish authenticity. See the
[consensus integration plan](../../../docs/integration/BLOCH-L1-DEX-CONSENSUS-PLAN.md).

Tests cover successful direct/encoded state equivalence, imports and burns,
all truncated prefixes, invalid headers/counts, trailing data, invalid committee
and native witnesses, cross-domain dispatch, expiry, replay, forged signatures
and exact/insufficient gas without partial state changes.
