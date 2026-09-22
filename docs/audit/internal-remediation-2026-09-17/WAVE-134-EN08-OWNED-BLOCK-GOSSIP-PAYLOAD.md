# Wave 134 — EN-08 owned block gossip payload

Date: 2026-09-19
Comparison base: `ffe8952e`

## Residual addressed

Wave 87 bound a locally produced block's canonical bytes to its suppression
identity and removed an envelope clone and decode. One proportional copy
remained on the typed libp2p path: `PreparedBlockBroadcast` owned a tagged
devnet frame, then `handle_broadcast` split that frame and called
`payload.to_vec()` because gossipsub must own an untagged payload.

For a block near `MAX_PROPOSAL_ENVELOPE_BYTES`, libp2p therefore retained the
tagged allocation while allocating and copying the complete canonical payload
again. This was bounded by the existing proposal cap, but scaled with the
whole block rather than being a fixed framing cost.

## Correction and consumer proof

The private `PreparedBlockBroadcast` now owns the canonical untagged payload
and the block id derived from the same borrowed envelope. Its fields and
constructor remain private, so callers cannot pair arbitrary bytes with a
suppression id.

Transport behavior remains explicit:

- devnet-only still constructs `block_frame(env)` directly;
- libp2p moves the prepared payload through the private command and directly
  into gossipsub after the existing suppression check; and
- dual transport builds the tagged devnet frame from the borrowed prepared
  payload, then moves the original payload to libp2p. The one full-payload copy
  for the second independently owning transport remains necessary.

The private `prepared_block_payload_if_fresh` helper consumes and returns the
same `Vec` allocation only when `Loop::note_block` accepts the bound id. A
duplicate drops that allocation. The generic raw-frame command is unchanged:
generic blocks retain their best-effort decode, malformed blocks retain their
historical publish behavior, and attestations, transactions and directed sync
keep their existing routing.

No public API, canonical payload, devnet frame, gossip topic, suppression id,
wire limit, peer verdict, consensus, persistence or recovery behavior changes.
The patch does not use in-place tag removal, so a caller-controlled oversized
`Vec` capacity cannot become retained gossipsub capacity through this typed
path.

## Adversarial coverage

- `prepared_block_broadcast_binds_large_wire_bytes_and_exact_id` uses a one-MiB
  transaction body and proves exact canonical payload parity, exact devnet
  frame parity, and binding to `env.block_id()`.
- `prepared_block_payload_moves_same_allocation_and_suppresses_duplicate`
  proves pointer, length and capacity identity across the consuming handoff,
  then proves a second announcement of the same id is suppressed.
- `prepared_block_id_suppresses_without_decode_and_generic_fallback_is_unchanged`
  keeps the typed suppression/no-decode and generic canonical/malformed
  fallback behavior pinned.

## Validation

```text
cargo check -p bloch-pos-node --bin bloch-pos --offline
# passed

cargo test -p bloch-pos-node --bin bloch-pos \
  prepared_block_broadcast_binds_large_wire_bytes_and_exact_id \
  --offline -- --nocapture
# 1 passed; 0 failed; 608 filtered out

cargo test -p bloch-pos-node --bin bloch-pos \
  prepared_block_payload_moves_same_allocation_and_suppresses_duplicate \
  --offline -- --nocapture
# 1 passed; 0 failed; 608 filtered out

cargo test -p bloch-pos-node --bin bloch-pos \
  prepared_block_id_suppresses_without_decode_and_generic_fallback_is_unchanged \
  --offline -- --nocapture
# 1 passed; 0 failed; 608 filtered out

cargo test -p bloch-pos-node --bin bloch-pos --offline
# 590 passed; 0 failed; 19 ignored; 62.10s
```

The full binary suite was run by the root integration owner outside the
sandbox, including localhost socket coverage.

The broader `cargo check --tests` currently reaches the unrelated
`recovery_fence` integration target, whose direct inclusion of `store.rs` lacks
the binary's `crate::p2p` module while `store.rs` references
`crate::p2p::MAX_SYNC_FRAME`. This pre-existing integration-target compile
failure is outside the two production files changed here.

## Residual boundary

- Gossipsub must still own one final payload allocation and perform its own
  message hashing.
- Dual transport still requires one body copy because devnet and libp2p own
  independent outbound messages.
- Generic block frames intentionally retain the decode fallback, and generic
  attestation and transaction frames still copy away their routing tag. Those
  paths are not changed by this typed block-only correction.
- No exact heap/RSS reduction is claimed; allocator and libp2p internals are
  outside this focused ownership proof.
- Full node, hosted CI, Linux reproducibility, release signing, rollback and
  fleet qualification remain integration/release work.
