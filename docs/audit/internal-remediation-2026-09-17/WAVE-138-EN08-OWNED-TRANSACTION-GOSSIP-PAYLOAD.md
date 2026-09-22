# Wave 138 — EN-08 owned transaction gossip payload

Date: 2026-09-19
Comparison base: `9b0e006a`

## Residual addressed

After a transaction passed every admission check, the engine copied its
canonical mempool key into a tagged `FRAME_TX` allocation. The generic libp2p
command then split that frame and called `payload.to_vec()` because gossipsub
must own an untagged message. The complete canonical transaction was therefore
allocated and copied a second time on libp2p, and once more for dual transport.

This cost scales with the admitted transaction. The mempool has an existing
16-MiB encoded-payload budget and gossipsub has its existing 4-MiB transmit
limit; this correction does not change either bound or claim unbounded work.

## Correction and invariants

`PreparedTransactionBroadcast` is a private-field, crate-local value built
only from a canonical byte slice. Its constructor copies those bytes into a
buffer requested with capacity for the payload plus a tag. `Vec::with_capacity`
guarantees at least that requested capacity; no claim is made about exact
allocator capacity.

The engine constructs the prepared value at the same point where it formerly
constructed the tagged frame: after all admission checks and planned evictions.
It then writes `mempool_admitted_at` and the mempool before broadcasting, in
the same order as before.

Transport behavior is unchanged:

- devnet consumes the prepared buffer and inserts `FRAME_TX` in its reserved
  leading slot without reallocating;
- libp2p moves the untagged buffer through a private command directly into the
  transaction gossip topic; and
- dual transport builds one tagged devnet frame from the borrowed payload and
  moves the original allocation to libp2p. One copy remains necessary for the
  second independent owner.

The public generic `broadcast(Vec<u8>)` API and its malformed/raw fallback are
unchanged. Block, attestation and directed-sync commands are unchanged. No
wire byte, topic, canonical encoding, admission decision, mempool ordering,
peer verdict, consensus rule, persistence or recovery behavior changes.

## Adversarial coverage

- `prepared_transaction_broadcast_preserves_large_payload_and_transport_bytes`
  uses a one-MiB payload and proves exact libp2p payload bytes, exact tagged
  devnet bytes, pointer identity for the moved libp2p allocation, and no
  reallocation when devnet prepends its tag. Its borrowed-frame branch is the
  exact two-owner operation used by `Net::Both`.
- `prepared_transaction_command_moves_same_payload_allocation` sends a one-MiB
  prepared value through the real private unbounded command and proves pointer
  and length identity after receipt.
- `v2_sweep_enters_by_rpc_and_gossip_and_comes_out_in_selection` proves the
  admitted gossip transaction remains in the mempool, deduplicates, and is
  returned by proposer selection after the new broadcast path.

## Validation

```text
cargo check -p bloch-pos-node --bin bloch-pos --offline
# passed

cargo test -p bloch-pos-node --bin bloch-pos prepared_transaction_ \
  --offline -- --nocapture
# 2 passed; 0 failed; 609 filtered out

cargo test -p bloch-pos-node --bin bloch-pos \
  v2_sweep_enters_by_rpc_and_gossip_and_comes_out_in_selection \
  --offline -- --nocapture
# 1 passed; 0 failed; 610 filtered out

cargo test -p bloch-pos-node --bin bloch-pos --offline
# 592 passed; 0 failed; 19 ignored; 60.66s
```

The V2 end-to-end test requires an ephemeral localhost listener and passed
outside the sandbox. The sandbox-only attempt failed with `EPERM` at bind,
before exercising the changed code.
The full binary suite also ran outside the sandbox so its localhost transport
coverage could execute.

## Residual boundary

- Gossipsub still needs one final owned transaction payload and performs its
  own hashing.
- Dual transport still needs one full copy for two independent owners.
- Generic raw transaction frames intentionally retain their existing tag-copy
  fallback. Locally admitted production transactions use the typed path.
- Attestation gossip still copies away its routing tag, but accepted
  attestations carry fixed cryptographic-size fields rather than a comparable
  variable transaction body.
- No exact heap/RSS reduction is claimed; allocator and libp2p internals remain
  outside this focused ownership proof.
- Hosted CI, Linux reproducibility, release signing, rollback and fleet
  qualification remain integration/release work.
