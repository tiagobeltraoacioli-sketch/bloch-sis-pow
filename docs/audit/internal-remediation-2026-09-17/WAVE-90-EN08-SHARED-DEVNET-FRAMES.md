# Wave 90 — EN-08 shared devnet queue frames

Date: 2026-09-19
Starting consolidation: `8f34af1`

## Residual addressed

The legacy devnet transport retained one owned `Vec<u8>` per writer queue.
`DevnetMesh::broadcast` cloned the complete frame for every configured and
inbound peer before calling `try_send`, so even an already-full queue caused a
copy proportional to the payload before refusing the frame. The shared sync
scheduler likewise cloned its nine-byte request for each selected peer.

Queue depths already bounded retention and drops remained recoverable through
the existing sync scheduler. This residual was avoidable allocation/copy work
inside those bounds, not an unbounded-retention or consensus bypass.

## Hardening and consumer proof

The private devnet writer queues now carry `Arc<[u8]>`. A generic devnet
broadcast handles the existing `FRAME_GET_BLOCKS` scheduler diversion first,
then converts its owned `Vec<u8>` once before fanout. Each writer queue receives
an `Arc` clone, including a clone immediately refused by `TrySendError::Full`.
The sync scheduler similarly constructs one shared request frame per pump and
clones only that handle across selected peers.

The only queue consumers are `run_inbound_writer` and
`run_connection_writer`. The writer inspects the first byte, validates a sync
request against `pending_sync`, and writes the frame by borrowing `&[u8]`; it
does not mutate or retain a second payload. `Connection::take_sync_request`
already accepted a slice. Consumer search found no queue path requiring unique
ownership.

The alias and all changed channel types remain private to the devnet module.
Queue depth, FIFO ordering, `Full` drop behavior, disconnected-peer pruning,
reconnect behavior, sync leases and authorization, frame bytes, length prefix,
consensus, verdicts and recovery behavior are unchanged.

## Adversarial coverage

- `devnet_broadcast_shares_wire_bytes_and_full_queues_do_not_displace` creates
  two independent peer queues, broadcasts a one-MiB frame, and proves both
  peers retain byte-exact frames backed by the same allocation with
  `Arc::ptr_eq`. With both queues full, it broadcasts a distinct frame and
  proves the retained entries are neither displaced nor reordered and no
  second entry appears.
- `devnet_broadcast_outbound_queue_is_bounded` preserves the production
  outbound queue-depth boundary while using the new internal item type.
- Existing scheduler and loopback tests remain the behavioral evidence for
  lease rotation, writer backpressure, disconnect/reconnect, request
  authorization and exact wire transmission. The root executed their combined
  filter outside the restricted sandbox, including the bidirectional live
  page test.

## Validation

```text
cargo check -p bloch-pos-node --tests --offline
# passed

cargo test -p bloch-pos-node --bin bloch-pos \
  devnet_broadcast_ --offline
# 2 passed; 0 failed; 589 filtered out

cargo test -p bloch-pos-node --bin bloch-pos \
  shared_sync_ --offline
# 7 passed; 0 failed; 584 filtered out

cargo test -p bloch-pos-node --bin bloch-pos --offline
# 572 passed; 0 failed; 19 ignored; finished in 72.72s
```

The complete binary suite was executed by the root outside the restricted
sandbox. Compiler output contained only existing unused-code/import warnings.

The root ran the combined `shared_sync_` filter outside the sandbox. Its seven
passing cases include all focused scheduler/reconnect tests cited during this
wave and the live bidirectional page regression:

```text
net::tests::shared_sync_leases_rotate_without_head_progress_and_bound_both_triggers
net::tests::shared_sync_backpressure_disconnect_and_full_queue_preserve_reacquisition
net::tests::shared_sync_stalled_writer_cannot_accumulate_or_flush_expired_requests
net::tests::shared_sync_two_silent_outbound_peers_cannot_starve_responsive_inbound
net::tests::shared_sync_bidirectional_large_pages_keep_both_readers_draining
```

## Residual boundaries

- Converting an owned `Vec<u8>` to `Arc<[u8]>` may perform one allocation and
  payload copy. The proven improvement is removal of payload-sized copies per
  fanout target and per refused full-queue attempt, not zero-copy construction.
- Atomic reference-count operations remain for every queue clone and drop.
- The same immutable payload remains retained until the last writer queue
  releases it; queue count/depth caps remain the retention boundary.
- This change is limited to devnet internal queues. Libp2p buffers and other
  transport-owned copies remain outside its scope.
- No exact allocator, heap or RSS reduction is claimed.
- Full node, hosted CI, Linux reproducibility, release signing, rollback and
  fleet qualification remain outside this focused checkpoint.
