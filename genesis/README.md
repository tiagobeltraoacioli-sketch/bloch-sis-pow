# Genesis-4 mainnet genesis

`genesis/mainnet.manifest` is the file the 64 validators booted from. A node
that hashes to a different digest is on a different network, which is the point
of publishing it rather than describing it.

    size            247514 bytes
    SHA-256         7eef82a70ef9b0e1dd86f86d33cba11fc10cdfc7395c2e5f6669613fa1beb2dd
    network digest  f47d3e498ff978e34471dafff5f94fe139fc3ff489b1a00f469c030258311966
    genesis time    2026-08-13 21:31:19 UTC
    validators      64
    slot            30 s, 32 slots to an epoch

It commits to the carryover by digest, not by content — the 54 MB of balances
live in `carryover.tsv.gz` and are checked against the manifest at boot. Both
are needed; neither is useful alone.

## Running a node against it

    gzip -dk carryover.tsv.gz     # the loader reads the uncompressed TSV
    bloch-pos run \
      --data-dir  ./data \
      --genesis   ./genesis/mainnet.manifest \
      --carryover ./carryover.tsv \
      --transport devnet --listen 19100 \
      --peers     <peer list — see deploy/OBSERVER-NODE.md §5> \
      --rpc-port  16400

A data dir with no `validator.key` runs in observer mode: the node follows the
chain and serves RPC, and signs nothing.

The full third-party procedure — prerequisites, every flag, the ports, the
weak-subjectivity window, and how to verify you are on the canonical chain —
is [`deploy/OBSERVER-NODE.md`](../deploy/OBSERVER-NODE.md).

## A gap this section used to describe, now closed

Until late August 2026 a cold sync over the devnet transport **did not
complete**: a node applied the blocks it could reach, then followed the live
tip without backfilling the gap, and reported a head as though it were caught
up (reproduced 2026-08-14: an observer at height 556 / state root `54870aa9…`
while the network was at 1511 / `2b7a7ac1…`, with no error raised). The
transport now runs a paginated sync pump — 512 blocks per page, from two peers
at a time, re-asking from its own head every few seconds until a peer answers
with an empty page (`src/net.rs`, `SYNC_PAGE_BLOCKS`/`SYNC_FANOUT`) — and
syncing from genesis completes. Verify anyway, every time:
`getchaininfo.behind_by_slots` must be 0–1, and your `block_id`/`state_root`
at a given slot must match a second source before the node's answers are
treated as the network's.
