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

    bloch-pos run \
      --data-dir  ./data \
      --genesis    ./genesis/mainnet.manifest \
      --carryover  ./carryover.tsv.gz  # decompress first; the loader reads TSV
      --rpc-port   16400

A data dir with no `validator.key` runs in observer mode: the node follows the
chain and serves RPC, and signs nothing.

## What does not work yet, stated because you will hit it in the first hour

Syncing from genesis over the transport the live fleet runs (`--transport
devnet`) **does not complete**. A node started this way applies the blocks it
can reach, then follows the live tip over gossip without backfilling the gap —
and reports a head, a height and a state root as though it were caught up. We
reproduced it on 2026-08-14: an observer reported height 556 and state root
`54870aa9…` while the network was at height 1511 and `2b7a7ac1…`, with no error
raised at any point.

So the missing piece for a third party is not the manifest or the snapshot.
Both are here. It is a transport that completes a cold sync and says so
honestly when it has not. That work is in progress; a node stood up before it
lands would answer confidently and wrongly, which is worse for an exchange than
not running one.
