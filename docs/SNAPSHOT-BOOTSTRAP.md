# Bootstrap a node from a datadir snapshot (skip initial sync)

Syncing a Genesis-3 node from scratch currently stalls around block
**10968–10969**: at that point the DAG needs certain side-block ("red") bodies
that peers no longer serve, so from-zero sync can't complete. Until that is fixed
in the node, bootstrap from a snapshot — a consistent copy of an already-synced
**archival** node's data directory. Your node starts near the tip and just
follows the chain live; no full IBD.

## Download

The snapshot is hosted on R2 (too large for the git tree):

```bash
curl -fL -O https://pub-dca67fd26bfb4a6b98115e596095ecd3.r2.dev/bloch-g3-datadir-snapshot-20260805.tar.gz
curl -fL -O https://pub-dca67fd26bfb4a6b98115e596095ecd3.r2.dev/bloch-g3-datadir-snapshot-20260805.tar.gz.sha256

sha256sum -c bloch-g3-datadir-snapshot-20260805.tar.gz.sha256
# expect: b7c8aad6eaaf448c0dfadf12ed70ebe43a779d1b1ca39ce868c66e604bee562f
```

- ~38.9 MB compressed (~83 MB on disk), taken at **block 17,587**.
- The archive contains a `g3-data/` RocksDB directory, captured after a clean
  node shutdown, so it opens cleanly.

## Run against it

Stop your node if running, extract, and point `--data-dir` at `g3-data`. Use the
**same flags** as a normal node — including `--carryover-snapshot`, which the node
**still requires even with a full datadir** (it verifies the carry-over root):

```bash
tar -xzf bloch-g3-datadir-snapshot-20260805.tar.gz     # -> ./g3-data

bloch --genesis3 --archive \
  --data-dir ./g3-data \
  --carryover-snapshot ./carryover.tsv \
  --rpc-bind 127.0.0.1 --rpc-port 16210 \
  --listen /ip4/0.0.0.0/tcp/16110 \
  --peer /ip4/192.248.190.123/tcp/16116 \
  --peer /ip4/45.76.89.225/tcp/16111
```

`carryover.tsv` is the same file described in [CARRYOVER.md](./CARRYOVER.md)
(`gunzip carryover.tsv.gz`).

## Verify

```bash
bloch-cli getblockcount        # starts ~17587 and climbs to the network tip
bloch-cli getnetworkinfo       # "syncing": false, peers > 0
```

Validated end-to-end on a clean node: opens at 17,587, reaches the tip,
`syncing: false`, and does not stall at 10968.
