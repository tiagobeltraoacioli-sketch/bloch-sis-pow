# Bootstrap a node from a datadir snapshot (skip initial sync)

Syncing a Genesis-3 node from scratch currently stalls (most recently around
block **26474**): the DAG needs certain side-block ("red") bodies that peers no
longer serve — bodies discarded before the retention fix (`4c0ba0c`) are gone
from the fleet, so from-zero sync can't complete. Until the block-serving path
is fixed in the node, bootstrap from a snapshot — a consistent copy of an
already-synced **archival** node's data directory. Your node starts at the
snapshot height and follows the chain live; no full IBD.

## Download

Current snapshot — taken **2026-08-07 23:02 UTC** at **block_count 28904**
(node at the network tip, clean SIGTERM shutdown):

```bash
curl -fL -O https://github.com/tiagobeltraoacioli-sketch/bloch-sis-pow/releases/download/g3-datadir-snapshot-20260807/bloch-g3-datadir-snapshot-20260807.tar.gz
curl -fL -O https://github.com/tiagobeltraoacioli-sketch/bloch-sis-pow/releases/download/g3-datadir-snapshot-20260807/bloch-g3-datadir-snapshot-20260807.tar.gz.sha256

sha256sum -c bloch-g3-datadir-snapshot-20260807.tar.gz.sha256
# expect: 760165389e9415b3e3931e1f53ddb53730a4a0ee90490f8071793229dcc6ea92
```

- ~1.1 GB compressed (~1.5 GB on disk), taken at **block_count 28,904**
  (`tip_blue_score` 27,516).
- The archive contains a `g3-data/` RocksDB directory only. `p2p_identity.bin`
  and `known_peers.json` are **not** included — your node generates a fresh
  libp2p identity on first boot (a shared identity would collide on the
  network; the 2026-08-05 snapshot wrongly shipped one — do not reuse it).
- R2 mirror (`pub-dca67fd26bfb4a6b98115e596095ecd3.r2.dev`) pending: the R2 S3
  upload token was lost with the OVH build host and `wrangler` caps uploads at
  300 MiB. Mint a new R2 S3 API token (dash → R2 → Manage R2 API Tokens) and
  `aws s3 cp` from a fleet box to restore the old URL pattern.

Superseded: `bloch-g3-datadir-snapshot-20260805.tar.gz` (block 17,587, sha
`b7c8aad6…`) — nodes restored from it stall at 26,474.

## Run against it

Stop your node if running, extract, and point `--data-dir` at `g3-data`. Use the
**same flags** as a normal node — including `--carryover-snapshot`, which the node
**still requires even with a full datadir** (it verifies the carry-over root):

```bash
tar -xzf bloch-g3-datadir-snapshot-20260807.tar.gz     # -> ./g3-data

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
bloch-cli getblockcount        # starts at 28904 and climbs to the network tip
bloch-cli getnetworkinfo       # "syncing": false, peers > 0
```

Validated end-to-end (2026-08-07) on a clean node (node4): opens at 28,904,
does **not** stall at 26,474, reaches the live tip and tracks it
(`syncing: false`, peers > 0, zero "cannot serve block" warnings).

## Known limitation: catching up a large gap may stall

The snapshot removes the dead 26,474 wall, but the peer block-body-serving
path has a live bug (under fix): a node backfilling a **large** gap (hundreds
of blocks / snapshot hours stale) can freeze mid-catch-up with repeated
`peer cannot serve block <hash> (pruned or unknown)` warnings even though its
peers hold those bodies. Restore the snapshot **as soon as possible after
downloading**, and if catch-up freezes (block_count stops climbing), **restart
the node** (`SIGTERM`, never `kill -9`) — each restart resumes backfill. A
node that reaches the tip tracks it reliably from then on.
