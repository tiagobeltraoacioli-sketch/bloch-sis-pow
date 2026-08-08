# Bootstrap a node from a datadir snapshot (skip initial sync)

Syncing a Genesis-3 node from scratch currently stalls (most recently around
block **26474**): the DAG needs certain side-block ("red") bodies that peers no
longer serve — bodies discarded before the retention fix (`4c0ba0c`) are gone
from the fleet, so from-zero sync can't complete. Until the block-serving path
is fixed in the node, bootstrap from a snapshot — a consistent copy of an
already-synced **archival** node's data directory. Your node starts at the
snapshot height and follows the chain live; no full IBD.

## Download

Current snapshot — taken **2026-08-08 19:50 UTC** from the **block producer**
at the network tip (height ~27,147; clean `systemctl stop`, 0.33 s stop window,
`cp -a` from the quiesced datadir):

```bash
curl -fL -O https://github.com/tiagobeltraoacioli-sketch/bloch-sis-pow/releases/download/g3-datadir-snapshot-20260808/bloch-g3-datadir-snapshot-20260808.tar.gz
curl -fL -O https://github.com/tiagobeltraoacioli-sketch/bloch-sis-pow/releases/download/g3-datadir-snapshot-20260808/bloch-g3-datadir-snapshot-20260808.tar.gz.sha256

sha256sum -c bloch-g3-datadir-snapshot-20260808.tar.gz.sha256
# expect: dc02514f19494b5cf1f60ed59805db65edfbf89e250ad2bbfb3da28b2b058f65
```

> **Run it with the [`genesis3-node-ancestry-flagday-h30000-20260808`](https://github.com/tiagobeltraoacioli-sketch/bloch-sis-pow/releases/tag/genesis3-node-ancestry-flagday-h30000-20260808)
> binary.** The consensus flag-day at height 30,000 (difficulty derived from
> block ancestry) is imminent; every earlier binary diverges there regardless
> of which snapshot it starts from.

- ~225 MB compressed (~309 MB on disk), taken at tip height ~27,147.
- The archive contains a `g3-data/` RocksDB directory only. `p2p_identity.bin`
  and `known_peers.json` are **not** included — your node generates a fresh
  libp2p identity on first boot (a shared identity would collide on the
  network; the 2026-08-05 snapshot wrongly shipped one — do not reuse it).
- R2 mirror (`pub-dca67fd26bfb4a6b98115e596095ecd3.r2.dev`) pending: the R2 S3
  upload token was lost with the OVH build host and `wrangler` caps uploads at
  300 MiB. Mint a new R2 S3 API token (dash → R2 → Manage R2 API Tokens) and
  `aws s3 cp` from a fleet box to restore the old URL pattern.

Superseded:

- `bloch-g3-datadir-snapshot-20260807.tar.gz` (block_count 28,904, sha
  `76016538…`) — predates the difficulty-ancestry rollout; prefer the current
  one.
- `bloch-g3-datadir-snapshot-20260805.tar.gz` (block 17,587, sha
  `b7c8aad6…`) — nodes restored from it stall at 26,474.

## Run against it

Stop your node if running, extract, and point `--data-dir` at `g3-data`. Use the
**same flags** as a normal node — including `--carryover-snapshot`, which the node
**still requires even with a full datadir** (it verifies the carry-over root):

```bash
tar -xzf bloch-g3-datadir-snapshot-20260808.tar.gz     # -> ./g3-data

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
bloch-cli getblockcount        # starts at the snapshot's count and climbs to the network tip
bloch-cli getnetworkinfo       # "syncing": false, peers > 0
```

The 2026-08-08 archive was verified before publishing (extracts cleanly,
RocksDB `CURRENT`/`MANIFEST` intact, no identity/peer files). The previous
snapshot (2026-08-07) was additionally validated end-to-end on a clean node
(node4): opened at its tip, did **not** stall at 26,474, reached the live tip
and tracked it (`syncing: false`, peers > 0).

## Known limitation: catching up a large gap may stall

The snapshot removes the dead 26,474 wall, but the peer block-body-serving
path has a live bug (under fix): a node backfilling a **large** gap (hundreds
of blocks / snapshot hours stale) can freeze mid-catch-up with repeated
`peer cannot serve block <hash> (pruned or unknown)` warnings even though its
peers hold those bodies. Restore the snapshot **as soon as possible after
downloading**, and if catch-up freezes (block_count stops climbing), **restart
the node** (`SIGTERM`, never `kill -9`) — each restart resumes backfill. A
node that reaches the tip tracks it reliably from then on.
