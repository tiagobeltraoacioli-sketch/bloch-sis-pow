# Bootstrap a node from a datadir snapshot (skip initial sync)

> **Historical — Genesis-3.** This describes the proof-of-work chain that
> stopped permanently at height 39,918 on 2026-08-13. The live chain is
> **Genesis-4, proof of stake** (30 s slots, 32-slot epochs, finality by
> epoch). Kept because Genesis-4's opening ledger is derived from it. It is
> not what runs.
>
> **Every command on this page boots a dead chain.** There is no live
> Genesis-3 tip to reach, no producer to track, and the peers listed below
> serve nothing. Nothing here onboards a node to the network that is running.
> Genesis-4 nodes take their opening ledger from a signed manifest, not from a
> Genesis-3 datadir, and there is at present no checkpoint-sync state download
> for them at all.

**Syncing a Genesis-3 node from scratch did not work — and could not be made
to work by retrying or upgrading.** The DAG needed certain side-block ("red")
bodies that no peer served anymore: bodies discarded before the retention fix
(`4c0ba0c`, 2026-08-05) were gone from the whole network, so from-zero IBD
stalled (around block_count **26,474**) and could never complete. The supported
onboarding path was a snapshot — a consistent copy of an already-synced
**archival** node's data directory. The node started at the snapshot height
and followed the chain live; no full IBD.

## Which binary

Genesis-3 operators ran the **latest published release** (see the
[releases page](https://github.com/tiagobeltraoacioli-sketch/bloch-sis-pow/releases));
older builds actively diverged. Two consensus flag-days mattered:

- **Difficulty-from-ancestry, local h=30,030 — activated, and the chain ran
  past it.** The expected difficulty of a block became a pure function of the
  block's own ancestry (parents carried in the header), so arrival order could
  no longer split producer and validator. Builds older than commit `1f7d328`
  (`genesis3-node-difficulty-choke-20260809`) rejected the blocks the network
  produced after that height.
- **Emission V3, local h=40,000 — scheduled but NEVER REACHED.** It would have
  cut the block reward 8,400 → 2,600 BLOCH (`legacy/specs/TOKENOMICS_V3.md`,
  commit `8538dea`, release `genesis3-node-emission-v3-floor60-20260810`,
  `bloch` sha256 `dfc6962d…`, incl. the PISO-60 60-BLOCH V3 tail floor). The
  chain stopped permanently at height **39,918** on 2026-08-13, 82 blocks
  short of the flag-day, so the reduced reward never took effect and every
  Genesis-3 block was minted at 8,400 BLOCH. Earlier ETAs on this page said
  "~2026-08-12/13"; that date arrived, the height did not.

Since commit `c21e09d`, a stale or poisoned `known_peers.json` was pruned
automatically on load (the PEX address-poisoning fix), so restoring an old
datadir no longer required deleting peer files by hand.

## Download

Last published snapshot — taken from the **block producer** at height
**≈27,614**. Note it sat **below the h=30,030 difficulty flag-day**: a node
restored from it synced the 27,614 → 30,030 stretch under the legacy
(order-sensitive) difficulty rule and could freeze at a retarget boundary on
the way up — if `block_count` stopped climbing, restarting the node resumed it.
A snapshot taken **above h=30,030** was to have replaced this one as the
recommended bootstrap; no such replacement was published before the chain
halted, and none will be:

```bash
curl -fL -O https://github.com/tiagobeltraoacioli-sketch/bloch-sis-pow/releases/download/g3-datadir-snapshot-h27614-20260808/bloch-g3-datadir-snapshot-h27614-20260808.tar.gz
curl -fL -O https://github.com/tiagobeltraoacioli-sketch/bloch-sis-pow/releases/download/g3-datadir-snapshot-h27614-20260808/bloch-g3-datadir-snapshot-h27614-20260808.tar.gz.sha256

sha256sum -c bloch-g3-datadir-snapshot-h27614-20260808.tar.gz.sha256
# expect: 12e813e42f92672352415f0fd03225f794ca37820d706ca2d7728aa0b53c3c4d
```

> **It had to be run with the newest binary** (see "Which binary" above — from
> 2026-08-09 that meant `genesis3-node-difficulty-choke-20260809` or newer).
> The release the snapshot's own notes referenced at publication
> (`genesis3-node-flagday-h27600-rpcfix-20260808`) was **superseded** and
> rejected the network's blocks.

- ~117 MB compressed, taken at height ≈27,614.
- The archive contains a `g3-data/` RocksDB directory only. `p2p_identity.bin`
  and `known_peers.json` were **not** included — the node generated a fresh
  libp2p identity on first boot (a shared identity would have collided on the
  network; the 2026-08-05 snapshot wrongly shipped one). This is Genesis-3's
  network stack, not Genesis-4's: the live PoS node does not use libp2p.
- R2 mirror (`pub-dca67fd26bfb4a6b98115e596095ecd3.r2.dev`) was never restored:
  the R2 S3 upload token was lost with the OVH build host and `wrangler` caps
  uploads at 300 MiB.

Superseded even within Genesis-3:

- `bloch-g3-datadir-snapshot-20260808.tar.gz` (tip ~h27,147, sha
  `dc02514f…`) — **below the h27,600 flag-day**; restoring it landed you in the
  legacy difficulty window and you froze at the first retarget boundary.
- `bloch-g3-datadir-snapshot-20260807.tar.gz` (block_count 28,904, sha
  `76016538…`) — predated the difficulty-ancestry rollout.
- `bloch-g3-datadir-snapshot-20260805.tar.gz` (block 17,587, sha
  `b7c8aad6…`) — nodes restored from it stalled at 26,474.

## Run against it

The procedure was: stop the node if running, extract, and point `--data-dir` at
`g3-data`, using the **same flags** as a normal node — including
`--carryover-snapshot`, which the node **still required even with a full
datadir** (it verified the carry-over root). Note that `--carryover-snapshot`
here is the Genesis-1 → Genesis-3 **opening** carry-over, not the Genesis-3 →
Genesis-4 terminal snapshot; see [CARRYOVER.md](./CARRYOVER.md), which
distinguishes the two.

```bash
tar -xzf bloch-g3-datadir-snapshot-h27614-20260808.tar.gz     # -> ./g3-data

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
bloch-cli getblockcount        # started at the snapshot's count and climbed toward the then-live tip
bloch-cli getnetworkinfo       # "syncing": false, peers > 0
```

Both commands still run against a restored datadir, but `peers > 0` will not
hold: there is no Genesis-3 network left to peer with. The public read RPC for
the **live** chain is <https://posternlabs.com/g4rpc> (version
`0.1.0-mainnet`), and it speaks Genesis-4, not these methods.

The h≈27,614 archive was verified before publishing (extracted cleanly,
RocksDB `CURRENT`/`MANIFEST` intact, no identity/peer files — 164 entries) and
was validated end-to-end at the time: **both fleet followers were restored from
exactly this archive**, reached the then-live tip and tracked it in consensus
with the producer. That was true while Genesis-3 ran; the tip it tracked is now
the terminal one at height 39,918.

## Known limitation: catching up a large gap could stall

The snapshot removed the dead 26,474 wall, but a node backfilling a **large**
gap (hundreds of blocks / snapshot hours stale) could still freeze mid-catch-up
with repeated `peer cannot serve block <hash> (pruned or unknown)` warnings
even though its peers held those bodies. The 2026-08-09 builds hardened this
path — a backfill ingest guard (one stale peer could no longer halt ingestion)
and the PEX `known_peers` fix (poisoned peer addresses were gray-listing
nodes into a gossip blackhole; entries self-healed on load) — but the
operational advice while the chain ran was: restore the snapshot **as soon as
possible after downloading**, and if catch-up froze (block_count stopped
climbing), **restart the node** (`SIGTERM`, never `kill -9`) — each restart
resumed backfill. A node that reached the tip tracked it reliably from then on.
