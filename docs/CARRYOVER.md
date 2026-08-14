# Genesis-3 carry-over snapshot

> **Historical — Genesis-3.** This describes the proof-of-work chain that
> stopped permanently at height 39,918 on 2026-08-13. The live chain is
> **Genesis-4, proof of stake** (30 s slots, 32-slot epochs, finality by
> epoch). Kept because Genesis-4's opening ledger is derived from it. It is
> not what runs.

## Two different carry-overs — do not confuse them

The word "carryover" names two distinct artifacts in this project, taken at
opposite ends of Genesis-3's life:

| | (a) **opening** carry-over | (b) **terminal** carry-over |
|---|---|---|
| direction | Genesis-1 → Genesis-3 | Genesis-3 → Genesis-4 |
| when | Genesis-3 slot/height 0 | Genesis-3 height 39,918, 2026-08-13 |
| size | 413,743 UTXOs | **452,726 outputs** |
| total | 3,475,441,200 BLOCH | **3,810,744,000 BLOCH** on the Genesis-3 side, which is **18,146,400,000 BLOCH** in Genesis-4 units |
| file | `carryover.tsv.gz`, described below | the signed terminal snapshot (set root `7c756ee8…`) |
| status | historical — it seeded a chain that has since stopped | **this is the one that matters now** |

**This document is about (a)** — the file Genesis-3 opened from. It is
historical record.

**(b) is what the live chain runs on.** Genesis-4 issues 57,146,400,000 BLOCH
at slot 0, of which 18,146,400,000 is the terminal carry-over; the authority is
`CARRYOVER_TOTAL_BLOCH` and `CARRYOVER_MEASURED_*` in
`crates/bloch-pos-committee/src/tokenomics_v4.rs`, and the ingestion path is
`Manifest::ingest_carryover` in `crates/bloch-pos-node/src/genesis.rs`. The two
totals differ by a factor of exactly 100/21 between the Genesis-3 and
Genesis-4 unit — 3,810,744,000 × 100 / 21 = 18,146,400,000, the same coins
redenominated, not more coins.

Neither total is 17,970,880,000, 3,773,884,800, 3,805,746,000 or
18,122,600,000; those are superseded provisional readings taken while
Genesis-3 was still minting. Nor was the terminal measurement taken at
"height 43,172" — 43,172 was a **block count** mislabelled as a height. Height
and block count are different measurements in a DAG: Genesis-3's terminal
height was 39,918 and its terminal block count was 50,690.

## What (a) was, and why it existed

Genesis-3 did **not** start from an empty ledger: it opened with the balances
carried over from the prior chain. A fresh Genesis-3 node had to ingest that
snapshot at startup, or it forked off with the wrong opening state and never
matched the network. This was the #1 reason a brand-new Genesis-3 node "didn't
sync." None of this applies to a Genesis-4 node, which takes its opening
ledger from the manifest instead.

The snapshot ships in this repo, gzip-compressed:

- **`carryover.tsv.gz`** — 413,743 UTXOs, ~16 MB compressed (~50 MB unpacked)
  — total **3,475,441,200 BLOCH** (= 413,743 × 8,400 exactly; the Genesis-3
  consensus constant `CARRYOVER_TOTAL_SAT`). This is the **opening** figure,
  not the terminal one.
- **`carryover.tsv.gz.sha256`** — checksums for both the compressed and the
  uncompressed file

It was also mirrored at <https://posternlabs.com/carryover.tsv.gz>.

## How it was used (Genesis-3 only — this will not start a live node)

The commands below are kept as record. `bloch --genesis3` runs the
proof-of-work node, and the peers listed served a chain that has stopped; there
is nothing live at the other end.

```bash
# 1. unpack (the .gz is what's committed; the node read the .tsv)
gunzip -k carryover.tsv.gz            # -k keeps the .gz; produces carryover.tsv

# 2. verify (must match carryover.tsv.gz.sha256)
shasum -a 256 carryover.tsv
# expect: 88f29fd3b7a5851cb557be8f8a6a7627b9efbe198662d8335695f2fd5f99373c

# 3. point the (Genesis-3) node at it
bloch --genesis3 --archive \
  --data-dir ~/bloch-data \
  --carryover-snapshot ./carryover.tsv \
  --rpc-bind 127.0.0.1 --rpc-port 16210 \
  --listen /ip4/0.0.0.0/tcp/16110 \
  --peer /ip4/192.248.190.123/tcp/16116 \
  --peer /ip4/45.76.89.225/tcp/16111
```

The raw `carryover.tsv` is intentionally git-ignored (it's a 50 MB build
artifact); only the compressed `.gz` is tracked. Always verify the checksum
before trusting a snapshot — the rule survives the chain it was written for.

## Reading Genesis-4 balances instead

A carried balance on the live chain is read over the public read RPC,
<https://posternlabs.com/g4rpc> (node version `0.1.0-mainnet`), not from this
file. Two caveats that hold today:

- Settlement on Genesis-4 is **finality, not confirmation depth**. Casper
  justification and finalisation happen **by epoch** — 32 slots of 30 s, so
  ~32 minutes typically and ~48 minutes worst case.
- A carried balance is liquid but **not yet stakeable in practice**: every
  node's mempool refuses `Deposit` and `Delegate`
  (`crates/bloch-pos-node/src/engine.rs:1900-1906`) because bonding is not yet
  funded from the UTXO set.
