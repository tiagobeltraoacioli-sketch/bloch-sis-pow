# Genesis-3 carry-over snapshot

> **HISTORICAL — this document describes a file that is no longer in this
> repository.** On 2026-08-14 `carryover.tsv.gz` was replaced by the
> **Genesis-3 terminal snapshot** (the state Genesis-4 opened with: 452,726
> rows, uncompressed SHA-256 `84ddbbac2afd…`, gz SHA-256 `4d1e2738baec…`).
> The current file is documented in the root `CARRYOVER-SNAPSHOT.md` and
> verified by the root `carryover.tsv.gz.sha256`. The Genesis-1 snapshot this
> page describes (413,743 rows, SHA-256 `88f29fd3b7a5…`) exists only in git
> history before 2026-08-14; the `bloch --genesis3` flags below are the
> retired PoW node's, not `bloch-pos`. Kept for operators of Genesis-3
> archive nodes.

Genesis-3 does **not** start from an empty ledger: it opens with the balances
carried over from the prior chain. A fresh node must ingest that snapshot at
startup, or it forks off with the wrong opening state and never matches the real
network. This is the #1 reason a brand-new node "doesn't sync."

The snapshot ships in this repo, gzip-compressed:

- **`carryover.tsv.gz`** — 413,743 UTXOs, ~16 MB compressed (~50 MB unpacked)
  — total **3,475,441,200 BLOCH** (= 413,743 × 8,400 exactly; consensus
  constant `CARRYOVER_TOTAL_SAT`)
- **`carryover.tsv.gz.sha256`** — checksums for both the compressed and the
  uncompressed file

It is also mirrored at <https://posternlabs.com/carryover.tsv.gz>.

## Use it

```bash
# 1. unpack (the .gz is what's committed; the node reads the .tsv)
gunzip -k carryover.tsv.gz            # -k keeps the .gz; produces carryover.tsv

# 2. verify (must match carryover.tsv.gz.sha256)
shasum -a 256 carryover.tsv
# expect: 88f29fd3b7a5851cb557be8f8a6a7627b9efbe198662d8335695f2fd5f99373c

# 3. point the node at it
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
before trusting a snapshot.
