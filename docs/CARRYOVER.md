# The carry-over snapshot

Bloch does **not** start from an empty ledger at a new genesis: it opens with
the unspent outputs of the prior chain. A fresh node must ingest that snapshot,
or it forks off with the wrong opening state and never matches the real
network. This is the #1 reason a brand-new node "doesn't sync."

## Genesis-4 (live)

The file in this repository, `carryover.tsv.gz`, is the **Genesis-3 terminal
snapshot at height 39,918** — the state Genesis-4 opened with.

    rows            452,726
    uncompressed    54,780,151 bytes
    SHA-256         84ddbbac2afdd5c78618096a7d4f66cf5b04a3e5757a03fe90550e50096183f6
    SHA3-256        3d67246e94881a17d302b464f79fee55886d8068794e76fed43081117fbe308d
    total           18,146,400,000 BLCH

Verify it:

```bash
gzip -dc carryover.tsv.gz | sha256sum   # 84ddbbac…
gzip -dc carryover.tsv.gz | wc -l       # 452726
```

**The node checks the SHA3-256**, not the SHA-256. `CarryoverSnapshot::check_against`
verifies four things against the commitment in the genesis manifest — file
digest, set root, entry count and total — and returns an error on any of them,
so a mismatch refuses the boot rather than warning
(`crates/bloch-pos-node/src/genesis.rs`). The SHA-256 is published only because
it is what `sha256sum` reproduces. The two names differ by one character and the
functions are unrelated; that has already cost this project a launch window.

`carryover.tsv.gz.sha256` carries both digests, with the uncompressed one in a
comment because `shasum -c` cannot check a file the repository does not track —
the raw `.tsv` is a ~55 MB build artifact and is git-ignored.

Genesis-4 values are Genesis-3 values scaled by 100/21, the ratio of the two
supply ceilings. The per-entry truncation that scaling introduces (57 sat across
111 rows) is closed deterministically; see `crates/bloch-pos-node/src/genesis.rs`.

`CARRYOVER-SNAPSHOT.md` at the repository root is the authority on this file.
If it and this document ever disagree, that one is right.

### How the live genesis was actually assembled

    bloch-pos genesis-mainnet          # crates/bloch-pos-node/src/main.rs

with the balance set ingested separately through `Manifest::ingest_carryover`.
That path, and only that path, produced the manifest the fleet runs. See
`docs/GENESIS4-MIGRATION-RUNBOOK.md`.

`tools/genesis4-carryover/` and `tools/genesis4-ceremony/` are **retired
parallel assemblers**. Neither has ever produced a byte the fleet runs, and
`genesis4-carryover` implements a rule set — drop founder-controlled outputs,
apply a 300 M cap pro-rata — that was **abandoned before launch**: the live
snapshot carries the founder's 426,194 outputs, 93.94% of the total. Run it
today against the shipped file and it emits a different ledger in a different
unit. They are kept as a record of what was considered, not as a runbook.

## Genesis-3 (historical)

Genesis-3 opened from the **Genesis-1** carry-over: 413,743 UTXOs, SHA-256
`88f29fd3b7a5851c…`, total 3,475,441,200 BLOCH (= 413,743 × 8,400). That file
was replaced in this repository on 2026-08-14. It is a different snapshot of a
different chain, and a node started against it today will refuse to boot.

If you are reading an older document that tells you to `expect: 88f29fd3…`,
that document predates 2026-08-14 and is stale.

Genesis-3 emission is keyed to `emission_height = local_height + 413,743`; see
`legacy/specs/TOKENOMICS_V3.md`. That offset is unrelated to the file above.
