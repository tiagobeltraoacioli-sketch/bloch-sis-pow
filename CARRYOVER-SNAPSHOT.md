# The Genesis-3 terminal snapshot

`carryover.tsv.gz` is the state Genesis-4 opened with: every exported unspent
output from the Genesis-3 snapshot published with terminal-height label
39,918. Whether the applied selected tip on the snapshot nodes was actually
39,917 or 39,918 remains the LG-01 provenance question below.

    rows            452,726
    uncompressed    54,780,151 bytes
    SHA-256         84ddbbac2afdd5c78618096a7d4f66cf5b04a3e5757a03fe90550e50096183f6
    SHA3-256        3d67246e94881a17d302b464f79fee55886d8068794e76fed43081117fbe308d
    set root        7c756ee8ffff9529b40c124b36bd3e1a9934a15f063affe5596913fb858efbdf

**Two totals, and they are not the same number — label them separately, or
an auditor summing this file gets a number that disagrees with both of
them:**

    file total (Genesis-3 units, as this TSV literally sums)   3,810,744,000 BLCH
    Genesis-4 opening supply (after the ×100/21 split)        18,146,400,000 BLOCH

The second figure — `CARRYOVER_TOTAL_BLOCH` in
`crates/bloch-pos-committee/src/tokenomics_v4.rs` — is what this repository
used to print here as if it were a property of the file itself. It is not:
`carryover.tsv.gz`'s rows sum to 3,810,744,000, in Genesis-3 units, because
that is the chain it was measured from. `3,810,744,000 × 100 / 21 =
18,146,400,000` exactly (the split's own arithmetic,
`SPLIT_NUMERATOR`/`SPLIT_DENOMINATOR` in the same file) — the Genesis-4
constant is *derived from* this file's total, not *equal to* it.

**The node checks the SHA3-256**, and refuses to start on a mismatch rather
than warning. The SHA-256 is here because it is what `sha256sum` reproduces;
the two names differ by one character and the functions are unrelated, which
has already cost this project a launch window.

## Documented, unreconciled facts about this snapshot

Recorded here as facts an auditor should know before treating the file as a
closed question — none of these change the SHA3-256 the node checks, and
none of them are fixed by this pass:

- **One block subsidy is unreconciled.** The ledger's terminal total sits
  **exactly one block subsidy (8,400 BLCH, pre-split) below** what the
  Genesis-3 emission schedule would predict for height 39,918, and nothing
  in this repository reconciles the gap — it depends on exactly how many
  blocks the applied chain actually contained at the snapshot point, a
  figure that was never published. Stated as an open fact, not resolved
  here.
- **38 outpoints carry a corrupted `vout`.** The file contains exactly two
  distinct `vout` values: `0` (452,688 rows) and `16777216` (38 rows).
  `16777216 = 0x01000000` is the little-endian byte pattern of `1` read as
  big-endian — the exporter wrote the vout little-endian and a reader
  parsed it big-endian. All 38 are genuine `vout = 1` outputs (ordinary
  change outputs from real spends) recorded under an impossible index. This
  does **not** affect any balance (value and script are untouched) and does
  **not** break reproducibility (the export and the load path make the same
  mistake identically, so the derived set root is stable) — but the claim
  that "the Genesis-3 outpoint crosses unchanged" is false for exactly these
  38 rows: no Genesis-3 explorer, wallet, or block will ever agree that
  `(txid, 16777216)` was ever a real outpoint.

## What was here before

Until 2026-08-14 this file held the **Genesis-1** carryover — 413,743 rows,
SHA-256 `88f29fd3b7a5851c…`. That is a different snapshot of a different
chain, and it was never what the fleet booted from. Anyone who cloned this
repository to rebuild the genesis got a file the node would refuse, which made
the live genesis unreproducible from source: the one thing an auditor, an
exchange, or an independent validator has to be able to do for themselves.

Reproduce it:

    gzip -dc carryover.tsv.gz | sha256sum   # 84ddbbac…
    gzip -dc carryover.tsv.gz | wc -l       # 452726

## LG-01 evidence boundary

The exact arithmetic admits two materially different explanations. The
snapshot nodes may have had an applied selected tip at 39,917 while 39,918
was an announced, stored, or later-observed height that those snapshots never
applied. Alternatively, block 39,918 may have been selected while the legacy
non-atomic Extension path logged a failed UTXO mutation and still advanced
`tip_hash`. The old exporter's silent-decode-skip path was another historical
possibility; the current exporter and `iter_utxos_sorted` now fail closed, so
a fresh successful derivation from each frozen archive can exclude that
possibility for the archive being inspected.

`scripts/verify-lg01-provenance.py` accepts reports from at least two distinct
archival snapshot nodes and classifies only these two cases. It refuses
artifact mismatches, incomplete block records, duplicate archive identities,
or disagreement between nodes. It never changes the carryover file or a
balance. Run its regression suite with:

    python3 scripts/test-verify-lg01-provenance.py

The verifier checks consistency, not authorship. Closing LG-01 requires the
operators to publish the raw outputs and authenticated hashes behind every
report field: frozen data-directory identity; snapshot-time
`getdaginfo.tip_height`; `meta.tip_hash`; maximum stored height; a fixed-tool
carryover verification giving the root, row count, total and file digests;
and the height-39,918 block lookup giving hash, selected disposition,
coinbase total and transaction count. The two node records need distinct
archive identities and matching selected-tip facts. If the evidence proves a
selected height-39,918 block whose effects are absent, accepting that
historical loss or defining any remedy remains an explicit owner decision;
this verifier does not invent a coinbase.
