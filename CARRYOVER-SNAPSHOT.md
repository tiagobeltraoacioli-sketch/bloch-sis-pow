# The Genesis-3 terminal snapshot

`carryover.tsv.gz` is the state Genesis-4 opened with: every unspent output of
Genesis-3 at its terminal height, 39,918.

    rows            452,726
    uncompressed    54,780,151 bytes
    SHA-256         84ddbbac2afdd5c78618096a7d4f66cf5b04a3e5757a03fe90550e50096183f6
    SHA3-256        3d67246e94881a17d302b464f79fee55886d8068794e76fed43081117fbe308d
    set root        7c756ee8ffff9529b40c124b36bd3e1a9934a15f063affe5596913fb858efbdf
    total           18,146,400,000 BLOCH

**The node checks the SHA3-256**, and refuses to start on a mismatch rather
than warning. The SHA-256 is here because it is what `sha256sum` reproduces;
the two names differ by one character and the functions are unrelated, which
has already cost this project a launch window.

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
