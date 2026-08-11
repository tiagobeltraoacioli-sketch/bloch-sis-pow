# Genesis-4 carryover

Turns the raw UTXO snapshot taken at the terminal height into the Genesis-4
opening balances: drop founder-controlled outputs, aggregate by address, apply
the 300 M cap pro-rata if it binds, emit a deterministic TSV and a SHAKE-256
commitment.

## Runbook, in order

```bash
# 1. at the terminal height, with the chain halted
bloch-snapshot-utxo --data-dir ~/bloch-data --out utxo-80000.tsv

# 2. filter and cap
python3 build_carryover.py \
    --utxo utxo-80000.tsv \
    --founder e986db5149cff7499b282a048272a09aff0af4ff \
    --cap-bloch 300000000 \
    --out genesis4-carryover.tsv

# 3. publish the artifact and its digest; the digest goes in the Genesis-4
#    genesis block
sha256sum genesis4-carryover.tsv > genesis4-carryover.tsv.sha256
```

## The two things this artifact must survive

**Nobody is defending the old chain after it halts.** With mining stopped, the
cost of producing an alternative history below the terminal height collapses.
The signed artifact is the record; the chain is not. That is why the digest
belongs inside the Genesis-4 genesis block, where it cannot be quietly
replaced.

**A snapshot is a trust anchor, not a proof** — the same caveat
`bloch-snapshot-utxo` states about its own output. Have several operators run
steps 1 and 2 independently on the same halted data-dir and compare digests.
Agreement between independent parties is the evidence; a digest published by
one party is only a commitment.

## Tests

```bash
python3 test_build_carryover.py
```

Validated against the real `carryover.tsv.gz` (413,743 UTXOs): founder
3,294,337,200 BLCH excluded, 181,104,000 BLCH across four non-founder addresses
carried, no scale-down needed. Plus pro-rata correctness, taint handling,
determinism of the digest, and the edge cases.
