<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# The reorg write path: what it costs, how often, and what the fix is worth

**Every number in this file was produced by the run described beside it.** None
is carried over from an earlier document. If you quote a figure from here,
quote the command too — the commands are all in this file and all reproducible.

This exists because the brief that started this work carried figures that had
no source. They are not repeated here, and the conclusion below is not the one
they implied.

---

## 1. What the code did

`Engine::do_reorg` called `Store::rewrite`, which re-encodes and re-writes
**every canonical block** on every reorg, at any depth. A reorg cannot change a
block below the fork point, so all of that is written back byte-identical to
what is already on disk. The work is sized by the chain, not by the reorg, and
it runs on the thread that also runs consensus.

## 2. What it costs — measured

`store::tests::reorg_write_cost_on_a_real_log`. Both write paths are asked to
produce the same log — the branch re-adopted is the tail already logged — so
each path's output must hash to the untouched original, and the test asserts
that before it reports a time.

    box     Edgevana, 2 cores, 7936 MB, Ubuntu 24.04.4, rustc 1.97.1, release
            136.244.82.226, load ~1.8, no fleet node running on it
    log     /home/ubuntu/g4/n58 — a real Genesis-4 data dir
            29,377 blocks, 390.5 MiB, sha3 7a7f9bba

    $ BLOCH_BENCH_DIR=/home/ubuntu/g4/n58 \
        ./target/release/deps/bloch_pos-<hash> \
        --ignored --nocapture --test-threads=1 reorg_write_cost_on_a_real_log

    depth       rewrite   replace_tail   speedup
        1       0.541 s        0.002 s      293x
        2       0.520 s        0.001 s      609x
        5       0.531 s        0.001 s      502x
       13       0.566 s        0.001 s      525x
       85       0.556 s        0.002 s      250x

`rewrite` is flat in the reorg depth and linear in the chain; `replace_tail` is
flat in the chain and linear in the depth. Both produced sha3 `7a7f9bba` at
every depth, which is the equivalence claim checked on real data rather than on
synthetic frames.

### A measurement that was wrong first, and why

The first run of this bench reported `replace_tail` at 0.2 s and a 3x speedup.
That number was an artifact of the harness: `copy_datadir` had just written
390 MiB, and the first `fsync` inside the timed region — whichever path issued
it — paid to flush them. The harness now flushes the copy before timing, which
is also the truthful model of production: a node's log is clean when a reorg
arrives, because every `append` already fsynced it. **The 3x figure was mine and
it was wrong; it is recorded here so the corrected one can be trusted.**

## 3. How often it is paid — measured

The cost only matters times the rate, and the rate had never been counted.
`REORG:` lines are written to `~/g4/nNN/node.log` on every fleet box.

    $ for ip in 139.84.201.52 139.84.202.139 139.84.204.46 139.84.205.54 \
                149.28.180.128 67.219.108.230 67.219.108.96; do
        ssh -i ~/.ssh/edgevana_fleet_g4 ubuntu@$ip \
          'for d in ~/g4/n*/; do echo "$d $(grep -c "^REORG:" $d/node.log) \
             $(grep -c "\] applied " $d/node.log)"; done'
      done

Read 2026-09-01 21:05 UTC. Live nodes are those whose `node.log` was still
being written; the rest are the branch abandoned on 2026-08-30.

|                              | nodes | blocks applied | reorgs | rate |
|------------------------------|------:|---------------:|-------:|------|
| live fleet                   |    63 |        297,795 |  **2** | 1 per 148,898 blocks |
| abandoned branch (30/08 fork)|    48 |        118,942 | **28** | 1 per 4,248 blocks |

Two reorgs across the whole live fleet, in a window of roughly 36 hours. Per
node that is **one reorg per ~47 days**. On the branch that was forking, the
rate is **35x higher**.

All 30 `REORG:` lines seen, live and dead, adopted a branch of 1 to 10 blocks.

### What the log line cannot tell you

    REORG: adopted branch of {n} blocks at ancestor {id} (head slot X -> Y)

`{n}` is `branch.len()` — blocks **adopted**. The number of blocks **given
back**, which is the reorg's depth, is not printed and is not derivable: slots
are sparse, so `X - Y` bounds it and does not determine it. Any statement about
this network's reorg depth distribution is unsourced unless it comes from
instrumentation that does not exist yet.

It does not affect the case for the change. What `replace_tail` saves is the
frames *below* the fork point, and at ~29,000 blocks a reorg of depth 1 or of
depth 85 leaves >99.7% of the log untouched either way. The saving is set by
the chain length, which is measured, not by the depth, which is not.

## 4. So is it a problem?

**Not today, and the honest answer is smaller than the change might suggest.**

At 0.55 s and one reorg per node per 47 days, this is not what is hurting
Genesis-4. A claim that the node is paying this bill continuously would be
false: it pays it twice a month.

What makes it worth fixing anyway, at 60 lines:

1. It is a **stall on the consensus thread**, not throughput. 0.55 s inside a
   30 s slot is 1.8% of the budget on an *idle* box; a fleet box runs nine
   nodes.
2. It is **chain-linear**. The live chain grew ~5,000 blocks per node in the
   36-hour window above (~3,300/day). The same reorg costs whatever the chain
   costs, for ever, and nothing else in the reorg path grows this way.
3. The rate is **35x higher during a fork**, which is the one condition where
   a consensus-thread stall is least affordable — and forks are the incidents
   this network has actually had (24/08, 30/08).

That is the whole case. It is a cheap removal of a growing term, not a fix for
a fire.

## 5. Crash safety, and what is *not* proved

`replace_tail` truncates and then appends, where `rewrite` was
atomic-by-rename. The states reachable after a crash are enumerated in the
method's doc comment; every one is a prefix of a chain the node validated, plus
at most one torn frame, which is not a new class of state — `append` already
produces it.

### Verified by violating

Each mutation was applied to `store.rs`, the suite re-run, and the result
recorded. Command: `scratchpad/mutate.py <name>` then `cargo test --bin
bloch-pos store::`.

| mutation | what it breaks | caught by |
|---|---|---|
| M1 remove the byte-comparison precondition | a splice can be written against a log the chain does not describe | `a_splice_whose_precondition_fails_does_not_touch_the_file` (1 test) |
| M2 cut at `fr.offset` instead of `fr.offset + fr.len` | off-by-one at the fork point | 5 tests, incl. both kill tests |
| M3 never truncate — write the branch over the old tail | **the spliced log**, the state the ordering exists to forbid | 6 tests, incl. `a_kill_mid_splice_leaves_a_replayable_prefix` |
| M4 do not shrink the frame table with the file | table describes bytes that are gone | `the_table_after_a_splice_matches_a_fresh_scan` (2 tests) |
| M5 remove the `sync_all` after the truncate | **durability of the truncation** | **nothing, until §5.2** |

M5 is the important row. Deleting the fsync broke **no test in the suite**, and
that is not a gap in the tests so much as a fact about process kills: a
`SIGKILL` does not empty the page cache, so the bytes are identical whether or
not the truncation was ever durable. A kill test cannot see this. It was
measured, not assumed.

### 5.2 The ordering check that closes M5 — partly

`the_truncation_is_made_durable_before_anything_is_written_past_it` runs a
splice under `strace` and asserts the order on the log's own descriptor:

    syscall order on blocks.log: ["ftruncate", "fsync", "write", "write", "fdatasync"]

and that no `write` lands between the truncate and its sync. With M5 applied it
fails, and it is the only test that does.

**This is an ordering proof, not a durability proof.** It shows the calls are
issued in the order that makes the guarantee possible; it assumes `fsync` means
what the filesystem claims. Cutting power to the device is not something this
suite does, and nothing here should be read as having done it. Linux only, and
inert (with a printed warning) where `strace` is absent.

### 5.3 A real kill, on real mainnet history, then a real boot

`a_kill_mid_splice_on_a_real_log_leaves_a_prefix` stages the death inside
`replace_tail` on the 29,377-block log — the branch is handed in as an iterator
that calls `process::abort()` partway through, so there is **no crash hook in
`Store` at all**, and the process really dies between the truncate and the
append (and again inside it).

    realkill/before-append: 29377 -> 29292 frames (cut at 29292)
    realkill/mid-append:    29377 -> 29332 frames (cut at 29292)

Then the real `bloch-pos` binary was pointed at each wounded data dir. Both
came up, replayed what was there, and agreed with the live fleet:

| data dir | frames | replayed to | state root | live fleet at that slot |
|---|---:|---|---|---|
| intact | 29,377 | slot 50239 | `8153f623` | `8153f623`, height 29377 |
| killed **before** the append | 29,292 | slot 50147 | `29eed4be` | `29eed4be`, height 29292 |
| killed **inside** the append | 29,332 | slot 50193 | `f0f97e7b` | `f0f97e7b`, height 29332 |

Live-fleet column read from `139.84.201.52:8080`, `getblockbyslot`, a node
running the **unmodified** binary. Heights match as well as roots.

    $ curl -s -X POST http://139.84.201.52:8080 -H 'content-type: application/json' \
        -d '{"jsonrpc":"2.0","id":1,"method":"getblockbyslot","params":[50147]}'

That is the whole crash-safety claim demonstrated rather than argued: after a
real kill in either window, the node boots to a chain state the network agrees
with. It is not a power-loss test — see §5.2.

## 5.4 State roots do not move

The first row above is also the constraint the change had to satisfy. Replaying
real mainnet history through the modified binary produced head slot 50239 /
state root `8153f623` / 29,377 blocks, byte-for-byte what a live node running
the old code reports for the same slot. Two further slots were checked the same
way and matched (`ac58dd84` at 40000, `28e5c4c6` at 10000).

Replay could not have been affected in any case: `store.append` and
`store.replace_tail` are both inside `if self.live`, which is `false` for the
whole of boot. The cross-check is the evidence, not the argument.

## 6. Reproducing all of it

    # unit + crash + ordering suite (ordering test needs Linux + strace)
    cargo test --bin bloch-pos store::

    # cost, on a real data dir — copies it, never writes to it
    BLOCH_BENCH_DIR=/path/to/datadir \
      ./target/release/deps/bloch_pos-<hash> \
      --ignored --nocapture --test-threads=1 reorg_write_cost_on_a_real_log

    # a real kill mid-splice on a real log
    BLOCH_BENCH_DIR=/path/to/datadir \
      ./target/release/deps/bloch_pos-<hash> \
      --ignored --nocapture --test-threads=1 a_kill_mid_splice_on_a_real_log
