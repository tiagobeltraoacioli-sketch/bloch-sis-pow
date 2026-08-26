# WP7 — the one number, and the one it turned out to hide

Binary: `bench/bloch-pos-wp7`, **release**, built from this worktree at WP3
`9f8ca097` merged into `pmo/wp7-syncmeasure`, into a PRIVATE target dir. Every
run asserts the `engine: draining at most N event(s) per tick` line before it
counts. Fixtures and raw logs: `bench/fixture*`, `bench/out*`, `bench/driver*.log`.

## A. Throughput — what the bound COSTS (fixture: 899 blocks, 4.67 MB, observer client)

| condition | runs | median blk/s | spread | worst tick |
|---|---|---|---|---|
| unbounded (`=0`) | 6 | 48.1 | 46..48 (±5%) | 4606 ms |
| cap 256 | 6 | 47.9 | 47..49 (±4%) | 5088 ms |
| cap 64 | 6 | 47.9 | 47..49 (±4%) | 1390 ms |
| cap 32 (WP3 default) | 6 | 47.9 | 29..48 (±40%) | 709 ms |
| cap 16 | 6 | 47.8 | 43..48 (±11%) | 387 ms |
| cap 4 (PR proposal) | 6 | 47.1 | 45..48 (±6%) | 110 ms |

The bound is 75x tighter from top to bottom and throughput moves 2%, inside the
noise. Ticks per run went 4 -> 300 while elapsed-to-tip stayed 18.6-19.9 s.

## B. Duty starvation — what the bound BUYS (fixture: 649 blocks, client is validator v2)

| condition | runs | slots skipped | worst single stall | proposed | attested |
|---|---|---|---|---|---|
| unbounded | 6 | 68 | **69 slots (10.4 s)** | 1 | 1 |
| cap 256 | 6 | 68 | 36 slots (5.4 s) | 2 | 2 |
| cap 64 | 6 | 77 | 10 slots (1.5 s) | 7 | 10 |
| cap 32 | 6 | 65 | 5 slots (0.75 s) | 16 | 22 |
| cap 16 | 6 | 46 | 3 slots (0.45 s) | 31 | 44 |
| cap 4 | 6 | **0** | 1 slot (0.15 s) | 93 | 94 |

Monotone, and reproducible to the slot: unbounded gave 69/69/69/69/73/69 across
six runs, cap 4 gave 1/1/2/1/2/1.

## C. Why 4 costs nothing, which is not obvious

`recv_timeout` blocks only while the channel is EMPTY. With a backlog it returns
at once, so a bounded drain does not batch work into 500 ms ticks — it re-enters
the loop immediately, and the only cost is the per-tick slot arithmetic, which
is microseconds against a ~21 ms block.

## D. The founder's ~8 blocks/s ceiling — refuted, and why

Boot replay does NOT pass through the bounded drain. Pre-patch line numbers:
`engine.rs:2214` `store.read_all()`, `:2330` `for (i, env) in logged...`,
`:2342` the `{rate:.1} blocks/s` line — all inside a plain `for` over a Vec,
never touching `rx`. The bound governs `:2553`. The 10-12 blocks/s figure is
from the replay loop and cannot be the baseline for the drain.
