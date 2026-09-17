# Genesis-4 node restart and recovery — response to Biconomy

16 September 2026

Dear Biconomy Integration Team,

Your reading of the 14 September source release is correct: the durable block
log is replayed on startup, the reorg snapshots are memory-only, and the
weak-subjectivity checkpoint does not supply a later ledger state. You did not
miss a supported fast-start flag in that release.

We have addressed the restart path in a new candidate implementation. We distinguish
that implementation from the published release below: we are **not** representing
this candidate as already deployed or as a qualified production SLA.

## 1. Persisted state and fast restart

The candidate writes a local committed-state cache after the first verified startup,
every 32 canonical blocks thereafter, and after a durable reorg rewrite. A restart
restores a compatible cache and verifies only the blocks after its recorded head.

This persists the complete consensus state, including the UTXO ledger, validator
registry, RANDAO state, finality and inactivity-leak accounting, slashing history,
queues and reward counters. It does not reset finality bookkeeping. The node
reconstructs derived indexes and verifies the restored state root against the
corresponding block header.

Cache files are bound to the network manifest, source build and exact durable log
prefix. Writes use fsync and atomic rename; one previous generation is retained.
Corrupt, incomplete, wrong-build or wrong-chain caches are rejected. The ordinary
fallback remains fully verified replay. We also fixed handling of an incomplete
last log record so subsequent appended blocks cannot be stranded behind it.

For supervised exchange operation the candidate adds:

```text
--require-state-cache --max-replay-blocks 63
```

This refuses startup when no valid cache is available or the tail exceeds the
configured limit, rather than silently beginning hours of historical execution.
Normally the periodic cache leaves at most 31 blocks; 63 permits recovery through
one older generation. Those bounds assume successful periodic writes. A limit on
blocks is not itself a wall-clock SLA.

**Availability and timeline:** the implementation and qualification tools have
been prepared on 16 September. They are not present in the 14 September binary.
Production publication remains gated on qualification of the intended Linux
binary against the current mainnet log and target host, followed by a standby-node
rollout. We do not have evidence to give a defensible production-release date yet.

The first move from the published release to this candidate requires one full
replay to create a cache derived from the node's own validation. Source-build
changes currently invalidate caches as well. These migrations should be performed
on a standby observer while the existing observer remains available.

## 2. Weak-subjectivity checkpoints and skipping history

You are correct about `--ws-checkpoint` and `--ws-signer-set`: they establish the
trust anchor and do **not** shorten replay in the published release. The checkpoint
contains commitments, not the UTXOs, queues and accounting state necessary to
execute the next block.

The candidate's acceleration comes from the node's own persisted state, independently
of those flags. The normal weak-subjectivity checks still run before service.
There is no new permission to truncate the historical log, skip verification of
previously unseen blocks, or bootstrap from an arbitrary downloaded cache.

**Keep the complete log.** Authenticated remote state-sync and log pruning are
separate capabilities and are not claimed here. A trusted backup must retain the
matching data directory and supporting genesis/carryover/WS artifacts. Validator
keys and slashing-protection records must never be duplicated among live signers;
exchange read observers can remain keyless.

## 3. Concrete recovery time and what is supported

We cannot honestly give the 14 September release a guaranteed minutes-level
restart time at today's chain height. It has no such qualified recovery bound.
The 0.59-second figure in the source is an old measurement, not a supported SLA.
That archive already contains the incremental UTXO Merkle-tree implementation, so
extrapolating that comment as the current per-block runtime is not reliable.

The candidate passed two local fixtures on an Intel Core i9-9880H at 2.30 GHz,
macOS, release build, with 64 validators and 96 blocks. Each restart restored
65 blocks from cache and executed the remaining 31. Fresh execution threads
prevented reuse of thread-local consensus caches from fixture generation;
filesystem caches and competing host load were uncontrolled.

| Fixture ledger entries | Genesis + full replay¹ | Genesis + cache + 31 blocks |
| ---: | ---: | ---: |
| 8,192 | 2.33 seconds | 1.71 seconds |
| 452,726 | 84.49 seconds | 87.44 seconds |

¹ The reference measurement includes writing the comparison cache. These are
single in-process samples, not equivalent end-to-end process/RPC measurements.
The larger fixture does **not** demonstrate a total-time speedup at 96 blocks.
Its cached run spent 77.02 seconds initializing genesis/carryover, 0.01 seconds
reading the log, 2.38 seconds restoring state and 8.03 seconds executing the tail.
It demonstrates that the cached prefix avoids historical execution, while also
exposing substantial startup work that this change does not remove. A longer
historical log still needs to be measured directly.

Separate real-process devnet tests passed cache-and-tail recovery, restart after
SIGKILL, identical state root/head versus full replay, recovery through the previous
cache generation, and refusal when both caches are corrupt. Those process tests
use a tiny ledger and establish failure behavior, not large-ledger latency.

These measurements establish the candidate's behavior on the stated fixtures and
host. They do not establish recovery latency for the full current mainnet history
or Biconomy's infrastructure. Our public RPC checks during this review returned
archival timeouts, so we have not substituted an assumed current height for a
verified one.

There are three different operational milestones:

1. Local state restored and the stored tail validated.
2. RPC answering from that state.
3. Caught up to a fresh, consistent and sufficiently finalized chain view to
   authorize deposits or withdrawals.

Validator mode separately retains its default 64-slot doppelganger observation
window (32 minutes at the mainnet cadence) before signing duties. This is not an
observer RPC delay, and cache recovery does not bypass it.

The third is the exchange-service readiness condition. It can take longer than
RPC availability, and must be evaluated independently. The candidate reports
recovery mode, skipped and replayed block counts, and elapsed cache/replay time.
The process qualification tool measures RPC readiness separately.

Before committing an RTO, we need the target CPU/RAM/storage, current mainnet log,
expected workload, required maximum downtime and repeated warm/cold restart runs.
A healthy independent standby is the operational answer during initial migration,
cache failure, storage failure or a source upgrade; the cache is not a replacement
for that redundancy.

## 4. Growth projections and the operational limit

At 30 seconds per slot there are 2,880 slots/day. Actual blocks/day can be lower
because a missed slot contributes no block to replay.

For full replay, the relevant model is the sum of historical execution costs:

```text
T_full(N) = startup + log/index work(N) + sum(c(k), k = 0 .. N-1)
```

If `c(k)` is approximately constant, execution grows linearly. If it grows with
state size, validator/queue history or fork-choice work, the sum can be super-linear.
The incremental UTXO tree removes a particular full-tree recomputation; it does not
prove that every per-block operation is independent of state or history size.

The candidate changes the execution term to a short tail:

```text
T_cached(N, D) = startup + log/index work(N) + restore current state
                 + sum(c(k), k = N-D .. N-1)
```

It still reads historical log/canonical metadata and reconstructs the state indexes.
It is therefore **not constant-time startup**, nor a guarantee against future state
or disk growth. Deep reorgs can also require historical execution. The current
cache-file limit is 512 MiB and writes are synchronous; disk space, write stalls
and peak RAM must be part of capacity qualification.

There is no hardware-independent height at which replay becomes prohibitive.
The threshold is where the measured recovery path exceeds the agreed RTO, available
memory or storage budget. As an illustration only, the historical assumption of
0.59 seconds/block gives 7,198 seconds (about two hours) for 12,200 blocks, before
other startup work. Under that assumption a five-minute execution budget is already
exceeded at 509 blocks. These are arithmetic scenarios, **not current benchmarks**.

We have provided a parameterized projection tool so the coefficients, daily block
rate, tail budget and RTO are explicit. The intended operational policy is to
qualify cached restart, monitor its actual age and cost, keep independent observers,
and fail over when the recovery budget is exceeded. It is not to accept indefinitely
growing replay downtime or weaken the WS/finality checks to hide it.

The accompanying operator runbook and validation records describe the exact flags,
trust assumptions, failure behavior and release gates. We will distinguish a
measured and qualified production commitment from a local benchmark throughout
that process.

Regards,
Bloch Engineering
