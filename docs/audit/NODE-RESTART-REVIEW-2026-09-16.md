# Node restart review — 2026-09-16

## Scope and release evidence

Reviewed the actual explorer-distributed `2026-09-14/bloch-pos-source.tar.gz`:
SHA-256 `29784c856c89a341376f51276d067b5c35cf01bb2a008a7654185c5d5db993dd`.
The published release metadata names commit
`58da5ce209acb6e293b3b381dfd826dedb8741fd`.

In that archive, `engine.rs:4680` reads the complete log, line 4879 replays it,
and line 4994 explicitly places the WS decision after replay. The cited 0.59
seconds/block comment appears at line 4863. The same archive's `transition.rs`
already contains an incremental UTXO Merkle tree (line 1815), so the old comment
is not a measurement of the current hot path and cannot establish a present SLA.

The candidate is based on `5af78a0`, isolated in branch
`fix/persisted-restart-recovery`. No live validator, archival service or exchange
node was restarted, modified or upgraded. No message was sent to Biconomy.

## Findings addressed

- Every restart re-executed all historical state transitions. Add a disposable,
  build-bound local cache of complete committed state and normal tail replay.
- The reorg ring was memory-only. Add atomic disk persistence with a previous
  generation, log-prefix integrity binding and state-root verification.
- Cache corruption must not become a trusted state. Validate before mutating the
  engine; reject incompatible/malformed caches and retain full replay fallback.
- Operators lacked an explicit bound on restart execution. Add strict cache mode
  and an optional replay-block ceiling, separate from wall-clock availability.
- A torn trailing log frame was ignored while its bytes remained before future
  appends. Repair only an incomplete tail before append; refuse repair if it
  overlaps indexed history or a length is oversized. Test restart/append/restart.
- Boot replay could discard a rejected durable block and continue toward service.
  Require each log block to become the canonical head or abort startup.
- The 0.59-second comment conflated an old measurement with current code. Replace
  it with the actual recovery policy and provide a parameterized projection tool.

## Trust and remaining limits

This is a cache of state the local node already validated. It is not authenticated
remote state-sync. Checksums are not authorization to load a downloaded snapshot.
The complete log, manifest, carryover and normal WS gate remain necessary.

The cache codec accounts for every CommittedState field through exhaustive
construction/destructuring; added fields require a compiler-visible codec update.
It persists the finality leak ledger rather than reinitializing it through
`FinalityState::new`/`ws::anchor`. Header-derived BlockId remains opaque.

The source identity check intentionally causes a full-replay migration between
builds. Startup still reads historical log/canonical metadata and reconstructs the
state's indexes. Deep reorgs can still fall back to historical execution. Snapshot
writes are synchronous; benchmark write stalls and peak memory before fleet use.
The configured file cap is 512 MiB. No claim of constant-time startup is made.

Current mainnet height could not be corroborated: on 2026-09-16 the two public RPC
URLs tried returned `no_upstream_answered` with timeouts/504s at the archival
observers. This does not prove a chain halt. It prevents a defensible measurement
of restart time at the current live height from this environment.

See `docs/operations/LOCAL-RESTART-CACHE.md` for migration, strict mode, fallback,
backup, readiness criteria and production qualification requirements. See the
Biconomy response for the externally shareable answers.

## Validation

- Node release suite: 382 passed, zero failures, 19 intentionally ignored.
- Committee debug suite with the local-state-cache feature: 423 passed, zero
  failures, four intentionally ignored.
- Final targeted cache tests: five passed; recovery budget/index-corruption tests:
  two passed; the revised bare-WS-anchor test also passed.
- The committee release-profile run had 421 passes and two failures in existing
  tests that expect debug-assertion panics. Those assertions are absent in release
  by design; the complete debug run passed. This release-profile result is not
  reported as a clean suite.
- Local process qualification covers a keyless observer, a seven-block tail,
  SIGKILL followed by zero-tail restart, equality with full replay, previous-cache
  recovery, and strict refusal when both generations are corrupt. The JSON record
  binds results to the binary SHA-256 and source digest.

Reproduction:

```sh
cargo test -p bloch-pos-node --release --bin bloch-pos --offline -- --test-threads=2
cargo test -p bloch-pos-committee --features local-state-cache --offline
BLOCH_BENCH_CARRYOVER=452726 BLOCH_BENCH_BLOCKS=96 cargo test -p bloch-pos-node --release --bin bloch-pos perf_local_cache_recovery --offline -- --ignored --nocapture
cargo build -p bloch-pos-node --release --offline
python3 scripts/qualify-local-restart.py --binary target/release/bloch-pos --output docs/audit/reproducers/restart-process-qualification-2026-09-16.json
```

Benchmark generation, full replay and cache restoration use separate execution
threads so thread-local consensus memoization does not carry over. Filesystem
caches and host contention are uncontrolled. Each fixture has 64 validators,
96 blocks and a 31-block replay tail. These are single local samples, not mainnet
history, percentile estimates or a production RTO. Earlier warmed measurements
are retained separately and must not be described as cold restart results.

## Cold application-cache measurements

The JSON record `reproducers/restart-cold-benchmarks-2026-09-16.json` preserves
raw results. On the local i9-9880H, the 8,192-entry fixture took 1.706 seconds
for genesis initialization + log read + restore + 31-block tail. The 452,726-entry
fixture took 87.442 seconds, of which 77.018 seconds was genesis initialization,
0.012 seconds log reading, 2.379 seconds restoration and 8.032 seconds tail replay.
The larger cache was 33,752,967 bytes and its measured write took 301 ms.

The reference genesis + full replay including comparison-cache write was 2.329
and 84.489 seconds respectively. At only 96 blocks, the larger fixture does not
show an end-to-end speedup. Startup initialization and uncontrolled host load
matter; the evidence supports elimination of prefix execution, not a fabricated
constant startup latency or a guaranteed speedup at every height. Future startup
optimization should address the costly genesis/carryover construction, while
qualification must measure a complete current mainnet log on the target machine.

Final release build and all five process qualification scenarios passed.
Binary SHA-256: `38b2b7453473bfed00f1765d9b6015eaa81a89fe5e7cfbaea7ae2dcd62a814ec`.
Source-tree SHA3-256: `de31f24a0e3746f54ddf673e8ed4b2f0814cd52a1ff50b151fc3518990f7c157`.
Target: `x86_64-apple-darwin`. The candidate has not been deployed to mainnet.
