# Wave 51 EN-23: linear canonical cold replay

Date: 2026-09-18. Starting point: `2abb416`. Scope: local block-log replay,
recovery regressions and audit evidence. No persisted format, consensus rule,
activation gate, deployment or live data changed.

## Recovered residual

Wave 50 removed the raw whole-log byte copy by decoding one bounded frame at a
time, but boot still passed every decoded canonical frame through ordinary
network ingestion. That path inserted the frame as a fork-choice candidate,
recomputed LMD-GHOST over the growing block map, and scanned finalized branch
pruning after every accepted frame. On a cold replay of `N` canonical frames,
the repeated prefix work remained quadratic even though `blocks.log` already
records the selected canonical order.

## Local correction

`Engine::ingest_replay` is now a dedicated canonical-extension operation. Each
frame must name the current durable head as its parent, must not duplicate a
known block, and must pass the unchanged full `Transition::apply_block` path.
Only then is it added to the canonical block map. A gap, duplicate, malformed
body, invalid proposer signature, invalid state root or any other transition
failure stops boot before the node can serve a partial head.

The replay path does not run fork choice, orphan release or branch pruning:
none can contribute information while rebuilding one already-selected linear
log into initially empty branch/orphan collections. It still reconstructs the
bounded recent authenticated-proposal window after transition verification, so
live equivocation observation after boot retains its prior local context.

The ignored end-to-end replay benchmark now calls the same `ingest_replay`
entry point as production boot. Its fork-choice timing column is explicitly a
zero-cost regression signal rather than a component of expected replay work.

## Compatibility and boundary

The `u32 length || envelope` log bytes, state/cache encoding, block ID,
transition verdict, state root and live gossip/fork-choice paths are unchanged.
The optimized assumption is narrow and checked on every frame: only the node's
own locked canonical log reaches this method.

EN-23 remains `PARTIAL`. Boot still retains all decoded canonical envelopes in
`Engine::blocks` and `Engine::chain`; transition cost can grow with committed
state; reorg fallback can replay an old prefix; and this wave supplies neither
production-scale peak-RSS measurements nor a qualified restart SLA. It removes
the known repeated fork-choice and empty-branch-pruning prefix scans, not every
possible source of chain-age growth.

Ledger status and aggregate counts remain unchanged.

## Validation

- `cargo test -p bloch-pos-node --bin bloch-pos boot_replay --offline --
  --nocapture`: 2 passed.
- `cargo test -p bloch-pos-node --bin bloch-pos local_cache::tests --offline --
  --nocapture`: 6 passed.
- The new regression proves out-of-order frames and a forged proposer
  signature fail without moving state or entering the block map, then proves
  the same two valid frames replay to the expected head in order.
- Both fixture groups required loopback socket permission outside the sandbox;
  the initial sandbox refusal was `PermissionDenied`, not a test failure.
