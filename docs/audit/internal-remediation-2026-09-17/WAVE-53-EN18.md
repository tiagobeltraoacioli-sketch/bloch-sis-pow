# Wave 53 EN-18: static build identity bypasses consensus

Date: 2026-09-18. Base: `405bfb0`. Scope: local RPC dispatch, one regression
and the audit ledger. No endpoint, response field, consensus rule, activation
gate, persisted format, network protocol or deployment changed.

## Correction

`getbuildinfo` is a process-identity query. Its complete response consists of
compile-time strings and reads no chain, mempool, block store or network state.
It nevertheless followed the general RPC route: reserve one of the 16 engine
queue permits, send an event to the consensus thread and wait for that thread
to construct the static JSON object.

The production backend now recognizes this request before queue admission and
returns the existing `build_info_json()` derivation directly. The engine arm is
retained as a compatibility fallback for direct engine callers and tests, so
there is still only one response formatter and no response-shape fork.

This removes static identity polling from both the bounded engine RPC budget
and the consensus event loop. It does not introduce a snapshot or a second
chain-derived source of truth.

## Regression

The regression constructs an `EngineBackend` without a published head and
drops the engine receiver. `BuildInfo` must still return this binary's compiled
source digest, proving that it neither sends nor waits on the engine channel.
The same backend must fail `ChainInfo`, proving that the local path did not
accidentally absorb a chain-owned request.

Validation on this checkout:

- focused queue-bypass regression: 1 passed;
- complete `rpc::tests` selection: all 46 non-socket tests passed; the 17 HTTP
  cases failed before assertions because this sandbox denies ephemeral
  loopback binds (`PermissionDenied`);
- the pre-existing direct-engine build-info test is likewise blocked while
  constructing its devnet listener, before it reaches the RPC assertion.

The workspace-wide formatting check reports extensive pre-existing drift in
unrelated crates; no bulk formatter was applied.

## Residual

EN-18 remains **PARTIAL**. Block lookup, envelope cloning and JSON
serialization; chain information and block count; mempool and transaction
status; and transaction submission still cross the engine queue and execute on
the consensus thread. The 16-request bound limits retained work but does not
make those operations independent of slot processing. Public RPC exposure and
fleet firewall policy were not inspected or changed.
