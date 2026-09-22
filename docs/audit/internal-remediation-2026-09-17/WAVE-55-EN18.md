# Wave 55 EN-18: published block-count polling

Date: 2026-09-18. Base: `da2eb46`. Scope: local RPC dispatch, canonical
summary publication, regressions and this report. No ledger row, endpoint,
response field, consensus rule, activation gate, persisted format, network
protocol or deployment changed.

## Correction

`getblockcount` is a polling endpoint whose six-field response combines
canonical height/slot with justified and finalized progress. Each request
previously reserved one of the 16 engine RPC permits, entered the consensus
event loop and derived that small response there.

The engine now publishes the complete response after every canonical mutation
path: successful direct extension, successful reorg and authenticated local-
cache restore. The cache path matters when it consumes the entire log and no
tail block remains to trigger ordinary application. Publication happens only
after both committed state and canonical chain have moved. One mutex protects
the complete JSON value, so a reader observes either the prior committed
generation or the next one, never a new height combined with old finality.

The engine fallback and published path share `block_count_reply`; the snapshot
does not reimplement height or finality derivation. Boot replay publishes as it
advances, and the RPC server still starts only after replay and weak-subjectivity
checks, so no client can observe the initial genesis placeholder during boot.

Existing `EngineBackend::new` and `with_head` callers retain their routing
behavior. Production explicitly supplies the additional canonical-summary
handle.

## Regression

The backend regression drops the engine receiver, supplies a distinctive
published height/slot/finality response and proves `BlockCount` still returns
that exact complete value. `ChainInfo` must fail through the same backend,
showing that chain-owned methods were not accidentally routed to the snapshot.

The engine continues to derive direct `BlockCount` responses through the same
helper, preserving the fallback used by engine-level tests.

Validation:

- complete `rpc::tests` selection: 64 passed;
- local-cache restore/publication regression: 1 passed;
- snapshot/replay reorg regression, including publication assertion: 1 passed;
- scoped `git diff --check`: clean.

## Residual

EN-18 remains **PARTIAL**. Block lookup, envelope cloning and serialization;
chain information; mempool and transaction-status reads; and transaction
submission still cross the engine queue and execute on the consensus thread.
A polling response can be one committed head older when a block lands between
cloning the published value and returning it, the same ordinary race present
when a queued answer crosses its reply channel. Public RPC exposure and fleet
firewall policy were not inspected or changed.
