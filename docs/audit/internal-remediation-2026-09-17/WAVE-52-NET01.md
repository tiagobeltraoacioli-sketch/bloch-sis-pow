# Wave 52: state-only validator RPC isolation

Date: 2026-09-18. Base: `c8ab7c8`. Scope: local RPC dispatch, regressions and
audit ledger only. No endpoint or deployment changed, and no consensus rule,
activation gate, persisted format or wire response changed.

## Correction

The RPC backend already receives the exact immutable `Arc<CommittedState>`
published by the consensus owner and used it for eUTXO reads. Four methods
whose complete answer also lives in that state still crossed the bounded
engine queue and executed on the consensus thread: `getvalidator`,
`getvalidatorcount`, `getvalidatorbykey` and `getvalidators`.

These methods now clone the published `Arc` under the existing short mutex and
derive their response after releasing the lock. A caller sees one complete
committed head, before or after a block, never a partially applied state.

The engine fallback and published-head backend call the same response helpers.
Validator-not-found codes, lifecycle fields, effective stake, registry order
and JSON types therefore retain one derivation rather than a snapshot-specific
implementation.

## Validation

The production backend is constructed in the regression with its engine
receiver deliberately dropped. Balance, UTXO and all four validator reads
still answer, including a by-key lookup and `VALIDATOR_NOT_FOUND`;
`getchaininfo` still fails because its chain-store and peer-count inputs are
not present in `CommittedState`. This proves the intended split.

- Focused published-head regression: 1 passed.
- Complete `rpc::tests`: 61 passed outside the sandbox, where the existing
  HTTP tests may bind loopback sockets.
- The initial sandbox run had 44 passes and 17 loopback `PermissionDenied`
  failures; none reached an assertion in the changed RPC logic.

## Residuals

NET-01 and EN-18 remain **PARTIAL**. Block lookup/serialization, chain info,
block count, mempool info, transaction status and transaction submission still
cross the engine queue; several require data intentionally owned only by the
consensus thread. Public RPC exposure and firewall state were neither
inspected nor changed. Snapshot answers may be one committed head older if a
block lands between cloning the `Arc` and writing the reply, the same ordinary
race already documented for eUTXO reads.
