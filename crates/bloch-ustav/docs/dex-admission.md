# Signed-operation admission for the local DEX host

The optional `native-dex-host` feature exposes `dex_admission::PendingBatch`.
It accepts signed `pool_wire` operations, allowing a host to assemble a candidate
without asking a wallet to construct the final post-state commitment. It is a
volatile queue for one candidate, not a production mempool or an HTTP endpoint.

## Admission and execution

`PendingBatch::new(&journal, height)` binds the queue to the journal's current
height/root and a later height supplied by the authenticated host. A poisoned
journal cannot start or service admission. Callers cannot provide a different
signature verifier or choose another parent through an operation frame.

`admit(&journal, frame)` reexecutes the entire ordered prefix plus the new frame
using fixed hybrid PQ verification. This supports deposits or swaps that consume
outputs created by earlier pending operations. It checks resource limits before
copying the new frame and appends bytes only after successful verification. The
returned outcome is a preview; no balances, fees, reserves or journal bytes have
changed and no inputs have been reserved. Invalid signatures, wrong domains,
expiry, dependencies or duplicate requests leave the previous queue intact.

`build(&journal)` revalidates the pending prefix and constructs an ordinary
`BLCHPCAN` candidate without modifying the queue or persistent state.
`commit(&mut journal)` builds the candidate and submits it through the journal's
own full verification and write/sync/commit boundary. Only success clears and
closes the batch. Any failure preserves pending frames; journal I/O failures
also poison the journal according to its existing recovery contract.

The complete parent checkpoint is checked on every operation. A batch becomes
stale if another candidate changes the journal, including a competing batch from
the same parent. The host must create a new batch and revalidate resubmitted
operations; the API does not silently rebase them or trust an earlier preview.
A successfully committed batch cannot be reused.

## Bounds and trust boundary

The queue retains at most 128 signed frames and 262,144 payload bytes. Count and
actual byte bounds precede allocation of a new payload. The existing batch
preflight also limits aggregate declared bytes and gas before cryptography.
Exact duplicate frames are rejected directly; alternate encodings or witnesses
cannot evade the underlying input-spend, authorization and replay checks.

Each admission revalidates its prefix; across a full queue the verification work
is quadratic in operation count, bounded by the fixed limits. Build and durable
commit revalidate as well. Production ingress still needs authenticated context,
rate and connection limits, scheduling and CPU/memory measurements. This API
does not promise fairness, reserve funds or report a transaction as finalized.

Pending frames are intentionally not durable and are lost if the host exits.
Clients must distinguish a successful preview from a durable commit and from
consensus finality. Only the existing candidate journal persists committed local
results. Neither queue admission nor journal commit authorizes a bridge payout.

## Validation

Real hybrid PQ integration tests enqueue two dependent deposits and a provider
redemption, then commit and reopen the journal. They check invalid signatures,
wrong domains, expiry, out-of-order operations, duplicates, malformed later
frames, stale parents and closed-batch reuse. Preview and rejection preserve the
confirmed state and file bytes; commit matches direct execution, fees and
custody. Capacity tests cover exact byte/count limits and arithmetic overflow.

No live node dependency, RPC route, block transaction variant, fee settlement,
wallet connection flow or bridge activation is introduced by this local API.
