# Wave 43: network and transport reconciliation

Date: 2026-09-18. Base: `45ae11e`. Scope: local source, tests and audit
ledger only. No node, validator, public endpoint or fleet configuration was
contacted or changed. This wave does not change consensus rules, activation
epochs, persisted formats or network wire encodings.

## Source recovery

The current six-artifact bundle preserved NET-21 and NET-22 only as aggregate
titles. Their itemized source was recovered from repository history at
`a79c88b:docs/audit/deep-audit-2026-09-16/A6-node-network-rpc.md`. This is the
same A6 referenced by the consolidated report and the all-findings table; it is
not a reconstructed or guessed list.

## NET-07 — engine-judged libp2p height hints

The existing scheduler already reserves one of three fanout positions for a
bounded rotation independent of height and shares exact request-ID accounting
across timer, connection and page-chase callers. The remaining defect was that
both gossip and directed-sync decode paths raised `peer_head` before the engine
had judged the block.

`Origin` now carries optional block provenance independently of a gossipsub
message id. Gossip blocks carry both forms; directed-sync blocks carry the peer
and slot only. Every engine verdict is returned through the command channel.
Only `Accept` may raise the hint, and only while that PeerId remains connected.
`Ignore` and `Reject` leave it unchanged. `forget_peer` removes the hint at the
last disconnect, and a late verdict cannot recreate it because the swarm loop
checks current connectivity first.

This is local request-selection policy. It does not claim that an
engine-admitted block is canonical progress, and it does not provide Sybil
resistance. The independent rotating fanout position remains necessary for
those reasons.

## Reconciled network findings

- NET-15 remains **PARTIAL**. Shared finite FIFO leases stop an all-peer burst
  in the current implementation, but legacy devnet responses still have no
  request id, page terminator or explicit empty response. Exact response
  completion accounting would require a separately qualified wire change or
  connection cancellation.
- NET-16 remains **IMPLEMENTED**. The metrics reader uses one absolute
  whole-request deadline across the request-head loop.
- NET-17 remains **IMPLEMENTED**. Devnet serving uses an aggregate 8 MiB
  encoded-page budget in addition to the frame cap and block-count cap.
- NET-19 remains **IMPLEMENTED**. New libp2p identities use the shared private,
  atomic, fsynced write under the data-directory lock.
- NET-20 remains **PARTIAL**. Local production packs and signs only a
  transport-carryable deterministic attestation prefix. Incoming or historical
  consensus-valid blocks above transport limits remain a compatibility and
  protocol-design problem; this wave does not reject them or change caps.

## NET-21 — recovered information-exposure items

The aggregate contains four informational observations:

1. `getbuildinfo` deliberately exposes compiler version, target, commit and
   source digest. Its response is regression-tested not to expose operational
   paths or secrets.
2. `/health` and `/metrics` expose validator activity and whether the keystore
   is sealed. Metrics are off by default and loopback-bound when enabled, but a
   routable deployment would disclose useful targeting information.
3. libp2p identify exposes the standard agent version and listen addresses.
4. `getchaininfo` exposes transport and peer counts, not peer addresses; there
   is no `getpeers` RPC.

These are intentional observability/interoperability choices with local-default
controls, not evidence that a routable metrics endpoint is safe. NET-21 is
therefore recorded as partial reconciliation rather than security closure.

## NET-22 — recovered minor code notes

The aggregate contains five bounded or residual observations:

1. Devnet allocates the declared frame buffer (at most 8 MiB) before payload
   completion. The whole-frame deadline and length cap bound the operation.
2. Devnet decodes a complete frame before engine-queue admission. Per-source
   and aggregate reservations bound retained work after decode, but do not
   eliminate per-connection decode CPU.
3. RPC and metrics emit a small overload response from the accept thread. The
   response fits an ordinary kernel send buffer; no practical blocking path was
   established by the audit.
4. RPC Host policy is a browser-origin control, not authentication. A client
   can send an allowed Host value; public exposure remains governed by the
   separate RPC findings.
5. A runtime block-index/log disagreement falls back to a full-log scan. Boot
   rebuilds the disposable index, but the corruption fallback can reopen the
   historical scan cost until restart or repair.

No speculative code change was made for these informational notes. NET-22 is
itemized and retained as partial because decode-before-admission and the
corruption fallback remain real residuals.

## Validation

Targeted offline tests on the pinned Rust 1.94.1 workspace:

- `cargo test -p bloch-pos-node sync_height_hint_requires_engine_acceptance_and_is_monotonic --offline`
- `cargo test -p bloch-pos-node directed_sync_origin_reports_every_engine_verdict --offline`

Both passed. The first covers `Ignore`/`Reject`, monotonic `Accept`, and
disconnect cleanup. The second proves that directed-sync origins enqueue all
three engine verdicts instead of becoming no-ops. Existing workspace warnings
remain; no new warning was introduced by this change.

`cargo fmt --all -- --check` remains unsuitable as a wave gate because the
inherited tree has broad pre-existing formatter drift. `git diff --check` is
the scoped whitespace gate for this wave.
