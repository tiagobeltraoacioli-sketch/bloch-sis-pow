# Wave 57 NET-22: leak-free RPC worker admission

Date: 2026-09-18. Base: `ab06afc`. Scope: existing RPC connection admission,
one pure regression and this evidence note. No endpoint, request/response
shape, network protocol, wire encoding, consensus rule, persisted format or
deployment changed.

## Correction

The RPC listener already admitted at most eight connections per normalized
source IP and 64 workers globally. Its per-IP allowance was represented by an
RAII guard, but the global counter depended on an explicit decrement after
`serve_connection` returned. An unexpected panic while parsing, formatting or
calling a backend unwound past that decrement. The per-IP allowance recovered,
but one global slot remained occupied until process restart; repeated panics
could permanently exhaust the listener's worker allowance.

Admission now returns one `RpcConnectionPermit` that owns both the existing
per-IP guard and one global count. The permit is acquired before the worker is
spawned and lives inside that worker. Its destructor returns the global count,
while the embedded address guard returns the normalized-IP count, on normal
completion, early return or unwind.

The numerical policy is unchanged: eight workers per normalized IP and 64
globally. Refused connections retain the existing close-without-worker
behavior.

## Regression

`rpc_connection_admission_releases_per_ip_and_global_slots_together` exercises
the helper without sockets. It proves that:

- IPv4 and its mapped IPv6 spelling share the eight-worker source cap;
- another source retains capacity after the first reaches its cap;
- dropping a combined guard restores both charges; and
- distinct sources cannot exceed 64 workers globally, with the count returning
  to zero after every guard is dropped.

Validation on this checkout:

- focused RPC connection-admission regression: 1 passed;
- `git diff --check`: passed.

No listener test, workspace-wide formatter or broad suite was run.

## Residual

NET-22 remains **PARTIAL**. These are node-local resource bounds, not client
identity or authorization. Distributed addresses can fill the global worker
allowance, clients behind one NAT share eight slots, and a routable RPC remains
unauthenticated and dependent on external firewall policy. RPC methods that
touch the block store, mempool or transaction status still execute on the
consensus thread. Libp2p still allocates its bounded gossip frame before the
application admission callback, and a valid unindexed block-log tail can still
be long.
