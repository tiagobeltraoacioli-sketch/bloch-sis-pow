# Wave 63 — NET-04/EN-07 RPC source fairness

Date: 2026-09-18
Requested base: `cef4b8e`

## Change

The HTTP RPC listener now carries the accepted socket's peer address through
JSON dispatch, the bounded engine queue, and the consensus-thread RPC call.
Only `sendrawtransaction` consumes it: transaction admission supplies the
derived identity to the shared gossip verifier's existing limits of 128 hybrid
verifications per attributed source and 1,024 in aggregate per wall slot.

IPv4-mapped IPv6 addresses are normalized to IPv4 before hashing, matching the
listener's existing connection accounting. The engine receives only a
domain-separated 32-byte digest, not a new protocol-visible identity. Embedded
or source-free callers retain the aggregate-only behavior.

No JSON-RPC parameter or response schema, network wire format, consensus rule,
fork-choice input, or persistent format changed.

## Overload and retry

Per-source and aggregate exhaustion remain node-local load. They return the
existing retryable `TX_REFUSED_RETRYABLE` error with `until_slot` set to the
next wall slot. They never become invalid bytes, a peer penalty, or a durable
rejection-cache entry, and no partial mempool insertion occurs.

Exact cached signature failures are still checked before quota reservation.
Thus a replay of the exact known failure consumes neither the RPC source share
nor aggregate headroom.

## Regression coverage

- `verification_identity_normalizes_ipv4_mapped_addresses` proves native IPv4
  and mapped IPv6 share one digest while another address does not.
- `rpc_source_identity_survives_queueing_and_normalizes_mapped_ipv4` proves the
  identity survives the queued-call lifetime and is released with the call.
- `rpc_source_exhaustion_is_retryable_and_leaves_other_source_headroom` spends
  one RPC source's 128-call share, checks the structured retry deadline and no
  partial admission, then admits the same valid transaction from another
  source under remaining aggregate capacity.
- `cached_failure_does_not_reconsume_source_or_aggregate_allowance` continues
  to pin cache-before-quota ordering for the shared verifier.

## Residual risk

- IP address is a fairness bucket, not authentication or reputation. NAT users
  can share a bucket; an operator with many source addresses can use several
  buckets, while the 1,024 aggregate ceiling remains the final CPU bound.
- A trusted reverse proxy makes the proxy address the source. Forwarded headers
  are deliberately not trusted because this unauthenticated server has no
  authenticated-proxy configuration.
- Non-HTTP/embedded RPC calls have no remote address and remain aggregate-only.
- Honest callers refused under transient load must retry at or after the
  returned slot; the node does not retain or replay their request automatically.
