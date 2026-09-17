# Source backlog admission (EN-08; EN-07 remains partial)

Date: 2026-09-17. Local operational policy only; no consensus acceptance,
activation epoch, signature domain, or wire-format change.

Both network transports now reserve source capacity **before their first
engine-facing channel**. This matters for libp2p: its original unbounded channel
preceded the existing global queue check in the forwarding thread. A reservation
travels in the event's `Origin`, survives clones and forwarding, and is released
when its last owner is dropped. It therefore remains charged while the engine
handles the event, even though the older global queue counter is released before
handling. Failed channel sends and shed events release the reservation.

Policy:

- Each devnet remote IP or authenticated libp2p PeerId can hold 256 events and
  16 MiB of charged encoded bytes. Transactions may consume only half the byte
  allowance and attestations three quarters; blocks can use the full allowance.
  Count slots are shared across classes: 256 tiny lower-priority messages can
  still exclude a block from that same source (including its shared NAT).
- The source registry also enforces the shared queue's aggregate 4,096 events
  and 64 MiB (with the same class byte headroom), bounding the libp2p first hop.
- At most 1,024 source entries are live. An entry is removed when its outstanding
  event count reaches zero. Reconnects cannot reset outstanding reservations.
- IPv4-mapped IPv6 addresses normalize to IPv4. A libp2p overload verdict is
  `Ignore`, never `Reject`. Devnet overload sheds the message without closing
  the connection or creating a persistent ban.

These are backlog allowances, not per-second quotas. A single full allowance
cannot consume the entire aggregate queue. Several identities can still exhaust
it; this is not a Sybil defense, an operator-independence measurement, a strict
round-robin scheduler, or a CPU-rate bound. Unique invalid hybrid signatures
still require separate verification-cost mitigation (EN-07). Encoded-byte
accounting does not claim to measure exact decoded heap allocations.

## NAT and trust assumptions

Devnet has no authenticated peer identity. TCP's observed remote IP groups
connections; it does not prove who controls a validator. Validators behind the
same NAT share the 256-event burst, including traffic from other validators they
relay. A busy shared NAT can therefore experience shedding. There is no durable
penalty: processing frees capacity immediately, and ordinary sync can re-request
blocks. Votes and transactions are not guaranteed eventual delivery by this
policy. Switching to distinct authenticated libp2p identities avoids grouping
all colocated validators by IP, but one operator can own several identities.

An off-path sender generally cannot finish a TCP handshake with a spoofed IP;
this does not make devnet authenticated or protect against routed/on-path
attackers. The same remote operator using both transports receives separate
IP/PeerId source allowances, while the aggregate budget remains shared.

## Regression coverage

The focused `source_` node test selection covers source flooding with another
peer still admitted, cloned guards retaining capacity, IPv4/mapped-IPv6 NAT
sharing, byte headroom for blocks, live-identity and aggregate bounds, registry
cleanup over identity churn, devnet processing/failed-send lifetime, and
libp2p admission before its first channel. Existing transport integration tests
must also pass before release. This closes the single-source queue monopolization
path, not all possible scheduling or verification unfairness.

Under quota saturation a libp2p sync page can be only partially enqueued. Its
transport chase hints can still advance; periodic sync from the applied engine
head remains the recovery path. This change does not promise complete page
admission or strict priority at the event-count limit.

Qualification: `source_` selection passed 8 tests (including 5 new source-budget
and channel-lifetime tests); `net::` passed 27 tests; `p2p::` passed 23 tests. Logs:
`/private/tmp/bloch-audit-wave6-source-budget.log` and
`/private/tmp/bloch-audit-wave6-net.log`, and
`/private/tmp/bloch-audit-wave6-p2p.log`.
