# NET-07/NET-15: shared libp2p request window

Date: 2026-09-17. This follow-up is separate from the producer wire-budget and
transaction-reporting segment. It changes local synchronization scheduling;
no consensus gate, wire message, timeout, or block acceptance rule is changed.

Previously, connection establishment, the engine sync timer, and full-page chase
each called `send_request` independently. A three-peer timer fanout did not bound
all outstanding requests, and duplicate walks could coexist for the same peer.

All three paths now enqueue into one requester:

- At most three active requests globally and one per authenticated PeerId.
- A FIFO holds at most 1,024 waiting peer/cursor pairs, deduplicated by peer.
  A repeated request keeps the earlier cursor so a speculative page cursor
  cannot skip a gap requested from the applied head.
- Full-page chase rejoins the FIFO tail. A fast responder cannot continuously
  reacquire a free slot ahead of a peer that has been waiting.
- Actual libp2p request IDs release the matching reservation on response or
  failure. The existing 30-second request timeout handles silent responders.
- Last-connection closure removes both active and waiting work for that peer.
  A delayed completion for an old request cannot release a newer reconnect's
  reservation. No new policy closes honest connections.
- Periodic peer selection excludes active peers and puts its rotating
  exploration choice before height-preferred choices. Thus even one free slot
  is not automatically spent on the largest unverified claimed height.

The request table and FIFO are bounded and contain no persistent reputation or
ban state. This is not an operator-independence or Sybil-resistance claim. A
configured population above the waiting bound can shed scheduling hints; the
normal timer may retry. It does not bound the entire libp2p heap or serving-side
work, which have separate controls. Legacy devnet still lacks response IDs and
page-end markers, so its exact response-window limitation is unchanged.

Source admission can still shed individual response blocks under overload.
Transport pagination hints can advance before the engine applies the page;
periodic sync from the applied engine head remains the recovery path. This patch
does not assert a production cold-sync or restart SLA.

## Qualification

Five focused tests passed in `/private/tmp/bloch-wave8-outbound-sync.log`:
shared count/peer cap, exact request matching, reconnect generation isolation,
production response/failure handler cleanup, and bounded/deduplicated FIFO
behavior including two silent holders, a responsive third peer, and a waiting
fourth peer receiving the next freed slot. The full transport suite also covers
actual cold paginated sync, restart-gap recovery, gossip mesh exchange, and the
producer-sized frame boundary.

Final full `p2p::` suite: **28 passed**, zero failures/ignored, in
`/private/tmp/bloch-wave8-p2p-full-final.log`. Peer-window tests use actual
libp2p-issued request IDs and injected completion events; the existing transport
integration tests exchange real loopback traffic. No elapsed-time timeout SLA is
inferred from the injected timeout event.
