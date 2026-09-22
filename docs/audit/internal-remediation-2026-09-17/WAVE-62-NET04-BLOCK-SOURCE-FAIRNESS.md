# Wave 62 — NET-04/EN-07 transported-block source fairness

Date: 2026-09-18  
Starting point requested: `d30afca`

## Change

Transported blocks now enter the existing hybrid-signature admission budget
with the same node-local source fingerprint already used by transported
attestations and transactions. The per-wall-slot limits remain:

- 1,024 hybrid verifications in aggregate; and
- 128 hybrid verifications for one attributed transport source.

The source is carried beside a block while it waits in either bounded deferred
collection:

- the 32-entry, 16 MiB future-block map; and
- the 256-entry orphan FIFO.

When a future block reaches its slot, or an orphan's parent/identity becomes
available, admission reuses the block's original source. It does not charge
the peer whose later block happened to unblock it. An unattributed internal
call remains subject to the aggregate limit but has no invented source.

Local or produced blocks remain outside the network-admission budget. No wire
encoding, consensus transition, fork-choice rule, durable format, or peer
identity protocol changed.

## Failure semantics

A depleted aggregate or per-source allowance returns `Ignore`. It is node
load, not evidence that the block or forwarding peer is invalid, and therefore
never becomes a peer penalty. Ordinary synchronization/re-offer provides the
retry path.

Exact cached signature failures are checked before quota reservation. A replay
of the same known failure costs neither source nor aggregate allowance.

## Regression coverage

- `one_source_cannot_spend_another_sources_slot_allowance` covers source and
  aggregate quota separation.
- `cached_failure_does_not_reconsume_source_or_aggregate_allowance` covers
  cache-before-quota ordering and preserves another source's headroom.
- `an_orphan_is_admitted_when_its_parent_lands` attributes child and parent to
  different sources and checks that the parked child's source survives its
  lifetime and promotion.
- `a_block_far_ahead_of_the_wall_clock_is_refused` checks that future holding,
  future release, and subsequent orphan holding retain the original source.

## Residual risk

- The source fingerprint is fairness identity, not reputation or proof of a
  unique operator. A sender with multiple peers or addresses can use multiple
  128-call shares, while the 1,024 aggregate ceiling still bounds node work.
- Sources hidden by internal/RPC paths use only the aggregate ceiling.
- Several peers behind one normalized address can share a source allowance.
- Budget exhaustion deliberately drops the current admission attempt with
  `Ignore`; availability depends on normal gossip or synchronization retry.
- Deferred entries retain one `Source` value each. Their count/payload caps
  continue to bound this extra node-local memory.
