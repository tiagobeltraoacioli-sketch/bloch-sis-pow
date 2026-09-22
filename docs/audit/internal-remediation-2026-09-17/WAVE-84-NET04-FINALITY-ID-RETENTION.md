# Wave 84 — NET-04 / EN-08 finality-refusal identity retention

Date: 2026-09-19
Starting consolidation: `ff48c1d`

## Residual addressed

`parked_refused_finality` retained up to 512 complete `BlockEnvelope` values so
an exact re-offer, or a child of a refused block, could be ignored before
signature verification and fork-choice replay. The early door is valuable,
but the payload retention was not: every consumer compared only the stored
block ID. No code read the parked header, signature, attestations or
transactions, and no code reconstructed a branch from this queue.

A branch below this process's finality latch cannot become adoptable during
the same run. Allowing such a rewind requires the explicit restart-time
override, which creates a fresh engine. Retaining complete bodies therefore
provided no recovery path while allowing the fixed 512-entry queue to retain
large payloads.

## Hardening

The FIFO now stores only `[u8; 32]` block identities. On finality refusal the
engine still:

- removes every conflicting envelope from the fork-choice input map;
- deduplicates by exact block ID;
- retains at most `MAX_PARKED_REFUSED_FINALITY` identities with the same FIFO
  eviction policy;
- increments `finality_rewinds_refused` once per refused reorg;
- exposes the same parked-entry count through `blocks_parked`; and
- removes already-waiting orphan descendants.

Admission still returns `Ignore` before cryptographic or orphan work when the
incoming ID is parked or its parent is parked. A refused parent is not turned
into a new sync gap, and no peer is blamed. The only changed log wording says
that identities, rather than full blocks, are parked.

This removes retained header/signature/body payloads from this queue. It is
not presented as an exact heap/RSS reduction: `VecDeque` allocation and engine
overhead remain, and temporary branch envelopes still exist in the caller
during the refusal operation.

No wire encoding, persistence format, consensus rule, finality decision,
fork-choice result, RPC schema, metric name, peer verdict or transport policy
changed.

## Consumer proof and adversarial coverage

A repository search for `parked_refused_finality` leaves only:

- initialization;
- `.len()` for logs/metrics;
- exact-ID/parent membership at the admission door;
- exact-ID dedup plus FIFO `pop_front`/`push_back`; and
- tests.

There is no remaining envelope-field consumer.

`refused_finality_parks_only_ids_with_exact_fifo_and_descendant_door` builds a
`MAX_PARKED_REFUSED_FINALITY + 1` branch containing a transport-admissible
three-MiB envelope and proves:

- the queue stops exactly at 512 fixed-size identities;
- cap+1 evicts the oldest identity and retains the large envelope's ID plus
  the newest ID;
- the stored element is exactly one 32-byte identity, not the large body;
- replaying a body variant with an already-retained exact ID leaves FIFO
  order unchanged; and
- a child of the retained large-envelope ID returns `Ignore` before unsigned
  rejection and without setting `needs_sync`.

Existing regressions continue to pin exact re-offer early refusal, pending
descendant removal, refusal counters and the finality override.

Focused validation:

```text
cargo check -p bloch-pos-node --tests --offline
# passed

cargo test -p bloch-pos-node --bin bloch-pos \
  engine::finality_latch_tests::refused_finality_parks_only_ids_with_exact_fifo_and_descendant_door \
  --offline -- --exact --nocapture
# 1 passed; 0 failed; 583 filtered out

cargo test -p bloch-pos-node --bin bloch-pos \
  engine::finality_latch_tests::a_reoffered_parked_block_is_ignored_before_any_further_check \
  --offline -- --exact --nocapture
# 1 passed; 0 failed; 583 filtered out
```

The engine fixtures require execution outside the sandbox because they bind
ephemeral loopback listeners. Compiler output contained only existing
unused-code/import warnings.

## Residual risk

- FIFO eviction means an identity older than the most recent 512 refusals can
  be re-authenticated and re-refused if offered again; that bounded CPU trade
  already existed and is unchanged.
- Multiple signature/body variants with the same header ID share one refusal
  identity, exactly as before.
- The finality-refusal branch is still temporarily materialized by the reorg
  caller; this change narrows retained payload, not peak refusal-time memory.
- The aggregate `blocks_parked` gauge remains a count across semantically
  different queues and is not a byte or RSS metric.

External binary release gates are unchanged: independently authenticated
Linux build comparison, hosted CI evidence, signed release/rollback artifacts,
fresh independent WS evidence, scratch-host rollback rehearsal and staged
canary evidence remain required.
