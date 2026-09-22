# Wave 83 — NET-04 / EN-08 orphan byte retention

Date: 2026-09-19
Starting consolidation: `b9c78ec`

## Residual addressed

The combined waiting and ready orphan queues had global and per-source entry
caps, but entry count was not a useful upper bound for retained payload: one
small envelope and one transport-limit envelope each consumed one slot. An
attacker could therefore maximize retained bytes while remaining inside all
Wave 82 fairness limits.

## Policy and hardening

The queues now share two serialized-byte budgets in addition to their existing
count budgets:

- 16 MiB globally, equal to two `MAX_SYNC_FRAME` responses; and
- 4 MiB per normalized gossip source, equal to one `MAX_GOSSIP_BYTES` frame.

Compile-time assertions pin
`MAX_PROPOSAL_ENVELOPE_BYTES <= per-source <= global` and require the global
budget to hold at least one maximum sync frame. The cap is an exact bound on
canonical encoded envelope bytes, used as a stable retention proxy. It is not
an exact heap/RSS bound: decoded structs, `Vec` capacity and allocator overhead
remain outside that measurement.

`codec::encoded_envelope_len` computes exactly the length emitted by
`encode_envelope` without allocating a second frame-sized buffer. The result is
cached on each parked entry and moves unchanged from waiting to deferred. Thus
admission sums integers across both queues rather than repeatedly encoding all
retained attacker-controlled bodies. The helper still walks the incoming
attestation and transaction collections once; deduplication and the cheaper
per-source count cap run before that work.

The existing semantics are preserved:

- `Gossip(Some(peer))` is charged to that normalized source and
  `Gossip(None)` to one collective unattributed bucket;
- `Local` is exempt from source fairness but remains inside the global byte
  and count budgets;
- source pressure drops the new entry; global pressure may FIFO-evict only
  still-waiting entries, never ready-to-promote work;
- an envelope larger than the complete global budget is refused before FIFO
  eviction; and
- immutable deferred bytes/count are preflighted with the incoming entry, so
  an admission that cannot succeed does not uselessly flush waiting work.

Every capacity refusal remains local `Ignore` pressure and increments the
existing internal `orphans_evicted` counter once per refused or displaced
entry. There is no peer penalty. Exact duplicates return before length
accounting and do not increment the counter. Retained gaps keep the existing
`needs_sync` behavior; refused work depends on later regossip or another sync
request and is not claimed to be automatically re-requested.

No consensus validity, signature rule, fork choice, source normalization,
wire encoding, persistence format or transport limit changed.

## Adversarial coverage

`encoded_envelope_len_tracks_empty_collections_fields_and_limits` pins exact
parity with real encoding for empty collections, an attestation, a transaction
and an `MAX_FIELD_LEN` proposer signature, preventing codec drift.

The orphan regressions prove:

- exact-cap acceptance and cap+1/overflow refusal arithmetic;
- combined `Gossip(None)` accounting across waiting and deferred queues;
- dedup-before-charge and exact byte reopening after removal;
- a deferred-only global cap refuses `Local`, then reopens exactly after one
  removal;
- a global-cap+1 internal envelope cannot evict existing waiting entries;
- an achievable global admission evicts the oldest waiting entry, admits the
  new one, increments the counter once and remains exactly at the cap; and
- with 15 MiB deferred + 1 MiB waiting, a 4 MiB incoming entry is refused
  once without altering the waiting IDs, because deferred + incoming cannot
  fit even after waiting eviction.

Focused validation:

```text
cargo test -p bloch-pos-node --bin bloch-pos byte --offline -- --nocapture
# 21 passed; 0 failed; 562 filtered out

cargo check -p bloch-pos-node --tests --offline
# passed

cargo test -p bloch-pos-node --bin bloch-pos \
  engine::ingest_admission_tests::the_orphan_pool_is_bounded_and_evicts_the_oldest_first \
  --offline -- --exact --nocapture
# 1 passed; 0 failed; 582 filtered out
```

The engine fixtures require execution outside the sandbox because they bind
ephemeral loopback listeners. Compiler output contained only existing
unused-code/import warnings.

## Residual risk

- Encoded bytes are a deterministic proxy, not a decoded heap/RSS measurement.
- Multiple normalized identities can partition the global budget; this is
  bounded retention and fairness, not Sybil resistance.
- NAT/proxy sharing and the collective `Gossip(None)` bucket intentionally
  make unrelated traffic contend for one source share.
- The global FIFO policy still prefers newer waiting work when admission is
  achievable; synchronization/regossip is the recovery path for an evicted
  gap.
- One promoted block transition remains non-preemptible and promotion remains
  one block per control turn.

External binary release gates are unchanged: independently authenticated
Linux build comparison, hosted CI evidence, signed release/rollback artifacts,
fresh independent WS evidence, scratch-host rollback rehearsal and staged
canary evidence remain required.
