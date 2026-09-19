# Wave 157 — EN-08 incremental orphan eviction accounting

Date: 2026-09-19
Comparison base: `f4e6d45e`

## Residual addressed

The orphan pool already retained each envelope's exact canonical encoded
length and bounded the combined waiting and deferred queues by count and
bytes. When a new waiting orphan required more than one FIFO eviction,
however, the admission loop recomputed the byte sum of both queues after every
`pop_front`.

That made one admission quadratic in retained-entry metadata in the worst
case. The bound remained finite at 256 entries, but a reachable full queue
with many small entries before large ones could require hundreds of complete
queue walks before admitting one envelope. No payload bytes needed to be
read, encoded or copied for those repeated sums.

## Correction and invariants

After all existing deduplication, per-source count/byte checks, exact envelope
length calculation, oversize refusal and immutable-deferred preflight, orphan
admission now sums waiting bytes once. It adds the already-computed deferred
total and subtracts the cached exact charge of each waiting entry removed by
the FIFO loop.

The arithmetic retains the existing saturating, fail-closed behavior. The
entry-count and byte conditions are unchanged, as are FIFO order, one
`orphans_evicted` increment per removed or refused entry, per-source fairness,
the collective `Gossip(None)` bucket, the Local exemption from source
fairness, immutable deferred work and `needs_sync` only after successful
parking. Admission still returns the same local `Ignore` behavior and creates
no peer verdict.

There is no wire, public API, disk-format, consensus, activation or recovery
change. No persistent counter was added, so queue mutation paths outside this
single admission remain unable to make accounting stale.

## Adversarial coverage

- `full_orphan_byte_cap_evicts_many_waiting_entries_in_exact_fifo_order`
  builds a reachable 256-entry queue at the exact global encoded-byte cap:
  248 one-KiB envelopes followed by eight transport-admissible large
  envelopes, distributed across eight attributed sources at each source's
  exact byte/count share. An equally large envelope from a ninth source
  requires exactly 249 FIFO removals. The regression pins the eviction
  counter delta, untouched suffix order, append position, final byte sum and
  `needs_sync`.
- The existing `orphan_` focused set retains deduplication, source fairness,
  bounded population, authentication reuse, promotion slicing and recovery
  behavior.
- `waiting_global_byte_cap_rejects_oversize_then_evicts_fifo` and
  `deferred_only_global_byte_cap_drops_local_then_reopens` retain exact-cap,
  oversize refusal, Local global charging and reopening behavior.
- `immutable_deferred_bytes_do_not_flush_waiting_work_uselessly` retains the
  preflight that refuses an impossible admission without displacing waiting
  work.

## Validation

```text
cargo test -p bloch-pos-node --bin bloch-pos \
  full_orphan_byte_cap_evicts_many_waiting_entries_in_exact_fifo_order \
  --offline
# 1 passed; 0 failed; 616 filtered out

cargo test -p bloch-pos-node --bin bloch-pos orphan_ --offline
# 12 passed; 0 failed; 605 filtered out

cargo test -p bloch-pos-node --bin bloch-pos global_byte_cap --offline
# 2 passed; 0 failed; 615 filtered out

cargo test -p bloch-pos-node --bin bloch-pos \
  immutable_deferred_bytes_do_not_flush_waiting_work_uselessly \
  --offline
# 1 passed; 0 failed; 616 filtered out

cargo check -p bloch-pos-node --bin bloch-pos --offline
# passed

cargo test -p bloch-pos-node --bin bloch-pos --offline
# 598 passed; 0 failed; 19 ignored; 59.70s
```

The focused and complete suites ran outside the restricted sandbox because
their engine fixtures bind localhost sockets. The initial sandbox execution
of the new regression failed only at the expected ephemeral socket bind with
`PermissionDenied`; the same test then passed outside the sandbox.

## Residual boundary

- Deduplication and source-fairness queries still scan a bounded queue. This
  wave removes only the repeated full global-byte scan inside the eviction
  loop; ordinary admission remains O(number of retained entries), bounded by
  `ORPHAN_MAX`.
- Envelope authentication, canonical length calculation and final retained
  decoded objects remain necessary.
- Encoded-byte caps are a retention proxy, not an exact heap/RSS measurement;
  decoded structs, collection capacities and allocator overhead remain.
- Hosted CI, release signing, deployment, rollback and fleet qualification
  remain outside source verification.
