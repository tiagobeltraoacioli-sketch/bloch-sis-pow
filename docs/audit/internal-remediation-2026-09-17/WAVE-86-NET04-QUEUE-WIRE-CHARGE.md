# Wave 86 — NET-04 / EN-08 retained queue wire charge

Date: 2026-09-19
Starting consolidation: `a228c91`

## Residual addressed

Both transports reserve bounded source and engine-queue bytes before work
reaches consensus. The source reservation already retained the exact bounded
wire payload length, and each decoded value was compared against a canonical
re-encoding before the guarded event was emitted to later queue stages. Those
stages ignored that proved length:

- the libp2p forwarder re-encoded the complete event to reserve the aggregate
  engine queue; and
- the engine re-encoded it again when releasing the same queue charge.

Legacy devnet reserved its aggregate bytes before decode, but likewise
re-encoded the retained event on engine release. For a large block this meant
one or two additional full-payload allocations/copies after the necessary
canonical check.

## Hardening and consumer proof

The private, RAII `SourceReservation` now exposes its already-stored byte
charge only inside the crate. `Origin` exposes that value as an optional hint,
and `charged_bytes` selects it for transport-reserved events. Source-free and
local events continue to compute `queued_bytes` from their canonical value.

The hint becomes reachable only through a reservation returned by the private
source registry. Transport receive paths reserve raw bytes, decode, and prove
`queued_bytes(decoded) == raw.len()` before emitting the guarded event. The
canonical comparison remains unchanged; `charged_bytes` is used only by the
later aggregate reserve, send-failure and engine-release paths. The same
retained integer therefore cancels the same charge symmetrically, while the
guard and normalized source remain attached to the event until processing
ends.

A consumer search leaves `queued_bytes` in the places that need canonical
measurement: source-free admission, legacy/p2p post-decode equality checks and
tests. Later queue bookkeeping uses `charged_bytes`. No wire field, decoder,
consensus rule, persistence format, event ordering, capacity, verdict, peer
score or recovery path changed.

This removes repeated serialization/allocation/copying of retained transport
payloads during queue bookkeeping. It does not remove the one canonical
re-encoding at the receive boundary, change retained bytes, or claim an exact
heap/RSS reduction.

## Adversarial coverage

- `devnet_predecode_charge_matches_the_engine_release_charge` proves an exact
  raw block-frame charge survives decode and source attachment. It then
  shortens the internal envelope after reservation and proves release still
  uses the original charge exactly, leaving both aggregate counters at zero.
- `source_free_queue_events_fall_back_to_canonical_size` proves work without a
  transport guard still reserves and releases its computed canonical bytes.
- `sync_envelopes_reserve_before_decode_and_release_every_exit` now includes a
  decoded-envelope-plus-trailing-byte input. It remains malformed, releases
  its tentative quota and cannot prevent the following canonical envelope
  from being admitted.
- `source_admission_lasts_through_processing_and_failed_delivery_releases_it`
  continues to prove the source guard lasts through processing and now pins
  both aggregate count and bytes at zero after failed channel delivery.

## Validation

```text
cargo check -p bloch-pos-node --tests --offline
# passed

cargo test -p bloch-pos-node --bin bloch-pos \
  devnet_predecode_charge_matches_the_engine_release_charge --offline -- --nocapture
# 1 passed; 0 failed; 585 filtered out

cargo test -p bloch-pos-node --bin bloch-pos \
  source_free_queue_events_fall_back_to_canonical_size --offline -- --nocapture
# 1 passed; 0 failed; 585 filtered out

cargo test -p bloch-pos-node --bin bloch-pos \
  sync_envelopes_reserve_before_decode_and_release_every_exit --offline -- --nocapture
# 1 passed; 0 failed; 585 filtered out

cargo test -p bloch-pos-node --bin bloch-pos \
  source_admission_lasts_through_processing_and_failed_delivery_releases_it \
  --offline -- --nocapture
# 1 passed; 0 failed; 585 filtered out
```

Compiler output contained only existing unused-code/import warnings.

## Residual risk

- Canonical validation still re-encodes the decoded event once. Removing that
  check would require a separately reviewed decoder-canonicality proof.
- Source reservations and aggregate queue reservations remain separate
  accounting layers by design; this change reuses their common byte charge,
  not their counters.
- An admitted cryptographic verification or state transition remains
  non-preemptible, and normalized transport source is not Sybil resistance.
- Full node, hosted CI, Linux reproducibility, release signing, rollback and
  fleet qualification remain outside this focused correction.
