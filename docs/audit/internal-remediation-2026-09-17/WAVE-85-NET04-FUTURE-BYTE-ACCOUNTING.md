# Wave 85 — NET-04 / EN-08 future-block byte accounting

Date: 2026-09-19
Starting consolidation: `3a45d9f`

## Residual addressed

Authenticated near-future gossip is retained behind 32-entry/16-MiB global
and 8-entry/4-MiB per-source limits. Before every new future admission, the
engine recomputed both byte totals by calling `encode_envelope` for every
retained block. At a full byte budget, one otherwise cheap arrival therefore
allocated and copied up to the complete retained 16-MiB payload again before
being ignored.

The envelope itself is still required for release at its signed slot. The
avoidable work was repeated serialization, not payload retention.

## Hardening and consumer proof

Each `future_blocks` entry now carries the exact canonical encoded length
computed once with `encoded_envelope_len` when the immutable owned envelope is
admitted. Global and matching-source totals scan only this fixed-size cached
metadata. The scan remains O(number of retained entries); this correction
removes re-encoding, allocation and copying proportional to retained body
payload from each later admission. It does not claim a smaller retained-byte
or decoded heap/RSS cap.

A repository search leaves five classes of `future_blocks` consumer:

- exact envelope/signature deduplication before authentication and length work;
- admission totals over source and cached byte length;
- ready-slot selection from the retained header;
- removal, which moves the envelope, source and private authentication proof
  together into deferred admission; and
- tests and empty-map initialization.

No consumer mutates a retained envelope. Removal consumes the complete tuple;
if normal deferred admission reparks the block as an orphan, the existing path
validates/recreates its private binding and computes that queue's own exact
length. Source attribution and authentication are therefore neither detached
nor reconstructed from cached byte metadata.

The length helper already has codec-parity regressions for empty, attestation,
transaction and boundary envelopes. Wire encoding, consensus, persistence,
verdicts, peer guilt, count/byte ceilings, release order and recovery behavior
are unchanged.

## Adversarial coverage

`future_cached_length_accounting_pins_global_source_exact_and_plus_one` pins
metadata accounting independently of payload shape:

- eight transport-admissible 2-MiB entries across seven sources sum to the
  exact 16-MiB global boundary;
- the selected source is charged exactly two entries and the exact 4-MiB share;
- equality is admitted and one additional byte fails closed for both global
  and source caps; and
- removing that source's two entries reopens exactly its count and 4-MiB byte
  share, which the same source can readmit.

`one_source_cannot_occupy_the_future_byte_budget_and_capacity_reopens` uses
real signed three-MiB envelopes and now additionally proves:

- the cached length equals a real `encode_envelope` length for every retained
  entry;
- exact duplicate delivery neither adds an entry nor changes its byte charge;
- a second large envelope from the same source remains `Ignore` at the source
  byte ceiling;
- another source retains its independent share; and
- releasing the ready large envelope reopens admission without stale totals.

Existing `authenticated_future_to_orphan_to_connected_skips_both_reverifications`
and `deferred_block_registry_key_change_reverifies_and_fails_closed` continue
to pin movement of source/private authentication through release, repark and
key-binding mismatch.

## Validation

```text
cargo check -p bloch-pos-node --tests --offline
# passed

cargo test -p bloch-pos-node --bin bloch-pos \
  engine::ingest_admission_tests::future_cached_length_accounting_pins_global_source_exact_and_plus_one \
  --offline -- --exact --nocapture
# 1 passed; 0 failed; 584 filtered out

cargo test -p bloch-pos-node --bin bloch-pos \
  engine::ingest_admission_tests::one_source_cannot_occupy_the_future_byte_budget_and_capacity_reopens \
  --offline -- --exact --nocapture
# 1 passed; 0 failed; 584 filtered out
```

The integration fixture requires execution outside the sandbox because it
binds an ephemeral loopback listener. Compiler output contained only existing
unused-code/import warnings.

## Residual risk

- Admission still scans at most 32 retained metadata entries; no aggregate
  counter was introduced, avoiding a second mutable source of truth.
- Canonical encoded bytes remain a stable retention/accounting proxy, not an
  exact decoded heap or RSS measurement.
- An admitted verification or state transition remains non-preemptible, and
  source identity is not Sybil resistance.
- Full node, hosted CI, Linux reproducibility, release signing, rollback and
  fleet qualification remain outside this focused correction.
