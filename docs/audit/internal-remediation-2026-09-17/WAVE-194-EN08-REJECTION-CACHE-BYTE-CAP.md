# Wave 194 — EN-08 rejection-cache byte cap

Date: 2026-09-19
Comparison base: `17e7545e`

## Reproduced residual

The node's local transition-refusal cache was bounded to 4,096 entries but not
by the bytes of its keys. Each key is the complete canonical transaction
encoding moved out of the mempool. Sequentially rejected large transactions
could therefore leave a much larger payload aggregate in `Engine::rejected`
than the 16 MiB aggregate payload budget enforced while those transactions
were pending.

This is bounded by the entry count and transport/admission limits, so it is not
an unbounded allocation claim. It is nevertheless a distinct retained-byte
gap: count alone permits thousands of independently large canonical keys.

## Correction

`REJECTION_BYTES_MAX` now equals the existing 16 MiB
`admission::MAX_MEMPOOL_BYTES`. `Engine::rejected_bytes` is the exact sum of
retained canonical key lengths. Lazy expiry recomputes it during the scan that
already visits the cache; replacement and capacity eviction use one private
removal helper, and admission evicts the same earliest-expiring entries until
both count and byte limits fit.

Re-barring an existing key removes its old accounting before capacity planning,
so replacement neither double-charges bytes nor displaces an unrelated entry.
An individually over-cap key is drop-new after ordinary expiry cleanup. Normal
production keys already passed through the same-sized aggregate mempool budget;
the guard keeps future callers fail-bounded.

## Preserved invariants

- expiry remains `slot + REJECTION_TTL_SLOTS` and equality remains expired;
- pressure still evicts the entry expiring soonest, with the existing key-order
  tie behavior inherited from the `BTreeMap` iteration;
- hit counting, first-hit logging, RPC rejection count, bar-before-capacity
  ordering and sweep/proposal call paths are unchanged;
- dropping a local retry barrier early under pressure remains recovery, not a
  validity judgment or peer penalty;
- no transaction encoding, public API, wire, persistence, consensus, block
  validity, activation gate or peer verdict changed.

## Regression coverage

`rejection_cache_byte_boundary_eviction_expiry_and_replacement_are_exact` uses
the production implementation with a small explicit test cap and fixes:

- admission at the exact byte boundary;
- aggregate boundary `+1` eviction of the earliest expiry;
- exact byte reopening after eviction and expiry;
- replacement without double charge or unrelated displacement;
- equality of cached accounting and the sum of retained canonical keys; and
- drop-new behavior for an individually over-cap key without displacing
  retained work.

Existing regressions retain the 4,096-entry cap, TTL reopening, hit accounting
and bar-before-mempool-capacity behavior. The replay benchmark initializer adds
only the zero-valued accounting field and does not change benchmark behavior.

## Validation

- `cargo test -p bloch-pos-node --bin bloch-pos --offline rejection_cache_byte_boundary_eviction_expiry_and_replacement_are_exact -- --nocapture`
  - outside the sandbox for the fixture's localhost socket: 1 passed;
    0 failed; 629 filtered out.
- `cargo test -p bloch-pos-node --bin bloch-pos --offline the_bar_ -- --nocapture`
  - outside the sandbox: 3 passed; 0 failed; 627 filtered out.
- `cargo test -p bloch-pos-node --bin bloch-pos --offline the_rejection_cache_is_bounded -- --nocapture`
  - outside the sandbox: 1 passed; 0 failed; 629 filtered out.
- `cargo check -p bloch-pos-node --bin bloch-pos --offline`
  - passed (pre-existing dead-code/unused warnings only).
- `cargo test -p bloch-pos-node --bin bloch-pos --offline`
  - outside the sandbox after the final exact-accounting hardening:
    611 passed; 0 failed; 19 ignored; 62.12s.

## Residual boundary

The 16 MiB value bounds canonical key payload bytes, not exact heap/RSS:
`BTreeMap`, `Vec`, allocator and entry metadata overhead remain. Lazy expiry and
earliest-expiry selection still perform bounded O(n) scans at write/capacity
time, and canonical bytes remain necessary for exact re-offer lookup. The cache
remains node-local, unsigned and intentionally non-authoritative. `EN-08`
remains `PARTIAL`.
