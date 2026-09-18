# Canonical lookup cost (EN-18, partial)

Date: 2026-09-17. This changes local lookup implementation only; canonical-chain
selection, checkpoint rules, transaction status semantics and wire formats remain
unchanged.

`height_of`, `slot_of_canonical_root` and RPC `getblock` by slot previously scanned
the canonical chain linearly. Block/finality responses and transaction status
could repeat those scans on the engine thread. Canonical slots are strictly
increasing, so exact-slot lookup now uses binary search.

A root lookup first checks canonical membership, handles genesis directly, then
uses the retained envelope's slot to binary-search the authoritative chain and
confirms the exact root at that position. It introduces no mutable height index.
Canonical envelopes are excluded from finalized-floor pruning; they are also
needed by the existing whole-log reorg rewrite. A linear fallback preserves a
valid old canonical lookup if an envelope is absent under a future retention
policy. A stored same-slot fork never inherits the canonical block's height.

The normal lookup uses existing tree maps/sets and binary search, so its cost is
logarithmic in stored/canonical entries instead of a full chain scan. This is not
an RPC latency or restart SLA. Block cloning, response serialization, state reads
and other RPC methods still run on the engine thread; EN-18 remains partial.

Regression coverage includes genesis, empty slots, exact sparse-slot responses,
a stored same-slot fork, missing-envelope fallback, rollback and successful
reorg. Existing real-vote finality and transaction-status boundary tests run with
the same selection, including rejected-branch transaction-index isolation.

Qualification: the `proposal_revalidation_tests` selection passed **9 tests**,
zero failures or ignored tests. Log:
`/private/tmp/bloch-wave8-canonical-lookup.log`.
