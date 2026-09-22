# Wave 168 — EN-08 borrowed deep-reorg replay

Date: 2026-09-19
Comparison base: `9d8c0ed4`

## Residual addressed

When a reorg fork point falls outside the two-state snapshot window,
`state_at_canonical` reconstructs its post-state by replaying the canonical
prefix from genesis. Before performing that unchanged transition fold,
`replay_to` cloned every prefix `BlockEnvelope` into a temporary `Vec`.

That aggregate duplicated all retained bodies, transactions, attestations and
signatures along the prefix. Its CPU and transient allocation scaled with the
encoded history being replayed, but it supplied no additional validation:
`replay_to` only read each clone and immediately discarded the complete
aggregate after the fold.

## Correction and invariants

`replay_to` now walks the same canonical-chain slice in the same order and
borrows each envelope directly from the authoritative block map. The target
lookup, canonical-block lookup and their existing invariant `expect`s are
unchanged. Each block is still decoded and applied through the same
`body_transactions` and `Transition::apply_block` calls.

The small owned `ProposalEnvelope` required by the transition API is still
constructed per block, including its header and proposer-signature clones.
Decoded transaction ownership produced by `body_transactions`, state
construction and the actual replay work also remain. This wave removes only
the additional whole-prefix `Vec<BlockEnvelope>` and its body clones; it does
not claim allocation-free replay or an exact heap/RSS reduction.

There is no wire, public API, disk-format, activation, fork-choice, consensus,
verdict or recovery change. The snapshot hit path is untouched, and the deep
fallback returns the same committed state or reaches the same canonical-chain
invariant failures.

## Adversarial coverage

- `replay_fallback_does_not_clone_a_prefix_aggregate` builds six canonical
  blocks, selects a target outside `REORG_STATE_WINDOW`, proves that the
  fixture must take the replay fallback, pins the absence of the former owned
  prefix aggregate, and compares the replayed state root with the root
  committed by the target block.
- `the_snapshot_and_the_replay_agree_at_every_canonical_depth` retains the
  shuffled hit/miss equivalence sweep across the snapshot boundary.
- `a_reorg_lands_where_replay_from_genesis_lands` retains real shallow and
  deep competing-branch adoption, including proof that both snapshot and
  replay paths are exercised.

## Validation

```text
cargo test -p bloch-pos-node --bin bloch-pos reorg_state_tests --offline
# 3 passed; 0 failed; 617 filtered out

cargo check -p bloch-pos-node --bin bloch-pos --offline
# passed

cargo test -p bloch-pos-node --bin bloch-pos --offline
# 601 passed; 0 failed; 19 ignored; 61.38s
```

The focused suite ran outside the restricted sandbox because its engine
fixtures bind localhost sockets. The same initial sandbox run failed all
three fixtures at that bind with `PermissionDenied`; it did not reach the
assertions and is not a product failure.

## Residual boundary

- A deep reorg still necessarily replays every canonical block from genesis
  through the full transition when its fork point is outside the bounded
  snapshot window.
- Per-block proposal-header/signature clones, decoded transaction ownership,
  state allocation and cryptographic/transition work remain.
- Canonical-chain and block-map searches remain bounded only by retained chain
  history; this wave changes ownership during the already-required fold, not
  replay complexity.
- Hosted CI, release signing, deployment, rollback and fleet qualification
  remain outside source verification.
