# Wave 160 — EN-08 indexed finality-orphan cleanup

Date: 2026-09-19
Comparison base: `9a9a20f8`

## Residual addressed

When the local finality latch refused a reorg, the engine removed waiting
orphans descended from that branch by repeatedly searching the whole orphan
FIFO for one newly reachable child and removing it by index. The queue was
already bounded to 256 entries, but a reverse-arrival chain placed each next
child near the end of the shrinking queue. One refusal could therefore make
quadratic metadata visits before deleting the same bounded subtree.

This work happened after the branch had already been judged permanently
incompatible with the node's local finalized checkpoint. Re-scanning unrelated
waiting envelopes did not add authentication, consensus or recovery evidence.

## Correction and invariants

`refuse_finality_rewind` now builds a temporary parent-to-child identity map
from the bounded waiting queue, walks descendants from the refused branch IDs
once, and removes the discovered set with one order-preserving `retain`.

The seed set and descendant relation are unchanged: every waiting orphan whose
parent is the refused branch or another removed orphan is deleted, independent
of arrival order and with multiple children supported. Unrelated entries keep
their exact FIFO order and complete `(id, envelope, source, authentication,
retained_bytes)` tuple. `orphans_evicted` increases by the exact number removed.

Only the explicitly refused branch IDs enter `parked_refused_finality`;
descendant IDs remain absent exactly as before. Deferred-orphan state,
`needs_sync`, peer verdicts and recovery scheduling are untouched. The branch
is still removed from fork-choice inputs, and exact branch or direct-child
reoffers still stop at the existing finality-refusal door.

There is no wire, public API, disk-format, consensus or activation change. The
temporary identity map/set are bounded by `ORPHAN_MAX`; this wave changes CPU
shape, not retained payload or heap/RSS limits.

## Adversarial coverage

- `finality_refusal_removes_reverse_arrival_tree_once_and_preserves_survivor`
  fills the waiting cap with 255 refused descendants in reverse arrival order
  plus one unrelated attributed gap. The refused tree contains two additional
  children at its midpoint. It pins the exact 255-entry counter delta, complete
  survivor bytes/source/authentication/charge, unchanged `needs_sync`, and the
  rule that only the refused root ID is parked.
- `audit_finality_refusal_discards_pending_descendants_but_keeps_other_gaps`
  retains the smaller reverse-order grandchild/child case and confirms that a
  refused parent is not converted into a new sync gap.
- The existing `finality_latch_tests` focused set retains latch boundaries,
  fork-choice removal, parked-ID FIFO/dedup and override behavior.

## Validation

```text
cargo test -p bloch-pos-node --bin bloch-pos \
  finality_refusal_removes_reverse_arrival_tree_once_and_preserves_survivor \
  --offline
# 1 passed; 0 failed; 617 filtered out

cargo test -p bloch-pos-node --bin bloch-pos finality_refusal --offline
# 2 passed; 0 failed; 616 filtered out

cargo test -p bloch-pos-node --bin bloch-pos finality_latch_tests --offline
# 9 passed; 0 failed; 609 filtered out

cargo check -p bloch-pos-node --bin bloch-pos --offline
# passed

cargo test -p bloch-pos-node --bin bloch-pos --offline
# 599 passed; 0 failed; 19 ignored; 63.90s
```

The focused and complete suites ran outside the restricted sandbox because
their engine and transport fixtures bind localhost sockets.

## Residual boundary

- Building the temporary adjacency map and ordered identity sets remains
  O(number of waiting orphans × log ORPHAN_MAX), under the existing 256-entry
  cap. The removed defect is the repeated full FIFO search/removal loop.
- The engine still scans bounded parked IDs at the admission door and retains
  the existing fixed-size identity-only refusal FIFO.
- This is local finality-latch cleanup only; it does not change finality policy,
  fork choice, branch validity or synchronization protocol.
- Hosted CI, release signing, deployment, rollback and fleet qualification
  remain outside source verification.
