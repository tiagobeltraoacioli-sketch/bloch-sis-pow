# Wave 164 — EN-08 indexed finality-refusal FIFO membership

Date: 2026-09-19
Comparison base: `7bfe20e1`

## Residual addressed

The finality-refusal FIFO retains at most 512 fixed-size block identities. For
every envelope in a refused branch, the update loop searched that FIFO from
the front to decide whether the identity was already parked. The existing
cap-plus-one regression exercises 513 branch identities, so a full FIFO could
perform a bounded full membership scan for each identity before producing the
same deduplicated FIFO.

For a branch no longer than the FIFO this is a quadratic-shaped sequence of
identity comparisons; for a longer branch the work is bounded by branch
length times the 512-entry cap. The bodies were not retained or compared, but
the repeated identity scans added no finality or recovery evidence.

## Correction and invariants

`refuse_finality_rewind` now builds one temporary `BTreeSet` from the parked
identities and uses it for membership while processing the refused branch.
The existing `VecDeque` remains the sole ordering authority. Every FIFO pop
removes the same identity from the set and every FIFO append inserts it, so
membership follows the sequential policy exactly.

That synchronization preserves the non-obvious case in which an identity is
present and skipped early in a branch, evicted by intermediate new identities,
then encountered again later: the later occurrence is appended at the back,
just as with the former linear membership scan. Existing identities do not
refresh their position, cap pressure still evicts exactly the oldest identity,
and duplicates still occupy one slot.

Only identities of the explicitly refused branch enter the FIFO. Descendant
orphans remain cleanup-only and are not added. Branch envelopes are still
removed from fork-choice inputs before membership handling; refusal counters,
door ordering, `Ignore` behavior, override behavior and recovery remain
unchanged.

There is no wire, public API, disk-format, consensus or activation change.
The temporary set contains at most the existing 512-entry cap. Its work is
O(branch length × log refusal cap), not strictly linear, and no heap/RSS claim
is made.

## Adversarial coverage

- `refused_finality_identity_index_matches_sequential_fifo_reappearance`
  starts with a full FIFO whose oldest identity also appears first in the
  branch. That occurrence is skipped; a new identity evicts it; a later copy
  of the old identity must then be appended. A direct oracle using the former
  sequential `contains/pop/push` policy pins the complete final FIFO, cap,
  tail position and single-copy invariant.
- `refused_finality_parks_only_ids_with_exact_fifo_and_descendant_door`
  retains cap-plus-one FIFO eviction, exact-ID dedup, identity-only retention
  despite a large envelope and the direct-child admission door.
- The complete `finality_latch_tests` set retains latch boundaries,
  fork-choice removal, override behavior and parked-refusal semantics.

## Validation

```text
cargo test -p bloch-pos-node --bin bloch-pos \
  refused_finality_identity_index_matches_sequential_fifo_reappearance \
  --offline
# 1 passed; 0 failed; 618 filtered out

cargo test -p bloch-pos-node --bin bloch-pos \
  refused_finality_parks_only_ids_with_exact_fifo_and_descendant_door \
  --offline
# 1 passed; 0 failed; 618 filtered out

cargo test -p bloch-pos-node --bin bloch-pos finality_latch_tests --offline
# 10 passed; 0 failed; 609 filtered out

cargo check -p bloch-pos-node --bin bloch-pos --offline
# passed

cargo test -p bloch-pos-node --bin bloch-pos --offline
# 600 passed; 0 failed; 19 ignored; 63.96s
```

The focused and complete suites ran outside the restricted sandbox because
their engine and transport fixtures bind localhost sockets.

## Residual boundary

- Admission still scans the bounded parked-ID FIFO to match an incoming block
  or its direct parent. Replacing that persistent check would require a second
  long-lived index kept consistent with every mutation; this wave deliberately
  limits the index to one atomic refusal update.
- Building and updating the temporary ordered set remains logarithmic in the
  fixed refusal cap, and computing each envelope's block ID remains necessary.
- The identity-only FIFO is local refusal memory, not protocol evidence or a
  peer penalty.
- Hosted CI, release signing, deployment, rollback and fleet qualification
  remain outside source verification.
