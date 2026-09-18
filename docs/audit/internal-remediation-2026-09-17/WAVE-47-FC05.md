# Wave 47 FC-05: inactive fork-choice slot tiebreak candidate

Date: 2026-09-18. Branch: `codex/audit-fc05-proposer-boost`. Starting
point: `1711937`. Scope: local source, tests, and audit evidence only. No
activation epoch, consensus behavior, node, validator, release, deployment,
or live state changed.

## Recovered finding and current behavior

The exact source was recovered from repository history at
`a79c88b:docs/audit/deep-audit-2026-09-16/A2-consensus-finality-forkchoice.md`.
FC-05 describes an ex-ante reorg in which the adversary controls both members
of slot s's two-member committee and the proposer at s+1. It withholds the
slot-s votes, builds the next block on s-1, and edits its body until the
resulting block id wins the zero-weight sibling tie. Honest slot-s+1 voters
then follow that selected head. The same finding also describes a balancing
attack and records that the protocol has no proposer boost.

The current `Store::head` confirms the root lever: equal-weight siblings pick
the lexicographically larger block id. The node applies that rule to stored
blocks and pool attestations. A block id commits to `body_root`, so a proposer
can cheaply sample either side of a root ordering. Merely reversing the order
to prefer the lower root, as one audit example suggested, does not remove the
grind: the proposer can sample for a smaller id instead.

## Candidate, deliberately inactive

`FORKCHOICE_SLOT_TIEBREAK_ACTIVATION_EPOCH` remains `u64::MAX`, and the shared
epoch-gate helper treats that sentinel as inactive even at a synthetic
`u64::MAX` epoch. Production therefore calls the historical root-tiebreak path
and selects exactly the same head as before this wave.

The staged candidate uses the slot already committed by each validated signed
header. When equal-weight sibling slots differ, the earlier slot wins; only
equal-slot siblings fall back to the historical larger-root order. The
next-slot proposer can edit its body and root but cannot turn its signed slot
into the honest sibling's earlier slot, so this removes the exact FC-05 ex-ante
body-grinding lever without pretending that a root direction is random.

The attack regression constructs an honest slot-10 sibling, grinds a slot-11
body until its id is larger, and proves three boundaries: live fork choice
selects the attacker's id, the inert epoch-gated entry point still selects the
same id, and the candidate selects the honest earlier-slot sibling. A final
same-slot control proves that the candidate deliberately retains root ordering
there.

FC-05 moves from `OPEN` to `UNARMED CANDIDATE`, not `IMPLEMENTED`. This narrow
candidate is not proposer boost and does not resolve balancing or same-slot
root grinding. Earlier-slot preference can itself affect liveness and reorg
dynamics under delayed delivery. Before any activation decision it needs a
complete timeliness/proposer-boost design comparison, adversarial simulations
covering balancing and partitions, stake/committee-size sensitivity, historical
replay, mixed-version fleet rehearsal, and an explicit coordinated flag day.

## Validation

- `cargo test -p bloch-pos-node --bin bloch-pos next_slot_body_grind_cannot_win_the_inactive_slot_tiebreak_candidate --offline`:
  one adversarial regression passed.
- `cargo test -p bloch-pos-node --bin bloch-pos forkchoice_tests --offline`:
  10 passed, one ignored performance test, zero failed.
- `cargo test -p bloch-pos-committee --test properties forkchoice_head_matches_the_reference_implementation --offline`:
  one differential property test passed.
- `git diff --check`: passed.

The builds emitted inherited unused-import and dead-code warnings. These local
tests are not evidence that the candidate is safe to activate.
