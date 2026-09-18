# Internal audit remediation, forty-seventh wave — committed equivocator-bar observability

Base: `1711937`; branch `codex/audit-fc12-equivocator-recovery`. This wave
adds a read-only projection and node-local observability. It does not expire a
bar, restore a vote, change consensus validity or state-root encoding, activate
a gate, migrate historical state, or deploy a binary.

## Recovered semantics

`CommittedState::accumulate_forkchoice` rebuilds a temporary fork-choice store
from committed latest messages on every block. Before accepting an attestation,
it skips any validator already present in `fc_equivocators`. A newly detected
same-slot conflict inserts the validator into that set and removes its latest
message. The set is serialized into `TAG_FC_EQUIVOCATOR` leaves and therefore
participates in every subsequent state root.

The set is monotone along one branch: its insertion sites have no matching
removal. Epoch rollover, voluntary exit and the slashing/ejection path do not
clear it. Exit does remove the validator from the active roster, so an exited
barred validator no longer represents excluded live weight, but its historical
record remains committed. A canonical reorg can replace the observed state
with another branch, which is why the node surface is a gauge rather than a
process-lifetime counter.

The gossip equivocation counter and slashing evidence are distinct paths.
Seeing a committed fork-choice bar does not prove that a slashing-evidence
transaction was included, and applying slashing does not consume or clear the
bar.

## Why no expiry candidate was added

The current set records only a validator index, not the offence epoch. A
bounded expiry needs at least a committed offence time and a migration rule for
every historical set member at activation. More importantly, restoring weight
requires protocol decisions that a local patch cannot infer:

- whether a bar ends after elapsed epochs, successful slashing, completed exit,
  or a newly bonded validator identity;
- whether validator indices may ever be reused and what old evidence means
  after re-entry;
- whether the latest message is restored, starts empty, or must be refreshed;
- how mixed binaries treat the first post-expiry vote and state root; and
- how the rule interacts with the separately unarmed bounded vote-history
  candidate.

Adding an inactive constant without the new committed timestamp and migration
would not be an executable candidate. Adding those fields would change the
post-activation state root and still leave the safety choices above undefined.
This wave therefore does not pretend to provide recovery.

## Operator-visible state

`CommittedState::forkchoice_equivocator_summary` is a pure read-only projection
with three values:

- the total historical members of the committed bar;
- the members still present in the current leak-adjusted consensus roster; and
- their exact active effective stake in satoshis.

The node samples that projection once per wall slot and exports:

- `bloch_pos_forkchoice_equivocators`;
- `bloch_pos_forkchoice_equivocators_active`; and
- `bloch_pos_forkchoice_equivocator_active_stake_sat`.

It also writes one diagnostic at startup when the committed set is non-empty
and again only when the canonical summary changes. No validator label is used,
avoiding an unbounded-cardinality metric. None of these values is read back by
block validation, fork choice, duty selection or replay.

## Status and residual

FC-12 moves from `OPEN` to `PARTIAL`, not `IMPLEMENTED`. Operators can now
distinguish a historical bar from active consensus weight loss and alert on the
quorum impact. The permanent bar itself remains unchanged. A safe recovery
still requires a written lifecycle/evidence policy, committed offence-age
representation, historical migration, mixed-version replay analysis and a
coordinated activation decision.

On this wave's isolated `1711937`-based branch, the post-wave ledger retained
all 200 findings: 71 implemented, 95 partial, 10 open, ten unarmed candidates,
seven base-changed, four protocol decisions, two verified positives and one
finding refuted by the original audit. Those branch-relative totals are not the
integrated ledger; the canonical `FINDINGS.md` counts were recomputed after all
concurrent Wave 47 changes were merged.

## Validation

- `cargo test -p bloch-pos-committee forkchoice_equivocator_summary_separates_history_from_active_weight -- --nocapture`
  — one focused regression passed.
- `cargo test -p bloch-pos-node metrics::tests::counter_increment_changes_render -- --nocapture`
  — the Prometheus registry regression passed.
- `cargo test -p bloch-pos-committee --lib` — 443 passed, zero failed and four
  ignored scale tests.
- `cargo test -p bloch-pos-node --bin bloch-pos` — 497 passed, zero failed and
  19 ignored rehearsal/benchmark tests when run with local socket permission.
- `cargo clippy -p bloch-pos-committee --lib` and
  `cargo clippy -p bloch-pos-node --bin bloch-pos` — completed with only
  pre-existing warnings.

The first sandboxed node-suite attempt passed 350 tests but denied local socket
creation to 147 tests. Re-running with local socket permission produced the
clean result above.
