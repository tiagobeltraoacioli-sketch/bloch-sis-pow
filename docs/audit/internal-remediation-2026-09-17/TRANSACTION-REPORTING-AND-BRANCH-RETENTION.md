# Transaction reporting and unreachable branch retention

Date: 2026-09-17. Follow-up to EN-06/EN-09 and explorer transaction accuracy.
These changes affect node-local bookkeeping and reporting. They do not alter
consensus validity, activation gates, checkpoint selection, wire formats, or
signatures.

## Transaction finality names a block

`Engine::tx_status` previously compared the transaction's inclusion epoch with
the finalized/justified epoch. Genesis finality therefore labeled a transaction
in slot 1 as finalized, although genesis itself was the named checkpoint. More
generally, the checkpoint convention selects the last block strictly before an
epoch boundary, so other blocks in that epoch are outside its finalized prefix.

Transaction status now uses `Engine::finality_of`, the same helper as block RPC
responses. It resolves the named checkpoint roots on the canonical chain and
compares their slots with the inclusion slot. An unresolved checkpoint cannot
promote a transaction to justified/finalized. No new confirmation-count heuristic
is introduced.

The regression includes a real signed funded transfer at slot 1 and drives real
attestations and proposals to finality. It checks transaction status before
finality and both sides of the resulting named checkpoint boundaries. Additional
synthetic transaction-index entries isolate the boundary reporting checks; the
finality state and canonical checkpoints themselves are not injected.

## Rejected reorganizations leave transaction records untouched

`Engine::do_reorg` previously updated the bounded transaction index after each
candidate block passed validation. If a later block failed, the canonical state
and head stayed unchanged but those earlier candidate transactions remained
reported as included. Resubmission could incorrectly return `Duplicate`; a large
candidate could also evict legitimate entries from the bounded index.

Candidate inclusion records now remain local until every block passes. The
node then removes losing-tail records, compacts stale FIFO identities once, and
records the accepted branch. Compaction prevents an old queue identity from
later evicting a freshly re-included transaction. The
regression builds a real signed transfer block followed by a signed block with
an invalid state root. Rejection must preserve state, head, transaction index,
and index order; the transfer must remain resubmittable. A valid-branch control
then proves that accepted reorganizations still publish inclusion.

## EN-09: remove descendants of already-pruned ancestors (partial)

Finalized-floor pruning already removed noncanonical blocks below its floor.
It left their high-slot descendants in the fork-choice input map permanently,
even though the removed ancestor made them unreachable. Pending descendants
could likewise continue occupying orphan slots.

The sweep now builds parent-to-child edges only when its existing floor policy
finds a removal. It propagates that removal through noncanonical stored blocks
and pending descendants, independent of arrival order. Canonical blocks always
remain; unrelated gaps and still-connected branches remain eligible. The test
uses actual voted finality and verifies unchanged canonical membership and
fork-choice head, retained independent branches/gaps, and exact cleanup counts.

This is not a cap on live fork-choice branches. Authenticated above-floor
forks can still accumulate while finality stalls; resolving that remaining
EN-09 case requires a qualified retention/synchronization design. Arbitrarily
dropping a selectable branch would risk local censorship or divergence.

## Targeted qualification

- Transaction proposal/reporting regressions: 7 passed, including both new
  reporting cases (`/private/tmp/bloch-wave7-tx-reporting-final.log`).
- Existing transaction-status compatibility suite: 9 passed
  (`/private/tmp/bloch-wave7-tx-status-existing.log`).
- Finalized descendant retention regression: 1 passed against actual voted
  finality (`/private/tmp/bloch-wave7-descendant-pruning.log`).

No ignored rehearsal or live deployment is counted as qualification here.
