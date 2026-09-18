# Internal audit remediation, forty-first wave — 2026-09-18

Base: `66b7de9`; branch `fix/internal-audit-20260917`. This wave reconciles
FC-06 against the current node and committee code. It does not arm a consensus
flag day.

## FC-06: orphan exposure removed; order dependence still gated

The original finding had two separable claims.

First, every stored envelope, including an orphan, fed node fork choice. That
is no longer true. Admission holds an unknown-parent block in the bounded
`orphans` queue, sets `needs_sync`, and does not insert it into `blocks`.
Promotion occurs only after the parent lands. Finality-shaped pruning also
removes stale stored descendants and related parked orphans without imposing
an arbitrary cap on a still-connected live branch. The node regressions prove
both boundaries and prove pruning does not move the selected head.

Second, the bare latest-message store is still order-dependent for one
validator's three-message O01 sequence: A and B conflict at one slot, while C
is later. If C is observed between the conflicting messages, four of the six
arrival orders miss the equivocation. A regression deliberately preserves
that exact current behavior.

The complete candidate retains a bounded per-validator, per-slot vote horizon
in committed state and, in an activation rehearsal, bars the equivocator in
all six orders. Its activation epoch remains unarmed. Turning it on changes
consensus state and historical replay, so a documentation reconciliation may
not choose a flag day or silently modify the live rule.

FC-06 is therefore `PARTIAL`, not `OPEN` and not `IMPLEMENTED`: one concrete
exposure is removed and the remaining one has a tested, deliberately inactive
candidate. The ledger retains all 200 rows: 66 implemented, 89 partial, 30
open, seven base-changed, four protocol decisions, one unarmed candidate, one
refuted by the original audit and two verified positives.

