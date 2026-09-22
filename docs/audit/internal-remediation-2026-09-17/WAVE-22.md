# Internal audit remediation, twenty-second wave — 2026-09-17

Base: `38c202d`; implementation commit `5759d0e`; branch
`fix/internal-audit-20260917`. This is local source/test evidence, not a fleet
deployment claim.

## Single block-validation stack

TX-21 is closed by source-history reconciliation and an executable regression,
not by deleting a second live validator in this wave. Commit `cabcdcee` deleted
the drifted `derive::validate_block` / `produce.rs` path. Git ancestry checks
prove that commit is an ancestor of both audited revision `562e220` and
remediation base `b066e3c`; the audit's claim that the stacks still coexist was
therefore stale when made.

The production node constructs a candidate through
`Transition::compute_post_state` and validates every own or peer block through
`Transition::apply_block`. A new source-structure test refuses a returned
`produce.rs`, its module declaration, or the retired validation/state-carrier
symbols, and requires both transition calls in the node engine. Historical
reference-harness and planning prose now identifies itself accurately instead
of presenting deleted code as an upcoming or parallel production path.

## Validation and status

All ten spec-reconciliation tests pass. The real node engine regression that
proposes and gives a block back to the validator passes and leaves the head
header root equal to committed state. Comment/constants, banned-language and
diff-integrity gates pass. Details are in `VALIDATION-WAVE-22.txt`.

TX-21 moves from open to implemented. The ledger retains all 200 rows: 61
implemented locally, 76 partial, 50 open, seven base-changed, four protocol
decisions, one unarmed candidate and one refuted by the original audit.
