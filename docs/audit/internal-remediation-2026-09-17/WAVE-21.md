# Internal audit remediation, twenty-first wave — 2026-09-17

Base: `64fabfc`; implementation commit `725c029`; branch
`fix/internal-audit-20260917`. This is local source/test evidence, not a fleet
deployment claim.

## Live state-component authority and diagnostic semantics

TX-20 is closed without changing a state-root byte. The frozen Phase-1
`StateRoots` type is now accurately classified as a 14-field compatibility DTO
with no production `StateCommitment` implementation. Production commits
`ConsensusState` through the concrete state-root fold. Its 30 component
names/tag bytes now have one public, append-only machine-readable authority:
`STATE_COMPONENT_TAGS`.

The existing uniqueness test consumes that registry instead of maintaining a
second hand-copied list. The spec-reconciliation test also consumes it and
requires every name and byte through `TAG_FUNDED_VALIDATOR = 0x1E` to appear
in the migration spec. The interfaces, node-storage, EVM and execution-plan
documents no longer present the compatibility DTO as the live tree schema.

The second half of TX-20 is also reconciled: transition reject precedence is
API-visible, operationally useful and kept cheap-first, but a local
`TransitionError` is neither encoded nor committed. Consensus requires equal
accept/reject results and equal accepted child roots; it does not require two
implementations to select the same diagnostic for a multiply-invalid block.

## Validation and status

All nine spec-reconciliation tests, the component-tag uniqueness regression
and both committee doc tests pass. Comment/constants, banned-language and
diff-integrity gates pass. Details are in `VALIDATION-WAVE-21.txt`.

TX-20 moves from open to implemented. The ledger retains all 200 rows: 60
implemented locally, 76 partial, 51 open, seven base-changed, four protocol
decisions, one unarmed candidate and one refuted by the original audit.
