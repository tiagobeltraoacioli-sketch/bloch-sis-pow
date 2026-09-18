# Internal audit remediation, nineteenth wave — 2026-09-17

Base: `b467e77`; implementation commit `28e2da9`; branch
`fix/internal-audit-20260917`. This is local source/test evidence, not a fleet
deployment claim.

## Delegation eligibility ownership

TX-18 is closed without changing tag `0x04` or removing its frozen eligibility
byte. The decoder continues to accept both canonical boolean values, preserving
the historical wire grammar. The committed-state transition now owns the
field's consensus meaning: it rejects `false` as a staking-rule violation and
stores the derived value `true` for every admitted legacy delegation.

The taint oracle that originally motivated caller-supplied eligibility was
retired before Genesis-4. Consequently, a transaction sender can no longer
write an eligibility decision into state. Internal `Delegation.eligible =
false` remains available only for protocol-owned lifecycle handling, including
the slash-exposure mask for an already withdrawn delegation.

A regression pins all three boundaries: the false byte still round-trips
through the frozen codec, transition rejection is atomic, and the only admitted
value produces an eligible committed delegation. The legacy bonding gate and
its activation schedule remain unchanged.

## Validation and status

The full committee package passed 620 tests with six ignored and no failures,
including the new eligibility regression, every transition/integration suite
and doc tests. Comment/constants, banned-language and diff-integrity gates
passed. Details are in `VALIDATION-WAVE-19.txt`.

TX-18 moves from open to implemented. The ledger retains all 200 rows: 58
implemented locally, 76 partial, 53 open, seven base-changed, four protocol
decisions, one unarmed candidate and one refuted by the original audit.
