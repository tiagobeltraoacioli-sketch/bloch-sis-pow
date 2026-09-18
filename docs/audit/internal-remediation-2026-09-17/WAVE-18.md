# Internal audit remediation, eighteenth wave — 2026-09-17

Base: `02d071c`; implementation commit `5173c7c`; branch
`fix/internal-audit-20260917`. This is local source/test evidence, not a fleet
deployment claim.

## Funded-deposit decode/judge separation

TX-17 is closed without changing its wire bytes or accepted transaction set.
`FundedDeposit::decode` now answers only whether bytes can be parsed within
explicit resource bounds. It retains maximum key, signature and input-count
limits before allocation, but no longer calls the economic `validate_shape`
judge. In particular, an empty input vector is syntactically representable and
decodes; admission and the committed-state transition reject it as `Shape`.

All existing judgment doors remain:

- node mempool admission calls `validate_shape` before accepting the deposit;
- CLI construction validates both the draft and its final change;
- committed-state validation calls `validate_shape` before network, stake,
  ownership, conservation and authorization checks;
- authorization validation itself also refuses an invalid shape.

Thus an invalid funded deposit in a block still rejects the block, and an
invalid submission still rejects at admission. Only the layer naming the
reason changes from a byte-decoding error to the transaction judge. A new
regression proves bounded invalid bytes decode and then receive `Shape`; the
existing hostile-length/input-count regression proves resource bounds remain
at the parser boundary.

## Validation and status

The full committee package passed 619 tests with six ignored and no failures,
including every funded-admission, codec, transition and doc test. The two
decoder-focused tests passed separately. Comment/constants, banned-language
and diff-integrity gates passed. Details are in `VALIDATION-WAVE-18.txt`.

TX-17 moves from open to implemented. The ledger retains all 200 rows: 57
implemented locally, 76 partial, 54 open, seven base-changed, four protocol
decisions, one unarmed candidate and one refuted by the original audit.
