# Internal audit remediation, twenty-third wave — 2026-09-17

Base: `e815b0e`; branch `fix/internal-audit-20260917`. This wave records local
verification of an existing safeguard; it contains no production-code change
and makes no fleet-deployment claim.

## Validator withdrawal mutation guard

ST-14 is a verified positive, not a defect repaired by this branch. The
repository's blocking GitHub Actions live-crates job already runs
`scripts/check-validator-lifecycle-mutations.py`. The script copies tracked
source to a disposable directory, requires an unmodified passing control, then
compiles and executes each mutation. A compiler error or missing test does not
count as a kill.

The guard was re-executed at this checkpoint. Its control passed, and the
validator lifecycle suite killed all eight mutations: activation, maturity,
one-shot payout, indeterminate write-off provenance, withdrawal credential,
integer narrowing, payout-output collision and write-off overflow. It then
confirmed the shipping lifecycle source was unchanged.

## Status

ST-14 moves from open to verified positive. It is deliberately not counted as
implemented: this wave did not create the safeguard. The ledger retains all 200
rows: 61 implemented locally, 76 partial, 49 open, seven base-changed, four
protocol decisions, one unarmed candidate, one refuted by the original audit
and one verified positive. Details are in `VALIDATION-WAVE-23.txt`.
