# Internal audit remediation, thirtieth wave — 2026-09-18

Base: `7e98917`; implementation commit `ba0dea6`; branch
`fix/internal-audit-20260917`.

## Optimized SIS regression profile

LD-03 measured the `bloch-sis-pow` test suite at 18 minutes 45 seconds because
three ordinary regressions mine real solutions through an unoptimized
implementation. Those tests are blocking in both CI systems, so the cost
dominated feedback time without increasing their coverage.

The workspace root now sets `opt-level = 3` for the `bloch-sis-pow` package in
the development/test profile. This follows the existing root-level treatment
of the expensive Argon2 and SHA3/Keccak implementations. It does not select a
release profile, disable debug assertions or disable overflow checks; source,
test vectors and accepted results are unchanged.

The complete crate suite passed offline: 81 tests passed and three explicitly
ignored maintenance/spec-vector utilities remained ignored. Wall time was
146.92 seconds, including 18.11 seconds rebuilding under the new profile. This
is an approximately 7.7x reduction from the audit's 1,125-second measurement.
The GitHub and GitLab timeout comments now describe the remaining long
consensus work rather than repeating the obsolete SIS estimate; the conservative
120-minute job timeout remains unchanged.

LD-03 is implemented. The ledger retains all 200 rows: 65 implemented, 79
partial, 42 open, seven base-changed, four protocol decisions, one unarmed
candidate, one refuted by the original audit and one verified positive.
