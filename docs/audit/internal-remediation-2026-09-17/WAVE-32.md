# Internal audit remediation, thirty-second wave — 2026-09-18

Base: `b4504dc`; implementation commit `735a2c1`; branch
`fix/internal-audit-20260917`.

## Fail-closed boot switches

EN-22 records node-local behavior controlled by flags and environment. Several
safety/recovery switches used presence semantics: an orchestrator rendering
`BLOCH_NO_DOPPELGANGER=0`, for example, still disabled doppelgänger protection.
Other malformed values silently produced inconsistent behavior between the
switches.

A single pure parser now owns the finality-rewind override, doppelgänger opt-out,
forced genesis replay and required-state-cache switches. Absence, `0` and
`false` mean off; only `1` and `true` mean on. Empty values, capitalization,
whitespace, arbitrary strings and non-text values fail startup with an
`InvalidInput` error that names the offending variable. Each switch is still
read exactly once during single-threaded boot.

Three regressions cover absent/explicit-false, explicit-true and ambiguous
values without mutating process environment, so the tests cannot race other
test threads.

EN-22 moves to partial. This does not remove the deliberate operator overrides
or solve KS-18: doppelgänger observation is still memory/window-bound and can
still be explicitly bypassed. The ledger retains all 200 rows: 66 implemented,
80 partial, 40 open, seven base-changed, four protocol decisions, one unarmed
candidate, one refuted by the original audit and one verified positive.
