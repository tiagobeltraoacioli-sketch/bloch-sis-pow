# Internal audit remediation, thirty-seventh wave — 2026-09-18

Base: `3a29db8`; implementation: `ac1d289`; branch
`fix/internal-audit-20260917`.

## BV-17: execute the emitted hybrid custody guard

The wallet suite previously compared only hashes of the program emitted by
`hybrid_wbtc_validator`. A new regression now executes that exact emitted
program through the historical eUTXO VM with its real stack contract:

- a valid ECDSA leg and valid PQ leg accept;
- an invalid ECDSA leg aborts at the mandatory assertion;
- an invalid PQ leg leaves a false terminal result.

This closes the missing-execution-test half of BV-17 and protects the helper's
`Pick` offsets and signature-family wiring from silent drift.

BV-17 remains partial. The native Ustav v3 ledger intentionally exposes only a
PQ verifier and rejects `Custody`/`VerifyEcdsa` policies with
`ClassicalPolicyNotAllowed`, even when a host would accept the classical
signature. The helper therefore runs only in the historical VM; it is not a
deployable Ustav anchor guard and is not wired into consensus.

The ledger retains all 200 rows: 66 implemented, 86 partial, 34 open, seven
base-changed, four protocol decisions, one unarmed candidate, one refuted by
the original audit and one verified positive.
