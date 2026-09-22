# Internal audit remediation, twentieth wave — 2026-09-17

Base: `d827aa4`; implementation commit `d6989c1`; branch
`fix/internal-audit-20260917`. This is local source/test evidence, not a fleet
deployment claim.

## Fee-market and tokenomics reconciliation

TX-19 is closed as a specification-integrity correction. The fee-market spec
now distinguishes the deployed eUTXO/lifecycle cost shape from reserved EVM
and Coherence pricing variants, records the epoch-800 increase from a 256 KiB
to 512 KiB transaction-payload cap, names the epoch-aware target, identifies
the live base-fee leaf as append-only tag `0x15`, and publishes the actual
integer-recurrence inflation values (434/285/168 bps in years 1/5/10).

The tokenomics spec now uses one terminal carryover dataset throughout:
452,726 outputs, 16 addresses, 18,146,400,000 BLCH, the published set/file
digest prefixes, 42,853,600,000 BLCH validator emission, and 1,099,570,620
BLCH across the 15 non-largest addresses. Allocation shares, the embedded
chart, policy-scheduled genesis liquidity, concentration arithmetic and the
2-year/8-year founder schedule were reconciled to those inputs. The abandoned
height-50,000 analysis remains explicitly labelled archived decision history.

Two new spec-reconciliation regressions derive the published caps, activation
epoch, inflation basis points, allocations and digest prefixes from shipped
Rust constants. They also refuse the concrete stale claims found by the audit.
No consensus behavior, wire encoding or activation schedule changed.

## Validation and status

The eight spec-reconciliation tests and the focused emission test pass.
Comment/constants, banned-language and diff-integrity gates pass. Details are
in `VALIDATION-WAVE-20.txt`.

TX-19 moves from open to implemented. The ledger retains all 200 rows: 59
implemented locally, 76 partial, 52 open, seven base-changed, four protocol
decisions, one unarmed candidate and one refuted by the original audit.
