# Internal audit remediation, twenty-fourth wave — 2026-09-17

Base: `dde87b8`; implementation commit `647c752`; branch
`fix/internal-audit-20260917`. This is local source/test evidence, not a fleet
deployment claim.

## Complete domain and preimage-shape registry

SR-11 is closed without changing a digest byte. `params::DOMAIN_TAGS` is now a
single machine-readable authority for all 15 shipped `BLCH4:*` domain tags and
the live preimage shapes using each one. The registry makes the frozen shared
domains explicit: body/state shapes have marker and kind bytes, sortition uses
disjoint role bytes, RANDAO shapes have different fixed lengths, and slashing
identities contain roots already separated by attestation/proposal domains.
The legacy and funded deposit PoP encodings remain frozen and are identified
separately rather than silently changing signatures after activation.

`DS_SPEND2`, previously absent from the independent frozen list and normative
table, is now covered by both. The spec reconciliation test consumes the live
registry, requires all entries to be documented and nonempty, and checks names
and bytes pairwise. The independent source scanner now requires the number of
`DS_*` constants to match its frozen registry. Stale prose that assigned an
exit root to `DS_SLASH` now names `DS_EXIT`; planning and namespace documents
describe the shipped 15-tag state.

## Validation and status

The complete committee suite passes: 624 passed, zero failed and six ignored.
That includes all ten spec-reconciliation tests, all nine independent wire-tag
registry tests and both doc tests. Comment/constants, banned-language and
diff-integrity gates pass. Details are in `VALIDATION-WAVE-24.txt`.

SR-11 moves from open to implemented. The ledger retains all 200 rows: 62
implemented locally, 76 partial, 48 open, seven base-changed, four protocol
decisions, one unarmed candidate, one refuted by the original audit and one
verified positive.
