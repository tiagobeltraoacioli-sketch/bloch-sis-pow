# Internal audit remediation, fourteenth wave — 2026-09-17

Base: `969fc22`, implementation commit `bbf4cc5`, branch
`fix/internal-audit-20260917`. This is local source evidence, not a fleet
activation or release approval.

## Complete single-derivation-path tripwire

SR-06 identified blind spots in the source-scanning test that guards Genesis-4
block identity. The scan used `read_dir(src)` and therefore inspected only the
top-level Rust files, even though consensus code now also lives below
`src/transition/**`. Its textual patterns also depended on one exact whitespace
spelling, so a tuple construction, trait implementation, alias or rename split
across lines could escape detection.

The test now walks every ordinary Rust source below `src/` recursively, sorting
each directory for deterministic diagnostics and reporting paths relative to
the source root. It strips comments/string contents as before, canonicalizes
qualified `BlockId` paths, and removes insignificant whitespace before checking
constructor, trait-implementation and alias/rename patterns. The coverage floor
is raised from five files to the current 29-file source tree.

A separate regression proves that nested funded/lifecycle modules are in the
enumeration and that five spacing variants normalize into a forbidden pattern.
The production `BlockId`, its canonical encoding and its digest are unchanged.
The recursive tripwire still observes exactly one construction site, inside
`BlockId::of`.

## Validation and status

Both focused regressions passed. The complete committee suite passed 618 tests
with six ignored, including compile-fail doctests; details are in
`VALIDATION-WAVE-14.txt`.

SR-06 moves from open to implemented. The ledger retains all 200 rows: 54
implemented locally, 75 partial, 58 open, seven base-changed, four protocol
decisions, one unarmed candidate and one refuted by the original audit.
