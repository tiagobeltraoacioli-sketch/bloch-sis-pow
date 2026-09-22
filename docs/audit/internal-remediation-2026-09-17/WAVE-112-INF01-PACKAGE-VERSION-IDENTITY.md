# Wave 112 — INF-01 package version identity

Date: 2026-09-19
Comparison base: `7b2895b`

## Reproduced gap

The unsigned candidate packager searched the complete multiline `--version`
output for the captured short commit, but published only the first two lines in
`BUILD-INFO`. A binary could therefore put an unbound version on line one, an
arbitrary nonempty identity on line two and the expected commit in a discarded
third line. The check passed although neither published field contained the
evidence that made it pass. Extra output was silently discarded as well.

## Correction

The packager now captures the raw output in a private file and requires exactly
two newline-terminated canonical text lines. The first must contain the exact
`(<commit-12>)` token. The second must match the node's real clean asserted
identity format: a 64-character lowercase SHA3-256 digest, decimal file/byte
counts, `commit-source:asserted` and `tree:asserted-clean`. The two validated
lines are the same bytes subsequently written into `BUILD-INFO` fields.

## Adversarial coverage

The hermetic fake binary now emits the real two-line shape. Existing dirty-tree
and captured-OID source/config/toolchain races remain covered. New fixtures
reject a two-line version missing the commit token, a commit decoy on line
three, an otherwise valid output with an extra line, and a malformed digest
with a dirty tree state.

## Validation

```text
bash scripts/package-pos-release-candidate.selftest.sh
# package-pos-release-candidate selftest: PASS

bash -n scripts/package-pos-release-candidate.sh
bash -n scripts/package-pos-release-candidate.selftest.sh
# passed
```

## Residual boundary

The version and source-identity strings remain assertions emitted by the built
program; structural validation does not authenticate the compiler, runner,
repository, dependencies or resulting semantics. A deliberate future change
to the two-line CLI contract requires an atomic packager/test update. Signing,
publication, independent canonical builds and comparison, approval, rollback
rehearsal, staged canary and fleet evidence remain external release gates.
INF-01 remains `PARTIAL`.
