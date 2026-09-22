# Wave 93 — INF-01 Debian snapshot format

Date: 2026-09-19
Comparison base: `d285a0e`

## Reproduced gap

The release comparator required one nonempty `debian_snapshot` field and
equality between builders, but did not validate its syntax. Two otherwise
canonical candidates containing:

```text
debian_snapshot=whatever-is-live
```

passed the complete comparator. Matching arbitrary text therefore satisfied a
field intended to identify the Debian archive snapshot used by the canonical
container recipe.

## Fail-closed correction

The comparator now reads each candidate's `debian_snapshot` once and requires
the exact 16-character structure `YYYYMMDDTHHMMSSZ`: eight ASCII decimal
digits, uppercase `T`, six ASCII decimal digits and uppercase `Z`. It caches
the validated values for the later builder-to-builder equality check.

Validation uses Bash string length, fixed-position slices and the explicit
character set `0123456789`; it does not use an external regular-expression
engine or a locale-sensitive character range. The canonical Dockerfile emits
`20260917T000000Z`, so existing canonical candidates remain compatible.

No binary, manifest, build argument or pipeline command changed.

## Adversarial coverage

The canonical copied-directory fixture remains green. Five pairs of otherwise
valid candidates carry the same malformed value on both sides:

- free-form text;
- lowercase `t`/`z` separators;
- a punctuation separator;
- a 15-character value; and
- trailing whitespace.

Each must fail with the exact snapshot-format diagnostic. All earlier alias,
tree, manifest, binary and metadata mutations remain covered.

## Validation

```text
bash -n scripts/compare-pos-release-builds.sh \
  scripts/compare-pos-release-builds.selftest.sh
# passed

bash scripts/compare-pos-release-builds.selftest.sh
# compare-pos-release-builds selftest: PASS

git diff --check -- <Wave 93 INF-01 files>
# passed
```

## Residual boundary

This validates only local structure and equality. It does not prove that the
digits name a calendrically valid date or time, that the snapshot exists,
remains immutable or was available, or that the declared value matches the
Dockerfile/build argument actually executed. It does not authenticate source
bytes or a builder, prove independent builds, establish image/tool
provenance, sign or publish an artifact, authorize deployment, exercise
rollback, or qualify a fleet. Those external INF-01 gates remain mandatory.
