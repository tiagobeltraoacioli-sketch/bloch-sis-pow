# Wave 92 — INF-01 source-date epoch format

Date: 2026-09-19
Comparison base: `7a91290`

## Reproduced gap

The release comparator required one nonempty `source_date_epoch` field and
equality between builders, but did not validate its syntax. Two otherwise
canonical candidates containing:

```text
source_date_epoch=not-a-timestamp
```

passed the complete comparator. Matching arbitrary text therefore satisfied a
field intended to carry the commit's Unix timestamp.

## Fail-closed correction

The comparator now reads each candidate's `source_date_epoch` once, requires a
nonempty string containing decimal digits only and caches that validated value
for the later builder-to-builder equality check. This matches the existing
contract in `build-pos-release-container.sh`, which obtains `%ct` from Git and
rejects empty or non-decimal output before invoking the container build.

No binary, manifest or pipeline command changed. Existing canonical candidates
already satisfy the format.

## Adversarial coverage

The canonical copied-directory fixture remains green. Four pairs of otherwise
valid candidates carry the same malformed value on both sides:

- alphabetic text;
- a negative sign;
- a decimal point; and
- trailing whitespace.

Each must fail with the exact source-date diagnostic, proving equality cannot
substitute for syntax validation. All earlier alias, tree, manifest, binary
and metadata mutations remain covered.

## Validation

```text
bash -n scripts/compare-pos-release-builds.sh \
  scripts/compare-pos-release-builds.selftest.sh
# passed

bash scripts/compare-pos-release-builds.selftest.sh
# compare-pos-release-builds selftest: PASS

git diff --check -- <Wave 92 INF-01 files>
# passed
```

## Residual boundary

This validates only local decimal syntax and equality. It does not prove the
epoch is plausible, canonical against leading-zero alternatives, or equal to
the declared commit's real timestamp. It does not prove that commit exists or
is reachable, authenticate source bytes or a builder, prove independent
builds, establish tool/image provenance, sign or publish an artifact,
authorize deployment, exercise rollback, or qualify a fleet. Those external
INF-01 gates remain mandatory.
