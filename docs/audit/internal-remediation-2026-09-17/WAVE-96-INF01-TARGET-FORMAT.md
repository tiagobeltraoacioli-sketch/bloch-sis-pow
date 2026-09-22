# Wave 96 — INF-01 target format

Date: 2026-09-19
Comparison base: `46de03c`

## Reproduced gap

The release comparator required one nonempty `target` field, canonical
`BUILD-INFO` encoding and equality between builders, but did not validate the
field's syntax. Two otherwise canonical candidates containing:

```text
target=not a rust target
```

passed the complete comparator. Matching arbitrary text therefore satisfied a
field intended to carry the host triple reported by `rustc -vV` in the
canonical Docker build.

## Fail-closed correction

The already single-read, cached `target` now must contain only lowercase ASCII
letters, decimal digits, underscore and hyphen. It must have at least three
nonempty hyphen-delimited components, with no leading, trailing or doubled
hyphen. Validation uses an explicit ASCII character set and Bash patterns;
there is no locale-sensitive range or external regular-expression engine.

The canonical fixture and Docker host value `x86_64-unknown-linux-gnu` satisfy
this structural contract. The check deliberately does not pin an architecture
that has not been qualified in this local environment. No binary, build
argument or pipeline command changed.

## Adversarial coverage

The canonical copied-directory fixture remains green. Five pairs of otherwise
valid candidates carry the same malformed target on both sides:

- whitespace-separated words;
- an uppercase architecture;
- a JSON/path-like value containing slash and dot;
- only two hyphen-delimited components; and
- an empty middle component expressed by a doubled hyphen.

Each must fail with the exact target-format diagnostic. All earlier alias,
tree, manifest, metadata-order, binary and per-field mutations remain covered.

## Validation

```text
bash -n scripts/compare-pos-release-builds.sh \
  scripts/compare-pos-release-builds.selftest.sh
# passed

bash scripts/compare-pos-release-builds.selftest.sh
# compare-pos-release-builds selftest: PASS

git diff --check -- <Wave 96 INF-01 files>
# passed
```

## Residual boundary

This validates only local target syntax and equality. It does not prove the
triple is recognized by the pinned compiler, identify the architecture/ABI
approved for release, exclude cross compilation, or prove the declared target
matches the compiler and binary actually produced. It does not authenticate a
builder, prove independent builds, establish image/tool provenance, sign or
publish an artifact, authorize deployment, exercise rollback, or qualify a
fleet. Those external INF-01 gates remain mandatory.
