# Wave 94 — INF-01 canonical BUILD-INFO bytes

Date: 2026-09-19
Comparison base: `7719e49`

## Reproduced gap

The release comparator required exactly eight recognized fields, validated
their security-sensitive values and compared both builders' complete metadata
files. It did not require the canonical producer's field order. Two otherwise
valid candidates with identical files beginning:

```text
source_commit=0123456789abcdef0123456789abcdef01234567
artifact_kind=canonical-container-candidate
```

passed the complete comparator even though the Dockerfile always emits
`artifact_kind` first and `source_commit` second.

## Fail-closed correction

After all existing per-field validators pass, the comparator now compares the
complete `BUILD-INFO` bytes with a generated canonical stream in the exact
Dockerfile order:

1. `artifact_kind`
2. `source_commit`
3. `source_date_epoch`
4. `debian_snapshot`
5. `target`
6. `binary_sha256`
7. `signed`
8. `deployment_authorized`

The stream includes the final newline and reuses the values already parsed and
validated. `target` and `binary_sha256` are now likewise cached for the later
A/B equality checks instead of being parsed a second time. No existing format,
checksum, unsigned-state or authorization validator was weakened.

The Dockerfile and canonical selftest fixture already emit this exact layout,
so canonical candidates remain compatible.

## Adversarial coverage

The canonical copied-directory fixture remains green. Three pairs of otherwise
valid candidates carry the same noncanonical ordering on both sides:

- the first two fields swapped;
- all eight fields reversed; and
- the two middle snapshot/target fields swapped.

Each reaches the full-file contract and fails with its exact diagnostic. A
fourth pair removes the final newline and remains refused by the existing
eight-line contract. All prior alias, tree, manifest, binary and per-field
mutations remain covered.

## Validation

```text
bash -n scripts/compare-pos-release-builds.sh \
  scripts/compare-pos-release-builds.selftest.sh
# passed

bash scripts/compare-pos-release-builds.selftest.sh
# compare-pos-release-builds selftest: PASS

git diff --check -- <Wave 94 INF-01 files>
# passed
```

## Residual boundary

This proves only a canonical local serialization of the declared metadata. It
does not validate every field's semantics or target syntax, prove a commit or
snapshot exists or matches the source/build actually executed, authenticate a
builder, prove independent builds, establish image/tool provenance, sign or
publish an artifact, authorize deployment, exercise rollback, or qualify a
fleet. Those external INF-01 gates remain mandatory.
