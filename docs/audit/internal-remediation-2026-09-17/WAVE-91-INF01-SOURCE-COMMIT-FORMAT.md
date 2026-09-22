# Wave 91 — INF-01 source-commit format

Date: 2026-09-19
Comparison base: `df03acf`

## Reproduced gap

The release comparator required one nonempty `source_commit` field and equality
between builders, but did not validate the value's format. Two otherwise
canonical candidates containing:

```text
source_commit=not-a-git-object
```

passed the complete comparator. Equality alone therefore allowed metadata that
could not name a commit under the current release builder's contract.

## Fail-closed correction

The comparator now reads each candidate's `source_commit` once, requires
exactly 40 lowercase hexadecimal characters and caches that validated value
for the later builder-to-builder equality check. This is the same SHA-1 object
name contract already enforced by `build-pos-release-container.sh` for HEAD
before it creates the canonical build context and metadata.

No binary, manifest or pipeline command changed. Existing canonical candidates
already satisfy the format.

## Adversarial coverage

The canonical copied-directory fixture remains green. Four pairs of otherwise
valid candidates carry the same malformed value on both sides, proving that
matching metadata cannot bypass syntax validation:

- one non-hexadecimal character;
- uppercase hexadecimal characters;
- 39 lowercase hexadecimal characters; and
- 41 lowercase hexadecimal characters.

Each must fail with the exact source-commit diagnostic. All prior alias, tree,
manifest, binary and metadata mutations remain covered.

## Validation

```text
bash -n scripts/compare-pos-release-builds.sh \
  scripts/compare-pos-release-builds.selftest.sh
# passed

bash scripts/compare-pos-release-builds.selftest.sh
# compare-pos-release-builds selftest: PASS

git diff --check -- <Wave 91 INF-01 files>
# passed
```

## Residual boundary

This validates only the local syntax and equality of the declared commit. It
does not prove the object exists or is reachable, authenticate source bytes or
a builder, prove independent builds, establish tool/image provenance, sign or
publish an artifact, authorize deployment, exercise rollback, or qualify a
fleet. A future Git object-format migration to SHA-256 requires a coordinated
contract change in both the canonical builder and this comparator; it must not
be silently accepted by only one side.
