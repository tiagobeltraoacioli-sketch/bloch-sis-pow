# Wave 97 — INF-01 canonical Debian snapshot identity

Date: 2026-09-19
Comparison base: `18da009`

## Reproduced gap

The release comparator validated the sixteen-byte structure of each
`debian_snapshot` value and required the two candidates to agree, but it did
not bind that value to the canonical producer. The checked-in Dockerfile fixes
`DEBIAN_SNAPSHOT=20260917T000000Z`, and the build wrapper does not override
that argument. Nevertheless, two otherwise canonical fixtures carrying the
same alternate value were accepted. A temporary full-selftest reproduction
using `20261317T000000Z` completed with `PASS`.

This was a local metadata-coherence gap. It was not evidence that a malformed
calendar value could be fetched from the Debian snapshot service or emitted
by the reviewed build wrapper.

## Correction

After retaining the Wave 93 structural validator, the comparator now requires
the exact canonical value `20260917T000000Z`. A structurally invalid value
continues to fail with the existing `YYYYMMDDTHHMMSSZ` diagnostic. A
structurally valid but different value fails with a distinct canonical-pin
diagnostic.

The pin intentionally mirrors `deploy/pos-release/Dockerfile`. Rotating the
snapshot requires one reviewed, atomic change to the Dockerfile, comparator
constant and canonical selftest fixture; an incomplete rotation fails closed.

## Adversarial coverage

The canonical copied-directory fixture remains green. Three pairs of otherwise
valid candidates carry the same noncanonical value on both sides and must
fail with the canonical-pin diagnostic:

- an alternate adjacent timestamp, `20260918T000000Z`;
- a structurally valid month-13 timestamp, `20261317T000000Z`; and
- an older valid timestamp, `20200101T000000Z`.

The five Wave 93 malformed-format fixtures remain and continue to require the
earlier structural diagnostic, proving that the new equality check did not
replace or weaken that validator.

## Validation

```text
bash scripts/compare-pos-release-builds.selftest.sh
# compare-pos-release-builds selftest: PASS

bash -n scripts/compare-pos-release-builds.sh
bash -n scripts/compare-pos-release-builds.selftest.sh
# passed
```

## Residual boundary

This proves only that supplied local metadata uses the snapshot identity
reviewed in the current canonical Dockerfile. It does not prove that
snapshot.debian.org was contacted, that installed packages or toolchain bytes
correspond to the pin, that the Docker build argument executed, or that a
candidate came from the reviewed builder. Builder provenance and independence,
hosted CI, signing, publication, approval, rollback and fleet rollout remain
external release gates. INF-01 remains `PARTIAL`.
