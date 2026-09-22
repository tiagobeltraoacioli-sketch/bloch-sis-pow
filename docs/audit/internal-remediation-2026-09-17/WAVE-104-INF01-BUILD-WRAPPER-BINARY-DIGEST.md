# Wave 104 — INF-01 build-wrapper binary digest

Date: 2026-09-19
Comparison base: `d669863`

## Reproduced gap

The canonical build wrapper computed the exported binary's SHA-256 and
required an exact one-line `SHA256SUMS`, but it did not compare that digest to
`BUILD-INFO.binary_sha256`. Replacing only the metadata value with sixty-four
zeros left the complete wrapper selftest green and produced a reported `PASS`
candidate whose two local hash declarations contradicted each other.

## Correction

The wrapper now reuses the SHA-256 already computed for the canonical manifest
and requires `BUILD-INFO` to contain exactly one `binary_sha256` field whose
complete value equals it. Missing, mismatching, empty or duplicate fields fail
with a specific binary-digest diagnostic. No second binary read or hash is
introduced.

All Wave 100–103 manifest, captured-context, unsigned-state and deployment-
authorization checks remain unchanged.

## Adversarial coverage

The real-wrapper/fake-engine selftest retains its canonical success and adds
two isolated rejection cases whose `SHA256SUMS` remains correct:

- the sole metadata digest is replaced with sixty-four zeros; and
- the correct digest is followed by a duplicate zero digest.

Both must fail with the binary-digest diagnostic. All earlier manifest,
metadata-state and moving-ref cases remain active.

## Validation

```text
bash scripts/build-pos-release-container.selftest.sh
# build-pos-release-container selftest: PASS

bash -n scripts/build-pos-release-container.sh
bash -n scripts/build-pos-release-container.selftest.sh
# passed
```

## Residual boundary

This proves only local consistency between the exported binary, its canonical
manifest and one metadata field returned by the selected engine. It does not
authenticate source, repository, engine, image, toolchain or builder, and it
does not claim complete wrapper validation of every other `BUILD-INFO` field.
Builder independence, hosted CI, signing, publication, independent approval,
rollback rehearsal, deployment and fleet evidence remain external gates.
INF-01 remains `PARTIAL`.
