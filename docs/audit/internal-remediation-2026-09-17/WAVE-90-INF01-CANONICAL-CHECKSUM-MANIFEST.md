# Wave 90 — INF-01 canonical checksum-manifest bytes

Date: 2026-09-19
Comparison base: `ebf9db7`

## Reproduced gap

The release comparator extracted every `SHA256SUMS` row whose second field was
`bloch-pos` and compared the resulting hash to the binary. It did not bind the
rest of the manifest or compare the two builders' manifest bytes. With the
exact three-file candidate tree, builder A accepted:

```text
<correct sha256>  bloch-pos
# ignored builder-a payload
```

Builder B carried a different ignored comment. The complete comparator still
returned success and described the supplied outputs as byte-identical.

## Fail-closed correction

The comparator now checks that its checksum tool produced exactly 64 lowercase
hexadecimal characters and compares the complete `SHA256SUMS` bytes against:

```text
<lowercase 64-byte sha256>  bloch-pos\n
```

The comparison uses a generated stream with the final newline intact. It
therefore rejects comments, extra rows, blank lines, trailing bytes and a
missing final newline rather than normalizing them away. The independent
`BUILD-INFO` checksum binding and all byte/provenance checks remain unchanged.

The canonical Docker export already writes this exact one-line manifest, so
ordinary exported and copied candidates remain compatible.

## Adversarial coverage

The canonical copied-directory fixture remains green. Four otherwise valid
three-file candidates independently add or remove manifest bytes:

- an extra comment line;
- a final blank line;
- trailing non-newline bytes after the canonical row; and
- the canonical row without its final newline.

Each must fail with the exact canonical-manifest diagnostic. All prior
same-directory, alias, extra-tree, permission, binary and metadata mutations
remain covered.

## Validation

```text
bash -n scripts/compare-pos-release-builds.sh \
  scripts/compare-pos-release-builds.selftest.sh
# passed

bash scripts/compare-pos-release-builds.selftest.sh
# compare-pos-release-builds selftest: PASS

git diff --check -- <Wave 90 INF-01 files>
# passed
```

## Residual boundary

This proves only that each local unsigned candidate has one exact manifest
whose hash matches its local binary and `BUILD-INFO`. It does not authenticate
those bytes or a builder, prove independent builds, establish tool/image
provenance, sign or publish an artifact, authorize deployment, exercise
rollback, or qualify a fleet. Those external INF-01 release gates remain
mandatory.
