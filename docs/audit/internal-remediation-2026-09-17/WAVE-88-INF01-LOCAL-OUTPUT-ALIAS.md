# Wave 88 — INF-01 local release-output alias refusal

Date: 2026-09-19
Comparison base: `cc966a8`

## Reproduced gap

`compare-pos-release-builds.sh` already refused the same resolved directory,
but accepted two distinct directories when their `bloch-pos`, `SHA256SUMS` and
`BUILD-INFO` entries were hardlinks to the same three filesystem objects. The
complete comparator returned:

```text
compare-pos-release-builds: PASS — distinct supplied outputs are byte-identical
builder independence still requires separately authenticated build records
```

Bash `test file-a -ef file-b` confirmed identical device/inode identity for
all three pairs. A parallel directory containing symlinked artifacts was also
accepted because `-f` follows symlinks. This does not forge bytes, but it lets
one local artifact tree be presented twice where the comparator claims two
distinct supplied outputs.

## Fail-closed correction

For each of the three canonical files, the comparator now requires a regular
non-symlink entry. After resolving and distinguishing the two input
directories, it also refuses each A/B file pair when Bash `-ef` says both
paths name the same filesystem object. Byte, checksum, metadata and unsigned
candidate checks remain unchanged.

Normal independently materialized or copied artifact directories remain
accepted. A storage layer that deduplicates exports as hardlinks must
materialize separate files before this local comparison.

## Adversarial coverage

The selftest keeps the existing copied-directory success and same-directory
refusal. It now pins the latter's diagnostic and independently replaces each
of `bloch-pos`, `SHA256SUMS` and `BUILD-INFO` with:

- a hardlink to builder A, requiring the exact same-object diagnostic; and
- a symlink to builder A, requiring the exact non-symlink diagnostic.

The pre-existing non-executable binary, byte tamper, provenance mismatch,
duplicate authorization field and unsupported metadata cases remain covered.

## Validation

```text
bash -n scripts/compare-pos-release-builds.sh \
  scripts/compare-pos-release-builds.selftest.sh
# passed

bash scripts/compare-pos-release-builds.selftest.sh
# compare-pos-release-builds selftest: PASS

git diff --check -- <Wave 88 INF-01 files>
# passed
```

## Residual boundary

This proves only that two local inputs do not use symlinks or the same
filesystem object for their three reviewed files. Different copies can still
originate from one build, and distinct filesystems can hide shared backing
storage. The check does not authenticate a builder, prove independent build
execution, establish tool/image provenance, sign or publish an artifact,
authorize deployment, exercise rollback, or qualify a fleet. Those remain
external INF-01 release gates.
