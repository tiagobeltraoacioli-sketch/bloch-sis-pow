# Wave 89 — INF-01 exact local release-output tree

Date: 2026-09-19
Comparison base: `7e1b605`

## Reproduced gap

The release comparator required and validated `bloch-pos`, `SHA256SUMS` and
`BUILD-INFO`, but ignored every other entry in each supplied output directory.
Adding an executable `install.sh` to builder A and copying that complete tree
to builder B still returned:

```text
compare-pos-release-builds: PASS — distinct supplied outputs are byte-identical
builder independence still requires separately authenticated build records
```

The canonical Docker export produces only the three reviewed files. Accepting
additional scripts, hidden files or directories meant the comparator's local
success did not describe the complete candidate tree it was given.

## Fail-closed correction

After separately requiring all three canonical names as regular non-symlink
files, the comparator now requires exactly three top-level directory entries.
It counts a fixed one-byte sentinel emitted once per `find` result rather than
counting printed path lines. Newlines or other display-sensitive bytes in a
filename therefore cannot reduce or confuse the entry count.

Because the required-name checks remain independent, cardinality three means
the complete top-level set is exactly `bloch-pos`, `SHA256SUMS` and
`BUILD-INFO`. The Docker export and ordinary copied fixtures remain unchanged.
A later signed bundle may contain signatures or documentation, but it must be
a separate packaging layer rather than masquerading as this canonical
unsigned container candidate.

## Adversarial coverage

The comparator selftest retains the canonical copied-directory success and all
prior same-directory, hardlink, symlink, permission, byte and metadata
refusals. Four new independent fixtures add one top-level entry to an otherwise
valid copied candidate:

- an executable regular file;
- a dotfile;
- a subdirectory; and
- a regular file whose name contains a newline.

Each must fail with the exact canonical-tree diagnostic and an observed count
of four.

## Validation

```text
bash -n scripts/compare-pos-release-builds.sh \
  scripts/compare-pos-release-builds.selftest.sh
# passed

bash scripts/compare-pos-release-builds.selftest.sh
# compare-pos-release-builds selftest: PASS

git diff --check -- <Wave 89 INF-01 files>
# passed
```

## Residual boundary

This is only a local structural proof for the three-file unsigned candidate.
Different files can still originate from one build, and distinct filesystems
can hide shared backing storage. The check does not authenticate a builder,
prove independent build execution, establish tool/image provenance, sign or
publish an artifact, authorize deployment, exercise rollback, or qualify a
fleet. Those external INF-01 release gates remain mandatory.
