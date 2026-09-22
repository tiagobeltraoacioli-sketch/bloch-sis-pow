# Wave 158 — INF-01 canonical wrapper exact export tree

Date: 2026-09-19
Branch: `fix/internal-audit-20260917`
Comparison base: `f4e6d45e`

## Reproduced gap

The canonical-container wrapper required and validated its three named files
but published every other top-level entry produced by the engine. A fake engine
emitted canonical regular `bloch-pos`, `SHA256SUMS` and `BUILD-INFO` files plus
an unexpected FIFO. The real wrapper verified the checksum and metadata,
reported `PASS`, and retained all four entries. The release comparator would
reject that wrapper output rather than recognizing it as a canonical candidate.

## Correction

Before consuming any exported file, the wrapper now requires exactly three
top-level entries. Its existing name and regular/non-symlink checks establish
that the complete set is exactly `bloch-pos`, `SHA256SUMS` and `BUILD-INFO`.
The count emits one fixed byte per entry through `find`, so whitespace and
newlines in engine-controlled names cannot undercount the tree; `pipefail`
keeps traversal failures fail-closed.

Independent fake-engine cases add an unexpected regular file, dotfile,
subdirectory and FIFO. Every case must report four entries and leave no
published output. The canonical path and the complete earlier digest,
symlink, manifest, metadata and captured-OID matrix remain green.

## Local validation

- `bash -n scripts/build-pos-release-container.sh`
- `bash -n scripts/build-pos-release-container.selftest.sh`
- `bash scripts/build-pos-release-container.selftest.sh`
- `git diff --check -- scripts/build-pos-release-container.sh scripts/build-pos-release-container.selftest.sh docs/audit/internal-remediation-2026-09-17/WAVE-158-INF01-WRAPPER-EXACT-TREE.md`

## Boundary and residuals

This proves the local top-level export snapshot contains only the three named
entries at preflight. It does not authenticate the engine or filesystem,
exclude hard-link/bind-mount aliasing, or prevent an owning/background process
from mutating the tree after the check. It also does not establish hosted-CI,
independent-build, signing, publication, rollback, canary or fleet evidence.
INF-01 remains `PARTIAL` and all external launch gates remain mandatory.
