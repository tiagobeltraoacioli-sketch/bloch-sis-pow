# Wave 174 — INF-01 integrity double-build output aliases

Date: 2026-09-19
Branch: `fix/internal-audit-20260917`
Comparison base: `3596a546`

## Reproduced gap

The legacy same-path integrity gate hashed two Cargo output paths but did not
require them to be self-contained files. A hermetic fake Cargo made both
paths symlinks to one external executable. The real guard observed equal
hashes, printed `determinism: ok`, executed the shared target and reported
`PASS`; no second output identity had actually been established.

## Correction

After both builds and before hashing or execution, the guard now requires
each `release/bloch-pos` output to be a regular non-symlink file with exactly
one hard link. The fixed-byte, `pipefail`-protected `find` check
matches the local wrapper/comparator hard-link contract and fails closed on an
unsupported/erroring observation.

The full-mode selftest can independently replace build 1 or build 2 with a
symlink or hardlink to its external fake executable. All four cases require a
build-specific diagnostic before the determinism claim. Canonical copied
outputs and the prior digest/lock/source/environment matrix remain green.

## Local validation

- `bash -n scripts/pos-release-integrity.sh`
- `python3 -m py_compile scripts/pos-release-integrity.selftest.py`
- `python3 -I scripts/pos-release-integrity.selftest.py`
- `git diff --check -- scripts/pos-release-integrity.sh scripts/pos-release-integrity.selftest.py docs/audit/internal-remediation-2026-09-17/WAVE-174-INF01-INTEGRITY-BINARY-ALIASES.md`

## Boundary and residuals

This proves only the local filesystem type and ordinary hard-link count
observed before hashing. It does not detect bind mounts or aliases
that do not increment that count, authenticate Cargo/compiler/PATH or the
filesystem, cover ACLs/xattrs/mount policy, prevent concurrent namespace/
link-count changes or later byte mutation, or turn two same-host builds into
independent builder evidence. The existing clean-source preflight race also
remains.
Hosted CI, independent builders, signing, publication, rollback, canary and
fleet evidence remain external launch gates. INF-01 remains `PARTIAL`.
