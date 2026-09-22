# Wave 166 — INF-01 canonical wrapper hard-link aliases

Date: 2026-09-19
Branch: `fix/internal-audit-20260917`
Comparison base: `7bfe20e1`

## Reproduced gap

The canonical-container wrapper required exactly three regular non-symlink
entries with safe basic write modes, but accepted an exported artifact that
was a hard link to an engine-controlled path outside the export directory.
A temporary fake engine hardlinked `bloch-pos` to its captured build context;
the real wrapper verified the bytes and metadata and reported `PASS`.

## Correction

Before consuming any exported bytes, the wrapper now requires each of
`bloch-pos`, `SHA256SUMS` and `BUILD-INFO` to have exactly one hard link.
The check uses the existing fixed-byte, `pipefail`-protected `find` pattern so
an unsupported/erroring observation cannot become a false zero. Independent
fixtures hardlink each artifact to an engine-controlled path and require the
artifact-specific failure without publishing an output directory.

The canonical fixture, including its permissive-umask run, and the complete
existing tree, type, mode, checksum, manifest, metadata and captured-object
matrix remain unchanged.

## Local validation

- `bash -n scripts/build-pos-release-container.sh`
- `bash -n scripts/build-pos-release-container.selftest.sh`
- `bash scripts/build-pos-release-container.selftest.sh`
- `bash -c 'umask 000; bash scripts/build-pos-release-container.selftest.sh'`
- `git diff --check -- scripts/build-pos-release-container.sh scripts/build-pos-release-container.selftest.sh docs/audit/internal-remediation-2026-09-17/WAVE-166-INF01-WRAPPER-HARDLINKS.md`

## Boundary and residuals

This is a local preflight observation of ordinary filesystem hard-link count.
It does not detect bind mounts or other aliasing that does not increment that
count, authenticate the engine/filesystem or owner, cover ACLs/xattrs/mount
policy, prevent a privileged actor from changing namespace relationships, or
prevent mutation after the last check. Hosted CI, independent builds, signing,
publication, rollback, canary and fleet evidence remain external launch gates.
INF-01 remains `PARTIAL`.
