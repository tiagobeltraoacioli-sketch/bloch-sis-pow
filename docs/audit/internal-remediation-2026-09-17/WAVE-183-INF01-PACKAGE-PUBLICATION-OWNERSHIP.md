# Wave 183 — INF-01 candidate-package publication ownership

Date: 2026-09-19
Branch: `fix/internal-audit-20260917`
Comparison base: `185f57e6`

## Reproduced gap

The unsigned candidate packager checked that its output path did not exist and
then published with portable `mv stage out_dir`. If another actor created
`out_dir` between those operations, `mv` treated it as a destination directory,
nested the candidate at `out_dir/stage`, returned success and let the packager
print `PASS` even though `out_dir/bloch-pos` did not exist.

## Correction

Immediately before publication, the packager requires its stage root to be a
real non-symlink directory and creates an unpredictable ownership token as a
direct child. After `mv`, it requires the output root to be a real non-symlink
directory and the same token to be its direct regular non-symlink child. The
token is removed before `PASS`.

The reproduced passive raced destination therefore nests the stage and token
and fails the direct token postcondition. A stage root replaced by a symlink
is refused before the token or publication. The canonical output retains only `bloch-pos`,
`SHA256SUMS` and `BUILD-INFO`; no ownership token remains.

## Adversarial coverage

The hermetic fake-toolchain selftest now proves:

- a destination created after the absence check makes the real portable `mv`
  produce the historical nested layout, but the packager returns nonzero with
  the publication diagnostic and without `PASS` or a direct binary;
- a deliberately substituted stage-root symlink is observed and refused
  before publication; and
- canonical publication succeeds with no retained token both normally and
  under `umask 000`, preserving the prior source, toolchain, version, digest,
  mode and metadata matrix.

## Local validation

- `bash -n scripts/package-pos-release-candidate.sh`
- `bash -n scripts/package-pos-release-candidate.selftest.sh`
- `bash scripts/package-pos-release-candidate.selftest.sh`
- `bash -c 'umask 000; bash scripts/package-pos-release-candidate.selftest.sh'`
- `git diff --check -- scripts/package-pos-release-candidate.sh scripts/package-pos-release-candidate.selftest.sh docs/audit/internal-remediation-2026-09-17/WAVE-183-INF01-PACKAGE-PUBLICATION-OWNERSHIP.md`

## Boundary and residuals

This is a local ownership/postcondition check around portable `mv`; it does not
make directory publication an atomic no-overwrite rename. A detected collision
can leave the owned stage nested under a destination the packager did not
create. Root checks reject observed symlinks but do not make the check/use
sequence atomic. The token does not defeat an actor able to mutate the output
parent or root between checks, including a same-owner or privileged actor, nor
filesystem/mount aliasing, ACL/xattr policy, mutation after the final check,
interruption or power loss. Hosted CI, independent builders, provenance,
signing, publication, independent approval, rollback rehearsal, canary and
fleet evidence remain external launch gates. `INF-01` remains `PARTIAL`.
