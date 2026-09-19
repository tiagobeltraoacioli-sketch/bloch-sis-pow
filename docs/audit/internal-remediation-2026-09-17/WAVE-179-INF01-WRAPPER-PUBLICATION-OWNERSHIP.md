# Wave 179 — INF-01 canonical wrapper publication ownership

Date: 2026-09-19
Branch: `fix/internal-audit-20260917`
Comparison base: `1a4d4307`

## Reproduced gap

The canonical wrapper checked that its output path did not exist before the
container build, then published much later with `mv stage out_dir`. A fake
engine created `out_dir` between those operations. Portable `mv` treated that
new directory as a destination container, nested the validated stage at
`out_dir/output`, and returned success. The wrapper printed `PASS` even though
`out_dir/bloch-pos` did not exist; the binary was only present one level down.

## Correction

Before inspecting any children, the wrapper requires the export root itself to
be a real non-symlink directory. After all artifact validation, it creates an
unpredictable ownership token inside that staged directory. After `mv`, it
again requires `out_dir` to be a real non-symlink directory and the token to
be its direct regular non-symlink child, removes the token, and only then
reports success. A destination created during the build causes the stage and
token to be nested, so the direct-token check fails closed instead of
misreporting publication. An engine that replaces the stage root with a
symlink is refused before child validation and cannot turn the post-move token
lookup into a symlink-following false proof.

The canonical regression requires exactly the original three final entries
and no retained publication token. A deterministic race fixture creates the
destination from the fake engine after the initial preflight, proves the
historical nested layout, and requires the new publication diagnostic without
a direct binary or `PASS`. An independent fixture replaces the export root
with a symlink, records that the replacement occurred, and requires the root
diagnostic, no output and no `PASS`. The existing tree/type/mode/link/digest/
metadata and captured-object matrix remains unchanged.

## Local validation

- `bash -n scripts/build-pos-release-container.sh`
- `bash -n scripts/build-pos-release-container.selftest.sh`
- `bash scripts/build-pos-release-container.selftest.sh`
- `bash -c 'umask 000; bash scripts/build-pos-release-container.selftest.sh'`
- `git diff --check -- scripts/build-pos-release-container.sh scripts/build-pos-release-container.selftest.sh docs/audit/internal-remediation-2026-09-17/WAVE-179-INF01-WRAPPER-PUBLICATION-OWNERSHIP.md`

## Boundary and residuals

This is a local ownership/postcondition check around portable `mv`; it is not
an atomic no-overwrite directory rename. A detected collision can leave the
owned stage nested under the raced directory because the wrapper cannot
safely remove a destination it did not create. Root checks reject observed
symlinks but do not make the check/use sequence atomic. The token narrows this
race but does not defeat a same-owner or privileged actor that can observe and
replace paths or token entries between checks, nor filesystem/mount aliasing,
ACL/xattr policy, power loss or mutation after the check. Hosted CI,
independent builders, signing, publication infrastructure, rollback, canary
and fleet evidence remain external launch gates. INF-01 remains `PARTIAL`.
