# Wave 162 — INF-01 canonical wrapper export write modes

Date: 2026-09-19
Branch: `fix/internal-audit-20260917`
Comparison base: `9a9a20f8`

## Reproduced gap

The canonical-container wrapper required an executable regular `bloch-pos` and
regular metadata files, but did not reject group/other-writable exports. A fake
engine emitted otherwise canonical bytes and mode `0777` for `bloch-pos`. The
real wrapper verified the checksum and metadata, reported `PASS`, and retained
the unsafe mode. The release comparator would reject that wrapper output.

## Correction

Before consuming an export, the wrapper now uses the same portable POSIX-bit
contract as the comparator for each of `bloch-pos`, `SHA256SUMS` and
`BUILD-INFO`: neither group-write nor other-write may be set. Fixed-byte
`find` output and `pipefail` keep traversal errors and unusual names from
becoming a false zero count. The existing executable requirement for the
binary remains independent; owner-write is not prohibited.

The fake engine independently makes the executable mode `0777` and each
metadata file mode `0666`. All three cases must fail with an artifact-specific
diagnostic and leave no published output. The canonical case and the complete
earlier tree, type, digest, manifest, metadata and captured-OID matrix remain
green. The fake engine explicitly establishes canonical `0755`/`0644` modes,
and a dedicated canonical run under `umask 000` proves the fixtures do not
confuse ambient mode inheritance with an adversarial export.

## Local validation

- `bash -n scripts/build-pos-release-container.sh`
- `bash -n scripts/build-pos-release-container.selftest.sh`
- `bash scripts/build-pos-release-container.selftest.sh`
- `bash -c 'umask 000; bash scripts/build-pos-release-container.selftest.sh'`
- `git diff --check -- scripts/build-pos-release-container.sh scripts/build-pos-release-container.selftest.sh docs/audit/internal-remediation-2026-09-17/WAVE-162-INF01-WRAPPER-WRITE-MODES.md`

## Boundary and residuals

This proves only the basic group/other POSIX write bits observed at local
preflight. It does not authenticate owner/group, ACLs, xattrs, mount policy,
the engine or filesystem; exclude hard-link/bind-mount aliasing; guarantee
later mode preservation; or prevent an owning/background process from changing
bytes or modes after the check. Hosted CI, independent builds, signing,
publication, rollback, canary and fleet evidence remain external launch gates.
INF-01 remains `PARTIAL`.
