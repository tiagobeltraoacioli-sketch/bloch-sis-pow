# Wave 170 — INF-01 comparator hard-link aliases

Date: 2026-09-19
Branch: `fix/internal-audit-20260917`
Comparison base: `9d8c0ed4`

## Reproduced gap

The release comparator rejected symlinks and corresponding artifacts that
were the same filesystem object across builder directories, but it accepted a
builder artifact hardlinked to a third path outside both supplied trees. A
canonical A/B fixture with an external hardlink to A's `bloch-pos` passed the
real comparator while the observed link count was two.

## Correction

Before reading artifacts from each supplied builder directory, the comparator
now requires each `bloch-pos`, `SHA256SUMS` and `BUILD-INFO` in that directory
to have exactly one hard link. It uses the same fixed-byte, `pipefail`-protected,
portable `find` contract as the canonical wrapper. The existing cross-builder
directory and `-ef` identity checks remain additional defenses.

Independent adversarial fixtures give each artifact in one otherwise
canonical builder tree a third external alias while the other builder remains
a distinct copy. Existing A/B same-object fixtures now also fail at the
earlier link-count preflight. Every case requires a path-specific diagnostic;
the canonical copy remains green. The harness fixes its own umask and
explicitly normalizes canonical metadata modes so caller policy cannot mask a
fixture's intended failure.

## Local validation

- `bash -n scripts/compare-pos-release-builds.sh`
- `bash -n scripts/compare-pos-release-builds.selftest.sh`
- `bash scripts/compare-pos-release-builds.selftest.sh`
- `bash -c 'umask 000; bash scripts/compare-pos-release-builds.selftest.sh'`
- `git diff --check -- scripts/compare-pos-release-builds.sh scripts/compare-pos-release-builds.selftest.sh docs/audit/internal-remediation-2026-09-17/WAVE-170-INF01-COMPARATOR-HARDLINKS.md`

## Boundary and residuals

This proves only a local preflight observation of ordinary filesystem
hard-link count for the supplied trees. It does not detect bind mounts or
aliases that do not increment that count, authenticate the builders,
filesystem, owner or group, cover ACLs/xattrs/mount policy, prevent concurrent
namespace/link-count changes or later byte mutation, or establish that A and B were
independently built. Hosted CI, signing, publication, rollback, canary and
fleet evidence remain external launch gates. INF-01 remains `PARTIAL`.
