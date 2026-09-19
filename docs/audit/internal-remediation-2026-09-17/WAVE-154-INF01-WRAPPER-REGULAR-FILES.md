# Wave 154 — INF-01 canonical wrapper regular-file contract

Date: 2026-09-19
Branch: `fix/internal-audit-20260917`
Comparison base: `1d6a6bf5`

## Reproduced gap

The canonical-container wrapper consumed and published exported symlinks. A
fake engine moved `bloch-pos` into the wrapper's private source context and
placed an absolute symlink at the expected export path, while emitting a valid
manifest and canonical `BUILD-INFO`. The real wrapper verified the target and
reported `PASS`; cleanup then removed the private context, leaving the retained
candidate's `bloch-pos` symlink dangling.

The same type ambiguity applied to `SHA256SUMS` and `BUILD-INFO`: their readers
followed links without requiring self-contained regular export files.

## Correction

Before consuming any exported byte, the wrapper now requires each of
`bloch-pos`, `SHA256SUMS` and `BUILD-INFO` to be a regular, non-symlink file.
The existing executable check, exact digest contract, manifest verification,
canonical metadata, captured-source and publication flow remain unchanged.

The fake engine can independently move each otherwise valid artifact into the
private context and leave a symlink in its place. All three cases must fail
with the artifact-specific regular-file diagnostic and no published output.
The canonical case and the complete prior adversarial matrix remain green.

## Local validation

- `bash -n scripts/build-pos-release-container.sh`
- `bash -n scripts/build-pos-release-container.selftest.sh`
- `bash scripts/build-pos-release-container.selftest.sh`
- `git diff --check -- scripts/build-pos-release-container.sh scripts/build-pos-release-container.selftest.sh docs/audit/internal-remediation-2026-09-17/WAVE-154-INF01-WRAPPER-REGULAR-FILES.md`

## Boundary and residuals

This proves the three retained exports are regular non-symlink files at the
local preflight. It does not authenticate the container engine or filesystem,
exclude hard-link/bind-mount aliasing, or prevent an owning/background process
from mutating files after the check. It also does not establish hosted-CI,
independent-build, signing, publication, rollback, canary or fleet evidence.
INF-01 remains `PARTIAL` and all external launch gates remain mandatory.
