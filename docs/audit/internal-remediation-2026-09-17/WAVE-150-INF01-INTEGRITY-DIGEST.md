# Wave 150 — INF-01 release-integrity digest contract

Date: 2026-09-19
Branch: `fix/internal-audit-20260917`
Comparison base: `a58e2ad2`

## Reproduced gap

The same-path release-integrity guard compared the unvalidated first fields
returned by its SHA-256 command. A hermetic full-mode fixture made both builds
byte-identical but placed a shim first on `PATH` that returned
`not-a-sha256` for every file. The real guard exited zero and reported both
`determinism: ok` and `pos-release-integrity: PASS`, including the malformed
string as its reference hash.

## Correction

Each build digest now passes through one fail-closed validator before the two
values can be compared or reported. The checksum command must succeed, and its
extracted output must be exactly 64 lowercase ASCII hexadecimal characters.
The existing lockfile, clean tracked source, build override, pinned compiler,
double-build, commit stamp and post-build lock drift flow is unchanged.

The selftest adds a full-mode fixture with fake Cargo builds, compiler identity
and executable version output. Its canonical SHA mode delegates to the host
implementation by absolute path. Separate cases prove rejection of checksum
tool failure, short, nonhexadecimal, uppercase and multiple-row output before
the guard can claim determinism. The prior lock/layout, source cleanliness,
environment override and source-level drift matrix remains intact.

## Local validation

- `bash -n scripts/pos-release-integrity.sh`
- `python3 -m py_compile scripts/pos-release-integrity.selftest.py`
- `python3 scripts/pos-release-integrity.selftest.py`
- `git diff --check -- scripts/pos-release-integrity.sh scripts/pos-release-integrity.selftest.py docs/audit/internal-remediation-2026-09-17/WAVE-150-INF01-INTEGRITY-DIGEST.md`

## Boundary and residuals

This proves fail-closed local digest shape and coherence for the guard's two
same-path outputs. It does not authenticate the checksum executable, compiler,
runner, source host or builder, and it does not turn same-path determinism into
an independently authenticated canonical-container comparison. Signing,
publication, hosted-CI enforcement, independent approval, rollback rehearsal,
canary rollout and fleet evidence remain external launch gates. INF-01 remains
`PARTIAL`.
