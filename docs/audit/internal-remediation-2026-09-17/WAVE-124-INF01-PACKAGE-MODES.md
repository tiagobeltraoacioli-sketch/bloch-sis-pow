# Wave 124 — INF-01 package output modes

Date: 2026-09-19
Comparison base: `7f324e3`

## Reproduced gap

The unsigned candidate packager normalized only the executable. Its output
directory and two metadata files inherited the caller's `umask`. Under
`umask 000` the command still reported success but published a mode-0777
directory and mode-0666 `SHA256SUMS` and `BUILD-INFO`, leaving the retained
candidate writable by group and other users.

## Correction

After all output bytes are complete and before publication, the packager now
sets the candidate directory and `bloch-pos` to mode 0755 and both metadata
files to mode 0644. This preserves binary execution and ordinary artifact
readability while removing dependence on a permissive caller umask.

## Adversarial coverage

The hermetic selftest runs a complete canonical package under `umask 000`. It
requires exact mode 0755 on the output directory and binary, exact mode 0644 on
both metadata files, readability of the metadata and executability of the
binary. The complete source, version, target, digest and pin matrix remains
active.

## Validation

```text
bash scripts/package-pos-release-candidate.selftest.sh
# package-pos-release-candidate selftest: PASS

bash -n scripts/package-pos-release-candidate.sh
bash -n scripts/package-pos-release-candidate.selftest.sh
# passed
```

## Residual boundary

This controls basic POSIX mode bits only. It does not authenticate owner or
group, inspect ACLs or extended attributes, constrain mount policy or the
parent directory, or prevent mutation by the owning runner. Signing,
publication, independent canonical builds and comparison, approval, rollback
rehearsal, staged canary and fleet evidence remain external release gates.
INF-01 remains `PARTIAL`.
