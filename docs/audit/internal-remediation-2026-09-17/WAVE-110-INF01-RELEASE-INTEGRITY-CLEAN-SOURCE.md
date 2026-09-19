# Wave 110 — INF-01 release-integrity clean source

Date: 2026-09-19
Comparison base: `e22cdee`

## Reproduced gap

The release-integrity guard checked only whether the committed root lockfile
had drifted. Other tracked worktree or index changes remained build inputs,
while both resulting binaries were stamped with the current `HEAD`. Two
identical builds of the same local edit could therefore pass the same-path
determinism check and be reported as bytes of a Git object that did not contain
that edit.

## Correction

After the existing lockfile-only mode has returned, and before the toolchain or
either build is selected, the full guard now fails separately on tracked
unstaged changes and staged changes. Untracked CI output remains allowed, and
`--locks-only` retains its deliberately narrow lock/layout contract.

## Adversarial coverage

The existing synthetic-workspace selftest now proves that a tracked node source
edit is refused both unstaged and staged. A positive-boundary fixture adds an
untracked output file and proves the guard passes the new checks, reaching the
fixture's intentionally missing toolchain-pin error. The full prior lockfile,
workspace-layout and environment-override matrix remains active.

## Validation

```text
python3 scripts/pos-release-integrity.selftest.py
# pos-release-integrity.selftest: PASS

bash -n scripts/pos-release-integrity.sh
python3 -m py_compile scripts/pos-release-integrity.selftest.py
# passed
```

## Residual boundary

This closes only tracked edits already present at the preflight. A concurrent
mutation after those checks remains possible because the legacy same-path
guard does not build from an immutable archive. Untracked files may still
affect tools that discover them, and Git objects, toolchain, dependencies,
runner and compiler remain unauthenticated. Canonical independent builds,
comparison, hosted CI, signing, publication, approval, rollback rehearsal,
staged canary and fleet evidence remain external gates. INF-01 remains
`PARTIAL`.
