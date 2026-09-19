# Wave 108 — INF-01 package source snapshot

Date: 2026-09-19
Comparison base: `848ccd3`

## Reproduced gap

The unsigned release-candidate packager captured `HEAD` and checked that the
tracked worktree and index were clean, but Cargo then read that mutable
worktree directly. A tracked edit or branch advance after the preflight could
therefore enter the binary while `BUILD-INFO` still named the earlier commit
and asserted `tracked_tree_clean=true`. A final cleanliness check would not
close a transient edit that was restored before the check.

## Correction

After the existing commit capture and clean checks, the packager now
materializes `git archive <captured-oid>` into a temporary source directory.
It reads the Rust pin from that snapshot and runs both Rust compiler queries
and Cargo with the snapshot as their current working directory. This binds
source files, the toolchain declaration and archived Cargo configuration to
one immutable Git object while preserving the CI commit check, build-override
refusals and existing unsigned-candidate metadata.

## Adversarial coverage

The hermetic selftest uses a temporary Git repository and fake Rust/Cargo
tools. Its Git shim advances `HEAD`, changes a tracked source marker, a config
marker and the Rust pin only when the packager requests the archive. The
resulting candidate must contain the earlier source/config/pin and earlier
full OID. A following clean build must contain the later revision. A tracked
edit present before invocation remains refused.

## Validation

```text
bash scripts/package-pos-release-candidate.selftest.sh
# package-pos-release-candidate selftest: PASS

bash -n scripts/package-pos-release-candidate.sh
bash -n scripts/package-pos-release-candidate.selftest.sh
# passed
```

## Residual boundary

This proves local source/config/toolchain-pin selection by a supplied Git OID.
It does not authenticate the repository, Git objects, Rust/Cargo executables,
registry dependencies, compiler, linker, runner or resulting binary, and it
does not make this explicitly unsigned, noncanonical candidate deployable.
Independent canonical builds and comparison, hosted CI, signing, publication,
approval, rollback rehearsal, staged canary and fleet evidence remain external
release gates. INF-01 remains `PARTIAL`.
