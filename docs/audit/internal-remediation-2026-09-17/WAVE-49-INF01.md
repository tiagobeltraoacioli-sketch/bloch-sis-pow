# Wave 49 INF-01: canonical release-container candidate

Date: 2026-09-18. Starting point: `1acd578`. Scope: repository-owned release
build recipe, independent-output comparison, CI self-test and documentation.
No binary was built on Linux, signed, published, approved or deployed.

## Repository gap

The release runbook correctly required a canonical container with source at
`/build`, but explicitly recorded that no such `bloch-pos` container existed.
The retained GitLab artifact was a traceable native-host candidate, not the
publishable reference build. Absolute manifest paths affect Rust symbol
metadata, so builds from arbitrary host paths cannot supply the reference
hash even when their source is identical.

## Candidate recipe

`deploy/pos-release/Dockerfile` now defines a binary-only export stage with:

- the Rust builder image pinned by digest;
- `/build` as the invariant source path;
- a fixed Debian snapshot for the native C/C++ toolchain;
- the checked-in root lockfile and pinned Rust compiler check;
- `BLOCH_BUILD_COMMIT` and the commit timestamp as `SOURCE_DATE_EPOCH`; and
- `BUILD-INFO` that explicitly says `signed=false` and
  `deployment_authorized=false`.

`scripts/build-pos-release-container.sh` creates the context with
`git archive HEAD`, not by copying the worktree. Untracked files, credentials, local Cargo
configuration and concurrent edits therefore cannot enter the context. It
requires Docker Buildx, verifies the exported checksum and provenance, and
refuses to replace an existing output directory.

`scripts/compare-pos-release-builds.sh` accepts two independently transported
output directories only when each checksum is internally valid, the binary
bytes are identical, and commit, commit timestamp, Debian snapshot, target and
binary digest agree. It requires exactly one value for each metadata field and
never upgrades the artifacts' unsigned or unauthorized markers. The
adversarial self-test proves changed binary bytes, changed provenance and a
duplicate authorization field are refused, and now runs in the blocking
GitLab release-integrity job.

## Status and release boundary

INF-01 remains `PARTIAL`. This worktree had no Docker/BuildKit engine, so the
canonical Linux build itself was not executed. Before describing a binary as
ready to launch, two independent Linux builders must build the same reviewed
commit and retain a passing comparator record. The resulting bytes must then
pass the remaining release checklist: full hosted CI, signatures, independent
approval, fresh weak-subjectivity artifacts, rollback rehearsal, staged
rollout and fleet `/proc` digest verification.

## Validation

- `bash -n` passed for all three release-container scripts.
- `bash scripts/compare-pos-release-builds.selftest.sh` passed its honest,
  tampered-binary, mismatched-provenance and duplicate-field cases.
- `git diff --check` passed.
- `docker buildx version` returned command-not-found; no container build or
  reproducibility claim is made.
