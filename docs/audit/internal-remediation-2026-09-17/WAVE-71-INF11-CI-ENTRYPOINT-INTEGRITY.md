# Wave 71 — INF-11 local CI entrypoint integrity

Date: 2026-09-19  
Starting point: `7a85a56`  
Scope: local checked-in content only; no hosted CI, runner-integrity, ruleset,
release, or deployment claim.

## Residual reproduced

Waves 68–70 bound the GitHub and GitLab jobs to exact ordered command strings.
Those contracts did not bind the bytes behind a command such as
`python3 scripts/check-attested-ssh.py`. Replacing that tracked file with a
successful stub, removing it, or redirecting it through a symlink left the CI
YAML unchanged, so the structural test-posture guard still passed.

## Remediation

`scripts/check-tests-blocking.py` now derives every `python3` and `bash` local
entrypoint from the three exact contracts it already owns:

- GitHub `cargo-test` ordered run steps;
- GitHub `tests-blocking-guard` ordered run steps;
- GitLab `build-and-test` ordered script.

The derived set, excluding the checker itself, must exactly equal the digest
map. Every one of the eleven files must be a regular file, must neither be nor
traverse a symlink, and must match its reviewed SHA-256 content. Adding a new
script command without adding its digest, or leaving a stale digest after a
command is removed, fails closed.

The checker cannot embed its own digest because that would be
self-referential. The chain instead works in both directions: the exact CI job
runs `check-tests-blocking.selftest.py` before the checker; that selftest proves
the checker's negative behavior, while the checker pins the selftest's bytes.
Coordinated legitimate edits require explicit review of both sides.

## Adversarial evidence

The selftest now adds three filesystem fixtures on top of its 78 YAML cases:

1. an empty entrypoint root is rejected with named missing-file errors;
2. a successful two-line replacement for `check-attested-ssh.py` is rejected
   by digest;
3. a symlink at that path is rejected before its target content is read.

All ordinary fixtures also exercise the checked-in entrypoints through the
default real-file root, providing the positive direction. The guard exposes a
test-only/root-selection argument, but the exact CI command contracts forbid
using it in either checked-in pipeline.

## Local verification

Run from the repository root:

```text
python3 scripts/check-tests-blocking.selftest.py
python3 scripts/check-scanners-blocking.selftest.py
python3 scripts/check-tests-blocking.py
python3 scripts/check-scanners-blocking.py
python3 -m py_compile scripts/check-tests-blocking.py scripts/check-tests-blocking.selftest.py
git diff --check -- scripts/check-tests-blocking.py scripts/check-tests-blocking.selftest.py docs/audit/internal-remediation-2026-09-17/WAVE-71-INF11-CI-ENTRYPOINT-INTEGRITY.md
```

Observed locally:

- test-posture selftest: 81 cases passed;
- scanner-posture selftest: 74 cases passed;
- real test guard: passed, covering eight live crates on both pipelines;
- real scanner guard: passed, with eight required jobs on each pipeline;
- Python compilation and scoped diff check: passed.

## Remaining boundary

This proves local bytes and paths for the script entrypoints at guard runtime.
It does not attest the `python3`, `bash`, `cargo`, `rustup`, package-manager, or
runner binaries; prove execution on a hosted service; establish repository
rulesets; or validate release/deployment behavior. A reviewer must update the
digest intentionally whenever a protected script legitimately changes.
