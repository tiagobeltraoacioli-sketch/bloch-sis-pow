# Wave 76 — INF-11 GitHub run-step environment boundary

Date: 2026-09-19
Starting point: `5580070`
Scope: checked-in GitHub Actions `run:` process environment; no claim about
action, executable, toolchain, package, runner-image, or hosted provenance.

## Residual reproduced

The test and security workflows constrained top-level YAML environment keys
and rejected job/step-local overrides, but their reviewed commands still
started through the hosted runner's default shell and inherited process
environment. An ambient `BASH_ENV`, Python startup path, Rust compiler/wrapper
variable, Cargo compiler override, or runner `PATH` suffix could therefore
change an otherwise byte-identical reviewed command.

The guards expressly rejected all top-level `defaults:`, so they also prevented
checking in a common environment-clearing shell contract.

## Remediation

Both GitHub workflows now have one exact global `defaults.run.shell` contract.
It executes every `run:` script through `/usr/bin/env`, removes:

- `BASH_ENV`, `ENV`, `PYTHONHOME`, and `PYTHONPATH`;
- `CARGO_HOME`, `RUSTUP_HOME`, and `RUSTUP_TOOLCHAIN`;
- `RUSTFLAGS`, `CARGO_ENCODED_RUSTFLAGS`, `RUSTC`, both Rust compiler-wrapper
  variables, and the corresponding `CARGO_BUILD_*` flags/compiler/wrappers;

then replaces inherited `PATH` with:

```text
/home/runner/.cargo/bin:/home/runner/.local/bin:/usr/local/bin:/usr/bin:/bin
```

Finally it starts `/bin/bash --noprofile --norc -euo pipefail {0}`. The fixed
path retains the conventional Rustup/Cargo shim directory and the workflow's
reviewed local scanner-install directory while excluding any inherited path
suffix. Disabling Bash profiles closes an additional startup-code channel.

Both posture guards require this global block exactly once and byte-for-byte
after YAML whitespace normalization. They continue to reject job- or
step-local `shell`, `defaults`, `env`, container, and service contexts.

## Bidirectional adversarial evidence

Positive fixtures in both guard suites accept the reviewed clearing shell.
Negative fixtures independently prove that each guard rejects:

1. removal of `-u RUSTC`, which would restore an ambient compiler-selection
   channel; and
2. replacement of the closed `PATH` with a value containing inherited
   `$PATH`.

The test-posture selftest now covers 96 cases. The scanner-posture selftest now
covers 79 cases. The SHA-256-protected test-posture selftest digest was updated
to its reviewed new bytes.

## Local verification

Run from the repository root:

```text
python3 -I scripts/check-tests-blocking.selftest.py
python3 -I scripts/check-scanners-blocking.selftest.py
python3 -I scripts/check-tests-blocking.py
python3 -I scripts/check-scanners-blocking.py
python3 -I -m py_compile scripts/check-tests-blocking.py scripts/check-tests-blocking.selftest.py scripts/check-scanners-blocking.py scripts/check-scanners-blocking.selftest.py
git diff --check
```

Observed locally:

- test-posture selftest: 96 cases passed;
- scanner-posture selftest: 79 cases passed in both directions;
- real test-posture and scanner-posture guards: passed;
- Python compilation and diff check: passed.

## External residuals

INF-11 remains `PARTIAL`. GitHub `uses:` actions execute outside
`defaults.run.shell`; their commits and allowed inputs remain structurally
pinned, but their bytes and transitive runtimes are not attested here. The
fixed directories, `HOME`, Bash, Python, Cargo, Rustup, Rust compiler,
scanners, dynamic libraries, runner image, kernel, hardware, hosted execution,
repository rulesets, release state, and deployment state remain external.
This change constrains selection channels for checked-in `run:` commands; it
does not establish tool-byte or hosted-service provenance.
