# Wave 75 — INF-11 GitLab execution-environment boundary

Date: 2026-09-19  
Starting point: `708aa80`  
Scope: checked-in GitLab inherited execution context; no claim about runner,
tool, interpreter, package, or hosted-service provenance.

## Residual reproduced

The protected GitLab `default.before_script` prepended the expected Cargo
directory to the runner's existing `PATH`:

```text
export PATH="$HOME/.cargo/bin:$PATH"
```

Consequently, every inherited suffix selected by the runner remained eligible
to provide Bash, Python, Cargo's native dependencies, and other commands. The
same context also retained ambient variables that can redirect shell startup,
Python startup, Rustup's selected toolchain and home, Cargo's home, or Cargo's
Rust compiler and wrappers. The guards required that permissive line exactly,
so this was a checked-in contract gap rather than merely an undocumented host
assumption.

## Remediation

The inherited GitLab setup now:

1. unsets `BASH_ENV`, `ENV`, `PYTHONHOME`, `PYTHONPATH`, `CARGO_HOME`,
   `RUSTUP_HOME`, `RUSTUP_TOOLCHAIN`, `RUSTC`, the direct Rust wrappers, and
   the equivalent `CARGO_BUILD_*` compiler-wrapper variables;
2. replaces, rather than extends, inherited `PATH` with the reviewed
   `$HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin` search set; and
3. retains the existing fail-fast Rust/C/Make version probes.

Both blocking-posture guards require the same exact inherited context. Any
removed unset, reordered entry, appended inherited path, or additional command
therefore fails closed until explicitly reviewed in both contracts.

This preserves the current GitLab job semantics: Cargo/Rustup still use the
runner account's conventional Cargo directory, and ordinary system tools still
resolve from the conventional local/system directories. It removes ambient
runner-selected suffixes and common startup/compiler substitution channels
from the checked-in execution contract.

## Bidirectional adversarial evidence

Positive fixtures in both guard suites accept the new exact environment.
Negative fixtures prove rejection when:

- the inherited `$PATH` suffix is restored;
- `RUSTUP_TOOLCHAIN` is allowed to survive;
- Python startup variables are allowed to survive; or
- another command is appended to the protected `before_script`.

The test-posture selftest now covers 93 cases. The scanner-posture selftest now
covers 76 cases. The SHA-256-protected test-posture selftest digest was updated
to its reviewed new bytes.

## Local verification

Run from the repository root:

```text
python3 -I scripts/check-tests-blocking.selftest.py
python3 -I scripts/check-tests-blocking.py
python3 -I scripts/check-scanners-blocking.selftest.py
python3 -I scripts/check-scanners-blocking.py
python3 -I -m py_compile scripts/check-tests-blocking.py scripts/check-tests-blocking.selftest.py scripts/check-scanners-blocking.py scripts/check-scanners-blocking.selftest.py
git diff --check -- .gitlab-ci.yml scripts/check-tests-blocking.py scripts/check-tests-blocking.selftest.py scripts/check-scanners-blocking.py scripts/check-scanners-blocking.selftest.py docs/audit/internal-remediation-2026-09-17/WAVE-75-INF11-GITLAB-EXECUTION-ENVIRONMENT.md
```

Observed locally:

- test-posture selftest: 93 cases passed;
- test-posture guard: both checked-in pipelines passed;
- scanner-posture selftest: 76 cases passed in both directions;
- scanner-posture guard: 8 GitLab and 8 GitHub jobs passed;
- Python compilation and scoped diff check: passed.

## External residuals

INF-11 remains `PARTIAL`. The fixed search directories, `$HOME`, executable
bytes, dynamic libraries, installed Rust toolchain and packages, runner image,
kernel, hardware, hosted job execution, repository rulesets and required-check
settings remain external state. This change narrows which ambient channels may
select tools; it does not attest the provenance or behavior of the tools that
the runner supplies.
