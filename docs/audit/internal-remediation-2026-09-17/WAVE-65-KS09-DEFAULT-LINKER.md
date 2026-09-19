# Wave 65 KS-09: observed platform-default linker fingerprint

Date: 2026-09-18. Base: `6e3328d`. Scope: build identity and parser
regressions. No consensus, wire, persistent format, release artifact or
deployed node changed.

## Correction

Wave 64 bound linkers explicitly selected in effective Cargo/Rust flags. An
ordinary native build usually selects no linker variable or flag at all, so
the platform default remained outside the build-environment digest.

When no explicit linker is configured, the build script now asks the selected
rustc to link a minimal target binary in Cargo's private `OUT_DIR` with
`--print link-args`. It parses either a direct linker command or rustc's
`env`-wrapped form, removes the exact probe source/output immediately and
fingerprints the resolved linker executable. The file becomes an incremental-
build dependency; its path and individual digest are not published.

Unknown `env` options, malformed command output, cross-target link failure or
an unresolvable executable produce an unavailable component rather than a
guessed conventional `cc` path. Explicit linker selection skips the default
probe because that selected binary is already handled by the configured-tool
or Rust-flags path. Buildinfo exposes only a zero/one
`build_default_linker_binaries_hashed` counter.

## Validation

- `cargo test -p bloch-pos-node --test build_command_parser --offline`: all 4
  parser/linker tests passed.
- `cargo test -p bloch-pos-node getbuildinfo_carries_a_bounded_build_environment_fingerprint --offline`:
  the native workspace build reported exactly one observed default linker.
- The Wave 65 integration checkpoint records the broad node suite.
- `git diff --check` passes.

## Residual boundary

KS-09 remains `PARTIAL`. Cross targets whose linker cannot execute during the
probe report zero, and an explicit wrapper with an unsupported option grammar
may still bind only its direct boundary. SDK/native libraries, operating-
system inputs and undeclared tools remain outside the digest. Independently
authenticated hermetic builds, binary comparison and signed provenance remain
release gates.
