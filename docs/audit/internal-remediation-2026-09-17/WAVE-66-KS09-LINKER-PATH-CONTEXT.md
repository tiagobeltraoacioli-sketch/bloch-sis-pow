# Wave 66 KS-09: bind the observed linker's PATH context

Date: 2026-09-18. Base: `514ed42`. Scope: build-identity probe and parser
regressions. No consensus, wire, persistent format, release artifact or
deployed node changed.

## Correction

Wave 65 fingerprinted the platform-default linker reported by rustc. Rustc can
emit that command through `env PATH=... linker`; the parser found `linker`, but
the byte lookup still used the build script's inherited PATH. Two same-named
executables could therefore make the stamp describe a different linker from
the one rustc actually invoked.

The parser now returns both the command and its effective PATH override. The
fingerprint resolver uses that exact search path. PATH assignments follow
command order, so a later assignment restores a path cleared by `env -i` or
`env -u PATH`. A bare command with a cleared, unrestored PATH fails closed;
an explicit executable path remains resolvable because it needs no search.
Unknown `env` options remain unavailable rather than guessed.

## Validation

- `cargo test -p bloch-pos-node --test build_command_parser --offline`: all 4
  parser groups passed, including overridden, cleared, restored and explicit
  linker paths.
- `cargo test -p bloch-pos-node getbuildinfo_carries_a_bounded_build_environment_fingerprint --offline`:
  the native build still fingerprints exactly one observed default linker.
- The Wave 66 integration checkpoint records the broad node suite.
- `git diff --check` passes.

## Residual boundary

KS-09 remains `PARTIAL`. Cross targets whose linker cannot execute during the
probe report zero, and an explicit wrapper with unsupported option grammar may
still bind only its direct boundary. SDK/native libraries, operating-system
inputs and undeclared tools remain outside the digest. Independently
authenticated hermetic builds, binary comparison and signed provenance remain
release gates.
