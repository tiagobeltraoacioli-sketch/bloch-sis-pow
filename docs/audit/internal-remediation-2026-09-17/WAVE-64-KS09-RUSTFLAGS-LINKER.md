# Wave 64 KS-09: effective Rust-flags linker fingerprint

Date: 2026-09-18. Base: `97ceeaf`. Scope: build identity and parser
regressions. No consensus, wire, persistent format, release artifact or
deployed node changed.

## Correction

The build-environment digest already included the value of `RUSTFLAGS`,
`CARGO_BUILD_RUSTFLAGS` and Cargo's effective encoded Rust flags. A linker
selected inside those flags could nevertheless be replaced in place while its
path-valued field stayed unchanged.

The shared restricted parser now extracts rustc's `-Clinker=...` and
`-C linker=...` forms. It reads Cargo's unit-separator encoded representation
without shell interpretation and uses the last selection, matching rustc's
effective option precedence. When Cargo does not expose encoded flags it falls
back in order to `CARGO_BUILD_RUSTFLAGS` and `RUSTFLAGS`. A resolvable selected
linker's bytes receive their own domain-separated field inside the build-
environment digest and the file becomes an incremental-build dependency.

Empty, absent, malformed or unresolvable selections remain represented by the
existing environment field but do not inflate the component count. Paths and
individual digests remain unpublished; the existing configured-tool counter
includes the linker when it is successfully bound.

## Validation

- `cargo test -p bloch-pos-node --test build_command_parser --offline`: all 3
  parser/delegation/linker-selection tests passed.
- The Wave 64 integration checkpoint records the broad node suite.
- `git diff --check` passes.

## Residual boundary

KS-09 remains `PARTIAL`. A platform-default linker selected without an
explicit Cargo/rustc option remains outside this fingerprint, as do wrapper
option grammars not conservatively recognized, SDK/native libraries,
operating-system inputs and undeclared tools. Independently authenticated
hermetic builds, binary comparison and signed provenance remain release gates.
