# Wave 63 KS-09: unambiguous delegated compiler fingerprints

Date: 2026-09-18. Base: `cef4b8e`. Scope: build identity and its local parser
regressions. No consensus, wire, persistent format, release artifact or
deployed node changed.

## Correction

Wave 62 fingerprinted the executable invoked directly by configured native
tool variables. For common compiler-cache/distribution commands such as
`sccache clang`, that bound the wrapper but not the compiler it delegated to;
replacing `clang` in place could preserve both the environment value and the
wrapper digest.

The restricted command parser now preserves quoted paths and conservative
backslash escapes without applying shell expansion or substitution. When the
first executable is one of `ccache`, `distcc`, `icecc` or `sccache`, and the
immediately following word is an unambiguous non-option compiler, both wrapper
and delegate bytes receive separate domain-separated fields inside the build-
environment digest. Both files are incremental-build dependencies. Paths,
commands and individual digests remain unpublished; the existing configured-
tool count includes each successfully fingerprinted executable.

The parser intentionally refuses unterminated quotes/escapes and does not try
to interpret wrapper-specific option grammars. Its small dependency-free
module is shared by the build script and a normal Cargo integration target, so
quoted Unix paths, Windows paths, all four known wrappers and refusal cases are
executable regressions rather than comments.

## Validation

- `cargo test -p bloch-pos-node --test build_command_parser --offline`: 2/2
  parser/delegation tests passed.
- The Wave 63 integration checkpoint records the broad node suite.
- `git diff --check` passes.

## Residual boundary

KS-09 remains `PARTIAL`. Wrapper commands containing wrapper-specific options
are not guessed, other wrapper brands remain direct-boundary-only, and an
unconfigured platform-default linker is not discoverable from stable rustc
build-script metadata. SDK/native libraries, operating-system inputs and
undeclared tools remain outside the digest. Independently authenticated
hermetic builds, binary comparison and signed provenance remain release gates.
