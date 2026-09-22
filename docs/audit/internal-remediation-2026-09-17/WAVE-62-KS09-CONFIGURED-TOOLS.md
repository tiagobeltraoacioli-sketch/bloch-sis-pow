# Wave 62 KS-09: configured native-tool fingerprints

Date: 2026-09-18. Base: `d30afca`. Scope: build identity and the
`getbuildinfo`/`buildinfo` representation. No consensus, wire, persistent
format, release artifact or deployed node changed.

## Correction

The build-environment digest already bound Rust/C tool-selection environment
values, the selected Cargo and rustc executables, and a load-bearing Rust
sysroot subset. A configured linker, C/C++ compiler, archiver, ranlib or rustc
wrapper could still be replaced in place without changing its path-valued
environment field.

The build script now resolves the executable invoked directly by every
explicitly configured tool variable in the reviewed Cargo/cc-rs target and
host forms. Its bytes receive a domain-separated SHA3-256 fingerprint inside
the build-environment digest, and the file is an incremental-build dependency.
Paths, commands and individual fingerprints are not published. Buildinfo adds
only `build_configured_tool_binaries_hashed`, the number of successfully bound
executables, and its scope text names this coverage.

For command forms containing arguments, the directly invoked wrapper is the
fingerprinted boundary. A quoted executable path is recognized without
interpreting the remainder as a shell program. Empty, absent or unresolvable
values remain represented by the existing environment fields but do not
inflate the executable count.

The integration reference now includes all three bounded component counters:
the Cargo/rustc executables, selected sysroot components and explicitly
configured tool executables.

## Validation

- `cargo test -p bloch-pos-node getbuildinfo_carries_a_bounded_build_environment_fingerprint --offline -- --nocapture`:
  1 focused node unit test passed; all integration targets selected zero tests.
- The Wave 62 integration checkpoint records the broad node suite.
- `git diff --check` passes.

## Residual boundary

KS-09 remains `PARTIAL`. An unconfigured platform-default linker is not
discoverable from stable rustc build-script metadata and is therefore not
fingerprinted here. A wrapper may delegate to an unbound compiler, and SDK,
native libraries, operating-system inputs and undeclared tools remain outside
the digest. Independently authenticated hermetic builds, binary comparison and
signed provenance remain release gates.
