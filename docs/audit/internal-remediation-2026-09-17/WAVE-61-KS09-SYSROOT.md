# Wave 61 KS-09: selected sysroot component fingerprint

Date: 2026-09-18. Starting point: `8bf7bfc`. Scope: build identity and its
RPC/CLI representation. Consensus, wire and persistent formats, release
artifacts and deployed nodes are unchanged.

## Local hardening

Wave 60 bound the selected `rustc` and Cargo executable bytes. A Rust compiler
still loads its implementation and target standard library from the selected
sysroot, so equal executable/version fields did not bind those load-bearing
files.

The build-environment digest now includes one domain-separated aggregate over
the sysroot `rustc` executable, available `rustc_driver` libraries and the
selected target's `libstd` artifacts. Each readable component is an
incremental-build dependency. Neither paths, component names nor component
digests are published; buildinfo exposes only the number incorporated into the
aggregate. A normal workspace build must bind the sysroot compiler plus at
least one target standard-library component.

The subset deliberately avoids hashing the whole toolchain on every build. It
binds the compiler driver and the standard library linked into ordinary Rust
programs while retaining a visible count when a vendored or unusual toolchain
does not expose an expected optional component.

## Residual boundary

KS-09 remains `PARTIAL`. The linker, SDK, other sysroot libraries, native C
toolchain/libraries, delegated wrappers and operating system are not fully
hashed. A malicious builder can alter this build script or final artifact.
Independent hermetic builds, binary comparison and signed provenance remain
release gates.
