# Wave 60 KS-09: build-tool binary fingerprints

Date: 2026-09-18. Starting point: `fc96e52`. Scope: build identity and its
RPC/CLI representation. Consensus, wire and persistent formats, release
artifacts and deployed nodes are unchanged.

## Local hardening

The build-environment digest previously bound verbose `rustc` and Cargo
version output plus selected code-generation variables. Those strings did not
bind the executable bytes that produced them: an in-place replacement or a
wrapper capable of printing the expected version could preserve the reported
identity while changing compilation.

The digest now includes domain-separated SHA3-256 fingerprints of the selected
`RUSTC` and `CARGO` executable files. Their paths and bytes are never published.
Each resolved executable is an incremental-build dependency, and `CARGO` joins
the explicitly watched environment variables. A bare command is resolved via
PATH for ordinary local builds; Cargo's normal explicit tool paths remain the
preferred and directly bound case.

`getbuildinfo` reports only the number of successfully hashed tool binaries and
states the expanded scope. The normal workspace regression requires both
compiler and Cargo fingerprints, while a vendored or unusual environment can
still build with a visible count below two rather than receiving a false
fingerprint.

## Residual boundary

KS-09 remains `PARTIAL`. The fingerprints do not hash the compiler sysroot,
linker, SDK, native libraries or operating system, and a wrapper may delegate
to further unbound tools. A malicious builder can alter this build script or
the final artifact. Independently authenticated hermetic builds, binary
comparison and signed provenance remain release gates.
