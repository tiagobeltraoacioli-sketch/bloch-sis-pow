# Wave 52 KS-09: build-environment fingerprint

Date: 2026-09-18. Starting point: `c8ab7c8`. Scope: build identity, RPC/CLI
reporting, tests and current integration documentation. No consensus rule,
wire encoding, release artifact, deployment or live node was changed.

## Local hardening

The existing `source_digest` identifies the checked-in source bytes but does
not distinguish two builders that compile those bytes with different flags,
wrappers, targets or compiler toolchains. The individually reported `rustc`,
profile and target fields were useful to an operator but did not bind the
remainder of the code-generation environment to one comparable value.

The node build now creates a domain-separated SHA3-256
`build_environment_digest` over canonical, length-prefixed fields:

- verbose rustc and Cargo identities;
- effective target triple and Cargo profile;
- Rust flags, wrappers, bootstrap and incremental controls;
- C compiler, archiver, flags and bindgen controls, including observed
  target-specific forms;
- Cargo target/profile overrides; and
- SDK/deployment-target and reproducible-build timestamp controls.

Only the digest and number of bound fields are published. Raw environment
values can contain local wrapper or SDK paths and are not exposed. Known
variables are watched even when absent so setting one invalidates an
incremental build; observed prefixed variables are watched individually.
`getbuildinfo` and `bloch-pos buildinfo` return the same additive fields. The
source-scope text was also corrected to name `.macros` and
`rust-toolchain.toml`, which were already hashed.

## Validation and boundary

Regressions require a lowercase 64-hex digest, bind at least compiler, Cargo,
target and profile, and preserve the no-path/no-secret disclosure contract.
The focused RPC/build-identity suite and full node suite are run at Wave 52
integration.

KS-09 remains `PARTIAL`. This fingerprint does not hash sysroot, linker, SDK,
native library or operating-system contents; it cannot discover an undeclared
environment variable used by future build logic; and a malicious builder can
modify the build script or reported binary. Independent hermetic builders,
binary comparison, signed provenance and publication are still required.
