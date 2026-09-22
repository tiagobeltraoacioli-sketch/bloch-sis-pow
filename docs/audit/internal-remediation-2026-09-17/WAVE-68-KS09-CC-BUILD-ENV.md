# Wave 68 KS-09: bind cc-rs output controls

Date: 2026-09-18. Base: `99287b4`. Scope: build-environment identity. No
consensus, wire, persistent format, release artifact or deployed node changed.

## Correction

The build digest already bound compiler/archive executables and ordinary
C/C++ flags, but the locked `cc` crate (`1.2.60`) consumes additional variables
that can change command construction, flag parsing, archive bytes or linked
libraries. Those values could alter native PQClean inputs without entering the
published build-environment digest.

The exact watched/hash set now also covers:

- `ARFLAGS` and `RANLIBFLAGS`, including host/target and exact triple forms;
- `CRATE_CC_NO_DEFAULTS` and `CC_SHELL_ESCAPED_FLAGS`;
- `CC_KNOWN_WRAPPER_CUSTOM` and the fail-closed `CC_FORCE_DISABLE` control;
- `CXXSTDLIB`, including host/target and exact triple forms.

Absent exact forms are still watched, so setting one after an incremental build
reruns the build script rather than retaining a stale stamp. Values remain
hashed and are never disclosed by `getbuildinfo`.

## Validation

- The variable inventory was reconciled against the locked `cc 1.2.60`
  implementation and its documented external-configuration surface.
- `cargo test -p bloch-pos-node getbuildinfo_carries_a_bounded_build_environment_fingerprint --offline`:
  passed with the expanded canonical environment field set.
- The Wave 68 integration checkpoint records the broad node suite.
- `git diff --check` passes.

## Residual boundary

KS-09 remains `PARTIAL`. SDK/native library contents, operating-system inputs,
wrapper-specific option grammars, failed cross-target probes and undeclared
tools remain outside the digest. Independently authenticated hermetic builds,
binary comparison and signed provenance remain release gates.
