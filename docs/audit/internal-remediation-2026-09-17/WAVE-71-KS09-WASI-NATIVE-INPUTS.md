# Wave 71 KS-09: bind WASI native input selectors

Date: 2026-09-19. Base: `7a85a56`. Scope: build-environment identity. No
consensus, wire, persistent format, release artifact or deployed node changed.

## Correction

The locked `pqcrypto-internals` build script consumes two native-input
selectors that were not among the node's exact watched and hashed environment
fields:

- `WASI_SDK_DIR` selects the sysroot passed to both cc-rs compilations for a
  WASI target;
- `DEP_WASM32_UNKNOWN_UNKNOWN_OPENBSD_LIBC_INCLUDE` selects an additional
  libc header tree and linked library for the freestanding wasm target.

Their values can therefore change compiled native inputs without changing the
source digest. Both exact variables are now included in the canonical
build-environment fingerprint and watched even while absent, so setting or
removing one invalidates an incremental stamp. Values are hashed and remain
absent from public `getbuildinfo` output.

This changes build identity only. It does not enable a WASI build, select a
target, alter PQ code or claim that an SDK directory's contents are
authenticated.

## Validation and boundary

- The variable inventory was reconciled against the checked-in
  `pqcrypto-internals/build.rs` branches that consume both selectors.
- `cargo test -p bloch-pos-node getbuildinfo_carries_a_bounded_build_environment_fingerprint --offline`:
  passes in the Wave 71 integration checkpoint.
- `git diff --check`: passes for this front.

KS-09 remains `PARTIAL`. Paths and presence are bound, but SDK/header/library
contents, operating-system inputs, cross-target execution, independently
authenticated builders, binary comparison and signed provenance remain
external to this correction.
