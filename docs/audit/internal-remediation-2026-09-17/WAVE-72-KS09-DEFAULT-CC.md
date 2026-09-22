# Wave 72 KS-09: bind the cc-rs selected compiler

Date: 2026-09-19. Base: `eef995e`. Scope: native build identity. No consensus,
wire, persistent format, release artifact or deployed node changed.

## Correction

The build fingerprint already hashed explicitly configured C compilers and
known wrapper delegates. When no `CC` selector was present, however, the
checked-in PQ native build still let cc-rs choose a platform compiler while the
node identity recorded no bytes for that selected executable.

The node build now asks the locked cc-rs implementation to resolve the
compiler for the effective host and target, resolves a bare command through
the build `PATH`, hashes the selected executable bytes under the existing
build-tool domain, and includes that digest in the private aggregate build
environment fingerprint. The selected file is watched for incremental
rebuilds. A missing or unreadable required compiler stops the build instead of
stamping an incomplete identity. Neither its command nor its path is exposed
through `getbuildinfo`.

The cc crate was already locked and used by the PQ dependency; making it a
direct build dependency adds no package or version to the lockfile.

## Adversarial coverage and boundary

- Mutating a selected executable fixture changes its digest.
- A missing selected executable cannot produce an identity.
- The focused build-environment RPC regression confirms the bounded aggregate
  digest and documents the newly covered cc-rs default selection.

KS-09 remains `PARTIAL`. Compiler-loaded libraries, SDK/header/library
contents, archiver defaults, wrapper-specific grammars, operating-system
inputs, independently authenticated builds, binary comparison and signed
provenance remain outside this correction.
