# Wave 73 KS-09: bind the cc-rs selected archiver

Date: 2026-09-19. Base: `42eeab0`. Scope: native build identity. No consensus,
wire, persistent format, release artifact or deployed node changed.

## Correction

Wave 72 bound the C compiler that the locked cc-rs implementation actually
selects, including its unconfigured platform default. The executable that
cc-rs selects to archive the resulting PQ object files into static libraries
remained implicit when no `AR` selector was present.

The node build now resolves the cc-rs archiver for the effective host and
target, resolves a bare command through the build `PATH`, hashes its executable
bytes under the existing build-tool domain, and adds that digest to the
private aggregate build-environment identity. The selected file is watched
for incremental rebuilds. An unavailable or unreadable required archiver stops
the build instead of emitting an incomplete identity. Its command and path are
not disclosed through `getbuildinfo`.

## Validation and boundary

- The shared selected-tool regressions pass 2/2: executable mutation changes
  identity, and a missing executable has no identity.
- The focused `getbuildinfo` build-environment regression passes and its public
  scope now names both cc-rs selected native tools without revealing either.
- `git diff --check` passes for this front.

KS-09 remains `PARTIAL`. Tool-loaded libraries, SDK/header/library contents,
wrapper-specific grammars, operating-system inputs, independently
authenticated builds, binary comparison and signed provenance remain outside
this correction.
