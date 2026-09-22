# Wave 74 KS-09: freestanding native include-tree identity

Date: 2026-09-19. Branch: `fix/internal-audit-20260917`. Comparison base:
`76e6cfb`.

## Finding narrowed

The build fingerprint already bound the selector path exported by the
freestanding-libc dependency, but did not bind the header bytes selected by
that path. A replacement header tree at the same location could therefore
leave the private aggregate build-environment fingerprint unchanged.

The build now recursively inventories
`DEP_WASM32_UNKNOWN_UNKNOWN_OPENBSD_LIBC_INCLUDE`, sorts UTF-8 relative paths,
and hashes every regular file name, length and body into a domain-separated
SHA3-256 tree identity. Both directories and files are registered as Cargo
rerun inputs. Missing or unreadable entries, non-UTF-8 relative paths,
symlinks, special files and traversal failures stop the build rather than
silently producing a partial identity.

Only the aggregate fingerprint remains observable through `getbuildinfo`; the
external path, filenames and individual header digests are not exposed.

## Validation

- Two focused integration tests cover in-place content changes, inventory
  additions and fail-closed symlink handling.
- The focused `getbuildinfo` scope regression covers the new bounded public
  description.
- Full node and posture validation is recorded in the Wave 74 integration
  checkpoint.

## Residual boundary

KS-09 remains `PARTIAL`. This closes the selected freestanding include-tree
gap, but does not yet bind the contents selected through `WASI_SDK_DIR`, native
libraries, dynamically loaded tool libraries, undeclared inputs or independent
build provenance. It makes no consensus, wire, storage or release-format
change.
