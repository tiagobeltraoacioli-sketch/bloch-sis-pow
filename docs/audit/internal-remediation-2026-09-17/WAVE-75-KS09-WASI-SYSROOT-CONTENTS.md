# Wave 75 KS-09: bind selected WASI sysroot contents

Date: 2026-09-19. Branch: `fix/internal-audit-20260917`. Comparison base:
`708aa80`.

## Finding narrowed

The build fingerprint already bound the value of `WASI_SDK_DIR`, but a WASI
build could replace headers, startup objects or libraries below that same path
without changing the identity. The checked-in `pqcrypto-internals` build
passes this path directly as its C compiler sysroot.

The node build now selects its external native tree exactly as that dependency
does:

- a `wasi` target recursively inventories and hashes `WASI_SDK_DIR`;
- every other target hashes the exported freestanding-libc include tree when
  present.

Relative UTF-8 paths, lengths and regular-file bodies enter the existing
domain-separated SHA3-256 tree identity in sorted order. Directory and file
watches invalidate Cargo state on inventory or content changes. Missing or
unreadable roots, symlinks, special files, non-UTF-8 paths and incomplete
traversal stop the build rather than recording a partial SDK.

Only the aggregate tree identity enters the private build-environment
fingerprint. Paths, filenames and individual digests remain absent from
`getbuildinfo`.

## Validation

- The native-input integration target passes 3/3, covering content changes,
  inventory changes, symlink refusal and target-specific selector choice.
- The focused `getbuildinfo` scope regression and full node validation are
  recorded in the Wave 75 integration checkpoint.

## Residual boundary

KS-09 remains `PARTIAL`. The selected freestanding and WASI sysroot trees are
now bound, but libraries loaded from outside those roots, dynamically loaded
tool libraries, implicit operating-system inputs, undeclared inputs and
independent build provenance remain open. This change affects build identity
only; it does not change consensus, wire, storage or release formats.
