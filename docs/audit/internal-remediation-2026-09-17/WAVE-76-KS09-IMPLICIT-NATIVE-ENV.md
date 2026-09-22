# Wave 76 KS-09: bind implicit native search and loader environment

Date: 2026-09-19. Branch: `fix/internal-audit-20260917`. Comparison base:
`5580070`.

## Finding narrowed

The build fingerprint covered explicit Rust, cc-rs and linker configuration,
but omitted conventional variables interpreted implicitly by native compilers,
linkers and their dynamic loaders. A build could therefore select different
headers, libraries, compiler subprograms or injected tool libraries while the
explicit `CC`/`AR`/linker selections and source tree remained unchanged.

The exact watched-and-hashed inventory now also includes:

- compiler include and subprogram search: `CPATH`, `C_INCLUDE_PATH`,
  `CPLUS_INCLUDE_PATH`, `OBJC_INCLUDE_PATH`, `COMPILER_PATH` and
  `GCC_EXEC_PREFIX`;
- native library search: `LIBRARY_PATH`;
- Linux loader selection: `LD_LIBRARY_PATH`, `LD_PRELOAD` and `LD_AUDIT`;
- macOS loader library, framework, root, suffix and versioned search/injection
  channels: the applicable `DYLD_*_PATH`, `DYLD_IMAGE_SUFFIX` and
  `DYLD_INSERT_LIBRARIES` variables; and
- archive timestamp control: `ZERO_AR_DATE`.

Each variable is watched even while absent. Its value is length-prefixed and
hashed into the private aggregate build-environment identity, never disclosed
through `getbuildinfo`. The inventory moved to a small shared module so its
security-sensitive membership can be tested directly.

## Validation

- The inventory regression passes 1/1 and proves all twenty channels are
  present and unique.
- The focused `getbuildinfo` scope regression passes and describes the new
  bounded coverage without exposing values.
- Full node validation is recorded in the Wave 76 integration checkpoint.

## Residual boundary

KS-09 remains `PARTIAL`. Binding a search or loader variable does not hash
every file reachable through its directories. Undeclared operating-system
defaults, tool-loaded libraries outside already hashed sysroots/native trees,
implicit tools, and independent build provenance remain open. No consensus,
wire, storage or release format changed.
