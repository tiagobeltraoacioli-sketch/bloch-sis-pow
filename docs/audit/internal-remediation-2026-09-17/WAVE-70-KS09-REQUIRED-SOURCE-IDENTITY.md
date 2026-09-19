# Wave 70 KS-09: require a complete workspace source identity

Date: 2026-09-19. Base: `e3fb033`. Scope: build source identity and local
regression coverage. No consensus, wire, persistent format, release artifact
or deployed node changed.

## Correction

Wave 69 made source traversal invalidate the digest on partial reads,
unrepresentable paths and symlinks. A detected ordinary workspace could still
finish compiling in that state and stamp `source_digest=unavailable`. That
answer is distinguishable, but it leaves enforcement to every downstream
consumer and permits a runnable workspace binary without the identity the
build promises.

The build now separates two cases:

- if no enclosing Cargo workspace can be detected, as for a genuinely
  vendored or git-dependency copy, the existing explicit `unavailable` result
  remains available;
- once the normal workspace is detected, every source entry and all three
  declared root inputs (`Cargo.toml`, `Cargo.lock` and
  `rust-toolchain.toml`) are mandatory. Any incomplete inventory stops the
  build instead of emitting an unidentified binary.

Successful-tree hashing, framing, extensions and public RPC fields are
unchanged.

## Adversarial coverage

- Removing a declared root input invalidates the digest.
- Introducing a source symlink into a detected workspace makes the required
  identity path panic before a binary can be stamped.
- Existing hidden `.macros`, source-symlink and path-encoding coverage remains
  attached to the same shared build module.

## Validation and boundary

- `cargo test -p bloch-pos-node build_source_digest_tests --offline`: all 4
  applicable macOS tests pass; integration targets selected by the filter
  also complete successfully with zero matching tests.
- `git diff --check`: passes for this front.

KS-09 remains `PARTIAL`. A malicious builder can edit the identity code;
vendored builds still report unavailable by design; SDK/native-library and
operating-system contents, wrapper-specific grammars, independent builds,
binary comparison and signed provenance remain outside this correction.
