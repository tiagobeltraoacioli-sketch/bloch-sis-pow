# Wave 69 KS-09: fail-closed source inventory

Date: 2026-09-18. Base: `8e0ebd6`. Scope: build source identity and local
regression coverage. No consensus, wire, persistent format, release artifact
or deployed node changed.

## Correction

The source digest covered the intended extensions, hidden directories and
workspace metadata, but its recursive inventory silently skipped directory
entries whose enumeration, metadata or path encoding could not be read. A
source symlink was also outside the ordinary-file branch. The resulting digest
could therefore describe a smaller set than the published scope without
reporting that the inventory was incomplete.

The inventory is now a shared, directly tested build module. Any directory
read, entry, metadata, relative-path or UTF-8 conversion failure invalidates
the whole identity instead of omitting an entry. Symlinks below `crates/` and
for the three root metadata inputs likewise yield `unavailable`; the digest
never claims the bytes reached through a mutable external path. `.git` and
`target` retain their explicit exclusions.

The hashing domain, canonical framing, extensions, root metadata, published
RPC fields and successful-tree digest semantics are unchanged.

## Adversarial coverage

- A source below a hidden directory with the `.macros` extension is counted,
  and changing its bytes changes the digest.
- A symlink bearing a source extension invalidates the complete identity.
- Linux coverage creates a non-UTF-8 source filename and proves that it also
  invalidates the identity. Darwin does not run that fixture because its
  filesystem may refuse creation before the inventory observes the name.

## Validation and boundary

- `cargo test -p bloch-pos-node build_source_digest_tests --offline`: two
  applicable macOS tests pass; the path-name fixture remains gated for a Linux
  run and no hosted outcome is claimed here.
- `git diff --check`: passes for this front.

KS-09 remains `PARTIAL`. An unavailable identity is explicit rather than a
partial digest, but release policy and independent builders must still refuse
it. SDK/native-library contents, operating-system inputs, wrapper-specific
option grammars, independently authenticated builds, binary comparison and
signed provenance remain outside this local correction.
