# Wave 98 — INF-01 artifact write modes

Date: 2026-09-19
Comparison base: `9e058f1`

## Reproduced gap

The release comparator required regular non-symlink files and an executable
`bloch-pos`, but it did not inspect group/other write bits. Two candidates
whose binary was mode `0777` still passed every byte, manifest, metadata,
alias and tree check. A temporary full-selftest reproduction with both copies
changed to that mode completed with `PASS`.

This is separate from candidate byte equality: identical content does not make
a locally group- or world-writable release artifact an acceptable canonical
input.

## Correction

For each of the three canonical artifacts, the comparator now uses portable
`find -perm` predicates to reject either the group-write or other-write bit.
The fixed-byte count avoids parsing filenames, and the script's existing
`pipefail` behavior makes traversal errors fail closed.

Owner-write remains allowed. The existing executable requirement for
`bloch-pos` is unchanged. This matches the current canonical container export:
the Dockerfile explicitly emits the binary as `0755`, while its generated
manifest and metadata are ordinary non-group/non-world-writable files.

## Adversarial coverage

The canonical copied-directory fixture remains green. Three independent pairs
of otherwise canonical, equal candidates must now fail with the precise mode
diagnostic:

- `bloch-pos` changed to `0777`;
- `SHA256SUMS` changed to `0666`; and
- `BUILD-INFO` changed to `0666`.

Both candidates in each pair use the same unsafe mode, proving that equality
between supplied directories cannot satisfy the local safety contract.

## Validation

```text
bash scripts/compare-pos-release-builds.selftest.sh
# compare-pos-release-builds selftest: PASS

bash -n scripts/compare-pos-release-builds.sh
bash -n scripts/compare-pos-release-builds.selftest.sh
# passed
```

## Residual boundary

This proves only the absence of POSIX group/other write bits on the three
supplied paths at comparison time. It does not authenticate ownership or
group identity, inspect ACLs, extended attributes or mount/storage policy, or
prove that a later archive, publication or installation preserves these mode
bits. It also does not prove builder independence or provenance, hosted CI,
signing, approval, rollback rehearsal, deployment or fleet state. INF-01
remains `PARTIAL`.
