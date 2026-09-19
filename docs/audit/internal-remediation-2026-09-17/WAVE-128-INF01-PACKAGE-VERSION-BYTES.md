# Wave 128 — INF-01 packaged version bytes

Date: 2026-09-19
Comparison base: `a121cce3`

## Reproduced gap

The unsigned candidate packager executed the Cargo output for `--version`, then
copied that path into its staging directory and hashed the copied bytes. An
executable could emit the expected two-line version identity and synchronously
rewrite itself before returning. The packager then published the rewritten
bytes and their digest alongside version metadata emitted by the earlier byte
set.

## Correction

The packager now copies the Cargo output exactly once into its private staging
directory before inspection. It validates and records that copy's SHA-256,
executes `--version` only from the same staged path, validates its SHA-256
again, and requires equality. The post-version hash is emitted into the
manifest and metadata only after this equality check. Digest validation is
centralized so both observations retain the existing exact lowercase 64-hex
contract.

## Adversarial coverage

The hermetic fake binary adds a mode that emits the complete valid two-line
identity, overwrites its own staged path and returns success. The packager must
refuse it because the before/after hashes differ. The canonical case and the
complete source, version, target, digest, pin and mode matrix remain active.

## Validation

```text
bash scripts/package-pos-release-candidate.selftest.sh
# package-pos-release-candidate selftest: PASS

bash -n scripts/package-pos-release-candidate.sh
bash -n scripts/package-pos-release-candidate.selftest.sh
# passed
```

## Residual boundary

This closes synchronous mutation during the local version query. It does not
prevent a background process or the owning runner from changing bytes after
the final hash, authenticate the version assertions, checksum tool, compiler
or runner, or provide filesystem immutability. Signing, publication,
independent canonical builds and comparison, approval, rollback rehearsal,
staged canary and fleet evidence remain external release gates. INF-01 remains
`PARTIAL`.
