# Wave 119 — INF-01 package digest metadata

Date: 2026-09-19
Comparison base: `1aff5ff`

## Reproduced gap

The unsigned candidate packager copied the first column printed by its SHA-256
tool directly into `SHA256SUMS` and `BUILD-INFO`. A successful tool could emit
a short or non-hexadecimal value, uppercase text, or multiple rows. The job
still reported success; multiple rows additionally injected physical lines
into both generated metadata files.

## Correction

The packager now propagates checksum-tool failure and requires its captured
digest to be exactly 64 lowercase hexadecimal characters before emitting the
manifest or build metadata. This is the same structural digest contract used
by the canonical two-builder comparator.

## Adversarial coverage

The hermetic selftest places a `sha256sum` shim first on `PATH`. Its canonical
mode delegates to the platform's real SHA-256 implementation by absolute path.
Adversarial modes exit nonzero or emit a short digest, a 64-character non-hex
digest, uppercase hex, or two digest rows; all are refused with the intended
diagnostic. The complete source race, version identity and target matrix
remains active.

## Validation

```text
bash scripts/package-pos-release-candidate.selftest.sh
# package-pos-release-candidate selftest: PASS

bash -n scripts/package-pos-release-candidate.sh
bash -n scripts/package-pos-release-candidate.selftest.sh
# passed
```

## Residual boundary

This validates digest shape and local consistency only. It does not authenticate
the checksum implementation or prove that the returned value is the correct
hash of the binary. It also does not authenticate the compiler, runner,
repository or dependencies. Signing, publication, independent canonical builds
and comparison, approval, rollback rehearsal, staged canary and fleet evidence
remain external release gates. INF-01 remains `PARTIAL`.
