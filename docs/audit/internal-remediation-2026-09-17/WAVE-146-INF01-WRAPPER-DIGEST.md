# Wave 146 — INF-01 canonical wrapper digest contract

Date: 2026-09-19
Branch: `fix/internal-audit-20260917`
Comparison base: `b3632ab6`

## Reproduced gap

`scripts/build-pos-release-container.sh` accepted the first whitespace-delimited
field returned by `sha256sum`/`shasum` without validating its shape. Before this
change, a PATH shim returning 63 zeroes let the complete wrapper self-test pass:
the fake engine consumed the same malformed tool output and emitted a matching
manifest and `BUILD-INFO` value.

## Correction

The canonical-container wrapper now fails closed unless its SHA-256 command
exits successfully and the extracted digest field is exactly 64 lowercase
ASCII hexadecimal characters.

This validation runs before the exported manifest, checksum and metadata are
accepted. Existing exact `SHA256SUMS`, checksum verification, canonical
`BUILD-INFO`, captured-OID and output-publication checks remain in force.

The self-test captures the real host SHA implementation for the fake engine,
then places a controllable shim only in the wrapper's PATH. The canonical case
still delegates to the real implementation. Dedicated adversarial cases cover
tool failure, short, nonhexadecimal, uppercase and multiple-row output, while
the pre-existing manifest, metadata and moving-HEAD matrix remains intact.

## Local validation

- `bash -n scripts/build-pos-release-container.sh`
- `bash -n scripts/build-pos-release-container.selftest.sh`
- `bash scripts/build-pos-release-container.selftest.sh`
- `git diff --check -- scripts/build-pos-release-container.sh scripts/build-pos-release-container.selftest.sh docs/audit/internal-remediation-2026-09-17/WAVE-146-INF01-WRAPPER-DIGEST.md`

## Boundary and residuals

This proves only fail-closed local shape and coherence of the digest observed
by this wrapper. It does not authenticate the checksum implementation, Git
objects, container engine, image, toolchain or builder; nor does it establish
independent-build equality, signing, publication, hosted-CI enforcement,
rollback rehearsal, canary rollout or fleet evidence. INF-01 therefore remains
`PARTIAL`, and every external launch gate remains required.
