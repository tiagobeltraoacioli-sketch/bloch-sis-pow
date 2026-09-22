# Wave 205: immutable Cosign image identity (INF-20)

Date: 2026-09-19
Comparison base: `c8286491`

## Reproduced residual

The image-signing wrapper and its operator README accepted and demonstrated a
mutable tag such as `example.invalid/bloch:test`. The wrapper passed that tag
separately to `cosign sign`, `cosign verify` and `cosign triangulate`, so the
repository did not require all three registry operations to name one immutable
image digest. The existing hermetic selftest reproduced acceptance of the
tag-only reference.

The wrapper also labeled `cosign triangulate` output as the digest for CoCo to
pin. That command locates the signature object; it is not the signed image
digest itself.

## Correction

`sign-image.sh` now fails before inspecting the key or invoking Cosign unless
the image argument has a nonempty, whitespace- and `@`-free repository prefix
and an exact `@sha256:` suffix containing 64 lowercase hexadecimal digits.
Both `repository@sha256:...` and `repository:tag@sha256:...` remain supported.

The identical digest-qualified reference is passed to sign, verify and
triangulate. The wrapper prints the supplied `sha256:<digest>` as the image
identity for policy preparation and labels triangulate output only as the
informational signature-object reference. The checked-in usage examples now
require the same digest-qualified form and distinguish the local build hash
from the registry manifest digest used in that reference.

## Adversarial coverage

The fake-Cosign selftest proves exact arguments and output labels for both a
plain digest reference and a tag-plus-digest reference. It rejects before any
fake Cosign invocation:

- a mutable tag without a digest;
- 63- and 65-character digests;
- nonhexadecimal and uppercase digest characters;
- bytes after the digest;
- a duplicate `@sha256:` segment;
- an empty repository prefix; and
- whitespace in the repository prefix.

The complete key ancestry, symlink, hardlink, mode and GNU/BSD-stat matrix from
Waves 197 and 201 remains covered.

## Validation

- `bash -n deploy/attestation/sign-image.sh deploy/attestation/sign-image.selftest.sh`
- `bash deploy/attestation/sign-image.selftest.sh`
- `bash -c 'umask 000; bash deploy/attestation/sign-image.selftest.sh'`
- `git diff --check`

## Residual boundary

This is a local syntactic identity binding. It does not prove that the digest
exists in a registry, matches locally built OCI bytes, was independently
derived or authenticated, or remains available. Registry authentication and
behavior, Cosign binary/PATH provenance, key custody, digest collision
resistance, signature upload/publication, public-key and admission-policy
distribution, KBS/TEE binding, deployment and hosted evidence remain external.
No network, real signing, publication or deployment was performed. INF-20
remains `PARTIAL`.
