# Wave 201: Cosign private-key mode boundary (INF-20)

Date: 2026-09-19
Comparison base: `c519e089`

## Reproduced residual

Wave 197 made the image-signing wrapper reject repository-local, symbolic-link
and hardlink aliases of the private key. It did not inspect the key's POSIX
mode. The hermetic selftest still passed under `umask 000`: its canonical key
was created as mode `0666` and reached all three fake-Cosign calls.

No real key, signature, registry, image or external service was used.

## Correction

After resolving the already checked physical, regular, non-symlink,
single-link key path, `sign-image.sh` now obtains its octal mode with the GNU
`stat -c '%a'` interface or the BSD/macOS `stat -f '%Lp'` fallback. A command
failure or any unrecognized output fails closed. Only `0400` and `0600` are
accepted before `cosign` can run.

The public key remains outside this private-key policy because it is intended
for distribution.

## Adversarial coverage

The hermetic fake-Cosign selftest now explicitly establishes every private-key
mode, independently of the invoking umask. It proves:

- regular external keys at `0600` and read-only `0400` reach the same exact
  sign, verify and triangulate calls;
- modes `0640`, `0644` and `0666` fail before fake Cosign runs;
- failed and malformed `stat` output fail closed; and
- the complete Wave 197 relative/missing, Git-ancestor, symlink and hardlink
  refusal matrix remains green.

## Validation

- `bash -n deploy/attestation/sign-image.sh deploy/attestation/sign-image.selftest.sh`
- `bash deploy/attestation/sign-image.selftest.sh`
- `bash -c 'umask 000; bash deploy/attestation/sign-image.selftest.sh'`
- `git diff --check`

## Residual boundary

This validates only traditional POSIX mode bits at one local instant. It does
not authenticate uid/gid ownership, directory modes, ACLs, xattrs, mount or
filesystem policy, copies/reflinks/history, ancestor replacement or other
TOCTOU races. Key generation, encryption, rotation, KMS/HSM custody, Cosign
binary/provenance and PATH integrity, registry authentication, image
digest/tag provenance, signing, publication, admission and deployment evidence
remain external controls. No real signing, publication or deployment was
performed. INF-20 remains `PARTIAL`.
