# Wave 197: cosign private-key filesystem boundary (INF-20)

Date: 2026-09-19
Comparison base: `aa231776`

## Reproduction

`deploy/attestation/sign-image.sh` required an absolute existing
`COSIGN_KEY`, but accepted an ordinary repository file such as `Cargo.toml`
as both the private and public key. With no `cosign` installed, that input
reached the signing command and stopped only at `cosign: command not found`.
No signature or registry operation was performed during reproduction.

That behavior did not enforce the script's stated local boundary that a
private signing key must be kept outside Git working trees.

## Correction

Before invoking `cosign`, the script now:

- rejects a private-key path whose final component is a symbolic link;
- resolves the containing directory physically and passes that physical key
  path to `cosign`;
- rejects a `.git` file, directory, or dangling symlink on the physical
  ancestor chain; and
- requires the private-key inode to have exactly one hard link.

The public key is intentionally not subject to the private-key boundary: it
is public material and may legitimately be distributed from the repository.

## Adversarial coverage

The new hermetic `deploy/attestation/sign-image.selftest.sh` uses a fake
`cosign` and covers:

- a canonical external, regular, single-link key and exact sign/verify/
  triangulate arguments;
- a key below a normal `.git` directory;
- a path through a symlinked ancestor into a linked-worktree-style `.git`
  file;
- final-component symlink and hardlink aliases; and
- the pre-existing relative, missing-private-key, and missing-public-key
  refusals.

## Validation

- `bash -n deploy/attestation/sign-image.sh deploy/attestation/sign-image.selftest.sh`
- `bash deploy/attestation/sign-image.selftest.sh`
- `bash -c 'umask 000; bash deploy/attestation/sign-image.selftest.sh'`
- `git diff --check`

## Residual boundary

This is a repository-local lexical/filesystem-alias guard, not proof of key
custody or of every possible Git metadata layout. Copies, reflinks, prior Git
history, owner/mode/ACL/xattr/mount policy, ancestor replacement and other
TOCTOU races remain outside this patch. Key generation, encryption, rotation,
KMS/HSM custody, cosign provenance, registry authentication, image digest/tag
provenance, publication, admission policy, and hosted deployment evidence
remain external operational controls. No real signing, publication, or
deployment was performed. INF-20 therefore remains `PARTIAL`.
