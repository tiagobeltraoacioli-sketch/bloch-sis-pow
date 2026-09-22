# Wave 109 — INF-09 rollback binary snapshot

Date: 2026-09-19
Comparison base: `a1e5663`

## Reproduced gap

The rollback assembler hashed its caller-provided binary, then executed that
same path for `--version`, and only afterwards copied it into the package. An
executable that rewrote itself during the version query, or a concurrent path
replacement, could therefore leave the installer constant, README and signed
trusted comment naming the earlier hash while the signed manifest and tarball
contained later bytes. Verification checked both identities independently but
did not require them to be equal.

## Correction

After minisign and the requested secret/public key have been validated, the
assembler copies the input exactly once into its private work directory. It
runs the version check on that private copy, hashes the bytes left after that
execution, derives the package identity, and moves the same file into the
package. The manifest, generated installer, README and signature statement now
all derive from that one private byte set. Unsigned assembly remains refused;
package names, formats and verification order are unchanged.

## Adversarial coverage

The existing disposable-key selftest now supplies an executable that rewrites
itself while answering `--version`. It requires the final packaged binary hash
to equal the `SHA256SUMS` row, `PACKAGE_BINARY_SHA256`, README identity and
verified trusted comment, then requires `install.sh --verify-only` to accept
that internally coherent signed package.

## Validation

```text
bash -n deploy/rollback/make-rollback-package.sh
bash -n deploy/rollback/make-rollback-package.selftest.sh
# passed

bash deploy/rollback/make-rollback-package.selftest.sh
# not run: minisign is not installed in this local environment
```

## Residual boundary

This binds local assembly metadata and the signed manifest to one privately
copied input. It does not prove that a binary's reported stamp is semantically
truthful, authenticate the caller's source path, or establish release-key
custody, artifact-store integrity, scratch-host rehearsal, staged canary,
rollback execution or fleet state. Those remain external release gates and
INF-09 remains `PARTIAL`.
