# Wave 193 — INF-09 installer stamp identity

Date: 2026-09-19
Comparison base: `17e7545e`

## Reproduced gap

Wave 189 made rollback-stamp validation fail closed when the private binary
snapshot could execute on the assembly host. Cross-platform assembly retained
the compatibility path that could not run the target binary. The generated
installer authenticated the package and printed the signed `STAMP`, but
`--verify-only` returned success without executing the binary. The apply path
executed the installed binary's `--version` and ignored its output.

A package assembled on an incompatible host could therefore carry a
structurally valid but incorrect stamp and still verify or proceed toward
activation on the compatible target host. The binary bytes remained signed;
the missing property was coherence between those authenticated bytes and the
authenticated self-reported identity.

## Correction

The signed generated installer now embeds the already validated package stamp
alongside its existing signing-key and binary-digest constants. After detached
signature and manifest verification, a private helper:

- requires the selected binary's `--version` command to succeed;
- considers only its first output line;
- requires the complete package stamp bounded by ASCII spaces; and
- hashes the same binary after execution and requires the signed package
  digest, refusing a binary that rewrites itself while reporting its version.

`--verify-only` applies the helper to the authenticated packaged binary before
reporting `PACKAGE VERIFIED`. The apply path copies the binary first and
applies the same helper to the installed copy before reading the old PID or
changing a systemd drop-in. The package schema, signed manifest, stamp format,
binary bytes, service configuration and final `/proc` proof are unchanged.

## Adversarial coverage

The disposable-key harness retains its complete signature/tamper, digest,
publication, self-mutation and verify-only matrix. One signed test binary now
has deterministic runtime modes, allowing pristine copies of the same
authenticated package to prove that:

- the canonical first-line stamp still verifies;
- a nonzero `--version` exit is refused without `PACKAGE VERIFIED`;
- the correct stamp only on a later decoy line is refused;
- the correct stamp embedded inside a larger first-line token is refused; and
- a binary that prints the correct stamp and then rewrites itself is refused
  by the post-execution digest check.

## Validation

```text
bash -n deploy/rollback/make-rollback-package.sh
bash -n deploy/rollback/make-rollback-package.selftest.sh
# passed

# The generated install.sh heredoc, prefixed with representative constants,
# was extracted to stdout and passed `bash -n` independently.

# The generated `verify_binary_identity` helper was extracted and executed
# with command/hash functions for canonical, exit, later-line decoy, embedded
# token and post-version digest-change cases; canonical passed and all four
# adversarial modes failed closed.

bash deploy/rollback/make-rollback-package.selftest.sh
# failed closed before key generation: minisign is not installed locally
# The complete disposable-key/adversarial matrix was therefore not observed
# locally; syntax checks are not claimed as a substitute.
```

## Residual boundary

This binds authenticated bytes to their self-reported stamp; it does not make
that self-description independently authoritative. A malicious but signed
binary can report the expected stamp without representing the claimed source.
The installer trusts its host, shell, checksum/minisign executables and
out-of-band public key. `--version` is trusted to terminate and can have side
effects. An actor able to mutate the extracted package source or privileged
destination paths can still race after the post-execution digest check, and
abort/power loss can leave the pre-systemd installed copy as residue.

Real signing and publication, independent source/builder/tool provenance,
out-of-band host-key pinning, scratch-systemd rehearsal, staged N-1
availability, rollback execution and fleet state remain external release
evidence. INF-09 remains `PARTIAL`.
