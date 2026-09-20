# Wave 189 — INF-09 rollback stamp identity

Date: 2026-09-19
Comparison base: `49abbbd9`

## Reproduced gap

The rollback assembler accepted the caller-supplied stamp when it appeared as
an arbitrary substring anywhere in the complete `--version` output of a
runnable binary snapshot. A truncated version prefix therefore passed, and a
structurally plausible but false stamp could pass when it appeared only on a
later decoy line after a different first-line identity.

This gap is distinct from the snapshot, digest and publication controls in
Waves 109, 137 and 140. Those controls keep package bytes and metadata
internally coherent, but did not constrain which portion of runtime output was
allowed to establish the caller-supplied stamp.

## Correction

Before assembly, the script now requires one canonical stamp token consisting
of an ASCII version atom and a parenthesised 7-to-64-character lowercase
hexadecimal commit identity. Newline and carriage-return input is rejected.
The range preserves current abbreviated and full SHA-1 forms while admitting
a future full SHA-256 object identity without asserting which Git object
format produced it.

When the private binary snapshot is runnable on the assembly host, only the
first `--version` line is considered. That line must contain the complete
validated stamp bounded by ASCII spaces. Existing output such as
`bloch-pos-node <stamp> built-by-selftest` remains compatible, while a prefix,
an embedding inside a larger token, or a later-line decoy cannot satisfy the
check. The existing behavior for a snapshot that cannot run on the assembly
host is unchanged.

## Adversarial coverage

The disposable-key rollback selftest retains its complete digest,
self-mutation, publication, signature/tamper, wrong-key, pasted-signature and
verify-only matrix. It additionally proves that:

- the existing canonical first-line form still assembles and verifies;
- a truncated stamp without its commit identity is rejected structurally;
- a valid-looking stamp present only on the second output line is rejected;
  and
- a valid-looking stamp embedded inside a larger first-line token is rejected.

Every negative case requires a nonzero exit, the specific diagnostic and no
published output.

## Validation

```text
bash -n deploy/rollback/make-rollback-package.sh
bash -n deploy/rollback/make-rollback-package.selftest.sh
# passed

bash deploy/rollback/make-rollback-package.selftest.sh
# failed closed before key generation: minisign is not installed locally

# A focused execution of the production validation/matching expressions passed:
# canonical accepted; truncated, later-line decoy and embedded-token refused.
# This is not claimed as a substitute for the disposable-key selftest.
```

## Residual boundary

This is a local syntax and self-report coherence check, not authentication of
the stamp, binary, signing key, checksum/minisign executable or assembly host.
A runnable malicious binary can still self-report the caller's structurally
valid stamp. If the snapshot cannot execute on the assembly host, the existing
cross-platform compatibility behavior still skips runtime comparison; the
stamp remains carried into the signed package. At this wave's comparison base,
the generated installer printed but did not yet compare that stamp on a
compatible host; Wave 193 closes that subsequent residual.

Real release signing and publication, out-of-band host key pinning, a
scratch-systemd rehearsal, staged N-1 availability, rollback execution and
fleet state remain external release evidence. INF-09 remains `PARTIAL`.
