# Wave 137 — INF-09 rollback digest contract

Date: 2026-09-19
Comparison base: `9b0e006a`

## Reproduced gap

The rollback assembler copied the first whitespace-delimited field printed by
its SHA-256 tool directly into the generated installer, README, signed trusted
comment and manifest. A tool could exit successfully while emitting a short,
non-hexadecimal or uppercase value, or multiple rows. The command still
continued toward signing and publication; multiple rows could additionally
inject physical lines into generated metadata.

This did not bypass minisign authentication, but it allowed the assembler to
emit a signed rollback package that its own installer could not interpret or
verify canonically. A rollback path must reject such local tool failure before
it produces an artifact operators may mistake for usable recovery evidence.

## Correction

One helper now captures every SHA-256 observation used by assembly, propagates
tool failure, and requires exactly 64 lowercase hexadecimal characters. The
validated value is used for the binary identity, every signed-manifest row and
the final tarball digest report. Manifest hashes are captured before `printf`,
so a failed command substitution cannot be masked by a successful formatter.
The tarball is first created under the private work directory and its digest
is validated there; only then is that same tarball moved to the output
directory and the public key copied beside it.

Canonical package bytes, manifest syntax, installer constants, README,
trusted comment and signature flow are unchanged. Minisign verification and
the out-of-band public-key contract remain the authentication boundary.

## Adversarial coverage

The disposable-key selftest places a controllable `sha256sum` shim first on
`PATH`. Canonical mode delegates to the host implementation and retains the
complete package, tamper and verify-only matrix. Adversarial modes make the
tool exit nonzero or return a short, non-hexadecimal, uppercase or duplicate
digest. A late duplicate-row mode lets the binary hash pass and corrupts a
later manifest observation. A seventh-call mode lets the binary and all five
manifest observations pass, then returns duplicate rows for the private
tarball; the output directory must remain empty. Every case must fail with the
intended diagnostic without publishing a tarball or public-key artifact.

## Validation

```text
bash -n deploy/rollback/make-rollback-package.sh
bash -n deploy/rollback/make-rollback-package.selftest.sh
# passed

bash deploy/rollback/make-rollback-package.selftest.sh
# not run end to end locally: minisign is absent and the selftest fails closed
# before key generation

# A temporary non-signing minisign shim was used only to reach the new SHA
# cases. All seven adversarial cases passed, including an empty output
# directory after malformed private-tarball hashing. The later authentication
# matrix predictably failed under that non-cryptographic shim; this is not
# claimed as a substitute for the complete disposable-key selftest above.
```

## Residual boundary

This validates digest shape and local metadata coherence. It does not
authenticate the checksum executable, PATH, assembler host, source binary,
minisign executable or signing key. Release-key custody, artifact-store
integrity, scratch-systemd rehearsal, staged N-1 availability, rollback
execution and fleet state remain external release gates. INF-09 remains
`PARTIAL`. The final tarball move and adjacent public-key copy are sequential,
not one atomic two-file publication; an output-filesystem failure between them
can still leave a partial publication that operators must discard.
