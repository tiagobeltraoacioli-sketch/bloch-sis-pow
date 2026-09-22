# Wave 50 SR-02: mandatory signer-arrangement pin

Date: 2026-09-18. Starting point: `d914a77`. Scope: node-side weak-subjectivity
trust input, tests and operator documentation. No checkpoint format, signature,
cached anchor, consensus rule, signer key, release or deployment changed.

## Closed local substitution path

A V1 checkpoint signature binds `signer_set_id`, but not the arrangement bytes
selected by that number. The node already supported an independently obtained
SHA3-256 pin over the complete `BPOSWSS1` file, yet accepted an external
checkpoint without it and printed only a warning. An attacker able to replace
both downloads could therefore choose conforming keys, quorum and review clock,
sign its own envelope and pass the shape checks.

External checkpoint onboarding now refuses unless all three inputs are
present: envelope, signer-set file and `--ws-signer-set-sha3`. The fingerprint
is checked before decoding the arrangement or verifying its signatures. A
mismatch remains a typed non-retryable boot refusal. Normal boot from genesis
or a previously verified `ws_latest` needs no new flag and historical bytes are
not reinterpreted.

The CLI parser also treats those inputs as one fail-closed tuple. It rejects
incomplete combinations, duplicate options, option tokens used as values and
weak-subjectivity options placed after `--`. This prevents an operator from
believing a pin or signer set was active when argument parsing had silently
ignored or mis-associated it.

Operator guides now show the mandatory pin and state its real trust boundary:
the fingerprint must arrive through an independent trusted channel. A hash
downloaded beside the same untrusted envelope and signer-set file proves
nothing about their origin. The stale-anchor recovery message and ceremony
publication checklist now name the same complete three-input requirement.

## Status and residual

SR-02 remains `PARTIAL`. This closes the repository's unpinned external-file
path, but the checkpoint V1 digest still commits only the numeric arrangement
ID. No authoritative production fingerprint has been published, and this
change cannot prove independent distribution or adoption. A future versioned
format still needs explicit arrangement-digest binding, authenticated rotation,
downgrade refusal and mixed-version qualification.

## Validation

- The boot regression proves an otherwise valid external arrangement is
  refused without the pin before its checkpoint can be admitted.
- Existing mismatch and review-clock substitution regressions retain their
  fail-closed verdicts.
- Parser regressions cover the complete tuple, incomplete combinations,
  duplicates, option-as-value confusion and the `--` boundary.
- Full focused `ws_boot::tests` and operator-document checks are run during
  Wave 50 integration.
