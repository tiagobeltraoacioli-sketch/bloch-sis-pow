# Wave 77 — KS-11 exact KDF expectation

Date: 2026-09-19
Base: `55d0d67`

## Finding

The bounded legacy-recovery switch prevented unbounded Argon2 parameters, but
`BLOCH_KEYSTORE_ALLOW_EXPENSIVE_KDF=1` still allowed an unauthenticated
keystore header to select any cost inside the broad historical ceiling.

## Remediation

Expensive recovery now requires both:

- `BLOCH_KEYSTORE_ALLOW_EXPENSIVE_KDF=1`; and
- `BLOCH_KEYSTORE_EXPECT_KDF=<memory_kib,passes,lanes>` copied from an
  independently reviewed `keys inspect` result.

The parser accepts exactly three unsigned decimal values, checks them against
the finite historical caps, and binds recovery to that one tuple. Missing,
malformed, extra, out-of-range, or mismatching values fail closed. Header
mismatch is rejected before salt/ciphertext parsing and before Argon2 key
derivation. The setting never changes the cost used for new seals.

The operator runbook also now states the actual ordinary limits: 64 MiB and
196,608 KiB-passes.

## Evidence

- `audit_expensive_kdf_recovery_requires_one_exact_reviewed_tuple`: passed.
- `audit_default_kdf_memory_and_combined_work_are_bounded_before_allocation`:
  passed.
- `the_binary_reopens_a_sealed_keystore_only_with_the_passphrase`: passed,
  including missing expectation, wrong expectation, expectation without the
  opt-in, and valid exact-tuple recovery.
- `git diff --check`: passed.

## Release impact

This closes the source-level unauthenticated cost-selection gap. It does not
satisfy the independent-build, hosted-CI, signing, rollback, WS-envelope, or
staged-rollout release gates and therefore does not make the MW binary ready
for launch by itself.
