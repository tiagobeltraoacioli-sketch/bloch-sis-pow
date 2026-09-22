# Wave 78 — KS-11 production KDF pin

Date: 2026-09-19
Base: `9eebe9d`

## Finding

Wave 77 bound explicit high-cost recovery to one reviewed tuple, but an
ordinary open still accepted every header-selected Argon2 tuple inside the
default ceilings. A modified unauthenticated header could therefore select a
different, including weaker, cost before AEAD authentication.

## Remediation

An ordinary passphrase unlock now accepts only the exact production tuple:
65,536 KiB, three passes and one lane. Every other tuple is refused before
salt/ciphertext parsing and before Argon2.

Historical non-production files remain recoverable. The operator must inspect
and independently authenticate the artifact, then provide both the legacy
recovery switch and the exact `BLOCH_KEYSTORE_EXPECT_KDF` tuple. Programmatic
callers using `passphrase_with` likewise bind reads to the exact tuple they
selected. No KDF, AEAD, file-format or new-sealing parameter changed.

## Evidence

- `audit_expensive_kdf_recovery_requires_one_exact_reviewed_tuple`: passed,
  including ordinary refusal of a weaker header before derivation.
- `audit_default_kdf_memory_and_combined_work_are_bounded_before_allocation`:
  passed.
- `audit_new_sealing_rejects_weak_kdf_but_legacy_decryption_survives`: passed;
  default opening refuses the legacy tuple and exact explicit recovery opens
  it.
- `the_binary_reopens_a_sealed_keystore_only_with_the_passphrase`: passed.
- `git diff --check`: passed.

## Residual risk

KS-11 remains `PARTIAL`: the fixed production derivation still deliberately
spends 64 MiB and 192 MiB-passes before detecting a wrong passphrase or an
authenticated-header modification. The legacy override also deliberately
permits a reviewed cost up to the finite historical hard caps.
