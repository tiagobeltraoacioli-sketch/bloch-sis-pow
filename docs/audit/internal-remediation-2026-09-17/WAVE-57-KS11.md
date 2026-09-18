# Wave 57 KS-11: production-bound ordinary Argon2 work

Date: 2026-09-18. Base: `ab06afc`. Scope: local sealed-keystore resource
policy, its parameter-only regression and this report. No ledger row, file
format, ciphertext, KDF output, consensus rule, deployment or live file changed.

## Correction

An unauthenticated sealed-keystore header previously received an ordinary
combined Argon2 allowance of 256 MiB-pass before the AEAD tag could authenticate
the file. New keystores use 64 MiB for three passes, or 192 MiB-pass; the fourth
pass was unused tuning headroom exposed to every untrusted header.

The ordinary combined-work ceiling is now exactly the shipped 192 MiB-pass
profile. Production remains accepted byte-for-byte. A custom or historical
keystore above that budget now requires the explicit
`BLOCH_KEYSTORE_ALLOW_EXPENSIVE_KDF=1` recovery route and independently verified
provenance. That route retains the finite 1 GiB memory, 64-pass and 16-lane hard
caps and still cannot authorize an expensive new seal.

## Regression

The regression constructs Argon2 parameters but performs no expensive KDF. It
pins production as the exact accepted ordinary work boundary, refuses the next
64 MiB pass before allocation, and proves that the former boundary remains
available only through the explicit finite recovery override. The independent
128 MiB one-allocation ceiling and absolute hard caps remain covered.

## Validation

- Focused boundary regression: 1 passed, 0 failed.
- Complete `keys::tests` suite: 33 passed, 0 failed.
- `git diff --check`: clean.

## Residual

KS-11 remains **PARTIAL**. An ordinary hostile header can still request one
128 MiB allocation and 192 MiB-pass of work before authentication, material on
a constrained validator host. The recovery opt-in deliberately acts on an
unauthenticated header, so operators must establish provenance before using it.
Authenticated weak historical parameters remain readable with the existing
migration warning; refusing them would create an upgrade-time availability
failure for a valid legacy validator identity.
