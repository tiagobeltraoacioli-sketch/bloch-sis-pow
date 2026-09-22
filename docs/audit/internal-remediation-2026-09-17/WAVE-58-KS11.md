# Wave 58 KS-11: production-bound ordinary Argon2 memory

Date: 2026-09-18. Base: `0c78e38`. Scope: local sealed-keystore resource
policy, its parameter-only regression and this report. No ledger row, file
format, ciphertext, KDF output, consensus rule, deployment or live file changed.

## Correction

An unauthenticated sealed-keystore header previously received an ordinary
one-allocation allowance of 128 MiB before its AEAD tag could authenticate the
file. New keystores use 64 MiB; the additional allocation headroom was not used
by the shipped profile and remained available to every untrusted header.

The ordinary one-allocation ceiling is now exactly production's 64 MiB. The
shipped 64 MiB times three-pass profile remains accepted byte-for-byte under the
existing 192 MiB-pass combined ceiling. A custom or historical keystore above
64 MiB now requires the explicit `BLOCH_KEYSTORE_ALLOW_EXPENSIVE_KDF=1` recovery
route and independently verified provenance. That route retains the finite
1 GiB memory, 64-pass and 16-lane hard caps and cannot authorize a new expensive
seal.

## Regression

The regression constructs Argon2 parameters but performs no expensive KDF. It
pins production memory as the exact accepted ordinary boundary, refuses the
next KiB before allocation, and proves that the former 128 MiB boundary remains
available only through the explicit finite recovery override. Production's
exact combined-work boundary and the absolute hard caps remain covered.

## Validation

- Focused boundary regression: 1 passed, 0 failed.
- Complete `keys::tests` suite: 33 passed, 0 failed.
- `git diff --check`: clean.

## Residual

KS-11 remains **PARTIAL**. An ordinary hostile header can still request one
64 MiB allocation and 192 MiB-pass of work before authentication, material on a
constrained validator host. The recovery opt-in deliberately acts on an
unauthenticated header, so operators must establish provenance before using it.
Authenticated weak historical parameters remain readable with the existing
migration warning; refusing them would create an upgrade-time availability
failure for a valid legacy validator identity.
