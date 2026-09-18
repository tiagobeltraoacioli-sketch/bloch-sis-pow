# Wave 56 KS-11: tighter unauthenticated Argon2 allocation ceiling

Date: 2026-09-18. Base: `4747cd6`. Scope: local sealed-keystore resource
policy, regression and this report. No ledger row, ciphertext, header encoding,
KDF output, key material, consensus rule, deployment or live file changed.

## Correction

Ordinary keystore opening previously allowed one Argon2 allocation of 256 MiB
before the AEAD tag could authenticate the file. The independent combined-work
ceiling was also 256 MiB-pass. A replaced public header could therefore force a
quarter-GiB allocation even though production uses 64 MiB times three passes.

The ordinary one-pass allocation ceiling is now 128 MiB. This retains twice
production's memory parameter and does not change the 256 MiB-pass combined
work ceiling: production at 192 MiB-pass and the explicit 64 MiB times four
boundary remain accepted. Values above 128 MiB are rejected before constructing
Argon2 or allocating its memory.

The explicit `BLOCH_KEYSTORE_ALLOW_EXPENSIVE_KDF=1` recovery route still
accepts independently verified authentic legacy files up to the original
finite 1 GiB memory, 64-pass and 16-lane hard caps. As before, that opt-in does
not authorize expensive new seals.

## Regression

The parameter-only regression executes no expensive KDF. It proves the exact
128 MiB ordinary boundary is accepted, the next KiB is rejected, the former
256 MiB one-pass default now requires the recovery opt-in, production remains
accepted, and the independent combined-work and absolute hard caps remain in
force.

## Validation

- Focused boundary regression: 1 passed, 0 failed.
- Complete `keys::tests` suite: 33 passed, 0 failed.
- `git diff --check`: clean.

## Residual

KS-11 remains **PARTIAL**. A hostile ordinary header can still request a 128
MiB allocation and 256 MiB-pass of work before authentication, material on a
constrained validator host. The recovery opt-in deliberately acts on an
unauthenticated header, so operators must establish provenance before using
it. Authenticated weak historical parameters remain readable with the existing
migration warning; silently refusing them would create an upgrade-time
availability failure for a valid legacy validator identity.
