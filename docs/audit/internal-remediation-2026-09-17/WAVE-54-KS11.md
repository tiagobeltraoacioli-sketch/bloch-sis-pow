# Wave 54 KS-11: tighter default Argon2 work ceiling

Date: 2026-09-18. Base: `db7b737`. Scope: local sealed-keystore resource
policy, regression and audit ledger only. No ciphertext, header encoding, KDF
output, key material, consensus rule, deployment or live file changed.

## Correction

The default open path already rejected a single Argon2 allocation above 256
MiB, but separately allowed 1 GiB-pass of combined memory/time work. A replaced
unauthenticated header could therefore ask the node to repeat the maximum 256
MiB allocation four times before AEAD authentication rejected the file.

The ordinary ceiling is now 256 MiB-pass. This is above the production setting
of 64 MiB times three passes (192 MiB-pass) and permits 64 MiB times four passes,
128 MiB times two, or one 256 MiB pass. A request above that combined work is
rejected before Argon2 construction or allocation.

The explicit `BLOCH_KEYSTORE_ALLOW_EXPENSIVE_KDF=1` recovery path retains the
original finite 1 GiB memory, 64-pass and 16-lane hard caps. It remains intended
only for an independently verified authentic legacy file, and it still cannot
authorize an expensive new seal.

## Regression

The parameter-only regression does not execute an expensive KDF. It proves:

- production parameters remain accepted;
- the exact 64 MiB times four boundary is accepted;
- one additional pass is rejected by the ordinary path;
- the same legacy parameters remain constructible only with the explicit
  recovery opt-in;
- the independent 256 MiB allocation boundary and original hard caps remain.

## Residual

KS-11 remains **PARTIAL**. The recovery opt-in acts on KDF values in an
unauthenticated header, so an operator must establish file provenance before
using it. The ordinary path may still allocate 256 MiB once, which is material
on constrained hardware. Authenticated weak historical parameters remain
readable and produce a migration warning; silently refusing them would turn a
valid legacy validator identity into an upgrade-time availability failure.
