# Wave 52 KS-11: independent default Argon2 memory ceiling

Date: 2026-09-18. Starting point: `c8ab7c8`. Scope: validator-keystore
resource policy, regression coverage and operator documentation. No keystore
format, ciphertext, KDF output, consensus rule, deployment or live file changed.

## Recovered residual

The earlier KS-11 correction bounded default combined Argon2 work at 1
GiB-pass before allocation. That removed combinations such as 1 GiB × 64
passes, but the product check still admitted `m_cost = 1 GiB, t_cost = 1`.
Because the KDF parameters are stored in the public header, a replaced file
could therefore request a one-GiB allocation before AEAD authentication.

## Local correction

Ordinary keystore opening now applies two independent default budgets before
constructing Argon2:

- at most 256 MiB for any one invocation; and
- at most 1 GiB-pass of combined memory/time work.

Production remains 64 MiB × 3 passes and is byte-identical. The 256 MiB limit
leaves four times the production memory setting for deliberate tuning while
removing the one-pass 1 GiB allocation from normal boot.

The existing `BLOCH_KEYSTORE_ALLOW_EXPENSIVE_KDF=1` recovery path remains the
compatibility escape hatch for an independently verified historical file. It
can restore the original finite hard limits—1 GiB memory, 64 passes and 16
lanes—but still cannot create a new keystore outside the default budgets. The
warning now fires when either the memory ceiling or combined-work ceiling is
being overridden.

The regression constructs Argon parameter objects without executing expensive
derivations. It proves the exact 256 MiB boundary is accepted, 256 MiB + 1 KiB
at one pass is refused by default before decryption, a 256 MiB × 5 workload is
independently refused by the work budget, the explicit recovery path retains
the hard historical bounds, and new sealing cannot use that override.

## Honest boundary

KS-11 remains `PARTIAL`. A deliberately enabled recovery override still trusts
an unauthenticated header enough to allocate up to 1 GiB and perform up to the
original finite CPU/lane limits; operators must use it only for a separately
authenticated legacy file. The default combined 1 GiB-pass budget can still be
slow on constrained hardware. Weak historical KDF settings remain readable for
compatibility and are warned after successful authentication rather than
rejected.

Ledger status and aggregate counts are unchanged.

## Validation

- `cargo test -p bloch-pos-node --bin bloch-pos
  audit_default_kdf_memory_and_combined_work_are_bounded_before_allocation
  --offline`: 1 passed.
- `cargo test -p bloch-pos-node --bin bloch-pos keys::tests --offline`: 33
  passed.
- `cargo test -p bloch-pos-node --test keystore_at_rest --offline`: 5 passed.
- `git diff --check`: passed for this change.
