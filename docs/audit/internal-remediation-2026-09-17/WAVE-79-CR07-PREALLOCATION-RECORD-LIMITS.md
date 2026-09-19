# Wave 79 CR-07: pre-allocation HD-wallet record limits

Base: `6a30397`; branch `fix/internal-audit-20260917`.

## Scope decision

Wave 78 bounded every repository production HD-wallet consumer by input bytes
and record count. The byte budget was enforced while reading, but the complete
`Vec<HdAddress>` and its strings/encrypted blobs were still allocated before
the post-parse record counters rejected the 1,025th address or 257th derived
key. This left avoidable allocation amplification inside the otherwise bounded
ordinary restore and public-listing paths.

## Change

The bounded public reader and `HdWallet::load_with_limits` now run a first-pass
Serde JSON visitor before full deserialization. The visitor retains no address
payloads: it ignores unrelated values, charges each address as soon as its
array element begins, and counts `derived: true` records while walking each
object. It fails immediately on the first excess address or derived-key check,
before allocating that excess record and before mnemonic parsing, Argon2,
decryption or key derivation.

The existing post-parse validators remain as defense in depth. Exact limits,
error text, unknown-field behavior, the HD-wallet schema, cryptography and
trusted compatibility entry points remain unchanged. Duplicate resource fields
are rejected consistently instead of creating ambiguous preflight accounting.

## Adversarial regression

The new regression proves that two records and one derived record are accepted
at their exact limits, while limits one below each boundary fail with the
existing deterministic errors. It then supplies a deliberately truncated third
record after two admitted records. The address-cap error wins before the
malformed excess record is parsed, demonstrating that the record is charged at
entry rather than allocated and inspected first.

The prior authentic 1,024/1,025 public-wallet and 256/257 derived-work boundary
tests continue to pass through the production APIs.

## Validation

- `cargo test -p bloch-crypto json_preflight_enforces_exact_record_limits_before_full_allocation --offline`: passed.
- `cargo test -p bloch-crypto bounded_default_accepts_exact_work_limits_and_rejects_each_excess --offline`: passed.
- `cargo test -p bloch-crypto public_metadata_reader_accepts_exact_bounds_and_rejects_each_excess --offline`: passed.
- `cargo test -p bloch-crypto --offline`: library 199 passed, 0 failed, 2 ignored; integration 6 passed, 0 failed; doc tests 2 ignored. The complete run used the approved unsandboxed test prefix because three HTTP regressions bind loopback sockets.
- `git diff --check` on the wallet source and this report: passed.

## Residual risk

CR-07 remains `PARTIAL`. Historical compatibility loaders and explicit
trusted-backup overrides intentionally allow broader policies, and external
consumers may still select them. Bounded JSON is traversed once for accounting
and once for materialization, so its CPU cost remains proportional to the byte
budget. Opaque crypto-backend/register copies and caller-owned copies remain
outside this correction.
