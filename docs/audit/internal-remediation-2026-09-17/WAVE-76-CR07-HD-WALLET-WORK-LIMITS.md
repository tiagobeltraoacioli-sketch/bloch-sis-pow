# Wave 76 CR-07: opt-in HD-wallet work limits

Base: `5580070`; branch `fix/internal-audit-20260917`.

## Scope decision

The HD-wallet loader already bounded file bytes, but a caller could not bound
the number of address ciphertexts decrypted and retained or the number of
`derived: true` records rederived from the mnemonic. A new unconditional entry
ceiling would reject a sufficiently large backup that previous releases could
create with repeated `new_address` calls. Recovery compatibility therefore
rules out imposing a new fixed cap on the historical load APIs.

## Change

`HdWalletLoadLimits` and `HdWallet::load_with_limits` provide an explicit,
fail-closed resource policy with three independent counters:

- maximum file bytes;
- maximum total address records; and
- maximum derived-key checks.

The address and derivation counts are checked after the bounded JSON parse but
before mnemonic parsing, the fixed Argon2 master-key derivation, ciphertext
decryption, or diversified PQ-key derivation. Exact bounds are accepted. The
derived-key counter applies only to records marked `derived: true`; imported and
legacy random-key records still consume the total-address allowance but do not
consume a derivation allowance.

`load` and `load_with_file_limit` retain their established behavior, so every
historical backup accepted before this wave remains recoverable. The file
schema, encryption, address derivation, consensus and wire formats are
unchanged.

## Adversarial regressions

The new regression covers exact and one-over boundaries for both counters. It
also sends invalid credentials through the public API and proves that an
over-budget file returns the resource error first, whereas the same file at the
exact boundary proceeds to mnemonic validation.

The first full-suite run also exposed a probabilistic Wave 75 regression. That
test flipped an arbitrary bit in a Falcon secret encoding; some generated keys
placed the bit in representation data that did not change the effective key, so
the supposedly corrupted key could still authenticate. The fixture now uses a
second independently generated, structurally valid raw secret against the first
public key. This pins the intended mismatch deterministically without changing
production signing behavior.

## Validation

- `cargo test -p bloch-crypto --lib hd_wallet::audit_wallet_boundaries::opt_in_load_limits_accept_exact_bounds_and_reject_excess_before_credentials --offline`: 1/1 passed.
- `cargo test -p bloch-crypto --lib hd_wallet::audit_wallet_boundaries --offline`: 7/7 passed.
- `cargo test -p bloch-crypto --lib wallet::legacy_sign_tests::corrupted_legacy_raw_secret_never_authenticates --offline`: 1/1 passed.
- `cargo test -p bloch-crypto --lib --offline`: 196 passed, 0 failed, 2 ignored
  (run outside the filesystem sandbox so HTTP tests could bind loopback sockets).
- `git diff --check` on the two Rust files and this report: passed.

## Residual risk

CR-07 remains `PARTIAL`. Callers must adopt `load_with_limits` to gain the new
aggregate controls; compatibility entry points intentionally retain only their
file-byte bound. JSON parsing occurs before the address counters, although its
input remains byte-bounded. Historical imported records retain their recovery-
safe load policy, and backend/register or caller-owned secret copies remain
outside Rust-side erasure guarantees.
