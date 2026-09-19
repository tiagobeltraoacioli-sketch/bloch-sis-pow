# Wave 111 — BV-09 zeroize V3 PQ-seed digest

Date: 2026-09-19
Comparison base: `4a79a4b`

## Residual addressed

The V3 vault derivation previously finalized its domain-separated SHA-256 into
an ordinary digest value, converted that value to `[u8; 32]`, and only then
wrapped the resulting PQ seed in `Zeroizing`. That repository-owned digest
temporary had no type-level cleanup contract.

The explicit disclosure-policy follow-up from Wave 107 remains complete for
repository production callers: the CLI is the sole product bundle creator and
selects `SingleKeyWallet` explicitly. Remaining calls through the public
compatibility wrapper are test coverage, not implicit production policy.

## Change and compatibility

A private `derive_v3_pq_seed` helper now creates a
`Zeroizing<[u8; 32]>` before SHA-256 finalization and uses `finalize_into` to
write the digest directly into that owner. `derive_vault_keys_v3` receives the
owner directly without an intermediate clone.

The exact domain tag, network byte, caller seed bytes and hashing order are
unchanged. All public APIs, V3 key bytes, restoration behavior and persisted
formats remain unchanged. This does not alter a KDF, RNG flow, consensus rule
or dependency.

## Validation

```text
cargo test -p bloch-pq-vault \
  v3_pq_seed_is_derived_directly_into_zeroizing_owner \
  --offline -- --nocapture
# 1 passed; 0 failed; 48 filtered out

cargo test -p bloch-pq-vault \
  v3_roles_cannot_be_derived_from_the_shared_public_parent \
  --offline -- --nocapture
# 1 passed; 0 failed; 48 filtered out

cargo test -p bloch-pq-vault \
  explicit_restore_preserves_each_existing_derivation_and_refuses_short_seeds \
  --offline -- --nocapture
# 1 passed; 0 failed; 48 filtered out

cargo test -p bloch-pq-vault --offline
# unit: 49 passed; 0 failed; 0 ignored
# documentation: 2 passed; 0 failed; 0 ignored
# total: 51 passed; 0 failed; 0 ignored

cargo test --manifest-path services/pq-shield-api/Cargo.toml --offline
# library: 19 passed; 0 failed; 0 ignored
# binary: 0 tests
# documentation: 0 tests
# total: 19 passed; 0 failed; 0 ignored
```

The new structural regression pins the private helper's zeroizing return type,
checks fixed testnet and mainnet known-answer vectors, and supports explicit
zeroization while each owner is live. Existing regressions exercise V3 role
separation and byte-identical restoration through the versioned dispatcher.
No test claims to inspect storage after `Drop`.

## Residual boundary

BV-09 remains `PARTIAL`. This change covers only the V3 PQ-seed digest owner.
It does not erase the caller-owned input seed, SHA-256 internal state, HMAC/BIP32
temporaries, copyable `Xpriv`/`SecretKey` values, PQ backend state,
compiler/register copies or external storage. Process aborts that skip
destructors remain outside Rust RAII guarantees.
