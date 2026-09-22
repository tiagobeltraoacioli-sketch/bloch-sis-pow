# Wave 75 CR-07: erase the legacy signing wrapper

Base: `708aa80`; branch `fix/internal-audit-20260917`.

## Scope decision

Wave 74 authenticated newly imported HD-wallet keypairs before admission. Applying
the same proof to historical imported records during every load is not yet a safe
compatibility change: hybrid signing consumes randomness and can introduce a new
runtime failure at the only point where an operator is trying to recover an old
backup. It is therefore not a deterministic file-validation rule.

The selected bounded residual is a secret-memory copy in the shared wallet
signer. Pre-envelope wallets store a raw private key. To use the current signer,
`Keypair::sign` constructed an enveloped copy in an ordinary `Cow::Owned<Vec<u8>>`.
Dropping that allocation released it without erasing the full copied secret.

## Change

The modern enveloped-key path still signs the borrowed stored key directly. The
legacy raw-key path now owns its temporary envelope in `Zeroizing<Vec<u8>>`, so
the complete wrapper and copied private-key bytes are overwritten when signing
returns, including error returns and unwinding.

The persistent wallet schema, public API, suite selection, produced signature,
legacy raw/enveloped compatibility paths, consensus and wire formats are
unchanged.

## Adversarial regression

The existing founder-style and raw-secret regressions continue to prove that
valid historical records sign and verify. A new regression corrupts a
correctly-sized raw historical secret while retaining the original public key.
Whether the backend rejects those bytes or emits a signature, the record must
never authenticate under the stored public key. This exercises the same owned
legacy-wrapper branch without weakening verification.

## Validation

- `cargo test -p bloch-crypto --lib wallet::legacy_sign_tests::corrupted_legacy_raw_secret_never_authenticates --offline`: 1/1 passed.
- `cargo test -p bloch-crypto --lib wallet::legacy_sign_tests --offline`: 3/3 passed.
- `cargo test -p bloch-crypto --lib --offline`: 195 passed, 0 failed, 2 ignored
  (run outside the filesystem sandbox so HTTP tests could bind loopback sockets).
- `git diff --check -- crates/bloch-crypto/src/wallet/mod.rs`: passed.

## Residual risk

CR-07 remains `PARTIAL`. Historical imported records retain their recovery-safe
load policy. The cryptographic backends can create internal and register copies
that Rust-side zeroization cannot prove erased; caller-created `Keypair` clones
also remain separately owned until their own drops. The existing file-byte bound
does not provide a separately configurable aggregate address/KDF-work budget.

