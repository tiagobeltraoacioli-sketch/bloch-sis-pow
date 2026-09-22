# Wave 86 — CR-07 zeroize repository master-seed consumers

Date: 2026-09-19
Comparison base: `a228c91`

## Residual addressed

`SeedPhrase::to_seed_bytes` and `to_seed_bytes_versioned` intentionally return
the public API's caller-owned `[u8; 64]`. A repository-wide search found two
production consumers of that return value outside `wallet/seed.rs`:

- `Wallet::from_seed_versioned`, where the master seed remains live throughout
  hybrid key generation; and
- the `postern-wallet` disclosure command, where it remains live while one or
  more disclosure keypairs are derived and signed.

Both consumers previously dropped their ordinary stack array without an
explicit wipe. The returned array is sensitive master-seed material, and both
copies are locally owned and removable without changing the seed API.

## Change and compatibility

Both consumers now move the returned array immediately into
`Zeroizing<[u8; 64]>`, without cloning it or allocating another seed buffer.
They continue passing the identical first 32 bytes to wallet key generation or
the identical complete 64-byte slice to disclosure. The public API, BIP39
phrase/passphrase handling, V1/V2 PRFs, 2,048 iterations, derivation outputs,
disclosure schema and CLI behavior are unchanged.

The wrapper wipes its owned array on ordinary return and unwind. Evidence is
structural: this report does not claim to inspect stack storage after `Drop`,
nor to remove compiler, register or cryptographic-backend copies.

## Regression and validation

`wallet_master_seed_consumer_uses_exact_zeroizing_array` checks that the owner
type has drop behavior, derives a direct hybrid keypair from the wrapped bytes,
and proves `Wallet::from_seed_versioned` produces the identical public and
secret outputs. Its explicit wipe assertion establishes `Zeroize` behavior on
the live array without attempting a post-`Drop` read.

```text
cargo test -p bloch-crypto wallet_master_seed_consumer_uses_exact_zeroizing_array --offline -- --nocapture
# 1 passed; 0 failed; 210 filtered out

cargo test -p bloch-crypto wallet::disclosure::tests --offline -- --nocapture
# 12 passed; 0 failed; 199 filtered out

cargo check -p bloch-crypto --no-default-features --features wallet-cli \
  --bin postern-wallet --offline
# passed

cargo test -p bloch-crypto --offline
# library: 209 passed, 2 ignored
# integration: 6 passed
# documentation: 2 ignored
# total: 215 passed, 4 ignored, 0 failed
```

The full suite ran outside the sandbox because HTTP regressions bind ephemeral
loopback sockets. Compiler output contained only the workspace's existing
non-root profile/patch warnings. `git diff --check` passed for the Wave 86
files.

## Residual boundary

CR-07 remains `PARTIAL`. External callers of the public seed-byte APIs still
own and must erase their returned arrays. The CLI's original mnemonic input,
`SeedPhrase`'s canonical phrase, the generation entropy and `bip39::Mnemonic`
backend representation have separate lifetimes. PBKDF2/HMAC/key-generation
internals and compiler/register copies remain opaque. Disclosure's per-index
derived seed and retained wallet keys are separate copies not changed here.
