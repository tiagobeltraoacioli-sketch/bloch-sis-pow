# Wave 87 — CR-07 zeroize repository diversified sub-seed

Date: 2026-09-19
Comparison base: `be16a79`

## Residual addressed

`crypto::diversified_seed` intentionally returns the public API's
caller-owned `[u8; 32]`. Its only repository consumer was
`crypto::diversified_keypair`, which previously passed that returned array as
an ordinary temporary directly into seeded key generation. The per-index seed
therefore had no explicit wiping owner after key generation returned.

A repository-wide consumer search found four production paths converging on
`diversified_keypair`:

- the reference pool miner's indexed payout key;
- wallet selective disclosure;
- HD-wallet address derivation; and
- `crypto::diversified_address`.

## Change and compatibility

`diversified_keypair` now moves the exact returned sub-seed immediately into
`Zeroizing<[u8; 32]>`, without cloning it, and borrows that owner for the
existing `generate_keypair_from_seed` call. The owner wipes its array on
ordinary return and unwind.

The public `diversified_seed` signature and caller-owned return are unchanged.
The SHA3 domain, master-seed input, little-endian index, seeded key-generation
API, public/secret key bytes, addresses and all wallet/disclosure formats are
unchanged.

Evidence is structural: the regression proves the internal owner has drop
behavior, contains the exact public sub-seed, produces the same keypair as the
historical direct call, and supports explicit zeroization while live. It does
not inspect storage after `Drop` or claim to erase the public API caller's
array, master seed, compiler/register copies, or cryptographic-backend state.

## Validation

```text
cargo test -p bloch-crypto \
  diversified_keypair_owns_exact_subseed_under_zeroizing_drop \
  --offline -- --nocapture
# 1 passed; 0 failed; 211 filtered out

cargo test -p bloch-crypto wallet::disclosure::tests \
  --offline -- --nocapture
# 12 passed; 0 failed; 200 filtered out

cargo check --manifest-path pool/Cargo.toml \
  --bin bloch-pool-miner --offline
# passed

cargo test -p bloch-crypto --offline
# sandbox library run: 207 passed; 3 socket-only EPERM; 2 ignored

cargo test -p bloch-crypto wallet::http_rpc::tests \
  --offline -- --nocapture
# outside sandbox: 5 passed; 0 failed; 207 filtered out

cargo test -p bloch-crypto --test acvp_mldsa --offline
cargo test -p bloch-crypto --test falcon_submission --offline
cargo test -p bloch-crypto --test tx_under_dual_and --offline
# integration: 3 + 2 + 1 = 6 passed; 0 failed

cargo test -p bloch-crypto --doc --offline
# documentation: 2 ignored; 0 failed
```

Together these runs cover the complete suite: 210 library tests passed with 2
ignored, 6 integration tests passed, and 2 documentation tests were ignored;
216 passed, 4 ignored and no code failure. The three failures in the initial
library run were solely `EPERM` when its HTTP regressions attempted to bind
loopback sockets inside the sandbox; all five HTTP tests passed outside it.

The crate-wide formatting check remains inapplicable to a focused patch
because the existing crate has extensive unrelated rustfmt drift. Targeted
diff checks are used instead.

## Residual boundary

CR-07 remains `PARTIAL`. Direct external callers of the public
`diversified_seed` function own and must erase its returned array. The master
seed and returned keypair remain caller-owned; disclosure secret keys retain
their existing zeroizing owners. CLI mnemonic input, generation entropy,
`bip39::Mnemonic`, PBKDF2/key-generation internals and compiler/register copies
remain separate residuals.
