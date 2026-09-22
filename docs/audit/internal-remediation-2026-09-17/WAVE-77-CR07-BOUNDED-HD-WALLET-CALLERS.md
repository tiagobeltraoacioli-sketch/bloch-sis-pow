# Wave 77 CR-07: bounded HD-wallet production callers

Base: `55d0d67`; branch `fix/internal-audit-20260917`.

## Scope decision

Wave 76 added independently configurable file, address and mnemonic-derived
key-check limits, but intentionally left adoption to consumers. Repository-wide
search found two production restore call sites. Both are in the retained
Genesis-3 `bloch-cli`: `newaddress` and `importfounder`. No current Genesis-4
binary restores an HD-wallet file.

## Change

`bloch-crypto` now publishes `DEFAULT_HD_WALLET_LOAD_LIMITS` and implements
`Default` for `HdWalletLoadLimits`. The interactive policy admits at most 64
MiB, 1,024 total address records and 256 expensive mnemonic rederivations.
`HdWallet::load_bounded` makes the safe ordinary path difficult for consumers
to misconfigure while leaving the historical compatibility APIs intact.

Both real CLI restore paths now use `load_bounded` by default. Operators can
explicitly select `--allow-large-hd-wallet` for a trusted historical backup;
that recovery-only path uses the existing compatibility loader with its
absolute 512 MiB ceiling and no newly imposed record-count ceiling. A normal
resource-limit error points to this explicit recovery option. The option is
removed by the global argument parser and is never sent to RPC methods.

No file schema, encryption, key derivation, consensus, persistence or wire
format changed.

## Adversarial regression

The new unit regression constructs the default policy's exact 1,024-record and
256-derived-record boundary and proves it is accepted. It then independently
adds the 1,025th total record and marks a 257th derived record, proving each
one-over input is rejected with the precise resource error.

## Validation

- `cargo test -p bloch-crypto bounded_default_accepts_exact_work_limits_and_rejects_each_excess --offline`: focused regression passed.
- `cargo test -p bloch --bin bloch-cli --offline`: 2 passed, 0 failed.
- `cargo test -p bloch-crypto --offline`: library 197 passed, 0 failed, 2 ignored; integration tests 6 passed, 0 failed; doc tests 2 ignored. The successful run was outside the filesystem sandbox because three HTTP tests bind loopback sockets.
- `git diff --check` on the two Rust files and this report: passed.

## Residual risk

CR-07 remains `PARTIAL`. The normal CLI restores are bounded, but downstream
consumers can still select compatibility APIs, and the explicit trusted-backup
override accepts substantially more work by design. JSON parsing still occurs
before record-count checks, although its bytes are bounded. Historical imported
records retain recovery-safe behavior, and backend/register or caller-owned
secret copies remain outside Rust-side erasure guarantees.
