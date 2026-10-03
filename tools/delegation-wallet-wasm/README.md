# Local wallet delegation signer

This WASI reactor builds and signs the existing funded delegate (`0x0e`),
undelegate (`0x0f`) and withdrawal (`0x10`) transactions from typed, reviewed
arguments. It directly reuses the current consensus wire encoding, signing roots,
fee calculations and transaction IDs. It does not change protocol gates, submit
transactions, accept arbitrary signing digests or export secret keys.

`open_keypair` and `open_mnemonic` are internal custody operations used only by
the wallet's isolated account worker. The expected canonical account is checked;
V1/V2 mnemonic resolution never chooses a different public key. Mainnet's manifest
domain is pinned. `review` stores a single-use fingerprint of the complete typed
review. `sign` consumes it and rebuilds against fresh context, rejecting changes
to the amount, account, epoch, fee, validator commission or position economics.
`cancel` and `lock` invalidate pending consent; lock zeroizes the secret.

Context is a trusted observer's report, not a cryptographic finality proof.
Withdrawal requires full inactivity, the code's actual 2,048-epoch additional
delay, zero active stake and an observed finalized epoch at maturity. Exit also
requires no earlier exit. Change and withdrawal destinations are always the
owner's native script hash. A withdrawal estimate is not a signed minimum payout:
rewards and losses can change before inclusion. The maximum fee is calculated
with the protocol's maximum hybrid witness length.

## Build

Use the repository-pinned Rust 1.94.1 toolchain and an official WASI SDK 33:

```sh
rustup target add wasm32-wasip1 --toolchain 1.94.1
WASI_SDK_ROOT=/path/to/wasi-sdk-33 sh tools/delegation-wallet-wasm/build-wasi.sh
cargo test --locked --offline -p bloch-delegation-wallet-wasm
cargo test --locked --offline -p bloch-pos-committee --lib wallet_discovery_is_owner_bound
cargo test --locked --offline -p bloch-pos-node --bin bloch-pos delegation_wallet_rpc_is_owner_scoped
cargo test --locked --offline -p bloch-pos-node --test rpc_method_registry
```

The ABI exports `memory`, `nw_alloc`, `nw_free`, and `nw_call`; requests are
`{"method":"review","args":{...}}` and replies are bounded JSON. All context
integers are canonical decimal strings. The wallet verifies the WASM SHA-256
before loading it and terminates/wipes the worker on disposal.

Tests use a published disposable mnemonic and real hybrid signatures. Export
public test vectors with `DELEGATION_WALLET_FIXTURE=/tmp/fixture.json` when running
the tests. Set `DELEGATION_BROWSER_SIGNATURES=/tmp/browser-signatures.json` to
independently verify the three signed results from the wallet browser tests.
Neither fixture operation connects to a network or accesses an existing wallet.

## Observer RPC

`getdelegationwallet(owner_hash, cursor)` accepts a native SHA3-256 public-key
hash and a u32 registry cursor. A page scans at most 512 registry positions and
returns at most 128 matching positions. `next_cursor` may therefore be non-null
even when `positions` is empty. The same committed snapshot includes owner
funding outputs (maximum 128), validators (maximum 512, with truncation flag),
real withdrawal/activation parameters, per-position reward/loss accounting and
the observer's finalized checkpoint. Activation resolution uses the complete
registry once per page. It is not an independent proof or a transaction history.

Clients bracket the snapshot with fresh chain reads, verify domain/owner/rules,
and reject stale, inconsistent or incomplete values instead of replacing them
with zeros. `gettxstatus` observes the consensus transaction ID returned by this
signer. Deployment should target a read observer; there is no need to change
validator consensus parameters to expose this method.
