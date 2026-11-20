# Local wallet signer for the native L2 deposit

This WASI reactor builds and signs the L1 `L2Deposit` transaction (wire tag
`0x14`): native BLCH escrowed on L1 for a 20-byte EVM recipient on the Bloch
L2. It reuses the consensus types directly (`L2Deposit`, `FundingInput`,
`TransferOutput`, `PosTransaction`, `fee_market::charge`,
`ADMISSION_PQ_SIGNATURE_MAX`), so the wire encoding, the signing root, the fee
and the txid are the node's own code, as in `bloch-pos l2-deposit prepare` and
`sign` (`crates/bloch-pos-node/src/l2_deposit_cli.rs`). It does not submit
transactions, change protocol gates, sign caller-supplied digests or export
secret keys.

It is modelled on the delegation signer (`tools/delegation-wallet-wasm`,
commit `46e2f4d2`): the same ABI, the same account opening, the same
single-use review.

## ABI

Exports `memory`, `nw_alloc`, `nw_free`, `nw_call`. A request is
`{"method": M, "args": {...}}`; a reply is `{"ok":true,"result":{...}}` or
`{"ok":false,"error":"..."}`, bounded to 2 MiB.

| Method | Arguments | Reply |
|---|---|---|
| `open_keypair` | `domainHex`, `publicKeyHex`, `secretKeyHex` | `publicKeyHex`, `ownerHashHex`, `domainHex` |
| `open_mnemonic` | `domainHex`, `publicKeyHex`, `mnemonic` | the same |
| `review` | `recipientHex`, `amountSat`, `inputs`, `baseFeeMillisatPerGas`, `tipMillisatPerGas` | `recipientHex`, `amountSat`, `feeSat`, `changeSat`, `txBytes`, `inputCount`, `reviewId`, and `baseFeeSat`, `priorityFeeSat`, `totalInputSat`, `baseFeeMillisatPerGas`, `tipMillisatPerGas`, `ownerHashHex`, `changeScriptHashHex`, `domainHex`, `txid` |
| `sign` | the `review` arguments, `reviewId`, optionally `feeSat` and `changeSat` | `transactionHex`, `txid`, `feeSat`, `changeSat` |
| `cancel` | none | `cancelled` |
| `lock` | none | `locked` |

- `domainHex` must equal the pinned mainnet domain. `open_mnemonic` derives the
  V1 legacy PBKDF2 seed first (the production web wallet's scheme), then V2;
  the expected `publicKeyHex` decides and no other account is ever selected.
- `recipientHex`: 40 hex characters, no `0x`, not zero. Either case is
  accepted (EIP-55 is the page's check); replies are lowercase.
- `amountSat`, the two prices, `feeSat`, `changeSat`: canonical decimal strings.
- `inputs`: 1 to 128 rows `{txidHex, vout, valueSat}`, optionally
  `scriptHashHex`. `vout` and `valueSat` are a canonical decimal string or a
  JSON unsigned integer. The signer sorts the rows and refuses duplicates.
- Unknown fields are refused (`unsupported field`).

## Rules the signer enforces itself

- The network domain is pinned in the code (`DOMAIN`); a test recomputes it
  from `genesis/mainnet.manifest`.
- Change goes only to SHA3-256 of the session's public key. No argument names
  a change destination, a key or a domain.
- `MIN_L2_DEPOSIT_SAT <= amount <= MAX_L2_DEPOSIT_SAT`.
- Exact conservation: `inputs = amount + change + fee`, where the fee is
  `fee_market::charge` at the declared size, which reserves the worst-case
  signature (`ADMISSION_PQ_SIGNATURE_MAX`).
- At most 128 inputs, strictly ordered, unique; the tip at or below
  `MAX_TIP_MILLISAT_PER_GAS`; the base fee inside the protocol range; the gas
  ceiling.
- `review` stores a single-use fingerprint of the whole witness-free
  transaction and its pricing context. `sign` consumes it, rebuilds the
  transaction from its own arguments and refuses any difference. `cancel`,
  `lock`, a new `review` and any failed call invalidate it; `lock` zeroizes
  the secret.
- The signature is drawn until it fits the admission bound
  (`crypto::sign_fitting`), verified before it is released, and the signed
  bytes must decode back to the same transaction with the node's decoder.

## What the signer cannot know

The input values and the base fee are the page's report, not a proof.
Consensus requires exact conservation at the including block's base fee and
the deposit carries no maximum base fee: a wrong input value, or a base fee
that moved before inclusion, makes the node refuse the transaction
(`L2DepositReject::Conservation`). Nothing is spent in that case; review and
sign again with fresh values (`getchaininfo.next_base_fee_millisat_per_gas`).

## The L2 protocol fee (not in this signer)

This signer targets the node deployed on mainnet (`0067547f`). The December
line adds an L2 protocol fee behind `params::L2_REVENUE_EPOCH` (inert,
`u64::MAX`): from that epoch the inputs must also pay
`l2_revenue::deposit_fee_sat(amount)` (5 bps, floor 5,000 sat, cap 1 BLCH),
created as output 2 for the treasury. The wire format and the signing root do
not change. A deposit from this signer would then be short by that fee and be
refused with `L2DepositReject::Conservation`, at the mempool door and in the
transition; nothing would be spent. Before that epoch is armed the signer
must be rebuilt on that line, take the including block's epoch (or the fee
state from `getchaininfo.hard_forks.l2_revenue`), subtract the protocol fee
from the change and show it in the review.

## Build

Use the repository-pinned Rust 1.94.1 and an official WASI SDK 33.0:

```sh
rustup target add wasm32-wasip1 --toolchain 1.94.1
WASI_SDK_ROOT=/path/to/wasi-sdk-33.0 sh tools/l2-deposit-wallet-wasm/build-wasi.sh
```

The artifact is `target/wasm32-wasip1/release/bloch_l2_deposit_wallet_wasm.wasm`.
The build is deterministic for a fixed source and Cargo home path; the paths
are embedded in panic strings, so another path gives other bytes.

## Tests

```sh
cargo test --locked --offline -p bloch-l2-deposit-wallet-wasm
cargo test --locked --offline -p bloch-l2-deposit-wallet-wasm --features state-acceptance
cargo test --locked --offline -p bloch-pos-committee --lib --features devnet-l2-deposits wallet_signer
```

- The first runs the known-answer test (decode with
  `PosTransaction::from_canonical_bytes`, the node's txid, the real hybrid
  signature under `bloch_crypto::crypto::verify`, field by field against the
  CLI's construction) and every refusal.
- `state-acceptance` adds the node's own preflight,
  `CommittedState::l2_deposit_refusal_at` (the mempool door, sharing
  `check_l2_deposit` with the transition), on a committed state bound to the
  mainnet domain. The feature enables the committee's `devnet-l2-deposits`
  for the test build only; `L2Deposit::validate_shape` is private at this
  commit and is exercised through that function.
- The committee test applies the committed fixture in a block through the real
  transition with the real hybrid verifier.

Tests use the published BIP39 test mnemonic. With
`L2_DEPOSIT_WALLET_FIXTURE=/path/fixture.json` the tests write the public
fixture (`fixtures/l2-deposit-fixture.json` is a committed copy). To check the
built WASM itself:

```sh
node tools/l2-deposit-wallet-wasm/replay-fixture.mjs <wasm> tools/l2-deposit-wallet-wasm/fixtures/l2-deposit-fixture.json /tmp/signed.json
L2_DEPOSIT_BROWSER_SIGNATURES=/tmp/signed.json cargo test --locked --offline -p bloch-l2-deposit-wallet-wasm committed_fixture
```

Neither operation connects to a network or opens an existing wallet.
