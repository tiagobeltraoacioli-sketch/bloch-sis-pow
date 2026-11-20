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
| `sign` | the `review` arguments, `reviewId`, optionally `feeSat` and `changeSat` | `transactionHex`, `txid`, `feeSat`, `changeSat`, `changeScriptHashHex` |
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
- Change goes only to the session's own key, in the ADDRESS form of its
  script hash: the first 20 bytes of SHA3-256(public key), which is what the
  account's `bloch1q...` address encodes, followed by twelve zero bytes. The
  signer computes it from the opened public key; no argument names a change
  destination, a key or a domain. `review` and `sign` state it
  (`changeScriptHashHex`) and the review fingerprint covers it. See "Change
  form" below.
- `MIN_L2_DEPOSIT_SAT <= amount <= MAX_L2_DEPOSIT_SAT`.
- Exact conservation: `inputs = amount + change + fee`, where the fee is
  `fee_market::charge` at the declared size, which reserves the worst-case
  signature (`ADMISSION_PQ_SIGNATURE_MAX`).
- At most 128 inputs, strictly ordered, unique; the tip at or below
  `MAX_TIP_MILLISAT_PER_GAS`; the base fee inside the protocol range; the gas
  ceiling.
- Its own fee ceilings, in `review` and in `sign` (see below): the tip may not
  exceed the base fee (`tip above base fee`) and the whole fee may not exceed
  0.1 BLCH (`fee above signer ceiling`).
- `review` stores a single-use fingerprint of the whole witness-free
  transaction and its pricing context. `sign` consumes it, rebuilds the
  transaction from its own arguments and refuses any difference. `cancel`,
  `lock`, a new `review` and any failed call invalidate it; `lock` drops and
  zeroizes the session's secret key (see "Secret material in memory").
- The signature is drawn until it fits the admission bound
  (`crypto::sign_fitting`), verified before it is released, and the signed
  bytes must decode back to the same transaction with the node's decoder.

## Change form

The node opens an output for a key under two forms (`transition::owns`): the
full 32-byte SHA3-256 of the public key, or the address form (its first 20
bytes and twelve zero bytes). Consensus puts no rule on which one a deposit's
change uses (`apply_l2_deposit` inserts `tx.change.script_hash` as given). The
web wallet's balance view and ordinary Send index only the address form, so
change under the full hash would still belong to the key but would vanish
from the wallet. This signer therefore always pays change to the address
form; there is no option. The node CLI (`l2-deposit prepare`) pays the full
hash; that is the one field where this signer's transaction differs from the
CLI's.

Inputs may be held under either form or a mix: the signer only names
outpoints, and the node accepts both for this key. The committee test spends
one input of each form, checks that the change lands under the address form,
and then spends that change with an ordinary transfer signed by the same key.

An address-form output is protected by 160 bits of preimage resistance, not
256 (the node's own note at `owns`); it is the protection every balance held
at a `bloch1q...` address already has.

## Fee ceilings

The fee is the one value of a deposit that goes to neither the owner nor the
recipient, so the signer bounds it without trusting the page:

1. `tipMillisatPerGas <= baseFeeMillisatPerGas` (`MAX_TIP_PER_BASE_FEE = 1`).
   The base fee is checked by the network: consensus requires exact
   conservation at the including block's base fee, so a wrong one is refused
   there. The tip is checked by nobody. With this rule the fee is at most
   twice what the network itself charges.
2. `feeSat <= 10,000,000` (`MAX_FEE_SAT`, 0.1 BLCH), base plus priority at the
   worst-case size, whatever prices are reported. This bounds the loss even
   if a deposit signed at an inflated base fee later meets a block priced
   there (a signed deposit does not expire).

What the second rule costs a legitimate deposit, with no tip (the test
`the_fee_ceiling_leaves_room_for_congestion` pins this table). The base fee
moves at most 1/8 per block, so the last column is the number of consecutive
completely full blocks needed, from the floor, to pass that price:

| Inputs | Fee at the floor (10) | Highest base fee still signed | Multiple of the floor | Full blocks |
|---|---|---|---|---|
| 1 | 2,140 sat | 46,731 | 4,673 | 76 |
| 2 | 2,874 sat | 34,805 | 3,480 | 73 |
| 8 | 7,273 sat | 13,750 | 1,375 | 65 |
| 16 | 13,139 sat | 7,611 | 761 | 60 |
| 32 | 24,871 sat | 4,020 | 402 | 55 |
| 64 | 48,334 sat | 2,068 | 206 | 49 |
| 128 | 95,262 sat | 1,049 | 104 | 44 |

Above those prices the signer refuses and nothing is signed; the owner can
deposit from fewer outputs or wait. Mainnet has been at the floor. Raising
the ceiling is a new build of the signer.

## Secret material in memory

While a session is open the secret key is in the module's memory; that is
what a session is. After every `nw_call` the WASM artifact:

- has wiped every heap block that was freed (a zeroing global allocator; the
  shared crypto crates free copies of key material without clearing them);
- overwrites the stack below the entry point (896 KiB of the 1 MiB stack),
  where the signature code leaves parts of the key in dead frames;
- overwrites the seeded-RNG slot of `pqcrypto-internals`, which keeps the
  ChaCha20 state keyed with the account seed after key derivation.

Measured on the built artifact by scanning its linear memory
(`review/adversarial-503.mjs`, section 6) after `lock`, after a refused
`open_keypair` and after a refused `open_mnemonic`: no 16-byte window of the
secret key, no key seed, no seed tail, no hex text of the secret and no
mnemonic text remain. Before these measures 1,008 bytes of the Falcon secret
key and the 32-byte key seed remained.

Limits, stated plainly:

- The scan looks for the raw encodings listed above. Values derived from the
  key in another form are not searched for; they lived in freed heap or dead
  stack, which are wiped, but that is by construction, not by measurement.
- A trap (for example a failing `random_get`) ends the call before any wipe.
- Request and reply text passes through the host's own memory, which this
  module cannot clear.

The wallet must therefore still terminate the worker (discard the instance)
after each operation and must not rely on `lock` alone.

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

The artifact is `target/wasm32-wasip1/release/bloch_l2_deposit_wallet_wasm.wasm`
(`$CARGO_TARGET_DIR` is honoured). `build-wasi.sh` maps the build machine's
paths to fixed names (`--remap-path-prefix`: `$CARGO_HOME` to `/cargo`, the
workspace root to `/bloch-sis-pow`) and fails if the artifact still contains
`/Users/`, `/home/`, the Cargo home or the source root. The artifact
therefore carries no account name, and the bytes do not depend on the source
path, the target directory or `CARGO_HOME`; see the report of 2026-11-20 for
the builds that were compared. Ambient `RUSTFLAGS` are replaced by the
script's own.

## Tests

```sh
cargo test --locked --offline -p bloch-l2-deposit-wallet-wasm
cargo test --locked --offline -p bloch-l2-deposit-wallet-wasm --features state-acceptance
cargo test --locked --offline -p bloch-pos-committee --lib --features devnet-l2-deposits wallet_signer
```

- `tests/review_503.rs`, `review/adversarial-503.mjs` and
  `review/mutation-503.py` are the independent review's reproductions
  (2026-11-20): an adversarial run against the built WASM through the real
  ABI (fee ceilings, boundary abuse, zero-entropy host, memory scan), the
  node's verdict on every transaction that run released, and a mutation run
  over `src/lib.rs`.
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
