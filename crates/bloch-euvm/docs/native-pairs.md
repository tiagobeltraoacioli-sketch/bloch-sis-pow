# Native asset pairs v1

Status: executable Ustav reference-kernel extension, **not activated in Genesis-4**.
This is atomic bilateral settlement (an exact, jointly signed exchange), not an
AMM, matching engine or a live Postern order book. EVM pool contracts remain a
separate L2 integration.

## Asset and stablecoin scope

`ustav::pairs` settles two registered Ustav assets without an EVM representation
or bridge between them. `Ledger::pair(a, b)` requires both assets in the current
ledger and returns a canonical, network-bound market identity. Reversing the
arguments produces the same identity. There is no mutable pool registry, reserve
custodian, LP token or market administrator in this extension.

A future native stablecoin can use Ustav's registration and Supply module:
capped issuer-authorized minting, emission nonces, holder/issuer-authorized
burning, and optional PQ Governance, transfer policy or KYC. Pair settlement
preserves those policies. It never mints or burns either traded asset.

Issuing a token and allowing it to trade does **not** establish a stable value.
Reserve custody, liability accounting, denomination/decimals, mint eligibility,
redemption, attestations and the intended peg remain issuer/product design work.
Crypto-backed issuance additionally needs reviewed collateral valuation and
liquidation rules. The example is illustrative and implements none of those
economic guarantees. No production stablecoin has been issued.

The all-zero native BLCH asset ID is explicitly refused: base-coin balances are
not part of the registered Ustav ledger. BLCH/stablecoin settlement needs a
reviewed atomic connection to the Genesis-4 base-coin ledger. Registering another
token called BLCH does not provide that connection.

## Authorization and execution

1. Build two ordinary Ustav transfer `Transaction`s, sorted by ascending asset
   ID. Each names actual inputs, exact output recipients and amounts, current
   policy revision and inclusive expiry height. Change is explicit.
2. Construct `PairSwap { legs: [leg0, leg1] }`. Both legs must have inputs and
   outputs, zero supply delta and zero mint nonce.
3. Obtain `swap.signing_hash(ledger.domain())`. **Every input owner and every
   applicable module authority signs this joint hash**, using ML-DSA-65 AND
   Falcon-1024. Signers review both legs. Connection grants no spending approval.
4. Call `Ledger::settle_pair` with two witness sets, authenticated host height,
   the native verifier and one total gas budget.
5. Consume the receipt only on success. Expiry, revocation, KYC, invalid
   signatures, conservation failure, collisions or insufficient gas reject the
   entire operation; neither leg commits alone.

The private verifier maps only the two native leg digests to the joint digest.
It delegates PQ key validation and verifies every applicable signature against
that joint digest. It has no ECDSA entry point, signature exemptions, synthetic
pool owners or fallback to standalone transfer signatures. Joint authorization
cannot authorize an isolated leg, and independently authorized transfers cannot
be combined without joint authorization.

Pricing is the exact exchange ratio the parties approve. This is a settlement
primitive beneath RFQ or an order book; it provides no price discovery, slippage
calculation or implied 1:1 rate. Consuming either funding input elsewhere prevents
bundle settlement. Expiry is inclusive, as in Ustav v3.

## Atomicity, limits and state

The kernel stages only two token records and referenced UTXOs, checks global
output collisions and final output capacity, validates both transfers, then
commits their changes together. It never clones unrelated balances. Per-leg
ceilings bound work at 256 combined inputs and 256 combined outputs. Native
witness and charter bounds remain in force. Gas covers staging and both native
validations; the second leg receives only the remaining budget. These are
reference gas units, not a mainnet fee schedule.

The receipt contains market identity, joint authorization digest, both native
receipts and total gas used. Outpoints retain each leg's native transaction hash
and output index. Input consumption prevents replay. No mutable ledger field or
snapshot format is added: trusted-root restoration preserves the resulting state.

## Canonical encoding

Let `H` be double SHA-256 and `B(x) = len(x):u64_le || x`.
Fixed hashes are 32 bytes. Pair version is 1; native kernel version remains 3.

```text
pair_id = H(B("USTAV-PAIR-v1") || domain || kernel:u32_le || version:u32_le
            || smaller_asset_id || larger_asset_id)
swap_hash = H(B("USTAV-PAIR-SWAP-v1") || pair_id || leg0_hash || leg1_hash)
```

Each leg uses the existing Ustav transaction encoding, binding every input,
output, policy revision and expiry. Asset IDs bind immutable charters and the
ruleset. Witnesses and token symbols do not enter market identity. Independent
Python-derived hash vectors are pinned in `tests/native_pairs.rs`.

## Validation and activation boundary

```sh
cargo +1.94.1 test --locked -p bloch-euvm -p bloch-ustav
cargo +1.94.1 run --locked -p bloch-ustav --example native_pair
python3 scripts/check-ustav-pq-boundary.py cargo +1.94.1
```

Deterministic adversarial tests cover joint authorization, rollback, replay,
domain separation, policy gates, gas exhaustion, input identity and conservation.
`bloch-ustav` tests also use real hybrid signatures, forged components and module
authority signatures. The example holds ephemeral keys in memory and exchanges
an illustrative native stablecoin and another asset locally.

Activation requires an operation/witness wire format, a block-level commitment
to the complete bundle, consensus dispatch as **one atomic operation**, state
persistence/reorg rollback, mempool admission, fee funding, RPC/indexer support,
PQ-wallet review/signing, testnet qualification and independent audit. Broadcasting
the two legs separately cannot implement this operation. This change supplies
none of those node integrations or an activation height.

The generic EUVM batcher is a separate AMM arithmetic reference. A permissionless
Ustav AMM still needs a reviewed pool-ownership/covenant model, LP accounting and
reserve-continuation rules compatible with native policies. MetaMask connection
supports the EVM L2; it does not authorize this L1 operation.

## Local validation — 2026-09-14

- Pinned Rust 1.94.1 full EUVM/Ustav suite: 400 tests passed, zero failed;
  four existing documentation examples remain ignored.
- Release transition/crypto suites: 52 tests passed, zero failed.
- Pair-specific coverage: 11 deterministic adversarial tests and three actual
  hybrid-cryptography integration tests, passing in debug and release.
- `bloch-ustav` all-target Clippy with warnings denied and the native PQ
  dependency-boundary check passed. Existing workspace profile/patch notices
  remain unrelated to this change.
- The native-pair example executed locally; new Rust files pass rustfmt.

These results do not qualify network activation, provide an independent audit,
or demonstrate collateral backing or stablecoin redemption.
