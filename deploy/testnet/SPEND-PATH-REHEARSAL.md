# The spend path, executed — 2026-09-01

Status: **done, on a chain, not on paper.** This is the record of the run, kept
because the integration book's §7.9 says the spend path "has never run with
production key material" and an exchange will not let a customer withdrawal be
its first execution. It has now run. Throwaway keys, a local four-validator
Genesis-4 testnet, no mainnet material of any kind.

Internal + partner-delivered as a file. Not published.

## What was run

Binary: `bloch-pos`, release, built from `agent/testnet-spendpath`.
Network: `deploy/testnet/local-testnet-up.sh`, 4 validators on loopback, 1 s
slots (mainnet cadence is 30 s; the slot length changes how long you wait, not
what happens). Fresh genesis, **no carryover**, one faucet allocation to a key
generated seconds earlier on the same host.

Genesis block `9953da73…`, manifest digest
`3392a85cb45c32e78f51b3870f701c0d96a24fb6eb892b6d26146a3333d7d2e3`.

### 1. The bring-up script's own three proofs

Production, finality, and a hybrid-signed spend of the genesis faucet output,
with exact fee conservation, agreed by all four nodes and then finalized.
Passed.

### 2. The partner's path, walked by hand over JSON-RPC only

Nothing below touched the devnet transport. Every write went through
`sendrawtransaction`, which is all a remote partner can reach.

| Step | Call | Result |
|---|---|---|
| Key | `bloch-pos keygen` + `spendkey` | `script_hash 544aa7d0…31adfc` |
| Balance before | `getbalance` | `0` |
| Drip | operator ran `faucet-drip.sh` | +1,000 tBLCH |
| Build, offline | `submit-tx --raw` with no `--signature` | signing root `9d39ed88…c509bf` |
| Sign, offline | `spendkey --sign <root>` | 9,158 hex chars, ML-DSA-65 ‖ Falcon-1024 |
| Canonicalise | `submit-tx --raw --signature …` | 8,485 bytes, txid `c90d28ab…33b9e3` |
| Submit | `sendrawtransaction` | `accepted: true` |
| Include | `gettxout(txid, 0)` | `unspent: true`, 25,000,000,000 sat to the payee |
| Settle | `getchaininfo` until finality passed the epoch | settled |

Conservation exact: 100,000,000,000 in; 25,000,000,000 out; 74,999,997,782
change; 2,218 sat fee at the 10 msat/gas floor with `gas = 5,000 + 9,000×16 +
72,748 = 221,748`.

### 3. The reference withdrawal client, on the testnet

`crates/bloch-withdraw`, configured `network: Testnet`, driven by
`examples/testnet_rehearsal.rs` against the live node: `create` → `tick` →
`Submitted` → `AwaitingFinality { landed: Some(0), observed_slot: 1642 }` →
**`Paid { attempt: Some(0) }`**. 31 ticks. The payee's balance moved by exactly
the amount, and all four nodes agreed on it.

This is the client an exchange would integrate, and before this change it could
not run here at all.

## Three things the run found that reading had not

### 1. `gettxout` has no `finalized` field

`ONBOARDING-PARTNER.md` and `HOSTED-TESTNET.md` both told a partner that
`gettxout(txid, vout).finalized` is the settlement judgement. It does not exist:
`txout_json` (`crates/bloch-pos-node/src/rpc.rs`) returns `txid`, `vout`,
`unspent`, `utxo`, `at_slot`. The flag is on `getblockbyslot` /
`getblockbyid`.

`gettxout` also does not report the slot the output *landed* in — `at_slot` is
the head the node answered from.

**The procedure that works, and is sound with today's surface:** poll `gettxout`
until `unspent: true` and keep its `at_slot = S`; then poll `getchaininfo` until
`finalized.epoch > S / 32`; then re-check `gettxout` still says `unspent`. A
reorg that dropped the output shows as `unspent: false`, and once finality has
passed that epoch nothing can reach it.

**Status: documented as a known limitation, not worked around silently.** All
three documents now describe the two-call procedure. Adding `finalized` to
`gettxout` is a change to a published RPC response and belongs to whoever owns
that surface; it is a request, not something to slip in beside a testnet fix.

### 2. `sendrawtransaction`'s `tx_hash` is not the txid

It is SHA3-256 of the canonical bytes — a correlation handle, and no block
commits to it. The response says so in a `tx_hash_note` field, which is good
practice and easy to skim past. Passing it to `gettxout` returns a perfectly
well-formed `unspent: false` that looks exactly like a lost withdrawal. The txid
comes from whatever built the transaction; `submit-tx` prints it on stderr.

### 3. The zero-balance failure, reproduced before it was fixed

On the running chain, with a real funded key:

```
script_hash  544aa7d0022aa9a5950846b267ad77b028066515d9b1ed995032ec665831adfc
  getbalance ->  74,999,997,782 sat

the same key, address-derived (first 20 bytes, zero-extended)
             544aa7d0022aa9a5950846b267ad77b028066515000000000000000000000000
  getbalance ->  0 sat
```

Two hashes, one key, one funded. Nothing errors. This is what a partner would
have reported as "your testnet is broken", and it is why the derivation is now
one function with a guard test around it
(`crates/bloch-pos-committee/src/script_hash.rs`,
`tests/one_script_hash_derivation.rs`).

## Reproducing this

```
cargo build --release -p bloch-pos-node
BLOCH_POS_BIN=target/release/bloch-pos BASE_PORT=19700 RPC_BASE=18700 \
  deploy/testnet/local-testnet-up.sh /tmp/t4 4 1000
BLOCH_POS_BIN=target/release/bloch-pos RPC_PORT=18700 MESH_PORT=19700 \
  deploy/testnet/faucet-drip.sh /tmp/t4 <your script_hash> 1000
cargo run --release -p bloch-withdraw --example testnet_rehearsal -- \
  127.0.0.1:18700 <payee script_hash> 1000000000
deploy/testnet/local-testnet-up.sh /tmp/t4 down
```

Total wall time on one laptop, from nothing: about eight minutes at 1 s slots.
At mainnet's 30 s cadence the same sequence takes roughly two hours, almost all
of it waiting for finality twice.
