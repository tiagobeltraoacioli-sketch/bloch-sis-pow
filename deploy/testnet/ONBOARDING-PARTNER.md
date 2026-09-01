# Bloch Genesis-4 public testnet — integrator onboarding

> Delivered privately to integration partners. Placeholders in ⟨angle
> brackets⟩ are filled at deployment; everything else is final.

## Endpoint

| | |
|---|---|
| JSON-RPC | `https://t4rpc.posternlabs.com` (POST, JSON-RPC 2.0) |
| Liveness | `https://t4rpc.posternlabs.com/health` |
| Genesis manifest | `https://t4rpc.posternlabs.com/genesis.blg` (+ `.sha256`) |
| Genesis digest | ⟨sha256 of genesis.blg⟩ |
| Genesis date | ⟨date⟩ — the network resets occasionally; every reset is announced ≥72 h ahead and changes this digest |

No authentication, no API key. CORS is open. Please be reasonable with
polling (the chain moves every 30 s; polling faster than ~5 s gains nothing).

## Chain constants (same as mainnet unless marked)

| Constant | Value |
|---|---|
| Slot | 30 s |
| Epoch | 32 slots = 16 min |
| Finality | ≈ 2 epochs ≈ 32 min (Casper-style justified/finalized checkpoints — there are no "confirmations") |
| Unit | 1 BLCH = 100,000,000 sat |
| Signature suite | hybrid ML-DSA-65 ‖ Falcon-1024 (post-quantum; secp256k1 hardware cannot sign this chain) |
| Account model | eUTXO. An output is locked to `script_hash` = SHA3-256 of the owner's hybrid public key (32 bytes, hex over RPC) |
| Fee | gas × price. gas = 5,000 + tx_bytes×16 + 72,748 per input signature; price = protocol base fee (floor 10 msat/gas, EIP-1559-style) + your tip. On an idle testnet the base fee sits at its floor |
| Validators | 4 (testnet; operated by Postern Labs) — mainnet has 64 |

## Getting test coins

The faucet is a manual drip for now: send your 64-hex `script_hash` and the
amount you need to ⟨contact channel⟩. Typical turnaround: same day. Test
BLCH has no value of any kind.

Generate a key and see your `script_hash` with the node binary
(⟨download/build reference⟩):

```
bloch-pos keygen --dir ./mykey --index 0
bloch-pos spendkey --dir ./mykey        # prints script_hash + pubkey
```

## Withdrawal-flow rehearsal (exchange integration)

1. **Watch balances / select inputs**
   `getbalance(script_hash)`, `getutxos(script_hash[, limit])` →
   `{txid, vout, value_sat}` entries.
2. **Build + sign.** `submit-tx` with `--raw` never touches a network; run
   it anywhere:
   ```
   bloch-pos submit-tx --raw \
     --pubkey <hex from spendkey> \
     --spend <txid>:<vout> \
     --pay <recipient_script_hash>:<sat> \
     --pay <change_script_hash>:<sat> \
     --tx-bytes 9000 --tip 0
   ```
   Without `--signature` it prints the 32-byte **signing root** and stops —
   that root is the external-signer seam; sign it with
   `bloch-pos spendkey --dir ./mykey --sign <root>` or your own signer.
   Inputs minus outputs must cover the fee exactly as priced by the fee
   market. Re-run with identical flags plus `--signature <hex>`: it prints
   the canonical transaction hex **and the txid**. (Changing any flag,
   including `--tx-bytes`, changes the root and voids the signature.)
3. **Submit** over public RPC:
   `sendrawtransaction(hex)`.
4. **Settle.** `gettxout(txid, vout)` on your created output — its
   `finalized: true` is the settlement judgement (~32 min). For crediting
   deposits, poll `getutxos` on your address and apply the same
   `finalized` test via `gettxout`.

There is deliberately **no transaction index**: `gettransaction` is refused
by design, and there is no address-history call. Track outpoints and
balances, not txids-after-the-fact.

Other read methods: `getchaininfo` (height, epoch, justified/finalized
checkpoints, `next_base_fee_millisat_per_gas`), `getblockcount`,
`getblockbyslot`, `getblockbyid`, `getvalidator`, `getvalidatorcount`,
`getmempoolinfo`.

## Validator rehearsal — current honest status

- **Available now, on request:** a *genesis-cohort seat*. At the next
  scheduled reset your freshly generated validator public key is included
  in the genesis validator set and you operate a validator node (connected
  over WireGuard) — key generation, duties, attestation, restart
  discipline, and the inactivity leak are all real.
- **Not yet possible anywhere, including mainnet:** on-chain deposit →
  activation → exit → withdrawal. The node currently refuses staking
  transactions at admission because deposits are not yet funded from the
  UTXO set and exits are not yet authenticated — closing that is a
  consensus wire-format change in progress. When it lands, it activates on
  this testnet **first**, and the lifecycle (MIN_DEPOSIT 25,000 tBLCH,
  activation delay 8 epochs, exit delay 32 epochs, withdrawal delay 2,048
  epochs ≈ 23 days) becomes rehearsable end to end here. We will notify
  partners; no date is promised.

## How this testnet differs from mainnet

| | Testnet | Mainnet |
|---|---|---|
| Genesis | fresh, faucet-funded, **no carryover** | carries the Genesis-3 opening ledger |
| Coins | worthless, faucet-dripped | real BLCH |
| Validators | 4, one operator | 64 |
| Resets | occasional, ≥72 h notice | never |
| TransferV2 (deduped witnesses) | refused until testnet epoch 800 (~9 days after each genesis — activation epochs are absolute) | active |
| Everything else | identical binary lineage: same transition, fee market, signature suite, RPC surface, cadence | — |

## Two safety rules

1. **Never reuse keys across networks.** Spend signatures on this chain
   commit to outpoints, not to a network id. The two networks' outpoints
   are disjoint by construction, so replay is impossible — keep it that
   way: testnet keys are throwaway, mainnet keys never touch testnet
   tooling.
2. Test BLCH is not redeemable, convertible, or transferable to mainnet,
   and nothing here is an offer of anything.
