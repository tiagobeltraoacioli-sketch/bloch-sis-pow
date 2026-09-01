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
| Fee | gas × price. gas = 5,000 + tx_bytes×16 + 72,748 **per hybrid signature verified**; price = protocol base fee (floor 10 msat/gas, EIP-1559-style) + your tip. On an idle testnet the base fee sits at its floor. Under V1 that is one term per input; under TransferV2 it is one per *owner*, so consolidating many inputs under one key gets materially cheaper once V2 is active |
| Validators | 4 (testnet; operated by Postern Labs) — mainnet has 64 |

## Getting test coins

Generate a key, read its `script_hash`, and ask for a drip. **The
`script_hash` is the identifier this chain uses** — not an address. A native
Genesis-4 key's `script_hash` is `SHA3-256(hybrid pubkey)`, a full 32 bytes,
and it has no address encoding at all.

### Faucet policy

| | |
|---|---|
| Drip | 1 tBLCH (100,000,000 sat) per request |
| Per recipient | one drip per `script_hash` per 24 h |
| Per source IP | 5 requests per hour |
| Global ceiling | 500 tBLCH per rolling 24 h across all requesters |
| Cost | free; test BLCH has no value of any kind |

The per-IP budget is charged on every **attempt**, not on every payout, so a
malformed request still costs you one of the five. The per-recipient cooldown
is charged only on a successful drip.

**Operating status, stated plainly:** the automated faucet service
(`tools/faucet`) is a reference implementation whose limits and policy are
real and tested, but which has **not yet been run against a live node** and
ships with the payout path disabled by default. Until it is commissioned, the
faucet is a **manual drip**: send your 64-hex `script_hash` to
⟨contact channel⟩, typical turnaround same day. Ask for the amount you need
up front — a manual drip has no cooldown, so one larger allocation is easier
for both of us than repeated top-ups.

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

## Does this exercise the same code path as a real mainnet withdrawal?

This is the question the testnet exists to answer, so here is the audited
answer rather than a reassurance. **Yes for the withdrawal path itself, with
three named deltas, none of which touch how a transfer is validated.**

**What is identical — verified, not assumed:**

- **The signing root.** `spend_signing_root` folds the same `DS_SPEND` domain,
  the same fields, in the same order, on both networks. There is no network
  branch in it.
- **Signature verification.** The spend path calls the same hybrid
  ML-DSA-65 ‖ Falcon-1024 verifier as consensus itself — spending an output is
  deliberately exactly as hard to forge as attesting to a block.
- **Admission.** `sendrawtransaction` decodes canonical bytes and verifies the
  hybrid signature **before** the mempool, on both networks, in the same
  function.
- **The state transition and the fee market.** No `if testnet` /
  `if mainnet` branch exists anywhere in transaction validation, the
  transition, or fee pricing. We grepped for it; every hit is a comment.
- **Finality.** `gettxout(txid, vout).finalized` is the same judgement from
  the same Casper-style checkpoint logic.

**Delta X — flag-day epochs are absolute, and a fresh testnet starts at epoch
0.** `TransferV2` (deduplicated witnesses) activates at epoch 800, which
mainnet passed long ago and a fresh testnet reaches after ≈8.9 days. **The
plain V1 transfer path — which is what a withdrawal is — is epoch-independent
and byte-identical from epoch 0.** So an ordinary withdrawal rehearsal is
unaffected. What you cannot rehearse in a new testnet's first nine days is
*witness-deduplicated consolidation*, i.e. sweeping many inputs owned by one
key into one signature. If your withdrawal design depends on that, tell us and
we will point you at a testnet instance that is already past epoch 800.

**Delta Y — binary lineage.** The testnet runs the current development branch;
the mainnet fleet runs an older build. No validation rule differs between the
two, but the bytes are not the same bytes, and the testnet-only CLI helpers
(`spendkey`, `genesis --alloc`, `submit-tx --raw`) are absent from the fleet
build. They are not feature-gated — they simply postdate it. Treat
`submit-tx --raw` as a reference signer, not as the tool you will run in
production; the seam you integrate against is the 32-byte signing root, and
that is stable.

**Delta Z — genesis composition.** Different validator set, different
balances, no carryover. This is the security boundary, not an incidental
difference; see safety rule 1 below and `REPLAY-ISOLATION.md`.

**What NEITHER network can rehearse today.** The staking lifecycle — on-chain
deposit, activation, exit, withdrawal — is refused at admission on mainnet and
testnet alike, because deposits are not yet funded from the UTXO set and exits
are not yet authenticated. If your integration only ever moves coins, this does
not affect you. If you intend to stake, no rehearsal exists anywhere yet, and
we will not pretend otherwise.

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
   commit to **outpoints, not to a network id** — there is no chain id in the
   signing root. Isolation therefore rests on one property: the two networks'
   outpoint sets are disjoint, because this testnet's genesis is funded from
   keys generated here and ingests none of mainnet's ledger. That is a fact
   about how we build the genesis, **not a guarantee the protocol enforces**,
   and we would rather you knew the difference. The full argument, including
   what is machine-checked and what is operational discipline, is in
   `REPLAY-ISOLATION.md` — ask us for it.

   The practical consequence for you: treat testnet keys as throwaway and
   never load a mainnet key into testnet tooling. Key reuse is not what
   would break isolation, but it is what would put you in the blast radius
   if anything else did.
2. Test BLCH is not redeemable, convertible, or transferable to mainnet,
   and nothing here is an offer of anything.
