# Bloch RPC cookbook

> **Honesty rails (full text in [index](index.md)):** unaudited mainnet-beta;
> relaxed PoW (**k=4**) → work is **trivially forgeable**; small,
> **51%-attackable** network. Bloch is **ownerless / neutral / agnostic**;
> Postern is one builder, no privilege. **BLCH is neutral native gas — never a
> value/investment claim.** Recipes below are **[exists today]** unless noted.

Every recipe assumes the `callRpc(endpoint, method, params)` helper from
[Build your first Bloch app](01-build-your-first-bloch-app.md#3-️-the-resulterror-quirk--handle-both-shapes),
which handles the **`result.error` quirk** for you. Endpoint defaults to
`http://127.0.0.1:16210/`.

All examples use these placeholders:

```js
const ENDPOINT = "http://127.0.0.1:16210/";
const ADDR = "bloch1q7b003a342f1529f4943e52181c661b0e34c96d02b71f8b78"; // example
const SAT_PER_BLOCH = 100_000_000n; // 1e8; satoshis are the truth
```

---

## Recipe 1 — Read a balance

`getbalance` takes `[address]` and returns satoshis (truth), a display `bloch`
float, and the UTXO count.

```js
const bal = await callRpc(ENDPOINT, "getbalance", [ADDR]);
// { satoshis: 500000000, bloch: 5.0, utxo_count: 2, address: "bloch1q..." }
console.log(`${bal.satoshis} sat across ${bal.utxo_count} UTXO(s)`);
```

Do money math on `satoshis` (integers), never on `bloch`.

For a richer view including pending mempool deltas, `getaddressinfo [address]`
returns `balance_sats`, `utxo_count`, `pending_incoming`, `pending_outgoing`,
and `pool_role`.

## Recipe 2 — List UTXOs (coin selection input)

`getutxos [address]` returns every unspent output for the address — the raw
material for building a payment.

```js
const u = await callRpc(ENDPOINT, "getutxos", [ADDR]);
// {
//   address, utxo_count, satoshis, bloch,
//   utxos: [ { txid, index, value /* sat */, script_pubkey /* 20-byte P2PKH */ }, ... ]
// }
for (const o of u.utxos) {
  console.log(`${o.txid}:${o.index} = ${o.value} sat`);
}
```

`script_pubkey` is simply `SHA3-256(pubkey)[..20]` — **there are no opcodes**;
outputs are fixed P2PKH.

## Recipe 3 — Validate an address

Always validate before you display, store, or pay an address.

```js
const v = await callRpc(ENDPOINT, "validateaddress", [ADDR]);
// { address, isvalid: true, network: "mainnet", checksum: true }
if (!v.isvalid) throw new Error("refuse to pay an invalid address");
```

`validateaddressverbose [address]` adds the decoded `hash_hex` and `prefix`, and
on failure returns `{ valid: false, reason }`.

## Recipe 4 — Estimate a fee

Simple: `estimatefee` (no params) returns the mempool median feerate.

```js
const f = await callRpc(ENDPOINT, "estimatefee", []);
// { feerate_sats, feerate_bloch, mempool_size, note }
```

Advanced: `estimatefeeadvanced` (no params) returns priority tiers.

```js
const fa = await callRpc(ENDPOINT, "estimatefeeadvanced", []);
// { next_block_sats, medium_priority, slow_priority,
//   mempool_median, mempool_size, recommended_bloch }
const feeRate = fa.medium_priority; // sat, a reasonable default
```

Note: on a near-empty mempool these estimates are naturally soft — treat them as
a floor and add headroom.

## Recipe 5 — Build + broadcast a payment

Bloch is **UTXO + P2PKH**, so a payment is: select inputs → build outputs →
**sign (post-quantum)** → `sendrawtransaction`.

### 5a. Coin selection (pure client logic)

```js
// Pick UTXOs until we cover amount + a fee reserve. Naive largest-first.
function selectCoins(utxos, targetSat, feeReserveSat) {
  const need = targetSat + feeReserveSat;
  const sorted = [...utxos].sort((a, b) => b.value - a.value);
  const picked = [];
  let sum = 0n;
  for (const o of sorted) {
    picked.push(o);
    sum += BigInt(o.value);
    if (sum >= need) break;
  }
  if (sum < need) throw new Error("insufficient funds for amount + fee");
  return { picked, inputSum: sum, changeSat: sum - need };
}
```

The `examples/payment-builder/` demo runs exactly this and prints the unsigned
plan (inputs, outputs, change, fee).

### 5b. Signing — delegate to the reference signer

**You cannot sign in a browser or plain Node.** A Bloch `script_sig` is a
length-prefixed **hybrid Falcon-1024 ‖ ML-DSA-65** signature + pubkey (both
lattice families must verify), `SIGHASH_ALL`. Produce it with the reference
wallet core, which is byte-compatible with the node:

```bash
# The reference CLI does getutxos-based coin selection, builds the tx,
# signs with WalletCore, and broadcasts via sendrawtransaction:
bloch-cli send <from-address> <to-address> <amount-bloch>
```

If you are building your own app, have it hand the unsigned plan to
`bloch-wallet` (or the UniFFI Kotlin/Swift bindings of `WalletCore`) and receive
back the signed raw hex.

### 5c. Broadcast

`sendrawtransaction [rawHex]` is **the single write method**. It returns the
`txid` on success, or (the quirk) `result.error` on failure.

```js
const out = await callRpc(ENDPOINT, "sendrawtransaction", [signedRawHex]);
// { txid: "…" }   (callRpc throws if result.error is present)
console.log("broadcast", out.txid);
```

Common `result.error` values to handle: `"invalid hex"`, `"deserialise failed"`,
`"coinbase not accepted"`, `"UTXO …:… not found"` (already spent / wrong node
view), `"invalid signature at input N"`, `"inputs < outputs"`.

You can dry-run the shape of your bytes first with
`decoderawtransaction [rawHex]`, which decodes without broadcasting.

## Recipe 6 — Track confirmations

After broadcast, poll `gettxstatus [txid]`.

```js
async function waitForConfirmations(txid, target = 1, ms = 5000) {
  for (;;) {
    const s = await callRpc(ENDPOINT, "gettxstatus", [txid]);
    // { status: "pending"|"confirmed"|"final"|"unknown",
    //   in_mempool, confirmations, block_height? }
    if (s.confirmations >= target && s.status !== "pending") return s;
    await new Promise(r => setTimeout(r, ms));
  }
}
```

**Finality is PoW depth**, not BFT (there is no validator set):

| Confirmations | Meaning |
|---|---|
| `0` | in mempool (`status: "pending"`) |
| `1–99` | `confirmed` |
| `100+` | `final` (coinbase-maturity depth) |

Applications wanting strong finality wait for **100+**. But remember the top-of-
page rails: under **k=4** and a low-hashrate network, even deep confirmations
carry **no real security today** — do not treat Bloch confirmations as
settlement for anything of value.

`gettransaction [txid]` gives the full decoded tx plus `block_height`,
`timestamp`, and `confirmations` once mined.

---

## Method quick reference (used above)

| Flow | Method | Params |
|---|---|---|
| Balance | `getbalance` | `[address]` |
| UTXOs | `getutxos` | `[address]` |
| Address detail | `getaddressinfo` | `[address]` |
| History | `listtransactions` | `[address, limit?, startHeight?, endHeight?, offset?]` |
| Validate | `validateaddress` / `validateaddressverbose` | `[address]` |
| Fee | `estimatefee` / `estimatefeeadvanced` | `[]` |
| Decode (dry-run) | `decoderawtransaction` | `[rawHex]` |
| **Broadcast (write)** | `sendrawtransaction` | `[rawHex]` |
| Status | `gettxstatus` | `[txid]` |
| Full tx | `gettransaction` | `[txid]` |

---

*Ownerless base · plans not promises · unaudited mainnet-beta · BLCH not a
security. This cookbook is offered under MIT OR Apache-2.0.*
