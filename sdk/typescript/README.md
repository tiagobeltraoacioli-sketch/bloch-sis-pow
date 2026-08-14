# @bloch/sdk — TypeScript client for Bloch

> ## ⛔ Historical — Genesis-3. Read this before the status block below.
>
> **This client targets the Genesis-3 proof-of-work JSON-RPC surface, and that
> chain stopped permanently at height 39,918 on 2026-08-13.** The live chain is
> **Genesis-4, proof of stake** (30 s slots, 32-slot epochs, finality by epoch);
> its public read RPC is `https://posternlabs.com/g4rpc`. Genesis-4 exposes a
> different and much smaller method set (`getblockbyslot`, `getvalidator`,
> `getvalidatorcount`, `getchaininfo`, `listunspent`, …), so most calls this SDK
> makes — `getdaginfo`, `gethashrate`, `getblockbyheight`, `getblocktemplate`,
> `getdifficultyhistory` — have no counterpart on it. Do not point this client
> at the live chain and expect it to work.
>
> Kept because Genesis-4's opening ledger is derived from Genesis-3. It is not
> what runs.

A permissively-licensed (**MIT OR Apache-2.0**) community TypeScript client for
the **Bloch** (Bloch-SIS-PoW) JSON-RPC surface: a typed JSON-RPC 2.0 client, the
core read-method wrappers, address/unit helpers, and a coin-selection +
transaction-builder **scaffold** for Bloch's UTXO / P2PKH model.

> ## ⚠️ Status — read this first (binding)
>
> - **SCAFFOLD, pre-production, UNAUDITED.** This SDK is a community tool, not a
>   finished product. APIs may change; do not depend on it for anything of value.
> - **This SDK has no privileged access** to the protocol. It talks to the same
>   public RPC any third party uses. ("Ownerless" was retracted — see
>   `docs/adr/ADR-036-retract-ownerless-adopt-foundation.md`.)
> - **The security question is concentration, not hashrate.** The old caveat
>   here — relaxed PoW at k=4, work trivially forgeable, the network nascent,
>   low-hashrate and 51%-attackable — described Genesis-3 and was true of it.
>   Under Genesis-4 the risk is different and larger: **all 64 validators are
>   run by one entity**, **93.94% of the carryover sits at a single address**,
>   and **56.05 B of the 57.15 B BLOCH issued at genesis is held by the founder
>   and the Foundation**. One operator can halt the chain and one holder can
>   outvote every other. A third party cannot yet join: the transport is a
>   point-to-point TCP full mesh with a fixed peer list, no discovery and no
>   authentication, and `Deposit`/`Delegate` are refused at every node's
>   mempool. No security is claimed.
> - **BLCH is the native gas** (a neutral protocol utility for paying fees on
>   Bloch) — it is **NOT a value or investment claim**. Nobody promises it will
>   ever have value. **BLCH is not a security.** The "17% founder premine
>   (10-year cliff, 40-year vesting)" disclosed here is Genesis-3 tokenomics V2
>   and no longer describes the supply: under Genesis-4 the founder holds
>   **27.04% of the 100 B cap** (`FOUNDER_TOTAL_BLOCH`, pinned at 2704 bps in
>   `crates/bloch-pos-committee/src/tokenomics_v4.rs`) and the Foundation a
>   further **29.00%**, leaving **1,099,570,620 BLOCH (1.92% of genesis supply)**
>   in third-party hands.
> - **Plans, not promises.** Anything labelled *planned* below does not exist yet.

---

## What exists vs. what's planned

| Capability | Status |
|---|---|
| Typed JSON-RPC 2.0 client (`POST /`, port 16210) | **implemented** |
| Both error shapes: standard `error` object **and** the `result.error` quirk | **implemented** |
| Typed wrappers for the core read methods | **implemented** |
| Address validation (`bloch1q…`/`bloch1t…`, SHA3-256 checksum) | **implemented** |
| Satoshis ↔ BLOCH unit helpers (bigint-safe) | **implemented** |
| Coin selection (largest-first) | **implemented (scaffold)** |
| Unsigned-tx builder for the P2PKH model | **implemented (scaffold)** |
| **Transaction signing** (hybrid Falcon-1024 ‖ ML-DSA-65) | **NOT in this SDK** — provided by WalletCore via the `Signer` interface |
| Canonical broadcast-byte serialization | **NOT in this SDK** — done by WalletCore (byte-compatible with the node) |
| Public testnet + faucet | **planned** (not deployed) |

This SDK is modelled against the **actual node dispatcher** (`src/rpc/mod.rs`),
not only the checked-in `docs/openapi.yaml` — the latter still carries the
pre-rename "Entanglement Layer / ENTL / `ent1q`" naming, whereas the live node
emits `bloch`-suffixed float fields, `bloch1q`/`bloch1t` addresses, and
`chain: "bloch-sis"`. Where they disagreed, the node source won.

---

## Install

```bash
npm install @bloch/sdk   # (once published; for now, build from this directory)
```

Requires **Node 18+** (uses the built-in global `fetch` and `crypto`
SHA3-256 — zero runtime dependencies). Build locally:

```bash
npm install
npm run build      # emits dist/
npm run typecheck  # tsc --noEmit
npm test           # compiles + runs the mocked unit tests
```

---

## Your first app in 20 lines

```ts
import { BlochClient, satsToBloch, isValidAddress } from "@bloch/sdk";

const client = new BlochClient({ url: "http://127.0.0.1:16210" });

const info = await client.getNetworkInfo();
console.log(`chain=${info.chain} height=${info.blocks} peers=${info.peers}`);

const address = "bloch1q....................................................";
if (!isValidAddress(address)) throw new Error("bad address");

const balance = await client.getBalance(address);
console.log(`balance: ${satsToBloch(balance.satoshis)} BLOCH (${balance.utxo_count} UTXOs)`);

const utxos = await client.getUtxoList(address);
console.log(`spendable outputs: ${utxos.length}`);

const fee = await client.estimateFee();
console.log(`suggested feerate: ${fee.feerate_sats} sat`);
```

## Sending a payment (with a WalletCore-backed signer)

This SDK **does not sign** — Bloch's hybrid Falcon-1024 ‖ ML-DSA-65 signatures
and the exact broadcast byte layout are produced by **WalletCore**
(`bloch-crypto` / `bloch-wallet`), which is byte-compatible with the node. You
implement the `Signer` interface over it; the SDK does coin selection and
assembles the unsigned transaction.

```ts
import { BlochClient, buildTransaction, blochToSats, type Signer } from "@bloch/sdk";

const client = new BlochClient();

// Provided by WalletCore — NOT reimplemented here.
declare const walletCoreSigner: Signer;

const from = "bloch1q...sender...";
const utxos = await client.getUtxoList(from);

const { tx, fee, change } = buildTransaction({
  utxos,
  to: "bloch1q...recipient...",
  amount: blochToSats("1.5"),      // satoshis are the truth
  fee: blochToSats("0.001"),
  changeAddress: from,
});

const rawHex = await walletCoreSigner.signToHex(tx);  // WalletCore signs + serializes
const { txid } = await client.sendRawTransaction(rawHex);

const status = await client.getTxStatus(txid);        // "pending" → "confirmed" → "final" (100+)
console.log(txid, status.status, `(fee ${fee}, change ${change})`);
```

---

## Error handling

Bloch reports failures in **two** shapes; the SDK normalizes both into
`BlochRpcError`:

```ts
import { BlochRpcError } from "@bloch/sdk";

try {
  await client.getBlock("not-a-hash");
} catch (e) {
  if (e instanceof BlochRpcError) {
    // e.source === "result-error"  → the non-standard result.error quirk (most method failures)
    // e.source === "jsonrpc-error" → standard JSON-RPC error object (Sprint-M auth / rate limit)
    if (e.isUnauthorized) { /* -32001 / HTTP 401: needs X-API-Key */ }
    if (e.isRateLimited)  { /* -32002 / HTTP 429: back off ~60s */ }
    console.error(e.method, e.message);
  }
}
```

`BlochTransportError` is thrown for network failures, non-JSON bodies, and
non-2xx responses that don't carry a JSON-RPC error.

---

## Covered RPC methods

Chain: `getnetworkinfo`, `getblockcount`, `getmempoolinfo`, `getdaginfo`,
`getpeerinfo`, `getpeers`. Blocks: `getblockhash`, `getblock`,
`getblockbyheight`, `getrecentblocks`, `gettxsbyblock`. Transactions:
`gettransaction`, `gettxstatus`, `decoderawtransaction`, `getrawmempool`.
Addresses: `getbalance`, `getutxos`, `getaddressinfo`,
`getaddressbalance_at_height`, `listtransactions`, `validateaddress`,
`validateaddressverbose`. Broadcast: `sendrawtransaction`. Fees:
`estimatefee`, `estimatefeeadvanced`. Analytics: `getchainstats`,
`gethashrate`, `getsupplydistribution`, `getdifficultyhistory`,
`getblocktimepercentiles`, `getmempoolstats`.

Any method not yet wrapped (e.g. `getblocktemplate`, `submitblock`,
`getattestation`, `getpools`) is still reachable via the low-level
`client.call<T>(method, params)`.

## Notes & known caveats (from the node, not invented)

- **Units:** integer satoshis are the truth (1 BLOCH = 10⁸ sat); float `bloch`
  fields are display-only. The helpers keep values in `bigint`.
- **Finality is PoW depth:** `0` = mempool, `1–99` = confirmed, `100+` = final
  (coinbase maturity). Wait for 100+ for strong finality.
- **No multisig / no script system:** outputs are strictly single-signature
  P2PKH; `script_pubkey` is literally the 20-byte hash.
- **`listtransactions`** depends on the address-history indexer, which **does
  not roll back on reorg** today — a documented limitation.
- **`getchainstats.avg_block_time_secs`** can report spurious values on
  out-of-order DAG timestamps (node v0.5.9 known issue).

## License

Dual-licensed under **MIT OR Apache-2.0**. See `LICENSE-MIT` and
`LICENSE-APACHE`. Contributions are accepted under the same dual license.
