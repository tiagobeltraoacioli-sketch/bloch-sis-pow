# Build your first Bloch app


> **Historical — Genesis-3.** This describes the proof-of-work chain that
> stopped permanently at height 39,918 on 2026-08-13. The live chain is
> **Genesis-4, proof of stake** (30 s slots, 32-slot epochs, finality by epoch),
> live since 21:31:19 UTC that day; its public read RPC is
> `https://posternlabs.com/g4rpc` and it exposes a different, much smaller
> method set than the one used below. Kept because Genesis-4's opening ledger is
> derived from Genesis-3. It is not what runs.
>
> **The risk disclosure below is superseded, not withdrawn.** "Small,
> low-hashrate, 51%-attackable" was Genesis-3's risk and was true of it. Under
> Genesis-4 the security question is concentration: **all 64 validators are run
> by one entity**, **93.94% of the carryover sits at a single address**, and
> **56.05 B of the 57.15 B BLOCH issued at genesis is held by the founder and
> the Foundation**. One operator can halt the chain and one holder can outvote
> every other. A third party cannot yet join: the transport is a point-to-point
> TCP full mesh with a fixed peer list, no discovery and no authentication, and
> `Deposit`/`Delegate` are refused at every node's mempool. "Ownerless" was
> retracted (ADR-036). Unaudited, not a security, no value claim: all still true.

> **Honesty rails (see [index](index.md) for the full text):** Bloch today is
> **unaudited mainnet-beta**; relaxed PoW (**k=4**) makes work **trivially
> forgeable**; the network is small and **51%-attackable**. Bloch is
> **ownerless, neutral, agnostic** — anyone can build; Postern is one builder
> with no privilege. **BLCH is neutral native gas, never a value/investment
> claim.** Items below are tagged **[exists today]** / **[planned]**.

"Building on Bloch" today concretely means writing an **RPC-integrated
application** — a wallet, payment tool, explorer, indexer, or dashboard — that
talks to a node's JSON-RPC. There is no VM and no SDK to install; the RPC is the
entire public developer surface. **[exists today]**

---

## 1. What you talk to

A Bloch full node (`bloch`) exposes **JSON-RPC 2.0 over HTTP** on a **single
`POST /` endpoint**, default port **`16210`**. **[exists today]**

- **Reads are public** (explorers/dashboards need them).
- **Writes** (`sendrawtransaction`) are rate-limited and *may* require an
  `X-API-Key` header depending on node config. **Localhost bypasses auth.**
- CORS is enabled; request bodies are capped at 1 MiB; there is a per-request
  timeout and a global concurrency limit.

There is **no published client SDK yet [planned]** — you call the RPC directly.
A machine-readable `docs/openapi.yaml` exists in the repo, but generated clients
still need a thin JSON-RPC-envelope wrapper.

## 2. The request / response envelope

Send a standard JSON-RPC 2.0 object. `params` is a **positional array**.

```jsonc
// Request
{ "jsonrpc": "2.0", "id": 1, "method": "getblockcount", "params": [] }

// Response
{ "jsonrpc": "2.0", "id": 1, "result": 12345 }
```

A first call with `curl` against a local node:

```bash
curl -s http://127.0.0.1:16210/ \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getnetworkinfo","params":[]}'
```

`getnetworkinfo` returns chain height, peer count, mempool size, protocol
version, and the `chain` name (`"bloch-sis"`).

## 3. ⚠️ The `result.error` quirk — handle BOTH shapes

Bloch's error reporting is **currently non-standard** and you must code for it:

- **Transport / auth / rate-limit errors** come back the standard way, in a
  top-level `error` object with an HTTP status (`401` unauthorized `-32001`,
  `429` rate-limited `-32002`).
- **Many method-level failures** (bad address, not found, decode failed, etc.)
  come back with HTTP `200` and the failure **inside** `result`, as
  `result.error`:

```jsonc
// "getbalance" with a malformed address — HTTP 200:
{ "jsonrpc": "2.0", "id": 1, "result": { "error": "invalid address" } }
```

This is documented for normalization later, but **today a correct client checks
both places.** A minimal, reusable caller:

```js
async function callRpc(endpoint, method, params = []) {
  const res = await fetch(endpoint, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });

  // 1) Transport / auth / rate-limit errors (standard JSON-RPC "error").
  let body;
  try { body = await res.json(); }
  catch { throw new Error(`HTTP ${res.status}: non-JSON response`); }
  if (body.error) {
    throw new Error(`RPC error ${body.error.code}: ${body.error.message}`);
  }

  // 2) The Bloch quirk: method-level failure inside result.error (HTTP 200).
  const result = body.result;
  if (result && typeof result === "object" && "error" in result) {
    throw new Error(`method error: ${result.error}`);
  }
  return result;
}
```

Every reference app in `examples/` uses exactly this pattern.

## 4. Units and addresses

- **Integer `satoshis` are the truth.** `1 BLOCH = 100,000,000 sat` (1e8). The
  float `bloch` field in responses is **display-only** — never do money math on
  it.
- **Addresses** are bech32-style: `bloch1q…` (mainnet) / `bloch1t…` (testnet),
  40 hex payload + 8 hex checksum. Validate them with `validateaddress` before
  use.

## 5. Reads you can build on today **[exists today]**

| Goal | Method(s) |
|---|---|
| Node / chain summary | `getnetworkinfo`, `getblockcount`, `getdaginfo` |
| Blocks | `getblock`, `getblockbyheight`, `getblockhash`, `getrecentblocks`, `gettxsbyblock` |
| Address balance / UTXOs | `getbalance`, `getutxos`, `getaddressinfo` |
| Address history (paginated) | `listtransactions` |
| Transactions | `gettransaction`, `gettxstatus`, `decoderawtransaction` |
| Mempool / fees | `getrawmempool`, `getmempoolinfo`, `estimatefee`, `estimatefeeadvanced` |
| Validation | `validateaddress`, `validateaddressverbose` |

## 6. The single write: `sendrawtransaction`

Bloch is **UTXO-based**, not account/EVM. To pay someone you:

1. `getutxos` for your address and select inputs (coin selection).
2. Build a `Transaction` (fixed **P2PKH** outputs — no scripting).
3. **Sign** it — a hybrid **Falcon-1024 ‖ ML-DSA-65** post-quantum signature.
4. Broadcast the serialized hex with `sendrawtransaction`.

**You cannot sign a Bloch transaction in a browser.** Signing requires the
reference wallet core (`bloch-wallet` / `bloch-cli`), which is byte-compatible
with the node. The [RPC cookbook](02-rpc-cookbook.md) and the
`examples/payment-builder/` demo show how an app builds and previews the
**unsigned** transaction plan and hands signing to that signer.

## 7. Next steps

- **[RPC cookbook](02-rpc-cookbook.md)** — the top flows, end to end.
- **[What Bloch is / is NOT](03-what-bloch-is-and-is-not.md)** — so you don't
  design against capabilities that don't exist (no VM, no multisig, no
  first-class data-carrier output).
- **[Anchoring quickstart](04-anchoring-quickstart.md)** — if you're building an
  L2 / finality gadget / notary.

---

*Ownerless base · plans not promises · unaudited mainnet-beta · BLCH not a
security. This guide is offered under MIT OR Apache-2.0.*
