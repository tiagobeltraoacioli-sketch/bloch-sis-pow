<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Bloch (BLCH) — Exchange Integration Specification

> **The chain you integrate against is Genesis-4, proof of stake.** Genesis-3,
> the proof-of-work chain, **stopped permanently at height 39,918 on
> 2026-08-13**. Genesis-4 has been live since **21:31:19 UTC on 2026-08-13**:
> 30 s slots, 32-slot epochs, finality by epoch. **Sections §2–§8 and §12–§13 of
> this document are a measurement record of the halted Genesis-3 chain**, kept
> because Genesis-4's opening ledger is derived from it and because the address
> format, key material and balances carried across unchanged. They are not what
> runs. The sections that describe the live chain are **§0, §1, §5, §9, §10 and
> §11**.

```
Document:   BLOCH-EXCHANGE-INTEGRATION
Audience:   Exchange integration, custody and risk teams
Status:     Partner document — NOT for publication. Deliver as a file.
Measured:   Genesis-3 sections measured 2026-08-13 against the then-live
            Genesis-3 node, before the halt. Genesis-4 sections revised
            2026-08-14 against the source of the running node.
Endpoints:  https://posternlabs.com/g4rpc   (Genesis-4, live, public read)
            https://g2rpc.posternpool.com/  (Genesis-3 — chain halted)
            https://blochl1.com/rpc         (Genesis-3 — chain halted)
Source:     crates/bloch-pos-node/, crates/bloch-pos-committee/,
            crates/bloch-crypto/ (Genesis-3), src/rpc/mod.rs (Genesis-3)
```

Every Genesis-3 fact in this document was produced by calling that node while it
was still producing blocks, not by transcribing an existing document. Where it
disagreed with `docs/API.md` or `docs/openapi.yaml`, it won, and the
disagreement is recorded in **§12**. Section **§13** lists what was *not*
verified, so you know the edges of this document's authority.

---

## 0. Read this first — three things that will change your plan

**0.1 — Genesis-3 is over. Do not build against it.**

Genesis-3 stopped permanently at **chain height 39,918** on 2026-08-13. It
produces no further blocks, and every RPC method in **§4** is a record of a
chain that no longer advances. What carried forward is the *address format*, the
*key material* and the *balances*, which crossed into Genesis-4 through the
snapshot (**§10**).

| Quantity | Value |
|---|---|
| Genesis-3 terminal chain height | **39,918** (`CARRYOVER_MEASURED_HEIGHT`, `crates/bloch-pos-committee/src/tokenomics_v4.rs:222`) |
| Genesis-3 terminal block count (DAG) | 50,690 |
| Carried outputs | **452,726** (`CARRYOVER_MEASURED_UTXOS`, same file:224) |
| Genesis-4 start | **21:31:19 UTC, 2026-08-13** |

Note the two numbers in the first two rows: **39,918 is a chain height and
50,690 is a DAG block count, and they are not the same measurement.** Genesis-3
was a DAG, so more blocks existed than the selected chain was tall. Older
revisions of this document and of `tokenomics_v4.rs` quoted "height 43,172",
which was in fact a *block count* mislabelled as a height — the chain was never
43,172 blocks tall. The doc comment on `CARRYOVER_TOTAL_BLOCH`
(`tokenomics_v4.rs:164-179`) records the error rather than quietly fixing it.
Both measurements are now stated separately everywhere they appear.

Our recommendation, stated plainly: **build against Genesis-4.** §11 states what
exists on it today and what does not.

**0.2 — Under Genesis-4 there is no confirmation count, and asking for one is
the wrong question.** Depth is not security on a chain with no difficulty: there
is no work to price a reorg in. The guarantee is **Casper finality**, and the
node hands you exactly one boolean for it. Credit on that boolean and on nothing
else. **§5** states the rule and the code that implements it.

**0.3 — No HSM on the market can hold these keys.** BLCH signing is
ML-DSA-65 ‖ Falcon-1024, on Genesis-4 as it was on Genesis-3. If you custody
BLCH, you custody it with a software key. This is a consequence of being
genuinely post-quantum, not a defect, but your custody team will hit it on day
one. **§9** states the position without softening it.

**0.4 — A third party cannot yet run a node on this network, and cannot yet
stake.** The live transport is a point-to-point TCP full mesh with a fixed peer
list, no discovery and no authentication, so there is no way to dial in; and
`Deposit`/`Delegate` transactions are refused at every node's mempool
(`crates/bloch-pos-node/src/engine.rs:1900-1906`) because bonding is not yet
funded from the UTXO set. Read access is over the public endpoint. **§11.4**
states what that means for decentralization, in figures.

---

## 1. The two chains

This repository contains two chains. They share an address format and a supply,
and nothing else. Keeping them apart is the single most important thing when
reading any Bloch document, including the older ones — and including the
Genesis-3 sections of this one.

| | **Genesis-3** | **Genesis-4** |
|---|---|---|
| Consensus | Proof of work (SHA-256d), DAG | **Proof of stake**, linear chain |
| Status | **Halted permanently** at height 39,918, 2026-08-13 | **Live** since 21:31:19 UTC, 2026-08-13 |
| Chain ID / version | `0xB10C_0004` (`ChainId::Genesis3Mainnet`) | `0xB10C_0005` (`VERSION_G4`, in the block header) |
| JSON-RPC | 37 methods (§4) — **the node they ran on no longer advances** | **Yes** (§11.1); public read at `https://posternlabs.com/g4rpc` |
| Settlement rule | Work depth only, and there was little work (§5.6) | **Casper justification/finalisation by epoch** (§5) |
| Supply | ~3.81 B BLCH at the halt | 100 B hard cap; 57,146,400,000 issued at slot 0 (§10.6) |
| Tx format | UTXO, hand-rolled wire codec (§7) | `PosTransaction::Transfer`, with real inputs and outputs (§11.1) |

Genesis-4 blocks carry `version = 0xB10C0005`, which renders in JSON as
`2970353669`. That is not a bug and must not be "fixed" to `4`: a client that
recomputes `block_id` hashes the 304 header bytes *including* that field, so a
friendlier value would be one it could not verify anything with
(`crates/bloch-pos-node/src/rpc.rs:1258-1266`).

The Genesis-3 node's self-report, recorded before the halt, is kept in §4 for
the record. Its `version` string read `0.3.0-genesis2` — a stale label on a
Genesis-3 node, and a good illustration of why you should not parse a version
string to detect a chain.

---

## 2. Transport

> **Historical — Genesis-3.** §2, §3, §4, §6, §7 and §8 describe the halted
> proof-of-work chain and the endpoints that served it. They are a measurement
> record taken before 2026-08-13, kept because Genesis-4's opening ledger is
> derived from that chain and because the address format (§6), the signing
> scheme (§7.5–§7.6) and the dust and fee constants (§8) carried across. The
> *endpoints and RPC methods* below did not carry across. For the live chain,
> read §5, §10 and §11.

Single endpoint, `POST /`, JSON-RPC 2.0 envelope. Everything below was measured
on the Genesis-3 node while it was still producing blocks.

| Property | Measured behaviour |
|---|---|
| Methods | `POST` only. `GET /` returns **HTTP 405**. |
| Content type | `application/json` |
| CORS | `access-control-allow-origin: *` |
| TLS | Both public endpoints are behind Cloudflare (`server: cloudflare`, HTTP/2) |
| Auth | **None on `g2rpc.posternpool.com`.** Writes are accepted unauthenticated. |
| `params` | **Optional.** Omitting it entirely works: `{"jsonrpc":"2.0","id":1,"method":"getblockcount"}` → `50546`. |
| `jsonrpc` field | **Not validated.** Omitting it works. |
| `id` | Echoed verbatim; strings accepted (`"abc"` → `"abc"`). |
| **Batch requests** | **NOT SUPPORTED.** A JSON array returns `{"id":null,"result":{"error":"unknown method: "}}` with HTTP 200 — it does not fail loudly. Send one request per HTTP call. |
| Malformed JSON | HTTP 400, plain-text body (not JSON-RPC): `Failed to parse the request body as JSON: …` |

### 2.1 The two endpoints are not equivalent

| | `g2rpc.posternpool.com` | `blochl1.com/rpc` |
|---|---|---|
| Backing node | same node | same node |
| Method surface | all 37 live methods | read-only allowlist |
| `sendrawtransaction` | accepted | **rejected**, HTTP 403 |
| Error style | `result.error`, HTTP 200 | **proper JSON-RPC `error` object** |

Measured, same request to each:

```jsonc
// blochl1.com/rpc — sendrawtransaction
{"jsonrpc":"2.0","id":1,
 "error":{"code":-32601,"message":"method not allowed via public proxy: sendrawtransaction"}}
// HTTP 403
```

Your client must handle **both** error conventions if it talks to both hosts.
Broadcast must go to the direct node.

### 2.2 Latency — set your timeouts high

Response times are not uniform. Measured on an idle chain:

| Method | Observed |
|---|---|
| `getblockcount`, `getbalance`, most reads | 0.3 – 1.6 s |
| `getblocktemplate` | **9.2 s** |
| `getdaginfo` | **10.3 s and 15.0 s** on separate calls |

The dispatch runs blocking storage reads on a `spawn_blocking` pool, and the
source itself records a production incident where `getblockcount` took 30 s and
filled the accept queue (`src/rpc/mod.rs:230-248`). **Use a client timeout of at
least 30 s** and do not poll `getdaginfo` in a tight loop.

---

## 3. Error model

**This is the most common integration mistake with this node.** Method-level
failures are returned as **HTTP 200** with the failure inside `result`:

```jsonc
{"jsonrpc":"2.0","id":1,"result":{"error":"invalid address"}}
```

There is **no** top-level `error` object for method failures. A standard
JSON-RPC client will report this as a *success* and hand your code
`{"error": "invalid address"}` as the result value. Every response must be
checked for a `result.error` key before use.

Real JSON-RPC error objects exist for exactly three cases:

| HTTP | Code | Message | When |
|---|---|---|---|
| 401 | `-32001` | `unauthorized: valid X-API-Key required` | node started with `--rpc-require-auth-for-writes` (not the case on the public endpoint) |
| 429 | `-32002` | `rate limit exceeded; retry after a minute` | per-IP rate limit; defaults 60 reads/min, 5 writes/min |
| 403 | `-32601` | `method not allowed via public proxy: <m>` | **proxy only**, `blochl1.com/rpc` |

### 3.1 Measured `result.error` strings

These are the exact strings, captured live. They are unstructured — there is no
error code inside `result.error`, only English prose. Match defensively.

| Method | Input | Exact `result.error` |
|---|---|---|
| *any* | unknown method name | `unknown method: <name>` |
| `getbalance`, `getutxos`, `getaddressinfo`, `getaddressbalance_at_height`, `listtransactions` | bad/absent address | `invalid address` |
| `getblock` | non-32-byte hex | `invalid hash` |
| `getblockhash` | height above tip | `height not found` |
| `gettransaction`, `gettxstatus` | bad txid | `invalid txid` |
| `gettxsbyblock` | bad identifier | `invalid block identifier (expected hex hash or height)` |
| `sendrawtransaction` | undecodable hex | `deserialise failed` |
| `decoderawtransaction` | truncated input | `decode failed: u32 EOF` |
| `submitblock` | short input | `deserialise failed: block too short for even 80-byte header` |
| `createauxblock` | no payout address | `invalid pool payout address` |
| `submitauxblock` | bad hash | `invalid aux block hash (need 32-byte hex)` |
| `validateaddressverbose` | wrong prefix | `invalid prefix (expected bloch1q or bloch1t)` |

Note that `validateaddress` does **not** use `result.error` — it returns a
normal object with `isvalid: false`.

---

## 4. Genesis-3 RPC method reference

> **Historical — Genesis-3.** None of these methods serve a chain that still
> advances. The chain behind them halted at height 39,918 on 2026-08-13. This
> reference is kept as the provenance record of the balances Genesis-4 opened
> with, and because §12 measures the repository's older documentation against
> it. The live Genesis-4 method surface is §11.1.

**37 methods were live** at the time of measurement. All 40 names in the
dispatch source were probed; the three `euvm_*` methods were compiled out
(`--features euvm` off) and answered `unknown method`.

| Group | Methods |
|---|---|
| Chain state | `getblockcount`, `getdaginfo`, `getnetworkinfo`, `getchainstats`, `getblocktimepercentiles`, `getdifficultyhistory`, `gethashrate`, `getsupplydistribution`, `getpools`, `getattestation` |
| Blocks | `getblockhash`, `getblock`, `getblockbyheight`, `getrecentblocks`, `gettxsbyblock` |
| Transactions | `gettransaction`, `gettxstatus`, `sendrawtransaction`, `decoderawtransaction` |
| Addresses | `getbalance`, `getutxos`, `getaddressinfo`, `getaddresscount`, `getaddressbalance_at_height`, `listtransactions`, `validateaddress`, `validateaddressverbose` |
| Mempool / fees | `getmempoolinfo`, `getrawmempool`, `getmempoolstats`, `estimatefee`, `estimatefeeadvanced` |
| Peers | `getpeerinfo`, `getpeers` |
| Mining (not for exchanges) | `getblocktemplate`, `submitblock`, `createauxblock`, `submitauxblock` |
| **Absent** | `euvm_buildtx`, `euvm_getutxo`, `euvm_listutxos` |

Methods an exchange might expect that **do not exist**: `getnewaddress`,
`listunspent`, `getbestblockhash`, `getinfo`, `sendtoaddress`,
`getreceivedbyaddress`, `importaddress`, `getblockheader`. **There is no wallet
in the node.** Address generation, key storage, coin selection and signing are
entirely your responsibility (§6, §7). `listunspent` exists only as a
client-side alias for `getutxos` in `src/bin/bloch-cli.rs:93`.

### 4.1 `getdaginfo` — chain tip

```bash
curl -sS -X POST https://g2rpc.posternpool.com/ -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getdaginfo","params":[]}'
```

```json
{"block_count":50561,"chain_length":39793,"k":10,
 "tip":"d97d753da1b89b8e1cb3625f4431aa2f657a7e8c883cab39ae1422e719fe6116",
 "tip_blue_score":48825,"tip_blue_work":"125828094770629180367",
 "tip_count":1,
 "tips":["d97d753da1b89b8e1cb3625f4431aa2f657a7e8c883cab39ae1422e719fe6116"]}
```

| Field | Meaning |
|---|---|
| `tip_height` | **The chain height.** This is the number that matters. |
| `block_count` | Total blocks in the **DAG**, side blocks included. Runs ~10,700 *above* `tip_height`. |
| `chain_length` | Selected-chain length; tracks `tip_height` + 1 |
| `tip_blue_score` | GHOSTDAG blue score of the tip |
| `tip_blue_work` | Cumulative work, **decimal string** (exceeds 2^53 — do not parse as a JSON number) |
| `tip_count` | Number of parallel tips; `1` means no visible fork right now |
| `k` | GHOSTDAG anticone parameter, 10 |

> ⚠️ **`getblockcount` is not the chain height.** It returns `block_count`
> (50,561), not `tip_height` (39,793). It is already numerically past the 50,000
> terminal height while the chain is 10,207 blocks away from it. Any logic that
> compares `getblockcount` to 50,000 — or that treats it as a height — is wrong.

### 4.2 `getbalance [address]`

```json
{"address":"bloch1qe986db5149cff7499b282a048272a09aff0af4ff84242073",
 "bloch":3578666569.9806376,
 "satoshis":357866656998063769,
 "utxo_count":426055}
```

- `satoshis` — integer, authoritative. **357,866,656,998,063,769 exceeds 2^53.**
  A JavaScript `JSON.parse` corrupts it silently. Parse from the raw token as a
  big integer.
- `bloch` — IEEE-754 float, **display only**. Never do arithmetic on it.
- 1 BLCH = 10^8 satoshi (`SAT_PER_BLOCH`,
  `crates/bloch-crypto/src/core/tokenomics_v2.rs:49`).

### 4.3 `getutxos [address, limit?]` — coin selection input

```json
{"address":"bloch1qe986db5149cff7499b282a048272a09aff0af4ff84242073",
 "satoshis":357866656998063769,"bloch":3578666569.9806376,
 "utxo_count":426055,"returned":2,
 "utxos":[
   {"txid":"002e53fee588d318a84d55265903214d09f63825273d3e2f16a264be48f85cd4",
    "index":0,"value":840000000000,
    "script_pubkey":"e986db5149cff7499b282a048272a09aff0af4ff"},
   {"txid":"0033feb9f1c13a99229b1227b61d2079e1df3e81ed0b28a58a9a4c46011acea6",
    "index":0,"value":840000000000,
    "script_pubkey":"e986db5149cff7499b282a048272a09aff0af4ff"}]}
```

`script_pubkey` is the bare 20-byte hash in hex — **not a script** (§6.3, §7.5).
`utxo_count` is the full count; `returned` is how many the call actually
returned. There is no cursor: pagination is by `limit` only, so a 426,055-UTXO
address cannot be walked incrementally through this method.

### 4.4 `gettransaction [txid]`

```json
{"txid":"a9348d840aa0a24a614c0dcdb68f790233dbf421e7217db172dae1f2689c53c3",
 "block_hash":"58ac221f9a2f2171f46892efbb718747420be5248ea3e451dcf36432ad995a2d",
 "block_height":39773,
 "confirmations":10771,
 "timestamp":1786625377,
 "transaction":{
   "version":1,"locktime":0,"coinbase":true,
   "inputs":[{"prev_txid":"0000…0000","prev_index":4294967295,"sequence":4294967295}],
   "outputs":[{"index":0,"value":840000000000,"bloch":8400.0,
               "script_pubkey":"e986db5149cff7499b282a048272a09aff0af4ff"}]}}
```

`confirmations` here is **wrong** — see §5.1. The block was 8 blocks below the
tip at the time of the call.

The `inputs` array in this view omits `script_sig` entirely, so you cannot
recover the spending signature or public key from `gettransaction`.

### 4.5 `gettxstatus [txid]` — lightweight

```json
{"txid":"a934…53c3","status":"final","in_mempool":false,
 "confirmations":10772,"block_height":39773}
```

`status` ∈ `pending | confirmed | final | unknown`. `final` is hardcoded at
`confirmations >= 100` (`src/rpc/mod.rs:1308`) and, because of the defect in
§5.1, **every mined transaction reports `final` immediately.** Unknown txids
return `status: "unknown"` with HTTP 200, not an error.

### 4.6 `getblockbyheight [height, verbose?]` / `getblock [hash, verbose?]`

```json
{"hash":"58ac221f…5a2d","height":39773,"blue_score":48805,
 "bits":"0x1b037a93","nonce":0,"timestamp":1786625377,"size":753,
 "parents":["dd6a274b…39d1"],
 "merkle_root":"a9348d84…53c3","tx_count":1,
 "txids":["a9348d84…53c3"]}
```

With `verbose = true` the `txids` array is replaced by a `transactions` array
of fully decoded transactions.

> ⚠️ **`bits` changes type between methods.** `getblock` and `getblockbyheight`
> return it as a **hex string** (`"0x1b037a93"`); `getrecentblocks` and
> `getdifficultyhistory` return it as an **integer** (`453212819`). Same field,
> same node, two JSON types. Handle both.

`nonce: 0` indicates a merged-mined (AuxPoW) block — most recent blocks are.

`parents` is an array because the chain is a DAG; the first entry is the
selected parent. For a single-transaction block, `merkle_root` equals the one
txid.

### 4.7 `listtransactions [address, limit, start_height, end_height, offset]`

The only address-history method. `limit` max 1000.

```json
{"address":"bloch1qe986…2073","count":2,"total_available":530,
 "limit":2,"offset":0,"start_height":0,"end_height":1000,
 "transactions":[
   {"txid":"dc7be805…291d","direction":"in","amount_sats":0,"amount_bloch":0.0,
    "block_height":0,"confirmations":50549,"timestamp":1785365935},
   {"txid":"a6a3bea9…c233","direction":"in","amount_sats":840000000000,
    "amount_bloch":8400.0,"block_height":92,"confirmations":50457,
    "timestamp":1785375054}]}
```

`total_available` tells you whether another page exists. The `confirmations`
field carries the same defect as everywhere else.

> ⚠️ `docs/API.md` records that the address-history index **does not roll back
> on reorg**. Do not treat `listtransactions` as a reconciliation source of
> truth; reconcile from blocks.

### 4.8 `validateaddress` / `validateaddressverbose`

```json
// validateaddress ["bloch1q1c89974d2bf852e926f188ccb2b177e27ba003e54e54d67b"]
{"address":"bloch1q1c8…d67b","isvalid":true,"checksum":true,"network":"mainnet"}

// one character changed in the checksum
{"address":"bloch1qe986…2074","isvalid":false,"checksum":false,"network":"mainnet"}

// validateaddressverbose
{"address":"bloch1q1c8…d67b","valid":true,"network":"mainnet",
 "prefix":"bloch1q","hash_hex":"1c89974d2bf852e926f188ccb2b177e27ba003e5"}
```

The two methods use **different field names** for the same concept
(`isvalid` vs `valid`). `validateaddressverbose` is the more useful of the two
because it returns the decoded 20-byte hash.

You do not need this method — the address scheme is fully specified in §6 and
you should validate locally — but it is a useful cross-check.

### 4.9 `sendrawtransaction [hex]` — broadcast

Takes the hex of the wire-serialized transaction **including `script_sig`**
(§7.2). Returns `{"txid": "…"}` on success, `{"error": "…"}` on failure. Must go
to the direct node, not the proxy (§2.1).

Rate-limited to **5 writes per minute per IP** by default. Batch withdrawals
accordingly.

### 4.10 Fee estimation

```json
// estimatefee
{"feerate_sats":1000,"feerate_bloch":0.00001,"mempool_size":0,
 "note":"median fee of current mempool entries"}

// estimatefeeadvanced
{"next_block_sats":10000,"medium_priority":5000,"slow_priority":1000,
 "mempool_median":1000,"mempool_size":0,"recommended_bloch":"0.00005000"}
```

Both were measured against an **empty mempool** (`size: 0`), so these are
floor/default values, not observed market rates. See §8 for the actual
consensus-level fee rule, which is what your transaction must satisfy.

### 4.11 Chain statistics

```json
// getchainstats
{"total_blocks":50781,"total_txs":50821,"blocks_last_24h":4671,"txs_last_24h":4675,
 "avg_block_time_secs":20.20408163265306,"avg_txs_per_block":1.0007876961855813,
 "current_difficulty":453212819,"hashrate_hs":4004704944907.0044,
 "hashrate_human":"4.00 TH/s"}
```

`total_blocks` is a **third** block counter, and it disagreed with both
`getblockcount` (50,533) and `tip_height` (39,761) in the same measurement
window. It counts DAG blocks. Observed hashrate moved between **4.00 TH/s and
6.11 TH/s** across a few minutes — see §5.3 for why that number matters.

`avg_txs_per_block ≈ 1.0008` means the chain is essentially empty: almost every
block contains only its coinbase.

### 4.12 `getsupplydistribution` — do not use for supply

```json
{"total_addresses":12,"total_bloch":434414400.0,"total_sats":43441440000000000,
 "tiers":[…]}
```

> ⚠️ **This method under-reports total supply by roughly 3.47 billion BLCH.**
> It counts only coins mined on Genesis-3 and **omits the carryover opening
> balance**. A single address (`getbalance` on the founder address) holds
> 3,578,666,569 BLCH — more than eight times this method's reported *total*.
> The `total_addresses: 12` here also disagrees with
> `getaddresscount → addresses_with_balance: 16`.
>
> For supply figures use `getbalance` against known addresses, or the genesis
> allocation table. Do not use this method for proof-of-reserves or market-cap
> reporting.

### 4.13 `getpools` — genesis allocation addresses

Useful because it publishes the three protocol addresses together with their
decoded hashes, which is how §6's encoding was cross-checked:

```json
{"current_height":50561,"next_block_height":50562,
 "subsidy_per_block_sat":260000000000,"miner_share_sat":260000000000,
 "pools":{
  "founder":{"address":"bloch1qe986db5149cff7499b282a048272a09aff0af4ff84242073",
             "address_hash_hex":"e986db5149cff7499b282a048272a09aff0af4ff",
             "balance_sat":357862456998063769,"utxo_count":426050,
             "vesting_months":480,"vesting_per_month_sat":743750000000000,
             "vesting_total_sat":357000000000000000,
             "vesting_active_at_next":false,"status":"active"},
  "oracle_pool":{"address":"bloch1qfc3e8ede9f6a4e1c8541731913d93963708f0604ebf94e61",
                 "balance_sat":0,"share_bps":0},
  "validator_pool":{"address":"bloch1qc23a3184ac8eb1c611b0181061855971be4a38786b3beafc",
                    "balance_sat":0,"share_bps":0}}}
```

Note `current_height` here is the **DAG** count (50,561), not the chain height —
a third inconsistent use of the word "height" in the same API.

### 4.14 Methods that die at the halt

`getblocktemplate`, `submitblock`, `createauxblock`, `submitauxblock`,
`gethashrate`, `getdifficultyhistory` are mining/PoW methods with no Genesis-4
successor (`docs/specs/BLOCH-RPC-V4.md` §1). They are listed here only for
completeness. `getattestation` is a **TEE** attestation report (SEV-SNP), not a
consensus attestation; it currently answers `attested: false` because no TEE
provider is active on this node.

---

## 5. Finality — what to credit a deposit on

### 5.1 The rule, in one line

**Credit a deposit when the block carrying it is finalized. Do not wait a
further number of blocks, and do not substitute anything else.**

Under Genesis-4 there is no confirmation count, and there is no honest way to
manufacture one. Depth is not security on a chain with no difficulty: nothing in
the protocol prices a reorg in work, so "6 blocks" and "100 blocks" are the same
statement — a statement about how long you waited, not about what it would cost
to undo. The guarantee rests instead on **Casper justification and
finalisation**: a finalised checkpoint cannot be reverted unless at least one
third of the total active stake is slashed, which is a bonded, attributable,
on-chain cost rather than a probabilistic one.

The node states this itself, at the type that carries it. From
`crates/bloch-pos-node/src/rpc.rs:1200-1216`, on `enum Finality`, under the
heading *"This is the field an exchange credits a deposit on"*:

> The integration question was "how many confirmations should we require, and
> what does the guarantee rest on". Under PoS there is no answer in that
> currency: depth is not security, and a chain with no difficulty cannot price a
> reorg in work. […] So the honest replacement for "N confirmations" is exactly
> one boolean: `Finality::Finalized`. […] Nothing is gained by waiting a further
> number of blocks past finalisation, and nothing else substitutes for it.

### 5.2 How to read it off the node

Every block the node returns carries two fields for this, and they are the same
judgement in two shapes (`rpc.rs:1293-1294`):

| Field | Type | Use |
|---|---|---|
| `finalized` | boolean | **This is the one to branch on.** |
| `finality` | string — `finalized` \| `justified` \| `canonical` \| `not_canonical` | The gradation, for display and for support tooling |

The four states, verbatim from `Finality` (`rpc.rs:1224-1236`):

| Value | Meaning |
|---|---|
| `finalized` | At or below the finalised checkpoint. Irreversible short of a one-third-of-stake slashing event. **Credit here.** |
| `justified` | At or below the justified checkpoint, above the finalised one. One epoch from finality in the normal case; **still reversible.** |
| `canonical` | On this node's canonical chain, not yet justified. Reorganisable by ordinary fork choice. |
| `not_canonical` | Known to this node, not on its canonical chain. |

`getchaininfo` carries the chain-level view (`rpc.rs:1144-1194`): `height`,
`finalized_height`, `epoch`, `slot_in_epoch`, `slots_per_epoch`, the
`justified` / `finalized` / `previous_justified` checkpoint objects, validator
totals, `total_active_stake_sat`, and `wall_slot` / `behind_by_slots`.

Two consequences your integration must handle:

1. **`height` is not the guarantee, `finalized_height` is.** The source says so
   directly: "an integrator reading only `height` is reading the number that is
   *not* the guarantee" (`rpc.rs:1149-1151`). Gate on `finalized_height`, or on
   the per-block `finalized` boolean.
2. **This is *that node's* view.** Finality is computed from the chain the node
   validated itself, which is exactly the property you want — the answer does
   not depend on trusting the producer — but it also means a node that has
   fallen behind reports its own staleness rather than an error. **Check
   `behind_by_slots` before trusting any finality answer.** At a 30 s slot, a
   `behind_by_slots` of 120 is an hour of lag.

### 5.3 Timing

| Parameter | Value | Source |
|---|---|---|
| Slot duration | **30 s** | `crates/bloch-pos-committee/src/params.rs`, `SLOT_DURATION_SECS` |
| Slots per epoch | **32** → epoch = **16 min** | same, `SLOTS_PER_EPOCH` |
| Rounds to finality | 2 (epoch N justifies; N+1 justifies on top; **N finalizes**) | `crates/bloch-pos-committee/src/finality.rs` |
| **Typical time to finality** | **≈ 32 minutes** | derived |
| **Worst case** | **≈ 48 minutes** for a block early in an epoch | derived |

Budget for the worst case, not the typical one, and note that an inactivity leak
(after 4 epochs, quadratic) extends it further if the validator set is not
voting.

### 5.4 The caveat that bounds the guarantee — read this with §5.1

Casper finality is a real guarantee about **what two thirds of the stake has
signed**. It is not a guarantee that the stake is distributed, and on Genesis-4
today it is not:

- **All 64 Genesis-4 validators are operated by a single entity.** There is no
  independent validator. One operator can halt the chain.
- **93.94% of the carryover sits at one address** — 17,046,829,380 of
  18,146,400,000 BLOCH (`LARGEST_CARRYOVER_ADDRESS_BLOCH`,
  `tokenomics_v4.rs:414`). Carried balances are **stakeable**, so if that
  balance stakes, the **Nakamoto coefficient is 1**.
- **56,046,829,380 of the 57,146,400,000 BLOCH issued at slot 0** is held by the
  founder (27.04% of the 100 B cap, `FOUNDER_TOTAL_BLOCH`) and the Foundation
  (a further 29.00%, across VC / team / marketing / liquidity buckets). That
  leaves **1,099,570,620 BLOCH — 1.92% of genesis supply** in third-party hands.
- **A third party cannot yet join.** The transport has a fixed peer list and no
  discovery, and `Deposit`/`Delegate` are refused at the mempool
  (`crates/bloch-pos-node/src/engine.rs:1900-1906`), so there is no
  permissionless path to becoming a validator today.

The short form, which we would rather write here than have you find it: **the
security question under Genesis-4 is not hashrate, it is concentration.** One
operator can halt the chain and one holder can outvote every other. §5.1's
guarantee is worth exactly as much as the validator set behind it, and §11.4
states the same thing in the same figures.

We are not asking you to accept that as a permanent condition, and the validator
emission (§10.6) exists to change it. We are asking you not to be surprised by
it.

---

### 5.5 Historical — Genesis-3's `confirmations` field was broken, and it failed open

> **Historical — Genesis-3.** §5.5 and §5.6 describe the halted proof-of-work
> chain. They are kept because §12 measures the repository's older documentation
> against them, and because an integrator who built against Genesis-3 needs to
> know what that integration was actually resting on. Neither section describes
> the live chain. **The live rule is §5.1: credit on `finalized`.**

`gettransaction`, `gettxstatus` and `listtransactions` all compute:

```rust
let tip = state.node_state.read().block_count;      // DAG block count
let confirmations = tip.saturating_sub(height) + 1;  // height = CHAIN height
```
`src/rpc/mod.rs:1307`

`block_count` counts **DAG** blocks; `height` is a **selected-chain** height.
Subtracting one from the other is a category error. Measured, in one window:

| | |
|---|---|
| `block_count` | 50,557 |
| `tip_height` | 39,789 |
| Constant offset | **10,768** |

So a transaction in the tip block — **one real confirmation** — reports:

```
50,557 − 39,789 + 1 = 10,769 confirmations
```

and since `final` was hardcoded at `>= 100`, its status was `"final"`. **Every
transaction on that chain reported as final the instant it was mined.** The
offset grew as the DAG widened, so it was never going to converge to
correctness.

The failure direction was the dangerous one: an exchange gating deposits on
`confirmations >= N` or `status == "final"` credited every deposit at depth 1.

The substitute at the time was to compute depth in consistent units yourself
(`getdaginfo.tip_height − gettransaction.block_height + 1`, cross-checked
against `getblockhash [height]`). This is recorded because it is the defect
`docs/API.md` and `docs/openapi.yaml` were measured against in §12 — **it is not
advice for the live chain, which has no confirmation count at all (§5.1).**

### 5.6 Historical — Genesis-3 had no finality. It had work depth, and not much of it.

There was no finality gadget on Genesis-3. What existed:

- **Cumulative work.** Ordinary Nakamoto probabilistic settlement: a
  competitor had to out-work the chain from the fork point.
- **A node-local reorg bound.** Each node refused reorgs deeper than
  `CHECKPOINT_DEPTH = 1,000` blocks below its own tip, persisted as
  `finalized_height` (`src/main.rs:3016-3040`, gate at `:2853`). At 20 s blocks
  that was ≈ 5.6 hours.

Be precise about what that bound was: an **assume-valid convenience policy**,
applied independently by each node from its own local view. It was not a
consensus rule and not agreement between nodes. Two nodes that saw the network
differently would refuse different reorgs. It stopped a deep reorg from being
*applied by that node*; it did not make a transaction irreversible, and it could
not, because nothing in the protocol had voted on it.

What the work depth was actually worth, stated as we stated it at the time:

- Measured network hashrate: **4.0 – 6.1 TH/s** (`gethashrate`) — on the order
  of a *single* modern SHA-256 ASIC. One Antminer-class unit approached the
  whole network.
- `tip_count: 1` and `avg_txs_per_block ≈ 1.0008`: block production was
  effectively **a single producer**, and the chain carried almost no
  transactions.
- The chain was **merged-mined with Bitcoin** (AuxPoW; `nonce: 0` on late
  blocks), which is what made the number defensible at all: the work was a
  by-product of Bitcoin mining. It did **not** confer Bitcoin's security budget,
  and it did not help if the merged miner was the adversary.

Honest statement of what that guarantee was: **on Genesis-3, deposit safety
rested on the concentration of block production, not on the cost of rewriting
history.** There was no economic finality to quote.

**Why this section still matters to you.** The shape of that disclosure did not
change when the consensus did — only its currency did. Genesis-4 replaces
probabilistic depth with a discrete, attributable, slashable commitment (§5.1),
which is a genuinely stronger *kind* of claim; but the concentration caveat
carries straight across, from concentrated block production to concentrated
stake. §5.4 states it in the figures that apply today.

---

## 6. Address specification

### 6.1 It is not bech32

Bloch addresses begin `bloch1q` and look like bech32. **They are not bech32 or
bech32m**, and several comments inside our own repository get this wrong. There
is no HRP separator semantics, no witness version, no 5-bit squashing, no
bech32 polymod, and no bech32 charset.

The proof is on the wire. A live mainnet address:

```
bloch1qe986db5149cff7499b282a048272a09aff0af4ff84242073
```

It contains `1` and `b` after the prefix. Both characters are **excluded from
the bech32 charset** (`qpzry9x8gf2tvdw0s3jn54khce6mua7l`). A bech32 decoder
rejects every valid Bloch address.

The body is plain lowercase **hex**.

### 6.2 The actual scheme

```
address = prefix ‖ hex( hash20 ‖ checksum4 )

hash20   = SHA3-256( pubkey )[0..20]
checksum4= SHA3-256( SHA3-256( hash20 ) )[0..4]
```

| Element | Value |
|---|---|
| Mainnet prefix | `bloch1q` (7 ASCII chars) |
| Testnet prefix | `bloch1t` (7 ASCII chars) |
| Hash | **SHA3-256** (FIPS-202, *not* Keccak-256, *not* SHAKE), truncated to 20 bytes |
| Checksum | SHA3-256 applied **twice** over the 20-byte hash, first 4 bytes |
| Body encoding | lowercase hex, `[0-9a-f]` |
| Total length | **55 characters** (7 + 40 + 8) |

Source: `crates/bloch-crypto/src/address.rs:56-61` (derivation), `:121-128`
(encoding), `:65-98` (decoding).

### 6.3 Verified against the live chain

The scheme above was implemented independently and checked against hashes the
node published via `getpools` and `validateaddressverbose`, plus the in-tree
known-answer vector. **All five reproduce exactly:**

```python
import hashlib
def encode(h20: bytes, prefix="bloch1q") -> str:
    c = hashlib.sha3_256(hashlib.sha3_256(h20).digest()).digest()[:4]
    return prefix + (h20 + c).hex()
```

| Source | 20-byte hash | Address |
|---|---|---|
| `getpools` founder | `e986db51…af4ff` | `bloch1qe986db5149cff7499b282a048272a09aff0af4ff84242073` ✅ |
| `getpools` oracle_pool | `fc3e8ede…f0604` | `bloch1qfc3e8ede9f6a4e1c8541731913d93963708f0604ebf94e61` ✅ |
| `getpools` validator_pool | `c23a3184…a3878` | `bloch1qc23a3184ac8eb1c611b0181061855971be4a38786b3beafc` ✅ |
| `validateaddressverbose` | `1c89974d…03e5` | `bloch1q1c89974d2bf852e926f188ccb2b177e27ba003e54e54d67b` ✅ |
| `tests/vectors/kat_address.json` | `8bb805e3…c8ce` | `bloch1q8bb805e36e9c74d7f17ffafdc0ae9370574ec8ce07b6a1b7` ✅ |

Known-answer vector, for your own test suite — public key of 3,745 bytes where
`byte[i] = i % 251`:

```
pubkey        : 3745 bytes, byte[i] = i mod 251
SHA3-256[0:20]: 8bb805e36e9c74d7f17ffafdc0ae9370574ec8ce
mainnet       : bloch1q8bb805e36e9c74d7f17ffafdc0ae9370574ec8ce07b6a1b7
testnet       : bloch1t8bb805e36e9c74d7f17ffafdc0ae9370574ec8ce07b6a1b7
```

### 6.4 ⚠️ The checksum does not cover the network prefix

Look at the two lines above: mainnet and testnet differ in **exactly one
character** (`q` vs `t`) and carry **identical checksums**. The checksum is
computed over the 20-byte hash alone (`address.rs:121-128`).

Consequence: a testnet address is a structurally valid, checksum-passing
mainnet address. Nothing in the encoding protects a user who pastes one for the
other. **Your deposit-address validator must compare the 7-character prefix
explicitly**; a checksum check alone will not catch it.

### 6.5 Output types you must support

**One.** There is no script language on Genesis-3.

`script_pubkey` is the bare 20-byte `SHA3-256(pubkey)[0..20]` — no version byte,
no opcodes, no length prefix, no P2SH, no multisig, no timelock. Confirmed on
the wire in §4.3 and §4.4, where every `script_pubkey` is 40 hex characters.

The spend rule (`src/main.rs:3361-3379`):

```rust
let (sig, pk) = Transaction::parse_script_sig(&inp.script_sig)?;
let pk_hash = Sha3_256::digest(&pk)[..20].to_vec();
if pk_hash != utxo.script_pubkey { return Err(...); }
let sighash = tx.sighash(i, core::node_chain_id());
if !crypto::verify(&pk, &sighash, &sig) { return Err(...); }
```

An eUTXO VM exists in the tree (`src/euvm/`) but is behind a default-off feature
flag, is **not wired into block acceptance**, and its methods are absent from
the live node (§4). Support the 20-byte form only; treat a future tagged-script
form as a breaking change you will be notified about.

---

## 7. Transaction format

### 7.1 Structure

`crates/bloch-crypto/src/core/mod.rs:1075-1096`:

```rust
struct Transaction { version: u32, inputs: Vec<TxInput>, outputs: Vec<TxOutput>, locktime: u32 }
struct TxInput  { prev_txid: [u8;32], prev_index: u32, script_sig: Vec<u8>, sequence: u32 }
struct TxOutput { value: u64, script_pubkey: Vec<u8> }
```

### 7.2 Wire serialization (what `sendrawtransaction` takes)

Hand-rolled, Bitcoin-shaped. `to_stratum_bytes`, `core/mod.rs:1222-1243`:

```
version              4 B  LE
input_count          varint
  per input:
    prev_txid       32 B  (as stored — NOT byte-reversed)
    prev_index       4 B  LE
    script_sig_len   varint      ] present only when serializing WITH script_sig
    script_sig       n B         ]
    sequence         4 B  LE
output_count         varint
  per output:
    value            8 B  LE
    script_pubkey_len varint
    script_pubkey    n B
locktime             4 B  LE
```

`varint` is the Bitcoin encoding: `< 0xFD` raw byte; `0xFD` + u16 LE; `0xFE` +
u32 LE; `0xFF` + u64 LE (`core/mod.rs:1104-1128`).

Decoder limits: ≤ 100,000 inputs, ≤ 100,000 outputs, `script_sig` ≤ 10,000 B,
`script_pubkey` ≤ 10,000 B.

> ⚠️ **`prev_txid` is not byte-reversed.** Unlike Bitcoin, the txid goes on the
> wire in the same byte order the RPC prints it. Do not reverse it.

### 7.3 `script_sig` layout

Fixed, not a script (`core/mod.rs:1387-1394`):

```
[4 B sig_len LE][signature][4 B pubkey_len LE][public key]
```

Note these two length prefixes are **fixed 4-byte little-endian**, *not*
varints. This differs from the transaction-level varints in §7.2.

### 7.4 txid

```rust
let bytes = self.to_stratum_bytes(self.is_coinbase());
txid = SHA256( SHA256( bytes ) )
```
`core/mod.rs:1305-1308`

- **SHA-256d**, printed as 64 lowercase hex, **not reversed**.
- For non-coinbase transactions the preimage **excludes `script_sig`** — this is
  deliberate anti-malleability, so the txid is stable before and after signing.
  You can compute a withdrawal's txid before you sign it.
- Coinbase transactions **include** `script_sig`.
- `is_coinbase()`: exactly 1 input, `prev_txid == [0u8;32]`,
  `prev_index == 0xFFFFFFFF`.

### 7.5 Sighash — the exact bytes you sign

`Transaction::sighash(input_index, chain_id)`, `core/mod.rs:1324-1355`:

```rust
let mut stripped = self.clone();
for (i, inp) in stripped.inputs.iter_mut().enumerate() {
    inp.script_sig = if i == input_index { b"BLOCH_SIGHASH".to_vec() } else { vec![] };
}
let body = bincode::serde::encode_to_vec(&stripped, bincode::config::standard())?;
let mut h = Sha3_256::new();
h.update(SIGHASH_DOMAIN);          // b"BLOCH-SIGHASH-v2", 16 bytes
h.update([SIGHASH_VERSION]);       // 0x02
h.update(chain_id.to_le_bytes());  // 0xB10C_0004 LE for Genesis-3 mainnet
h.update(&body);
h.finalize()
```

Preimage:

```
SHA3-256( "BLOCH-SIGHASH-v2" ‖ 0x02 ‖ chain_id_LE(4) ‖ bincode(stripped_tx) )
```

| Property | Value |
|---|---|
| Hash | **SHA3-256** (note: *different* from the SHA-256d used for txid) |
| Domain tag | `BLOCH-SIGHASH-v2`, 16 bytes |
| Version byte | `0x02` |
| Chain ID | `0xB10C_0004` (Genesis-3 mainnet), 4 bytes **little-endian** |
| Sighash flags | **None exist.** No `SIGHASH_ALL`/`SINGLE`/`ANYONECANPAY` byte on the wire; ALL semantics are implicit. |
| Commits to | version, locktime, every input's outpoint + sequence, **every** output |
| Does *not* commit to | any `script_sig`; the spent UTXO's **value** (bound only indirectly via the outpoint) |

Per input, the signed digest differs: the input being signed carries the
13-byte marker `BLOCH_SIGHASH` in its `script_sig` slot while every other input's
is emptied.

> 🔴 **The single hardest part of reimplementing Bloch signing.** The sighash
> body is **bincode 2.x with `config::standard()`** — *not* the §7.2 wire
> format. The two encodings coexist in the same transaction lifecycle: bincode
> for the sighash, hand-rolled for the wire and the txid. `bincode::standard()`
> means little-endian with **variable-int** integer and length encoding. You
> must replicate it byte-exactly or your signatures will not verify, and the
> node will give you no diagnostic beyond a rejection. Pin `bincode 2.0.1`
> semantics and test against a known-answer vector before going near mainnet.

### 7.6 Signing — ML-DSA-65 ‖ Falcon-1024

**Both** signatures are required and **both** are verified — logical AND
(`crates/bloch-crypto/src/crypto/mod.rs:204-226`):

```rust
if mldsa65::verify_detached_signature(&sig, message, &pk).is_err() { return false; }
falcon::verify(fpk, message, fsig)   // both must pass
```

Procedure for each input `i`:

1. `digest = sighash(i, 0xB10C_0004)` → 32 bytes (§7.5)
2. `s1 = ML-DSA-65.sign(sk_mldsa, digest)` → 3,309 bytes
3. `s2 = Falcon-1024.sign(sk_falcon, digest)` → **variable**, ~1,271 bytes
4. `sig_body = s1 ‖ s2`
5. Prepend the 4-byte suite header → `signature`
6. `script_sig = len32le(signature) ‖ signature ‖ len32le(pubkey) ‖ pubkey`

**Envelope** (`crypto/mod.rs:31-42`) — every key and signature blob carries a
4-byte header:

```
byte 0..2 : 0xB1 0x0C          magic
byte 2..4 : suite_id  u16 LE   0x0001 = ML-DSA-65 ‖ Falcon-1024
byte 4..  : body
```

The two halves are concatenated **ML-DSA first, Falcon second, with no inner
length prefixes** — the split is at ML-DSA's fixed length and Falcon is the
remainder.

**Sizes** (`core/mod.rs:328-330`):

| Object | Composition | Bytes |
|---|---|---|
| ML-DSA-65 public key | | 1,952 |
| Falcon-1024 public key | | 1,793 |
| **Hybrid public key** | 4 + 1,952 + 1,793 | **3,749** |
| ML-DSA-65 secret key | | 4,032 |
| Falcon-1024 secret key | | 2,305 |
| **Hybrid secret key** | 4 + 4,032 + 2,305 | **6,341** |
| ML-DSA-65 signature | fixed | 3,309 |
| Falcon-1024 signature | **variable**, max 1,462 | ~1,271 typical |
| **Hybrid signature** | 4 + 3,309 + variable | **~4,584 typical, 4,775 max** |

> ⚠️ Two corrections to numbers that circulate internally. The hybrid public key
> is **3,749** bytes, not 3,745 — 3,745 is the *body*, before the 4-byte suite
> header. And the signature is **not** a fixed 4,589 bytes: Falcon-1024
> signatures are variable-length, so `SIG_SIZE = 4,775` is an upper bound used
> for fee estimation, not a wire length. **Never hard-code a signature length.**

> ⚠️ **Legacy un-enveloped keys are still valid.** A blob without the `B1 0C`
> magic is parsed as suite `0x0001` (`crypto/mod.rs:173-178`), so **3,745-byte**
> public keys from the carryover verify alongside 3,749-byte enveloped ones.
> They hash to **different addresses**. Both forms appear on-chain. Your
> validator must accept both.

### 7.7 Practical size and cost

`estimate_size` budgets `SIG_SIZE + PUBKEY_SIZE` = 4,775 + 3,749 ≈ **8,568 bytes
of witness overhead per input** (`core/mod.rs:1397-1404`). A 1-input, 2-output
withdrawal is roughly **8.6 kB** — two orders of magnitude larger than the
Bitcoin equivalent.

Plan for this in fee budgeting, mempool limits and bandwidth. Consolidating
inputs is expensive; the founder address alone holds 426,055 UTXOs.

---

## 8. Fees, dust and limits

| Rule | Value | Source |
|---|---|---|
| `DUST_THRESHOLD` | **546 sat** | `core/mod.rs:305` |
| `MIN_RELAY_FEE_RATE` | **1 sat per byte** | `src/mempool/mod.rs:24` |
| `MAX_TX_SIZE` (mempool) | 400 KiB | `src/mempool/mod.rs:33` |
| `MAX_BLOCK_SIZE` | 1,000,000 B | `core/mod.rs:261` |
| `COINBASE_MATURITY` | 100 blocks | `core/mod.rs:266` |
| Mempool capacity | 50,000 tx | `src/mempool/mod.rs:12` |
| Wallet-side default min fee | 1,000 sat (bare literal) | `core/mod.rs:1413` |

**The fee rate is measured against the bincode length, not the wire length.**
`tx.actual_size()` returns the bincode encoding's size, and that is what the
mempool multiplies by `MIN_RELAY_FEE_RATE` (`src/mempool/mod.rs:170-177`). The
two encodings differ (§7.5), so a fee computed from the §7.2 wire length can be
slightly under the threshold. Compute from bincode length, or add margin.

**Dust is enforced in three places with three separate literals** — the shared
`DUST_THRESHOLD` in block validation (`core/mod.rs:1888`, which **skips the
coinbase**), a local `546` in mempool admission (`src/rpc/mod.rs:1646`), and a
third local `546` in the wallet's change logic
(`crates/bloch-crypto/src/wallet/mod.rs:265`), where sub-dust change is silently
dropped into the fee. **Never create an output between 1 and 545 satoshi** — it
will fail every block that contains it. Operational history: a single stuck
sub-dust transaction in the mempool once poisoned every block that included it.

---

## 9. Custody — the part that has no workaround

**No hardware security module on the market can sign a Bloch transaction.**

Signing requires ML-DSA-65 ‖ Falcon-1024. Every HSM, smart card and hardware
wallet in general availability implements ECDSA/EdDSA over classical curves, and
some implement RSA. A device that cannot execute the lattice and NTRU signing
paths cannot produce either half of the required signature, and both halves are
verified (§7.6). This includes Ledger, Trezor, and the general-purpose
FIPS-140-3 HSM fleets used by exchange custody desks.

The consequences, stated plainly:

- **Private keys live in software.** There is no threshold-signing,
  MPC or HSM-backed option for BLCH today, because no vendor implements these
  primitives. Cold storage means an air-gapped machine holding a software key,
  not a signing device.
- **Key sizes break existing plumbing.** A 6,341-byte secret key and a
  3,749-byte public key do not fit key-storage schemas sized for 32- or 65-byte
  material. Expect schema and secret-manager changes.
- **Signatures are variable-length** (§7.6). Fixed-width signature columns and
  buffers will break.

This is the price of being genuinely post-quantum rather than nominally so. A
chain that could be signed by your existing HSM would be a chain whose keys fall
to the same attack the design exists to prevent. We are not going to add a
secp256k1 path to make custody convenient.

What we can offer: an air-gapped signing reference, deterministic key
derivation, and engineering support for your key-ceremony design. What we cannot
offer is a hardware root of trust, and we would rather you learn that from this
document than three weeks into an integration.

---

## 10. Snapshot and the Genesis-3 → Genesis-4 balance mapping

### 10.1 The mechanism

Genesis-3 did not upgrade into Genesis-4. It **stopped**, permanently, at chain
height **39,918** on 2026-08-13; a snapshot of the UTXO set was taken at that
height; every balance was multiplied by 100/21; and Genesis-4 launched with
those balances in its genesis state at 21:31:19 UTC the same day. **This has
already happened.**

There was no bridge, no swap contract, and no claim process. **Holders did
nothing.** Balances appear at the same addresses, because Genesis-4 keeps the
address format and key material of §6 and §7.6 unchanged. Deposit addresses
issued on Genesis-3 survived the migration.

### 10.2 The conversion rule

`crates/bloch-pos-committee/src/tokenomics_v4.rs:57-67`:

```rust
pub const fn split_g3_sat(g3_sat: u128) -> u128 {
    g3_sat * SPLIT_NUMERATOR / SPLIT_DENOMINATOR   // 100 / 21
}
```

A **×100/21 split**, applied per balance, in `u128`, multiply-first so there is
exactly one rounding step at the end. Rust integer division **truncates toward
zero**, so every balance rounds **down** by up to 20/21 of a satoshi. There is
no remainder handling in the code — the dropped fraction goes nowhere.

Verified arithmetic:

| Genesis-3 | Genesis-4 | Note |
|---|---|---|
| 1 sat | **4 sat** | 16/21 sat dropped (not 4.76) |
| 21 sat | 100 sat | exact |
| 840,000,000,000 sat (8,400 BLCH) | 4,000,000,000,000 sat (40,000 BLCH) | exact — the legacy coinbase amount |
| 260,000,000,000 sat (2,600 BLCH) | 1,238,095,238,095 sat | 5/21 dropped |
| **Terminal supply, 3,810,744,000 BLCH** | **18,146,400,000 BLCH** | exact, zero aggregate dust |

Note the asymmetry: the 8,400-BLCH coinbase rows that dominate the ledger scale
**exactly**, but Emission-V3-era rows (2,600 BLCH, and the 60-BLCH tail floor)
do not. Those are the rows that produced per-row dust in the terminal snapshot,
and §10.5 is the rule that closes the resulting gap.

`split_g3_sat` is applied by the genesis builder — `genesis.rs:632` per row and
`:666` on the aggregate, with the ceremony tool calling it at
`tools/genesis4-ceremony/src/lib.rs:544` and `:1098`. An earlier revision of
this document reported it as having zero callers; that was true when written and
is no longer.

**No dust threshold and no minimum balance.** The only value floor is a
structural rejection of `value == 0` rows in the snapshot parser
(`src/storage/mod.rs:1248`). There is no sweep, no minimum, no address cap. The
holder cap and the "taint set" that appear in older documents were both
**dissolved** — `HOLDER_CARRYOVER_CAP_BLOCH` is explicitly retired to `0`
(`tokenomics_v4.rs:203-207`). Every Genesis-3 balance crosses as ordinary
**liquid, stakeable** balance, the founder's included.

### 10.3 Snapshot file format

Tab-separated, **no header row**, one line per UTXO, sorted ascending by
(txid, vout). Frozen at `src/storage/mod.rs:1233-1250`, emitted by
`src/bin/bloch-snapshot-utxo.rs:130`.

```
txid_hex <TAB> vout <TAB> value_sat <TAB> script_pubkey_hex
```

| # | Column | Type |
|---|---|---|
| 1 | `txid` | 32-byte txid, lowercase hex, 64 chars, **not reversed** |
| 2 | `vout` | output index, decimal `u32` |
| 3 | `value_sat` | **satoshis**, decimal `u64` — not BLCH |
| 4 | `script_pubkey` | hex; the 20-byte address hash of §6.5. **Hex, never an address string.** |

Real lines from the shipped artifact:

```
00001c233f0f5a1a515e29c13c6bdc6b1b332a38298aa323602b37212dbbc75c	0	840000000000	e986db5149cff7499b282a048272a09aff0af4ff
0000eb82764944f8dd953a92b6874bd067e839fc2523e883c8f05272c68ff839	0	840000000000	e986db5149cff7499b282a048272a09aff0af4ff
```

To go from column 4 to a displayable address, apply §6.2 — take the 20 bytes and
prepend `bloch1q` plus the doubled-SHA3 checksum.

> ⚠️ **The `carryover.tsv.gz` in this repository is the wrong file for your
> purposes.** It is the **Genesis-1 → Genesis-3** carryover: 413,743 rows,
> 5 distinct addresses, 3,475,441,200 BLCH total, all rows exactly 8,400 BLCH.
> The **Genesis-3 → Genesis-4** snapshot is a different file, taken at the halt:
> **452,726 outputs, 18,146,400,000 BLCH after the split, at chain height
> 39,918.** Same format, different contents. Likewise `docs/CARRYOVER.md` and
> `docs/SNAPSHOT-BOOTSTRAP.md` describe Genesis-3 bootstrapping, not this
> migration.

### 10.4 How the snapshot is verified

`src/storage/mod.rs:1102-1250`. Fail-closed; all checks are evaluated with no
short-circuit, and nothing is written to the store on failure:

1. **SHAKE-256** (32-byte XOF read) over the file's **raw bytes**, compared to a
   pinned root constant. Deliberately no sorting or normalisation — a reordered
   file has a different root and is refused.
2. Line count equals the pinned UTXO count.
3. Summed value equals the pinned total.
4. **Outpoints must be unique** — added because count and sum alone accept a
   file that duplicates an equal-value row.
5. **Zero-value rows rejected** — they would change the count without changing
   the total.
6. Malformed lines are hard failures, never skipped.

> 🔴 **The snapshot is not cryptographically signed.** No signing mechanism
> exists in the code. `bloch-snapshot-utxo` prints a SHAKE-256 root and nothing
> else. The phrase "signed snapshot" appears in prose but has no implementation
> behind it. The stated trust model is **independent reproduction**: several
> parties rebuild the snapshot from their own node and compare roots. Describe
> it to your risk team as *hash-committed and independently reproducible*, not
> as *signed*.
>
> If you want assurance here, ask us for the root through a second channel and
> reproduce the file yourself from an archive node before crediting the
> migration. We would rather you did.

> ⚠️ **Unresolved: three different hash functions are named for the Genesis-4
> commitment.** `tokenomics_v4.rs:189-193` says SHAKE-256 plus SHA-256 of the
> file; the migration runbook says record both; but
> `crates/bloch-pos-node/src/genesis.rs:85` defines the manifest's
> `CarryoverCommitment.digest` as **SHA3-256**. SHAKE-256 and SHA3-256 are
> different functions. The tool emits one, the manifest field names another.
> This must be settled before launch and you should ask for the resolution in
> writing.

### 10.5 Mapping granularity and the reconciliation gap

The mapping is **per-UTXO, not per-address**. The snapshot is the UTXO set, and
the Genesis-4 manifest commits `entry_count` = number of outputs.

This matters for the dust rule. Truncating per row loses satoshis, but
`Manifest::check_supply()` (`crates/bloch-pos-node/src/genesis.rs:240-261`)
refuses any manifest where `carryover.total_sat + Σ allocations ≠
GENESIS_ISSUED_SAT` **exactly**. Someone must therefore absorb the accumulated
remainder.

**The rule is implemented, and it is deterministic.** At
`crates/bloch-pos-node/src/genesis.rs:662-695`, the builder computes
`split_g3_sat` of the *aggregate*, subtracts the sum of the per-row splits, and
adds the whole remainder to **the single highest-value output, ties broken to
the lowest `(txid, vout)`**. A sum of floors never exceeds the floor of the sum,
so the remainder is always non-negative and the accounting closes exactly. The
tie-break is a strict `>` over entries the parser has already forced into
strictly ascending outpoint order — the source notes that a `>=` there would
take the last maximum instead, "and two nodes disagreeing about where one
satoshi landed is two state roots."

Practical consequence for you: a Genesis-4 opening balance **is** predictable to
the satoshi from a Genesis-3 balance — apply `split_g3_sat` per UTXO — with
exactly one exception, the single largest output in the whole snapshot, which
carries the aggregate remainder on top. An exact-match reconciliation test is
now buildable; write it with that one row special-cased. An earlier revision of
this document said the rule was unimplemented, which was true when written.

### 10.6 Supply figures

All figures below are the **terminal** ones, measured at the halt and pinned in
`crates/bloch-pos-committee/src/tokenomics_v4.rs`. They are final.

| Quantity | Value | Pinned at |
|---|---|---|
| Genesis-4 hard cap (`TOTAL_SUPPLY_BLOCH`) | **100,000,000,000 BLCH** = 10^19 sat | `:84` |
| Carryover after the ×100/21 split (`CARRYOVER_TOTAL_BLOCH`) | **18,146,400,000 BLCH** | `:188` |
| — measured at Genesis-3 chain height | **39,918** (`CARRYOVER_MEASURED_HEIGHT`) | `:222` |
| — over this many outputs | **452,726** (`CARRYOVER_MEASURED_UTXOS`) | `:224` |
| — from this Genesis-3 total | 3,810,744,000 BLCH | — |
| Issued at slot 0 (`GENESIS_ISSUED_SAT`) | **57,146,400,000 BLCH** | `:251` |
| Validator emission over 40 years (`VALIDATOR_EMISSION_BLOCH`) | **42,853,600,000 BLCH** — unissued | `:233` |
| Founder / VC / Team / Marketing / Liquidity | 10 B / 10 B / 10 B / 4 B / 5 B BLCH | — |

> ⚠️ **Do not quote 17,970,880,000 BLCH or "height 43,172".** Those appear in
> older revisions of our documents and of `tokenomics_v4.rs`'s own comments. The
> figure was superseded, and the label was wrong twice over: **43,172 was a
> block count, not a height** — Genesis-3 was a DAG, so it had more blocks than
> the selected chain was tall, and the chain was never 43,172 blocks tall.
> Anyone attempting to reproduce the measurement "at height 43,172" would have
> been waiting for a height that yields a different number. The doc comment at
> `tokenomics_v4.rs:164-179` records the error deliberately rather than quietly
> fixing it. The correct pair is **height 39,918 / block count 50,690**.

> ⚠️ **The carryover figure is no longer provisional.** It was pinned to a
> pre-halt measurement (height 39,328) and grew with every Genesis-3 block until
> the halt. The terminal re-pin has happened. 18,146,400,000 is final.

> ⚠️ Raising the carryover to the terminal figure did **not** breach the cap.
> `VALIDATOR_EMISSION_BLOCH` is the remainder of a fixed total, so every extra
> BLCH of carryover is one less BLCH of future validator emission. Nothing was
> taken from anyone who already held coins.

> ⚠️ 10^19 sat is **54.21% of `u64::MAX`** and **1,110× JavaScript's 2^53**.
> Genesis-4 emits satoshi amounts as **decimal strings**. Build your parser for
> strings; §4.2's bare numbers were the legacy Genesis-3 form.

> ⚠️ 10^19 sat is **54.21% of `u64::MAX`** and **1,110× JavaScript's 2^53**.
> Genesis-4 will emit all satoshi amounts as **decimal strings**
> (`docs/specs/BLOCH-RPC-V4.md` §6). Build your parser for strings now; §4.2's
> bare numbers are the legacy Genesis-3 form.

> ⚠️ Several prose comments in `tokenomics_v4.rs` are stale relative to their own
> constants — the flat reward, the halving figures, the year-1 inflation rate and
> the emission-dust explanation were not re-derived after the 2026-08-13
> re-pin. **Quote the constants and the compile-time assertions, never the
> surrounding comments.** The same caution applies to any figure you take from
> our older documents.

---

## 11. Genesis-4: what exists and what does not

Documented as it is, not as it is planned. **This section was rewritten on
2026-08-14 against the source of the running node.** An earlier revision, written
before the launch, described Genesis-4 as unbuilt and listed an RPC server, a
transfer format and carryover ingestion among the things that did not exist.
All three exist. The corrections are itemised in §11.2 rather than deleted,
because an integrator who read the earlier revision needs to know which of its
blockers were lifted.

### 11.1 What exists and works

`crates/bloch-pos-committee/` — pure consensus mathematics, no I/O.
`crates/bloch-pos-node/` — the `bloch-pos` binary, with subcommands `selfcheck`,
`keygen`, `genesis`, `submit-tx`, `run`.

Live on mainnet since 21:31:19 UTC on 2026-08-13: 64 validator processes
producing blocks, attesting, justifying and finalizing, with **real
ML-DSA-65 ‖ Falcon-1024 signatures on every consensus path**, append-only
block-log persistence with deterministic replay on restart, LMD-GHOST fork
choice, and a weak-subjectivity boot gate.

**The JSON-RPC surface** (`crates/bloch-pos-node/src/rpc.rs`; served on
`--rpc-bind`:`--rpc-port`, default `127.0.0.1:16310`, `--rpc-port off` to
disable). Public read access is at **`https://posternlabs.com/g4rpc`**.

| Method | Returns |
|---|---|
| `getchaininfo` | head, `height`, **`finalized_height`**, epoch, slot-in-epoch, the justified/finalized/previous-justified checkpoints, validator totals, `total_active_stake_sat`, base fee, mempool depth, `wall_slot`, `behind_by_slots` |
| `getblockcount` | height |
| `getblockbyslot` / `getblockbyid` | one block, with `finality` and `finalized` (§5.2) |
| `getvalidator` / `getvalidatorcount` | validator records and the set size |
| `getbalance` | balance for a script hash |
| `getutxos` / `listunspent` | paginated outputs for a script hash |
| `sendrawtransaction` | canonical bytes in, mempool admission out |
| `getmempoolinfo` | mempool state |

Two methods **refuse on purpose**, and answer with a reason rather than
`method not found` (`rpc.rs:815-830`) — the source's point being that "this node
cannot do that, here is why, do not retry" is actionable where "no such method"
would send you looking for a newer build:

| Method | Refusal |
|---|---|
| `gettransaction` | `no_transaction_index` — there is no txid at this layer to look up, and approximating one would be worse than the absence |
| `getnewaddress` | `no_wallet` — a node RPC does not mint key material, and no address format is frozen |

**The transfer transaction format exists.** `PosTransaction::Transfer` carries
`{ inputs: Vec<TransferInput>, outputs: Vec<TransferOutput>, tx_bytes,
tip_millisat_per_gas }` (`crates/bloch-pos-committee/src/transition.rs:242-262`)
— real inputs and real outputs, spending and creating. Its own doc comment
records the two earlier shapes it replaced, both of which were gas terms with no
sender, recipient or amount. Deposits and withdrawals are specifiable.

**Carryover ingestion exists**, through `Manifest::ingest_carryover`
(`crates/bloch-pos-node/src/genesis.rs:182+`), checked against all four fields of
`CarryoverCommitment` — file digest, set root, entry count and total — with the
split and the dust rule applied per §10.2 and §10.5. Genesis-4 opened with the
carried balances in it.

### 11.2 What does not exist, and what changed since the pre-launch revision

| # | Item | Status today |
|---|---|---|
| 1 | JSON-RPC server | ✅ **Exists** (§11.1). Was listed as a total blocker before launch. |
| 2 | Value-transfer transaction format | ✅ **Exists**, with inputs and outputs (§11.1). Was listed as a total blocker. |
| 3 | Carryover ingestion | ✅ **Exists** and ran at genesis (§11.1). |
| 4 | Mainnet genesis manifest | ✅ **Exists** — the chain launched from it. |
| 5 | The ×100/21 split and the per-row dust rule | ✅ **Implemented and applied** (§10.2, §10.5). Both were reported unimplemented before launch. |
| 6 | **A network a third party can join** | ❌ **Still missing, and this is the one that matters.** See below. |
| 7 | **Permissionless staking** | ❌ **Still missing.** `Deposit` and `Delegate` are refused at every node's mempool. See below. |
| 8 | RocksDB store | ❌ Persistence is an append-only block log with replay-on-boot, not a keyed state store. Boot cost is O(chain length). Correct, durable, and not yet what a large archival deployment wants. |
| 9 | Slashing-evidence pipeline; checkpoint-sync state download | ❌ Still missing. Finality's economic guarantee (§5.1) rests on slashing being enforceable; the evidence pipeline that would make a violation punishable end-to-end is not built. **State this to your risk team.** |
| 10 | Emission curve | Three curves are implemented (flat, halving, decay). Treat published yield and inflation figures as subject to that choice. |

**On (6) — the transport.** The live fleet runs `Transport::Devnet`, and the
default has not changed. Describe it as it is: **a point-to-point TCP full mesh
with a fixed peer list, no discovery and no authentication.** Frames are
`u32 LE length ‖ type byte ‖ payload`. It has no relay logic and no peer
scoring, which is exactly why it works for a fixed set of known hosts and
exactly why a third party cannot dial in. There is a libp2p module in the tree
(`crates/bloch-pos-node/src/p2p.rs`, behind `--transport libp2p`) carrying the
Genesis-3 gossipsub incident fixes. **It is not what the live fleet runs, and
you should not plan around it until we tell you it is.**

**On (7) — staking.** `Deposit` and `Delegate` are refused at mempool
admission, at every node, with an explicit message
(`crates/bloch-pos-node/src/engine.rs:1900-1906`):

> deposits are not accepted: bonding is not yet funded from the UTXO set

The exposure that refusal closes, in the source's words: a `Deposit` "names an
amount, carries no signature, and spends no output". Until bonding is funded
from the eUTXO set, accepting one would create bonded stake out of nothing.
Transfers are open; staking is not. **There is no permissionless path to
becoming a validator today.**

A grep for `todo!()`, `unimplemented!()`, `FIXME` and `TODO` across the PoS
crates returns **zero hits** — the gaps are recorded in module prose, not in
markers, so a TODO scan **understates** what is missing. Take the table above,
not the grep.

> ⚠️ `crates/bloch-pos-committee/src/lib.rs` declares itself **UNAUDITED**. That
> half stands and is load-bearing: no external audit has been completed on the
> consensus crate that now runs mainnet. An older "Not wired into the node"
> clause alongside it is stale — the crate is a workspace member and a
> dependency of `bloch-pos-node`.

### 11.3 The finality gadget, as implemented

`crates/bloch-pos-committee/src/finality.rs`. This is the mechanism behind the
§5.1 claim.

| Parameter | Value |
|---|---|
| Slot duration | 30 s |
| Slots per epoch | 32 → **epoch = 16 minutes** |
| Checkpoints | one per epoch |
| Quorum | `weight × 3 ≥ total_active × 2` — **≥ 2/3 of total active stake**, `u128` integer, no division |
| Casper `k` | 1 consecutive justification |
| **Time to finality** | **≈ 32 minutes** typical; **≈ 48 minutes** worst case for a block early in an epoch |
| Vote signatures | **ML-DSA-65 ‖ Falcon-1024, both halves verified. No BLS** — grep for `bls`/`blst`/aggregate signatures returns zero hits. |
| Inactivity leak | after 4 epochs, quadratic |

The two rounds: epoch N justifies; epoch N+1 justifies on top of it; **epoch N
finalizes**.

**Committee selection is a partition, not a sample.** The active set is
deterministically shuffled (SHAKE-256) and cut into 32 committees, so every
active validator votes exactly once per epoch and the quorum denominator is the
total active stake with no sampling variance. This replaced an earlier sampled
design after an adversarial finding. `COMMITTEE_SIZE = 128` and
`SLOT_SUBCOMMITTEE_SIZE = 8` are pinned at
`crates/bloch-pos-committee/src/params.rs:17` and `:27`.

One design note worth relaying to your risk team: the finality state is a **pure
fold over vote history**, written that way deliberately after a 2026-08-08
consensus split in which node-local mutable state caused nodes running identical
binaries to diverge. Equivocating validators count toward no target at all, so
the result is order-independent.

> ⚠️ Do not cite `crates/bloch-ffg/` for any of this. It is a separate, static
> 14-of-21 named-seat committee, marked "FOUNDATION. NOT wired into consensus."

### 11.4 Decentralization today — stated plainly

From our own migration runbook, and we would rather write it here than have you
find it. These are the figures as they stand on the live chain, not projections:

| | |
|---|---|
| Validators | **64, all operated by a single entity.** There is no independent validator. **One operator can halt the chain.** |
| Nakamoto coefficient | **1** |
| Largest carryover address | **17,046,829,380 of 18,146,400,000 BLCH — 93.94%** (`LARGEST_CARRYOVER_ADDRESS_BLOCH`, `tokenomics_v4.rs:414`). Carried balances are **stakeable**, so if that balance stakes it alone decides finality. |
| Founder holding | **27,046,829,380 BLCH — 27.04% of the 100 B cap** (`FOUNDER_TOTAL_BLOCH`, pinned by a compile-time assertion at 2704 bps, `tokenomics_v4.rs:434-435`) |
| Foundation holding | a further **29.00%** — VC 10 B, team 10 B, marketing 4 B, liquidity 5 B |
| Third-party float at genesis | **1,099,570,620 BLCH — 1.92%** of the 57,146,400,000 issued at slot 0 |
| Permissionless entry | **None today.** Fixed peer list, no discovery, no authentication on the transport; `Deposit`/`Delegate` refused at the mempool (§11.2). |

Casper finality is a real guarantee about *what a two-thirds majority of stake
has signed*. It is not a guarantee that the stake is distributed, and today it is
not. Any statement we make about finality should be read with that attached:
**§5.1's guarantee is worth exactly as much as the validator set behind it.**

One precision note, so you do not over-read the table: the repository pins the
*founder* at 27,046,829,380 BLCH. The remaining 29.00% is **Foundation**-held
across five allocation buckets whose recipient script hashes are not in the
repository. "Founder and Foundation together hold 56,046,829,380" is verified
arithmetic; "one key holds 56 B" is not, and we are not asserting it.

We are not asking you to accept any of this as a permanent condition — the
42,853,600,000 BLCH validator emission (§10.6) exists to dilute it over 40
years, and the transport and staking work in §11.2 exists to open entry. We are
asking you not to be surprised by it.

---

## 12. Divergences: repository documentation vs. the Genesis-3 node

> **Historical — Genesis-3.** Every row below was measured on 2026-08-13
> against the Genesis-3 node, before the halt. It is retained as the audit
> record of where our published documentation diverged from our running code —
> the kind of list an integrator is entitled to see, and one we would rather
> keep than quietly drop when the chain it describes stopped. **Rows D1–D17
> describe Genesis-3 RPC behaviour that no longer runs.** Rows D18–D25 concern
> the migration and Genesis-4; their present status is given in the correction
> column added below the tables.

This list is the answer to "your docs don't match your node".

### 12.1 Methods

| # | Claim | Reality | Severity |
|---|---|---|---|
| D1 | Six methods reported as confirmed working: `getbalance`, `sendrawtransaction`, `getnewaddress`, `listunspent`, `gettransaction`, `getblockcount` | **`getnewaddress` and `listunspent` do not exist.** Both return `unknown method`. There is no wallet in the node at all. `listunspent` is only a client-side alias for `getutxos` in `bloch-cli`. | **High** |
| D2 | `docs/openapi.yaml` enumerates 36 methods | The node dispatches **40**; `createauxblock` and `submitauxblock` are live but **absent from the OpenAPI enum**. | Low |
| D3 | `docs/openapi.yaml` documents `euvm_*` as part of the surface | The three `euvm_*` methods are **compiled out** and answer `unknown method`. | Medium |

### 12.2 Semantics

| # | Claim | Reality | Severity |
|---|---|---|---|
| D4 | `gettxstatus.confirmations` is a confirmation count; `status: "final"` at ≥ 100 | Computed as `DAG block_count − chain height + 1`; over-reports by **10,768** and marks **every mined tx `final` immediately** (§5.1). | 🔴 **Critical** |
| D5 | `docs/API.md`: "`>= 100` = final (coinbase maturity). Applications requiring strong finality should wait for 100+ confirmations" | Unreachable as written — the counter is already >10,000 at depth 1. Advice is inert. | 🔴 **Critical** |
| D6 | Addresses described as "bech32-style" throughout the repo, including in source comments | **Not bech32.** Plain hex with a doubled-SHA3 checksum (§6). A bech32 decoder rejects every valid address. `docs/API.md` §"Hex encoding" is the one place that gets it right. | **High** |
| D7 | `getsupplydistribution` reports total supply | Omits the carryover; under-reports by ~3.47 B BLCH. Its `total_addresses: 12` also contradicts `getaddresscount: 16`. | **High** |
| D8 | `getblockcount` is the chain height | Returns the **DAG** block count (50,561 vs chain height 39,793). Already past the 50,000 terminal height while the chain is 10,207 blocks short of it. | **High** |

### 12.3 Types and transport

| # | Claim | Reality | Severity |
|---|---|---|---|
| D9 | `bits` has one type | **Hex string** in `getblock`/`getblockbyheight`, **integer** in `getrecentblocks`/`getdifficultyhistory`. | Medium |
| D10 | JSON-RPC 2.0 compliance | Batch requests **unsupported** and fail silently as `unknown method: ""` with HTTP 200; `jsonrpc` field unvalidated; method errors returned as HTTP 200 `result.error`. | **High** |
| D11 | `docs/API.md`: "There is currently **no authentication**" in §Transport, then documents an auth scheme in the next section | Both are partly true and the document contradicts itself. Measured: the public endpoint requires **no auth, including for writes**. | Medium |
| D12 | `docs/API.md`: single endpoint on port 16210 | Two public endpoints on 443 with **different method surfaces and different error conventions** (§2.1). Neither is on 16210. | Medium |
| D13 | Amounts fit standard JSON numbers | `satoshis` and `tip_blue_work` **exceed 2^53**; `tip_blue_work` is already a string, `satoshis` is still a bare number. | **High** |
| D14 | `validateaddress` and `validateaddressverbose` share a schema | Different field names for validity: `isvalid` vs `valid`. | Low |
| D15 | `getchainstats.total_blocks` agrees with other counters | A **third** block count (50,781), disagreeing with `getblockcount` (50,533) and `tip_height` (39,761) in the same window. `getpools.current_height` is a fourth use of "height" meaning the DAG count. | Medium |

### 12.4 Migration and Genesis-4

| # | Claim | Reality | Severity |
|---|---|---|---|
| D18 | The Genesis-4 snapshot is "signed" | **No signing mechanism exists in the code.** The tool emits a SHAKE-256 root; trust rests on independent reproduction (§10.4). The word "signed" appears in prose only. | **High** |
| D19 | The snapshot commitment has one hash function | **Three are named**: SHAKE-256 (tool), SHA-256 (runbook), **SHA3-256** (`genesis.rs:85`, the manifest field). Unresolved (§10.4). | **High** |
| D20 | The ×100/21 split is applied | `split_g3_sat` has **zero callers**. Carryover ingestion is not implemented — `CarryoverCommitment` is validated but never creates balances (§11.2). | **High** |
| D21 | The per-row dust rule is defined | Truncation loses satoshis, `check_supply()` demands exact reconciliation, and **the rule that closes the gap is unimplemented** — the source comment says so (§10.5). | Medium |
| D22 | `crates/bloch-pos-node/Cargo.toml:5` says Genesis-3 halts at height **80,000** | The constant is **50,000**, lowered 2026-08-12. Stale metadata. | Medium |
| D23 | `tokenomics_v4.rs` comments match its constants | Stale after the 2026-08-13 re-pin: flat reward (1,022.63 vs 1,019.03 BLCH/slot), halving figures, year-1 inflation (436 vs 435 bps), emission dust (176,880 vs 772,880 sat). **Constants and asserts are correct; comments lag.** | Medium |
| D24 | The terminal height is enforced everywhere | `is_past_terminal_height` appears **zero times in `src/rpc/mod.rs`**. `getblocktemplate` and `createauxblock` keep issuing templates past height 50,000; the resulting blocks are then rejected by `accept_block`. **Merged miners will burn work at the halt** unless the pool checks height itself. | **High** (for miners, not for exchanges) |
| D25 | `crates/bloch-pos-committee/src/lib.rs:36` — "Not wired into the node" | Stale; it is a workspace member and a dependency of `bloch-pos-node`. The "UNAUDITED" half stands. | Low |

**Status of D18–D25 as of 2026-08-14**, since these are the rows an integrator
would act on today:

| # | Then | Now |
|---|---|---|
| D18 | Snapshot called "signed"; no signing mechanism | **Unchanged.** Trust still rests on independent reproduction of the SHAKE-256 set root, not on a signature. Describe it to your risk team as *hash-committed and independently reproducible*, never as *signed*. |
| D19 | Three hash functions named for one commitment | **Resolved.** `CARRYOVER_MEASURED_FILE_SHA3_256` and `CARRYOVER_MEASURED_FILE_SHA256` are now separately named constants, and `CARRYOVER_MEASURED_ROOT` is the SHAKE-256 set root. The node had been refusing to start on a FILE-DIGEST mismatch because a SHA-256 value had been pasted into a SHA3-256 field; it was right to refuse. |
| D20 | `split_g3_sat` had zero callers | **Resolved.** Applied per row and on the aggregate by the genesis builder (§10.2). |
| D21 | Per-row dust rule undefined | **Resolved and implemented** — remainder to the highest-value output, ties to the lowest outpoint (§10.5). |
| D22 | `Cargo.toml` said the halt was at 80,000 | **Superseded twice over.** The constant went to 50,000, and the chain in fact stopped at **39,918**. Do not use any of the three as a live figure. |
| D23 | `tokenomics_v4.rs` comments stale vs. its constants | **Partly resolved.** The carryover comment now records both the terminal figures and the 43,172 block-count error (§10.6). The standing advice does not change: **quote the constants and the compile-time assertions, never the surrounding comments.** |
| D24 | Terminal height not enforced in the RPC; miners would burn work | **Moot.** Genesis-3 no longer produces blocks and there is no mining on Genesis-4. |
| D25 | "Not wired into the node" | **Resolved.** The UNAUDITED half still stands and is load-bearing (§11.2). |

### 12.5 Documentation status

| # | Claim | Reality | Severity |
|---|---|---|---|
| D16 | `docs/API.md` is current | Self-sealed as a "Genesis-3-era document, sealed 2026-08-12", superseded by `docs/specs/BLOCH-RPC-V4.md` — which is itself marked **DRAFT** and describes an unimplemented surface. **There is no current, accurate published RPC specification.** This document is intended to close that gap. | **High** |
| D17 | `posternlabs.com/docs` publishes an integration spec | Publishes an institutional PDF dossier; "Migration & carryover", "Tokenomics V4" and the PoS design are listed as *in review*. The criticism is accurate. | **High** |

---

## 13. What was NOT verified against the live node

Stated explicitly so you can calibrate how much of this document is measurement
and how much is source reading.

**Verified by calling the live Genesis-3 node** (2026-08-13): every claim in
§2, §3, §4, §5.1, §5.3; the address encoding in §6 (independently reimplemented
and reproduced against five live and in-tree values); the presence/absence of
all 40 dispatch methods.

**Read from source, NOT executed:**

1. **The entire signing path (§7.5, §7.6).** No transaction was constructed,
   signed or broadcast. Doing so requires a funded mainnet key, and generating a
   production key was out of scope for this document. The sighash preimage,
   the bincode encoding, the envelope layout and the AND-verification are read
   from `crates/bloch-crypto/`, not demonstrated. **Before you move value, build
   a known-answer test against a node you control and confirm a real signature
   verifies.** This is the largest unverified surface here.
2. **The wire serialization round-trip (§7.2, §7.3).** `sendrawtransaction` was
   exercised only with deliberately invalid input to capture error strings. No
   valid transaction was serialized or accepted.
3. **Fee, dust and size rules (§8).** Constants read from source; no
   transaction was submitted to observe enforcement.
4. **The terminal-height halt (§0.1).** At measurement time the constant and its
   four enforcement sites were read from source and the halt had not been
   observed. **It has since happened, at height 39,918 — below the 50,000
   constant, because the chain was stopped rather than left to reach it.** The
   coins between 39,918 and that ceiling were never minted, which is why the
   carryover is a measured figure and not a derived one.
5. **Everything about Genesis-4 (§5, §10, §11).** At the time of the 2026-08-13
   measurement there was no Genesis-4 chain to call. **Those sections were
   revised on 2026-08-14 against the source of the now-running node, and they
   are still source reading, not measurement.** The finality parameters are read
   from `finality.rs` and `params.rs`; the RPC surface from `rpc.rs`; the
   mempool refusal from `engine.rs`. **No epoch was observed justifying or
   finalizing by the author of this document, and no RPC call was made against
   `posternlabs.com/g4rpc`.** Before you credit anything, call the endpoint
   yourself and confirm that `getchaininfo` returns a `finalized_height` that
   advances. This is the largest unverified surface in the current revision and
   we would rather name it than let it pass.
6. **The Genesis-3 → Genesis-4 snapshot (§10).** The terminal snapshot was
   taken at the halt; its figures are read from the pinned constants in
   `tokenomics_v4.rs`, not from the file. The format in §10.3 and the
   verification in §10.4 were read from source and cross-checked against the
   *Genesis-1 → Genesis-3* artifact shipped in this repository
   (`carryover.tsv.gz`, 413,743 rows, both published SHA-256 checksums
   verified) — **note that this shipped file is the earlier migration and is
   not the Genesis-3 → Genesis-4 snapshot.** The §10.2 conversion arithmetic
   was computed independently from the constants. **The snapshot is not
   signed** (§10.4); if you want assurance, ask us for the root through a
   second channel and reproduce the file from an archive node.
7. **Reorg behaviour (§5.6).** `CHECKPOINT_DEPTH` and the `finalized_height`
   gate are read from Genesis-3 source. No reorg was observed; `tip_count` was
   `1` throughout, so no fork was visible during measurement. **No reorg has
   been observed on Genesis-4 either**, and none of §5.1's finality behaviour
   has been exercised adversarially by us.
8. **Rate limits (§3, §4.9).** The 60 reads/min and 5 writes/min defaults are
   from source and `docs/API.md`. They were not deliberately tripped — probing
   stayed well under them.
9. **Authentication (§3).** The `-32001` path was not exercised; the public
   endpoint has no auth configured, so no request could produce it.
10. **`getattestation` with a live TEE.** The node answers `attested: false`; the
   populated response shape is unverified.

Measurements were taken from a single vantage point against a single node. All
`tip_height`/`block_count` figures are live values that have advanced since.

---

## Appendix A — Quick reference

### Genesis-4 — the live chain

```bash
# Chain state, including the number you gate deposits on.
# Check `behind_by_slots` before trusting `finalized_height`.
curl -sS -X POST https://posternlabs.com/g4rpc -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getchaininfo","params":[]}'

# Balance for a script hash (amounts are decimal STRINGS — parse as big integers)
curl -sS -X POST https://posternlabs.com/g4rpc -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getbalance","params":["<script_hash_hex>"]}'

# One block, with the deposit decision on it
curl -sS -X POST https://posternlabs.com/g4rpc -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getblockbyslot","params":[<slot>]}'

# THE DEPOSIT RULE: credit when block.finalized == true. Nothing else.
# There is no confirmation count on this chain, and waiting extra blocks
# past finalisation buys nothing (§5.1).
```

| Constant | Value |
|---|---|
| Live chain | **Genesis-4, proof of stake**, since 21:31:19 UTC 2026-08-13 |
| Block header version | `0xB10C_0005` — renders as `2970353669`; do not "fix" it to `4` |
| Public read RPC | `https://posternlabs.com/g4rpc` |
| Node RPC default bind | `127.0.0.1:16310` (`--rpc-port off` disables) |
| Slot / epoch | 30 s / 32 slots = 16 min |
| Committee size | 128 (slot subcommittee 8) |
| Validators | 64, **all operated by one entity** |
| Time to finality | ≈ 32 min typical, ≈ 48 min worst case |
| Deposit rule | `finalized == true`. **Not a confirmation count.** |
| Hard cap | 100,000,000,000 BLCH |
| Issued at slot 0 | 57,146,400,000 BLCH |
| Carryover | 18,146,400,000 BLCH, 452,726 outputs, at G3 height 39,918 |
| Signing | ML-DSA-65 ‖ Falcon-1024, both halves verified. **No HSM can do this.** |
| Amounts | decimal **strings** — 10^19 sat is 54.21% of `u64::MAX` |
| Staking | `Deposit`/`Delegate` **refused at the mempool** |
| Transport | TCP full mesh, fixed peer list, no discovery, no auth — you cannot join |

### Genesis-3 — historical, chain halted

```bash
# These endpoints served a chain that stopped at height 39,918 on 2026-08-13.
# Retained for provenance only. Do not build against them.
#   https://g2rpc.posternpool.com/   (direct node)
#   https://blochl1.com/rpc          (read-only proxy)
```

| Constant | Value |
|---|---|
| Chain ID (Genesis-3 mainnet) | `0xB10C_0004` |
| Genesis block hash | `c7522d0ef29fe67463be45a8095db7f5e23b9542dde867363ea3131647aff348` |
| **Terminal chain height (actual)** | **39,918** — the chain was stopped, not left to reach the 50,000 constant |
| Terminal DAG block count | 50,690 |
| Address prefix | `bloch1q` mainnet / `bloch1t` testnet, 55 chars total — **carried into Genesis-4 unchanged** |
| Satoshi | 1 BLCH = 10^8 sat |
| Dust | 546 sat |
| Min relay fee | 1 sat/byte (bincode length) |
| Coinbase maturity | 100 blocks |
| Target / measured block time | 30 s / 20.04 s |
| Signature suite | ML-DSA-65 ‖ Falcon-1024, verified AND |
