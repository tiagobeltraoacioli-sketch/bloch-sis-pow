<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Bloch Genesis-4 — the JSON-RPC surface


> ### STATUS — RECOVERED AND VERIFIED, NOT PUBLISHABLE AS WRITTEN
>
> This document was written on **2026-08-13** from measurement, on the branch
> `worktree-agent-afaacd9bb218fa648`
> (commit `ef1deeb9`), and was never landed. It existed on that ref and on no
> other; it is recovered here on **2026-09-01**, before that branch is deleted,
> because the measurement in it is worth keeping.
>
> **It has not been rewritten.** The body below is the 2026-08-13 text
> verbatim. Every falsifiable claim in it was re-checked against `main` @
> `737078d1` on 2026-09-01, and where the tree has since moved, a
> **CORRECTION** block sits immediately above the affected section. Read those
> blocks; the prose underneath them was true when written and is not true now.
>
> **Six corrections below. Three of them are not editorial** — following the
> uncorrected text would cause real harm, not just confusion.
>
> The full verdict, claim by claim — including what could **not** be verified
> from source alone and needs a live node — is in
> `docs/integration/BLOCH-G4-DOCS-VERIFICATION-2026-09-01.md`.
>
> Do not send this to an integrator, and do not publish it, until §§ marked
> CORRECTION are rewritten and the captures re-measured against a current node.

```
Document:   BLOCH-G4-RPC
Status:     MEASURED — every response below was captured from the live endpoint
Measured:   2026-08-13, 16:44–17:15 UTC
Endpoint:   https://posternlabs.com/g4rpc
Sources:    crates/bloch-pos-node/src/rpc.rs (dispatch, formatting, error contract)
            crates/bloch-pos-node/src/engine.rs (handlers, finality classification)
            docs/specs/BLOCH-RPC-V4.md (design rationale)
            ~/dev/posternlabs-deploy/functions/g4rpc.js (edge proxy allowlist)
Scope:      The RPC transport only. Transaction format, address format and the
            Genesis-3→4 snapshot mapping are documented separately.
```

Every request and response in this document was issued against the live
endpoint and pasted back verbatim. Nothing here is transcribed from a
specification. That is deliberate: the previous integration document
(`docs/API.md`) was written from the spec, was never checked against a running
node, and the exchange found the discrepancies before we did.

---

## 0. Read this first: this is a TESTNET

`https://posternlabs.com/g4rpc` serves a **test network**, and three facts
about it are load-bearing before you read another line.

1. **It runs on throwaway keys.** The 52 validator keys were generated in an
   ordinary working session, on a normal machine, with no ceremony and no
   air-gap. They are not production key material and will not become it.

2. **Its genesis carries no balances.** The Genesis-3 snapshot exists and the
   node knows how to ingest it, but this chain's genesis has not. Every
   `getbalance` you issue against a real address will return `"0"`. That is
   correct, not a bug, and not a sync problem.

3. **It is relaunched at will, and relaunching resets everything.** The chain
   we measured has a genesis timestamp of **1786637615 = 2026-08-13T16:13:35Z**
   — thirty-one minutes before our first probe. Heights, slots and every
   `block_id` restart from zero when this happens. Do not persist a Genesis-4
   `block_id` or height across a testnet relaunch and expect it to resolve.

**Use this endpoint to build and test an integration. Do not credit a customer
against it.** When mainnet Genesis-4 exists it will be a different chain with a
different genesis, announced separately; the method surface documented here is
what will carry over, and the data will not.

A fourth fact, measured rather than designed, is in §4.5: during our observation
window block production **stopped entirely at height 69 and had not resumed
eight minutes later**, and finality never advanced past genesis — the only block
we ever saw report `finalized: true` was genesis itself. The endpoint stayed
responsive throughout and reported no error. Read §4 before you build a deposit
gate, and build the gate to wait rather than to assume.

---

## 1. The endpoint, and the two paths to it

There are two ways to reach a Genesis-4 node, and **they do not answer
identically.** An integrator hitting the public URL is talking to the proxy, and
several of the codes they will see are the proxy's, not the node's.

### 1.1 The public path (what you will use)

```
POST https://posternlabs.com/g4rpc
Content-Type: application/json
```

A Cloudflare Pages Function (`functions/g4rpc.js`) parses the request, checks
the method against an allowlist, re-serialises it, and forwards it to the node.
It never forwards the raw body.

### 1.2 The node path (what the code does)

The node's own RPC is `rpc.rs`'s hand-rolled HTTP/1.1 server. It
**authenticates nothing** — no API key, no rate limit, no per-method
authorisation — which is why `--rpc-bind` defaults to `127.0.0.1` and why the
public endpoint is fronted by an allowlisting proxy rather than exposed
directly. If you run your own node (and for a deposit gate you should — see
§4.2), you are talking to this server, and the differences in §1.4 apply in
reverse.

### 1.3 The HTTP contract

Measured against both paths:

| Property | Proxy | Node |
|---|---|---|
| Method | `POST` only; `OPTIONS` returns `204` with CORS headers | `POST` only |
| Non-POST | **Returns the website's HTML with HTTP 200** — see below | `405` + JSON-RPC `-32600` |
| `Content-Type` | Not enforced — a POST with no content-type succeeded | Not enforced |
| Transfer-encoding | n/a | Chunked refused: **`411` measured** |
| `Content-Length` | n/a | Required: `411` if absent |
| Max body | n/a | 1 MiB → **`413` measured** (1,200,063 bytes rejected) |
| Max header | n/a | 16 KiB → **`431` measured** (20 KiB header rejected) |
| Keep-alive | HTTP/2 via Cloudflare | None — `Connection: close`, one request per connection |
| Concurrency cap | Cloudflare's | 64 connections → `503` (not exercised) |
| Socket timeout | 12 s to upstream | 30 s read/write; 10 s waiting on the consensus thread |
| CORS | `access-control-allow-origin: *` | None |
| HTTP status on a JSON-RPC error | Always `200` | `200` (HTTP codes only for HTTP-level faults) |

**HTTP-level faults carry a JSON-RPC body too.** The node never drops the
connection on a bad request — it answers with an HTTP error status *and* a
well-formed JSON-RPC envelope, always coded `-32600`, so a client that only
parses bodies still gets a usable answer. Measured:

```
HTTP/1.1 411 Length Required
{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"invalid request: chunked transfer-encoding is not supported; send Content-Length"}}

HTTP/1.1 413 Payload Too Large
{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"invalid request: request body too large"}}

HTTP/1.1 431 Request Header Fields Too Large
{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"invalid request: request header too large"}}
```

Note the consequence for `sendrawtransaction`: the 1 MiB body cap is the real
ceiling on a submittable transaction, and it is enforced before any parsing.

**Parser bounds**, measured against the node — all reported as `-32700` with
HTTP 200:

| Input | Message |
|---|---|
| JSON nested deeper than 64 levels | `parse error: nesting too deep` |
| Body that is not valid UTF-8 | `parse error: body is not UTF-8` |
| A number with a leading zero (`01`) | `parse error: number has a leading zero` |
| Malformed object | `parse error: object key must be a string` |

The depth bound is a stack-overflow guard, not fussiness: the parser is
recursive and this is an unauthenticated port, so an unbounded nesting depth
would let one request kill a validator. The leading-zero refusal keeps the
encoding injective — a number with two spellings is a value with two
encodings.

**The GET trap.** A `GET https://posternlabs.com/g4rpc` returns
`content-type: text/html` with **HTTP 200** — the Pages Function only defines
`onRequestPost` and `onRequestOptions`, so anything else falls through to the
static site. A client that health-checks with a GET and asserts on the status
code will report the endpoint healthy no matter what the node is doing. Health-
check with a real `POST getblockcount`.


> **CORRECTION — 2026-09-01, verified against `main` @ `737078d1`.**
>
> Row 1 of this table is wrong. An **omitted** `jsonrpc` field does not give
> `-32600` at the node either — `rpc.rs:975` only checks the field when it is
> present, and `rpc/tests.rs:759` pins a successful request that omits it. Only
> a *wrong* value is refused. This row is not a proxy/node divergence at all.

### 1.4 Where the two paths disagree

These are measured divergences, not theory. All four matter.

| Case | Proxy answers | Node answers |
|---|---|---|
| `gettransaction` | `-32601` "not exposed by this proxy" | `-32005` with the full reasoning |
| `getnewaddress` | `-32601` "not exposed by this proxy" | `-32006` with the full reasoning |
| Any method outside the allowlist (`getpeerinfo`, `bogusmethod`, …) | `-32601`, message names `gettransaction`/`getnewaddress` **regardless of what you asked for** | `-32601` "method not found: `<name>`" |
| `"jsonrpc": "1.0"`, or the field omitted entirely | **Succeeds.** The proxy discards your envelope and re-serialises with `jsonrpc: "2.0"` hardcoded | `-32600` "`jsonrpc` must be \"2.0\"" |

The third row is worth dwelling on. Ask the proxy for `getpeerinfo` and it
replies:

```json
{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method 'getpeerinfo' is not exposed by this proxy. Genesis-4 refuses gettransaction and getnewaddress at the node itself — there is no transaction id at this layer and the node holds no wallet."}}
```

The explanatory half of that message is about two *other* methods and does not
apply to `getpeerinfo`. Read the quoted method name, not the prose.

**The `-32000` collision.** This is the one that can actually cost you. At the
node, `-32000` is `BLOCK_NOT_FOUND` — a permanent answer about a specific
block. At the proxy, `-32000` is *upstream unreachable* — a transport failure
you should retry. Same code, opposite handling. Disambiguate on the message:
the proxy's begins `upstream Genesis-4 node unreachable`. If you are writing a
retry policy, this is the single place where branching on the code alone is
wrong.

---

## 2. Conventions that apply to every method

**Amounts are decimal strings, never JSON numbers.** `"20000000000000"`, not
`20000000000000`. This is rule R3 of the V4 spec and it is not stylistic: the
V4 supply cap is 10^19 satoshi, roughly 1110× JavaScript's 2^53 exact-integer
limit, so a JSON number is silently corrupted by every browser that parses it.
Counts, slots, epochs, heights and indexes *are* JSON numbers — they are small
and bounded. The rule is per-field: if it is denominated in satoshi it is a
string.

Denomination: 1 BLCH = 10^8 satoshi. `"2060000000000000"` is 20,600,000 BLCH.

**Errors are always the top-level `error` object.** Never a string inside
`result` under HTTP 200. Genesis-3 did the latter and every client carries a
shim for it; V4 does not.

**Parameters may be positional or named.** Both are accepted and both were
measured:

```json
{"method":"getblockbyslot","params":[2]}
{"method":"getblockbyslot","params":{"slot":2}}
```

**Integer parameters also accept decimal strings.** `"params":["3"]` returned
slot 3. Deliberate: R3 makes clients string-minded about large integers, so
refusing a stringified slot would be gratuitous. Non-integers (`1.5`, `1e3`)
are refused rather than truncated.

**Hex parameters accept an optional `0x` prefix.** `getbalance` with
`"0x1111…"` returned `script_hash` normalised to `1111…` without the prefix.

**Batching is not supported** on either path. Send one call per request.

**Your `id` is echoed verbatim**, including string ids and absent ids (which
come back as `null`). This holds even when the rest of the request was
nonsense, which is what lets you correlate an error with the call that caused
it.

Verbatim means *exactly* verbatim, including integers a double cannot hold. We
sent `id: 9007199254740993` (2^53 + 1) and got it back unchanged:

```json
{"jsonrpc":"2.0","id":9007199254740993,"result":{"height":69,…}}
```

The node keeps numeric values as their raw source text rather than parsing them
into floats, which is the same discipline that makes satoshi amounts safe. Your
own JSON library is now the weakest link in that chain — most will silently
round this id.

---

## 3. Method reference

Ten methods are reachable through the public endpoint. Every response below is
a real capture.

### 3.1 `getchaininfo`

**Purpose.** The whole head-state in one call: tip, epoch position, both
checkpoints, validator-set size, fee state, and sync lag. This is the method a
finality-aware consumer polls.

**Params.** None.

**Captured** (2026-08-13 16:50:36 UTC, during the stall described in §4.5):

```json
{"jsonrpc":"2.0","id":1,"result":{
  "block_id":"b23460b2bcfafe469f39254757a34c36ab51a4dae747b4a5764ae731b9d53d63",
  "slot":69,
  "height":69,
  "finalized_height":0,
  "epoch":2,
  "slot_in_epoch":5,
  "slots_per_epoch":32,
  "state_root":"31469624986a57a710487fd0fce1313d59fe45fe754b70ed6beed909c171ed93",
  "justified":{"epoch":1,"root":"020dc665ad2c6ff7991a3c9a94f7860c02178f5d14da2196cc247df5792252b7"},
  "finalized":{"epoch":0,"root":"9953da73a2794e190b1c551a787f39d6486a288f40b69ecc361281d5a893e415"},
  "previous_justified":{"epoch":0,"root":"9953da73a2794e190b1c551a787f39d6486a288f40b69ecc361281d5a893e415"},
  "validators":{"total":52,"active":52},
  "total_active_stake_sat":"2073231885900104",
  "base_fee_millisat_per_gas":"10",
  "next_base_fee_millisat_per_gas":"10",
  "mempool":1,
  "blocks_known":69,
  "wall_slot":76,
  "behind_by_slots":7
}}
```

**What the fields mean, where "what it is" is not enough:**

- `height` vs `slot` — **not the same number, and the gap is information.**
  Slots tick every 30 seconds whether or not anyone proposes; height counts
  blocks that exist. `slot − height` is the count of missed proposals since
  genesis. In the capture they are equal (69/69), meaning no proposal had been
  missed up to that point. Do not assume they stay equal.
- `finalized_height` — the canonical height at or below which this node's
  history is settled. **This is the number a deposit gate cares about**, and it
  is `0` in the capture, meaning nothing but genesis was final. See §4.
- `wall_slot` and `behind_by_slots` — the slot the clock says it is, and the
  gap to the node's head. Under PoS there is no difficulty and no depth to
  infer sync state from, so the node states it. `behind_by_slots: 7` here means
  the chain had produced nothing for three and a half minutes. **A non-trivial
  `behind_by_slots` means the answer you just got is stale**, and it is the
  first thing to check before trusting any other field.
- `blocks_known` vs `height` — blocks in the store versus blocks on the
  canonical chain. Equal here; a divergence means the node is holding
  non-canonical forks.
- `total_active_stake_sat` — **this grows.** It read `"2060000000000000"` at
  16:44 and `"2073231885900104"` at 16:50 as staking rewards accrued. It is not
  a constant and must not be cached as one.
- `justified` / `finalized` / `previous_justified` — Casper checkpoint pairs,
  each `{epoch, root}`. `root` is a `block_id`.
- `base_fee_millisat_per_gas` — millisatoshi per gas, so `"10"` is 0.01 sat/gas.
- `mempool` — pending transaction count, same value as `getmempoolinfo.size`.

**Errors.** None specific to this method. Transport errors (§6) apply.

### 3.2 `getblockcount`

**Purpose.** The polling method. Returns height *and* the finality state that
height is entitled to, in one call.

**Params.** None.

**Captured:**

```json
{"jsonrpc":"2.0","id":1,"result":{
  "height":69,
  "slot":69,
  "epoch":2,
  "finalized_height":0,
  "justified_epoch":1,
  "finalized_epoch":0
}}
```

**Note the shape.** Genesis-3's `getblockcount` returned a bare integer. V4
returns an object, on purpose: a client given only a height will reinvent
confirmation counting on top of it, which is exactly the mistake §4.4
documents. `height` is what exists; `finalized_height` is what is safe; the gap
between them is the only lag that matters.

**Errors.** None specific.

### 3.3 `getmempoolinfo`

**Purpose.** Pending-transaction queue depth and the next block's base fee.

**Params.** None.

**Captured**, before and after we submitted one transaction:

```json
{"jsonrpc":"2.0","id":1,"result":{"size":0,"max":4096,"bytes":0,"next_base_fee_millisat_per_gas":"10"}}
{"jsonrpc":"2.0","id":1,"result":{"size":1,"max":4096,"bytes":33,"next_base_fee_millisat_per_gas":"10"}}
```

- `size` — transactions pending. `max` is 4096; reaching it is what produces
  `-32003` from `sendrawtransaction`.
- `bytes` — total canonical bytes of the pending set.
- The mempool is **in-RAM and not persisted**. A node restart drops it. A
  submitted transaction that has not yet appeared in a block is not durable.

**Errors.** None specific.

### 3.4 `getblockbyslot`

**Purpose.** Fetch the canonical block at a slot. This is the block-scanning
primitive — with no transaction index (§5.1), walking slots is how you find
anything.

**Params.**

| # | Name | Type | Required |
|---|---|---|---|
| 0 | `slot` | unsigned integer, or a decimal string | yes |

**Captured** (slot 1):

```json
{"jsonrpc":"2.0","id":1,"result":{
  "block_id":"6f6a66d877e44b6eb3ecf57b077452ff06cd9b83c8ac17a334fec56b4f1911e0",
  "version":2970353669,
  "parent":"9953da73a2794e190b1c551a787f39d6486a288f40b69ecc361281d5a893e415",
  "slot":1,
  "epoch":0,
  "height":1,
  "proposer_index":28,
  "timestamp":1786637645,
  "state_root":"3b31edfb74b1e063f87caf09f73d9c80ffeee2ffb8a688f66e5291dced3b38ca",
  "body_root":"3d272a088c490760c4f7d74cb6c3d2275f884842ad4e6ccb9e40a34a9e5a8400",
  "randao_reveal":"14954de9c3e3772131cd5773c1f52e6998439235acfd856a1a9b43c51dd396c9",
  "randao_mix":"e7958b6c325a899d45c5444b4f90278c0c9384d125705432f3f7a18615ace99d",
  "justified_root":"9953da73a2794e190b1c551a787f39d6486a288f40b69ecc361281d5a893e415",
  "finalized_root":"9953da73a2794e190b1c551a787f39d6486a288f40b69ecc361281d5a893e415",
  "attestation_root":"65617f7b01ac604f1325a4c7d4f87a26ed6278c8f11b20426f8515e7ec477989",
  "coherence_root":"3ac97a48fe4c1dc2de33022b2473e76e609c85ce0c0bce96540851f682bccb56",
  "finality":"canonical",
  "finalized":false,
  "tx_count":0,
  "attestation_count":0
}}
```

**Field meanings that are not obvious:**

- `version: 2970353669` — **this is correct; do not "fix" it to 4.** It is the
  header's version field verbatim: `0xB10C0005`, a 32-bit magic, rendered as
  decimal. A client that recomputes `block_id` hashes the 304 header bytes
  *including this field*, so emitting a friendlier `4` would hand you a number
  you could not verify anything with.
- `block_id` — SHA3-256 over the header. **The only identity.** Genesis-3 had
  two (`pow_hash` and `block_hash`) and the split caused a tip-selection stall;
  V4 has one everywhere.
- `timestamp` — **derived from the slot for display, not a consensus field.**
  `BlockHeaderV4` carries no time. It is exactly `genesis_time + slot × 30`.
  Never use it as evidence of when anything happened.
- `parent` — a scalar, not an array. There is no DAG.
- `height` — canonical height, or `null` for a block the node stores but has
  not adopted.
- `finality` / `finalized` — see §4. The string carries the gradation
  (`finalized | justified | canonical | not_canonical`); the boolean is the one
  you branch on.
- `attestation_count` — attestation **records** in the body, not the number of
  validators that attested. We measured `0` for early blocks and `2` for blocks
  from slot 32 onward. Whether each record is an aggregate covering many
  validators is stated in the spec but is **not verifiable through this RPC
  surface** — see §7.
- `tx_count` — transactions in the body.

**Errors.**

| Code | Condition | Captured |
|---|---|---|
| `-32007` `SLOT_EMPTY` | The slot carries no canonical block. **Normal under PoS** — a proposer missed its turn. Advance to the next slot; do not alert. | `{"code":-32007,"message":"no canonical block at slot 999999 (head is at slot 48); a slot with no block is a missed proposal, not an error"}` |
| `-32602` | `slot` absent | `{"code":-32602,"message":"invalid params: missing \`slot\`"}` |
| `-32602` | `slot` not a non-negative integer (e.g. `1.5`) | `{"code":-32602,"message":"invalid params: \`slot\` must be a non-negative integer"}` |
| `-32000` | The slot names a block the node no longer stores (pruning). Not reproduced on this testnet. | — |

`-32007` is the code that makes a scanner correct. A slot past the head and a
slot a proposer skipped return the *same* code, so a scanner that treats
`-32007` as "advance" works in both cases — but it must independently bound
itself with `getblockcount.height`, or it will walk forward forever.

### 3.5 `getblockbyid`

**Purpose.** Fetch a block by its `block_id`. Use this to confirm that the
block you recorded at a height is still the block at that height.

**Params.**

| # | Name | Type | Required |
|---|---|---|---|
| 0 | `block_id` | 32-byte hex string, 64 chars, optional `0x` | yes |

**Captured** — round-tripped from `getblockbyslot [10]`, returning the
identical block. Response shape is exactly §3.4's.

```json
{"jsonrpc":"2.0","id":1,"result":{"block_id":"5cbcfe5b598d0b6a40d27c69b7da38d4f321ece84d49fc39cd29684ad71d4a31","version":2970353669,"parent":"dc5db22ecab98ccfec700dfb95bb20f29f80d5f70fd0a8cc016d46bbca422f1c","slot":10,"epoch":0,"height":10,"proposer_index":3,"timestamp":1786637915,…,"finality":"justified","finalized":false,"tx_count":0,"attestation_count":0}}
```

**Genesis is fetchable** and answers in the ordinary block shape, with all-zero
roots and `parent` all zeros:

```json
{"jsonrpc":"2.0","id":1,"result":{"block_id":"9953da73a2794e190b1c551a787f39d6486a288f40b69ecc361281d5a893e415","version":2970353669,"parent":"0000000000000000000000000000000000000000000000000000000000000000","slot":0,"epoch":0,"height":0,"proposer_index":0,"timestamp":1786637615,"state_root":"0000000000000000000000000000000000000000000000000000000000000000",…,"finality":"finalized","finalized":true,"tx_count":0,"attestation_count":0}}
```

Genesis is synthesised from the manifest rather than stored, so that it answers
in the normal shape instead of being a special case clients must handle.

**Errors.**

| Code | Condition | Captured |
|---|---|---|
| `-32000` `BLOCK_NOT_FOUND` | No block with that id is known | `{"code":-32000,"message":"no block 0000…0000 is known to this node"}` |
| `-32602` | Not 32 bytes of hex — wrong length *or* non-hex characters both give this one message | `{"code":-32602,"message":"invalid params: \`block_id\` must be 32 bytes of hex (64 characters)"}` |
| `-32602` | `block_id` absent | `{"code":-32602,"message":"invalid params: missing \`block_id\`"}` |

Remember §1.4: through the proxy, `-32000` is ambiguous with "upstream
unreachable". Check the message.

### 3.6 `getvalidator`

**Purpose.** One validator's registry record.

**Params.**

| # | Name | Type | Required |
|---|---|---|---|
| 0 | `index` | unsigned integer, must fit in 32 bits | yes |

The V4 spec sketches lookup by `pubkey_hash` as well; **only lookup by index is
implemented.** A string that is not a decimal integer is rejected.

**Captured** (index 0):

```json
{"jsonrpc":"2.0","id":1,"result":{
  "index":0,
  "pubkey_hash":"b8a7122d9b59be390ac7c8cceb948a082f8ab7fbc44d5b5cb11b519563e96cc2",
  "pubkey_bytes":3749,
  "state":"active",
  "own_stake_sat":"20000000000000",
  "effective_stake_sat":"20000000000000",
  "commission_bps":"0",
  "randao_commitment":"62373a03a9b84736d7da9cb96d75560cec2d6c04584d45e2ca070a62ee40975e",
  "slashed":false,
  "activation_epoch":0,
  "exit_epoch":null,
  "withdrawable_epoch":null
}}
```

**Field meanings:**

- `pubkey_bytes: 3749` — the **size** of the public key, not the key. 3749
  bytes is the hybrid post-quantum key (ML-DSA ‖ Falcon). The key itself is
  returned only as `pubkey_hash` (SHA3-256). This is the number your custody
  team should look at first: no HSM on the market holds a key of this shape.
- `state` — `queued | active | exiting | exited | slashed`. `slashed` outranks
  everything: a slashed validator whose exit epoch has not arrived reads
  `slashed`, not `exiting`.
- `own_stake_sat` vs `effective_stake_sat` — own stake as committed, versus the
  weight the active set actually samples this epoch (post the 1% iterated cap).
  `effective_stake_sat` is **`null`, not `0`**, for a validator the active set
  does not carry. "Not sampled this epoch" and "sampled with no weight" are
  different states and the encoding keeps them apart.
- `commission_bps` — reported **verbatim**, including a value above the
  consensus cap. Consensus applies the cap; the RPC does not launder the
  committed value into it. A rate someone set above the cap is visible here.
  Present on every validator response by design (rule R5): V4 tokenomics leaves
  commission uncapped on the explicit bet that clients surface the rate.
- `activation_epoch` / `exit_epoch` / `withdrawable_epoch` — **`null` means
  "never"**, encoding `u64::MAX`. Do not read `null` as zero or as unknown.

**Measured set composition.** We enumerated all 52 records. Every one reads
`state: "active"`, `commission_bps: "0"`, `slashed: false`,
`activation_epoch: 0`, `pubkey_bytes: 3749`. Stakes cycle in a repeating
three-step pattern by index:

| index mod 3 | `own_stake_sat` | BLCH |
|---|---|---|
| 0 | `"20000000000000"` | 200,000 |
| 1 | `"40000000000000"` | 400,000 |
| 2 | `"60000000000000"` | 600,000 |

17 complete triples (indexes 0–50) plus index 51 at 20 trillion sums to exactly
`2060000000000000` — the `total_active_stake_sat` reported at genesis, which
confirms the enumeration is complete and the aggregate is consistent with the
per-record values.

**Errors.**

| Code | Condition | Captured |
|---|---|---|
| `-32001` `VALIDATOR_NOT_FOUND` | Index not in the committed registry | `{"code":-32001,"message":"validator 9999 is not in the committed registry (52 registered)"}` |
| `-32602` | Index does not fit in 32 bits | `{"code":-32602,"message":"invalid params: \`index\` must fit in 32 bits (got 4294967296)"}` |
| `-32602` | `index` absent or not an integer | `invalid params: missing \`index\`` |

The `-32001` message carries the registry size, so a client that walks indexes
until it errors learns the bound from the error itself.

### 3.7 `getvalidatorcount`

**Purpose.** Set size and aggregate stake without enumerating 52 records.

**Params.** None.

**Captured:**

```json
{"jsonrpc":"2.0","id":1,"result":{
  "total":52,
  "active":52,
  "total_active_stake_sat":"2060000000000000"
}}
```

- `total` — registered validators, all states.
- `active` — those in the current epoch's active set.
- `total_active_stake_sat` — summed effective stake of the active set. Grows
  with rewards; see §3.1.

**Errors.** None specific.

### 3.8 `getbalance`

**Purpose.** Summed value of every unspent output locked to a script hash.
Exact — computed from the committed eUTXO set, not an index that can drift.

**Params.**

| # | Name | Type | Required |
|---|---|---|---|
| 0 | `script_hash` | 32-byte hex string, 64 chars, optional `0x` | yes |

**This does not take an address.** It takes a 32-byte script hash. Genesis-4
has not frozen an address format (§5.2), so there is nothing else it could
take. The mapping from whatever address form you hold to a script hash is the
transaction-format pass's subject, not this document's.

**Captured:**

```json
{"jsonrpc":"2.0","id":1,"result":{"script_hash":"0000000000000000000000000000000000000000000000000000000000000000","balance_sat":"0","utxo_count":0}}
```

With a `0x` prefix on input, the prefix is stripped in the echoed value:

```json
{"jsonrpc":"2.0","id":1,"result":{"script_hash":"1111111111111111111111111111111111111111111111111111111111111111","balance_sat":"0","utxo_count":0}}
```

- `balance_sat` — decimal string, satoshi.
- `utxo_count` — how many outputs make up that balance. Relevant because
  `getutxos` pages and this is the total to page against.

**Every balance on this testnet is `"0"`** — genesis carries no balances (§0).
A zero here is not evidence that your script-hash derivation is wrong.

**Errors.**

| Code | Condition | Captured |
|---|---|---|
| `-32602` | Not 32 bytes of hex | `{"code":-32602,"message":"invalid params: \`script_hash\` must be 32 bytes of hex (64 characters)"}` |
| `-32602` | `script_hash` absent | `invalid params: missing \`script_hash\`` |

An unknown script hash is **not an error** — it returns a zero balance. There
is no way to distinguish "never used" from "used and emptied" through this
method.

### 3.9 `getutxos` (alias `listunspent`)

**Purpose.** The individual unspent outputs behind a balance.

**`listunspent` is the same request as `getutxos`** — same handler, same
semantics, two names so a Genesis-3 client ports by re-pointing its endpoint.
There is deliberately no second semantics for the second name; that is how a
client ends up with two disagreeing balances.

**Params.**

| # | Name | Type | Required | Default |
|---|---|---|---|---|
| 0 | `script_hash` | 32-byte hex string | yes | — |
| 1 | `limit` | unsigned integer | no | 100 |

`limit` is **clamped, not rejected**, to the range 1–1000. We sent `99999` and
got a normal response. `null` is accepted and means "default".

**Captured:**

```json
{"jsonrpc":"2.0","id":1,"result":{
  "script_hash":"0000000000000000000000000000000000000000000000000000000000000000",
  "total":0,
  "returned":0,
  "truncated":false,
  "utxos":[]
}}
```

- `total` — matching outputs that exist.
- `returned` — how many this response carries.
- `truncated` — `true` when `total > returned`.
- `utxos[]` — each entry is `{txid, vout, value_sat, script_hash}`.

**There is no cursor.** Pagination is by `limit` only, so an address with more
than 1000 outputs **cannot be walked incrementally through this method** — you
can raise `limit` to 1000 and you cannot ask for "the next page". `truncated`
tells you the page was cut; it does not help you get the rest. This is a known
limitation, stated rather than papered over with a pagination protocol the
OpenAPI V4 freeze has not decided on. If you need to enumerate a large address,
you need a different method than this one, and it does not exist yet (§7).

**A note on `txid` inside a UTXO entry.** The eUTXO entries carry a `txid`
field. This is *not* contradicted by §5.1's "there is no transaction id": the
eUTXO set's `txid` is an outpoint reference within the state model, and there
is no method that resolves one to a transaction. You cannot pass it to
anything. We could not verify what it contains on this testnet because the
UTXO set is empty (§7).

**Errors.** Same as `getbalance`, plus:

| Code | Condition |
|---|---|
| `-32602` | `limit` present but not a non-negative integer |


> **CORRECTION — 2026-09-01, verified against `main` @ `737078d1`.**
>
> **This section is the most dangerous page in the document. Do not follow it.**
> Three things changed within hours of it being written:
>
> 1. **Admission validates now.** The claim below that admission checks only
>    "already pending" and "mempool full", with no signature check, was made
>    obsolete by `72de2e93`/`4fd5731c` (both 2026-08-13) and `b9a2b745`
>    (2026-08-18). `engine.rs:1382` calls `admissible()`; `engine.rs:2711+`
>    refuses `Deposit`, `Delegate`, empty inputs and empty outputs, and at
>    `engine.rs:2767-2772` **verifies every input's hybrid signature**.
> 2. **The worked example is refused today.** The zero-input, zero-output
>    `Transfer` submitted below now returns `-32008` ("transfer has no inputs —
>    it spends nothing and cannot apply"). Its capture, its `tx_hash`, the
>    duplicate-resubmission capture, and §3.3's `size: 1 / bytes: 33` are all
>    unreproducible.
> 3. **That exact transaction is what halted the chain.** The stall this
>    document reports as undiagnosed in §4.5 was diagnosed the same day, in
>    `72de2e93`: this transaction was admitted, every proposer that selected it
>    failed with `produce refused: Transfer(0, NoInputs)`, and production
>    stopped at slot 69. Both fixes landed.
>
> The source reference `engine.rs:663` is also stale; that line is now inside
> `fn rolled_to`.
>
> Still correct below, verified byte-for-byte: the response fields, the
> `tx_hash_note` and `confirmation` strings, and the `-32602`/`-32002` message
> texts and the reasoning for that split. **`tx_hash` is genuinely not a txid
> and no other node agrees on it — this document states that correctly**, and
> that is worth keeping.

### 3.10 `sendrawtransaction`

**Purpose.** Submit canonical transaction bytes to the mempool. The only method
on this surface that changes anything.

**Params.**

| # | Name | Type | Required |
|---|---|---|---|
| 0 | `hex` | hex string of the canonical bytes, optional `0x` | yes |

**Captured.** We submitted an inert transaction — a `Transfer` with zero
inputs, zero outputs, `tx_bytes = 0` and `tip = 0`, which moves nothing and
touches no account (33 bytes, hex `01` followed by 64 zeros):

```json
{"jsonrpc":"2.0","id":1,"result":{
  "accepted":true,
  "status":"accepted",
  "kind":"transfer",
  "bytes":33,
  "tx_hash":"65e8d35c3a22bf35ca3c6f34e88727de8429f01b5933c2be21f0beb9bf1b652f",
  "tx_hash_note":"local correlation handle only (SHA3-256 of the canonical bytes); not a consensus transaction id — no block commits to it",
  "confirmation":"this transport does not confirm: watch for the transaction in a block via `getblockbyslot`, and treat it as settled only once that block reports `finalized: true`"
}}
```

Resubmitting the identical bytes returns `status: "duplicate"` with
`accepted: true` — the client's intent is satisfied, so it is a success, but it
is reported distinctly so a resubmission loop can tell that it is looping:

```json
{"jsonrpc":"2.0","id":1,"result":{"accepted":true,"status":"duplicate","kind":"transfer","bytes":33,"tx_hash":"65e8d35c3a22bf35ca3c6f34e88727de8429f01b5933c2be21f0beb9bf1b652f",…}}
```

**Read `accepted: true` correctly — this is the most dangerous field on the
surface.** It means *the bytes decoded and were queued*. It does **not** mean
the transaction is valid. Mempool admission (`engine.rs:663`) checks exactly
two things: whether the bytes are already pending, and whether the mempool is
full. There is **no signature check, no balance check, no fee check, and no
double-spend check at submission time.** Our zero-input zero-output transfer
was accepted. A transaction spending money that does not exist would also be
accepted here and would simply fail to do anything when a block applied it.

Consequently: **`accepted: true` is not a receipt.** The `confirmation` field
in the response says so in the response itself. The only evidence a transaction
did anything is finding it in a block and that block reporting
`finalized: true`.

- `kind` — `transfer | deposit | exit | delegate | slashing_evidence`, decoded
  from the leading tag byte.
- `bytes` — canonical length.
- `tx_hash` — **a local correlation handle, not a transaction id.** SHA3-256
  over the canonical bytes, computed by this node for your convenience. No
  block commits to it, no other node agrees it names anything, and no method
  accepts it as input. Do not build deposit crediting on it. The response
  labels it itself, which is unusual and deliberate.

**Errors.**

| Code | Condition | Captured message |
|---|---|---|
| `-32602` | `hex` absent | `invalid params: missing \`hex\`` |
| `-32602` | Not valid hexadecimal | `invalid params: \`hex\` is not valid hexadecimal` |
| `-32602` | Decoded to zero bytes (empty string) | `invalid params: \`hex\` decoded to zero bytes` |
| `-32002` `TX_DECODE_FAILED` | Unknown leading tag | `not a canonical Genesis-4 transaction: unknown transaction tag 0xde` |
| `-32002` | Input ran out mid-field | `not a canonical Genesis-4 transaction: transaction truncated` |
| `-32002` | Decoded a whole transaction and bytes remained | `not a canonical Genesis-4 transaction: trailing bytes after transaction` |
| `-32002` | Slashing-evidence tag `0x05` | `not a canonical Genesis-4 transaction: slashing evidence is encoded one-way (signing roots, not envelopes) and cannot be recovered from a block body` |
| `-32003` `MEMPOOL_FULL` | Mempool at 4096 entries. **Retry later — the transaction was not judged invalid.** Not reproduced (mempool was empty). | — |

The `-32602`/`-32002` split is meaningful and worth branching on: `-32602` is a
client-side encoding mistake you can fix and retry; `-32002` means the bytes
are not a Genesis-4 transaction and **must not be retried unchanged**.

Trailing bytes and truncation are refused rather than tolerated because the
encoding must be injective — two encodings decoding to one transaction would
break the `body_root` commitment.

---


> **CORRECTION — 2026-09-01, verified against `main` @ `737078d1`.**
>
> **§3 is one method short.** The node routes **eleven** methods (twelve names,
> counting the `listunspent` alias); `gettxout` is missing here entirely
> (`rpc.rs:894-908`, landed `eb7874d3`, 2026-08-21).
>
> `gettxout(txid, vout=0)` answers one outpoint. Its response is exactly
> **`{txid, vout, unspent, utxo, at_slot}`** — `rpc.rs:1543-1560`. There is **no
> `finalized` field**; do not add one. `unspent: false` covers both "spent" and
> "never existed", and `at_slot` is returned either way, so the answer pins to a
> point on the chain rather than to the moment of the call.
>
> This also reverses §3.9's closing note: an eUTXO `txid` **can** now be passed
> to something — `gettxout` is exactly the method that resolves it. Whether the
> public proxy allowlists it is not verifiable from this repository.
>
> One more field is missing above: `gettransaction`'s `kind` also emits
> `"transfer_v2"` (`rpc.rs:1394-1401`, wire tag `0x06`) — six values, not five.

## 4. Finality — the section that matters most

### 4.1 The rule

**Gate deposits on `finalized: true` from the block containing the
transaction. Nothing else.**

Not a confirmation count. Not a depth. Not a number of blocks past
finalisation. There is no confirmation count on this surface because depth is
not what secures this chain, and adding one would only invite someone to gate
on it.

The guarantee behind that boolean is Casper justification and finalisation: a
finalised checkpoint cannot be reverted unless at least **one third of the
total active stake is slashed.** That is a bonded, attributable, on-chain cost
— someone loses identified money — rather than a probabilistic statement about
how much work an attacker would need. It is a different *kind* of guarantee
from Bitcoin's, not a stronger or weaker setting of the same dial.

Two corollaries follow, and both matter:

- **Waiting longer than finality buys nothing.** Blocks past a finalised block
  add no security to it. If you are tempted to wait "finalized plus 10 more
  blocks", you have misunderstood the mechanism.
- **Waiting a lot of blocks without finality buys nothing either.** A block a
  thousand deep behind a stalled finality gadget is reversible. Depth is not a
  weaker form of finality; it is not a form of finality.

### 4.2 The fields, and how to read them

Every block-returning method carries both:

```json
"finality": "canonical",
"finalized": false
```

`finality` is a four-value string; `finalized` is the boolean you branch on.
They are the same judgement — `finalized` is `true` exactly when `finality` is
`"finalized"` — emitted twice so that display code can show the gradation
without client code hardcoding the string set.

| `finality` | Meaning | Credit? |
|---|---|---|
| `finalized` | At or below the finalised checkpoint. Irreversible short of a ⅓-of-stake slashing event. | **Yes** |
| `justified` | At or below the justified checkpoint, above the finalised one. Normally one epoch from finality. Still reversible. | No |
| `canonical` | On this node's canonical chain, not yet justified. Reversible by ordinary fork choice. | No |
| `not_canonical` | Known to the node, not on its canonical chain. | No |

At the chain level, `getchaininfo.finalized_height` and
`getblockcount.finalized_height` give the same line as a height: history at or
below it is settled.

**Classification is by slot against the checkpoint block's slot, not by
epoch.** The checkpoint convention places the checkpoint at the last block
strictly *before* an epoch's first slot, so "in a finalised epoch" and "at or
below the finalised checkpoint" are different sets — and only the second is
what finality actually covers. Do not compute finality yourself from
`finalized_epoch` and a block's `epoch`. Read the field.

**This is the node's own view, and that is the point.** Finality here is
computed from the chain that node validated itself, so the answer does not
depend on trusting the block producer. It also means a node that is behind
reports its own staleness rather than someone else's confidence — which is why
`behind_by_slots` exists, and why **running your own node is the correct
deployment for a deposit gate.** Reading finality from someone else's RPC means
trusting their node's view, which reintroduces exactly the trust the boolean
was supposed to remove.

The deposit loop, concretely:

1. Poll `getblockcount` for `height` and `finalized_height`.
2. Scan slots with `getblockbyslot`, treating `-32007` as "advance" and
   bounding the walk with `height`.
3. Find your transaction in a block body.
4. Credit **only** when that block reports `finalized: true`. Re-read the block
   to check; do not infer it from a height comparison.
5. Before trusting any of it, check `behind_by_slots` from `getchaininfo`.

### 4.3 The honest caveat: finality is worth what the validator set is worth

The cryptography is sound and the guarantee is real. The guarantee is also
**exactly as decentralised as the set of validators standing behind it**, and
at launch that set is not decentralised at all.

Measured on this testnet:

- **52 validators**, all `active`, all with `commission_bps: "0"`, all
  activated at epoch 0, all with identically-shaped 3749-byte keys, stakes
  cycling in a mechanical 20/40/60-trillion pattern by index.
- Every one of them generated in a single session and operated by **one
  entity**.

So: the **stake-weighted** Nakamoto coefficient — how many validators must
collude to control one third of stake — is **12**, because the largest single
holding is 60 trillion satoshi out of 2.06 quadrillion, about 2.9%. But the
**operator** Nakamoto coefficient is **1**. Twelve keys and one key are the
same key when one party holds both.

State it without softening: **on this testnet, "finalised" means one operator's
52 keys agreed.** A ⅓-of-stake slashing cost is only a deterrent when the stake
belongs to parties who would each lose something. It is not a deterrent against
the party that holds all of it, who could revert a finalised checkpoint by
slashing itself.

This is a property of the launch configuration, not of the protocol. It
improves exactly as independent validators join with independent stake, and not
before. Until then, the correct posture for an exchange is that Genesis-4
finality is a *technically correct implementation of a guarantee whose
decentralisation assumption is not yet met.*

> **A note on the brief.** We were told to expect **64** keys. We measured
> **52**, consistently, across `getchaininfo.validators.total`,
> `getvalidatorcount.total`, the `-32001` message text ("52 registered"), and a
> complete index enumeration where 52 and 53 both returned `-32001`. Either the
> figure changed or the testnet was launched with a different set. The
> conclusion is unaffected — 52 keys under one entity is Nakamoto coefficient 1
> just as 64 would be — but the number in this document is the measured one.

### 4.4 Why this section exists: the Genesis-3 `confirmations` defect

Genesis-3 had a `confirmations` field, and it was wrong in the direction that
loses money.

It computed:

```rust
let tip = state.node_state.read().block_count;      // DAG block count
let confirmations = tip.saturating_sub(height) + 1;  // height = CHAIN height
```

`block_count` counted **DAG** blocks; `height` was a **selected-chain** height.
Subtracting one from the other is a category error, and because the DAG is
wider than the chain is long, the difference was a large positive constant.
Measured in one window:

| | |
|---|---|
| `block_count` | 50,557 |
| `tip_height` | 39,789 |
| Offset | **10,768** |

So a transaction in the tip block — **one real confirmation** — reported
`50,557 − 39,789 + 1 = 10,769` confirmations. And because `gettxstatus`
hardcoded `"final"` at `confirmations >= 100`, **every transaction on the chain
reported `final` the instant it was mined.** The offset grew as the DAG
widened, so it was never going to converge to correctness.

The failure mode is the one that matters: an exchange gating deposits on
`confirmations >= N` or `status == "final"` **credited every deposit at depth
1, while believing it had waited.** Fixed 2026-08-13.

Two things follow for Genesis-4:

1. **There is no `confirmations` field on this surface, and that is
   deliberate.** Not an omission to be filled in later. A number that looks
   like a security signal will be used as one, and under PoS no such number
   exists.
2. **Do not reconstruct one.** `height − block_height + 1` is computable from
   fields on this surface. It would be arithmetically correct and would still
   mean nothing, because depth is not the guarantee. `finalized` is.


> **CORRECTION — 2026-09-01, verified against `main` @ `737078d1`.**
>
> **The stall in this section was diagnosed, the same day, by the author.** See
> the CORRECTION above §3.10: a zero-input transfer submitted through the public
> RPC was admitted, and every proposer that selected it refused to build. Commit
> `72de2e93` (2026-08-13) names the slot-69 stop and fixes it from both ends —
> the proposer now drops the culprit and retries, and admission refuses the
> transaction. Reading this section as a standing liveness warning about the
> chain is wrong: it was a single-transaction denial of service, self-inflicted
> by §3.10, and it is closed.

### 4.5 What we actually measured about liveness

This is the part that should temper any timeline, and it is the reason §0 says
what it says.

**Finality never advanced past genesis during a 30-minute observation.**

| Time (UTC) | height | epoch | `justified_epoch` | `finalized_epoch` | `finalized_height` |
|---|---|---|---|---|---|
| 16:45:26 | 63 | 1 | 0 | 0 | 0 |
| 16:45:57 | 64 | 2 | 1 | 0 | 0 |
| 16:46:28 | 65 | 2 | 1 | 0 | 0 |
| 16:48:33 | 69 | 2 | 1 | 0 | 0 |
| 16:49:04 | 69 | 2 | 1 | 0 | 0 |
| 16:50:36 | 69 | 2 | 1 | 0 | 0 |
| … (unchanged every 30 s) | 69 | 2 | 1 | 0 | 0 |
| 16:56:46 | 69 | 2 | 1 | 0 | 0 |

Justification worked — `justified_epoch` advanced 0 → 1 at the epoch boundary,
and blocks in epoch 0 reclassified from `canonical` to `justified`, which is
the gadget doing its job. **Finalisation did not follow**, because Casper needs
two consecutive justified epochs and the chain stopped producing before
reaching one.

**Block production stopped at height 69 and did not resume.** The last block
arrived at 16:48:33. Every poll for the following eight minutes returned the
identical head. At 16:57:03 the node reported:

```
"slot":69, "height":69, "blocks_known":69,
"wall_slot":86, "behind_by_slots":17,
"mempool":1
```

Seventeen slots — eight and a half minutes — with no block, while the node
itself remained responsive and answered every RPC call promptly. Our submitted
transaction was still sitting in the mempool. This is a **hard stall, not a run
of missed proposals**: a missed proposal advances the slot and leaves the height
behind, whereas here the node's own `slot` froze with its height, and only
`wall_slot` kept moving.

Note what did *not* happen: nothing in the RPC surface reported an error. Every
call returned HTTP 200 with a well-formed result. **A client that polls only
`getblockcount` cannot tell this state from a healthy chain** — the response is
valid, it is simply the same response forever. `behind_by_slots` from
`getchaininfo` is the only field that distinguishes them, which is precisely
why it exists.

What this means for an integrator:

- **The only block reporting `finalized: true` for most of our window was
  genesis** (height 0). A deposit gate implemented exactly as §4.2 prescribes
  would have credited nothing, correctly.
- That is the gate **working**, not failing. It is also a fair warning that a
  correct gate against this testnet may sit and wait indefinitely, and your
  integration tests need a timeout and an alert rather than an assumption that
  finality arrives.
- **`behind_by_slots` is the health signal. Alert on it.** A stalled chain and
  a healthy one are indistinguishable from `getblockcount` alone. Poll
  `getchaininfo` and alert when `behind_by_slots` exceeds a small multiple of
  the slot time — a handful of slots is normal jitter, seventeen is not.

We did not diagnose the stall. It is outside this document's scope, and the
node's operational state — peers, proposer duties, why the schedule stopped —
is not visible through this RPC surface at all.

---

## 5. Two permanent refusals

`gettransaction` and `getnewaddress` are **routed, answered, and refused** at
the node, with dedicated error codes. They are not missing features and they
are not "not yet implemented". They were deliberately not left to fall through
to `method not found`, because "no such method" would send an integrator
looking for a newer build, and no newer build is coming for these two.

### 5.1 `gettransaction` → `-32005` `NO_TRANSACTION_INDEX`

**Node response, captured:**

```json
{"jsonrpc":"2.0","id":1,"error":{"code":-32005,"message":"this node cannot look up a transaction by id: at Genesis-4's current layer a transaction carries no id (the transfer format is not yet specified — `PosTransaction::Transfer` encodes only fee-market terms), and the block store keeps no txid index. Track deposits by scanning blocks via `getblockbyslot` and reading the eUTXO set via `getbalance` / `listunspent`, both of which are exact. This is a permanent answer for this build, not a transient failure — do not retry."}}
```

**The reasoning, which is structural rather than a missing index.** A
`PosTransaction` has **no transaction id at all** at this layer. Blocks commit
to a `body_root` computed over the canonical *bytes*, and the block store is an
append-only log with no secondary index. So there is nothing to hash into a
txid and nothing to look one up in.

The tempting fix is worse than the absence: synthesising a digest of the
canonical bytes would produce an identifier **no other node, block or client
agrees on.** An integrator would build deposit crediting on it, it would look
like it worked, and it would mean nothing. That is precisely the shape of the
`confirmations` defect in §4.4 — a number that appears authoritative and is
not. Saying the capability is absent is the only honest answer.

Note that `sendrawtransaction` returns `tx_hash`, which *is* such a digest —
and labels itself, in the response body, as a local handle that is not a
consensus id. Treat it accordingly.

**What to do instead.** Scan blocks with `getblockbyslot` and read the eUTXO
set with `getbalance` / `listunspent`. Both are exact reads of committed state.

### 5.2 `getnewaddress` → `-32006` `NO_WALLET`

**Node response, captured:**

```json
{"jsonrpc":"2.0","id":1,"error":{"code":-32006,"message":"this node holds no wallet and does not generate addresses. Two reasons, both permanent for this build: a node RPC must never mint key material (production keys are generated by a human on an air-gapped machine, per BLOCH-GENESIS-KEYS.md), and Genesis-4 has not frozen an address format yet — `withdrawal_credentials` is opaque bytes by declaration, so any address returned here could not be honoured later. Generate deposit addresses in your own wallet and watch them with `getbalance` / `listunspent`, which take a 32-byte script hash."}}
```

**Two independent grounds, either of which alone would be sufficient.**

*First: a node RPC must never mint key material.* Key generation belongs in a
wallet the operator controls. A node that mints a keypair on an unauthenticated
port and hands back an address has generated key material in an observable
session with no record of who asked. Rule zero of `BLOCH-GENESIS-KEYS.md` puts
production key generation on an air-gapped machine operated by a human, and
this port is the opposite of that in every respect. This ground does not expire
when the address format is decided.

*Second: Genesis-4 has no frozen address format.* `withdrawal_credentials` is
declared as opaque bytes precisely because the address format belongs to a
transaction layer that does not exist yet. There is no string this method could
return that a later build would still honour.

**What to do instead.** Generate deposit addresses in your own wallet and watch
them with `getbalance` / `listunspent`, which take a 32-byte script hash.

### 5.3 What you will actually see at the public endpoint

**Neither `-32005` nor `-32006`.** Both methods are outside the proxy's
allowlist, so the proxy refuses them by name before the node is ever consulted,
and you get `-32601`:

```json
{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method 'gettransaction' is not exposed by this proxy. Genesis-4 refuses gettransaction and getnewaddress at the node itself — there is no transaction id at this layer and the node holds no wallet."}}
```

The proxy's message summarises the reasoning, which is why the codes differ but
the conclusion does not. A client running against its own node sees `-32005` /
`-32006`; a client running against `posternlabs.com/g4rpc` sees `-32601`.
**Handle all four codes** — you will meet different ones in development and in
production depending on which path you take.

---


> **CORRECTION — 2026-09-01, verified against `main` @ `737078d1`.**
>
> **The node's table is missing the code an integrator will hit most.**
> `-32008 TX_REFUSED` (`rpc.rs:147`, emitted at `engine.rs:2094`; landed
> `6a7301ea`, 2026-08-22) means *the node judged the transaction invalid* —
> **never retry the same bytes**.
>
> `-32003 MEMPOOL_FULL` is still worded correctly, but it is no longer the only
> refusal, and the retry advice in the table below is wrong for the common case:
> a bad signature now yields `-32008`, not `-32003`. Before this split, every
> refusal returned `MEMPOOL_FULL` with "the transaction was not judged invalid"
> appended, which for an invalid transaction was simply false.
>
> Also missing from the HTTP list: **`400 Bad Request`** (`rpc.rs:1084`,
> `rpc.rs:1114`), which does carry a JSON-RPC envelope. And the claim that all
> HTTP-level errors carry one has an exception: the `503` path (`rpc.rs:1023`)
> writes the bare literal `{"error":"too many connections"}`.

## 6. Error codes, both paths

### From the node

| Code | Name | Cause | Retry? |
|---|---|---|---|
| `-32700` | parse error | Body was not JSON, or not UTF-8 | No — fix the client |
| `-32600` | invalid request | JSON but not a JSON-RPC 2.0 request object; wrong `jsonrpc` version; batch; non-POST | No |
| `-32601` | method not found | No such method in this build | No |
| `-32602` | invalid params | Method exists, arguments do not fit: bad hex, missing field, out of range | No — fix and resubmit |
| `-32603` | internal error | A bug in the node | Report it |
| `-32000` | `BLOCK_NOT_FOUND` | No block with that id is known | Only if you were syncing |
| `-32001` | `VALIDATOR_NOT_FOUND` | Index not in the committed registry | No |
| `-32002` | `TX_DECODE_FAILED` | Valid hex, not a canonical transaction | **No — never unchanged** |
| `-32003` | `MEMPOOL_FULL` | Admission refused for capacity; **not** a validity judgement | **Yes, later** |
| `-32004` | `NODE_UNAVAILABLE` | Consensus thread did not answer in 10 s, or shutting down | **Yes** |
| `-32005` | `NO_TRANSACTION_INDEX` | §5.1 — permanent | **Never** |
| `-32006` | `NO_WALLET` | §5.2 — permanent | **Never** |
| `-32007` | `SLOT_EMPTY` | Slot carries no canonical block. **Normal** — a missed proposal | Advance to the next slot |

Codes are stable; messages explain and may be reworded. Branch on codes, log
messages — with the one exception below.

### From the proxy

| Code | Cause | Retry? |
|---|---|---|
| `-32700` | Body is not JSON | No |
| `-32600` | Batch request, or `method` missing / not a string | No |
| `-32601` | Method outside the allowlist — **including `gettransaction` and `getnewaddress`** | No |
| `-32000` | **Upstream node unreachable** (network error, or 12-second timeout) | **Yes** |

**The one place you must read the message.** `-32000` means `BLOCK_NOT_FOUND`
from the node and *upstream unreachable* from the proxy — a permanent answer
and a retryable transport failure sharing a code. The proxy's message begins
`upstream Genesis-4 node unreachable`. Branch on that substring, or run your
own node and avoid the ambiguity entirely.

### HTTP-level, node only

`405` non-POST · `408` read timeout · `411` missing `Content-Length` or chunked
encoding · `413` body over 1 MiB · `431` headers over 16 KiB · `503` more than
64 concurrent connections. All carry a JSON-RPC-shaped body. The proxy returns
HTTP 200 for everything except its `204` OPTIONS preflight.

---


> **CORRECTION — 2026-09-01, verified against `main` @ `737078d1`.**
>
> **Item 6 below is no longer an open question, and its answer changed.** "From
> the source it is not observable, because admission does no validation" was
> true on 2026-08-13 and is false now: admission validates structurally and
> cryptographically and reports its verdict as `-32008` with a reason string.
> See the CORRECTION above §3.10.
>
> Items 10 and 13 (`getepochattestations` specified but not implemented;
> `getvalidator` by `pubkey_hash` sketched but index-only) were re-checked and
> are **still open** exactly as written.

## 7. What we could not verify

Stated explicitly, because the value of this document depends on the line
between what was measured and what was read.

**Blocked by the testnet's empty state:**

1. **A non-zero `getbalance` or a populated `getutxos`.** Genesis carries no
   balances, so `balance_sat` was `"0"` and `utxos` was `[]` in every call. The
   *shape* of a `EutxoEntry` (`{txid, vout, value_sat, script_hash}`) is from
   the source, not from a capture. We never saw a real one.
2. **`truncated: true` and the pagination cut.** Requires more than 1000 UTXOs
   on one script hash. The clamp of `limit` to 1–1000 is from the source; we
   confirmed `limit: 99999` does not error, but not what it clamped to.
3. **What `EutxoEntry.txid` actually contains**, and whether it is stable
   across a restart.

**Blocked by the absence of a valid transaction we could construct:**

4. **A block with `tx_count > 0`.** Our submitted transaction was still in the
   mempool when production stalled. We never observed a transaction being
   included, so we never traced one from `sendrawtransaction` through
   `getblockbyslot` to `finalized: true` — the exact end-to-end path a deposit
   integration depends on. **This is the most significant gap in this
   document.**
5. **`-32003` `MEMPOOL_FULL`.** Would need 4096 pending transactions.
6. **Whether a semantically invalid transaction is dropped at block
   application**, and whether that is observable at all. From the source it is
   not: admission does no validation, and there is no method that reports what
   happened to a submitted transaction.

**Blocked by finality never arriving:**

7. **A block transitioning `justified` → `finalized`.** We watched
   `canonical` → `justified` and the corresponding `finality` reclassification,
   but `finalized_epoch` stayed at 0 and `finalized_height` at 0 throughout. The
   only block we ever saw with `finalized: true` was genesis.
8. **How long finalisation takes in practice.** Two epochs is 64 slots ≈ 32
   minutes by design; we could not confirm it empirically.
9. **`not_canonical`.** Requires a fork. Never observed.

**Blocked by the method surface itself:**

10. **How many validators one `attestation_count` record represents.** We
    measured 2 records per block from slot 32 onward. Whether each is an
    aggregate over many validators is described in the spec but there is **no
    method on this surface that exposes attestation contents** —
    `getepochattestations` is specified and not implemented. So participation
    rate is not measurable through this endpoint, which means **you cannot
    independently verify that finality is backed by the stake it claims.**
11. **`-32004` `NODE_UNAVAILABLE`** and **`-32603` internal error.** Neither
    was triggered. Notably, `-32004` did **not** appear during the eight-minute
    production stall — the consensus thread kept answering RPC promptly while
    producing nothing, so this code does not signal the failure you might
    expect it to.
12. **The node's `503` concurrency cap** (64 connections). Not exercised —
    hammering a shared testnet to reproduce it is not a reasonable measurement.
    The other HTTP bounds (`405`, `411`, `413`, `431`) and the parser bounds
    *were* measured; see §1.3.
13. **`getvalidator` by `pubkey_hash`.** The V4 spec sketches it; the
    implementation takes an index only. We confirmed the refusal, not a future
    intention.

**Read, not measured:**

14. Everything about **mainnet** Genesis-4. It does not exist. Every number in
    this document — 52 validators, 2.06 quadrillion satoshi of stake, 30-second
    slots, 32-slot epochs — is this testnet's, and the first three will not
    carry over.
15. The Genesis-3 `confirmations` measurement in §4.4 (offset 10,768) is quoted
    from `BLOCH-EXCHANGE-INTEGRATION.md` §5.1, which measured it against the
    Genesis-3 node. We did not re-measure it; Genesis-3 is a different chain
    and is outside this document's scope.

---

## 8. Reproducing these measurements

Every capture in this document came from a plain `curl`. The template:

```sh
curl -sS -X POST https://posternlabs.com/g4rpc \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getchaininfo","params":[]}'
```

A liveness check that is actually a liveness check (see §1.3 on the GET trap):

```sh
curl -sS -X POST https://posternlabs.com/g4rpc \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]}'
```

To see the node's own error codes rather than the proxy's, a node you run
yourself is the supported path — and is what you should be running for a
deposit gate anyway (§4.2).

Chain constants used above, from `crates/bloch-pos-committee/src/params.rs`:
`SLOT_DURATION_SECS = 30`, `SLOTS_PER_EPOCH = 32` (16 minutes per epoch).
Block `timestamp` is exactly `genesis_time + slot × 30`, derived for display
and not a consensus field.
