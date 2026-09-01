<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Bloch Genesis-4 — JSON-RPC Method Surface and Stability Contract

```
Document:   BLOCH-RPC-STABILITY-V4
Status:     NORMATIVE for the shipped surface. Section 5 is a PROPOSAL.
Created:    2026-08-31
Scope:      crates/bloch-pos-node/src/rpc.rs and its engine handlers
Parents:    docs/specs/BLOCH-RPC-V4.md (design rationale, R0–R5)
            docs/WIRE-NAMESPACE-REGISTRY.md §5 (name allocation, PMO-owned)
            docs/integration/BLOCH-GENESIS4-EXCHANGE-INTEGRATION.md (how-to)
Not public: internal + direct delivery to integrators. Do not publish to the
            site and do not publish as a shared Artifact.
```

`BLOCH-RPC-V4.md` says what the surface should be. This document says what it
**is**, enumerated by reading the dispatcher rather than by probing it, and what
an integrator may rely on across a release. Everything in §1–§4 is asserted by
tests named inline; §5 is a design that is not built.

---

## 0. Read this first: you are probably not talking to a node

The surface an integrator sees is the **intersection** of two allowlists, and
only one of them is in this repository.

```
client ──▶ https://posternlabs.com/g4rpc ──▶ 6+ upstream nodes
           Cloudflare Pages Function            crates/bloch-pos-node
           READ_METHODS + WRITE_METHODS         route() — 15 names
           12 names                              (this document)
           (posternlabs-deploy/functions/g4rpc.js:109)
```

Probed against the public endpoint on 2026-08-31, `getsupply`, `getvalidators`,
`getstakinginfo`, `getpeers`, `help`, `getblockbyheight`, `getissuance` and
`getsupplyinfo` all return `-32601`. So do `gettransaction` and `getnewaddress`
— **but those two exist on the node**, with their own permanent codes and an
explanation. The proxy's blanket `-32601` hides that distinction, and its
message is the same sentence for every unknown name:

```
method 'zzz' is not exposed by this proxy. Genesis-4 refuses gettransaction and
getnewaddress at the node itself — there is no transaction id at this layer and
the node holds no wallet.
```

Three consequences an integrator must know:

1. **`-32601` from the public endpoint does not mean the node lacks the
   method.** It means the edge did not forward it. `gettransaction` is the
   proof: the node answers `-32005` with a paragraph of reasoning, and nobody
   integrating through the proxy has ever seen it.
2. **Any method added to the node is invisible until `READ_METHODS` is
   updated.** That includes `getcapabilities` (§3). This is a required
   follow-up, in a different repository, listed in §6.
3. `getbalance`, `getutxos`, `listunspent`, `gettxout`, `getvalidator` and
   `getmempoolinfo` are **never cached** at the edge; `getchaininfo` (3 s),
   `getblockcount` (3 s), `getvalidatorcount` (5 s), `getblockbyslot` (10 s) and
   `getblockbyid` (300 s) are. The branch-sensitive reads are additionally
   quorum-checked across upstreams, so one client call can be several node
   calls.

An exchange that wants the real contract should run its own node and read it on
loopback. That is also the only configuration in which `finalized: true` is a
statement you have verified rather than one you have been told (§2.3).

---

## 1. The method surface, as dispatched

Read out of `crates/bloch-pos-node/src/rpc.rs:1079` (`route`). **Fifteen
names**, eleven request variants, two permanent typed refusals, one alias pair.

Amounts marked `sat` are **decimal strings**, never JSON numbers (R3: the cap is
10^19 sat, ~1110× JavaScript's exact-integer limit). Hashes are 64 lowercase hex
characters, unprefixed on output; input accepts an optional `0x`. Parameters may
be positional (array) or named (object). Batch requests are refused.

### 1.1 Chain and finality

| Method | Params | Result | Errors beyond `-32602` |
|---|---|---|---|
| `getchaininfo` | — | `block_id`, `slot`, `height`, `finalized_height`, `epoch`, `slot_in_epoch`, `slots_per_epoch`, `state_root`, `justified{epoch,root}`, `finalized{epoch,root}`, `previous_justified{epoch,root}`, `validators{total,active}`, `total_active_stake_sat`, `base_fee_millisat_per_gas`, `next_base_fee_millisat_per_gas`, `mempool`, `blocks_known`, `wall_slot`, `behind_by_slots` | `-32004` |
| `getblockcount` | — | `height`, `slot`, `epoch`, `finalized_height`, `justified_epoch`, `finalized_epoch` | `-32004` |

`finalized_height` is `null` before the first finalisation. `behind_by_slots` is
`wall_slot − slot`: under PoS there is no difficulty and no depth from which to
infer whether a node is current, so the node states it.

### 1.2 Blocks

| Method | Params | Result | Errors beyond `-32602` |
|---|---|---|---|
| `getblockbyslot` | `slot` u64 | block object | `-32007 SLOT_EMPTY`, `-32000` |
| `getblockbyid` | `block_id` hex32 | block object | `-32000 BLOCK_NOT_FOUND` |

Block object: `block_id`, `version`, `parent`, `slot`, `epoch`, `height`,
`proposer_index`, `timestamp`, `state_root`, `body_root`, `randao_reveal`,
`randao_mix`, `justified_root`, `finalized_root`, `attestation_root`,
`coherence_root`, `finality`, `finalized`, `tx_count`, `attestation_count`.

- **There is no `transactions` array.** `tx_count` is a count. The body is
  committed by `body_root`; the transactions themselves are not projected here.
- **There is no `getblockbyheight`.** Slots are the addressing unit. Height
  exists as a field and is `null` for a non-canonical block.
- `version` is the header field verbatim — `0xB10C0005`, which renders as
  `2970353669`. It is not "4", and it must not be prettified: a client
  recomputing `block_id` hashes these 304 header bytes including this one.
- `finality` ∈ `finalized | justified | canonical | not_canonical`;
  `finalized` is the boolean form of the first. `timestamp` is derived from the
  slot for display — `BlockHeaderV4` carries no time.
- `SLOT_EMPTY` is **normal**: a slot with no block is a missed proposal. A
  scanner must advance, not alert.

### 1.3 Ledger reads

| Method | Params | Result | Errors beyond `-32602` |
|---|---|---|---|
| `getbalance` | `script_hash` hex32 | `script_hash`, `balance_sat`, `utxo_count` | — |
| `getutxos` | `script_hash` hex32, `limit`? (1–1000, default 100) | `script_hash`, `total`, `returned`, `truncated`, `utxos[]` | — |
| `listunspent` | *alias of `getutxos`* | *identical* | — |
| `gettxout` | `txid` hex32, `vout`? u32 (default 0) | `txid`, `vout`, `unspent`, `utxo`\|`null`, `at_slot` | — |

UTXO entry: `txid`, `vout`, `value_sat`, `script_hash`.

- **Lookups are by 32-byte script hash, not by address.** Derivation from a
  `bloch1q…` address: take the 20 bytes after the prefix and right-pad with
  zeros to 32.
- `limit` is **clamped**, not validated: `99999999` yields 1000, silently. That
  is deliberate — an unbounded page size is a memory amplifier on an
  unauthenticated port — but it means a client must read `returned` and
  `truncated` rather than assume it got what it asked for.
- `getutxos` has **no cursor**. `total` reports the true count; `truncated`
  says the page was cut. For a script hash with 425,568 outputs, 424,568 of
  them are unreachable through this method. `gettxout` exists because of that
  gap: it is the only way to ask about one specific outpoint.
- `unspent: false` covers both "spent" and "never existed". It is a statement
  about committed state, not about this node's knowledge — the third case
  cannot arise here.

### 1.4 Validators

| Method | Params | Result | Errors beyond `-32602` |
|---|---|---|---|
| `getvalidator` | `index` u32 | validator object | `-32001 VALIDATOR_NOT_FOUND` |
| `getvalidatorcount` | — | `total`, `active`, `total_active_stake_sat` | — |

Validator object: `index`, `pubkey_hash`, `pubkey_bytes`, `state`,
`own_stake_sat`, `effective_stake_sat`, `commission_bps`, `randao_commitment`,
`slashed`, `activation_epoch`, `exit_epoch`, `withdrawable_epoch`.

- `state` ∈ `slashed | exited | exiting | queued | active`, evaluated in that
  order — a slashed validator whose exit epoch has not arrived is `slashed`,
  never `exiting`.
- `effective_stake_sat` is `null` when the active set does not carry the
  validator. That is a different fact from zero and is not defaulted.
- `commission_bps` is the **committed** value, reported verbatim even when it
  exceeds the consensus cap, so a rate set above the cap is visible rather than
  laundered into it (R5).
- Lifecycle epochs are `null` where the record holds `u64::MAX` ("never").
- **There is no bulk listing.** See §5.2.

### 1.5 Submission

| Method | Params | Result | Errors |
|---|---|---|---|
| `sendrawtransaction` | `hex` string of the canonical bytes | `accepted`, `status`, `kind`, `bytes`, `tx_hash`, `tx_hash_note`, `confirmation` | `-32602` bad hex · `-32002 TX_DECODE_FAILED` · `-32003 MEMPOOL_FULL` · `-32008 TX_REFUSED` · `-32004` |
| `getmempoolinfo` | — | `size`, `max`, `bytes`, `next_base_fee_millisat_per_gas` | — |

- `status` ∈ `accepted | duplicate`. A byte-identical resubmission is a
  **success**, reported distinctly so a retry loop can stop.
- `tx_hash` is SHA3-256 over the canonical bytes and is a **local correlation
  handle only**. No block commits to it; no other node agrees it names
  anything. `tx_hash_note` says so in the payload. Do not credit deposits on it.
- The three failure codes are three different instructions: `-32003` means
  retry later, `-32002` and `-32008` mean never retry these bytes.

### 1.6 The two permanent refusals

| Method | Always answers | Why |
|---|---|---|
| `gettransaction` | `-32005 NO_TRANSACTION_INDEX` | A Genesis-4 transaction has **no id at this layer**. `PosTransaction::Transfer` encodes `inputs`, `tx_bytes` and a tip — fee-market terms with no sender, recipient or amount. Blocks commit to `body_root` over canonical bytes; the store is an append-only block log with no secondary index. There is nothing to hash into a txid and nothing to look one up in. A synthesised digest would be an identifier no other node, block or client agrees on, and an integrator would build deposit crediting on it. |
| `getnewaddress` | `-32006 NO_WALLET` | Two independent grounds. A node RPC must never mint key material — production keys are generated by a human on an air-gapped machine (`BLOCH-GENESIS-KEYS.md`), and this port is unauthenticated. And Genesis-4 has frozen no address format: `withdrawal_credentials` is opaque bytes by declaration, so any address returned here could not be honoured later. |

These are routed methods, not gaps. They answer at the dispatcher and never
reach the node. `-32601` would have sent an integrator hunting for a newer
binary that does not exist.

**Reconciliation without transaction ids** is the intended path and it is exact:
scan slots with `getblockbyslot`, and read the ledger with
`getbalance` / `listunspent` / `gettxout` against a script hash.

### 1.7 Error codes

| Code | Name | Client action |
|---|---|---|
| `-32700` | parse error | Body was not JSON. Fix the client. |
| `-32600` | invalid request | Not a JSON-RPC 2.0 request object. Batches land here. |
| `-32601` | method not found | No such method **on this hop** (see §0). |
| `-32602` | invalid params | Method exists, arguments do not fit. |
| `-32603` | internal error | A bug. Report it. |
| `-32000` | `BLOCK_NOT_FOUND` | Retry after syncing, or it never existed. |
| `-32001` | `VALIDATOR_NOT_FOUND` | Index is not in the committed registry. |
| `-32002` | `TX_DECODE_FAILED` | Not a canonical transaction. Never retry unchanged. |
| `-32003` | `MEMPOOL_FULL` | Capacity, not validity. Retry later. |
| `-32004` | `NODE_UNAVAILABLE` | Consensus thread did not answer in 10 s. Retry. |
| `-32005` | `NO_TRANSACTION_INDEX` | Permanent. Do not retry. |
| `-32006` | `NO_WALLET` | Permanent. Do not retry. |
| `-32007` | `SLOT_EMPTY` | Normal. Advance to the next slot. |
| `-32008` | `TX_REFUSED` | Judged invalid. Never retry these bytes. |

Failures are always the top-level JSON-RPC `error` object under HTTP 200 — never
a `result.error` string (R4). The V3 convention forced a `ResultError` shim into
both generated SDKs and the explorer; it is not carried forward.

### 1.8 Transport and limits

`HTTP/1.1`, `POST` only, `Content-Length` required. No chunked transfer
encoding, no keep-alive, no TLS at the node, no compression, no batching. The
bounds are anti-exhaustion, **not authorisation**:

| Limit | Value |
|---|---|
| `max_body_bytes` | 1,048,576 |
| `max_header_bytes` | 16,384 |
| `max_connections` | 64 (beyond this: HTTP 503) |
| `max_json_depth` | 64 |
| socket read/write timeout | 30 s |
| engine answer timeout | 10 s → `-32004` |
| `getutxos` page | 100 default, 1000 max |

**There is no authentication, no authorisation and no rate limiting.**
`--rpc-bind` defaults to `127.0.0.1`; any routable bind must be firewalled to
the clients meant to reach it, because `sendrawtransaction` is a write.

The RPC listener does not open until boot replay finishes. During replay the
port refuses connections rather than timing out.

---

## 2. The stability contract

### 2.1 Classes

Every name carries one, in `RPC_SURFACE` (`rpc.rs:765`) and in the
`getcapabilities` response.

**`committed`** — for the life of the major surface version:

1. The name keeps its meaning.
2. Parameters keep their positions, names and types. New parameters may be
   added only as **optional trailing** ones whose default reproduces today's
   behaviour.
3. Every field listed in §1 keeps its name, JSON type and meaning.
4. Fields may be **added** at any time. **A client MUST ignore unknown
   fields.** A client that fails on one is not covered by this contract.
5. R3, R4 and the hex conventions hold everywhere: amounts are decimal strings,
   errors are top-level `error` objects, hashes are 64 lowercase hex chars.
6. Removing a field or changing its meaning requires a major bump **and** one
   minor release in which both shapes are served and the old one is marked
   `deprecated` in `getcapabilities`.

Committed: `getbalance`, `getblockbyid`, `getblockbyslot`, `getblockcount`,
`getcapabilities`, `getchaininfo`, `getmempoolinfo`, `gettxout`, `getvalidator`,
`getvalidatorcount`, `sendrawtransaction`.

**`provisional`** — the name and its meaning hold; the response shape is not
finished and **will** change inside this major version. Read the fields you
need; do not assume the set is closed.

Provisional: `getutxos`, `listunspent`. The reason is specific and known: there
is no cursor, and one will be added. `truncated` is a placeholder for a
pagination protocol the OpenAPI V4 freeze has not decided. Anything a client
builds on "the first page is the whole answer" will break — and already gives
wrong answers for any script hash past 1000 outputs.

**`refused`** — the method is routed and answers, permanently, with a typed
error. The code is committed; the message is prose.

Refused: `gettransaction` (`-32005`), `getnewaddress` (`-32006`).

### 2.2 Versioning

`getcapabilities.rpc_surface_version` — currently **`4.1.0`**.

| Bump | Means |
|---|---|
| **major** | A committed method changed meaning, lost a field, or was removed. Read the changelog before upgrading. |
| **minor** | A method or a response field was **added**, or a provisional response changed shape. Nothing you already read has moved. |
| **patch** | An error message was reworded, or documentation changed. |

The node binary's own version is reported separately as `node_version`, and
`genesis_block_id` identifies the chain without depending on a name anyone
could reuse.

Deprecation window: **one minor release, minimum 30 days**, announced through
`getcapabilities`, before any major removal.

### 2.3 What no class covers

State these to an integrator explicitly; each has already caused a support
question on this chain.

- **Error message text.** The *code* is the contract. Never parse the message.
- **Node-local fields.** `mempool`, `blocks_known`, `wall_slot`,
  `behind_by_slots`, everything in `getmempoolinfo`, and a block's `height`,
  `finality` and `finalized` are **this node's view of its own validated
  chain**. Two honest nodes may disagree, and on 2026-08-23 six upstreams
  demonstrably did — three agreeing, three each alone. `finalized: true` from a
  node you run and have synced is the guarantee; the same field from someone
  else's node is a claim about their chain.
- **JSON key order.** Stable in practice, not contractual.
- **Block retention.** `getblockbyid` may answer `-32000` for a block a pruned
  node no longer stores. Absence is not evidence.
- **The public proxy's allowlist** (§0). It is a separate repository with a
  separate release cycle and it is not versioned by `rpc_surface_version`.
- **Depth.** There is no confirmation count and none is coming. Settlement is
  `finalized: true` — a finalised checkpoint cannot revert unless at least one
  third of the total stake is slashed, an attributable on-chain cost. Waiting N
  further blocks past finalisation buys nothing, and nothing else substitutes.

### 2.4 Asking instead of probing

`getcapabilities` (`rpc.rs:1422`) returns, from constants:

`rpc_surface_version`, `node_version`, `block_version`, `genesis_block_id`,
`methods[]` (name, stability, `alias_of`, summary), `absent[]` (name, reason),
`error_codes[]` (code, name), `encoding{}`, `transport{}`, `limits{}`,
`authentication{}`, `settlement{}`.

`absent[]` is the point: every name in it was discovered by an integrator
sending the call and reading `-32601`, which cannot distinguish "never existed
here" from "your node is old". Each now comes back with a reason.

Its cost is constant — it walks no state — which is deliberate: the method every
client calls first, on a port with no rate limit, must not be a lever.

---

## 3. The frozen namespace

`docs/WIRE-NAMESPACE-REGISTRY.md` §7 gap 2 records that the RPC name allocation
was frozen by nothing. It is now frozen by
`crates/bloch-pos-node/src/rpc/tests.rs`.

### 3.1 Why the compiler does not help

Dispatch is `match method { "getchaininfo" => …, … }` on a `&str`
(`rpc.rs:1080`). A string `match` has no exhaustiveness to verify. A duplicate
literal is at most an `unreachable_patterns` **warning**, and only once both
arms are in the same `match` in the same file — two worktrees each holding one
arm produce no diagnostic until they merge, and the merge may resolve to a file
where one arm was dropped.

This is a weaker failure than the frame-byte class (`if frame.first() ==
Some(&FRAME_GET_BLOCKS)` — no diagnostic at all, ever) and stronger than the
state-root-tag class (silent and consensus-fatal). It is still not something to
rely on.

### 3.2 What the freeze asserts

`the_rpc_method_namespace_is_frozen` (`tests.rs:579`) reads the dispatcher's own
source via `include_str!("../rpc.rs")`, extracts every arm literal, and checks:

- `RPC_SURFACE` equals a **golden list written out in the test** — not derived
  from the table, so an edit to the table is a diff a reviewer must approve;
- `RPC_SURFACE` is sorted and duplicate-free;
- the extracted arms equal that same golden list — **both directions**: a
  method wired into `route` but absent from the table fails, and a name in the
  table that nothing dispatches fails;
- no name is dispatched twice;
- the wildcard arm is `RpcError::method_not_found(other)`, so an unknown name
  cannot fall through to something else.

`only_the_frozen_names_route` (`tests.rs:663`) asserts the negative half: every
name in `RPC_ABSENT`, every Genesis-3 name that must not silently return with a
PoW meaning (`getblockhash`, `getdaginfo`, `gethashrate`,
`getsupplydistribution`, `gettxstatus`, `validateaddress`, …), and six near
misses (`GetBalance`, `getbalance `, ` getbalance`, `getBalance`,
`get_balance`, `""`) all answer exactly `-32601`. It also asserts the two
refused methods answer their own codes and never reach the backend, and that no
name appears in both `RPC_SURFACE` and `RPC_ABSENT`.

`getcapabilities_describes_the_surface_without_reading_state` (`tests.rs:741`)
pins the capability response against the table, so the document a client reads
cannot drift from the dispatcher.

**Verified by mutation.** Adding `"getmempoolstats" => RpcRequest::MempoolInfo`
to `route` — the exact shape of an unregistered parallel-work addition — turns
the test red and names the offending method in the failure message. Reverted.

### 3.3 Registration for the PMO registry §5

The registry's current §5 list has a defect: it names 13 methods and omits
`getutxos`, then says "13 names, 12 handlers" in the prose below. The
dispatcher had **14** names before this work. Replacement text:

> Served today (mainline, **15 methods**, frozen by
> `crates/bloch-pos-node/src/rpc/tests.rs:579`
> `the_rpc_method_namespace_is_frozen` and `:663`
> `only_the_frozen_names_route`):
>
> `getbalance`, `getblockbyid`, `getblockbyslot`, `getblockcount`,
> `getcapabilities`, `getchaininfo`, `getmempoolinfo`, `getnewaddress`,
> `gettransaction`, `gettxout`, `getutxos`, `getvalidator`,
> `getvalidatorcount`, `listunspent`, `sendrawtransaction`.
>
> Dispatch table is `crates/bloch-pos-node/src/rpc.rs:1080-1148` — 15 names,
> 11 request variants, 2 typed-error stubs; `getutxos` and `listunspent` alias
> one handler. The authoritative in-code allocation is
> `rpc::RPC_SURFACE` (`rpc.rs:765`), which carries a stability class per name;
> `rpc::RPC_ABSENT` (`:866`) carries the names deliberately not served, and the
> freeze test asserts the two lists are disjoint and that everything in
> `RPC_ABSENT` really answers `-32601`.

| Method | Status | Owner | Frozen by |
|---|---|---|---|
| `getcapabilities` | **CLAIM REQUESTED, 2026-08-31** — surface self-description; `rpc.rs:1081` dispatch, `capabilities_json` `:1422`, engine arm `engine.rs:1976`. Constant cost, reads no state. | rpc-stability | `rpc/tests.rs:741` |

The claim is filed rather than assumed. The name was swept against mainline,
`legacy/genesis3-node`, all 59 local worktrees, the wallet client, the anchoring
crate and both explorer/site proxies: **zero occurrences**. If the PMO assigns a
different name, it changes in exactly three places — the `route` arm, the
`RPC_SURFACE` entry, and the golden list in the freeze test — and the test fails
until all three agree.

`getconsensusschedule` (claimed by the PMO in
`agent-aeb2ec6de2cd89cbb`) is **not** in this build. When it merges it must be
added to `RPC_SURFACE` with a stability class and to the golden list, or the
freeze test fails — which is the intended behaviour, not an obstruction.

---

## 4. Cost of the shipped reads, and three existing amplifiers

Every read is serviced **on the consensus thread**, on a port with no
authentication and no rate limit. The price of a method is therefore the size of
the lever an anonymous caller has on block production, not a performance
footnote. `what_a_read_costs_at_carryover_scale` (`tests.rs:845`, `#[ignore]`d)
measures the ones that scan.

Measured on a release build against a state of **452,726 eUTXO entries** — the
live Genesis-4 carryover, to the entry:

| Method | Cost | Measured | Notes |
|---|---|---|---|
| `gettxout` | O(log U) | **28 µs** | One map lookup. |
| `getcapabilities` | O(1) | **100 µs** | Constants only; the time is building the JSON tree, and it does not move with the chain. |
| `getblockcount`, `getvalidatorcount`, `getmempoolinfo` | O(1)–O(mempool) | — | |
| `getblockbyid`, `getblockbyslot` | O(1) / O(chain) | — | `getblockbyslot` scans the canonical vector linearly. |
| `getvalidator` | O(V + D) | — | Goes through `active_validators()` → `consensus_roster_at` → delegation resolve + cohort cap + leak. |
| `getchaininfo` | **2 × O(V + D)** | — | See F1. |
| `getutxos` / `listunspent` | O(U) + O(matches) allocated | **10.7 ms** (limit 100) · **30.8 ms** (limit 1000) | See F3. |
| `getbalance` | **2 × O(U)** | **18.2 ms** | See F2. U grows; this number only goes up. |

**What 18 ms means on this port.** RPC is serialised through the engine channel
onto the consensus thread, so ~55 `getbalance` calls per second consume 100% of
a validator's consensus thread. `MAX_CONNECTIONS` is 64, there is no
authentication and no rate limit, and the public edge neither caches
`getbalance` nor answers it from one node — it quorum-checks it across
upstreams, so one client call is several nodes each paying the 18 ms twice. A
single anonymous client can price a validator out of proposing. `gettxout`
answers a narrower question 650× cheaper; where a client can use it, it should.

Three pre-existing amplifiers, each a small local fix, none of them consensus.
**Reported, not changed** — they touch the code path the live fleet runs, and
that is the founder's call, not this document's.

- **F1 — `getchaininfo` computes the validator roster twice per call.**
  `chain_info_json` calls `state.active_validators()` (→ `consensus_roster_at`)
  and `state.total_active_stake_sat()` (→ `duty_roster`), and each recomputes
  the delegation resolve, the cohort cap and the leak from scratch. This is the
  most-polled method on the chain. Fix: compute the roster once and pass both
  derived values, or memoise per `(epoch, head)`.
- **F2 — `getbalance` scans the entire eUTXO set twice.** `balance_json` calls
  `state.balance_sat()` to sum and then iterates `state.eutxos()` again to
  count. One pass yields both, and would halve the measured 18.2 ms. The edge
  never caches this method and quorum-checks it across upstreams, so one client
  call is several nodes doing it twice each.
- **F3 — `getutxos` collects every match before truncating.** `utxos_json`
  builds a `Vec` of **all** matching entries to learn `total`, then takes
  `limit`. For a script hash with 425,568 outputs that is ~3.4 MB of references
  allocated to return 100 of them. `total` needs a count, not a collection —
  which is also why `limit=1000` measures 3× `limit=100` when both do the same
  single scan.

---

## 5. Proposal: the missing read methods

The gap that matters beyond documentation: **there is no RPC way to read the
validator set or the issued supply**, which blocks a supply audit and blocks any
third party verifying stake distribution independently. Three methods close it.
None is implemented. Each is costed against §4's constraint — nothing here may
give an unauthenticated caller a new lever.

### 5.1 `getsupply` — issued against the cap

**Cost: O(1).** The counter already exists in committed state: `issued_sat`
(`transition.rs:1160`), committed under `TAG_ISSUED_SUPPLY = 0x14`, seeded at
genesis with `tokenomics_v4::GENESIS_ISSUED_SAT` and advanced at epoch
boundaries by the satoshis `close_epoch` actually credits. It is a field read.

Requires one line in `bloch-pos-committee`: `pub fn issued_sat(&self) -> u128`.
The field is private, which is correct; a read-only accessor changes no
transition behaviour and is the same shape as the `validator_count` /
`balance_sat` accessors added for the RPC in August.

```json
{
  "issued_sat": "…",            // decimal string, R3
  "cap_sat": "…",               // tokenomics_v4::TOTAL_SUPPLY_SAT, 100e9 BLCH
  "remaining_sat": "…",         // cap − issued; the invariant is one-sided
  "genesis_issued_sat": "…",    // what existed at slot 0
  "emitted_since_genesis_sat": "…",
  "at_slot": 0, "at_epoch": 0,
  "finalized": false            // is this state at or below the finalized checkpoint
}
```

**Honesty requirements, in the response and not only in prose.** `issued_sat`
is **gross and monotone**: fees move existing coins, whistleblower rewards come
out of slashed bonds, and burns never decrement it — they widen the gap below
the cap. It is therefore *not* circulating supply and must not be labelled as
such. A `note` field should say so, for the same reason `tx_hash_note` exists.

**Circulating supply is deliberately not offered here.** It would require
`total_unspent_sat()` — a full scan of the eUTXO set, on the consensus thread,
uncached and unauthenticated. If it is genuinely needed, serve it memoised per
**finalised** epoch (one scan per ~16 minutes, amortised across all callers,
and finality is the only boundary at which the answer is stable anyway) and
report the epoch it was computed at. Never compute it per request.

### 5.2 `getvalidators` — the registry, paginated

**Cost: O(page) records + one roster computation, O(V + D).** V is 64 today and
bounded by consensus; D (delegations) is 0 today and is not.

```
getvalidators(start?: u32 = 0, limit?: usize = 50, max 500)
→ { total, start, returned, next_start | null, epoch, validators: [ validator object ] }
```

Reuses `validator_json` verbatim, so there is one definition of what a validator
looks like and a client that already parses `getvalidator` needs no new code.

Four anti-DoS requirements, all mandatory:

1. **Page cap**, same shape as the UTXO page: clamp rather than reject, and
   report `returned` and `next_start` so the client can tell.
2. **Compute the roster once per call**, not once per record. The naive
   implementation calls `active_validators()` inside the loop to find each
   `effective_stake_sat`, which is O(V²·D).
3. **Memoise the roster per `(epoch, head)`.** It changes only at epoch
   boundaries and is already recomputed twice per `getchaininfo` (F1). One memo
   fixes F1, this method and §5.3 together, and is the single highest-value
   change in this document.
4. **Watch `pubkey_hash`.** It is SHA3-256 over a hybrid ML-DSA-65 ‖ Falcon-1024
   public key — roughly 3.7 KB per record. At a 500-record page that is ~1.8 MB
   of hashing per call. Negligible at V=64; if the registry opens to external
   validators, cache the hash on the record rather than raising the page cap.

Requires a paginated accessor over the private `validators: BTreeMap<u32,
ValidatorRecord>` — `pub fn validator_records(&self, start: u32, limit: usize)`
— which is a `range()` over a `BTreeMap` and therefore genuinely O(page), not
O(V) with a skip.

### 5.3 `getstakedistribution` — what a third party needs to check us

**Cost: one roster computation, O(V + D), plus O(V log V) for a sort. Response
is fixed-size regardless of V.** Memoise per epoch and it is free after the
first caller in each epoch.

This is the method that makes the concentration claim verifiable by someone who
does not trust us, which is the entire point of publishing it.

```json
{
  "epoch": 1636,
  "active": 64,
  "total_active_stake_sat": "…",
  "nakamoto_coefficient": { "one_third": 4, "one_half": 7 },
  "top": [ { "index": 0, "effective_stake_sat": "…", "share_bps": 1563 } ],
  "quantiles": { "p50_sat": "…", "p90_sat": "…", "p99_sat": "…" },
  "gini_bps": 0,
  "measures": "stake_by_validator_index"
}
```

- `nakamoto_coefficient.one_third` is **the** number, because that is the
  threshold at which finality can be reverted — not one half. Reporting only
  the half would understate the risk by the factor that matters.
- `top` is capped (20 entries) so the response size does not track V.
- `measures: "stake_by_validator_index"` is a disclaimer with a field name.
  This measures **stake per index, not per operator**. Sixty-four indices can be
  one operator, and on this chain today they largely are. The RPC cannot know
  who runs what, and this method must not imply that it does.

### 5.4 Deliberately not proposed

- **`getpeers`.** Peer identity on an unauthenticated port is a targeting aid
  for exactly the eclipse and backfill-flood failures this fleet has already
  suffered. It is an operator question, answered by an operator channel.
- **A txid index.** The obstacle is structural, not scheduling: there is no
  transaction identity at this layer to index. Creating one is a consensus-level
  decision about what a transaction *is*, not an RPC feature.
- **`getblockbyheight`.** Slots are the addressing unit and height is already a
  field. A second addressing scheme is a second thing to keep consistent across
  reorgs.
- **A `transactions` array on the block object.** It would need a transaction
  projection format, which is the same unfinished decision as the txid.

### 5.5 Sequencing

`getsupply` first: it is O(1), it needs one accessor, and it unblocks the supply
audit on its own. Then the roster memo (F1 + §5.2 + §5.3 share it). Then
`getvalidators` and `getstakedistribution` on top of the memo.

Every one of them is a new name in a shared namespace. **Claim from the PMO
before writing the constant** (`docs/WIRE-NAMESPACE-REGISTRY.md` §0), then add
the entry to `RPC_SURFACE` and to the golden list in the freeze test in the same
commit. The names used above are proposals, not allocations.

---

## 6. Required follow-ups

1. **`getcapabilities` must be added to the public proxy allowlist** —
   `posternlabs-deploy/functions/g4rpc.js`, `READ_METHODS` at line 109 — or it
   is unreachable through the only public endpoint. Never cached. It is a
   different repository and is not touched by this work.
2. **The proxy's `-32601` message should distinguish "not forwarded here" from
   "not served by the node"**, and should not recite `gettransaction` and
   `getnewaddress` for every unknown name. Better: forward those two so an
   integrator sees `-32005` / `-32006` and their reasoning.
3. **The explorer proxy allowlist is still the Genesis-3 surface** —
   `apps/explorer/functions/rpc.js` lists `getblockbyheight`, `gethashrate`,
   `getdifficultyhistory`, `getsupplydistribution` and other PoW-era names that
   no Genesis-4 node serves. Its own comment says it must be rebuilt for V4.
   Also recorded in the PMO registry §5.
4. **`docs/openapi.yaml` is the V3 contract** and does not describe any of §1.
   It is the normative wire artefact the explorer, three wallets and two
   generated SDKs fan out from.
5. **F1–F3 (§4)** are unowned.
6. **`getconsensusschedule`** must join `RPC_SURFACE` and the golden list when
   it merges.
