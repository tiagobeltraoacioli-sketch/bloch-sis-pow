<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Bloch Genesis-4 — JSON-RPC Method Surface and Stability Contract

```
Document:   BLOCH-RPC-STABILITY-V4
Status:     NORMATIVE for the shipped surface. Section 5 is BUILT as of
            2026-09-01 and is now normative with the rest.
Created:    2026-08-31
Updated:    2026-09-01 — §5's three methods are implemented; surface 4.2.0
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
           READ_METHODS + WRITE_METHODS         route() — 18 names
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

Read out of `crates/bloch-pos-node/src/rpc.rs` (`route`). **Eighteen names**,
fourteen request variants, two permanent typed refusals, one alias pair.

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
| `getvalidators` | `start`? u32 (default 0), `limit`? (1–50, default 25) | `total`, `start`, `returned`, `next_start`, `epoch`, `page_max`, `validators[]` | — |
| `getstakedistribution` | — | `epoch`, `active`, `total_active_stake_sat`, `duty_total_active_stake_sat`, `nakamoto_coefficient{one_third,one_half}`, `top[]`, `top_n`, `quantiles{}`, `gini_bps`, `measures`, `measures_note` | — |

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
- **The bulk listing is `getvalidators`**, added 2026-09-01. It returns the
  same record `getvalidator` does, from the same function, so a client that
  parses one parses the other.
- `getvalidators.start` is a **registry index, not an offset**. The registry is
  a `BTreeMap` and may be sparse: resume from `next_start`, never from
  `start + limit`. A page that is exactly full always carries a cursor even
  when it ended the registry, so a full walk makes one final call returning
  `returned: 0` and `next_start: null`. **Stop on `next_start: null`.**
- `limit` is clamped to **50**, not rejected — the same shape as `getutxos`,
  and far smaller than its 1,000 because `pubkey_hash` is SHA3-256 over 3,745
  bytes of hybrid key material per record and costs ~32 µs there. The ceiling
  is a measured number, not a round one; see §4 and §5.2.
- `getstakedistribution` measures **stake per validator index, not per
  operator** — it says so in `measures` and `measures_note`, because a client
  rendering it as decentralisation must render the disclaimer with it. Its
  `total_active_stake_sat` is the **consensus** roster (leak applied) and is
  the denominator for every `share_bps`; `duty_total_active_stake_sat` is the
  pre-leak figure `getchaininfo` and `getvalidatorcount` publish. The two
  differ whenever the inactivity leak is biting, and they are named apart so
  that difference reads as two facts rather than as a contradiction.

### 1.4a Supply

| Method | Params | Result | Errors beyond `-32602` |
|---|---|---|---|
| `getsupply` | — | `issued_sat`, `cap_sat`, `remaining_sat`, `genesis_issued_sat`, `emitted_since_genesis_sat`, `at_slot`, `at_epoch`, `finalized_epoch`, `finalized`, `issued_note`, `remaining_note` | — |

Two caveats ship **in the payload**, as `issued_note` and `remaining_note`,
for the same reason `tx_hash_note` does: the integrator who most needs them is
the one who never opened this document.

- **`issued_sat` is gross and monotone, and is NOT circulating supply.** Burns
  never decrement it and fees move existing coins. It is an upper bound on what
  could be spendable, never the amount that is.
- **`remaining_sat` is the unminted validator emission budget**, not "coins the
  chain has yet to create". `GENESIS_ISSUED_SAT = TOTAL_SUPPLY_SAT −
  VALIDATOR_EMISSION_SAT`, so everything except the validator emission existed
  at slot 0. `emitted_since_genesis_sat` is the number that actually grows and
  is the one to watch for issuance.
- **Circulating supply is not served.** It needs the whole eUTXO set summed per
  request on the consensus thread. `getcirculatingsupply` is in `RPC_ABSENT`
  with that reason rather than left to return a bare `-32601`.
- `finalized` is `at_epoch <= finalized_epoch`, so it is normally `false`: the
  counter advances at epoch boundaries and the head's boundary is not yet
  finalised. An audit that wants a figure nobody can take back waits for it.

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
`getcapabilities`, `getchaininfo`, `getmempoolinfo`, `getsupply`, `gettxout`,
`getvalidator`, `getvalidatorcount`, `getvalidators`, `sendrawtransaction`.

**`provisional`** — the name and its meaning hold; the response shape is not
finished and **will** change inside this major version. Read the fields you
need; do not assume the set is closed.

Provisional: `getutxos`, `listunspent`, `getstakedistribution`.

For `getutxos` / `listunspent` the reason is specific and known: there is no
cursor, and one will be added. `truncated` is a placeholder for a pagination
protocol the OpenAPI V4 freeze has not decided. Anything a client builds on
"the first page is the whole answer" will break — and already gives wrong
answers for any script hash past 1000 outputs.

For `getstakedistribution` the reason is different and equally specific: it is
the only method here that reports a **derived statistic** rather than committed
state, and the statistic is not finished. `measures` exists precisely because
the value it carries today (`stake_by_validator_index`) is not the one an
auditor wants — a per-operator grouping is, and the node cannot produce one. If
operator identity ever becomes expressible, `measures` takes a second value and
the field set grows. Read `measures`, read the fields you need, and do not
assume the set is closed.

`getvalidators` is **committed**, not provisional, despite also being
paginated: its cursor is real (`next_start` is an index, not a placeholder) and
its records are `getvalidator`'s, which are already committed. The distinction
from `getutxos` is that `getutxos` has no cursor at all, not that one is newer
than the other.

**`refused`** — the method is routed and answers, permanently, with a typed
error. The code is committed; the message is prose.

Refused: `gettransaction` (`-32005`), `getnewaddress` (`-32006`).

### 2.2 Versioning

`getcapabilities.rpc_surface_version` — currently **`4.2.0`**.

4.1.0 → 4.2.0 is a **minor** bump: `getsupply`, `getvalidators` and
`getstakedistribution` were added, and three names left `absent[]` for
`methods[]`. Nothing an integrator already read has moved.

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
dispatcher had **14** names before this work and has **18** after it.
Replacement text:

> Served today (mainline, **18 methods**, frozen by
> `crates/bloch-pos-node/src/rpc/tests.rs`
> `the_rpc_method_namespace_is_frozen` and `only_the_frozen_names_route`):
>
> `getbalance`, `getblockbyid`, `getblockbyslot`, `getblockcount`,
> `getcapabilities`, `getchaininfo`, `getmempoolinfo`, `getnewaddress`,
> `getstakedistribution`, `getsupply`, `gettransaction`, `gettxout`,
> `getutxos`, `getvalidator`, `getvalidatorcount`, `getvalidators`,
> `listunspent`, `sendrawtransaction`.
>
> Dispatch table is `route` in `crates/bloch-pos-node/src/rpc.rs` — 18 names,
> 14 request variants, 2 typed-error stubs; `getutxos` and `listunspent` alias
> one handler. The authoritative in-code allocation is
> `rpc::RPC_SURFACE`, which carries a stability class per name;
> `rpc::RPC_ABSENT` carries the names deliberately not served, and the
> freeze test asserts the two lists are disjoint and that everything in
> `RPC_ABSENT` really answers `-32601`.

| Method | Status | Owner | Frozen by |
|---|---|---|---|
| `getcapabilities` | **CLAIM REQUESTED, 2026-08-31** — surface self-description; `rpc.rs` dispatch, `capabilities_json`, engine arm in `engine.rs`. Constant cost, reads no state. | rpc-stability | `rpc/tests.rs` `getcapabilities_describes_the_surface_without_reading_state` |
| `getsupply` | **CLAIM REQUESTED, 2026-09-01** — issued counter against the cap; `RpcRequest::Supply`, `supply_json`, `CommittedState::issued_sat`. O(1), reads one committed field. | rpc-missing-reads | `rpc/tests.rs` `getsupply_ships_its_caveats_as_fields_not_as_documentation` |
| `getvalidators` | **CLAIM REQUESTED, 2026-09-01** — paginated registry listing; `RpcRequest::Validators`, `validators_json`, `CommittedState::validator_records`. O(log V + page) + one roster build. | rpc-missing-reads | `rpc/tests.rs` `getvalidators_pages_by_index_and_stops_without_looping` |
| `getstakedistribution` | **CLAIM REQUESTED, 2026-09-01** — concentration of the active set; `RpcRequest::StakeDistribution`, `stake_distribution_json`. One roster build + O(V log V); fixed-size response. | rpc-missing-reads | `rpc/tests.rs` `getstakedistribution_reports_nakamoto_at_one_third` |

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
| `getbalance` | **2 × O(U)** | **18.2 ms** (withdrawn; ~1.7 ms warm after F2) | See F2. U grows; this number only goes up. |
| `getsupply` | O(1) | **3.1 µs** | One committed field plus two constants. Flat in V (2.3 µs at V=512) and flat in U. Cheaper than `getcapabilities`. |
| `getstakedistribution` | O(V + D) + O(V log V) | **30 µs** (V=64) · **38 µs** (V=512) | One roster build (3.3 µs at V=64, 16.4 µs at V=512) dominates. Response is fixed-size: 2,194 bytes at V=64, 2,221 at V=512. |
| `getvalidators` | O(log V + page) + O(V + D) | **1.58 ms** (page 50) | Tracks the PAGE, not the registry: the same page measures 1.59 ms at V=512. ~32 µs per record, all of it `pubkey_hash`. |

Measured 2026-09-01, release build, by `what_the_new_reads_cost`
(`rpc/tests.rs`, `#[ignore]`d). That bench needs only the validator registry —
none of the three touches the eUTXO set — which is why it completes in seconds
where `what_a_read_costs_at_carryover_scale` has never been run to the end.

**The measurement changed the design.** §5.2 proposed a 500-record page cap and
judged the hashing "negligible at V=64". It is negligible at V=64 only because
a 500-page cannot return more than 64 records when the registry holds 64. At
V=512, where it can, **a 500-record page costs 17.1 ms** — one uninterruptible
block of the consensus thread, from one unauthenticated caller, in the same
band as the worst read on this surface. The ceiling shipped at **50**, where
the worst page (1.58 ms) is what the worst already-sanctioned read costs, so
`getvalidators` adds no new lever. `the_validator_page_cap_stays_within_the_worst_sanctioned_read`
asserts the bound as a constant, and says in its failure message that the fix
for a larger registry is to cache `pubkey_hash` on the record rather than to
widen the cap.

The quadratic shape §5.2 warns about is also measured rather than asserted:
rebuilding the roster per record adds 0.09 ms to a 50-record page at V=64 and
0.87 ms at V=512 — the term becoming visible exactly where the
validator-opening program would put it.

**What 18 ms means on this port.** RPC is serialised through the engine channel
onto the consensus thread, so ~55 `getbalance` calls per second consume 100% of
a validator's consensus thread. `MAX_CONNECTIONS` is 64, there is no
authentication and no rate limit, and the public edge neither caches
`getbalance` nor answers it from one node — it quorum-checks it across
upstreams, so one client call is several nodes each paying the 18 ms twice. A
single anonymous client can price a validator out of proposing. `gettxout`
answers a narrower question 650× cheaper; where a client can use it, it should.

Three pre-existing amplifiers were reported here on 2026-08-31 as
"reported, not changed". **All three have since been fixed in mainline**, and
the descriptions below are kept as the record of what they were, each with its
current status. Re-read the code before quoting any of the "before" numbers:
the 18.2 ms `getbalance` figure in the table above was withdrawn on 2026-09-01
and corrected to ~1.7 ms warm in `balance_json`'s own doc comment.

- **F1 — FIXED. `getchaininfo` computed the validator roster twice per call.**
  `chain_info_json` calls `state.active_validators()` (→ `consensus_roster_at`)
  and `state.total_active_stake_sat()` (→ `duty_roster`), and each recomputes
  the delegation resolve, the cohort cap and the leak from scratch. This is the
  most-polled method on the chain. Both halves shipped:
  `CommittedState::active_roster_summary` builds the roster once and reads both
  numbers off it, and `Canonical::active_roster` (`engine.rs`) memoises the two
  resulting integers on the state generation, so the build is once per block
  rather than once per caller. It caches the two integers and **not** the
  roster — `duty_roster_at`'s contract is that the roster is never cached. The
  duplicate build was worth about 2 µs at V=64; the memo is the half that
  matters on a port with no rate limit.
- **F2 — FIXED. `getbalance` scanned the entire eUTXO set twice.** `balance_json` calls
  `state.balance_sat()` to sum and then iterates `state.eutxos()` again to
  count. One pass yields both, and would halve the measured 18.2 ms. The edge
  never caches this method and quorum-checks it across upstreams, so one client
  call is several nodes doing it twice each. `balance_json` is now one fold
  producing both numbers; the measured improvement is 2.04x (13.454 ms → 6.592
  ms on the node crate's bench at 452,726 outputs), which is precisely "two
  walks became one". It is **not** a denial-of-service fix and must not be
  reported as one: the remaining walk is still linear in the whole set, because
  there is no index by script hash.
- **F3 — FIXED. `getutxos` collected every match before truncating.** `utxos_json`
  builds a `Vec` of **all** matching entries to learn `total`, then takes
  `limit`. For a script hash with 425,568 outputs that is ~3.4 MB of references
  allocated to return 100 of them. `total` needs a count, not a collection —
  which is also why `limit=1000` measured 3× `limit=100` when both did the same
  single scan. `utxos_json` now counts rather than collects and keeps at most
  `limit` entries.

---

## 5. The missing read methods, as built

**Built 2026-09-01.** This section was a proposal; the three methods now
dispatch. The gap it closed: there was no RPC way to read the validator set or
the issued supply, which blocked a supply audit and blocked any third party
verifying stake distribution independently.

Each is costed against §4's constraint — every read runs on the consensus
thread, on a port with no authentication and no rate limit, so the price of a
method is the size of the lever an anonymous caller has on block production.
None of the three touches the eUTXO set. That is the property that made them
safe to add, and it is why they are measured by
`what_the_new_reads_cost` (`rpc/tests.rs`, `#[ignore]`d) rather than by
`what_a_read_costs_at_carryover_scale`: the state they need is the validator
registry, not the 452,726-entry carryover.

### 5.1 `getsupply` — issued against the cap

**Cost: O(1), measured at 3.1 µs.** `CommittedState::issued_sat()` is a field read of state
committed under `TAG_ISSUED_SUPPLY`, seeded at genesis with
`tokenomics_v4::GENESIS_ISSUED_SAT` and advanced at epoch boundaries by the
satoshis `close_epoch` actually credits. Plus two compile-time constants and
the JSON build. It does not move with the chain, with V, or with the eUTXO set
— the only other method on this surface with that property is
`getcapabilities`, and `getsupply` is **thirty times cheaper than it** (3.1 µs
against ~100 µs), because it builds a much smaller JSON tree. It is the
cheapest method on the surface, full stop.

```json
{
  "issued_sat": "…", "cap_sat": "…", "remaining_sat": "…",
  "genesis_issued_sat": "…", "emitted_since_genesis_sat": "…",
  "at_slot": 54547, "at_epoch": 1704,
  "finalized_epoch": 1702, "finalized": false,
  "issued_note": "…", "remaining_note": "…"
}
```

**Both caveats ship as fields, not as prose here.** `issued_note` and
`remaining_note` are in the payload for the same reason `tx_hash_note` is: the
reader who most needs them is the one who never opened this document.

1. **`issued_sat` is gross and monotone.** Fees move existing coins,
   whistleblower rewards come out of slashed bonds, and burns never decrement
   it — they widen the gap below the cap, and the invariant is one-sided
   (`issued_sat <= TOTAL_SUPPLY_SAT`, enforced in `compute_post_state`). It is
   therefore **not circulating supply** and the response says so in those
   words. A Bitcoin-shaped audit that reads it as circulation is wrong by
   however much has been burned, in the direction of overstating.

2. **`remaining_sat` is the unminted validator emission budget.**
   `GENESIS_ISSUED_SAT = TOTAL_SUPPLY_SAT − VALIDATOR_EMISSION_SAT`, so
   everything except the validator emission existed at slot 0.
   `genesis_issued_sat` rides beside it so the two cannot be confused, and
   `emitted_since_genesis_sat` — the number that actually grows — is the
   headline for anyone watching issuance. This identity is asserted, not
   assumed: `getsupply_ships_its_caveats_as_fields_not_as_documentation`
   checks `remaining_sat == VALIDATOR_EMISSION_SAT − emitted`, so if the
   relation ever changes, `remaining_note` fails rather than lies.

Both subtractions saturate. The invariant they rest on is enforced elsewhere,
and a query surface that panics when an invariant it does not own is violated
turns a consensus bug into a dead node — which on an unauthenticated port is
the whole attack. `getsupply_does_not_panic_when_the_supply_invariant_is_violated`
covers it from both directions.

**Circulating supply is deliberately not offered.** It would require summing
`eutxos()` in full, on the consensus thread, uncached and unauthenticated. The
name `getcirculatingsupply` sits in `RPC_ABSENT` carrying that reason, so an
integrator who probes it is told why rather than being handed a bare `-32601`.
If it is ever genuinely needed, serve it memoised per **finalised** epoch — one
scan per ~16 minutes, amortised across all callers, and finality is the only
boundary at which the answer is stable anyway — and report the epoch it was
computed at. Never per request.

`finalized` is `at_epoch <= finalized_epoch` and is normally `false`: the
counter advances at epoch boundaries and the head's boundary has not finalised.
That is a warning, not a formality — an audit wanting a figure nobody can take
back waits for it.

### 5.2 `getvalidators` — the registry, paginated

**Cost: O(log V + page) records, plus ONE roster build of O(V + D).** Measured
at **1.58 ms for a 50-record page** — and 1.59 ms for the same page at V=512,
because the cost tracks the page and not the registry. V is 64 today and
bounded by consensus; D (delegations) is 0 today and is not.

```
getvalidators(start?: u32 = 0, limit?: usize = 25, max 50)
→ { total, start, returned, next_start | null, epoch, page_max, validators: [ … ] }
```

Records come from `validator_json` verbatim, so there is one definition of what
a validator looks like and a client that already parses `getvalidator` needs no
new code. `getvalidators_reuses_the_getvalidator_record_verbatim` asserts the
two are byte-identical rather than merely similar.

The four anti-DoS conditions, and how each is met:

1. **Page cap.** Clamped, not rejected — the same shape as the UTXO page —
   with `returned` and `next_start` reported so the clamp is visible.
   `getvalidators_clamps_an_absurd_page_instead_of_refusing_it` pins it. **The
   ceiling shipped at 50, not the 500 this section proposed, and the default at
   25.** The proposal's reasoning was wrong in a way only measurement caught:
   the hashing is negligible at V=64 solely because a 500-page cannot return
   more than 64 records from a 64-record registry. At V=512 a 500-record page
   costs **17.1 ms**, which is a new lever of the same size as the worst read
   on this surface. At 50 the worst page is 1.58 ms — the cost that already
   existed — so the method adds none.
2. **Roster computed once per call, not once per record.** The engine reads
   `active_validators()` once, reduces it to `(index, effective_stake)` pairs
   and hands them in. `validators_json` **has no state handle in its
   signature**, so the O(page · (V + D)) shape is not merely avoided, it is
   unavailable to write. That is the load-bearing decision in this method.
3. **Memoisation — deviated from, deliberately.** The proposal asked for a
   roster memo per `(epoch, head)`. The engine already has one
   (`Canonical::active_roster`, keyed on the state generation) and it caches
   **two integers, not the roster**, because `duty_roster_at`'s own contract is
   that the roster is derived on demand and never cached — a cached roster is
   the §5.5 pattern the committee crate bans. So `getvalidators` and
   `getstakedistribution` each pay one roster build per call, and F1's
   duplicate build is what the existing memo removed. Extending the memo to
   hold the roster itself is a change to a consensus-adjacent invariant and is
   the founder's call, not this document's. The measured cost of one build at
   V=64 is in `what_the_new_reads_cost`.
4. **`pubkey_hash` is the per-record cost, and it is the whole cost.**
   SHA3-256 over a hybrid ML-DSA-65 ‖ Falcon-1024 public key — 3,745 bytes per
   record, measured at **~32 µs**. A page is `limit × 32 µs` and essentially
   nothing else, which is why the same 50-record page costs the same at V=64
   and V=512, and why the ceiling had to come down rather than the roster work
   being optimised. The benchmark uses real 3,745-byte keys for exactly this
   reason; a 64-byte stub would understate a page by two orders of magnitude.

   **When the registry opens to external validators, cache the hash on the
   record — do not raise the cap.** The cap bounds the symptom; the hash is the
   cause. `the_validator_page_cap_stays_within_the_worst_sanctioned_read` says
   so in its failure message, so the next person to try meets the reasoning
   before the diff goes green.

`CommittedState::validator_records(start, limit)` is a `BTreeMap::range` plus a
`take`, so it is genuinely O(log V + page) and not O(V) with a skip.

**`start` and `next_start` are registry indices, not offsets.** The registry is
a map and may be sparse; a client computing `start + limit` skips records the
moment an index is missing. A page that is exactly full always carries a
cursor, even when it happened to end the registry — a full page cannot know it
was the last without reading a record past it, and that peek would cost a clone
of a 3.7 KB key on every page to save one lookup on the last. So a full walk
ends with one call returning `returned: 0`, `next_start: null`. **Stop on
`next_start: null`, never on arithmetic over `total`.**

### 5.3 `getstakedistribution` — what a third party needs to check us

**Cost: one roster build, O(V + D), plus O(V log V) for the sort. The response
is fixed-size regardless of V.** Measured at **30 µs at V=64 and 38 µs at
V=512** — the roster build is nearly all of it — with the response at 2,194 and
2,221 bytes respectively. That second pair of numbers is the anti-DoS property
made checkable: the per-validator list is capped at 20 and everything else is a
scalar, so neither the caller nor the registry can grow the response. It is the
cheapest of the three by an order of magnitude, and there is no argument for
paginating or restricting it.

```json
{
  "epoch": 1704, "active": 64,
  "total_active_stake_sat": "…", "duty_total_active_stake_sat": "…",
  "nakamoto_coefficient": { "one_third": 4, "one_half": 7 },
  "top": [ { "index": 0, "effective_stake_sat": "…", "share_bps": 1563 } ],
  "top_n": 20,
  "quantiles": { "p50_sat": "…", "p90_sat": "…", "p99_sat": "…" },
  "gini_bps": 0,
  "measures": "stake_by_validator_index",
  "measures_note": "…"
}
```

This is the method that makes the concentration claim verifiable by someone who
does not trust us, which is the entire point of publishing it.

- **`nakamoto_coefficient.one_third` is the number**, because one third is the
  threshold at which finality can be reverted. Reporting only the half would
  understate the risk by the factor that matters. `one_half` is reported beside
  it because it is what other chains publish and omitting it invites a wrong
  comparison — not because it is the threshold here.
- **The count is over a strict majority of the threshold.** Three validators
  holding exactly one third each give `one_third: 2`, not 1: holding exactly a
  third cannot revert anything, and a `>=` would name a set that cannot do what
  the number claims it can. `getstakedistribution_reports_nakamoto_at_one_third`
  pins that case specifically.
- **`measures: "stake_by_validator_index"` is a disclaimer with a field name.**
  This measures stake per **index**, not per operator. A registry index is a
  slot, not an identity; the RPC cannot know who runs what, and on this chain
  sixty-four indices are largely one operator today. Every figure here is
  therefore an *upper bound* on the per-operator answer. `measures_note` says
  so in the payload, because a client rendering this as decentralisation must
  render the disclaimer with it.
- **Two denominators, named apart.** Shares are over `total_active_stake_sat`,
  which is the **consensus** roster with the inactivity leak applied — that is
  the weight that actually decides finality. `getchaininfo` and
  `getvalidatorcount` publish the **duty** roster's pre-leak total, and it is
  reported here as `duty_total_active_stake_sat` so the difference reads as two
  facts rather than as a contradiction. Publishing one total and computing
  shares with the other is how a distribution that does not sum to 10,000 bps
  gets shipped.
- **Ties break by ascending index**, so two honest nodes on identical state
  return identical lists. Without that, a third party diffing two nodes reads a
  disagreement that is not there — and on this chain, node disagreement is a
  thing operators have chased for real.
- **An empty or fully-leaked roster answers rather than dividing by zero.** The
  leak drives effective stake toward zero and this fleet has run with it
  biting; `nakamoto_coefficient` and `share_bps` go `null`, `gini_bps` reads 0.

### 5.4 Deliberately not served

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

### 5.5 What shipped, and what is still owed

All three landed together on `rpc/missing-reads`, with the accessors they need
(`CommittedState::issued_sat`, `::validator_records`) added to
`bloch-pos-committee` as read-only projections of already-committed state — the
same shape as `validator_count` and `balance_sat`, changing no transition
behaviour.

Registration is done in all three places the freeze test checks: the `route`
arm, the `RPC_SURFACE` entry with a stability class, and the golden list in
`the_rpc_method_namespace_is_frozen`. `getsupply` and `getvalidators` were
**moved out** of `RPC_ABSENT` rather than merely added to `RPC_SURFACE` — the
freeze test asserts the two lists are disjoint, and
`getcapabilities_describes_the_surface_without_reading_state` now asserts the
move in both directions, because a client that reads `absent[]` and
short-circuits would never call a method that works.

Verified by mutation, as `getcapabilities` was: adding
`"getsupplystats" => RpcRequest::Supply` to `route` without a table entry turns
`the_rpc_method_namespace_is_frozen` red and names `getsupplystats` in the diff.
Reverted.

**Names still to be confirmed by the PMO.** The three constants are written and
the freeze test holds them, but `docs/WIRE-NAMESPACE-REGISTRY.md` §0 requires a
claim. If the PMO assigns different names, each changes in exactly three places
— the `route` arm, the `RPC_SURFACE` entry, the golden list — and the test fails
until all three agree. §3.3 above carries the claim rows.

**Still owed, and not done here:** the public proxy's `READ_METHODS` allowlist
(§6.1) does not forward these names, so they are unreachable through
`posternlabs.com/g4rpc` until it is updated. That is a different repository.

---

## 6. Required follow-ups

1. **`getcapabilities`, `getsupply`, `getvalidators` and
   `getstakedistribution` must be added to the public proxy allowlist** —
   `posternlabs-deploy/functions/g4rpc.js`, `READ_METHODS` — or they are
   unreachable through the only public endpoint. It is a different repository
   and is not touched by this work.

   Caching guidance, since these four differ: `getcapabilities` is never cached
   (it is the method a client calls to learn what it is talking to).
   `getsupply` and `getstakedistribution` change only at epoch boundaries and
   can be cached ~30 s safely — both are cheap enough that caching is a
   courtesy to the node rather than a necessity. `getvalidators` must **not**
   be quorum-checked across upstreams the way `getbalance` is: paginating
   across nodes that disagree about the head would interleave two registries
   and hand a client a list that exists nowhere. Pin a page walk to one
   upstream, or serve it from the indexer instead.
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
5. **F1–F3 (§4) are fixed** in mainline as of 2026-09-01 — this item is closed.
   What remains open is the durable version of F2: an index by script hash in
   committed state, so `getbalance` stops being linear in the whole eUTXO set.
   That is a consensus-level change, not an RPC one.
6. **`getconsensusschedule`** must join `RPC_SURFACE` and the golden list when
   it merges.
