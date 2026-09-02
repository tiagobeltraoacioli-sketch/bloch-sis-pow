# Bloch Genesis-4 — Exchange & Integrator Guide

```
Document:   BLOCH-GENESIS4-EXCHANGE-INTEGRATION
Audience:   Exchange integration, custody and risk teams
Chain:      Bloch Genesis-4 · Ticker BLCH · Proof of Stake · live mainnet
Describes:  the RELEASED binary — main @ e4083f9
Measured:   2026-08-26, height 15,146, epoch 1,101
Revised:    2026-08-31, after an integrator audit (see §0.1)
Delivery:   file, to named contacts. Not published. Not a shared artifact.
```

---

## 0. How to read this document

### 0.1 Why this revision exists

An exchange integrating against Genesis-4 audited the previous revision of this
document against the code at `main` @ `e4083f9` and found three claims it did
not support:

1. `staking::validate_deposit` has no production call site.
2. `unlock_epoch` does not appear anywhere in `bloch-pos-committee`.
3. The block payload cap doubled to 524,288 at epoch 800 — which they worked
   out themselves, because the previous revision printed the post-flag-day
   figure flat, with no era attached.

All three were correct. The first two were our error in kind, not degree: the
document described work that exists only on an unreleased branch as though it
were in the binary they had downloaded. This revision fixes that, and the audit
that produced it found a further **nineteen** claims that were wrong, stale or
materially incomplete — including the name of the node binary, the address
derivation rule, the default RPC port, and the input ceiling in §6. Those are
corrected below and listed in
[`INTEGRATION-BOOK-AUDIT-2026-08-31.md`](INTEGRATION-BOOK-AUDIT-2026-08-31.md).

Their summary of why a stale parameter is not a minor problem on this chain is
the best statement of it anyone has made, and it is worth repeating at the top
of the document it corrects:

> *"Conservation is an equality, so a stale fee assumption is a hard rejection
> rather than a slow confirm."*

That is exactly right. `sum(inputs) == sum(outputs) + fee` is checked with
`!=`. There is no tolerance band, and no overpayment path — an overpaying
transfer is rejected for the same reason an underpaying one is. So every fee
input published here is load-bearing: build against a stale one and every
transaction you sign is rejected, with an error that names a value mismatch
rather than the parameter that actually moved.

Every number in this document is now pinned by a test
(`crates/bloch-pos-committee/tests/integration_book_claims.rs`) that names the
section it belongs to, and moving a published constant without updating this
document is a CI failure. The rule is written down in
[`CONSENSUS-CHANGELOG-DISCIPLINE.md`](CONSENSUS-CHANGELOG-DISCIPLINE.md).

### 0.2 Status markers

Every substantive claim carries one of four markers. **Unmarked prose describes
the released binary.**

| Marker | Meaning |
|---|---|
| **`[LIVE]`** | in the released binary, reachable on the wire today |
| **`[SCHEDULED]`** | in the released binary, behind a gate at a **named future epoch**. Not reachable yet. |
| **`[INERT]`** | in the released binary, behind a gate set to `u64::MAX`. Not reachable, and no date. |
| **`[UNRELEASED]`** | **not in the released binary at all.** Exists on a branch, named where it appears. |

`[SCHEDULED]`, `[INERT]` and `[UNRELEASED]` all mean *you cannot use this
today*. They are distinguished because what you should do about each is
different: schedule work for the first, ignore the second, and talk to us about
the third.

The distinction is the entire lesson of the audit. Code that exists, compiles
and is tested is not a wire guarantee. Two of the three findings were exactly
this: functions that are public, fully tested, and unreachable.

### 0.3 The three things most likely to break your integration

1. **`sendrawtransaction` does not return a `txid`.** It returns `tx_hash`,
   which is a node-local handle, not a consensus identifier — no block commits
   to it and no other node agrees on it. There is no transaction id on this
   chain and no txid→block index. Key your deposit records on outpoints
   (`txid`, `vout`) read from the UTXO set. See §3.7 and §5.
2. **`getblockbyslot` returns an error, `-32007`, for empty slots.** Missed
   proposals are normal under PoS. A scanner that treats `-32007` as a fault
   will alert continuously. See §3.9.
3. **The fee is derived, never declared, and conservation is an equality.**
   You cannot overpay. Read the price immediately before building. See §6.4.

And one that will not break your client but should shape your credit policy:
**`finalized` is not currently guaranteed to be the same value on every node.**
Read it from two independent nodes and require agreement. See §5.3 — it is the
most important risk disclosure in this document, and read the caveat under it
on what "two independent nodes" is currently worth, which is less than it
sounds.

---

## 1. Chain parameters

| | | Status |
|---|---|---|
| Ticker | BLCH | `[LIVE]` |
| Decimals | 8 — 1 BLCH = 100,000,000 sat | `[LIVE]` |
| Slot time | 30 seconds | `[LIVE]` |
| Epoch | 32 slots (16 minutes) | `[LIVE]` |
| Ledger | eUTXO, outputs keyed `(txid, vout)` | `[LIVE]` |
| Signatures | ML-DSA-65 ‖ Falcon-1024 (post-quantum hybrid) | `[LIVE]` |
| Block gas limit | 60,000,000 (target 30,000,000) | `[LIVE]` |
| Block payload cap | **524,288 bytes since epoch 800** — see below | `[LIVE]` |
| Genesis carryover | 452,726 outputs · 18,146,400,000 BLCH | `[LIVE]` |

**Amounts are decimal strings in every response.** Balances exceed 2^53, so
parse them as big integers. This is deliberate: it makes satoshi-exact
accounting the default. It is also the single most common integration bug on
this chain.

### 1.1 The payload cap has two eras

This is the finding the integrator made for themselves, and the previous
revision's flat "524,288" is what let them.

| Epoch range | Payload cap | EIP-1559 byte target |
|---|---|---|
| 0 – 799 | 262,144 | 131,072 |
| 800 – | **524,288** | 262,144 |

The switch is `params::BLOCK_BYTES_V2_ACTIVATION_EPOCH = 800`. Cap and target
move together as one switch — splitting them would price a half-full block as
congested and reach you as an unexplained fee spike.

The chain passed epoch 800 long before this document was first measured
(epoch 1,101), so **524,288 is the figure to build against today**. It is
stated with its era because a number without an era is a number that was false
for the first 800 epochs of this chain and gives you no way to check whether it
is still true when you read it. If you are replaying history — reconstructing
balances from blocks rather than reading the UTXO set — you need both rows.

Pinned by `book_block_payload_cap_and_the_era_it_belongs_to`.

### 1.2 Activation gates

Four gates exist in `params.rs`. Three of them arm code that nothing on the
wire can reach today. They are listed here because a capability behind a closed
gate is not a capability, and you should not design against one.

| Gate | Value | State | What it controls |
|---|---|---|---|
| `BLOCK_BYTES_V2_ACTIVATION_EPOCH` | 800 | **open** | the 512 KiB payload cap (§1.1) |
| `TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH` | 800 | **open** | the V2 deduplicated-witness transfer (§6) |
| `LEAKED_ROSTER_ACTIVATION_EPOCH` | 1,400 | `[SCHEDULED]` | whether the inactivity leak reaches the duty roster (§5.3) |
| `LEAK_RECOVERY_ACTIVATION_EPOCH` | `u64::MAX` | `[INERT]` | leak recovery and the quorum-denominator floor — **read §5.3 before crediting** |

A fifth constant, `ANCESTRY_SEED_ACTIVATION_EPOCH`, is also `u64::MAX` but
**gates nothing**: the seed look-ahead it once guarded was made unconditional
on 2026-08-24 and the constant is now unreferenced. It is dead, not scheduled.
It is named here only so that finding it in the source does not read as a
pending feature.

There is **no gate for validator entry**. See §8.

Pinned by `book_activation_gates_are_classified_not_assumed`.

---

## 2. Custody

Signing uses a post-quantum hybrid scheme, ML-DSA-65 combined with
Falcon-1024. Keys are held and used in software; the reference implementation
is a WASM signing core that runs in-process, so your key material never leaves
your own boundary and never transits an RPC.

**There is no hardware custody path, and this is not a roadmap item we can
date.** No HSM on the market signs ML-DSA ‖ Falcon, and no hardware wallet
(Ledger, Trezor) can sign for this chain — they implement secp256k1, which the
Genesis-4 base layer does not use for spending. If your custody policy requires
an HSM or a hardware signer, that requirement cannot be met today by us or by
anyone, and it should be raised before integration work starts rather than at
security review.

Falcon signatures are variable-length and hedged — the same inputs produce
different valid bytes each time, with the same set of authorised spends. Sign
once per transfer and broadcast the stored bytes on any retry. The variable
length also means **you cannot compute a transaction's encoded size from a
formula**; you must measure the bytes you actually produced (§6.2).

We work directly with integrators on custody design. Contact us before
starting.

---

## 3. RPC reference

JSON-RPC 2.0 over HTTP POST. Parameters may be a positional array or a named
object.

### 3.0 Transport constraints — read before writing a client

These are not defaults you can tune; they are what the server does.

| | |
|---|---|
| **Authentication** | **none.** The server authenticates nothing. |
| **CORS** | **none.** No `Access-Control-Allow-*` header is ever sent, and `OPTIONS` is rejected with HTTP 405. A browser cannot call this endpoint cross-origin. |
| **TLS** | none. Terminate it yourself. |
| Verb | POST only; anything else is HTTP 405 |
| Batch requests | **not supported** — a JSON array is refused with `-32600` |
| Keep-alive | **not supported** — one request per connection |
| Concurrency | 64 connections, then HTTP 503 |
| Body limit | 1 MiB, then HTTP 413 |
| Header limit | 16 KiB, then HTTP 431 |
| `Content-Length` | required; chunked encoding refused with HTTP 411 |
| Socket timeout | 30 s (HTTP 408) |
| Engine timeout | 10 s, surfaced as `-32004` |

`sendrawtransaction` is a write on an unauthenticated port. Bind to loopback
and put your own proxy in front of it. Do not expose it.

### 3.1 `getcapabilities` — `[UNRELEASED]`. Do not call it yet.

**Correction, 2026-09-01.** A previous revision of this document, and item 1 of
the §11 checklist, told you to call `getcapabilities` at connect time. **That
instruction fails on every node you can reach today.** We measured it rather
than assuming it:

Measured **2026-09-02T04:13:56Z**, both archivals then on the same head
(height 34,628, epoch 1,735, block id `4b0949e8624ff38b…`):

| Endpoint | `getcapabilities` | `getbuildinfo` | `getversion` |
|---|---|---|---|
| archival `139.180.166.5:8080` | `-32601` | `-32601` | `-32601` |
| archival `139.180.173.231:8080` | `-32601` | `-32601` | `-32601` |
| all nine RPC upstreams behind our public edge | `-32601` | `-32601` | `-32601` |
| published binary `g4-node-20260901` (`7a83ca89`) | absent from its source | absent | absent |

Read that table beside the head they agreed on. The two archivals returned the
identical height, epoch and block id — flawless agreement on chain state — and
there is no query in the surface that would tell you whether that agreement is
two independent opinions or one opinion served twice. That is the gap, stated
as compactly as it can be.

The method is real, implemented and tested — on an **unreleased branch**. It is
not in the tag you downloaded. The document described the repository and called
it the wire, which is the same error §0.1 already records twice, made a third
time; our apology for the wasted integration time.

**What to do instead, today.** Treat this document's §3 tables as the surface,
and probe nothing. When you get `-32601` for `getcapabilities`, that is the
expected answer and not a sign of a misconfigured endpoint.

**And do not use that `-32601` to date a node.** It is tempting to read a
method-not-found as "this endpoint is behind" — it is not. `getcapabilities` is
absent from the source of the published `g4-node-20260901` binary, absent from
`main`, and absent from the binary the fleet runs; it exists on one unreleased
branch. A node on the newest thing we have published and a node that has not
been restarted in months return the same `-32601`. The answer is consistent with
every generation and identifies none, which is precisely why §3.1.1 exists.

**What it will do when it lands.** It returns the method table with a stability
class per method, the deliberately absent names with the reason for each, the
error-code table, the limits above, and `rpc_surface_version` — from the running
binary, so it cannot be stale the way a document can. At that point, branch on
it rather than on §3. `rpc_surface_version` is `4.2.0` on the branch and moves
under semver: major for a removal or a breaking change, minor for an added
method or field, patch for wording.

**One place it already works.** Our public explorer edge
(`blochl1.com`, `posternlabs.com`) answers `getcapabilities` **itself**, out of
its own knowledge, without forwarding it. That answer describes *the edge's*
guarantees — its cache classes, its corroboration rules — and is not a
statement about any node. Do not read it as one.

### 3.1.1 `getbuildinfo` — which binary, and which consensus lineage — `[UNRELEASED]`

Branch `rpc/build-identity` @ `a8a0912e`, unmerged — named per §0.2, because
`[UNRELEASED]` without a branch is the defect §0.1 records. It is the answer to
a question this document could not previously answer at all: **which binary is
the node I am talking to running?**

Until it lands, there is no way to tell. No deployed node exposes any version
method — `getcapabilities`, `getbuildinfo` and `getversion` all return `-32601`
on both public archivals (measured 2026-09-01). The `node_version` field inside
`getcapabilities` did not help either: on the branch it was the bare package
version, `0.1.0-mainnet`, byte-identical on every binary ever built from this
crate. That is fixed in the same change.

```json
{"node_version":"0.1.0-mainnet (46133196f0a1)",
 "build_commit":"46133196f0a1",
 "build_clean":true,
 "rpc_surface_version":"4.2.0",
 "block_version":2969567237,
 "genesis_block_id":"…",
 "consensus_gates":[
   {"name":"BLOCK_BYTES_V2_ACTIVATION_EPOCH","epoch":800,"armed":true},
   {"name":"LEAKED_ROSTER_ACTIVATION_EPOCH","epoch":1400,"armed":true},
   {"name":"LEAK_RECOVERY_ACTIVATION_EPOCH","epoch":null,"armed":false}, …],
 "gates_digest":"…",
 "knows_gates_through_epoch":1400,
 "gates_digest_proves":"…", "gates_digest_does_not_prove":"…",
 "compatibility_rule":"…", "scope":"node-local …"}
```

`build_commit` is the field that matters. A semantic version does not identify a
binary on this chain — the 2026-08-11 fleet survey found three boxes running
three different binaries, all reporting the same version string — and what you
actually need to know is not how new a node is but **whether it is on the same
consensus lineage as the node you checked yesterday.**

`build_clean` is `true`, `false` (built from a modified tree) or `null` (the
build had no git to ask, e.g. a container). `null` and `false` are different
facts; do not collapse them.

**`gates_digest`, and its limit.** The digest is SHA3-256 over the sorted list
of consensus gates and their activation epochs. Read both halves of what it
means, because the useful half and the dangerous half are the same field:

- **It proves**: two nodes reporting the same digest link the same *set* of
  consensus gates, at the same epochs, and agree on which are inert. Digests
  that **differ** mean those two nodes will diverge at the first gate they
  disagree about. Act on a mismatch immediately.
- **It does not prove**: that the two nodes *behave* the same. The digest covers
  the constants, not the code behind them. **Two nodes with an identical
  `gates_digest` can still derive different committees, different fork choices
  and different state roots.** Every consensus defect this chain has actually
  shipped lived below the gate table, not in it. A match is necessary for
  compatibility and nowhere near sufficient.

`scope` says `node-local`: the answer describes the one node that replied. If
you put a load balancer in front of several nodes, this answer is meaningless —
ask each node on its own address.

**It is cheap enough to poll.** Measured on branch `rpc/build-identity`
@ `a8a0912e`, `--release`, on an idle 2-core box, against a fixture at live
carryover scale (452,726 outputs): **4.7 µs** per call, against 1.4 µs for
`getblockcount` and 4.85 **ms** for `getbalance`. It reads no chain state and
does not grow with the height, so polling it per connection — or per credit
decision — costs the node nothing measurable. That matters more here than
elsewhere: this port has no authentication and no rate limit, and every method
is served by the consensus thread, so we will not add a method to it that a
caller could turn into a lever. Do **not** infer from these numbers what
`getbalance` costs you at your own scale; §3.3 has that, and it is three orders
of magnitude away.

### 3.2 `getchaininfo` — chain head and settlement state

No parameters.

```json
{"height":15146,"slot":35247,"epoch":1101,"slot_in_epoch":…,"slots_per_epoch":32,
 "block_id":"…","state_root":"…","finalized_height":15069,
 "previous_justified":{"epoch":…,"root":"…"},
 "justified":{"epoch":1100,"root":"…"},
 "finalized":{"epoch":1099,"root":"…"},
 "validators":{"total":64,"active":64},
 "total_active_stake_sat":"6177107126034566",
 "base_fee_millisat_per_gas":"10",
 "next_base_fee_millisat_per_gas":"10",
 "mempool":1,"blocks_known":15146,"behind_by_slots":0,"wall_slot":…}
```

Four fields matter for integration: `finalized` (settlement — §5),
`behind_by_slots` (is your node current), `next_base_fee_millisat_per_gas`
(what the next block will charge — §6.4), and `state_root` (agreement — §7.5).

`total_active_stake_sat` and both base-fee fields are decimal strings; the rest
are numbers.

### 3.3 `getbalance [script_hash]` — authoritative balance

```json
{"script_hash":"…","balance_sat":"0","utxo_count":0}
```

`utxo_count` is a **true total**, counted over the whole committed set and not
capped by any page limit. This is the method to poll.

### 3.4 `getutxos [script_hash, limit]` — individual outputs

```json
{"script_hash":"…","total":0,"returned":0,"truncated":false,"utxos":[
  {"txid":"…","vout":0,"value_sat":"4000000000000","script_hash":"…"}]}
```

**Three corrections to the previous revision, all of which will break a client
written against it:**

- **There is no `offset` parameter.** The method takes `script_hash` and
  `limit` only; a third positional argument is silently ignored. There is no
  cursor and no pagination — `truncated` tells you the set was larger than your
  limit, and that is all you get.
- **The default `limit` is 100, not 1,000.** The maximum is 1,000. Values are
  clamped into `1..=1000` without an error, so `limit: 5000` silently returns
  1,000 and `limit: 0` silently returns 1.
- **The UTXO objects do not carry `at_slot`.** They carry `txid`, `vout`,
  `value_sat` and `script_hash`.

Because there is no cursor, **an address with more than 1,000 outputs cannot be
fully enumerated by this method.** Keep deposit addresses below 1,000 outputs
(§5) or use `gettxout` against outpoints you already know.

### 3.5 `listunspent [script_hash, limit]`

The same dispatch arm as `getutxos`: same request, same response, same limits.
Two names, one method.

### 3.6 `gettxout [txid, vout]` — is this specific output still unspent

```json
{"txid":"…","vout":0,"unspent":true,"utxo":{…},"at_slot":…}
```

`vout` is optional and defaults to 0. `at_slot` is the head slot the answer was
computed at — it is a freshness stamp on the answer, not a property of the
output. The nested `utxo` object carries `script_hash` alongside the value.

Exact, single-output, constant-cost. **This is the primitive for confirming an
individual payment**, and it is the one that keeps working on an address whose
output count has passed the `getutxos` limit.

### 3.7 `sendrawtransaction [hex]` — broadcast

```json
{"accepted":true,"status":"accepted","kind":"…","bytes":…,
 "tx_hash":"…","tx_hash_note":"…","confirmation":"…"}
```

**There is no `txid` field.** The previous revision showed one; it does not
exist, and a client that reads `result.txid` gets `undefined`.

`tx_hash` is SHA3-256 of the canonical bytes. It is a **node-local handle for
your own bookkeeping** — no block commits to it, no other node agrees on it,
and no method looks anything up by it. The response says so itself in
`tx_hash_note`. Do not key deposit or withdrawal records on it and do not show
it to a customer as a transaction id.

`accepted` is `true` whenever the call succeeds; failure arrives as a JSON-RPC
error object, never as `accepted: false`. `status` distinguishes `"accepted"`
from `"duplicate"`.

**How to confirm a send, given that there is no txid:** the outputs you created
are addressable as `(txid, vout)` where `txid` is derived from the transaction
you signed. Poll `gettxout` for them, or poll `getbalance` on the destination.
See §5.

### 3.8 `getmempoolinfo` — pending state and next price

```json
{"size":1,"max":4096,"bytes":338487,"next_base_fee_millisat_per_gas":"10"}
```

`max` is 4,096 transactions. `next_base_fee_millisat_per_gas` is the price the
next block will charge; the same value is on `getchaininfo`, so one poll can
serve both purposes.

### 3.9 Error codes — the complete table

The previous revision listed five codes, mislabelled one, and omitted the two
that matter most operationally. This is the full set; `getcapabilities` returns
the same table from the running node.

| Code | Name | Meaning and correct client response |
|---|---|---|
| `-32700` | `PARSE_ERROR` | body is not JSON or not UTF-8 |
| `-32600` | `INVALID_REQUEST` | malformed request — **also how a batch array is refused** |
| `-32601` | `METHOD_NOT_FOUND` | no such method on this build |
| `-32602` | `INVALID_PARAMS` | the message names the offending field |
| `-32603` | `INTERNAL_ERROR` | declared; not emitted on any known path |
| `-32000` | `BLOCK_NOT_FOUND` | **not "general node error"** — specifically: no block with that id |
| `-32001` | `VALIDATOR_NOT_FOUND` | index not in the committed registry |
| `-32002` | `TX_DECODE_FAILED` | valid hex, not a canonical encoding. Do not retry unchanged |
| `-32003` | `MEMPOOL_FULL` | capacity, **not a verdict on your transaction**. Retry later |
| `-32004` | `NODE_UNAVAILABLE` | consensus thread unreachable or shutting down. Retry |
| `-32005` | `NO_TRANSACTION_INDEX` | permanent answer for `gettransaction`. There is no txid index |
| `-32006` | `NO_WALLET` | permanent answer for `getnewaddress`. The node has no wallet |
| `-32007` | `SLOT_EMPTY` | **normal.** The proposer missed that slot. Advance; do not alert |
| `-32008` | `TX_REFUSED` | judged invalid on its merits. **Never resubmit these bytes** |

Two of these decide whether your integration is operable:

- **`-32007` is not an error condition.** Missed proposals are ordinary under
  PoS. A block scanner that treats a `-32007` as a fault will page you
  continuously. Advance to the next slot.
- **`-32003` and `-32008` are opposites and must not be conflated.**
  `-32003` means try again; `-32008` means these exact bytes will never be
  accepted, rebuild the transaction. A client that retries `-32008` loops
  forever.

Anything you do not handle explicitly will be treated as a generic failure,
which for `-32007` means false alarms and for `-32008` means an infinite retry
loop. Handle both by name.

### 3.10 Methods that do not exist

Deliberately absent, each with its reason. `getcapabilities` returns this list
too, so you do not have to probe and infer from `-32601`.

| Name | Why not |
|---|---|
| `getblockbyheight` | height is not the addressing unit under PoS — use `getblockbyslot` |
| `getvalidators` | no bulk listing; read one at a time with `getvalidator` |
| `getpeers` | peer identities are not exposed on an unauthenticated port |
| `getsupply`, `getissuance`, `getsupplyinfo` | not built; `getsupplyinfo` is a Genesis-3 name not carried forward |
| `getstakinginfo` | proposed as `getstakedistribution`, not built |
| `gettransaction` | **exists but always fails, `-32005`** — there is no txid index |
| `getnewaddress` | **exists but always fails, `-32006`** — no wallet, and no frozen address format |

The last two return dedicated permanent codes rather than `-32601`. If you
probe them and read the previous revision's error table, you will misclassify
both.

Also served, and omitted from the previous revision entirely: `getblockcount`,
`getblockbyid`, `getvalidator`, `getvalidatorcount`.

### 3.11 `getblockbyslot [slot]` — block header

```json
{"slot":35242,"height":15141,"block_id":"…","parent":"…",
 "proposer_index":55,"timestamp":…,"epoch":1101,
 "state_root":"…","body_root":"…","attestation_root":"…","coherence_root":"…",
 "tx_count":0,"attestation_count":2,
 "justified_root":"…","finalized_root":"…","finalized":true,"finality":"finalized",
 "randao_mix":"…","randao_reveal":"…","version":2970353669}
```

Empty slots return `-32007`, not an empty result (§3.9).

`finality` is one of `"finalized"`, `"justified"`, `"canonical"`,
`"not_canonical"`. There is also a boolean `finalized` — that is the field
your credit rule (§5) should read.

`version` is the raw header magic `0xB10C0005` = 2970353669, **not** `4`. A
client that recomputes a block id must hash this value verbatim.

`height` may be `null`.

Headers give you the chain's shape. Balances and outputs should be read from
the UTXO set (§3.3–3.6), which is exact and needs no block traversal.

---

## 4. Addresses and `script_hash`

Balance and UTXO methods take a **`script_hash`**: exactly 64 hex characters,
32 bytes. **No RPC method accepts a `bloch1q…` address** — there is no
`validateaddress` on this chain and `getnewaddress` is a permanent refusal. You
derive the `script_hash` yourself.

### 4.1 The address format is not bech32

Despite the `bloch1q` prefix, this is **not bech32** and a bech32 decoder will
not read it. There is no bech32 charset and no BCH checksum. The scheme is:

```
"bloch1q" ‖ hex(20-byte hash) ‖ hex(4-byte checksum)
checksum = SHA3-256(SHA3-256(hash20))[..4]
```

So the prefix is followed by **48 hexadecimal characters**: 40 for the hash and
8 for the checksum. (Testnet prefix is `bloch1t`.)

### 4.2 Deriving `script_hash` from an address

The previous revision said "take the 20 bytes that follow the `bloch1q`
prefix". Implemented literally that produces a wrong `script_hash`, because
what follows the prefix is 48 hex characters, not 20 bytes. The correct rule:

1. Strip the `bloch1q` prefix.
2. Take the **first 40 hex characters** and hex-decode them to 20 bytes.
3. Verify the remaining 8 hex characters against
   `SHA3-256(SHA3-256(hash20))[..4]`.
4. **Right-pad the 20 bytes with zeroes to 32 bytes.** That is the
   `script_hash`.

### 4.3 The zero-extension is for carried balances only

An important scope limit the previous revision did not state.

There are two lock forms on this chain:

- **carried** (Genesis-3 balances brought over by the snapshot): the first 20
  bytes match and the last 12 are zero — a 160-bit lock;
- **native** Genesis-4 outputs: the full 32 bytes of `SHA3-256(pubkey)` — a
  256-bit lock.

The `bloch1q…` derivation above produces the *carried* form. It is a
deliberately accepted weaker tier, not an oversight, and it is what you get if
you hand out zero-extended `script_hash` values as deposit addresses. If your
risk policy distinguishes 160-bit from 256-bit locks, this is the paragraph
that matters, and you should talk to us before choosing.

### 4.4 Echo check

Every balance and UTXO response echoes back the `script_hash` it used, and each
UTXO element carries its own. Compare it to what you sent — it is a genuine
round-trip check against truncation and transposition, and it costs nothing.

---

## 5. Deposits

Genesis-4 is a UTXO chain and the UTXO set is queried directly and exactly.
Deposit detection is a poll of the address you issued — there is no txid index
to scan and no block traversal to get right:

1. **`getbalance [script_hash]`** — cheap, exact, true `utxo_count`.
2. When it moves, **`getutxos [script_hash, limit]`** — which outputs arrived,
   with `txid`, `vout` and `value_sat`.
3. **`gettxout [txid, vout]`** — confirm an individual output.

**Address strategy:** one address per user, or per deposit. §3.4 makes this
load-bearing rather than merely tidy: `getutxos` has no cursor, so an address
that passes 1,000 outputs cannot be fully enumerated. Keep each address under
1,000 outputs and one call always returns the complete set.

### 5.1 Settlement

| Stage | Signal | Action |
|---|---|---|
| Accepted | `sendrawtransaction` → `accepted:true` | in this node's mempool |
| Included | output visible via `gettxout` / `getutxos` | in a block |
| **Final** | `getchaininfo.finalized.epoch` ≥ that block's epoch | **credit** |

Finality is explicit and published in every `getchaininfo` response — you do
not estimate it from a confirmation count, and there is no `confirmations`
field to misread.

**Credit on `finalized`.** Included is not settled: a block that is canonical
now can be reorganised, and only finalisation is the cryptographic guarantee.

### 5.2 How long finality actually takes

Finalisation happens at epoch boundaries, so the floor is set by where in an
epoch your transaction landed, and the realistic figure is **2–3 epochs
(32–48 minutes)** from inclusion, not the "1–2 epochs" the previous revision
gave. Under degraded participation it is unbounded — see §5.3.

Size your customer-facing SLA off the observed distribution, not off the floor,
and treat `finalized` as the only signal. If you need a faster provisional
credit, take it against `finality: "justified"` with your own risk limit and
know that you are taking reorg risk to do it.

### 5.3 `finalized` is not currently a network-unique value — read it from two nodes

This is the most important risk disclosure in this document and the previous
revision did not carry it at all.

**Read the finalized checkpoint from at least two independent nodes and require
them to agree before you credit.** Our own public RPC front end does exactly
this internally — it refuses a read unless two nodes concur — and an integrator
crediting from a single node has weaker assurance than we give ourselves.

> **Caveat added 2026-09-01, and it bounds the rule above.** "Two independent
> nodes" is only worth what the independence is worth, and today **that is not
> checkable — by you or by us.**
>
> The rule assumes the two nodes you poll are two different things. Nothing on
> the wire establishes that. No node deployed today exposes any version method:
> `getcapabilities`, `getbuildinfo` and `getversion` all answer `-32601` on both
> of our public archivals (measured 2026-09-01). And that `-32601` is not itself
> evidence of anything, which is the sharper half of the finding — **the
> published `g4-node-20260901` binary does not contain `getcapabilities` in its
> source at all**, so a node running the current release and a node running
> something years older give the identical answer. The observation is consistent
> with every generation and distinguishes none.
>
> So the two-node rule we gave you is, as of this revision, **unfalsifiable over
> the RPC**: there is no query whose result could show that your two nodes are
> the same build, and therefore none that could show the rule is being satisfied.
> Two nodes on one build are two copies of one opinion — they agree with each
> other by construction, and would go on agreeing while both were wrong.
>
> Until `getbuildinfo` (§3.1.1) ships and you can compare `build_commit` and
> `gates_digest` across the nodes you poll, prefer **one of our archivals plus a
> node you run yourself** over two of ours: you at least know the provenance of
> one of them. Treat agreement between two endpoints you cannot tell apart as
> weaker evidence than it looks. This does not weaken §5.4's separate warning:
> two nodes still do not protect you from a finality rewind, because both rewind
> independently.

Here is why, precisely.

Finalisation is Casper-style: a checkpoint is justified when attestations
covering it reach **two thirds of the active stake**, and finalised by
consecutive justification. The denominator that "two thirds" is measured
against is **leak-adjusted**: stake belonging to validators that have not been
heard from is subtracted, which is what lets a partitioned majority keep
finalising.

The problem is what bounds that subtraction, and today nothing does.
`FinalityState::leaked` has exactly one write path — accrual — with **no decay,
no reset and no removal**. The denominator therefore shrinks monotonically and
never comes back. Once enough stake has leaked, a handful of validators — one,
in the limit — hold two thirds of what remains and can finalise alone. That is
not hypothetical: on **2026-08-24 three nodes finalised epoch 986 under three
different roots**, and no amount of arriving blocks reunified them.

Two mitigations exist in the binary and **neither is reachable**:

| Mitigation | Constant | State |
|---|---|---|
| Leak recovery — the accumulator drains on healthy epochs | `INACTIVITY_LEAK_RECOVERY_QUOTIENT = 16` | `[INERT]` |
| Quorum-denominator floor — the denominator may not fall below **half** the unleaked total | `MIN_QUORUM_DENOMINATOR_NUM/DEN = 1/2` | `[INERT]` |

Both sit behind `LEAK_RECOVERY_ACTIVATION_EPOCH = u64::MAX`. They are gated
because the floor decides which checkpoints justify, justification is committed
into the state root, and applying either rule to historical epochs makes a node
compute a root the existing headers do not carry — which stops its replay dead.
Arming them is a flag day with a fleet rebuild, not a config change.

Separately, whether the leak reaches the **duty roster** — so a written-off
validator also stops winning proposer draws — is `[SCHEDULED]` at
`LEAKED_ROSTER_ACTIVATION_EPOCH = 1400` and is not in force yet.

### 5.4 `finalized` is also not a latch — it can move backwards

A second, independent defect, and you must plan for it separately because the
mitigation for §5.3 does not cover it.

Within the finality gadget itself the finalized checkpoint is monotone — it
will only ever be replaced by a strictly higher one. **But the node does not
own that gadget across a reorg.** A reorg replaces the whole committed state
with an ancestor's, and the adopt path performs no comparison of the incoming
finalized checkpoint against the outgoing one. Fork choice walks from the
*justified* root, not the finalized one, and nothing prunes branches by
finalized checkpoint.

The practical consequence: a reorg down to the justified root installs a state
whose finalized epoch predates the one the node was reporting. A block that
`getblockbyslot` returned with `"finalized": true` can subsequently report
`"justified"` or `"canonical"`. `finalized_height` can go down.

**Two independent nodes do not fix this one.** Both can rewind, and they can
rewind independently. Agreement between them protects you against §5.3's
divergence, not against §5.4's rewind.

### 5.5 What to do about §5.3 and §5.4

- **Credit on `finalized`, and require two independent nodes to report the same
  finalized root at the same epoch.** Disagreement is a hold condition, not a
  retry.
- **Re-verify before releasing funds.** Do not treat a single `finalized: true`
  reading as durable. Re-read the output with `gettxout` immediately before you
  act on it, and treat a block that has stopped being finalized as a hold.
- **Add a depth margin.** Credit at a fixed number of epochs *past* finality
  rather than at the finality boundary itself. The margin is what absorbs a
  rewind, and it is the only mechanism here that does.
- **Alert on `finalized.epoch` not advancing, independently of height.** Block
  production and finalisation are separate: heights advance, `getblockbyslot`
  keeps answering, the node looks healthy, deposits stop being creditable.
- **Alert on `finalized.epoch` moving backwards**, and on a finalized root at a
  given epoch changing. Neither should happen; both do.
- **Do not read a rising `finalized` as recovery.** Because the denominator
  shrinks and has no floor, a partitioned minority reaching two thirds of what
  is left will finalise its own branch. `finalized` advancing again is not
  evidence the network reunified.
- Have a manual hold procedure. A stall does not currently clear itself.

We would rather you learned this from us than from your reconciliation.

---

## 6. Withdrawals

`sendrawtransaction [hex]` broadcasts an already-signed transfer. See §3.7 for
what comes back — in particular, not a txid.

### 6.1 Two transfer formats

| Tag | Format | Verification charged | Status |
|---|---|---|---|
| `0x01` | V1 | one hybrid verification **per input** | `[LIVE]` |
| `0x06` | V2, deduplicated witness | one hybrid verification **per distinct owner key** | `[LIVE]` since epoch 800 |

V2 is active (`TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH = 800`, passed) and is
what you should build. It carries a witness table of owner keys plus 40-byte
inputs that index into it, so an exchange hot wallet spending many of its own
coins signs **once**, not once per coin.

The witness table must be **strictly ascending by public-key bytes** and every
entry must be referenced by at least one input. Both are consensus rules, not
lint: an unsorted table is `WitnessTableNotCanonical` and an unused entry is
`WitnessKeyUnused`.

### 6.2 Transaction sizing — correcting the "815 inputs" figure

**The previous revision's ceiling of 815 inputs was wrong, and the formula
behind it described a transaction that cannot exist.** It printed:

```
gas(n) = 5,000 + (8,649 + 40n) × 16 + 72,748 × n
n = 815 → 59,954,604   of 60,000,000
```

The arithmetic is right and the model is not: it takes the **byte** term from
V2 (one witness table entry plus 40 bytes per input — a *single-owner*
transfer) and the **verification** term from V1 (one hybrid verification per
*input*). No transaction has both shapes.

The actual rule, from `Transition::apply_transfer_v2`:

```
gas = 5,000 + tx_bytes × 16 + 72,748 × (number of DISTINCT OWNER KEYS)
```

Two consequences:

- **If your inputs share one owner key — the normal exchange case — the
  verification term is 72,748 × 1.** An 815-input single-owner transfer uses
  under a quarter of the gas cap. The binding constraint is the 524,288-byte
  payload cap, not gas, and the real ceiling is roughly **an order of magnitude
  above 815**.
- **If every input had a distinct owner, 815 could not be encoded at all.** 815
  witness entries is about 6.8 MB against a 524,288-byte cap. The true
  distinct-owner ceiling is around 62 — essentially the same as V1, which is
  the point: deduplication buys nothing when there is nothing to deduplicate.

**Do not use a constant as your ceiling.** Falcon-1024 signatures are variable
length, so the encoded size of a transfer is not a function of its input count.
Build the transaction, measure the bytes you actually produced, and check:

```
encoded_bytes            ≤ 524,288                                (payload cap)
5,000 + bytes×16 + 72,748×owner_keys ≤ 60,000,000                 (gas cap)
```

A planner that measures is correct in both directions and stays correct when a
constant moves. Pinned by
`book_v2_input_ceiling_is_bytes_bound_not_the_published_815`.

### 6.3 Serialise withdrawals

Coin selection reads the current UTXO set, so a batch built from one snapshot
selects the same coins more than once. Send one transfer, wait for inclusion
(~30 s), then build the next — or track committed outpoints locally and exclude
them from selection. The reference wallet does the latter and refuses a
transfer whose inputs are already committed, before signing.

*(The previous revision gave a per-stage ceiling of "20,000,000 BLCH". That is
not a protocol constant and appears nowhere in consensus code — it was a
reference-wallet policy figure. Ignore it and use §6.2.)*

### 6.4 Pricing — where a stale number becomes a rejection

**A transfer is valid at exactly one price point.** The fee is never declared
by the transaction: it is derived from the transaction's class and declared
byte count, priced at the block's committed base fee, and the difference
between inputs and outputs must equal it exactly.

```
sum(inputs) == sum(outputs) + fee          checked with !=
fee         == base_fee_sat + priority_fee_sat
```

You cannot overpay. An overpaying transfer is `ValueNotConserved` exactly like
an underpaying one — sweeping a remainder to the proposer would be a fee nobody
set.

Practically:

1. Read `next_base_fee_millisat_per_gas` (from `getmempoolinfo` or
   `getchaininfo`) **immediately before building**.
2. Compute the fee, bake it into the change output.
3. Broadcast promptly.

**How stale is too stale.** The base fee moves by at most ±1/8 per block, and
only blocks move it — skipped slots leave the price unchanged. So a quote is
off by at most a factor of (9/8)^k after k blocks. A quote more than one block
old is a rejection risk; two blocks is a coin flip in a busy period. The floor
is 10 millisatoshi per gas and is absorbing — the price cannot fall below it.
Pinned by `book_price_staleness_is_bounded_at_one_eighth_per_block`.

**The tip field the previous revision never mentioned.** A transfer carries
`tip_millisat_per_gas` on the wire, and the settled fee is base **plus** tip.
Set it to zero unless you have a reason not to. If you set it non-zero, note
that the two parts are settled and **rounded up independently**:

```
fee = ceil(gas × base / 1000) + ceil(gas × tip / 1000)
```

A wallet that folds the prices together and divides once
(`ceil(gas × (base+tip) / 1000)`) can be one satoshi short, and one satoshi
short is a hard rejection. Pinned by
`book_fee_is_base_plus_tip_each_rounded_up_separately`.

### 6.5 Refusal is not permanent — but `-32008` is

Distinguish two different things that both look like "my transaction was
refused":

- **`-32008 TX_REFUSED` at the RPC layer** means the node judged those exact
  bytes invalid. Never resubmit them; rebuild.
- A transfer refused because it was priced against a base fee that has since
  moved is refused *about the chain state at the time*, not about the bytes.
  Repricing and re-signing is the correct response.

`[UNRELEASED]` — a mempool rejection cache with an expiring bar is on branch
`canario/cache-recusa` and is **not in the released binary**. See §10.

---

## 7. Running a node

Any integrator can run their own node and read from it directly.

### 7.1 The binary is `bloch-pos`

The previous revision called it `bloch-pos-quatro`. That name does not exist
anywhere; the binary target is **`bloch-pos`** and copying the old invocation
gives `command not found`.

### 7.2 Requirements

- The node binary — use the build the network runs
- `mainnet.manifest` (~247 KB)
- `carryover.tsv` (~55 MB, 452,726 opening outputs) — required, because the
  mainnet manifest commits to it
- 8 GB RAM, 2 cores, 20 GB disk per node

Replay is single-threaded and pins one core; allocate cores per node, not per
box.

### 7.3 Run

```
bloch-pos run \
  --data-dir  /var/lib/bloch/data \
  --genesis   /var/lib/bloch/mainnet.manifest \
  --carryover /var/lib/bloch/carryover.tsv \
  --transport devnet \
  --listen 19100 --listen-addr 0.0.0.0 \
  --peers <ip:port,…> \
  --rpc-port 16400 --rpc-bind 127.0.0.1
```

`--data-dir` and `--genesis` are required; `--listen` is required under
`--transport devnet`; `--carryover` is required against the mainnet manifest.

**The argument parser does not reject unknown flags.** A typo is silently
ignored and the default silently applies. Check your unit file against
`bloch-pos run --help`, not against this document.

**Ports — correcting the previous revision.** It said "P2P uses the 19xxx
range, RPC the 16xxx range". That is not what the code does:

| | Default |
|---|---|
| `--rpc-port` | **16310** |
| libp2p P2P listen | **16400** |
| devnet `--listen` | no default — you must pass one |

19xxx is a convention in our local devnet scripts, not a protocol default. Note
that the example above puts RPC on 16400, which is the *libp2p P2P default* —
harmless under `--transport devnet`, but if you later switch transports you
will get a bind conflict. Pick your ports deliberately.

**`--transport devnet` authenticates nothing.** It is a TCP full mesh with no
authentication, no admission control and no relay logic. If you bind it to a
routable address, as the example does, you **must** firewall it to your known
peer addresses.

### 7.4 Bootstrap

Copy `blocks.log` (and optionally `meta.bin` and `ws_latest.bin`) from a
current node's data directory (~202 MB today) and start. Replay of 15,000
blocks completes in about 4 minutes at 52 blocks/s. `meta.bin` and
`ws_latest.bin` are both recreated if absent, and both are refused if they came
from a different network — so copying them is safe but not required.

**Two things to delete from a copied data directory, which the previous
revision did not warn about:**

- **`p2p_identity.bin`** — a copied node keeps the donor's libp2p PeerId. Under
  `--transport devnet` it is never read, so the problem is latent; it becomes
  real the moment you switch to libp2p. Delete it.
- **`validator.key`** — if the donor was a validator, copying this makes your
  node a **second signer for the same validator index**. That is equivocation,
  and it is slashable. There is no safe version of it. Copy the three files
  named above and nothing else.

**"Syncing from genesis is also supported" was wrong for the transport this
document recommends.** Over `--transport devnet`, cold sync does not complete,
and the failure is silent: the node reports a head, a height and a state root
as though it were caught up. Reproduced 2026-08-14 at height 556 against a
network at 1,511, with no error raised. Bootstrap from a copied `blocks.log`,
and verify with §7.5 before you trust the node.

### 7.5 Observer mode

A data directory with **no `validator.key`** starts in observer mode: it
applies every block, serves reads, and signs nothing. This is the right mode
for an exchange and it is not silent — the node prints `observer mode: no
keystore in …` at startup and reports `observer (no keystore, signs nothing)`
in its banner.

There is no flag. The presence of the file is the switch, which is why §7.4
tells you to delete it.

### 7.6 Confirm your node agrees with the network

Compare `state_root` at the same height against a second node:

```
your node  h=15130  root=c2ee4935…
reference  h=15130  root=c2ee4935…
```

Identical roots at identical height is agreement. Also check `behind_by_slots`
— 0 or 1 is current.

**Do this against two independent references, not one.** A single reference
that has itself stopped will agree with you about a stale height and tell you
nothing. Divergent nodes on this chain do not announce themselves: they answer
RPC normally and report a plausible head.

### 7.7 Supervise it

```ini
[Unit]
Description=Bloch Genesis-4 node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=bloch
ExecStart=/usr/local/bin/bloch-pos run --data-dir /var/lib/bloch/data …
Restart=always
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

---

## 8. Validators

Genesis-4 runs with **64 active validators**, active since genesis. The 64 is
the population of the genesis manifest, **not a protocol constant** — there is
no constant that fixes it. (`params::COMMITTEE_SIZE = 128` and
`SLOT_SUBCOMMITTEE_SIZE = 8` are dead names from a superseded sampled-committee
design; the node reads neither. Do not size anything from them.)

Committees are a **true partition** of the active set across the 32 slots of an
epoch — shuffled, cut into 32 contiguous chunks — so every validator has a duty
in exactly one slot of every epoch. At 64 validators that is 2 seats per slot
committee.

**Stake figures.** Genesis active stake is **160,000,000,000,000 sat**
(64 × 2,500,000,000,000). The 6,177,107,126,034,566 sat quoted in §3.2 is a
**live reading** taken on 2026-08-26 — it is genesis stake plus 1,101 epochs of
reward accrual, and it grows every epoch. Treat it as a measurement with a
timestamp, never as a parameter.

### 8.1 Validator entry does not exist in the released binary

The previous revision said entry "activates on a scheduled flag day". **There
is no such flag day**, and "scheduled" implied a constant a reader could look
up. There is none — §1.2 lists every gate in `params.rs` and no gate concerns
validator entry.

What is actually true of `main` @ `e4083f9`:

- `staking::validate_deposit` is public, fully tested, and **has no production
  call site**. Neither does `validate_exit` or `validate_withdrawal`, and the
  `StakingLifecycle` trait that declares them has **no implementor anywhere in
  the workspace**. This is the integrator's first finding, and it is correct.
- `unlock_epoch` appears **nowhere in `bloch-pos-committee`**. This is their
  second finding, and it is correct. The field exists in the genesis manifest
  (`bloch-pos-node/src/genesis.rs`), where it is documented as making vesting
  consensus-enforced — but the enforcement is not in the committee crate on
  this branch.
- `ACTIVATION_DELAY_EPOCHS = 8` and `MAX_ACTIVATIONS_PER_EPOCH = 4` are
  enforced on a live code path at every epoch boundary, but their input queue
  has no reachable writer, so neither has ever gated anything.
- **No staking transaction can be submitted through any public interface.** The
  node's mempool refuses `Deposit`, `Exit` and `Delegate` at admission.
- **That refusal is node-local policy, not a consensus rule.** The validator set
  is therefore held fixed by operator policy rather than by the protocol. The
  specification's deposit rules — proof of possession, bounds, input
  eligibility — are written and tested but are not on the path that decides
  what a block may contain.

The practical summary for a risk team: **treat the validator set as fixed and
externally administered.** It is not open to entry, its stability does not rest
on a consensus rule, and the lifecycle described in the protocol specification
is not the lifecycle the released binary enforces. If your listing assessment
turns on validator-set integrity, raise it with us directly — there is more to
say than belongs in a document.

`[UNRELEASED]` — the funded bonding work exists on branch `wt/signed-exit-wire`
(and siblings), where the deposit path routes through
`staking::validate_deposit_fields` from the transaction dispatch and the
committee carries `unlock_epoch` including the enforcement
`if entry.unlock_epoch > self.epoch`. **None of that is in the binary the
network runs.** It has no flag day, and we will not give it a date here.

If validator participation is part of your integration plan, treat it as not
yet available and talk to us about timing.

---

## 9. What this document does not cover

Stated so that silence is not read as assurance:

- **Hardware custody.** Not possible today (§2).
- **A transaction id.** There is none, and no txid→block index (§3.7).
- **Bulk historical scanning.** No `getvalidators`, no supply methods, no
  cursor on `getutxos`. Reconstructing history from the RPC surface is not
  something we have made work.
- **Validator entry and exit** (§8).
- **Decentralisation.** Stake is concentrated and the validator set is the
  genesis set. We are not going to characterise that as decentralised here, and
  you should form your own view before listing.

---

## 10. Divergence: released binary vs unreleased branches

The reason two of the three audit findings existed. Anything in this table is
**not in the binary the network runs**, regardless of how complete it looks in
the repository.

| Capability | On `main` @ `e4083f9` | Branch | Book section |
|---|---|---|---|
| Funded validator bonding — deposit reaches the transition via `staking::validate_deposit_fields` | absent; `validate_deposit` has no call site | `wt/signed-exit-wire`, `wt/exit-churn-limit`, `lead/delegation-off-explicit` | §8.1 |
| `unlock_epoch` enforcement in the committee (`if entry.unlock_epoch > self.epoch`) | absent from `bloch-pos-committee` entirely | same | §8.1 |
| Mempool rejection cache — `REJECTION_TTL_SLOTS = 128` slots (≈ 64 min) | absent | `canario/cache-recusa` | §6.5 |

### 10.1 The rejection cache, since you will read about it

`[UNRELEASED]`. On `canario/cache-recusa`, a transaction the block transition
refuses is removed from the mempool *and barred from re-entering* for
`REJECTION_TTL_SLOTS = 128` slots — 128 × 30 s ≈ **64 minutes**. Without the
bar, peers still holding the transaction re-offer it and it walks straight back
in; this was measured on the live chain on 2026-08-30, a node proposing with
`mempool 0` in the log line and still holding 21 of the same transactions 383
slots later.

**The bar expires, and that is a design decision, not an oversight.** Refused
bytes are not permanently invalid. A transfer refused because it was priced
against a base fee that has since moved becomes valid again when the price
comes back, and a permanent ban would turn a transient pricing error into a
dead transaction — coins quietly unspendable through a node that will never
reconsider. So: if your transaction is barred, you may retry after the TTL.

Note this is a *different* instruction from `-32008 TX_REFUSED` (§3.9), which
says never resubmit those bytes. Do not conflate them.

Behaviour on that branch is pinned by
`a_refused_transaction_does_not_come_back_through_gossip` (which asserts the
bar lifts at exactly `slot + REJECTION_TTL_SLOTS`) and
`the_rejection_cache_is_bounded`. When it merges, this section moves to §6 and
its pin moves into `integration_book_claims.rs` in the same commit.

---

## 11. Integration checklist

- [ ] ~~Call `getcapabilities` at connect time and branch on it, not on §3~~
      **WITHDRAWN 2026-09-01 — this call fails on every node deployed today**
      (`-32601` on both public archivals and all nine of our upstreams; the
      method is not in the published `g4-node-20260901` binary at all). Branch
      on §3's tables until §3.1 says otherwise. Do not treat the `-32601` as a
      fault on your side.
- [ ] Parse all amounts as big integers from decimal strings
- [ ] Derive `script_hash` per §4.2 — **48 hex characters follow the prefix**,
      take the first 40 — and verify it against the echo in the first response
- [ ] Handle `-32007 SLOT_EMPTY` as normal, not as a fault
- [ ] Handle `-32008 TX_REFUSED` as terminal and `-32003 MEMPOOL_FULL` as
      retryable — never the reverse
- [ ] Do not read `result.txid` from `sendrawtransaction`; there is none
- [ ] Poll `getbalance`; expand with `getutxos [script_hash, limit]` — no
      `offset`, default limit 100, max 1,000, no cursor
- [ ] Keep deposit addresses under 1,000 outputs
- [ ] Credit on `finalized` from `getchaininfo`; budget 2–3 epochs
- [ ] Require **two independent nodes to agree** on the finalized root before
      crediting — disagreement is a hold, not a retry (§5.3)
- [ ] Check that those two nodes are actually two: compare `build_commit` and
      `gates_digest` from `getbuildinfo` (§3.1.1) once it ships. **Until then
      the two-node rule is unfalsifiable over the RPC** — no deployed node
      answers any version query, and the `-32601` it gives you is also what the
      current release gives, so it distinguishes nothing. Prefer one of ours
      plus one of yours (§5.3)
- [ ] Do **not** read matching `gates_digest` values as "these nodes agree".
      The digest covers the consensus constants, not the behaviour behind them
      (§3.1.1)
- [ ] Credit at a **depth margin past** finality, not at the boundary, and
      re-verify with `gettxout` before releasing funds — `finalized` can move
      backwards and two nodes do not protect you from that (§5.4)
- [ ] Alert on `finalized.epoch` stalling **independently of height**, and on it
      moving backwards
- [ ] Do not read a rising `finalized` as evidence the network reunified (§5.5)
- [ ] Serialise withdrawals, one inclusion at a time
- [ ] Read `next_base_fee_millisat_per_gas` immediately before each build; treat
      a quote older than one block as stale
- [ ] Set `tip_millisat_per_gas` explicitly (zero unless you mean otherwise) and
      round base and tip **separately**, each up
- [ ] Size transfers by **measuring** encoded bytes against 524,288 and gas
      against 60,000,000 — do not use a fixed input count
- [ ] Run your own node in observer mode, supervised, `bloch-pos` binary
- [ ] Delete `p2p_identity.bin` and `validator.key` from any copied data dir
- [ ] Check `state_root` agreement against **two** independent references

---

## 12. Reference

- Claim-by-claim audit behind this revision —
  [`INTEGRATION-BOOK-AUDIT-2026-08-31.md`](INTEGRATION-BOOK-AUDIT-2026-08-31.md)
- How a consensus-parameter change reaches you —
  [`CONSENSUS-CHANGELOG-DISCIPLINE.md`](CONSENSUS-CHANGELOG-DISCIPLINE.md)
- Designed RPC surface, including methods scheduled but not shipped —
  [`../specs/BLOCH-RPC-V4.md`](../specs/BLOCH-RPC-V4.md)
- Carryover ledger construction — [`../CARRYOVER.md`](../CARRYOVER.md)
- Protocol specification — [`../SPEC.md`](../SPEC.md)

Chain figures measured 2026-08-26 at height 15,146, epoch 1,101.
Code claims verified against `main` @ `e4083f9` on 2026-08-31 and pinned by
`crates/bloch-pos-committee/tests/integration_book_claims.rs`.
