# Bloch Genesis-4 — Exchange & Integrator Guide

**Chain:** Bloch Genesis-4 · **Ticker:** BLCH · **Consensus:** Proof of Stake
**Status:** live mainnet · **This document describes the implemented surface**, verified
against a live archival node.

For the designed future surface — methods planned but not yet shipped — see
[`../specs/BLOCH-RPC-V4.md`](../specs/BLOCH-RPC-V4.md). Everything in *this* document is
available today.

---

## Quick start

```bash
curl -s -X POST https://<your-node>:16400 \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getchaininfo","params":[]}'
```

```json
{"jsonrpc":"2.0","id":1,"result":{
  "height":15146,"slot":35247,"epoch":1101,
  "finalized_height":15069,
  "justified":{"epoch":1100,"root":"…"},
  "finalized":{"epoch":1099,"root":"…"},
  "validators":{"total":64,"active":64},
  "total_active_stake_sat":"6177107126034566",
  "base_fee_millisat_per_gas":"10",
  "mempool":1,"blocks_known":15146,"behind_by_slots":0}}
```

Three numbers matter for integration: `finalized` (settlement), `behind_by_slots`
(is your node current), and `base_fee_millisat_per_gas` (what the next block charges).

---

## 1. Chain parameters

| | |
|---|---|
| Ticker | BLCH |
| Decimals | 8 — 1 BLCH = 100,000,000 sat |
| Slot time | 30 seconds |
| Epoch | 32 slots (16 minutes) |
| Settlement | finality at epoch boundaries, typically 1–2 epochs |
| Ledger | eUTXO, outputs keyed `(txid, vout)` |
| Signatures | ML-DSA-65 ‖ Falcon-1024 (post-quantum hybrid) |
| Validators | 64 active |
| Block payload | 524,288 bytes |
| Block gas | 60,000,000 |
| Genesis carryover | 452,726 outputs · 18,146,400,000 BLCH |

**Amounts are decimal strings in every response.** Balances exceed 2^53, so parse them as
big integers. This is deliberate: it makes satoshi-exact accounting the default.

---

## 2. Custody

Signing uses a post-quantum hybrid scheme, ML-DSA-65 combined with Falcon-1024. Keys are
held and used in software; the reference implementation is a WASM signing core that runs
in-process, so an integrator's key material never leaves their own boundary and never
transits an RPC.

Falcon signatures are variable-length and hedged — the same inputs produce different valid
bytes each time, with the same transaction identity. Sign once per transfer and broadcast
the stored bytes on any retry.

We work directly with integrators on custody design. Contact us before starting.

---

## 3. RPC reference

JSON-RPC 2.0 over HTTP POST. Parameters are positional arrays.

### `getchaininfo` → chain head and settlement state

No parameters. Returns the fields shown in Quick start.

### `getblockbyslot [slot]` → block header

```json
{"slot":35242,"height":15141,"block_id":"…","parent":"…",
 "proposer_index":55,"timestamp":…,"epoch":1101,
 "state_root":"…","body_root":"…",
 "tx_count":0,"attestation_count":2,
 "justified_root":"…","finalized_root":"…","finality":…,
 "randao_mix":"…","randao_reveal":"…","version":…}
```

Headers give you the chain's shape: proposer, timing, roots, transaction and attestation
counts, and the finality view as of that block. Balances and outputs are read from the
UTXO set (§4), which is exact and does not require block traversal.

### `getbalance [script_hash]` → authoritative balance

```json
{"script_hash":"…","balance_sat":"0","utxo_count":0}
```

`utxo_count` is a true total. This is the method to poll.

### `getutxos [script_hash, limit, offset]` → individual outputs

```json
{"script_hash":"…","total":0,"returned":0,"truncated":false,"utxos":[
  {"txid":"…","vout":0,"value_sat":"4000000000000","at_slot":…}]}
```

Returns up to 1,000 outputs per call. `getbalance.utxo_count` is the reference total;
keep deposit addresses below that and enumeration is complete in one request.

### `listunspent [script_hash, …]` → same shape as `getutxos`

### `gettxout [txid, vout]` → is this specific output still unspent

```json
{"txid":"…","vout":0,"unspent":true,"utxo":{…},"at_slot":…}
```

Exact, single-output answer. This is the primitive for confirming an individual payment.

### `sendrawtransaction [hex]` → broadcast

```json
{"accepted":true,"txid":"…"}
```

`accepted` means the node took the transaction into its mempool.

### `getmempoolinfo` → pending state and next price

```json
{"size":1,"max":4096,"bytes":338487,"next_base_fee_millisat_per_gas":"10"}
```

`next_base_fee_millisat_per_gas` is the price the next block will charge. Read it before
building a transfer.

### Error codes — the decision table

Branch on the **code**, and on `error.data` where it exists. Never on the message:
codes and `data` are the contract, messages are prose and get reworded.

| Code | Name | Terminal? | What to do |
|---|---|---|---|
| `-32700` / `-32600` / `-32601` / `-32602` | parse / invalid request / method not found / invalid params | **Terminal** | Fix the client. Never retry unchanged. |
| `-32603` | internal error | Retryable | A bug in the node. Retry once, then report it. |
| `-32000` | `BLOCK_NOT_FOUND` | **Depends — read `data.canonical`** | `true`: the block is canonical and this node pruned it. It exists. **Fetch it from an archival — do not conclude the block is absent.** `false`: this node cannot say whether it ever existed (unsynced, pruned, other branch, or never was). |
| `-32001` | `VALIDATOR_NOT_FOUND` | **Terminal** | The index is not in the committed registry. |
| `-32002` | `TX_DECODE_FAILED` | **Terminal** | The bytes are not a canonical transaction. Rebuild; never resubmit these bytes. |
| `-32003` | `MEMPOOL_FULL` | Retryable | Capacity only — the transaction was **not** judged invalid. Back off and resubmit the same bytes. |
| `-32004` | `NODE_UNAVAILABLE` | Retryable | The consensus thread did not answer. Retry, or fail over to another node. |
| `-32005` | `NO_TRANSACTION_INDEX` | **Terminal** | This build has no txid lookup. Do not retry; see §"There are no transaction ids". |
| `-32006` | `NO_WALLET` | **Terminal** | The node mints no keys and no addresses. Generate them yourself. |
| `-32007` | `SLOT_EMPTY` | **Depends — read `data.settled`** | `true`: the slot is behind the head and settled empty (a missed proposal). **Advance.** `false`: this node has not reached the slot. **Do not advance — it may still fill.** |
| `-32008` | `TX_REFUSED` | **Terminal** | Judged on its merits — an unverifiable signature, no inputs, no outputs, a format behind a flag day. Retrying these bytes cannot help. |
| `-32009` | `TX_BARRED` | **Retryable, and it says when** | This node's proposer watched the transition refuse it against a *state*. Wait for the head to pass `data.until_slot`, then resubmit the **same** bytes. See the two remedies below. |

#### `-32008` vs `-32009`: the split, and why you may not see `-32009` yet

These were **one code**. Until the split, `-32008` carried both the terminal verdict and
the retryable bar, separable only by the English in `message` — which is exactly the
parse-the-prose failure a code-based contract exists to prevent. A withdrawal retry loop
branching on `-32008` alone was wrong half the time, in whichever direction hurt:
abandoning a transfer that would have landed, or hammering bytes that never will.

`-32008` **kept the terminal half**. If you are already integrated against it as "give
up", that belief was right half the time before and is right always now. `-32009` is a
code you will not recognise until you add it; your default branch should surface it to a
human rather than act on it, which is the safe direction while you update.

#### A bar has two remedies, and `data` tells you which

`-32009` fires for two different reasons and only one of them is fixed by waiting:

1. **Wait.** The transfer spends an output this branch does not have — built against a
   node on another branch, or its parent has not landed. Resubmit after `data.until_slot`.
2. **Reprice.** Conservation is a **strict equality** (`spent == created + fee`) and the
   base fee belongs to the *block*, not to the transaction. Outputs built at an old price
   cannot balance a new block, and no amount of waiting changes that. Rebuild the outputs
   against `data.next_base_fee_millisat_per_gas` (also on `getmempoolinfo`).

If you resubmit identical bytes and are barred a second time, you are looking at the
price, not at the clock.

#### The trap: a stale fee is accepted, then dropped in silence

A transfer priced against a stale base fee **passes admission** — `sendrawtransaction`
returns success, and it gossips across the mesh. The strict-equality check runs inside
block production, where the proposer drops it without telling anyone. There is no error
to catch.

Therefore: **confirmation must be positive, never the absence of an error.** A `200` from
`sendrawtransaction` means "admitted to a mempool", not "will confirm".

#### There are no transaction ids

`gettransaction` is refused by design (`-32005`), and `sendrawtransaction`'s `tx_hash` is
**node-local** — no other node, block or client agrees on it. Do not key anything on it.

A retry loop must key on **outpoint and balance**: poll `listunspent` / `getbalance` for
the destination `script_hash` and treat the appearance of the expected outputs as the only
confirmation. Positive evidence, from the eUTXO set, at a height you have read back.

---

## 4. Addresses and `script_hash`

Balance and UTXO methods take a **`script_hash`** — 32 bytes of hex.

Derive it from a `bloch1q…` address by taking the 20 bytes that follow the `bloch1q`
prefix and right-padding with zeroes to 32 bytes.

Every response echoes the `script_hash` it used. Compare it to what you sent as a
one-line integration self-check.

---

## 5. Deposits

Genesis-4 is a UTXO chain, and the UTXO set is queried directly and exactly. Deposit
detection is a poll of the address you issued:

1. **`getbalance [script_hash]`** — cheap, exact, gives a true `utxo_count`.
2. When it moves, **`getutxos [script_hash, limit, offset]`** — see which outputs arrived,
   with `txid`, `vout`, `value_sat` and the slot they landed in.
3. **`gettxout [txid, vout]`** — confirm an individual output.

This gives satoshi-exact crediting with no reorg-scanning logic, no block traversal, and no
dependence on an indexer staying in sync with the chain.

**Address strategy:** one address per user, or per deposit. Keeping each address under
1,000 outputs means a single `getutxos` call always returns the complete set.

### Settlement

| Stage | Signal | Action |
|---|---|---|
| Accepted | `sendrawtransaction` → `accepted:true` | in the mempool |
| Included | output visible via `gettxout` / `getutxos` | in a block |
| **Final** | `getchaininfo.finalized.epoch` ≥ that block's epoch | **not sufficient — see the note below** |

Finality is explicit on Genesis-4 and published in every `getchaininfo` response — you do
not estimate it from a confirmation count.

> **Do not credit on `finalized` alone.** An earlier revision of this page called that a
> cryptographic settlement guarantee. **It is not one**, and we are correcting it rather
> than waiting to be asked. What Genesis-4 offers today is *economic* finality under an
> assumption of healthy participation. Two defects, both demonstrated by test:
>
> 1. **The quorum denominator shrinks with no floor.** It is leak-adjusted
>    unconditionally; the floor and the recovery rule are written but gated behind
>    `LEAK_RECOVERY_ACTIVATION_EPOCH`, which is `u64::MAX`. A partitioned minority
>    holding 6.25% of stake has been shown to self-finalise once the absent majority
>    has leaked away.
> 2. **`finalized` is not a latch across a reorg.** Fork choice walks from the
>    *justified* root, and the state committed there already finalises two epochs below
>    the head — so the deepest cut the algorithm may legitimately propose, with no
>    invalid block and no misbehaving peer, is itself a finality rewind. Measured
>    repeatedly: finalized epoch 6 → 4 → 2 → 0 in three in-rules cuts.
>
> **Two nodes agreeing does not mitigate this.** Both can rewind independently.
>
> **What to do instead**, until this note is withdrawn: credit at **finalized + 3 epochs**
> (~48 minutes past finality), require **two independently operated nodes** to agree on
> the same finalized **root and epoch** — not the epoch alone — and **re-verify
> immediately before releasing funds**. The margin of 3 bounds the single-cut case with
> one epoch to spare. It does not bound a repeated ratchet: **no depth is provably safe
> today**, and we would rather say so than quote a number that sounds like one.
>
> This note is withdrawn when the finality latch ships and the denominator floor is
> armed. See `docs/decisions/LEAK-RECOVERY-ARMING-BRIEF.md` and
> `docs/decisions/FINALITY-LATCH-FORK-SAFETY.md`.

---

## 6. Withdrawals

`sendrawtransaction [hex]` broadcasts an already-signed transfer.

### Transaction sizing

Capacity is measured in **inputs**, not amount — the most one transfer moves is the sum of
its largest N coins:

| Format | Inputs per transfer |
|---|---|
| V1 | 61 |
| V2 | **815** |

The V2 figure follows from the block gas budget:

```
gas(n) = 5,000 + (8,649 + 40n) × 16 + 72,748 × n
n = 815 → 59,954,604   of 60,000,000
```

Use 815 as the V2 ceiling in any planner.

### Staged sending

Amounts above one transfer's capacity are sent in stages, one per block, each waiting for
the previous to be included. Per-stage ceiling is the lesser of available coins and
20,000,000 BLCH.

### Serialise withdrawals

Coin selection reads the current UTXO set, so a batch built from one snapshot selects the
same coins more than once. Send one transfer, wait for inclusion (~30 seconds), then build
the next — or track committed outpoints locally and exclude them from selection. The
reference wallet does the latter and refuses a transfer whose inputs are already committed,
before signing.

### Pricing

A transfer is valid at exactly one price point: the base fee is baked into the change
output. Read `getmempoolinfo.next_base_fee_millisat_per_gas` immediately before building,
and broadcast promptly.

---

## 7. Running a node

Any integrator can run their own node and read from it directly. Verified procedure:

### Requirements

- Node binary — use the build the network runs
- `mainnet.manifest` (~247 KB)
- `carryover.tsv` (~55 MB, 452,726 opening outputs)
- 8 GB RAM, 2 cores and 20 GB disk are sufficient for one node; more cores let several
  nodes replay concurrently

### Bootstrap

Copy `blocks.log`, `meta.bin` and `ws_latest.bin` from a current node's data directory
(~202 MB today) and start. Replay of 15,000 blocks completes in **4 minutes at 52
blocks/s**. Syncing from genesis is also supported.

Replay is single-threaded and pins one core; allocate cores per node, not per box.

### Run

```
bloch-pos-quatro run \
  --data-dir  /var/lib/bloch/data \
  --genesis   /var/lib/bloch/mainnet.manifest \
  --carryover /var/lib/bloch/carryover.tsv \
  --transport devnet \
  --listen 19100 --listen-addr 0.0.0.0 \
  --peers <ip:port,…> \
  --rpc-port 16400 --rpc-bind 127.0.0.1
```

P2P uses the **19xxx** range, RPC the **16xxx** range. Expose P2P; keep RPC on loopback
behind your own proxy.

A data directory with no keystore starts in **observer mode** — it applies every block and
serves reads without taking on consensus duties. This is the right mode for an exchange.

### Supervise it

```ini
[Unit]
Description=Bloch Genesis-4 node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=bloch
ExecStart=/usr/local/bin/bloch-pos-quatro run --data-dir /var/lib/bloch/data …
Restart=always
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

### Confirm your node agrees with the network

Compare `state_root` at the same height against a second node:

```
your node  h=15130  root=c2ee4935…
reference  h=15130  root=c2ee4935…
```

Identical roots at identical height is agreement. Also check `behind_by_slots` — 0 or 1 is
current.

---

## 8. Validators

Genesis-4 runs a committee of **64 validators**, active since genesis, with
6,177,107,126,034,566 sat of active stake. Committees are a partition of the active set
across the 32 slots of each epoch, so every validator has duties every epoch.

Validator entry opens with the eUTXO-funded bonding upgrade, which gives deposits and
withdrawals real inputs and outputs on the UTXO ledger and activates on a scheduled flag
day. Until that upgrade the committee is the genesis set.

---

## 9. Integration checklist

- [ ] Parse all amounts as big integers from decimal strings
- [ ] Derive `script_hash` and verify it against the echo in the first response
- [ ] Poll `getbalance`; expand with `getutxos` when it moves
- [ ] Credit on `finalized`, read from `getchaininfo`
- [ ] Keep deposit addresses under 1,000 outputs
- [ ] Serialise withdrawals, one inclusion at a time
- [ ] Read `next_base_fee_millisat_per_gas` before each build
- [ ] Cap planners at 815 inputs per transfer
- [ ] Run your own node in observer mode, supervised, and check `state_root` agreement

---

## 10. Reference

- Designed RPC surface, including methods scheduled but not yet shipped —
  [`../specs/BLOCH-RPC-V4.md`](../specs/BLOCH-RPC-V4.md)
- Carryover ledger construction — [`../CARRYOVER.md`](../CARRYOVER.md)
- Protocol specification — [`../SPEC.md`](../SPEC.md)

Measured 2026-08-26 at height 15,146, epoch 1,101.
