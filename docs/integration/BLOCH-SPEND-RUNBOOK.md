# BLOCH Genesis-4 — End-to-End Spend Runbook

**Build → sign → submit → confirm, executed with non-production keys.**

Status: EXECUTED against a local two-validator devnet at the commit this file
ships in; read-only checks executed against the live chain
(`http://139.84.201.52:16400`). The one thing this document does NOT prove is
an execution on mainnet with a funded key — §11 states exactly which steps
that leaves unproven and what a rehearsal costs. Everything else in here was
actually run; every terminal transcript in §9 is real output, not an example.

Why this exists: `docs/integration/BLOCH-EXCHANGE-INTEGRATION.md` §13 item 1
admits, correctly, that the entire signing path of the Genesis-3 book was read
from source and never executed. An exchange refuses — reasonably — to let the
first execution of a spend path be a customer withdrawal. This runbook is the
"someone has actually run it" document for the **Genesis-4 (PoS)** chain, which
is the live chain since 2026-08-13. Nothing here touches production or
treasury key material, and nothing here ever should: rehearse with throwaway
keys and rehearsal amounts, on a devnet first and a dust-level mainnet coin
second.

The executable companion is `tools/spend-runbook` (binary `spend-runbook`).
It deliberately compiles the node's own source files for every wire format it
emits, so it cannot drift from what the node parses.

---

## 0. The eight facts that shape everything below

Read these first; every operational rule in this document derives from one of
them. Source references are to this repository at this commit.

1. **There is no transaction id on the wire and no transaction index.**
   `gettransaction` answers a permanent, explained refusal (`-32005`). A
   transfer's `txid` exists — `SHA3-256(DS_TXID ‖ signing_root)` — but no
   block commits to it as an index key and no RPC looks it up. You confirm a
   payment by looking for the **outpoint it creates** (`gettxout`) or the
   balance it moves (`getbalance`), never by a txid lookup.
   (`crates/bloch-pos-node/src/rpc.rs`, `transition.rs::txid`.)

2. **Signatures are hybrid ML-DSA-65 ‖ Falcon-1024, verified AND.** Public
   key ≈ 3,749 B, signature ≈ 4.6 KB, both wrapped in a 4-byte suite envelope
   (`B1 0C 01 00`). No hardware wallet signs this suite. The signer is
   software holding the secret key. (`crates/bloch-crypto/src/crypto/mod.rs`.)

3. **Value conservation is EXACT: `sum(inputs) == sum(outputs) + fee`,** and
   the fee is **derived, never declared**: `gas × price`, where gas =
   `5000 + 16·tx_bytes + 72,748·inputs` and price = the **base fee committed
   by the chain** plus your tip. Overpaying is not "generous", it is
   `ValueNotConserved` and the transfer is invalid.
   (`transition.rs::apply_transfer`, `fee_market.rs::charge`.)

4. **A transfer therefore commits to exactly one base fee.** If the network's
   base fee moves between build and inclusion, the conservation equation
   breaks and the transaction is **permanently invalid — rebuild and re-sign;
   never resubmit.** The base fee floor is 10 msat/gas and the live chain has
   sat at the floor since launch (near-empty blocks; ±1/8 per block only under
   load), so in practice today the fee is stable — but the wallet MUST read
   `getchaininfo.next_base_fee_millisat_per_gas` at build time and MUST treat
   a moved base fee as a rebuild trigger.

5. **`tx_bytes` is declared, is inside the signing root, and must cover the
   real encoding.** Consensus refuses a declaration below the canonical
   encoding (`UnderdeclaredSize`) and accepts one above it (you pay the gas on
   the declared figure). Since the Falcon half of the signature is
   variable-length, the correct procedure is: fix `tx_bytes` to an upper
   bound computed with a maximal-length dummy signature, THEN derive the
   signing root, THEN sign. Changing `tx_bytes` after signing voids the
   signature.

6. **Rejection after admission is silent.** The mempool's admission check is
   structural plus signature verification. A transfer whose inputs do not
   exist, or which fails conservation (wrong base fee!), is **admitted**,
   then dropped by the first proposer that picks it up — without notice, and
   barred from re-admission on that node. Detection is entirely on you:
   the created outpoint never appears and `getmempoolinfo` drains. There is
   no error to wait for. (`engine.rs::on_transaction`, the proposer drop
   loop in `engine.rs::propose`.)

7. **Settlement is the `finalized: true` boolean, not depth.** PoS has no
   depth-as-security; block responses carry `finalized`, and an exchange
   credits at finality (typically ~2 epochs = 64 slots ≈ 6 min behind head).
   (`rpc.rs::block_json`, `getchaininfo.finalized_height`.)

8. **Two spendable script-hash forms exist for one key.** An output's
   `script_hash` is 32 bytes. A full-form output commits to
   `SHA3-256(pubkey)` (all 32 bytes). An address-form output commits to the
   first 20 bytes with 12 zero bytes appended — because a `bloch1q…` address
   only carries 20 hash bytes. The node's `owns()` accepts both for the same
   key. **They are different script hashes**: balances and UTXO queries are
   per-form, so a wallet must query both forms (or standardise on one).
   (`rpc.rs::owns`, `crates/bloch-crypto/src/address.rs`.)

---

## 1. Tools and build

```bash
cargo build --release -p bloch-pos-node -p spend-runbook
# produces target/release/bloch-pos  and  target/release/spend-runbook
```

`spend-runbook` subcommands, in runbook order:

| Subcommand | What it does | Network access |
|---|---|---|
| `keygen`   | throwaway hybrid keypair → hex files, prints address + both script-hash forms | none |
| `genesis`  | devnet genesis manifest with a **liquid allocation** (spendable opening coin) | none |
| `build-tx` | size → fee → change → signing root → sign → self-verify → canonical hex | none |
| `decode`   | decode any canonical transfer hex, re-verify signatures | none |

Broadcast and confirmation are plain JSON-RPC over HTTP (`curl` below) — the
tool holds no transport on purpose; the RPC surface is the integration
surface.

---

## 2. Key generation — NON-PRODUCTION

```bash
spend-runbook keygen --out /path/to/spender
```

Writes `spend.pk.hex` and `spend.sk.hex` (mode 0600) and prints:

- `script_hash (full 32)` — `SHA3-256(pubkey)`, hex, 64 chars. Use this as
  the getbalance/getutxos parameter for coins sent to the full form.
- `script_hash (addr20+0)` — first 20 bytes of the same digest + 24 zero hex
  chars. This is the form an output paid **to the address** carries.
- `address (mainnet)` — `bloch1q` + hex(20-byte hash) + hex(4-byte checksum),
  55 chars. Checksum = `SHA3-256(SHA3-256(hash))[..4]`.

Rules:

- The secret key is a plain hex file. That is acceptable ONLY because the key
  is throwaway. Production custody is out of scope here and unsolved by any
  HSM (fact 2).
- The tool refuses to overwrite an existing `spend.sk.hex`.
- Never derive anything from the treasury or any production keystore with
  this tool. It cannot read `validator.key` keystores for signing, by design.

Address → script_hash (the rule an exchange needs for deposits): strip
`bloch1q` (or `bloch1t`), take the first 40 hex chars (20 bytes), verify the
last 8 hex chars are `SHA3-256(SHA3-256(hash20))[..4]`, then zero-extend the
20 bytes to 32. That 32-byte value is the `script_hash` parameter for
`getbalance` / `listunspent`, and the `script_hash` to put in an output
paying that address.

## 3. Funding and UTXO discovery

A wallet spends **outpoints**, so it must know `(txid, vout, value)` for each
coin it holds:

```bash
curl -sS -X POST http://NODE:16400 -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"listunspent","params":["<script_hash 64-hex>"]}'
```

Answer: `{script_hash, total, returned, truncated, utxos:[{txid, vout,
value_sat, script_hash}]}`. `value_sat` is a **decimal string** (fact: the
V4 surface strings every satoshi amount; parse as u64/u128, never as a JS
number). Page size defaults to 100, max 1,000; `truncated: true` means there
are more.

Query **both** script-hash forms of your key (fact 8) or you will miss coins.

`getbalance` takes the same parameter and returns `{script_hash, balance_sat,
utxo_count}`.

## 4. Building and signing

```bash
spend-runbook build-tx \
  --sk spender/spend.sk.hex --pk spender/spend.pk.hex \
  --spend <txid>:<vout>:<value_sat> \            # repeatable
  --pay   <script_hash-or-address>:<amount_sat> \ # repeatable, order = vout order
  --change <script_hash-or-address> \
  --base-fee <msat/gas from getchaininfo.next_base_fee_millisat_per_gas> \
  --tip 0 \
  --out-hex tx.hex
```

What it does, in the only order that works:

1. **Shape**: inputs (each carrying the pubkey and, later, the signature),
   outputs = your `--pay` list plus one change output.
2. **Size**: encodes the transfer with a maximal-length dummy signature
   (4 + 3309 + 1330 bytes) per input and declares `tx_bytes` = that length.
   Real Falcon signatures are ≤ the bound, so `UnderdeclaredSize` cannot
   fire; the few bytes of over-declaration cost ~a hundred sat of gas.
3. **Fee**: `gas = 5000 + 16·tx_bytes + 72,748·n_inputs`;
   `fee_sat = ceil(gas·base_fee/1000) + ceil(gas·tip/1000)`.
4. **Change** = inputs − pays − fee, exactly (fact 3). Zero change → the
   change output is dropped and the fee recomputed for the smaller shape.
   Negative → "insufficient funds", stop.
   **There is no consensus dust floor on outputs in Genesis-4** — but do not
   emit micro-change anyway; it bloats the UTXO set and the Genesis-3 chain
   has already been through a dust incident. If change would be < ~1,000 sat,
   prefer raising the paid amount so change is zero.
5. **Signing root** = SHA3-256 over `DS_SPEND ‖ spend-points ‖ outputs ‖
   tx_bytes ‖ tip` — the witnesses are excluded (they contain the signature
   being produced). Every input of this transfer is authorised by a signature
   over this ONE root.
6. **Sign** with the hybrid key; **fill** the signature into every input.
   (One key owning all inputs signs once and the same signature is carried
   per input — that redundancy is what `TransferV2` removes; see §10.)
7. **Self-verify**: AND-verification of both halves over the root, encoded
   length ≤ declared `tx_bytes`, decode round-trip through the node's own
   decoder, conservation restated.

It prints the `signing_root`, the **txid**, the fee breakdown, and the
canonical hex. **Record the txid and the output ordering** — `(txid, 0)` is
your payment outpoint, `(txid, last)` is your change outpoint; they are what
you confirm by in §6, and the change outpoint is what you spend next.

The printed BASE FEE WARNING is the contract of fact 4: any change of
`--base-fee`, `--tip`, `--spend`, `--pay`, or the tool's computed `tx_bytes`
changes the root and voids the signature. The tool never mutates a signed
transaction; it rebuilds.

## 5. Submitting

```bash
curl -sS -X POST http://NODE:16400 -H 'Content-Type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"sendrawtransaction\",\"params\":[\"$(cat tx.hex)\"]}"
```

Success: `{"accepted":true,"status":"accepted","kind":"transfer","bytes":N,
"tx_hash":"…", …}` plus two verbatim notes: `tx_hash` is a **local**
correlation handle (SHA3-256 of the canonical bytes — not the txid, and not
consensus), and the transport does not confirm — see §6.

`"status":"duplicate"` = these exact bytes are already in this node's
mempool. Not an error; do not treat as a second payment.

Error codes you can branch on (top-level JSON-RPC `error`):

| code | name | meaning | action |
|---|---|---|---|
| −32602 | invalid params | not hex / empty | fix the client |
| −32002 | TX_DECODE_FAILED | hex ok, not canonical bytes | never retry unchanged |
| −32008 | TX_REFUSED | judged invalid at admission (no/empty inputs or outputs, **signature does not verify**, deposit/delegate refused) | never retry these bytes; rebuild |
| −32003 | MEMPOOL_FULL | 4,096-entry cap hit | retry later, unchanged |
| −32004 | NODE_UNAVAILABLE | consensus thread busy >10 s | retry |

Submission SHOULD go to more than one node (the public `g4rpc` proxy already
broadcasts writes to all its upstreams): admission is per-node, gossip does
the rest.

**The write port is unauthenticated.** A node's RPC defaults to 127.0.0.1;
anything routable must be firewalled to the clients meant to reach it.

## 6. Confirming — by outpoint, then by finality

You already know the created outpoints (§4). Poll:

```bash
# inclusion: the payment outpoint exists in the committed UTXO set
curl … -d '{"jsonrpc":"2.0","id":1,"method":"gettxout","params":["<txid>",0]}'
#  -> {"unspent":true,"utxo":{...},"at_slot":N}    (typically 1–2 slots after submit)

# settlement: the chain has finalized past the including slot
curl … -d '{"jsonrpc":"2.0","id":1,"method":"getchaininfo","params":[]}'
#  -> credit when finalized_height/finalized epoch has passed the inclusion slot
```

`getbalance` on the recipient's script hash corroborates (remember fact 8:
use the form the output was actually created under — pays to an address are
the addr20+0 form).

`gettxout → unspent:false` means: never existed, **or already spent, or not
yet included**. It is one boolean answering "is this outpoint in the
committed set right now", pinned by `at_slot`. For deposit crediting that
ambiguity doesn't bite (you created the outpoint and nobody else can spend
it before you); for anything else, disambiguate with `getbalance` deltas.

**Timeout rule**: if the outpoint has not appeared within ~10 slots and
`getmempoolinfo` shows the pool drained, the transfer was silently dropped
(fact 6). Diagnose (§7), rebuild, re-sign, resubmit. Do not blind-resubmit
the same bytes: if the drop reason was state-dependent (already-spent input,
moved base fee), the same bytes can never apply — and the dropping node has
barred them anyway.

## 7. Failure modes, exhaustively

At admission (you get an explicit error — §5 table). After admission
(**silent**, fact 6): the proposer's transition probe refuses the transfer,
drops it from its mempool, bars the bytes. The reasons and their wallet-side
meanings (`transition.rs::TransferReject`):

| reject | what it means for the wallet |
|---|---|
| `UnknownInput` | outpoint spent, never existed, or the node's head hasn't caught up to the funding tx. Re-select coins and rebuild. Double-spend attempts land here. |
| `DuplicateInput` | same outpoint twice in one transfer — wallet bug. |
| `ScriptMismatch` | pubkey doesn't hash to the output's script_hash — wrong key, or wrong script-hash form assumption. |
| `ValueNotConserved` | inputs ≠ outputs + fee. **The base-fee-moved case lands here.** Also: arithmetic bug, stale coin value. Rebuild against current `next_base_fee_millisat_per_gas`. |
| `UnderdeclaredSize` | declared `tx_bytes` < canonical length. Cannot happen via `build-tx`'s upper-bound sizing; hand-rolled builders must re-sign at a larger declaration, never inflate post-signature. |
| `OutputExists` | a created outpoint collides with a live one — effectively impossible (needs a SHA3-256 collision); a duplicate of an earlier identical transfer surfaces as `UnknownInput` instead (its inputs are gone). |
| `BadSignature` | cannot pass admission on current nodes (admission verifies), but a relayed-from-elsewhere tx dies here. |
| `NoInputs`/`NoOutputs` | refused at admission (−32008). |
| `FormatNotActive` | `TransferV2` before epoch 800 — moot on mainnet (epoch ≥ 1,590). |

Mempool lifecycle facts an operator must know:

- The pool holds ≤ 4,096 entries; a block carries ≤ 256 transactions and
  ≤ 512 KiB of payload (V2 cap, epochs ≥ 800).
- Inclusion in ANY block this node accepts removes the entry ("included is
  included").
- Refusal by this node's own proposer removes AND bars the entry.
- A transfer sitting in the pool of a node that never proposes just sits
  there (this build has no TTL on unproposed entries) — but every validator
  proposes, so on the live fleet a valid transfer is picked up within a few
  slots and an invalid one is dropped within a few slots. Either way the
  pool does not tell you which; the outpoint does.

## 8. Devnet rehearsal — what §9 actually ran

A two-validator devnet, one liquid allocation to a throwaway key, one spend,
one confirmation, plus the two negative rehearsals that matter (duplicate
submission; base-fee-mismatch silent drop). Copy-paste sequence:

```bash
B=target/release/bloch-pos; SR=target/release/spend-runbook; D=/tmp/blochdev

# 1. validator keystores (devnet-only keygen)
$B keygen --dir $D/v0 --index 0
$B keygen --dir $D/v1 --index 1

# 2. throwaway spending keys — NEVER production
$SR keygen --out $D/spender
$SR keygen --out $D/recipient

# 3. genesis with a 1,000 BLCH liquid allocation to the spender
$SR genesis --keys $D/v0,$D/v1 \
  --alloc <spender script_hash (full 32)>:100000000000 \
  --out $D/genesis.bin --slot-ms 2000 --start-in 10
#   prints: allocation outpoint <ALLOC_TXID>:0

# 4. run both validators (RPC on 17310/17311, loopback)
$B run --data-dir $D/v0 --genesis $D/genesis.bin --listen 17701 \
      --peers 127.0.0.1:17702 --rpc-port 17310 &
$B run --data-dir $D/v1 --genesis $D/genesis.bin --listen 17702 \
      --peers 127.0.0.1:17701 --rpc-port 17311 &

# 5. wait for blocks, check the opening coin
curl … getchaininfo             # height rising
curl … getbalance [spender full-32 script_hash]   # 100000000000 sat

# 6. build+sign: pay 400 BLCH to the recipient's ADDRESS, change back
$SR build-tx --sk $D/spender/spend.sk.hex --pk $D/spender/spend.pk.hex \
  --spend <ALLOC_TXID>:0:100000000000 \
  --pay   <recipient bloch1q… address>:40000000000 \
  --change <spender script_hash (full 32)> \
  --base-fee 10 --tip 0 --out-hex $D/tx.hex

# 7. submit to node 0, confirm on node 1 (cross-node = it really gossiped)
curl 17310 … sendrawtransaction [$(cat $D/tx.hex)]
curl 17311 … gettxout [<TXID>, 0]        # until unspent:true
curl 17311 … getbalance [recipient addr20+0 form]  # 40000000000
curl 17311 … getbalance [spender full-32]          # change = 100000000000 − 40000000000 − fee
```

## 9. Evidence — transcripts of the actual run

The `EVIDENCE` block appended at the end of this file holds the verbatim
outputs of every step above as executed on 2026-08-31 (devnet: 2 validators,
2 s slots, commit as shipped). Key measured figures from that run:

- pubkey 3,749 B; hybrid signature 4,586 B (this run; the Falcon half is
  variable); one-input two-output transfer 8,492 B encoded; declared
  `tx_bytes` 8,549 (the upper bound the tool sizes against).
- gas 214,532 for one input, two outputs → fee 2,146 sat at the
  10 msat/gas floor (0.00002146 BLCH).
- admission-to-inclusion: ≤ 2 slots (submitted ≈ slot 152, included at
  slot 154); the created outpoints answered `unspent: true` from the OTHER
  node immediately after, and the including block reported
  `finalized: true` two epochs later.
- resubmitting the already-included bytes: admitted again
  (`status: "accepted"`, mempool 1) and then silently dropped by the next
  proposer — `dropping a transaction the transition refuses
  (Transfer(0, UnknownInput)); proposing without it` in the node log,
  nothing on the RPC. That is the double-spend shape, and it is silent.
- a rebuild of the same spend at `--base-fee 11` (network at 10): admitted,
  second submission answered `status: "duplicate"`, then silently dropped —
  `Transfer(0, ValueNotConserved)` in both proposers' logs; the spent coin
  stayed untouched. Exactly the fact-4/fact-6 behaviour warned about above.
- an address-form (addr20+0) output — the carryover-shaped script hash —
  was spent by its key in a second transfer (slot 219, finalized), proving
  the `owns()` 20-byte+zero-tail path end to end.
- every explicit error code in §5's table was triggered and captured:
  −32602 (bad hex), −32002 (non-canonical bytes), −32008 (tampered
  signature: "retrying the same bytes will not help"), −32005 and −32006
  (the two permanent refusals).
- mainnet read surface (139.84.201.52:16400, live chain, epoch ≈ 1590):
  `getchaininfo` (base fee at the 10 msat/gas floor, `finalized_height`
  ~68 blocks behind head), `getbalance` and `listunspent` on a live
  address-form script hash (45,649 UTXOs, `value_sat` as decimal strings,
  `truncated: true` pagination) — shapes identical to the devnet's.

## 10. Mainnet deltas

Everything in §2–§7 is chain-independent. What changes on mainnet:

- **Endpoint**: your own node's RPC (default `127.0.0.1:16310`), a fleet
  node's `16400+i`, or the `g4rpc` proxy — which requires 2 agreeing nodes on
  reads and broadcasts writes to all upstreams. Do NOT trust one foreign
  node's answers for crediting; run your own or use quorum.
- **Base fee**: read `getchaininfo.next_base_fee_millisat_per_gas` at build
  time (it has sat at the floor of 10 since launch). Rebuild on change (fact 4).
- **Format**: mainnet epoch ≥ 800, so `TransferV2` (deduplicated witnesses,
  tag 0x06) is active and is what a consolidation sweep should use — one
  signature per owner instead of per input. `build-tx` emits V1 (tag 0x01),
  which remains fully valid and is the right shape for a 1–2 input payment;
  the signing root, txid and signature are byte-identical between the two
  encodings of the same logical transfer.
- **Rehearse before value**: first mainnet execution should move a dust-level
  amount between two fresh throwaway keys (§11).

## 11. What remains unproven, precisely

Executed and proven (devnet, non-production keys): key generation, address
and both script-hash derivations, UTXO discovery, sizing, fee arithmetic at
the committed base fee, exact-conservation change, signing-root derivation,
hybrid signing and AND-verification, canonical encoding and round-trip,
`sendrawtransaction` admission, gossip to a second node, block inclusion by
a real proposer, confirmation by `gettxout`/`getbalance`, finalization of
the including block, duplicate-submission semantics, and the silent drop of
a base-fee-mismatched rebuild.

Executed against mainnet: read-only surface only (`getchaininfo`,
`getbalance`, `listunspent` shapes and the string-amount convention).

NOT yet executed, and impossible without funded mainnet coins:

1. `sendrawtransaction` of a value-bearing transfer on **mainnet** — i.e.
   admission by fleet binaries at their deployed commit, gossip across the
   real 60-plus-node fleet, inclusion by a mainnet proposer, and mainnet
   finalization of a spend.
2. The mainnet fee figures above at real base fee (expected identical: the
   constants are the same crate the fleet compiles).
3. Spending a **carryover** (Genesis-1/3-era) output with a legacy-derived
   key — the treasury's coins are that shape (addr20+0 script hashes, legacy
   pre-envelope keys are also accepted by `crypto::verify`). A rehearsal
   cannot synthesise this without a production key; the closest safe proxy
   is the devnet addr20+0 spend, which §9 covers (the recipient was paid to
   an address-form output; spending THAT output back is the same code path).

To close item 1 the founder needs to fund one throwaway rehearsal key with
roughly **0.001 BLCH (100,000 sat)** — enough for ~40 one-input transfers at
the current floor fee — sent to a `spend-runbook keygen` address, and run
§4–§6 against a mainnet node. Nothing about that rehearsal needs, or should
ever touch, the treasury key itself beyond the one funding send from
whatever wallet the founder already uses.

---

*Companion tool: `tools/spend-runbook`. Integration book being superseded:
`docs/integration/BLOCH-EXCHANGE-INTEGRATION.md` (Genesis-3; its §13 item 1
is the debt this document pays down for Genesis-4).*

---

## EVIDENCE — verbatim transcripts, 2026-08-31

Local devnet: 2 validators, `--slot-ms 2000`, nodes on 127.0.0.1 (RPC
17310/17311), binaries built `--release` from this repository at this commit.
Key and hash values below are real and throwaway; the devnet was destroyed
after the run.

### E1. Key generation

```
$ spend-runbook keygen --out .../spender
pubkey_len            : 3749 bytes (suite-enveloped hybrid)
script_hash (full 32) : efe42e324690613e6e4f6390de1daa72b79819a93be3dffa1ff049cd8dc3e9a0
script_hash (addr20+0): efe42e324690613e6e4f6390de1daa72b79819a9000000000000000000000000
address (mainnet)     : bloch1qefe42e324690613e6e4f6390de1daa72b79819a936734f93

$ spend-runbook keygen --out .../recipient
script_hash (full 32) : e2aa400deb3b17e83e81965579b2b929dfeb096e63f341ab10bf9f3f4d2e58a5
script_hash (addr20+0): e2aa400deb3b17e83e81965579b2b929dfeb096e000000000000000000000000
address (mainnet)     : bloch1qe2aa400deb3b17e83e81965579b2b929dfeb096ee198fe47
```

### E2. Genesis with a liquid allocation, nodes up, coin discoverable

```
$ spend-runbook genesis --keys v0,v1 --alloc efe4…e9a0:100000000000 \
    --out genesis.bin --slot-ms 2000 --start-in 20
wrote genesis.bin: 2 validators, slot 2000 ms, genesis block 9953da73
allocation outpoint  : 0970123752dda7e11dc6e2ee14c48d3a8369fde814cf1c52158012ef61360e7e:0
                       value 100000000000 sat

$ bloch-pos run --data-dir v0 --genesis genesis.bin --listen 17701 \
    --peers 127.0.0.1:17702 --rpc-port 17310     # and the mirror for v1

getchaininfo  → "height":12 … "validators":{"total":2,"active":2},
                "base_fee_millisat_per_gas":"10", "mempool":0

listunspent [efe4…e9a0] →
  {"txid":"0970123752dda7e11dc6e2ee14c48d3a8369fde814cf1c52158012ef61360e7e",
   "vout":0,"value_sat":"100000000000","script_hash":"efe4…e9a0"}
```

### E3. Build + sign (the transfer that was later included at slot 154)

```
$ spend-runbook build-tx --sk spender/spend.sk.hex --pk spender/spend.pk.hex \
    --spend 0970…0e7e:0:100000000000 \
    --pay bloch1qe2aa400deb3b17e83e81965579b2b929dfeb096ee198fe47:40000000000 \
    --change efe4…e9a0 --base-fee 10 --tip 0 --out-hex tx1.hex
signing_root      : 944466ac05b310e3645c0847a5879bac07927c9b61c43833944c4c92fe3de54d
txid              : c3d743e017311c21497d0759c7370e3a79bffb1c33c39d7a9b0dc00ef56ec176
output 0          : 40000000000 sat -> e2aa400d…096e000000000000000000000000
output 1          : 59999997854 sat -> efe42e32…8dc3e9a0
declared tx_bytes : 8549 (encoded 8491 bytes)
gas               : 214532
fee               : 2146 sat (base 2146 @ 10 msat/gas + tip 0 @ 0 msat/gas)
signature_len     : 4585 bytes per input
```

`decode --hex @tx1.hex` reproduced the same txid/signing root and reported
`signature VERIFIES` (AND-verification of both hybrid halves).

### E4. Submit and confirm — cross-node

```
sendrawtransaction (node :17310) →
  {"accepted":true,"status":"accepted","kind":"transfer","bytes":8491,
   "tx_hash":"29c7ad78…","tx_hash_note":"local correlation handle only …"}

gettxout ["c3d7…c176",0]  (node :17311) →
  {"unspent":true,"utxo":{"value_sat":"40000000000",
   "script_hash":"e2aa400d…0000"},"at_slot":160}

getbalance [e2aa400d…0000]  → "balance_sat":"40000000000"   (recipient, addr form)
getbalance [efe42e32…e9a0]  → "balance_sat":"59999997854"   (spender change)
getmempoolinfo → "size":0

getblockbyslot [154] → "tx_count":1 … "finalized":true      (the including block)
```

Conservation on-chain: 100,000,000,000 = 40,000,000,000 + 59,999,997,854 + 2,146. Exact.

### E5. Negative rehearsal 1 — resubmitting spent bytes (double-spend shape)

```
sendrawtransaction (same tx1.hex again) → {"accepted":true,"status":"accepted",…}
getmempoolinfo → "size":1
… a few slots later …
getmempoolinfo → "size":0        # nothing told the submitter anything
node logs (BOTH proposers):
  [slot 179] dropping a transaction the transition refuses
             (Transfer(0, UnknownInput)); proposing without it
```

### E6. Negative rehearsal 2 — base fee moved (built at 11, network at 10)

```
$ spend-runbook build-tx … --spend c3d7…c176:1:59999997854 --base-fee 11 …
fee               : 2360 sat (base 2360 @ 11 msat/gas + tip 0)

sendrawtransaction → {"accepted":true,"status":"accepted",…}
sendrawtransaction (again) → {"accepted":true,"status":"duplicate",…}
… a few slots later, silently …
node logs: [slot 197] dropping a transaction the transition refuses
           (Transfer(0, ValueNotConserved)); proposing without it
getbalance [efe42e32…e9a0] → "59999997854"   # the coin never moved
```

### E7. Spending an address-form output (carryover-shaped script hash)

```
$ spend-runbook build-tx --sk recipient/spend.sk.hex --pk recipient/spend.pk.hex \
    --spend c3d7…c176:0:40000000000 \
    --pay bloch1qefe4…36734f93:39999000000 --change e2aa…58a5 --base-fee 10
txid              : 87368787c7c946e74bc98feecf8560a3779635fd182dfc48f6fe50b837bad78b

sendrawtransaction (node :17311) → accepted
gettxout ["8736…d78b",0] (node :17310) → {"unspent":true, "value_sat":"39999000000"}
getbalance [e2aa400d…0000] → "0"     # the addr-form coin was spent by its key
getblockbyslot [219] → "tx_count":1  # finalized:false at first read;
  "finality":"finalized","finalized":true two epochs later — re-read AFTER
  BOTH NODES WERE RESTARTED and replayed their 195-block store ("replayed
  195 blocks: head slot 302 … finalized e7"), so the spend also survived a
  full persistence round-trip
```

### E8. The explicit-error surface

```
params ["abcdef"] → -32002 "not a canonical Genesis-4 transaction: unknown transaction tag 0xab"
params ["zzzz"]   → -32602 "invalid params: `hex` is not valid hexadecimal"
tampered witness  → -32008 "transfer carries a signature that does not verify —
                    this transaction cannot be admitted; retrying the same
                    bytes will not help"
gettransaction    → -32005 (permanent refusal, full text explains the scan-based alternative)
getnewaddress     → -32006 (permanent refusal)
```

### E9. Mainnet, read-only (139.84.201.52:16400, 2026-08-31)

```
getchaininfo → "height":29999,"finalized_height":29931,"epoch":1590,
               "base_fee_millisat_per_gas":"10","next_base_fee_millisat_per_gas":"10",
               "validators":{"total":64,"active":64},"mempool":0

getbalance ["e986db51…0000"] → {"balance_sat":"3793847323578573533","utxo_count":45649}
listunspent ["e986db51…0000",2] → "total":45649,"returned":2,"truncated":true,
  utxos[].value_sat as decimal strings
```

No write was sent to mainnet. That is the boundary of this rehearsal, and
§11 is the statement of what crossing it requires.
