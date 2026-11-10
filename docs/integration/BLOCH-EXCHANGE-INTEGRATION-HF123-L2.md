# Bloch exchange integration after hard forks 1, 2 and 3, and the L2 bridge

Edition 2026-10-30. Written against the armed release `78d4921c`
(branch `release/hf123-armado-20261025`) and checked with read-only calls to
the public RPC endpoints `80.240.16.185:8080`, `199.247.22.8:8080` and
`139.180.173.231:8080` (all three report build `fa980367`, which is
`78d4921c` plus a node-only network transport change) at L1 epoch 7022.

**Draft of 2026-11-01 for the owner: not published.** §6 and §7 were
refreshed for the L2 v2.1 settled RPC (`18be911a…`, unsigned at the time of
writing). In those sections each statement carries **[M]** (measured on a
private rehearsal net, with real binaries unless the text says otherwise) or
**[R]** (read from the code, not run). No L2 mainnet exists yet to measure.
The L1 sections were not re-read against the public nodes in this refresh.

**Update of 2026-11-02 (agent 148), draft, not published, nothing sent:**
§6.5.2 and the new §6.8 describe the **next build** (build commit `17383fe`,
release `bloch-l2-2026-11-02-next-native-78d4921c`, signing target release
`SHA256SUMS` `116bfaba…`, **unsigned**; kit tip `f1c8033`). Sources are named
per statement: `PINS-NEXT.md`, agent reports 92, 93, 106, 124, 127, 139, and
the kit files at `f1c8033`. Nothing in §6.8 was measured on a mainnet L2.

This page is for exchanges and custodians that list BLCH. It supplements
[`BLOCH-G4-TECHNICAL-INTEGRATION-REFERENCE-v2.md`](./BLOCH-G4-TECHNICAL-INTEGRATION-REFERENCE-v2.md)
(the full method, address and transaction reference). Where the two
disagree, this page reflects the current code (see §8).

A reference checker that implements every rule below, using only the
Python standard library, is in
[`bloch_exchange_check.py`](./bloch_exchange_check.py) (§7).

---

## 1. Summary

| Question | Answer |
| --- | --- |
| Do I have to upgrade my node? | **Yes, before epoch 7178 (2026-11-01 15:39 UTC).** A node without the armed release stops following the chain at epoch 7180. |
| Do deposit or withdrawal flows change? | **No.** Addresses, transaction format, signing, fees and RPC shapes for transfers are unchanged at every fork. Signed but unbroadcast withdrawals stay valid across all three forks. |
| Does the crediting rule change? | No. Credit an L1 deposit when your own upgraded node reports `gettxstatus` = `"finalized"` (§3). HF1 makes that signal stricter during a network split, not weaker. |
| New transaction types? | `0x18` (validator withdrawal-credential rotation, from epoch 7360) never pays an exchange address. `0x19`/`0x1A` (post-quantum rescue) are behind an emergency gate that is not armed. You can ignore all three if you credit by output (§3). |
| New address type after HF3? | No new format. Wallets may use the optional signature suite `0x0003` from epoch 7360; their addresses look and work exactly like today's (§5). |
| KES (epoch 8620)? | Validator signing keys only. Nothing for exchanges. |
| L2 (chain 700770)? | Activated on L1 but **not yet operating**: no L2 block has been settled, and there is no public L2 RPC or explorer yet. §6 describes the flows for when it is live. |

## 2. Schedule

Epoch `E` starts at `1786656679 + 960 × E` (unix time; 32 slots of 30 s).
The epoch number is binding, the clock time is an estimate.

| Epoch | UTC (estimate) | What it is | What an exchange sees |
| --- | --- | --- | --- |
| 7178 | 2026-11-01 15:39 | Upgrade deadline (E1 − 2) | Your node must run the armed release by now. |
| **7180** | **2026-11-01 16:11** | **HF1**: L2 claim finality, frozen finality set | Old nodes stop following. L2 claims pause about 2 epochs (§6.4). L1 transfers unchanged. |
| 7186 | 2026-11-01 17:47 | HF1: own-target vote counting | Nothing. |
| 7270 | 2026-11-02 16:11 | **HF2**: canonical signatures for validator consensus messages; slashing relay policy; funded-validator growth cap | Nothing. Transaction signatures are judged exactly as before. |
| 7360 | 2026-11-03 16:11 | **HF3**: optional signature suite `0x0003` for spends; `0x18` credential rotation; KES registration opens | Deposits may arrive from `0x0003` wallets; nothing else (§5). |
| 8620 | 2026-11-17 16:11 | KES enforcement | Nothing. |

Your node reports the schedule it enforces. Use it as a machine check that
the node is on the armed release:

```
curl -s -X POST http://127.0.0.1:16400 -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"getchaininfo","params":[]}'
```

Required in the result (values read from the public nodes on 2026-10-30):

```json
"hard_forks": {
  "hf1_claim_finality": {"activation_epoch": 7180, "active": false},
  "hf2_sig_canonical":  {"activation_epoch": 7270, "active": false},
  "hf3_slh":            {"activation_epoch": 7360, "active": false},
  "hf3_kes_enforce":    {"activation_epoch": 8620, "active": false},
  ...
},
"signature_suites": [
  {"suite": "0x0001", "name": "ML-DSA-65+Falcon-1024", "activation_epoch": 0, "active": true, "spend_allowed": true},
  {"suite": "0x0002", "name": "ML-DSA-65", "activation_epoch": 0, "active": true, "spend_allowed": false},
  {"suite": "0x0003", "name": "SLH-DSA-SHAKE-128s+Falcon-1024", "activation_epoch": 7360, "active": false, "spend_allowed": false}
]
```

A node without these fields, or with `activation_epoch: null` for
`hf1_claim_finality`, is **not** upgraded. `getbuildinfo` reports the
build's `commit` and `source_digest`; compare them with the release notes.

### 2.1 Upgrading

1. Install the signed release binary and verify it
   (`minisign -Vm SHA256SUMS -p bloch-release-20260922.pub`, then
   `sha256sum --check SHA256SUMS`). For `78d4921c` the `bloch-pos`
   Linux x86-64 SHA-256 is
   `700631b040a3a4b2299017162dd4a2c5f521bb49d5fa3c9ed677ba285673794e`.
2. Restart with your existing data directory and command line. History
   before epoch 7180 replays to the same state roots, so no resync is needed.
3. Check `getchaininfo`: `hard_forks` as above, `behind_by_slots` 0 or 1,
   and the same `finalized.epoch`/`finalized.root` as a second independent
   node.

You do not need to suspend deposits or withdrawals. If you prefer, pause
them only while your node restarts.

## 3. L1 deposits

### 3.1 Detection (unchanged)

Balances and outputs are keyed by the 32-byte `script_hash`, never by the
address string. Convert each deposit address once (§5.1), then:

| Step | Call | Notes |
| --- | --- | --- |
| Poll | `getbalance [script_hash]` | `{"script_hash","balance_sat","utxo_count"}`; amounts are decimal strings in sat (8 decimals). |
| List | `getutxos [script_hash, limit]` (alias `listunspent`) | Up to 1,000 per call, `truncated` tells you if there are more. Each entry has `txid`, `vout`, `value_sat`, `script_hash`. |
| One output | `gettxout [txid, vout]` | `unspent`, `utxo{txid,vout,value_sat,script_hash}`. `at_slot` is the node's head slot, not the output's inclusion slot. |

**These three calls answer from the node's unfinalized head state.** A
balance or output they report is *included*, not *finalized*, and can still
be reorganized out. Nodes built from a release that carries the 2026-11-10
change add three fields to each of the three replies (nothing was renamed or
removed; older nodes simply do not send them, except `at_slot` on
`gettxout`):

| Field | Meaning |
| --- | --- |
| `at_slot` | Slot of the head state the answer was read from. |
| `finalized_height` | Height of this node's finalized checkpoint block on its canonical chain, or `null`: the same value and representation as in `getblockcount` and `getchaininfo`. |
| `finalized_epoch` | This node's finalized epoch, as in `getblockcount`. |

The two `finalized_*` fields describe the **node's finality line, not the
outputs in the reply**: they do not say that a listed output is final. Use
them to see, in the same reply, that the answer is ahead of finality and by
how much, and to stop on `finalized_height: null` with `finalized_epoch` > 0
(§3.2). An output is final only when the block that carries it is at or
below the finalized checkpoint, which is what `gettxstatus` = `finalized`
and a block's `"finalized": true` (compare its `height` with
`finalized_height`) report. The crediting rule in §3.2 is unchanged. The
finality line is published one step after the state, so it can be one block
apart from `at_slot`.

Any transaction kind can create an output to your `script_hash`: transfers
(`0x01`, `0x06`), validator payouts (`0x0D`), L2 withdrawal claims (`0x16`,
vout 0), and, only after an emergency gate that is not armed, a
post-quantum rescue reveal (`0x1A`, vout 0). If you credit by output, the
transaction kind does not matter.

### 3.2 Crediting rule

Credit an output when **all** of the following hold:

1. `gettxstatus [txid]` on **your own upgraded node** returns
   `{"status": "finalized"}`.
2. `getchaininfo` on that node shows `behind_by_slots` ≤ 2 and a non-null
   `finalized_height`. (`finalized.epoch` > 0 with `finalized_height: null`
   means the finalized checkpoint is not on your node's chain: stop and
   contact the operators.)
3. `gettxout [txid, vout]` returns the expected `script_hash` and
   `value_sat` (or the output has since been spent by your own sweep).
4. For large credits (your threshold; the operators' guidance is above
   100 BLCH), a second independently operated node returns `"finalized"` too
   and reports the same `finalized.root` at the same `finalized.epoch`.

What `gettxstatus` means (code: `engine.rs` `tx_status`, `finality_of`):

| Status | Meaning | Action |
| --- | --- | --- |
| `pending` | in this node's mempool | wait |
| `included` | in a block on this node's canonical chain, above the justified checkpoint | wait; can still be reorganized |
| `justified` | at or below the justified checkpoint block | wait; one epoch from finality on a healthy chain |
| `finalized` | at or below **this node's own finalized checkpoint block on its canonical chain** | credit (with the checks above) |
| `unknown` | not seen, dropped, reorganized out, or older than the node's index | see below |

Notes:

- `finalized` is decided by comparing the transaction's slot with the slot
  of the finalized checkpoint **block on this node's canonical chain**, not
  by epoch numbers. A checkpoint finalized on another branch does not count.
  The node refuses any reorganization below its own finalized checkpoint,
  so a transaction it reported `finalized` does not later leave its chain.
- The status index holds the **65,536 most recent** canonical transactions
  this node applied (it is rebuilt on restart by replay). Older
  transactions read `unknown`; for those use `gettxout`/`getutxos` and the
  block's `finality` (`getblockbyid` → `"finality": "finalized"`).
- Typical time to `finalized` on a healthy chain: 2 to 3 epochs (32 to 48
  minutes). Read on 2026-10-30: head epoch 7022, finalized epoch 7020.
- From epoch 7180 (HF1) the frozen finality set makes the chain **pause
  finality** during a network split instead of finalizing a minority side.
  Deposits then stay at `included`/`justified` until finality resumes. Do
  not credit early; wait. A finality stall longer than about 10 epochs (2
  to 3 hours) is an incident: contact the operators.

Live example (txid from the public explorer, block `e08122b2…` at slot
222938):

```
curl -s -X POST http://80.240.16.185:8080 -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"gettxstatus","params":["619e49e4460190e7c32ac6f03158d94295580d96aa5c6da9ad01dccb9ccaa93d"]}'
```

```json
{"jsonrpc":"2.0","id":1,"result":{"status":"finalized"}}
```

All three public nodes returned `finalized` for it, and `gettxout` with
`vout` 0 returned `value_sat` `"10000000"` to
`d8cbb87b41540d0c5cadb4ed13c0e630cdc63938000000000000000000000000`.

### 3.3 Optional: finality certificate

`getfinalitycertificate ["latest"]` (or `[epoch]`) returns the votes that
finalized a checkpoint (`epoch`, `root`, `checkpoint_slot`, `votes`,
`format: "BLOCHFC1"`, `certificate` hex; about 1.6 MB). It lets an auditor
check finality offline. It is not needed for crediting.

The `bloch-finality-verify` built from the current release sources counts own
bond, so its verdict does not follow the chain's rule from HF1 (e7180), and it
refuses every certificate with bound votes from HF2 (e7270). Rely on
`gettxstatus` until the release that adds `getlcproof`.

## 4. L1 withdrawals (unchanged at every fork)

1. Select inputs (`getutxos`/`gettxout`); exclude outpoints you already
   committed to an unconfirmed withdrawal.
2. Read `next_base_fee_millisat_per_gas` from `getchaininfo` or
   `getmempoolinfo` immediately before building. A transfer is valid at
   exactly one base fee (exact conservation).
3. Sign with your existing signer (suite `0x0001`, ML-DSA-65 + Falcon-1024).
   **No signer change for HF2.** HF2's canonical-signature rule applies to
   validator consensus messages only; transaction witnesses use the
   transaction signature policy at every epoch (tests
   `hf_gates_leave_transfers_byte_identical`,
   `v1_transfer_forms_stay_valid_across_the_canonical_flag_day`,
   `offline_cli_v1_signatures_verify_under_the_transaction_policy_at_every_epoch`).
4. Broadcast with `sendrawtransaction [hex]`. The answer is
   `{"accepted": true, "status": "accepted"|"duplicate", "kind", "bytes", "tx_hash", ...}`.
   `tx_hash` is only a local handle; **the consensus `txid` is the one your
   signer computed**. Track it with `gettxstatus [txid]` until `finalized`.
   **`accepted: true` means only that the node's mempool took the bytes.**
   It is not inclusion and not payment (§6.5).
5. Errors: `-32002` not a canonical transaction (do not retry the bytes);
   `-32008` refused on its merits (rebuild); `-32009` retryable after
   `error.data.until_slot` (usually a stale base fee: rebuild); `-32003`
   mempool full; `-32010` 64 pending transactions from one source key.

You do not need to switch your hot wallet to suite `0x0003` after HF3. If
you choose to: each `0x0003` witness costs about 15 times the
verification gas of a `0x0001` witness, and the signature is larger
(about 7.9 KB SLH-DSA plus about 1.3 KB Falcon).

## 5. Addresses, suites and the HF3 transaction types

### 5.1 Address to script_hash

`bloch1q` + hex(20-byte hash ‖ 4-byte checksum), 55 characters. The hash is
the first 20 bytes of `SHA3-256(enveloped public key)`; the checksum is
`SHA3-256(SHA3-256(hash))[0..4]`. The carried-form `script_hash` is the
20-byte hash followed by 12 zero bytes:

```
python3 docs/integration/bloch_exchange_check.py address bloch1q89747fe8bda0f0fbad1f107d9852bb5523d446e0db89ce31
```

```
89747fe8bda0f0fbad1f107d9852bb5523d446e0000000000000000000000000
```

Both the carried form and the full 32-byte native form are spendable by the
key's owner, with no epoch gate.

### 5.2 Suite 0x0003 after HF3 (epoch 7360)

- The enveloped public key carries its suite id, so a `0x0003` wallet's
  address is still `bloch1q…` with the same length, checksum and
  `script_hash` rule. **You cannot and need not tell suites apart from an
  address.** Sending to it is an ordinary transfer.
- A deposit from a `0x0003` sender is an ordinary transfer with larger
  witnesses. Credit it like any other (§3).
- `getchaininfo.signature_suites` shows `spend_allowed: true` for `0x0003`
  from epoch 7360. `0x0002` (ML-DSA alone) stays refused for new spends.

### 5.3 New transaction tags

| Tag | Name | Gate | Relevance |
| --- | --- | --- | --- |
| `0x17` | `kes_register` | 7360 | validators only |
| `0x18` | `withdrawal_credential_rotation` | 7360 | validators only; changes where a future validator payout goes; creates no output |
| `0x19` | `pq_rescue_commit` | lattice-emergency gate, **not armed** | none |
| `0x1A` | `pq_rescue_reveal` | lattice-emergency gate, **not armed** | would sweep all outputs of one key to one output at vout 0; credit by output if it ever pays you |
| `0x1B` | `kes_rotate` | 7360 | validators only |

`sendrawtransaction` refuses each tag before its gate. You never need to
build any of them.

### 5.4 KES

KES (forward-secure validator keys) registers from 7360 and is enforced
from 8620. It changes how validators sign blocks and votes. It does not
touch transactions, addresses, fees or RPC fields an exchange uses.
`getkes` exists for validator operators.

## 6. L2 (chain 700770)

### 6.1 Status on 2026-10-30 (not re-read for this draft)

The L2 was activated on L1 at epoch 5850 (slot 187200), but the operators
have not started it. Read-only `getl2settlement` on the public nodes:

```json
"chain_id": 700770, "profile": {"activated": true, "deposits": true, "user_transactions": true},
"inbox": {"count": 0, "consumed": 0, "escrow_sat": "0"},
"accepted": null,
"withdrawals": {"count": 0, "roots": [], "claimable": null, "delay_blocks": 64,
  "large_claim_sat": "10000000000", "large_delay_blocks": 2880,
  "release_window": {"blocks": 2880, "bps": 1000, "floor_sat": "1000000000", ...},
  "attestor_set": "1c06adbb…cc4b", "escrow_conserved": true,
  "finalized_checkpoint": {"epoch": 7020, "root": "d65248bb…11ba", "own_root": null, "own_chain_rule_active": false}}
```

`accepted: null` means no L2 block has been settled; the L2 head is still
its genesis `632e45ae…f468`. **There is no public L2 RPC, no L2 explorer
and no L2 transaction to show yet.** Do not open L2 deposits or
withdrawals until the operators announce the L2 RPC URL and the first
settled blocks. Until then, list BLCH on L1 only.

### 6.2 Parameters (fixed by the activated rules)

| | |
| --- | --- |
| Chain id | 700770 (`0xab162`) |
| Asset | BLCH as the native gas coin, 18 decimals (1 sat = 10^10 wei) |
| Addresses | 20-byte EVM addresses, secp256k1 |
| Minimum L1 → L2 deposit | 0.01 BLCH (1,000,000 sat) |
| Minimum L2 → L1 withdrawal | 0.01 BLCH, a whole number of sat |
| Claim delay | 64 L1 blocks; 2,880 L1 blocks for claims of 100 BLCH or more |
| Attestation | claims of 100 BLCH or more need 3-of-5 attestor signatures |
| Release window | per 2,880 L1 blocks, at most max(10 BLCH, 10% of escrow) is released |

List the L2 as a separate network ("BLCH — Bloch L2 (EVM)"). Never accept
an L1 address for an L2 withdrawal or the reverse.

### 6.3 Crediting on the L2 itself

Use the standard Ethereum post-Merge pattern on the settled L2 RPC.

1. `eth_chainId` must be `0xab162`. **[M]**
2. `eth_getBlockByNumber ["finalized", false]` gives `F`. `finalized` advances
   only after the L2 block's settlement is in the L1 finalized prefix, as
   verified by a follower that replays L1. `bloch_finality` returns the levels
   with their L1 anchors, and `bloch_settlement [number]` returns the L1
   settlement of a finalized L2 block, or `null`. **[M]** for the answers,
   **[R]** for the derivation.
3. Credit an L2 transaction when `eth_getTransactionReceipt` has `status` `0x1`
   and `blockNumber` ≤ `F`. **[M]**
4. Bridge mints (L1 → L2 deposits) and contract transfers have no top-level L2
   transaction: reconcile with `eth_getBalance [address, "finalized"]`. **[M]**
   for the call.

```
curl -s -X POST http://L2_RPC -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"bloch_finality","params":[]}'
```

Answer on a healthy v2.1 RPC, shortened **[M]**:

```json
{"finalized_height": 60,
 "finalized": {"number": "0x3c", "hash": "0x…"},
 "safe": {"number": "0x3c"}, "latest": {"number": "0x3d"},
 "l1": {"finalized": {"epoch": 1507, "slot": 48223, "root": "…"}, "safe_settlement": {"…": "…"}},
 "status": {"state": "ok", "written_at_unix": 1793581692, "age_s": 4},
 "trust": "finalized: native FFG replay from the pinned genesis; safe: the local native node's head; no checkpoint signatures"}
```

**Do not credit on `latest` or `safe`.** After an L1 reorganization of an
accepted settlement, an RPC can keep serving `latest` and `safe` blocks that L1
dropped until its operator repairs it. `finalized` stayed correct. **[M]**

**A reply to `eth_sendRawTransaction` is not inclusion.** Follow the receipt.
On v2.1 a forward clock step on an RPC host can evict acknowledged spooled
transactions: +4 h evicted 3 of 3 on an earlier build with the same spool code.
**[M]** on v2 `4fc9fa1e…`; absence of the fix from v2.1 is **[R]**. Through the
gateway, a send with no sequencer answers `-32053`. **[M]**

Timing: no mainnet cadence exists. Settlements on private nets took 5.3 to 15
minutes each, and 24 to 37 minutes from block to acceptance when proofs queued
for a shared prover. **[M]**, not mainnet. The earlier estimate of about 100
minutes from inclusion to `finalized` is unmeasured.

#### 6.3.1 `-32001` on `finalized`

```json
{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"finality unavailable: this node has lost a valid follower status; safe and finalized are closed"}}
```

Treat it as **unavailable: retry, do not credit, do not refuse, and do not
read it as a reversal.** Finality already seen remains final.

| While an RPC is closed (v2.1) | Answer | |
| --- | --- | --- |
| `finalized`, `safe` tags on block methods, `eth_getBalance`, `eth_call`, `eth_getLogs` | `-32001` | **[M]** |
| `latest`, numbered blocks, `eth_blockNumber` | served | **[M]** |
| `bloch_finality.status.state` | `missing` or `invalid` | **[M]** |
| `bloch_settlement` | `null`, **the same as "not settled"**: do not read it as an answer about the block | **[M]** |
| Valid status again | reopens within a poll | **[M]** |

- Causes measured: status file deleted, corrupt or contradicting the local
  chain, or above the v2.1 size limit (30,194 settlements, unreachable while
  settlement stops at block 4097, §6.7), or a foreign settlement (§6.3.3). **[M]**
  Those status files were written by the tests.
- The v2.1 gateway passes `-32001` through and does not try the other backend
  for that read, and its `/health` shows `finalized: null`. **[R]**
- **`null` is not "nothing is final".** A v2.1 RPC started without a status, or
  one whose database has not reached the tip, answers `finalized: null`, and
  the first also `bloch_finality: null`. Treat `null` like `-32001`. **[M]**
  for a start without status on v2.1; the lagging start was run on the next
  build only.

#### 6.3.2 What `age_s` does and does not tell you

`bloch_finality.status.age_s` has no enforced threshold: nothing closes when it
grows. **[M]**

| Situation (v2.1) | `state` | `age_s` | `finalized` |
| --- | --- | --- | --- |
| Follower stopped, status file frozen | `ok` | grows (76,384 s seen) | still served **[M]** |
| Database behind the status: it names a block this RPC lacks | `ok` | **stands still near 0** (file 7,204 s old, `age_s` 0 and still 0 nine seconds later) | served, not advancing **[M]** |

So **a small `age_s` does not prove that finality is current on v2.1.** An old
`finalized` is still true, so this delays credits and makes `finalized` balances
old. It does not credit anything falsely.

To detect staleness, compare with your own L1 node:

- `bloch_finality.l1.finalized.epoch` against `getchaininfo.finalized.epoch`.
  The gap was 3 epochs on three healthy private nets. **[M]** That the field
  freezes along with the rest of the document is **[R]**. There is no mainnet
  figure yet, so set your alert after the first settlements.
- Whether `finalized_height` advances while L1 shows new accepted settlements
  (`getl2settlement.accepted`). **[R]**

The next RPC build computes `age_s` at the call and adds state `lagging`, and
`status.schema`, whose absence identifies v2.1. **[M]** on a dev build; it is
not a release.

#### 6.3.3 `-32001` caused by a foreign settlement

Anyone can settle a rule-conforming L2 block on L1. On v2.1, if the status's
`safe_settlement` names a block the RPC's database holds with another hash, the
RPC closes **both** `safe` and `finalized` with `state: invalid`, although the
finalized prefix is still good. **[M]**, with a synthetic `safe_settlement`
written by the test. The follower takes that field from `getl2settlement`.
**[R]**

It fails closed: nothing false is served. On the sequencer's RPC it lasts until
recovery finishes, about 2.5 epochs plus the rebuild and restart, and returns
with each new foreign block. An RPC with no such local block stays open, so
another backend may serve. **[R]** Handle it as §6.3.1, and escalate if it lasts
over several epochs. The next build closes `safe` only. **[M]** on a dev build.

### 6.4 Moving BLCH from L1 to L2 (L1 tag 0x14)

1. Build and sign an `l2_deposit` (`bloch-pos l2-deposit prepare` / `sign`)
   to your 20-byte L2 address, funded from a suite `0x0001` key, and
   broadcast it with `sendrawtransaction`. The escrow output is always
   vout 1 (`ESCROW_VOUT`); change, when present, is vout 0.
2. Track the L1 txid with `gettxstatus` to `finalized` (§3.2).
3. While waiting for the next settlement, the deposit is listed in
   `getl2settlement` → `source.pending[]` (`txid`, `vout`, `sats`,
   `recipient`). After settlement it is minted to the recipient in that L2
   block; credit the L2 side at `finalized` (§6.3).

### 6.5 Moving BLCH from L2 to L1 (L2 outbox, then L1 tag 0x16)

1. On the L2, call the outbox predeploy
   `0x4200000000000000000000000000000000000102`,
   `initiateWithdrawal(bytes32 l1Recipient)` (selector `0xb769844a`) with
   the amount as `value`. `l1Recipient` is the full 32-byte L1
   `script_hash` (§5.1). The receipt's
   `WithdrawalInitiated(uint256 indexed nonce, bytes32 indexed l1Recipient, address sender, uint256 amountWei)`
   log gives the withdrawal **index** (`nonce`).
2. Wait until it is **claimable**. On every node you use,
   `getl2settlement` → `withdrawals`:
   - use `claimable` for amounts below `large_claim_sat`
     (100 BLCH), `claimable_large` at or above it; it must be non-null and
     its `count` must be greater than your index;
   - its `finalized` must be `true`;
   - from epoch 7180, `finalized_checkpoint.own_root` must equal
     `finalized_checkpoint.root`. `own_root: null` right after 7180 is the
     one-time claim pause (about 2 epochs, until a checkpoint of epoch 7180
     or later finalizes); a different non-null `own_root` means your node's
     chain carries a finality that is not its own: **stop claiming and
     crediting**;
   - the index must not be set in `claimed` (§6.5.1);
   - `escrow_conserved` must be `true`.
   Do **not** use `matured`/`matured_large`; they mean only that the delay
   has passed. **[R]** Measured `own_root` = `root` on private nets after the
   rule's gate. **[M]**
3. Get the proof, and build the claim with `bloch-pos l2-claim prepare` /
   `sign`, funded by a suite `0x0001` key that pays the fee. Claims of 100 BLCH
   or more also need the attestors' partial signatures. If
   `release_window.remaining_sat` is below the amount, the claim fits a later
   window (or, attested, as the first claim of a window). The proof comes from:
   - **On a v2.1 RPC:** `bloch-l2-produce-dev withdrawal-proof` on your own L2
     database. **v2.1 has no `bloch_getWithdrawalProof`: it answers `-32601`.**
     **[M]**
   - **On the next RPC build:** `bloch-l2-withdraw.py` (§6.5.2), which needs no
     local database. **[M]** on a provisional build.
4. Broadcast with `sendrawtransaction`, then **confirm from L1 state, not from
   the reply.**

   `accepted` and `duplicate` mean only that the mempool took the bytes.
   Admission does not check the nullifier, root, delay, attestation or fee.
   On one private net, 12 observed sends all answered `accepted: true`, and
   8 moved nothing: a repeat with the same bytes, a repeat as a new
   transaction, a wrong recipient, a stale base fee, a claim on an unfinalized
   settlement, a large claim before its delay, one with no attestation, and one
   large claim that also returned `accepted`. **[M]** The cause of the last one
   was not established at the time of writing. Escrow was conserved; no second
   payment occurred. **[M]**

   `tx_hash` in the reply is a local handle, not a txid. **[R]** A claim is
   paid when its index is set in `claimed` **and** the claim's txid is
   `finalized`. The recipient output is **vout 0** and pays exactly the
   withdrawn sats to `l1Recipient`. Credit it as an L1 deposit (§3.2).

A refused claim can be built and sent again later; an index is never paid
twice. **[M]**

#### 6.5.1 Reading claim status from the bitmap

`getl2settlement` → `withdrawals.claimed` is authoritative:

```json
"claimed": {"count": 5, "floor": 0, "words": [{"word": 0, "bits": "2f00…00"}]}
```

An index `i` is claimed if `i div 256` is below `floor`, or if the word
`i div 256` is listed and bit `(i mod 256) mod 8` of byte `(i mod 256) div 8` of
`bits` is set, counting bits from the least significant. A word that is not
listed and not below `floor` has nothing claimed. **[R]**, native `rpc.rs`.
`count` is only a total: it does not say which indexes.

Worked example **[M]**: `2f` is `00101111`, so indexes 0, 1, 2, 3 and 5 are
claimed and index 4 is not, with `count` 5. The checker and the withdraw tool
both read that net this way.

Read `claimed` at a node you trust and, for crediting, only after the claim's
transaction is `finalized`: `claimed` is the node's view at its head. **[R]**

#### 6.5.2 `bloch-l2-withdraw.py` and its exit codes

The tool is on the next RPC branch, not in the v2.1 kit. It holds no key and
sends nothing. **[R]** Give it your own L1 node.

```
python3 bloch-l2-withdraw.py fetch --l2-rpc http://L2_RPC --l1-rpc http://YOUR_L1_NODE:8080 --index I --any-recipient --out proof.json --wait 7200
```

| Exit | Meaning | Action | Seen with |
| --- | --- | --- | --- |
| 0 | `fetch`: proof verified, file written. `verify`: valid and **not claimed**. **Never "paid"** | go on to the claim | **[M]** |
| 1 | refused: bad proof, wrong owner or network, or a method the RPC lacks | **do not retry blindly**, read the message | **[M]** wrong network pin; `-32601` on v2.1 |
| 3 | not ready: retry later, with `--wait` the tool does so itself | wait | **[M]** unknown index (`-32042`), refused connection, HTML error page |
| 4 | index already claimed on L1 (`status`: claimed; finality of the paying output not shown) | do not resend; check your ledger | **[M]** |
| 5 | `status` only: still unclaimed long after sending, presumed dropped, nothing moved | build a new claim | **[R]** tool docstring at `f1c8033` |

On the next build the tool is in the kit as
`deployment/mainnet/withdraw/bloch-l2-withdraw.py` `1791d8ca…` (PINS-NEXT kit
table; hash re-read at `f1c8033`), with subcommands `burn`, `find`, `fetch`,
`verify` and `status`. **[R]** The next settled RPC serves
`bloch_getWithdrawalProof [index]` or `[index, root]`, which `fetch` calls.
**[R]** Withdraw suite 35 OK at 17383fe and 36 OK at 583d8ec, Mac. **[M]**,
agent 124. Use `status` after sending to decide credit or retry; exit 0 of
`verify` is never a payment. **[R]**

- `-32001`, `-32041`, `-32042`, `-32043`, `-32045`, `-32046`, `-32005`, `-32053`
  are exit 3 in the current tool. **[R]**; review tests ran these with stub RPCs.
- **Exit 3 can hide an operator problem.** A wrong URL serving HTML, or a single
  own RPC with frozen proofs (`-32046`), looks like "later" until `--wait` ends.
  The message names the cause. Alert on exit 3 lasting beyond your expected
  settlement time. **[M]** for HTML; **[R]** for `-32046`.
- An older copy of the tool (8f4cd9c) gives exit 1 for an HTML page **[M]**, and
  for `-32001` and `-32046` **[R]**. Use the current one.
- A `verify` of a proof whose root has left the L1's retained list refuses
  (exit 1) before it looks at `claimed`. **[R]** Use §6.5.1 for old claims.
- The tool's default pins are mainnet. On any other net pass `--network` and
  `--genesis-hash`, or it refuses. **[M]**

#### 6.5.3 Raw height fields

Several raw fields named as L1 heights hold the **L2 record count**, not the L1
chain height.

| Field | Holds |
| --- | --- |
| Statement and provenance field `l1_height`, explorer variable `l1Height` | L2 count **[R]** |
| `getl2settlement`: `native_height`, `source.height`, `withdrawals.roots[].height` | L2 count **[M]** |
| `getchaininfo.height`, `getblockbyid.height` | L1 chain height **[M]** |

Measured on one block of a private net: `source.height` 4137 and
`getblockbyid.height` 4201 at the same `source.slot` 4689; `native_height` 29606
against `getchaininfo.height` 29670. The offset was 64 there and 0 on a net with
L2 active from its first block. **[M]** On mainnet it was about 152,014 when read.
**[R]** It follows from where the L2 activated, so do not hard-code it.

To locate a settlement on L1 use its `slot` or block id. Compare these fields
only with each other: the claim delay compares a record's `height` with the L2
count, so the delay of 64 blocks is still 64 L1 blocks. **[R]**

### 6.6 If you run your own settled RPC

Upgrade **the RPC before the follower's status schema**. A v2.1 RPC closes
`safe` and `finalized` on a v3 status: **[M]** with a real follower's file. Readers
that see a closed RPC recover when it is upgraded (0.2 s on the same database
and file, **[M]** in the larger-status case).

| Step | What |
| --- | --- |
| 1 | Next settled RPC on every host serving this status |
| 2 | Readers of the file on that host: attestor kit, replica kit, bridge signers |
| 3 | New follower binary, schema still v2, the default |
| 4 | `BLOCH_L2_STATUS_SCHEMA=v3` in `follower.env`, restart, one host at a time. Check `bloch_finality.status.schema` |

Going back is a restart with v2. A flip back and forth under a live RPC gave no
error and no height change in a rehearsal. **[M]** on a dev build, with the
systemd override not started. The new follower's default of v2 and this order are
on a provisional branch, and no release has these hashes yet.

A v2.1 attestor kit given a v3 file signs nothing and raises no alert. **[R]**

### 6.7 Known limits of v2.1

- **Settlement stops at L2 block 4097** (`MAX_REPLAY_BLOCKS` = 4096). `finalized`
  stops advancing and deposits and withdrawals wait; no funds move. **[R]**: no
  chain was run to that block. A release must fix this first.
- On a compressed rehearsal schedule, settlements in flight crossed HF1,
  own-target, HF2, HF3 and the KES gate, claims were honoured after them, escrow
  was conserved and rebuilds from L1 matched. **[M]**, rehearsal builds of
  provisional v2.1. No claim fell inside the HF1, own-target or HF2 windows, and
  no settlement or claim was exercised after the first KES handover (period 1,
  e8710 on mainnet).

### 6.8 The next build (17383fe) at launch

Draft for the next build launch. The owner has not signed `116bfaba…` yet.

**Finality levels.**
- `safe` follows an L1 reorg **down**, never below `finalized` (602f1a6), and
  by-hash reads check the canonical hash (ff9753a). **[R]**, agent 124. Do not
  credit at `safe`; nothing that moves value in the kit reads it. **[R]**, agent
  46's survey spot-checked by 124. A falling `safe` is normal after an L1 reorg.
- `finalized` answers **`-32001`** ("this level is closed") until the RPC has
  read a follower status file, where v2.1 answered `null`. **[M]**, agent 139,
  settled-rpc `e5754d05…` (a harness that expected `null` died on it). Treat
  `-32001` as "not yet", not as an error to page on at once; the reference
  checker already does (§7).
- A foreign settlement closes `safe` only, no longer `finalized` (§6.3.3).
  **[M]** on a dev build.

**Deposit-only launch, idle blocks.** User transactions on the L2 are off.
The settler is configured with `--skip-idle-blocks --max-idle-seconds 86400
--min-block-interval 1800`: no block without demand, a heartbeat block at most
every 24 h, at most one block every 30 min. **[R]**, go-live plan D15 (agent
127, from agent 92). So **the L2 head can be up to 24 h old while healthy.**
Do not alert on head age alone. Tell idle from stuck:
- `l2_monitor.py` adds `--max-idle-seconds` to the head, settlement and
  finalized age thresholds (`idle_thresholds`), so `l2_head_age` is graded
  against 25/45 min **plus** 24 h. **[R]**, `l2_monitor.py` `71f14a64…`.
  `l2_head_age` went CRIT on agent 92's rehearsal anyway, because the head's
  time is its anchor and older than its acceptance by the proof time; plan
  D18 suggests N + 45 min + proof time. **[R]**, agent 127.
- `deposit_wait` is the stuck signal: time since L1 deposits began waiting with
  none consumed (`--backlog-state` file). Idle with no deposits waiting is
  healthy; deposits waiting and `deposit_wait` growing is stuck. Defaults
  45/90 min; plan D18 suggests 5,400/10,800 s for 30 min pacing (agent 127's
  value, **not measured**). **[R]**
- From outside, the same test: `getl2settlement` → `source.pending[]`
  non-empty with no new accepted settlement past your expected wait means
  stuck. **[R]**

**Proof cadence and times.** With 30 min pacing and proofs of about 30–60 min
per block, expect:
- a deposit to mint in about **40–70 min** (two blocks after an idle
  stretch), longer as proofs slow with height. **[R]**, plan D15; not measured
  end to end on mainnet;
- then `finalized` on L2 after the L1 finalizes the settlement (§6.3), and
  for withdrawals the claim delay and L1 finality on top (§6.5).
Proof time by height, real proofs on 32 vCPU, dense guest `203114bf…`: 814–944
s at block 2048, 1,563 s at 4097, 2,731–2,809 s at 8191 (about 46 min).
**[M]**, agent 93. The monitor WARNs around block 4,000 at 1,800 s interval.
**[R]**, plan D16. Set customer-facing estimates to at least 2 h for deposits
and allow more as height grows (my suggestion, not measured).

**`RateLimited` large claims.** A claim larger than what remains of the release
window (`release_window.remaining_sat`) is answered `accepted` by
`sendrawtransaction` and then refused with `RateLimited`; nothing moves. **[M]**,
agent 67 (the unexplained case of §6.5 step 4); **[R]** for the rule, withdraw
README. A claim above `cap_sat` fits only as the **first** claim of a window,
so any earlier claim, however small, blocks it for that window (2,880 blocks).
**[R]** Confirm with `status` / the `claimed` bitmap, never with the reply.

**Spool expiry while user transactions are off.** The RPC drops a queued
transaction 3 h after it first saw it (`SPOOL_LIMITS.ttl`), whether or not a
block could include it, and a dropped nonce makes the sender's later nonces
expire too. **[R]**, PINS-NEXT trap (agent 55 finding 3), settled-rpc source at
17383fe. It does not affect the deposit-only launch, since user transactions
are off; it **must be fixed before they turn on**. Do not build any queuing
of user L2 transactions on this build.

**For node operators: a stuck L1 node.** On mainnet, do **not** wipe the data
dir: an empty mainnet node exits with `ERR_WS_REQUIRE_CHECKPOINT` (genesis anchor
beyond the 2016-epoch weak-subjectivity window), with or without
`ws_latest.bin`. **[M]**, agent 106, mainnet binary `01c98b68…`. Instead
refill from a healthy node you operate: stop it, copy its chain files by name
(`blocks.*`, `meta.*`, `ws_latest*`, `state.cache*`), **never key files**,
then start. Measured 97 s to serve the head (2.9 GB local copy; host transfer
time comes on top). **[M]**, agent 106. Without `state.cache` the node
replays the full chain in 51–54 min. **[M]** With a signed checkpoint it is
about 11.5–15 h (extrapolated). **[M]**/extrapolated. The runbook fix is on
`codex/recovery-r6-20261102`; check that your copy of
`docs/L1-STUCK-NODE-RUNBOOK.md` has the refill steps. **[R]**, agents 106, 127.

## 7. Reference checker

[`bloch_exchange_check.py`](./bloch_exchange_check.py), Python 3.9+, no
dependencies, read-only. Give each independent node with `--rpc`
(default: the two public RPC nodes, for testing only). Exit status 0 =
creditable/claimable, 1 = not yet, 2 = refused, disagreement or error.
`--wait SECONDS` polls every 30 s.

```
python3 docs/integration/bloch_exchange_check.py --rpc http://127.0.0.1:16400 --rpc http://SECOND_NODE:16400 tx 619e49e4460190e7c32ac6f03158d94295580d96aa5c6da9ad01dccb9ccaa93d --vout 0 --script-hash d8cbb87b41540d0c5cadb4ed13c0e630cdc63938000000000000000000000000 --amount 10000000 --wait 3600
```

```
python3 docs/integration/bloch_exchange_check.py --rpc http://127.0.0.1:16400 claim --index 0 --sats 100000000
```

```
python3 docs/integration/bloch_exchange_check.py l2tx 0xTXHASH --l2-rpc https://L2_RPC_URL
```

`tx` halts (exit 2) if any node is behind, has a finalized checkpoint off
its canonical chain, is not on the armed release (`hard_forks` check), or
if two nodes report different roots for the same finalized epoch. `claim`
applies every condition of §6.5 step 2 and reports the attestation and
release-window conditions. `l2tx` checks receipt status, canonical block
hash and the `finalized` tag; a `-32001`, `-32053` or null `finalized` is exit 1,
and it prints `bloch_finality.status` (§6.3.2).

The exit codes differ from `bloch-l2-withdraw.py` (§6.5.2): here an already
claimed index is exit 2 (tool: 4), and "not yet" is exit 1 (tool: 3).

Run on 2026-11-01 against private nets, read-only: `l2tx` on the v2.1 RPC gave
`CREDITABLE` (exit 0) and `WAIT` (exit 1) for a block above `finalized`; the
claim verdicts for claimed, claimable and beyond-count indexes came from the
function behind `claim`, since `claim` and `tx` correctly halt on a private net
whose gates differ from the armed schedule (exit 2). A stub replaying the real
`-32001` text gave exit 1.

Run on 2026-10-30 against the three public nodes: `tx` above returned
`CREDITABLE` (exit 0); the same with `--amount 10000001` returned
`REFUSED` (exit 2); an unknown txid returned `WAIT` (exit 1); `claim`
returned `no L2 settlement accepted yet` (exit 1).

## 8. Corrections to earlier integration pages

- `BLOCH-G4-TECHNICAL-INTEGRATION-REFERENCE-v2.md` §11.4 says
  `gettxstatus` `"finalized"` is an epoch comparison. In the current code it
  compares the transaction's slot with the slot of the finalized checkpoint
  block on the node's own canonical chain (`Engine::finality_of`), the same
  rule as the block RPC's `finality`. Since the 2026-10-19 interim guidance
  it is the recommended crediting signal (§3.2).
- `sendrawtransaction` returns no `txid`; `tx_hash` is a local handle
  (unchanged; restated because it matters for `gettxstatus`).
- The HF compatibility analysis of 2026-10-20 listed an HF2 signer
  blocker for exchanges. It no longer applies: the canonical-signature rule
  was re-scoped to validator consensus messages before the release was
  armed (§4).

## 9. Checklist

- [ ] Node upgraded before epoch 7178; `getchaininfo.hard_forks` shows 7180 / 7270 / 7360 / 8620.
- [ ] Credit L1 deposits only on `gettxstatus` = `finalized` from your own node, with the output check.
- [ ] Second independent node for large credits, same finalized root and epoch.
- [ ] Halt on `finalized_height: null` with `finalized.epoch` > 0, or on finalized-root disagreement.
- [ ] No signer change; no need to re-sign pending withdrawals at any fork.
- [ ] L2 not listed until the operators publish the L2 RPC and settled blocks.
- [ ] L2 claims: use `claimable`/`claimable_large`, never `matured`; check `own_root` = `root` from epoch 7180.
- [ ] Treat `-32001` and a null `finalized` as "unavailable": no credit, no refusal, retry, alert.
- [ ] Do not take a small `age_s` as proof of currency on v2.1: compare `bloch_finality.l1.finalized.epoch` with your own L1 node.
- [ ] Never treat `accepted` as paid: confirm a claim from `claimed` and the finalized claim txid.
- [ ] Handle withdraw tool exit 3 as retry, with an alert if it persists; exit 4 as "do not resend".
- [ ] Do not read `source.height`, `native_height`, `roots[].height` or `l1_height` as L1 chain height.
- [ ] Own RPC: upgrade the RPC before any follower moves to status schema v3.
