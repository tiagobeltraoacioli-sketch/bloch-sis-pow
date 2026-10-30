# Bloch exchange integration after hard forks 1, 2 and 3, and the L2 bridge

Edition 2026-10-30. Written against the armed release `78d4921c`
(branch `release/hf123-armado-20261025`) and checked with read-only calls to
the public RPC endpoints `80.240.16.185:8080`, `199.247.22.8:8080` and
`139.180.173.231:8080` (all three report build `fa980367`, which is
`78d4921c` plus a node-only network transport change) at L1 epoch 7022.

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

### 6.1 Status on 2026-10-30

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

### 6.3 L2 deposits and withdrawals on the L2 itself

Use the standard Ethereum post-Merge pattern on the settled L2 RPC:

1. `eth_chainId` must be `0xab162`.
2. `eth_getBlockByNumber ["finalized", false]` → `F`. `finalized` advances
   only after the L2 block's settlement is in the L1 finalized prefix, as
   verified by an independent follower that replays L1. `bloch_finality`
   returns the `latest`/`safe`/`finalized` levels with their L1 anchors, and
   `bloch_settlement [number]` returns the L1 settlement of a finalized L2
   block (or `null`).
3. Credit an L2 transaction when `eth_getTransactionReceipt` has
   `status` `0x1` and `blockNumber` ≤ `F`.
4. Bridge mints (L1 → L2 deposits) and contract transfers have no
   top-level L2 transaction: reconcile with `eth_getBalance [address, F]`.

Expected timing on mainnet (to be re-measured on the first blocks): one L2
block every 12 to 15 minutes, `finalized` about 100 minutes after
inclusion. Details: `bloch-l2-evm/docs/MAINNET-EXCHANGE-INTEGRATION.md`.

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
   - the index must not be set in `claimed` (bit `index mod 256` of word
     `index div 256`, or any word below `claimed.floor`);
   - `escrow_conserved` must be `true`.
   Do **not** use `matured`/`matured_large`; they mean only that the delay
   has passed.
3. Build the claim with `bloch-l2-produce-dev withdrawal-proof` (the proof
   for your index against the claimable root), then
   `bloch-pos l2-claim prepare` / `sign`, funded by a suite `0x0001` key
   that pays the fee. Claims of 100 BLCH or more also need the attestors'
   partial signatures. If `release_window.remaining_sat` is below the
   amount, the claim fits a later window (or, attested, as the first claim
   of a window).
4. Broadcast with `sendrawtransaction` and track the claim txid with
   `gettxstatus` to `finalized`. The recipient output is **vout 0** of the
   claim and pays exactly the withdrawn sats to `l1Recipient`. Credit it as
   an L1 deposit (§3.2).

A claim broadcast too early is refused (`NotMatured`, `NotFinalized`,
`AttestationRequired`, window cap) and must be broadcast again later; it
is never paid twice (the index is marked in `claimed`).

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
hash and the `finalized` tag.

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
