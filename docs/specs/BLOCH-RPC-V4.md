<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Bloch — JSON-RPC Surface V4 (Genesis-4)

```
Document:   BLOCH-RPC-V4
Status:     DRAFT — for DEV-3 (owner of the RPC layer) and the OpenAPI V4 freeze
Created:    2026-08-11
Author:     Assistant A5 (ecosystem)
Parents:    BLOCH-ECOSYSTEM-MIGRATION.md §1 (measured V3 inventory; partially
            superseded — see its seal), BLOCH-POS-SHA3-LATTICE-MIGRATION.md
            §5.3–§5.5 (BlockHeaderV4, state commitment), BLOCH-TOKENOMICS-V4.md
            (supply, emission, validator revenue), BLOCH-POS-INTERFACES.md
            (frozen consensus traits the RPC layer reads through)
Baseline:   src/rpc/mod.rs as of 2026-08-11 (38 methods + 3 feature-gated
            euvm_*), docs/openapi.yaml (V3 contract)
```

This document is the Genesis-4 RPC surface: what dies with PoW, what changes
meaning, and what is born with staking, delegation, commission and finality.
It supersedes §1 of `BLOCH-ECOSYSTEM-MIGRATION.md` where the two differ — that
survey was written before the taint machinery was dissolved and before the
supply reverted to 100 billion, and this document folds both reversals in.

The OpenAPI V4 major (`docs/openapi.yaml`) is the normative wire contract;
this document is its design rationale and method-level disposition. Freeze the
OpenAPI file early in the gap — explorer, three wallets, two generated SDKs
and the L2 all fan out from it (ecosystem plan §8.1).

> **Note, 2026-08-11 (after this draft).** The founder decided EVM runs **at
> L1, with no rollup**, and Ustav becomes a consensus object — so every
> reference below to "the L2" as a consumer (the anchor/bridge finality
> predicate on `getchaininfo`, the fan-out above) is superseded: `bloch-l2-evm`
> is being replaced, not re-pointed. The methods themselves stand; the L1-EVM
> surface (eth-namespace or not, account-model queries) is a **new, unscoped
> addition** to this document, owned by the 2026-08-11 wave.

---

## 0. Rules that shape every method

- **R1 — Depth is dead; finality is a state, not a number.** V4 has no
  difficulty and no depth-as-security. Every method that today implies
  security-by-depth must instead report the containing block's relation to the
  justified/finalized checkpoints. `confirmations` may survive as an
  informational display value, never as a security signal.
- **R2 — One naming rule for "attestation".** `getattestation` already exists
  and means **TEE attestation** (SEV-SNP report, `src/rpc/mod.rs:1493`,
  `src/attestation/`); the shipping desktop wallet calls it. PoS methods MUST
  NOT use the bare word: the consensus-vote feed is `getepochattestations`
  (§4). See §5.
- **R3 — Amount encoding is decided once, in the OpenAPI file.** All
  satoshi-denominated fields are decimal **strings** on the wire in V4. See §6
  for the arithmetic, including which risk is resolved (Go `int64`) and which
  is not (JavaScript 2^53).
- **R4 — Standard JSON-RPC errors only.** The V3 convention of returning
  method-level failures as `result.error` strings with HTTP 200 is a defect
  every client special-cases (explorer `rpc.ts`, both generated SDKs carry a
  `ResultError` shim). The V4 major is the one chance to fix it without
  breaking anyone: errors are always the top-level JSON-RPC `error` object.
- **R5 — Commission disclosure is part of consensus safety.** Tokenomics V4
  §6.3 leaves validator commission uncapped *on the explicit bet* that wallets
  and the explorer surface the rate prominently. The RPC layer therefore MUST
  return `commission_bps` on every validator-listing response, not behind a
  detail call (§4.2).

What is **not** in V4, and why: the earlier ecosystem plan specified
`gettaintstatus` as the enabling API for coin-eligibility warnings. The taint
machinery was dissolved on 2026-08-11 (the carryover crosses as one set, with
no exclusion list), so there is no coin class to query and the method is
dropped. The open remnant is vesting-lock visibility — see §4.6.

---

## 1. Removed — dies with PoW, no replacement

| Method | V3 location | Why it dies |
|---|---|---|
| `getblocktemplate` | `mod.rs:689` | mining template (incl. `genesis2_expected_bits_for_parents`) |
| `submitblock` | `mod.rs:812` | PoW block submission — V4 proposals arrive via P2P from the scheduled proposer |
| `createauxblock` | `mod.rs:840` | AuxPoW / merged mining |
| `submitauxblock` | `mod.rs:907` (+ aux-candidate ring `mod.rs:1517`) | AuxPoW / merged mining |
| `gethashrate` | `mod.rs:1213` | no hashrate exists |
| `getdifficultyhistory` | `mod.rs:1225` | no retargets exist |

These are removed from the dispatch, the OpenAPI file, and the generated SDKs.
Per the relaunch decision there is no compatibility window: the G4 node never
validates a PoW block, so a stub answering "gone" would be the only
alternative, and an unknown-method error says the same thing.

## 2. Replaced — same need, new shape

| V3 method | V4 replacement | Notes |
|---|---|---|
| `getdaginfo` (`mod.rs:946`) | **`getchaininfo`** | There is no DAG. Returns tip (`block_id`, `slot`, `height`), current epoch and slot-in-epoch, latest justified and finalized checkpoints (root + epoch each), and validator-set size. This is the method the L2 anchor/bridge finality predicate reads (ecosystem plan §5.1). |
| `getpools` (`mod.rs:1053`) | **`getstakinginfo`** (§4.4) | `getpools` is built entirely on `tokenomics_v2` miner/validator/oracle subsidy splits, none of which exist under V4. |
| `getblocktimepercentiles` (`mod.rs:1246`) | **`getslotstats`** | Block time is a protocol constant (30 s slots); the informative metric inverts to **missed slots**: per-window missed-slot rate, longest gap, and per-proposer miss counts. |

## 3. Changed semantics

### 3.1 `gettxstatus` — the load-bearing change

V3 (`mod.rs:1267`) answers `pending | confirmed | final | unknown`, with
`"final"` hardcoded at ≥ 100 confirmations — coinbase-maturity depth standing
in for finality. The explorer, the `anchoring` crate (`FINAL_DEPTH = 100`,
`anchoring/src/anchor.rs:79`), and the wallets all trust this method verbatim
and do no arithmetic of their own. Under PoS, depth no longer means finality —
a 5-deep transaction inside a finalized epoch is irreversible while a 500-deep
transaction past a stalled finality gadget is not.

V4 contract:

```jsonc
// gettxstatus [txid]
{
  "txid": "…",
  "status": "pending" | "included" | "justified" | "finalized" | "unknown",
  "in_mempool": false,
  "block_id": "…",          // absent when pending/unknown
  "block_height": 41230,     // absent when pending/unknown
  "slot": 41290,             // absent when pending/unknown
  "epoch": 1290,             // absent when pending/unknown
  "confirmations": 17        // informational depth ONLY — no security meaning
}
```

- `pending` — in the mempool.
- `included` — in a block on the canonical chain, block not yet justified.
- `justified` — the containing block is an ancestor of (or equal to) the
  latest justified checkpoint.
- `finalized` — the containing block is an ancestor of (or equal to) the
  latest finalized checkpoint. **This is the only state that may be treated
  as irreversible.** A rollback below it is a network catastrophe, not a
  reorg to handle (ecosystem plan §5.1).
- `unknown` — not found.

`confirmations` is retained for display continuity but documented as
informational. Clients that today gate on `status == "final"` map it to
`"finalized"`; clients that gate on `confirmations >= K` must migrate to the
status enum — the OpenAPI description says so explicitly.

Blocks get the same treatment: every block-returning method adds a
`finality: "pending" | "justified" | "finalized"` field (blocks have no
mempool state, so three values, not four) so no client reimplements
checkpoint arithmetic.

### 3.2 Block-returning methods — `getblock`, `getblockbyheight`, `getrecentblocks`

The V3 serializations (`mod.rs:346`, `:383`, `:421`) emit `bits`, `nonce`,
`parents[]`, `blue_score`, `timestamp`, `merkle_root`. All of those die with
`BlockHeaderV4` (migration spec §5.3). V4 emits:

```jsonc
{
  "block_id": "…",                 // SHA3-256(DS_BLOCK ‖ header) — the ONLY identity
  "version": 4,
  "parent": "…",                   // explicit single parent (wire vector is pinned len==1;
                                    // RPC exposes the scalar so clients fail loudly if that ever changes)
  "slot": 41290,
  "epoch": 1290,
  "height": 41230,
  "proposer_index": 17,
  "timestamp": 1790000000,          // DERIVED from slot for display; not a consensus field
  "state_root": "…",
  "body_root": "…",
  "randao_reveal": "…",
  "randao_mix": "…",
  "justified_root": "…",
  "finalized_root": "…",
  "attestation_root": "…",
  "coherence_root": "…",
  "finality": "finalized",
  "tx_count": 12
}
```

Two V3 defects die with the reshape and must not be reproduced: `getblock`
emitted `bits` as a hex string while `getrecentblocks` emitted it as a number
(clients special-case it, e.g. explorer `BlockDetail.tsx:23`); and there were
two block identities (`pow_hash` vs `block_hash`), the split behind the
2026-08-05 tip-selection stall. V4 has exactly one `block_id` everywhere.

`getblockhash [height]` survives with a cleaner meaning: on a linear chain
with a finality floor, height→`block_id` is unique below the finalized
checkpoint and canonical-tentative above it; the response gains the same
`finality` field.

### 3.3 `getnetworkinfo` (`mod.rs:307`)

`blue_score` and the `best_announced` blue-score lag fields die. Replaced by:
tip slot vs wall-clock slot (sync lag in slots), peer count, and the
justified/finalized epochs. Everything else survives.

### 3.4 `getchainstats` (`mod.rs:1175`)

`current_difficulty`, `hashrate_hs`, `hashrate_human` die. The rest (block
counts, tx counts, sizes) survives; add participation rate of the previous
epoch, since that is the number that replaces hashrate as the one-glance
health metric.

### 3.5 `getsupplydistribution` (`mod.rs:1192`)

Rewritten from scratch against Tokenomics V4:

- Reports the seven genesis allocations (carryover, founder grant, VC, team,
  marketing, liquidity, validator emission) with vested-vs-locked splits
  computed from the consensus vesting schedules, plus cumulative burned fees.
- **Terminology is normative** (Tokenomics V4 §6.3.2): the headline figure is
  `max_issued` = 100,000,000,000 BLCH; `circulating` = issued − burned − locked.
  The two diverge from the first burned fee onward; the method must never
  label the cap "total supply".
- The V3 implementation **omits the carryover balance** (known defect — it
  under-reports supply by ~3.47 B; recorded in the ops memory and ecosystem
  plan §1.2). The rewrite is the fix: genesis allocations are the source of
  truth, so nothing is computed by scanning a subset of coinbases.

### 3.6 `decoderawtransaction` (`mod.rs:655`) and `sendrawtransaction` (`mod.rs:550`)

Both survive; deposits, exits, delegations and undelegations are ordinary
transactions and flow through them. `decoderawtransaction` learns the new tx
types (`DepositTx` with suite-tagged pubkey + proof-of-possession, `ExitTx`,
`DelegateTx`, `UndelegateTx`) and reports their decoded staking fields.

### 3.7 Survivors (unchanged apart from R3 string amounts and R4 errors)

`getblockcount`, `getmempoolinfo`, `getmempoolstats`, `getrawmempool`,
`gettransaction`, `gettxsbyblock`, `getbalance`, `getutxos`,
`getaddressinfo`, `getaddresscount`, `getaddressbalance_at_height`,
`listtransactions`, `validateaddress`, `validateaddressverbose`,
`estimatefee`, `estimatefeeadvanced`, `getpeerinfo`, `getpeers`,
`getattestation` (TEE — see §5), and the feature-gated `euvm_*` trio.

---

## 4. New — staking, delegation, commission, finality

Names are the V4 canon; DEV-3 owns the implementation. Where the backing
state already exists in-tree it is cited — most of this surface is a read
layer over `crates/bloch-pos-committee`.

### 4.1 `getepochinfo [epoch?]`

Current (or given) epoch: number, slot range, proposer schedule for the
epoch's slots, participation of current and previous epoch (attesting stake /
active stake), and the justified/finalized checkpoint pair as of that epoch.

### 4.2 `getvalidators [state?]` and `getvalidator [index | pubkey_hash]`

Registry view over `delegation::Registry` and `rewards::StakeAccount`:

- per validator: `index`, `pubkey_hash`, `state`
  (`queued | active | exiting | exited | slashed`), `own_stake_sat`,
  `delegated_stake_sat`, `effective_stake_sat` (post cap — the 1% fixed-point
  iterated cap), **`commission_bps`** (R5: present on the LIST response),
  `activation_epoch`, `exit_epoch`, `withdrawable_epoch`, attestation-credit
  performance over a trailing window.
- `getvalidator` adds: commission **change history** (the explorer's
  rate-change event feed is a MUST per ecosystem plan §2.3), reward totals,
  and current delegator count.

### 4.3 `getdelegations [address]`

A delegator's positions: validator index, amount, state
(`warming_up | active | cooling_down | withdrawable`), epochs remaining in
warm-up/cool-down queues (`delegation.rs` `StakeState`), pending withdrawals,
and each position's slashing exposure (delegators are slashed pro-rata,
Tokenomics V4 §6.3.1 rule 3 — the field exists so wallets can show it before
delegation, not after).

### 4.4 `getstakinginfo`

Network-level staking economics: total active stake, staked % of circulating,
nominal staking yield vs inflation (`rewards.rs::nominal_yield_bps`; both
numbers, per Tokenomics V4 §6.3 — and the response names its denominator, per
§6.1's "the denominator is load-bearing"), activation/exit queue lengths, and
the public decentralisation gates: `top_share_bps` and the Nakamoto
coefficient at the one-third threshold (`Registry::nakamoto_coefficient`).
These are public commitments; the RPC is where they become checkable.

### 4.5 `getcheckpoints [count?]`, `getslashings [count?]`, `getepochattestations [epoch?]`

- `getcheckpoints` — finality history: recent (epoch, justified_root,
  finalized_root, participation) tuples; the explorer's finality-stall banner
  reads this.
- `getslashings` — evidence feed: offence class (closed enum, interfaces
  §2.6), offender index, penalty, correlated-window total, inclusion slot.
- `getepochattestations` — the consensus-vote feed for an epoch (aggregate
  participation bitfields + `AttestationData`), named per R2/§5. Serves the
  explorer's participation views and slashing-monitor tooling; individual
  hybrid signatures are not returned (they are prunable after finality,
  migration spec §6.5.1).

### 4.6 Open — vesting-lock visibility (`getvestingstatus`)

With taint dissolved, the only coin-class question left is **vesting**:
founder/VC/team/marketing genesis outputs carry consensus vesting locks
(Tokenomics V4 §7), and a wallet should be able to ask "is this output
spendable now, and if not, when?" before building a doomed transaction.
Whether this is a dedicated `getvestingstatus [outpoint | address]` or extra
fields on `getutxos` is an OpenAPI-freeze decision; the need itself is pinned
by interfaces doc §4.6 (vesting locks are what replaced the taint set's
eligibility role). Decide before the freeze; do not resurrect the word
"taint" in the API.

---

## 5. The `getattestation` name — decided

`getattestation` (`src/rpc/mod.rs:1493`) predates PoS and returns the node's
**TEE attestation report** (Bloch-SIS-Linux L3, SEV-SNP; pluggable provider,
`attested: false` without a TEE). The shipping desktop wallet already calls
it (ecosystem plan §3.2).

Decision recorded here so it cannot be re-litigated by accident:

1. `getattestation` **keeps its TEE meaning, unchanged**, in V4. Renaming it
   would break a shipping client to free up a word PoS does not need.
2. No PoS method uses the bare word "attestation". The vote feed is
   `getepochattestations` (§4.5); any future per-slot variant follows the
   same `get<scope>attestations` pattern.
3. Header/response **fields** named by the frozen specs (`attestation_root`,
   `AttestationData`) are unaffected — the collision risk is at the method
   dispatch, where a client asks by name and gets the wrong subsystem.
4. The OpenAPI V4 file documents both meanings side-by-side, with a
   cross-reference on each, so generated SDK docs carry the distinction.

## 6. Amount encoding — one risk resolved, one still live

Numbers, measured:

- V4 supply cap: 100,000,000,000 BLCH = **2.1 × 10^18 sat**.
- `i64::MAX` = 9.223 × 10^18 → the cap is **22.8%** of it (4.39× headroom).
- The cap is hard (no tail — Tokenomics V4 §6.2 retired it) and base-fee burn
  only ever lowers supply, so no future total can approach the boundary.
- JavaScript's exact-integer limit 2^53 = 9,007,199,254,740,992 sat ≈
  **90,071,992.5 BLCH** — and single real balances already exceed it ~39×
  (the largest carryover address holds 3.546 B BLCH).

Therefore:

1. **Resolved — do not "fix" it back:** `sdk/go/models.go:16`
   (`type Satoshis = int64`) overflowed only under the abandoned 100 B draft
   (10^19 sat, 8.4% past `i64::MAX`). At the reverted 21 B cap it fits with
   wide margin, permanently. The overflow warnings in
   `BLOCH-ECOSYSTEM-MIGRATION.md` §1.4/§4.3/§8.3 are **superseded on the Go
   side**; the type stays `int64`. (Consensus-internal arithmetic is a
   separate matter: the frozen interfaces carry `u128` end-to-end,
   interfaces doc §1.2 — that rule is about overflow-free *sums*, not wire
   width, and also stands.)
2. **Still live — the wire:** any JSON consumer that parses numbers as IEEE-754
   doubles (every browser, including the explorer) silently corrupts amounts
   above ~90 M BLCH. So in the V4 OpenAPI contract **every
   satoshi-denominated field is a decimal string** (`"sat": "354617540000000000"`),
   uniformly — balances, UTXO values, stakes, rewards, penalties, supply
   figures. Uniformity is deliberate: a "only large fields are strings" rule
   is a latent bug in every client that hits its first large value. The
   display-only float `*_bloch` companions may remain, documented as lossy.
3. Generated SDKs absorb this in codegen: Go parses the strings into `int64`
   (fits, per 1), Python into `int`; the hand-written TypeScript SDK and the
   explorer use `BigInt`.

## 7. Deployment surface — the public proxy allowlist

The explorer's same-origin proxy (`apps/explorer/functions/rpc.js`) carries a
read-only method allowlist that must be regenerated for V4 — it currently
lists G3 methods including four that die (§1) and none of §4. V4 allowlist =
§3.7 survivors + §2 replacements + §4 additions, minus `sendrawtransaction`
(the proxy is read-only; wallets submit via their own endpoints). Keep
`getattestation` on it only if the archive/G4 host actually runs SIS-Linux;
an allowlisted method that always answers `attested: false` invites
misreading.

## 8. Sequencing

1. This document + the superseded notes above feed the **OpenAPI V4 major**;
   freezing that file is the scheduling lever for all seven consumers
   (ecosystem plan §8.1).
2. DEV-3 implements against the frozen `bloch-pos-committee` interfaces; the
   new methods are read layers over `Registry`, `rewards`, and the finality
   state — no new consensus surface.
3. The G3 archive node keeps the **V3** surface verbatim (frozen, read-only)
   so history stays queryable; V4 methods never appear there, V3 mining
   methods never appear on G4. Two chains, two contracts, no straddling
   client.
