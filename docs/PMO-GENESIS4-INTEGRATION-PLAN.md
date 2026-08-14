<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Genesis-4 — Integration Plan for the Four Remaining Items

> **Status as of 2026-08-14 — three of the four items have shipped.** This plan
> was written on 2026-08-13, before Genesis-4 went live at 21:31:19 UTC that
> day. Read it as the engineering record of how the launch was sequenced, not
> as a list of outstanding work.
>
> | Item | Status |
> |---|---|
> | 1. PoS RPC | **Shipped.** `crates/bloch-pos-node/src/rpc.rs`; served on `--rpc-bind`:`--rpc-port`, default `127.0.0.1:16310`. Public read at `https://posternlabs.com/g4rpc`. |
> | 2. `Transfer` with value | **Shipped.** `PosTransaction::Transfer` carries real `inputs` and `outputs` (`crates/bloch-pos-committee/src/transition.rs:242-262`). |
> | 3. Carryover ingestion at genesis | **Shipped and executed.** `Manifest::ingest_carryover` (`crates/bloch-pos-node/src/genesis.rs`); the chain opened with 452,726 carried outputs totalling 18,146,400,000 BLOCH, measured at Genesis-3 chain height 39,918. |
> | 4. Production network | **NOT shipped.** The live fleet still runs `Transport::Devnet` — a point-to-point TCP full mesh with a fixed peer list, no discovery and no authentication, which is why a third party cannot yet join the network. A libp2p module exists in-tree; it is not what the fleet runs. |
>
> Two things this plan does not cover that are now the binding limitations, and
> that anyone reading it for current status must know:
>
> - **`Deposit` and `Delegate` are refused at every node's mempool**
>   (`crates/bloch-pos-node/src/engine.rs:1900-1906`) because bonding is not yet
>   funded from the UTXO set. Combined with item 4, there is **no permissionless
>   path to becoming a validator today.**
> - **All 64 Genesis-4 validators are operated by a single entity**, 93.94% of
>   the carryover sits at one address, and 56,046,829,380 of the 57,146,400,000
>   BLOCH issued at slot 0 is held by the founder (27.04% of the 100 B cap) and
>   the Foundation (a further 29.00%). One operator can halt the chain and one
>   holder can outvote every other. The Nakamoto coefficient is 1.
>
> Where this document says "devnet" it means the **transport**, which is
> accurate. The chain, the network and the binary are **mainnet**.

```
Document:   PMO-GENESIS4-INTEGRATION-PLAN
Status:     PLAN — for DEV assignment; no production code written by this pass
Created:    2026-08-13
Owner:      PMO
Method:     read of crates/bloch-pos-committee/ and crates/bloch-pos-node/ at
            c633449 on branch worktree-agent-afb34b81b0474a587, plus a measured
            build and test run (§1). file:line cited where code exists;
            "does not exist" written where it does not.
Relates:    BLOCH-POS-NODE-INTEGRATION.md (module ownership, §1.2),
            BLOCH-RPC-V4.md (the surface item 1 implements),
            BLOCH-POS-GAPS.md (2026-08-11 inventory — now partly stale, §8)
Scope:      the four items the founder ranked: (1) PoS RPC, (2) Transfer with
            value, (3) carryover ingestion at genesis, (4) production network.
```

The one-line summary: **items 1, 3 and 4 are additive and can run in parallel
behind one small serialized preparation PR. Item 2 is the only one that
redefines consensus bytes, it is the only one that must be sequenced, and half
of item 1 is silently blocked on it.**

---

## 1. Measured baseline (what was actually run, on this tree)

| Command | Result |
|---|---|
| `cargo test -p bloch-pos-committee -p bloch-pos-node --no-run` | exit 0; 5 warnings, all `never used` constants in `crates/bloch-pos-node/src/genesis.rs:119-124` (`VC`, `MARKETING`, `LIQUIDITY`, `VALIDATOR_EMISSION` allocation tags) |
| `cargo test -p bloch-pos-committee -p bloch-pos-node` | exit 0 — **381 tests, 381 passed, 0 failed** across 8 binaries |

Per-binary, from the same run:

```
bloch_pos_committee (lib)   198 passed   62.52s
tests/committee.rs          102 passed    0.55s
tests/e2e.rs                  5 passed  504.78s   ← outlier
tests/one_state_root.rs       5 passed    0.00s
bloch_pos (bin, unit)        27 passed    0.18s
tests/schedule.rs            15 passed    0.13s
tests/properties.rs          27 passed    0.48s
(codec/store)                 2 passed    0.14s
```

Two facts worth carrying into planning:

- **`tests/e2e.rs` costs 505 seconds for 5 tests.** It is 99% of suite wall
  time. Every one of the four items will touch code this suite covers; at this
  cost no one will run it per-commit, which is how a regression lands. Budget a
  task to bisect that runtime before the streams start, or accept that the
  effective pre-merge gate is the other 376 tests.
- The tree is green today. Any red after this plan starts is attributable.

Not run: `cargo test --workspace` (the root Genesis-3 package), `cargo clippy`,
any multi-node devnet. See §10.

---

## 2. The consensus-format ruling — what moves block identity and what does not

This decides what can land without a flag day, so it comes before the items.

There is exactly one block identity and one derivation path
(`crates/bloch-pos-committee/src/header.rs:265`, `BlockId::of`), enforced by a
source-scanning test (`header.rs:626`, `single_derivation_path`) and pinned by
a known-answer test (`header.rs:531`, `known_answer_identity`). Identity is
`SHA3-256(DS_BLOCK ‖ canonical_serialize(header))` over a **fixed 304-byte**
header (`header.rs:120`, `ENCODED_LEN`), and every field is proven to move the
id (`header.rs:438`).

Two of those 304 bytes' fields are the roots the four items can reach:

```
PosTransaction::canonical_bytes   transition.rs:297
        │
        ▼
derive::body_root                 derive.rs:402
        │
        ▼
header.body_root ─────────────┐
                              ├──► canonical_serialize ──► BlockId::of ──► identity
CommittedState::compute_root  │                                            header.rs:130/265
        transition.rs:874     │
        │                     │
        ▼                     │
header.state_root ────────────┘
```

Therefore:

| Change | Moves `body_root`? | Moves `state_root`? | Moves block id? | Flag day needed on a *running* chain? |
|---|---|---|---|---|
| **Item 1 — RPC** | no | no | **no** | **no** |
| **Item 2 — Transfer with value** | **yes** | **yes** (spends mutate `eutxos`; a real fee debit mutates balances) | **yes** | **yes** |
| **Item 3 — carryover ingestion** | no | **yes**, from block 1 onward | yes, from block 1 | **yes** |
| **Item 4 — libp2p transport** | no | no | **no** | no — but see §6.3 |

Three consequences the PMO should treat as rulings:

1. **Items 1 and 4 are not consensus changes and never need a flag day.** They
   can land before or after launch. Nothing in them touches `canonical_bytes`,
   `body_root`, `compute_root` or the header layout.
2. **Items 2 and 3 must land before Genesis-4 starts, or never.** Both change
   the state root of every block. Before launch that costs nothing — there is
   no chain and no peer to break. After launch each is a hard fork.
3. **Adding or removing a header field is categorically different** from all
   four items: it changes `ENCODED_LEN` and breaks `known_answer_identity`
   (`header.rs:534`, whose message already says *"canonical encoding or
   DS_BLOCK changed: hard fork"*). None of the four items requires this. If a
   design discussion starts proposing a header field, it has left this plan's
   scope.

### 2.1 The genesis block is a special case, and it is currently under-committed

`Manifest::genesis_header()` (`crates/bloch-pos-node/src/genesis.rs:274-289`)
hardcodes `state_root: [0u8; 32]` (`:278`). The genesis block's header does
**not** commit to the genesis state.

The practical effect on item 3: seeding the carryover changes
`genesis_state()` but **not** `genesis_id()`. Networks are separated instead by
the manifest digest — SHA3-256 over the manifest bytes, checked in
`Store::open` (`crates/bloch-pos-node/src/store.rs:44-79`) and used to derive
the network id (`ws_boot.rs:98`) — and the manifest does carry the
`CarryoverCommitment` (`genesis.rs:146-154`). So the *commitment* is bound to
network identity; the *file that satisfies it* is bound to nothing.

Two nodes given the same manifest and **different** carryover files therefore
agree on block 0, boot happily, and diverge at block 1 with a
`StateRootMismatch`. That is a late, confusing failure of exactly the shape
this codebase has been burned by twice. **Recommendation: while item 3 is open
in this file anyway, populate `genesis_header().state_root` with the computed
root.** It is a three-line change in the same function, it makes the failure
happen at boot instead of at block 1, and pre-launch it is free.

---

## 3. Item 1 — the PoS RPC

### 3.1 Starting position, measured

There is no RPC, no HTTP, no serde, and no async runtime in the Genesis-4 tree.
`crates/bloch-pos-node/Cargo.toml` `[dependencies]` is three lines
(`bloch-pos-committee`, `bloch-crypto`, `sha3`). The node is `std::thread` +
`std::sync::mpsc` throughout.

**A naming correction that matters, because it has already misled a reader of
this tree:** `crates/bloch-pos-committee/src/ws.rs` and
`crates/bloch-pos-node/src/ws_boot.rs` are **weak subjectivity**, not
WebSocket. They are checkpoint format, verification and boot policy
(`ws.rs:3`). Nothing in Genesis-4 opens an HTTP or WebSocket socket. The only
listening socket in the binary is the devnet TCP mesh at `net.rs:183`.

The surface to implement is already specified: `docs/specs/BLOCH-RPC-V4.md`
(402 lines) — methods, error convention (R4: real JSON-RPC `error` objects),
and the amount encoding rule (R3: **all satoshi fields are decimal strings**,
because 10^19 sat is 1,110× JavaScript's exact-integer limit).

### 3.2 What it touches

| File | Change | Size |
|---|---|---|
| `crates/bloch-pos-node/Cargo.toml` | + `axum`/`tokio`/`serde`/`serde_json` | small, but see §7.1 |
| `crates/bloch-pos-node/src/rpc/` (new) | the whole surface | large, self-contained |
| `crates/bloch-pos-node/src/engine.rs:625-700` (`apply_canonical`), `:705-792` (`do_reorg`) | publish a read snapshot | ~10 lines, 2 sites |
| `crates/bloch-pos-node/src/engine.rs:84-95` (`Config`) | `rpc_listen: Option<...>` | 1 field |
| `crates/bloch-pos-node/src/main.rs:282-316`, `:85-126` | flags + help | small, PMO-controlled |
| `crates/bloch-pos-node/src/store.rs` | indexes (see below) | large |

### 3.3 What breaks

- **The single-writer invariant is the thing to protect.** `Engine` is private
  and stack-local inside `run()` (`engine.rs:129`, `:826`); there is **no
  `Mutex` or `RwLock` anywhere** in the node, and exactly one shared handle —
  `head_slot: Arc<AtomicU64>` (`engine.rs:156`). `BLOCH-POS-NODE-INTEGRATION.md`
  §1.1 requires that RPC "never hold a reference into consensus state". An RPC
  that takes a lock on `CommittedState` violates the architecture.
  - **Write path is already free:** clone the `Sender<NetEvent>` created at
    `engine.rs:863`; `NetEvent` (`net.rs:45`) already carries
    `Transaction(PosTransaction)`. `sendrawtransaction` costs no engine change.
  - **Read path:** publish an `Arc<ChainSnapshot>` (arc-swap or `RwLock` over a
    cheap immutable struct) at the two — and only two — sites where the
    canonical chain moves: `apply_canonical` and `do_reorg`. Precedent exists:
    `head_slot.store(...)` already happens at `engine.rs:642` and `:767`.
- **`bloch-pos-committee` must not gain serde.** Its purity is an explicit
  contract (`BLOCH-POS-NODE-INTEGRATION.md` §2: *"Nothing in this plan adds a
  dependency to it"*; the crate has one dependency, `sha3`). All JSON
  serialization lives in the node's `rpc/` module, hand-written against the
  committee types. This is not optional and it is the most likely thing for a
  DEV to get wrong under deadline.
- **`StateReader` is frozen** (`interfaces.rs:455-490`, two-reviewer rule at
  `:66-72`). An RPC needing a value it does not expose must **not** add a
  method to it — the RPC is a consumer, not a consensus rule. Add a node-side
  view type instead.
- **Storage cannot answer normal RPC questions.** `store.rs` (166 lines) is an
  append-only block log with four methods: `open`, `append`, `read_all`,
  `rewrite`, plus `blocks_after(&Path, u64)` (`:152`) which rescans the whole
  file per call. There is **no** block-by-id index, **no** tx index, **no**
  address/script-hash index, and **no height concept at all** — only `slot`
  (`header.rs:97`), which is sparse because skipped slots produce no block.
  `getblockbyheight` in the RPC spec has no backing data structure.

### 3.4 The split nobody has costed yet

**The RPC is two products, and only one of them is buildable today.**

| Buildable now (reads consensus state that exists) | Blocked |
|---|---|
| `getchaininfo`, `getblockcount`, `getblock`/`getblockhash` (by slot/id), `getepochinfo`, `getvalidators`, `getvalidator`, `getstakinginfo`, `getcheckpoints`, `getepochattestations`, `getpeerinfo`, `getslotstats` | `getbalance`, `getutxos`, `getaddressinfo`, `getaddressbalance_at_height`, `listtransactions`, `gettransaction`, `gettxstatus`, `decoderawtransaction`, `getsupplydistribution` |

The blocked column needs items 2 and 3. Specifically:

- `CommittedState.eutxos` (`transition.rs:676`) is a **private field with no
  accessor** — nothing outside `transition.rs` can read a balance. A
  `getbalance` has nothing to return.
- There is **no txid derivation for any transaction** anywhere in the tree.
  `EutxoEntry.txid` is produced only at genesis, by
  `Manifest::allocation_outputs` (`genesis.rs:350-356`). `gettxstatus [txid]`
  has no txid to be given.
- `getsupplydistribution` per `BLOCH-RPC-V4.md` §3.5 reports carryover
  vs. allocations — meaningless until item 3 seeds the carryover.

**PMO action:** the founder ranked RPC first *because it is what a partner
integration consumes*. A partner consumes balances and transaction status —
the blocked column. Ship the left column as "chain and staking telemetry" and
do not describe it to a partner as an integration surface until item 2 lands.
Setting that expectation now is cheaper than retracting it later.

---

## 4. Item 2 — `Transfer` with value

### 4.1 Starting position, measured

`PosTransaction::Transfer` (`transition.rs:189-201`) is
`{ inputs: u32, tx_bytes: u64, tip_millisat_per_gas: u128 }` — 29 bytes on the
wire (`transition.rs:304-309`), pinned byte-for-byte by
`tests::transfer_encoding_is_gas_priced_not_declared` (`transition.rs:3036`).
It has no sender, no recipient and no amount, and `transition.rs:672-675` says
so plainly.

Its validation arm, in full (`transition.rs:1131-1138`), computes a gas charge
and returns `Ok`. **It is total — it cannot fail.** No balance check, no
signature check, no UTXO existence check, no double-spend check. Compare
`Deposit` (`:1149-1162`), `Exit` (`:1192-1202`) and `Delegate` (`:1213-1221`),
which all validate.

The pieces that already exist and are waiting:

- `SignatureVerifier::verify_with_key(pubkey: &[u8], signing_root: &[u8; 32],
  signature: &[u8]) -> bool` (`attestation.rs:106`) — written *for* this, per
  its own doc at `:93-105`, and with **zero production call sites** today.
  Real impl: `crates/bloch-pos-node/src/keys.rs:133`.
- `CommittedState.eutxos: BTreeMap<([u8;32], u32), EutxoEntry>`
  (`transition.rs:676`), committed under `TAG_EUTXO = 0x01`
  (`state_root.rs:122`, inserted at `:1079-1081`).
- `interfaces::UtxoRef { txid: [u8;32], vout: u32 }` (`interfaces.rs:154`) —
  **field-identical to the `eutxos` map key**. Reuse it; do not invent a
  second outpoint type.
- A complete, tested, **unwired** eUTXO reference implementation in
  `crates/bloch-euvm/src/lib.rs`: `EuTx` (`:599`), `validate_tx` (`:704`) with
  real per-asset value conservation (`:710-727`), `ExtOutput.validator_hash`
  (`:76`) — the same `[u8; 32]` shape as `EutxoEntry.script_hash`.

### 4.2 What must be built (none of it exists)

1. **A txid derivation.** Domain-separated, per §5.4 discipline. This is a new
   consensus primitive and needs a KAT.
2. **A spend signing root** and a `DS_SPEND` domain tag. `params.rs:73-97`
   currently has `DS_ATTEST`, `DS_BLOCK`, `DS_STATE`, `DS_DEPOSIT`,
   `DS_PROPOSE`, `DS_BODY`. A new tag must be 16 bytes, zero-padded, and
   pairwise-distinct — `header.rs:734` (`domain_tag_shape`) and `main.rs`'s
   selfcheck both police this.
3. **Accessors on `eutxos`** and on `EutxoEntry::entry_key`/`serialize`, which
   are private (`state_root.rs:419`, `:425`).
4. **The fee debit.** Today fees are computed and *credited* to the proposer
   (`transition.rs:1980-1984`) but **never taken from anyone** — the payer side
   is created from nothing. Giving `Transfer` value semantics necessarily makes
   the fee a real debit. This is the largest conceptual change in the item and
   it cross-couples with `issued_sat` (`transition.rs:652`) and the supply cap
   check (`:1814`).

### 4.3 The encoding decision — and why the in-code advice should be revisited

`transition.rs:281-284` instructs that the real transfer format arrive as a
**new discriminant**, because "the discriminant tag makes that a widening
rather than a re-keying". `from_canonical_bytes` is strict on both ends
(`:416` unknown tag, `:420-422` trailing bytes), so widening tag `0x01` in
place is a hard break: old nodes reject new transfers as `TrailingBytes`, new
nodes reject old ones as truncated.

**That advice was written for a running chain. Genesis-4 has not launched.**
Before launch there are no peers to break and no history to keep decodable.
Taking the new-discriminant route now buys nothing and costs permanently: the
gas-only `Transfer` at tag `0x01` becomes vestigial, must be kept decodable
forever, and every future reader has to learn why two transfer types exist.

**PMO recommendation: redefine tag `0x01` in place, before launch**, update
`transfer_encoding_is_gas_priced_not_declared` (`transition.rs:3036`) to pin
the new bytes, and record the decision in an ADR. Reserve the
new-discriminant route for any change that lands *after* the genesis block
exists. This needs a founder/DEV-1 ruling either way — it is listed as
open item 3 in `BLOCH-POS-NODE-INTEGRATION.md` §8 and is marked there as
**blocking `apply_block` beyond fixtures**.

### 4.4 What breaks

- `body_root` for every block containing a transfer → block identity. Expected;
  pre-launch it is free.
- `derive::ChainState` (`derive.rs:66`) carries a **second** `eutxos: Vec<EutxoEntry>`
  (`:70`) rooted independently (`:134-137`). `derive::validate_block` was
  deleted, but `ChainState` is still `pub` and re-exported (`lib.rs:119`). Any
  new eUTXO component must be threaded through both or they silently diverge —
  this is precisely the failure `tests/one_state_root.rs` was written about.
  **Consider deleting `ChainState` as part of this item** rather than
  maintaining a second carrier.
- The field-coverage test `every_committed_state_field_is_bound_by_the_root`
  (`transition.rs:3448`, mutation list `:3462-3568`) has **no entry for
  `eutxos`** (nor `issued_sat`). eUTXO sensitivity is pinned one layer down at
  `state_root.rs:1573-1577`. Adding `must_move!("eutxos", …)` is cheap and
  belongs in this item.
- Mempool admission (`engine.rs:589`, `on_transaction`) currently admits
  anything that decodes. With real value it needs balance/double-spend
  screening or it is a free DoS surface.
- `inputs` and `tx_bytes` are today unconstrained and unbacked — a transfer can
  declare `inputs: 4_000_000_000` and pay gas it cannot fund. Only the
  block-level caps (`:1968`, `:1971`) bound it. Real funding closes this.

### 4.5 Out of scope, and say so out loud

`Deposit` (`transition.rs:1166-1181`) and `Delegate` (`:1222-1233`) **mint
stake from nothing** — neither carries funding inputs. Staking value and eUTXO
value are two disjoint pots with no bridge, and the key spaces do not even
match (`u32` validator/delegator index vs. 32-byte `script_hash`).
`withdrawal_credentials` is deliberately format-free (`interfaces.rs:177-182`),
so withdrawals have no destination either.

Item 2 as scoped does **not** fix this. Fixing it is a fifth item ("staking is
funded by real coins"), and it should be named as such rather than discovered
mid-sprint when someone notices a validator can bond 10 B BLCH it never had.

---

## 5. Item 3 — carryover ingestion at genesis

### 5.1 Starting position, measured

The commitment type exists and is fully plumbed through encode/decode:
`CarryoverCommitment { digest: [u8;32], entry_count: u64, total_sat: u128 }`
(`genesis.rs:82-94`), encoded at `:146-154`, decoded at `:199-209`.

**Nothing consumes `digest` or `entry_count`.** Exhaustive grep across the repo
finds `CarryoverCommitment` only in `genesis.rs` itself. No code hashes a
snapshot file and compares; no code counts entries and compares. Only
`total_sat` participates in arithmetic (`genesis_issued_sat`, `:228-231`). The
doc comment at `:70-74` describes ingestion that does not exist.

Worse: `check_supply()` (`:240-261`) — the function that would catch a wrong
total — **is never called on the load path**. `Manifest::load` (`:263-269`)
does not call it and `engine::run` does not call it. Its only caller is
`main.rs:262`, inside `genesis_cmd`, i.e. when *writing* a devnet manifest,
where `carryover` is hardcoded `None` (`main.rs:259`). **The
`carryover.is_some()` branch at `:253` can never fire today.**

The seam to fill is a single argument. `Manifest::genesis_state()`
(`genesis.rs:298-331`) calls `CommittedState::genesis(…, &self.allocation_outputs())`
at `:329`; that last parameter is `opening_balances: &[EutxoEntry]`
(`transition.rs:698`), stored into the map at `:769-772`. Item 3 is, at its
core: **parse the TSV into `Vec<EutxoEntry>`, verify it against the
commitment, concatenate with `allocation_outputs()`, pass it at `:329`.**

And the shapes line up exactly. `EutxoEntry` is
`{ txid: [u8;32], vout: u32, value: u64, script_hash: [u8;32] }`
(`state_root.rs:406-417`); the key is `(txid, vout)` — literally the TSV's
first two columns.

### 5.2 Reuse: the legacy loader is a straight lift

`src/storage/mod.rs` (Genesis-3 tree) already parses **this exact format**:

- `parse_carryover_line` (`src/storage/mod.rs:1235-1250`) — splits on `\t`,
  requires a 32-byte hex txid (`:1242`), `u32` vout, `u64` value, hex 4th
  column, rejects a 5th column, rejects `value == 0` (`:1248`).
- `parse_carryover_inner` (`:1163-1233`) — unique-outpoint enforcement
  (`:1193-1205`), malformed lines are failures not skips (`:1209-1216`),
  accumulates all errors rather than short-circuiting.
- `verify_carryover_snapshot` (`:1102-1121`) — compares against a
  `(root, count, total_sat)` triple. **That is exactly the
  `CarryoverCommitment` triple.**

The parser is pure and depends only on `hex` + `sha3`. Lift it; do not rewrite
it. Two adaptations are required, and both are decisions, not typing:

### 5.3 Three decisions that block this item

**D1 — the dust rule for the 100/21 split. Unresolved in code, and the code
says so.** `tokenomics_v4.rs:57-67`:

> *"This is the function the carryover rebuild must apply per balance. It
> truncates: a balance not divisible by 21 loses up to 20/21 of a satoshi. The
> ceremony pins the artifact's TOTAL against `CARRYOVER_TOTAL_BLOCH` exactly,
> so the builder must state its dust rule (who absorbs the sub-satoshi
> remainders) and make the rows sum to the pinned figure — **truncate-and-hope
> does not close the accounting**."*

Concretely: the snapshot is 452,133 outputs totalling 3,805,746,000 BLCH
(pre-split). `CARRYOVER_TOTAL_BLOCH = 18_122_600_000` (`tokenomics_v4.rs:187`),
and `3,805,746,000 × 100 / 21 = 18,122,600,000` **exactly** at the aggregate.
Per row it does not divide: truncating each of 452,133 rows loses under 1 sat
each, so the row sum can fall short of the pinned total by up to ~452,133 sat
(≈0.0045 BLCH). `check_supply` demands **exact** equality (`genesis.rs:253`),
so even a 1-sat shortfall is a hard refusal. Someone must name who absorbs the
remainder. This is a founder/tokenomics call, not a DEV call.

**D2 — which hash, and over what.** The legacy loader digests with
**SHAKE-256 over the file's raw bytes** (`src/storage/mod.rs:1172-1175`).
`CarryoverCommitment::digest` is documented as **SHA3-256**
(`genesis.rs:85`). The snapshot root supplied for this work
(`162cb763…6d8714da`) is recorded as SHAKE-256 and is pinned in-tree as
`CARRYOVER_MEASURED_ROOT` (`tokenomics_v4.rs:194-197`). Pick one and make the
doc, the constant and the loader agree. Nothing consumes the field yet, so
either side can move at zero cost — today.

**D3 — what the 4th column is.** The legacy TSV's 4th column is a raw
variable-length `scriptPubKey`; `EutxoEntry.script_hash` is a fixed 32-byte
SHA3-256. If the new snapshot's column is already a 32-byte script hash it
drops straight in; if it is a raw script, `script_hash = SHA3-256(script)` must
be defined and pinned. **No code in the repo performs that hashing today** —
`script_hash` has zero references in `transition.rs`.

### 5.4 What it touches, and what breaks

Touches: `crates/bloch-pos-node/src/genesis.rs` (loader + the call at `:329`),
a new `carryover.rs` module in the node, `main.rs` (a `--carryover-snapshot`
flag), and the boot path in `engine.rs` (call `check_supply` on load — see
below).

Breaks: `state_root` of block 1 onward (expected, §2). Also:

- **`issued_sat` is already wrong on devnet.** `CommittedState::genesis`
  unconditionally sets `issued_sat = GENESIS_ISSUED_SAT`
  (`transition.rs:768`) — 57.12 B BLCH — even for a devnet whose eUTXO set is
  empty. Item 3 should make issuance follow the actual opening balances.
- **`unlock_epoch` is committed into the allocation txid preimage but not into
  state.** `EutxoEntry` has no vesting field and nothing enforces one. The
  claim at `genesis.rs:100-102` that vesting "is enforced by every node" is
  **not implemented**. Not item 3's job to build, but the doc comment should
  stop asserting it.
- **The test fixture carries stale figures.** `mainnet_sample()`
  (`genesis.rs:414-417`) still uses `entry_count: 413_743` and
  `17_970_880_000` BLCH — the pre-re-measurement numbers. Should be 452,133 and
  18,122,600,000 to match `tokenomics_v4.rs:187/:201`.
- **`check_supply` must start being called at load**, or the whole commitment
  apparatus stays decorative.

### 5.5 A landmine: two incompatible genesis definitions coexist

`tools/genesis4-ceremony/src/lib.rs` defines its **own** `state_root`
(`:820-840`) as a flat SHA3 over concatenated roots — a completely different
construction from `bloch_pos_committee::state_root::state_root`
(`state_root.rs:1172`), which is a 256-deep SMT. Its `genesis_header`
(`:894-928`) also differs from `Manifest::genesis_header`: it sets a **non-zero**
`state_root` and derives `randao_mix` from the carryover digest, versus
`genesis.rs`'s all-zero `state_root` and `GENESIS_MIX = [0;32]`.

It also reads a **different file format** — 2-column, address-aggregated,
ascending-order (`lib.rs:177-210`) — produced by
`tools/genesis4-carryover/build_carryover.py`, versus the 4-column per-UTXO
format everything else uses.

And `tools/genesis4-ceremony/Cargo.toml` declares its own `[workspace]`; the
root `Cargo.toml` members list does not include `tools/`. **CI never builds it
and never cross-checks the two genesis definitions.** Whichever one is
authoritative, the other must be deleted or explicitly sealed as superseded
before launch. This is the single highest-risk item in this document, because
both will produce a confident, well-tested, *different* genesis.

---

## 6. Item 4 — production network

### 6.1 Starting position, measured

`crates/bloch-pos-node/src/net.rs` (264 lines) says of itself: *"This is not
the production network layer"* (`:5`). It is blocking `std::net`, one OS thread
per connection, a static `--peers` list with no discovery, and a doubly-dialed
full mesh (two TCP connections per pair, `:19-22`). Frame layer is
`u32 LE length ‖ type byte ‖ payload` with four types (`:36-42`). **No
authentication, no admission control, no peer scoring** (`:167-172`).

The port source is in-tree and already locked: `libp2p 0.56` with
`gossipsub`/`noise`/`yamux`/`mdns` (`Cargo.toml:165`), behind the root
package's `node` feature. Code to copy-and-adapt: `src/network/mod.rs` (2360
lines, the swarm + topics + `NetworkMessage`), `src/network/sync_rr.rs` (519,
request-response sync), `src/network/pex_validator.rs` (340, PEX hardening),
`src/transport/upgrade.rs` (the Kyber PQ security upgrade), and
`src/dandelion.rs` (already generic over peer type — directly portable).

### 6.2 The good news: consensus is already transport-agnostic

`crates/bloch-pos-committee/src/gossip.rs` (802 lines) is pure admission
policy with **no sockets, no clock** (`:3-13`). Its entire coupling to a
transport is three injected boundaries:

- `trait CommitteeLookup` (`gossip.rs:124`), blanket-impl'd for `Fn(u64) -> Vec<u32>` (`:128`)
- `trait BlockLookup` (`gossip.rs:135`), blanket-impl'd for `Fn(&[u8;32]) -> bool` (`:139`)
- `&dyn SignatureVerifier`, injected into `process` (`:219`) and `on_block` (`:320`)

Its output enum `GossipDecision { Accept, Ignore, Reject, Hold }` (`:99-116`)
maps onto gossipsub's `report_message_validation_result` verbs, and the type
split exists specifically so the node *cannot* wire an `Ignore` into a peer
penalty (`:79-80`). **libp2p can be swapped underneath without touching
consensus.**

### 6.3 The catch, and why this item is riskier than it looks

`AttestationPool` **has never run**. Grep for it in `crates/bloch-pos-node/`
returns only the comment at `net.rs:13` saying it is *not* wired — the engine
does its own dedup instead. So item 4 is not "swap the transport"; it is
"swap the transport **and** turn on 802 lines of admission policy that has
only ever been exercised by its own unit tests".

And there is a known, recorded divergence waiting for it. `derive.rs:452-464`,
verbatim, records that the producer's attestation filter calls
`crate::slot_subcommittee` (the **superseded** sampled draw) while the
transition's step 8 calls `committees::committee_for_slot` (the **current**
partition):

> *"a producer filtering with this predicate can drop attestations its own
> validator would have accepted, and keep ones it would refuse… Fixing it is a
> change to `produce.rs`'s filter, on a seam this task did not open."*

Under the devnet mesh, where everyone hears everything and blocks are trivially
small, this is masked. Under real gossip with real loss it becomes intermittent
block rejection between honest nodes. **Fix the filter divergence as a
prerequisite to item 4, not as part of it** — it is a small, independently
testable change to `produce.rs`, and bundling it into a 2,000-line network port
is how a consensus bug gets attributed to the network.

Note also that wiring the pool changes *which* attestations end up in blocks,
which moves `attestation_root` and participation, which moves `state_root`.
Item 4 is transport-neutral only if the pool's admission decisions match what
the engine does today. They do not necessarily.

### 6.4 What breaks

- `net.rs` is replaced wholesale; `engine.rs:864-871` (start) and
  `:1042-1065` (the event drain) are rewritten.
- The frame layer gains libp2p's; **keep `codec.rs` and
  `PosTransaction::canonical_bytes` exactly as they are.** There is currently
  one transaction encoding shared by gossip and block bodies (`net.rs:38-40`);
  preserving that is what keeps item 4 off the consensus ledger.
- Today an unknown frame type is silently dropped (`net.rs:137`, `_ => None`)
  with no log and no counter — a new node type propagates while old nodes
  ignore it, and nobody can tell "peer didn't get it" from "peer ignored it".
  The legacy tree has `PROTOCOL_VERSION`/`MIN_PROTOCOL_VERSION`
  (`src/network/mod.rs:74-77`) and an `INGEST_DROPS` counter (`:43-70`) — port
  both; they were built after real incidents.
- Two hard-won fixes must survive the copy or they will be re-discovered in
  production: **no `add_explicit_peer` on every connection**, and **explicit
  `TopicScoreParams`** instead of `..Default::default()` (which inherits a P3
  penalty impossible to satisfy at 30-second slots). Also the yamux
  stream-limit alignment. New protocol prefix so G3 and G4 never mesh.

---

## 7. Merge-conflict analysis

### 7.1 The four-way conflicts — fix these first, in one PR

Three files are touched by **every** item, in the same functions:

| File | Why all four collide |
|---|---|
| `crates/bloch-pos-node/src/main.rs:282-316` (`run_cmd`) and `:85-126` (`print_help`) | every item adds a CLI flag. The file is **PMO change-controlled with a two-reviewer rule** (`main.rs:25-28`), so every conflict is also a process event. |
| `crates/bloch-pos-node/src/engine.rs:84-95` (`Config`) | every flag needs a field, in one struct |
| `crates/bloch-pos-node/Cargo.toml` + the lockfiles | items 1 and 4 both add heavy deps and **both need `tokio`** |

**Mitigation — Phase 0, one serialized PR, PMO-authored:** land all four
items' flags and `Config` fields up front as accepted-but-inert, add `tokio`
once, and take the lockfile decision below. After that PR, each stream fills in
its own field and touches nothing the others touch. This converts four
guaranteed conflicts in a change-controlled file into one scheduled review.

**The lockfile decision that must be taken in Phase 0.**
`crates/bloch-pos-node/` and `crates/bloch-pos-committee/` each carry their own
`Cargo.lock` *and* are listed as members of the root workspace
(`Cargo.toml:6-19`). A workspace member's lockfile is not used when building
from the root, and its `[patch.crates-io]`
(`crates/bloch-pos-node/Cargo.toml`) is ignored there too. So dependency
resolution differs depending on which directory you build from. Both
dep-adding items will trip over this.

**Measured, this pass:** the committed root `Cargo.lock` contains **no**
`bloch-pos-committee` and **no** `bloch-pos-node` entries. Running
`cargo test -p bloch-pos-committee -p bloch-pos-node` from the repo root adds
17 lines to it. So nobody has built the workspace from the root since these
crates became members — which is precisely the condition
`BLOCH-POS-GAPS.md` warned about when it made them members: *"the first
command any reviewer runs tested the retired PoW node and none of the PoS
consensus."* The lockfile drift is the proof that the fix is not yet load-
bearing. (This pass reverted the lockfile rather than commit an unrelated
change; landing it belongs in Phase 0.)

Decide now: member of the root workspace
(delete the inner lockfiles and the inner `[patch]`), or standalone (remove
from root members). Note this also contradicts
`BLOCH-POS-NODE-INTEGRATION.md` §0/§7.1, which still describes these crates as
never being root members — see §8.

### 7.2 The pairwise matrix

`—` no contact · `·` light · `▲` real conflict risk

| File | 1 RPC | 2 Transfer | 3 Carryover | 4 Net |
|---|---|---|---|---|
| `committee/transition.rs` | · (needs accessors) | ▲ **heavy** | · (`genesis` args) | — |
| `committee/state_root.rs` | — | ▲ (new tags, expose privates) | · | — |
| `committee/derive.rs` | — | ▲ (`ChainState` mirror) | — | · (filter fix) |
| `committee/gossip.rs` | — | — | — | ▲ **heavy** |
| `committee/params.rs` | — | · (`DS_SPEND`) | — | — |
| `node/genesis.rs` | — | — | ▲ **heavy** | — |
| `node/engine.rs` | ▲ (snapshot publish) | ▲ (mempool, tx path) | · (boot) | ▲ **heavy** (rip out net) |
| `node/net.rs` | — | — | — | ▲ replaced |
| `node/store.rs` | ▲ (indexes) | · | — | · |
| `node/codec.rs` | — | · | — | ▲ |
| `node/main.rs` | ▲ | ▲ | ▲ | ▲ |

The two genuine pairwise hazards:

- **Item 2 × item 3 in `transition.rs`.** Textually they are far apart
  (`CommittedState::genesis` at `:683` vs. `apply_transaction` at `:1118`), so
  git will merge them. **The coupling is semantic, not textual**, which is
  worse: item 2's spend path must handle carryover-seeded UTXOs, and item 2's
  fee debit must reconcile with item 3's `issued_sat` accounting. Sequence
  them — 3 then 2 — and the coupling resolves itself.
- **Items 1, 2 and 4 in `engine.rs`.** They touch different functions
  (`apply_canonical`/`do_reorg` vs. `on_transaction`/`select_transactions` vs.
  `run`'s startup and event drain), so conflicts are mechanical **provided item
  4 does not reorder `run()`'s body**. Land item 4's engine surgery on its own,
  with the other two rebasing onto it.

---

## 8. Ordering and parallelization

```
Phase 0  (serialized, PMO, small)
  └─ flags + Config fields inert · tokio once · lockfile ruling · e2e runtime triage
     └─────────────┬──────────────┬───────────────────────┐
                   │              │                       │
Phase 1 (parallel) │              │                       │
   Item 3 ─────────┤   Item 1a ───┤   Item 4 prereq ──────┤
   carryover       │   RPC: chain │   produce.rs filter   │
   ingestion       │   + staking  │   divergence fix      │
   (D1/D2/D3 first)│   reads      │   (derive.rs:452-464) │
                   │              │                       │
                   │              │   Item 4 ─────────────┤
                   │              │   libp2p port +       │
                   │              │   wire AttestationPool│
                   ▼              │                       │
Phase 2 (serialized after 3)      │                       │
   Item 2 ────────────────────────┤                       │
   Transfer with value            │                       │
   (needs D4 encoding ruling)     │                       │
                   │              │                       │
                   ▼              ▼                       ▼
Phase 3
   Item 1b — RPC wallet half (getbalance/getutxos/gettxstatus),
             unblocked only now; + store.rs indexes
```

Why this shape:

- **Item 3 is the true head of the critical path**, not item 1. It is
  self-contained (one file plus a lifted parser), it is blocked only by
  decisions D1–D3 which are *founder* decisions available today, and both
  item 2 and the RPC's wallet half depend on it. Start the decisions now.
- **Item 1 splits** (§3.4). Its left column parallelizes immediately; its right
  column is Phase 3 whatever anyone wishes.
- **Item 4 has a prerequisite** (§6.3) that is small and independently testable.
  Doing it first keeps consensus bugs from being attributed to the network port.
- **Item 2 is alone in Phase 2** by design — it is the only consensus-format
  change, and it should land against a green tree with nothing else in flight.

Genuinely parallel with zero contact: **item 3 × item 4** (disjoint files
entirely), and **item 1a × item 3**.

---

## 9. Stale documentation this pass falsified

Correcting these is cheap now and expensive after someone plans against them.

1. **`BLOCH-POS-GAPS.md` (2026-08-11) is materially out of date.** It states
   the node is "a 134-line skeleton" with "zero lines" for `store/`, `net/`,
   `genesis/`; the node is now ~3,600 lines across `engine.rs` (1303),
   `ws_boot.rs` (949), `genesis.rs` (577), `main.rs` (378), `net.rs` (264),
   `codec.rs` (246), `store.rs` (166), `keys.rs` (159). **GAP-3 is fixed**
   (`PosTransaction::SlashingEvidence` exists, `transition.rs:251`). **GAP-2 is
   half-fixed** — the parallel validator was deleted (commit `a79f322`), but a
   *new* divergence was recorded 2026-08-12 (`derive.rs:452-464`, §6.3).
2. **`BLOCH-POS-NODE-INTEGRATION.md` §0/§7.1** says the PoS crates carry their
   own `[workspace]` and are "not a member of the node workspace". The root
   `Cargo.toml:6-19` now lists both as members. Documented architecture no
   longer matches the build graph (§7.1).
3. **`tokenomics_v4.rs` prose drift**, two instances: the `EMISSION_DUST_SAT`
   doc block (`:588-596`) reasons to 176,880 sat while the constant (`:597`)
   and its test are 772,880; and the `annual_inflation_bps` doc (`:564-567`)
   says 436 / 4.36% while the asserted value is **435** (`fee_market.rs:529`,
   `tests/committee.rs:663`). The constants are right and the prose is wrong in
   both cases — but a reader auditing tokenomics reads the prose.
4. **`genesis.rs:100-102`** asserts vesting "is enforced by every node".
   `EutxoEntry` has no vesting field and nothing enforces one (§5.4).
5. **`genesis.rs:70-74`** describes carryover ingestion ("the node ingests the
   snapshot file separately and refuses it unless all three agree") that does
   not exist (§5.1).
6. **`genesis.rs:414-417`** test fixture carries superseded carryover figures.

---

## 10. What I did not do

Stated plainly, because a plan that hides its gaps is worth less than a shorter
honest one.

- **I wrote no production code.** The only file added by this pass is this
  document.
- **I did not touch anything in production.** No SSH, no deploy, no
  `~/dev/posternlabs-deploy`, no contact with the live Genesis-3 chain, the
  fleet, or any node. Nothing was read from `136.244.82.226`; the snapshot
  figures in §5 are taken from the constants already committed in
  `tokenomics_v4.rs` and from the task brief, **not** re-measured from the
  file.
- **I generated no keys of any kind.**
- **I did not `git push`.** The commit is on this worktree branch only.
- **I did not verify the snapshot.** I never read
  `g3-balances-20260813-100920.tsv`. I did not recompute its SHAKE-256 root, did
  not count its rows, did not sum its values, and did not check whether its 4th
  column is a raw `scriptPubKey` or an already-hashed 32-byte value — D3 (§5.3)
  is open *because* I could not check it. Every claim about the file's format
  is inferred from the legacy parser (`src/storage/mod.rs:1235-1250`) and the
  brief.
- **I did not run the full workspace suite** — only
  `-p bloch-pos-committee -p bloch-pos-node` (§1). The root Genesis-3 package,
  `tools/genesis4-ceremony` (which is outside the workspace entirely) and
  `cargo clippy` were not run. The §5.5 claim that the ceremony's genesis
  differs from the node's is from reading both, not from executing them and
  diffing the output — **that comparison is the single most valuable thing to
  do next**, and it is a half-day of work.
- **I did not estimate effort or dates.** The sequencing in §8 is a dependency
  order, not a schedule; sizing belongs to the DEVs who will do it.
- **The e2e suite's 505 seconds is measured but undiagnosed.** I did not
  profile which of the 5 tests dominates.
