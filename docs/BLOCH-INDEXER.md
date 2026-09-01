# The Genesis-4 historical index

**Status: unaudited. Read-only against production. Not a consensus component.**

`tools/bloch-indexer` builds a historical index over a Genesis-4 `blocks.log`
and serves it over a small HTTP/JSON read API, so that an explorer never has to
ask a validator a historical question.

---

## 1. Why this is a safety requirement and not a performance nicety

A Genesis-4 node answers about **current state only**:

| Question | What the node offers |
|---|---|
| balance of an address | `getbalance` — sums the eUTXO set **as it is now** |
| a block | `getblockbyslot` / `getblockbyid` — one header summary, with `tx_count`, **not the transactions** |
| a transaction | `gettransaction` — **refuses**: `RpcError::no_transaction_index()` |
| an address over time | nothing |
| epoch, finality, participation history | nothing |
| supply over time | nothing (`getsupply` and `getissuance` are listed as proposed, not built) |

So every historical question decomposes into a burst of RPC calls. That RPC has
**no authentication and no rate limiting**, and it is served by the thread that
runs consensus — `rpc.rs` says so in those words: *"the node's consensus thread
must survive its RPC port being hammered."* A test has already starved the nodes
it was measuring by polling too hard.

An explorer pointed at a validator is therefore a load generator aimed at
consensus. This index exists so that it is not.

**Operational rule: index from the archival observers, never from the fleet.**
`139.180.166.5:8080` and `139.180.173.231:8080` are keyless, hold no validator
key, and are the correct thing to read. The indexer reads a **local copy** of an
archival's `blocks.log`; the only network call it ever makes is `compare`'s
bounded, spaced `getbalance` sample, and `Probe::new` refuses any address that
is not one of the two archivals.

---

## 2. Where the data comes from

The canonical source is `blocks.log` — `<data-dir>/blocks.log` on an archival,
`u32 LE payload length ‖ payload` frames butted end to end from byte 0, where
each payload is `codec::encode_envelope(&BlockEnvelope)`. No magic, no checksum,
no compression.

```
scp -i ~/.ssh/edgevana_fleet_g4 \
    ubuntu@139.180.166.5:/home/ubuntu/g4/archival/blocks.log ./blocks.log
scp ... :/home/ubuntu/g4/mainnet.manifest ./
scp ... :/home/ubuntu/g4/carryover.tsv ./
```

Three things the format forces, all handled:

1. **Genesis is not in the log.** The first frame is the block at the first
   produced slot, so `height(nth frame) = n + 1` and height 0 comes from the
   manifest.
2. **A torn trailing frame is normal**, not corruption — appends are one
   `write_all` plus `sync_data`, so a crash or a copy taken mid-write leaves one
   incomplete frame. The reader drops it and says so.
3. **A reorg replaces the file, inode and all.** `Store::rewrite` writes the
   whole new chain to `blocks.log.tmp` and renames it over `blocks.log`, so the
   file can *shrink* and every byte offset is invalidated. `LogReader` keeps a
   fingerprint (`len`, `inode`, `mtime`) and `changed()` reports when a re-scan
   is mandatory.

### The frame table, reused

`LogReader` carries the node's own frame table — `FrameRef { slot, offset, len }`
from `perf/network-sync` `e904a6db`, where it took a 512-block page fetch at
`after_slot=53,400` from 77.1 ms to 2.1 ms and made it flat in the chain length.
Two properties are carried over deliberately:

- `offset` points at the frame's **payload**, not its length prefix.
- Lookup filters **entry by entry, with no monotonicity assumption**. Slots are
  strictly increasing when the engine writes the log, but that is an engine
  invariant, not a format guarantee. `tests::indexed_and_scanned_answers_are_
  identical_on_a_non_monotonic_log` feeds it slots `[4,1,9,9,2,40,7]` and
  carries a control showing the `skip_while`/`take_while` version would differ.

Building the table reads 4 + 304 bytes per block and seeks past the body, which
is why a range query over blocks costs 100 × 304 bytes rather than 100 × 14 KB.

---

## 3. The schema

Held in memory, rebuilt from the log; nothing here is a second copy of a
consensus artifact.

### `chain: Vec<BlockRow>` — index *is* height, `chain[0]` is genesis

```
block_id parent slot epoch height proposer_index
state_root body_root justified_root finalized_root
tx_count attestation_count frame_len
outputs_created_sat inputs_spent_sat fees_sat
eutxo_total_sat eutxo_count
```

`height` and `epoch` are **derived**: the header carries neither. `epoch =
slot / SLOTS_PER_EPOCH` (32); height is the position on the applied chain.

### `utxo: HashMap<OutPoint, Utxo>` and `balance: HashMap<ScriptHash, u128>`

`OutPoint { txid, vout }` is consensus's own key. `balance` is `u128`, never
`u64` and never a float: the cap is 10^19 sat and the largest carried holder is
354,617,540,000,000,000 sat — 39× past the largest integer a double represents
exactly. Every satoshi field on the wire is a **decimal string**
(`"354617540000000001"`), per `BLOCH-RPC-V4.md` §0 R3.

### `by_script`, `history`, `txs`, `by_txid`, `epochs`, `participation`

- `by_script: ScriptHash -> HashSet<OutPoint>` — an address's outputs are a
  lookup, not a scan of the set.
- `history: ScriptHash -> Vec<HistoryEntry>`, each entry carrying its height —
  which is what lets a rollback truncate exactly the orphaned entries.
- `txs: Vec<TxRow>` in chain order, with `tx_starts` parallel to `chain`.
- `by_txid: Txid -> Vec<usize>` — a **list**, see §4.
- `epochs: BTreeMap<u64, EpochRow>` — blocks produced out of 32, attestations
  included, distinct proposers, and the justified/finalized roots the epoch's
  last block pointed at.
- `participation: BTreeMap<(epoch, validator), Participation>` with three
  counters: `attested_target` (attestations whose target is this epoch),
  `included_here` (attestations carried by blocks of this epoch), `proposed`.
  Both attestation counters are kept because they differ when inclusion is late,
  and **consensus's own reward rule uses the second one**: a validator
  participated in epoch E iff at least one of its attestations was included in a
  block of epoch E.

---

## 4. The permalink scheme

| Thing | Permalink | Why |
|---|---|---|
| Block | `/block/id/<block_id>` | `SHA3-256(DS_BLOCK ‖ 304-byte header)` — consensus's own identity, covers the whole header, survives being orphaned |
| Block, positionally | `/block/height/<h>`, `/block/slot/<s>` | convenient and **reorg-unstable**; every answer carries `block_id` and `chain_tip` so a caller can tell |
| Transaction | `/tx/<block_id>/<tx_index>` | **primary**; unique unconditionally |
| Transaction, by identity | `/txid/<txid>` | `SHA3-256(DS_TXID ‖ spend_signing_root)`; returns a **list** |
| Output | `/outpoint/<txid>/<vout>` | consensus's own eUTXO key |
| Address | `/script/<script_hash>/…` | 32 bytes, never an address string |

### There *are* transaction ids — but `txid` cannot be the primary key

`gettransaction` refusing is an index gap, not the absence of an identity.
`PosTransaction::txid` is real, consensus-committed, and malleability-free: it
is taken over the **witness-free** signing root, so re-encoding the signatures
cannot move where a payment lands. V1 and V2 encodings of one logical transfer
have byte-identical txids (`tests::the_two_transfer_encodings_share_one_txid`),
so a payment does not change its permalink when a wallet changes its encoding.

The catch, which is why the primary key is `(block_id, tx_index)`: for the
**staking variants** the signing root is over the canonical bytes alone and
those carry no nonce, so **two `Exit { validator: 7 }` in different blocks have
the same txid**. That is pinned by
`tests::two_identical_exits_share_a_txid_which_is_why_txid_is_not_the_primary_key`.
A `txid` permalink would therefore be silently ambiguous, and only for staking
messages. So `/txid/<h>` returns every match, with a note, rather than picking
one; in practice transfers are unique and the list has one element.

### Addresses are `script_hash`, and the index will not convert

A native Genesis-4 key's `script_hash` is `SHA3-256(pubkey)` — **all 32 bytes**.
A carried Genesis-3 balance's is a 20-byte hash160 with twelve zero bytes after
it, transcribed once from `carryover.tsv` and never derived from a key.
`transition::owns` accepts **both** forms, so an output locked under the wrong
one is spendable and nothing rejects it: the mistake is silent. Six tools in
this repository once computed `SHA3-256(pubkey)[..20] ‖ 0×12` because that is
the shape an address prints in, and the same key showed 74,999,997,782 sat under
one derivation and **0** under the other.

`bloch_pos_committee::script_hash` is the single implementation. This index does
no address decoding at all: it takes 64 hex characters, exactly as `getbalance`
does, and refuses a `bloch1…` string **with the reason**
(`tests::an_address_is_refused_with_the_reason`).

`getbalance` matches on **exact 32-byte equality**, not `owns()`, so the index's
exact-match keying is apples-to-apples with the node — including the consequence
that querying a carried address requires the carried shape.

---

## 5. Reorgs

**The invariant.** `chain[i].block_id` is the id of the `i`th block of the
node's selected chain, for every `i` applied. `Index::sync` re-establishes it
every tick:

1. **Detect** — compare the frame table against `chain` on `(slot, block_id)`.
   Comparing block ids and not merely slots is what catches a reorg that
   replaces a block with a *different block at the same slot*; a slot-only
   comparison misses it entirely.
2. **Roll back** — undo every block above the fork, newest-first, from a
   per-block journal: created outpoints deleted, spent outpoints restored with
   their prior values, balance deltas subtracted, history truncated by height,
   participation and epoch aggregates restored to their exact prior values.
   Rollback costs the work the orphaned blocks did, not a rescan.
3. **Re-apply** forward from the fork.

**`finalized` is not a watermark.** On this chain a node has been observed below
its own previously finalized checkpoint (`FcStore::head` ratchets downward), so
"finalized" cannot mean "this can never change". That forbids the obvious
optimisation — dropping undo records below the finalized height — and the index
does not take it. The journal is bounded in **blocks** (`--undo-depth`, default
4,096 ≈ 315× the deepest reorg measured on this chain, 13). A reorg deeper than
the journal **refuses and says so** rather than half-rolling-back
(`tests::a_reorg_deeper_than_the_journal_refuses_rather_than_guessing`); the
index then stays behind, serving old answers rather than wrong ones, until it is
rebuilt. Rebuilding is 50 s.

---

## 6. Verifying by violating

```
bloch-indexer verify-reorg --log L --manifest M --carryover C --depth 13
```

Against **real chain bytes**, not a synthetic fixture:

1. Build over the whole log.
2. Truncate the last `--depth` frames and put the shorter log in place **by
   rename**, exactly as `Store::rewrite` does, so the reader meets the same
   inode change a real reorg produces.
3. Require the index to roll back exactly `depth` blocks — then compare it,
   whole, against a *fresh build of the same shortened log*: chain rows, unspent
   set, balances, transaction count, epoch aggregates and participation.
   Converging on the tip is not the same as converging on the state.
4. Restore the original log and require convergence forward onto it, compared
   the same way.
5. **The control.** Compare the full-chain index against the truncated one and
   require that comparison to **fail**. A comparison that cannot fail proves
   nothing.

```
bloch-indexer compare --log L --manifest M --carryover C --sample 40
```
samples indexed balances against a live archival's `getbalance` — top holders,
evenly-spaced middle, bottom — plus an all-zero `script_hash` that must read 0
on both sides, which is the shape the two-derivation bug takes.

---

## 6b. Measured

**Index build**, full chain, on one idle Edgevana box (2 cores, 8 GB) —
33,886 blocks / 473,564,003 bytes of `blocks.log` / 452,731 opening outputs,
2026-09-01:

| Phase | Cold cache | Warm |
|---|---|---|
| genesis manifest + carryover ingest (54 MB TSV, all four commitment checks) | 0.657 s | 0.682 s |
| frame-table scan | 2.900 s | 0.035 s |
| seed the opening ledger | 0.231 s | 0.227 s |
| apply 33,886 blocks | 1.848 s | 1.357 s |
| **total** | **5.636 s** | **2.301 s** |

18,337 blocks/s cold. The scan is fast even on a cold cache because it reads
4 + 304 bytes per block and seeks past the body — the frame table is what makes
that possible. Resident set of the running server: 190 MB.

A full rebuild costing seconds is what makes the "refuse and rebuild" answer to
a too-deep reorg (§5) an acceptable one.

**Read API**, same box, loopback, explorer-shaped mix (35% 100-block ranges,
25% single blocks, 20% balances, 15% address history, 5% epoch participation),
keep-alive:

| Concurrency | req/s | p50 | p90 | p99 | max | errors |
|---|---|---|---|---|---|---|
| 16 | 7,733 | 1.80 ms | 3.52 ms | 6.77 ms | 24 ms | 0 |
| 64 | 5,689 | 9.11 ms | 22.1 ms | 38.6 ms | 97 ms | 0 |

At concurrency 16 that run answered 4,295,740 questions that would otherwise
have been **node RPC calls** — 285,765/s — against a node whose RPC caps at 64
concurrent connections, has no rate limit, and answers from the consensus
thread. That ratio, not the request rate, is the number this crate exists for.

Two defects were found by these runs and fixed rather than reported as
characteristics:

- Thread-per-connection with a socket per request **collapsed** at concurrency
  32: 1,088 req/s at 4 → 121 req/s with a 13-second p99. Replaced with a fixed
  worker pool, keep-alive, and a `try_send` backlog that refuses with 503
  instead of accepting a connection it will not serve.
- Keep-alive against a pool smaller than the connection count **starved** the
  queued connections invisibly: p50 stayed at 5.6 ms while the max reached
  10.6 s. Fixed with `MAX_CONNECTION_HOLD`, a 2-second deadline after which a
  connection is politely retired so the pool rotates. Max at concurrency 64 went
  10.6 s → 97 ms.

**Balances against the live chain**: `compare` sampled all 28 script hashes
holding a balance against `139.180.166.5:8080`'s `getbalance`. **28 agree, 0
differ**, including values past 2^53 where a float would have rounded, plus an
all-zero `script_hash` reading 0 on both sides. Block 30,000 checked field by
field against the node's `getblockbyslot 50884`: `block_id`, `parent`, `slot`,
`epoch`, `height`, `proposer_index`, `state_root`, `body_root`,
`justified_root`, `finalized_root` all identical, every one of them derived here
from the log rather than taken from the node.

**Reorg**: `verify-reorg --depth 13` against the real 33,649-block chain rolled
back exactly 13, matched a fresh build of the truncated log whole, converged
back onto the original tip and state, matched a fresh build again, and the
control comparison failed as it must.

---

## 7. What the explorer still cannot ask

Stated rather than left to be discovered:

- **Issuance, and therefore true total supply.** There is no coinbase, no
  per-block issuance field and no `getissuance`. Emission is credited to
  `ValidatorRecord.staked_sat` at each epoch close, and the counter advances
  **only by the operator leg** of `rewards::distribute` — the delegator leg,
  forfeited slices from non-attesting validators, and truncation dust are never
  minted. Deriving it needs the duty roster with effective stake, which needs
  the leak, slashing and cohort-cap machinery: a full consensus replay, not
  block bodies. `/supply` therefore serves `eutxo_total_sat` — satoshi held in
  **unspent outputs**, which is exact and derivable — and says in the response
  that staked and delegated balances are not in it.
- **Stake, delegations, validator records, slashing state.** All live in
  `CommittedState`, none in the eUTXO set. `getbalance` does not see a
  validator's bond either.
- **Orphaned blocks.** The node rewrites `blocks.log` to the canonical chain, so
  a block that lost a reorg is *gone from the source*. The index can tell you a
  reorg happened and how deep; it cannot show you the losing branch. Capturing
  that needs a gossip-tapping observer, not a log reader.
- **Committee membership** — "was this validator *supposed* to attest in slot
  S?" needs `committee_for_slot(seed_for_epoch(E), …)`, i.e. RANDAO and the
  roster, i.e. a state replay.
- **Slashing evidence contents.** Wire tag `0x05` folds its nested messages in
  through the roots they were signed over; nothing recovers an envelope from a
  hash. The index records that such a transaction was present and can hex-dump
  it, and that is all anyone can do.
- **The mempool.** Unconfirmed transactions are not in the log. `getmempoolinfo`
  on an archival is the only source, and it is per-node.
- **`state_root` agreement.** The index maintains the eUTXO set but not the SMT
  over it, so it cannot state that its set hashes to the node's `state_root`.
  What it does instead is `compare`, which checks the numbers the set produces
  against the node that computed the root. Implementing `state_root::eutxo_leaf`
  here would upgrade "the balances agree" to "the set is bit-identical"; it is
  the obvious next increment and it is not done.
- **Scale.** The index is in memory, rebuilt on start. At 33,649 blocks /
  452,731 opening outputs / 70,890 live outputs that is comfortable and the
  build is 50 s. It is a fine design to roughly 10^7 outputs; past that the
  tables need to go on disk behind the same interfaces.

---

## 8. Running it

```
bloch-indexer build        --log L --manifest M --carryover C
bloch-indexer serve        --log L --manifest M --carryover C [--bind 127.0.0.1:8090] [--poll-ms 5000]
bloch-indexer verify-reorg --log L --manifest M --carryover C [--depth 13]
bloch-indexer compare      --log L --manifest M --carryover C [--archival 139.180.166.5:8080] [--sample 64]
```

`serve` polls the log's fingerprint and re-syncs when it changes, handling a
reorg on the way. Point it at a local mirror refreshed by `rsync` from an
archival; do not point it at a validator's live data dir.

### Read API

```
GET /health
GET /status
GET /blocks?from=&to=&limit=
GET /block/height/:h        /block/slot/:s        /block/id/:hex
GET /block/height/:h/txs
GET /tx/:block_id/:index                       # primary permalink
GET /txid/:hex                                 # secondary; returns a list
GET /outpoint/:txid/:vout
GET /script/:hex/balance
GET /script/:hex/utxos?limit=&offset=
GET /script/:hex/history?limit=&offset=
GET /epochs?from=&limit=      /epoch/:e        /epoch/:e/participation
GET /validator/:i/participation?from=&limit=
GET /supply?from=&to=&step=
```

Pages are capped at 1,000. Every answer carries `chain_tip`.
