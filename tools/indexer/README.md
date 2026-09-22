# Bloch Reorg-Safe Indexer (reference)

A standalone reference address / UTXO / history indexer for Bloch. It consumes
blocks via JSON-RPC (`getblockcount`, `getblockhash`, `getblockbyheight`), tracks
the RPC height mapping, detects replaced blocks, rolls back the affected height
range and re-applies replacement blocks. Offline tests cover these operations.
A sync pass stages at most 16 linked blocks before publishing changes, rechecks
the fork anchor and batch tip, and refuses observed RPC branch shifts without
changing balances. Concurrent sync callers share one pass. Fork searches stop
after 2,048 comparisons and require operator reconciliation beyond that bound.
RPC work has a 30-second pass deadline (`INDEXER_SYNC_TIMEOUT_MS`, configurable
from 1 through 300,000 ms). Fetch and body reads receive cancellation; late
responses cannot publish a cancelled batch. Collection stops early to leave
budget for final anchor/tip checks, allowing shorter batches on slow sources.
SIGINT/SIGTERM cancel pending reads and poll sleeps. Synchronous block application
and whole-state fsync cannot be preempted by a JavaScript timer, so this is not a
hard wall-clock bound on those phases.
Missing verbose bodies and malformed transaction arrays/identifiers/indices are
errors, not evidence that indexing is complete. No missing spend/output list is
silently converted into an empty transaction.

These checks mitigate mixed-branch reads; they do not create an atomic RPC
snapshot. A reorg after the final check remains possible. DAG parent membership
does not prove the selected-parent choice. In the legacy node, `put_block`
overwrites `CF_HEIGHT` for every stored block at a height; the height RPC reads
that index, while fork choice walks `selected_parent` separately. Therefore even
stable, linked height responses do not prove canonical selected-chain membership.
This requires an upstream canonical-chain RPC contract before live qualification. This reference is not a qualified live balance
authority. Whole-state persistence, history pruning, existing misindexed data
and live chain qualification remain unresolved. Failed block validation may
publish a shorter valid staged prefix, with its undo records, before retry.
At the transport's 8 MiB limit, a full 16-block stage can hold up to 128 MiB of
raw response-equivalent data plus parsed object overhead.

It persists to a simple embedded JSON store and exposes a small read API.

> **License:** MIT OR Apache-2.0 — a *different*, more permissive licence than
> the protocol itself. This line used to claim "the same permissive terms as the
> Bloch protocol", which was never true: the Genesis-3 node shipped
> AGPL-3.0-or-later, and the Genesis-4 crates were relicensed to match on
> 2026-08-11. Whether these two G3-era tools should follow is an open
> founder/PMO call; the false claim is corrected here regardless, because a
> wrong licence statement misleads whether or not the licence changes.

---

## ⚠️ Status & honesty rails (binding — read before use)

- **SCAFFOLD / reference tool. Unaudited. Pre-production.**
- **Reference, untested against a live network.** It builds, and its reorg logic
  is verified end-to-end against a deterministic offline stub chain (self-test +
  `INDEXER_STUB=true`). It has **not** been validated against a live Bloch node.
  No claim is made that it "works end-to-end against mainnet."
- **Testnet-only reference.** Defaults encode addresses with the testnet
  `bloch1t…` prefix.
- **Legacy RPC model.** The reference was written for the retired Genesis-3
  proof-of-work API. Genesis-4 uses proof of stake; this tool has not established
  an equivalent canonical-chain contract with that node. Do not infer support
  for current exchange accounting from the offline examples.
- **Bloch is ownerless and neutral.** Postern Labs is **one builder among many**
  with **no protocol privilege**.

Why this exists: the roadmap (§2.1 / Phase 0) notes that Bloch's existing
address-history indexer **does not roll back on reorg**, which makes it
undependable as shared infrastructure. This reference implementation demonstrates
the fix.

---

## The reorg-handling approach (explicit)

**Target invariant:** the indexer's applied map `chain[height] -> hash` is a
prefix of the node's selected chain. The following tick logic is tested with a
consistent RPC view; separate RPC calls do not provide an atomic chain snapshot:

1. **Detect.** If we have an indexed tip at height `Ht` with hash `Hh`, re-fetch
   the node's hash at `Ht` (`getblockhash`). If it differs (or is now missing),
   a reorg has replaced blocks at/below our tip.
2. **Find the fork.** Walk backwards from `Ht-1`, comparing our stored hash vs
   the node's hash at each height, until they agree. That height is the **fork
   point** (can be `-1`, meaning the whole chain was replaced).
3. **Roll back.** Undo every block **above** the fork point, newest-first, using
   a per-block **undo journal** recorded at apply time. Each undo record holds:
   - the UTXO keys the block **created** (deleted on rollback),
   - the UTXOs the block **spent**, with their prior values (restored),
   - the net per-address **balance deltas** (subtracted).
   Address-history entries carry their block height, so rollback drops exactly
   the entries at orphaned heights. No full re-scan — rollback costs only the
   work the orphaned blocks did.
4. **Re-apply.** Walk forward from `fork + 1`, fetching each block by height
   (`getblockbyheight … verbose=true`) and applying it, until the node has no
   block at the next height.

Applying a block: for each transaction, spend its inputs (remove UTXOs, credit
"out" history, decrement balances) and create its outputs (add UTXOs, credit
"in" history, increment balances). The on-chain `script_pubkey` is the 20-byte
pubkey hash, which is re-encoded to a checksummed `bloch1t…`/`bloch1q…` address.

The self-test (`npm run selftest`) proves the key property: after a reorg that
orphans a payment to "Carol", Carol's balance is `0`, her UTXO is gone, and she
has **no stale history** — while the replacement payment to "Dave" is present.

## Satoshi amounts are `bigint`, never `number`

Normative rule: `docs/specs/BLOCH-SATOSHI-ENCODING.md`. **A satoshi amount is a
decimal string on the JSON wire and a `bigint` in memory.**

This is not a style preference. `JSON.parse` turns every JSON number into an
IEEE-754 double, exact only to `Number.MAX_SAFE_INTEGER` = 9,007,199,254,740,991
sat. Genesis-4's supply is 10^19 sat (1,110x that), and the largest single
carried-over address already holds 354,617,540,000,000,000 sat — 39x past the
limit. An indexer that exists to compute balances cannot hold them in a type that
rounds them.

Consequences, all implemented here:

- `TxOutput.value`, `Utxo.value`, `HistoryEntry.amountSats`, `StoreState.balances`,
  `UndoRecord.deltas` and `getBalance()` are `bigint`. Heights, indices,
  timestamps and counts stay `number`.
- All parsing goes through **one** helper, `parseSats` in `src/sats.ts`. It
  accepts the canonical decimal string *and* the legacy bare-number form that the
  historical Genesis-3 API emitted, and rejects negatives, non-integers, and
  anything above 10^19.
- `HttpTransport` reads responses with `parseJsonExactIntegers`, not
  `res.json()`: an oversized integer literal is recovered from its **raw source
  text**, never through a double.
- The read API emits amounts as decimal strings
  (`"balanceSats": "354617540000000000"`). The `balanceBloch` companion is a
  float, display-only and lossy — do not use it for accounting.
- The JSON state file stores amounts as decimal strings (`bigint` is not
  JSON-serializable — `JSON.stringify` throws on it). A state file written by the
  older number-typed build still loads exactly, and is migrated to strings on the
  next `persist()`.

The self-test covers this end to end: a balance of 354,617,540,000,000,001 sat is
indexed, persisted, reloaded, served over HTTP, and then reorged back to `0`. The
`+1` is deliberate — 354,617,540,000,000,000 happens to be exactly representable
as a double (spacing at that magnitude is 64), so only the `+1` distinguishes
correct arithmetic from `number` arithmetic. Measured against the pre-migration
code, that same scenario reports 354,617,540,000,000,000 (one satoshi silently
lost), and reports `"0354617540000000000"` — a string concatenation — when fed
the Genesis-4 wire form.

## Storage

`JsonStore` (in `src/store.ts`) persists the whole index — tip, chain map, UTXO
set, balances, history, and the undo journal — to a single JSON file
(`INDEXER_DATA_FILE`). It implements the `IndexStore` interface, so a
SQLite/sled backend can be dropped in later without touching the indexer logic.

## RPC transport seam

The transport is behind `JsonRpcTransport`:
- `HttpTransport` — talks to a real node; handles Bloch's quirks (positional
  params; application errors buried in `result.error`; `-32001/-32002` auth
  errors).
- `StubChainTransport` (`src/stubchain.ts`) — a scripted offline chain that
  performs a reorg on command, so the reorg path runs with **no node**.

## Build & run

```bash
cd tools/indexer
npm install
npm run typecheck    # tsc --noEmit
npm run build        # tsc -> dist/
npm test             # offline selftests and security/regression suite
npm run selftest     # offline reorg + satoshi-encoding tests (no node)

# Watch reorg handling against the built-in stub chain (no node needed):
INDEXER_STUB=true INDEXER_POLL_MS=1000 npm start

# Against a real node:
INDEXER_RPC_URL=http://127.0.0.1:16210/ npm start
```

## Read API

- `GET /health`
- `GET /status` — tip, blocksApplied, blocksRolledBack, reorgsHandled, counts.
- `GET /address/:addr/balance` — `balanceSats` is a decimal **string**;
  `balanceBloch` is a lossy display float.
- `GET /address/:addr/utxos` — `value` is a decimal string.
- `GET /address/:addr/history` — `amountSats` is a decimal string.
- `GET /utxo/:txid/:index` — `value` is a decimal string.
- `GET /block/:height` — the indexer's applied hash at that height.

## Known limitations

- Single-writer, single JSON file; not tuned for large chains or concurrent
  writers. Swap in an embedded DB via the `IndexStore` interface for scale.
- Follows the node's **selected chain** by height; it does not index the full
  BlockDAG's non-selected (red) blocks.
- Assumes `getblockbyheight` returns the node's current selected block at each
  height (true for the node's storage model). Not audited; not load-tested.

## Naming

This is the **community edition**. Do not refer to it as "Postern OS" or by the
registered legacy mark; approved names are Yagabona and Izbushka.

## Internal audit LG-07 hardening (2026-09-17)

Address UTXO and history responses are now **paginated**. This is a client-visible
change: callers must follow `nextCursor` to obtain all entries. Both endpoints
accept `?limit=100` (default 100, maximum 500) and an optional opaque `cursor`.
The existing `utxos`/`history` arrays and decimal-string amounts are preserved;
responses also contain `nextCursor`, `snapshot`, `limit` and `indexedTip`.
A null `nextCursor` means the complete result has been read.

Cursors bind the address, endpoint and exact in-memory index revision. A new
block, rollback or process restart makes an old cursor return HTTP 409; restart
pagination and discard the incomplete traversal. This prevents a traversal from
silently mixing revisions, including a reorg returning to the same tip hash.
It is not a historical snapshot service: a rapidly changing tip may require
retries. UTXO order is not a transaction-history guarantee. The dense secondary
index provides O(page-size) page extraction and O(1) balance UTXO counts without
materializing all UTXOs for a large address.

The API rejects invalid limits/cursors, caps URL length at 2,048 characters,
refuses request bodies, and bounds connections and HTTP lifetimes. Responses
are capped at 1 MiB; unusually large individual string fields are refused.
If a page exceeds the byte cap, HTTP 503 asks the caller to request a smaller
page. Address spelling is canonicalized and must match the configured network.
The upstream JSON-RPC client caps streamed response bodies at 8 MiB, including
responses without Content-Length, retains its 10-second per-call deadline in
addition to pass cancellation, and refuses
redirects.

Snapshots keep their existing JSON format. Persistence uses a unique, exclusive
0600 temporary file, fsyncs it, atomically renames it, and fsyncs the directory.
Unchanged poll cycles skip rewriting the snapshot. The first persist after a
load still normalizes legacy numeric amount fields to decimal strings. Corrupt
snapshots are never overwritten automatically, and data queries return HTTP
503 rather than authoritative-looking empty balances. Repair or rebuild the
index explicitly after preserving the failed snapshot. Store mutations must go
through `applyBlock`/`rollbackTo`; the exposed `state` is for inspection.

**Remaining scaling limitation:** every changed snapshot still serializes and
rewrites the entire index synchronously. Memory use also grows with retained
UTXOs, history and undo records. A transactional incremental store/WAL and a
reviewed reorg/pruning policy remain required for production scale. The JSON
backend is single-writer; these changes do not add multi-process transactions
or make this reference indexer production-qualified. No deployed index data was
modified by the audit work.

### Transactional block application follow-up

Block planning now uses a private UTXO overlay. A transaction can consume an
output created earlier in the same block without leaving a phantom unspent
output or overstating intermediate addresses' balances. Duplicate spends,
output collisions and references to outputs created only later in the block
are rejected before committed state changes. Undo restores only outputs that
existed before the block, never same-block intermediate outputs. A missing
historical undo record is detected before rolling back any higher block.

Snapshot loading validates required shapes, numeric counters/heights and
chain/tip/undo consistency. Cursor and dirty-state revisions are private bigint
counters independent of persisted statistics. Serialization preserves own keys
such as `__proto__` in address-indexed maps. Existing valid JSON snapshots and
legacy decimal/numeric amount decoding remain compatible, but malformed files
previously treated as empty or partially defaulted now fail closed. These fixes
do not repair balances already misindexed by an older build: affected indexes
need a separately authorized rebuild from verified source data.

Fetched blocks must report the requested height. **Remaining source-consistency
blocker:** several RPC calls do not form an atomic selected-chain snapshot. A
branch switch between awaits can still mix branch observations. The generic
`parents` array is not documented here as a unique selected-parent contract,
so this patch does not assume a linear parent rule for the DAG. Production
qualification requires a pinned selected-chain snapshot or a verified ancestry
contract and adversarial branch-switch tests. The indexer is a reference
consumer of node RPC, not an independent consensus verifier.


### Operational configuration (audit continuation, 2026-09-17)

Remote RPC requires HTTPS. Plain HTTP is permitted only for exact loopback
hostnames/addresses (`localhost`, `127.0.0.1`, `[::1]`). URL credentials and
fragments are rejected; use `INDEXER_RPC_API_KEY` for an authorization header.
Startup logs only the RPC origin, not query parameters. Existing remote HTTP
configurations must provision TLS before adopting this version.

Invalid network/boolean settings now fail at startup rather than selecting a
different network or live/stub mode silently. Poll intervals must be integer
10–3,600,000 ms, RPC pass deadlines 1–300,000 ms, and API ports 1–65,535. Defaults
remain 3,000 ms polling, 30,000 ms pass deadline, and port 8081. These are local
resource policies, not assurances about upstream honesty or chain finality.
