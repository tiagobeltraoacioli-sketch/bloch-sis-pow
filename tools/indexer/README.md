# Bloch Reorg-Safe Indexer (reference)

A standalone reference address / UTXO / history indexer for Bloch. It consumes
blocks via JSON-RPC (`getblockcount`, `getblockhash`, `getblockbyheight`) and —
the point of this tool — is **reorg-safe**: it tracks the selected-chain tip,
detects when a reorg replaces blocks, **rolls back** the affected height range,
and re-applies the new blocks, so address balances and history stay correct.

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
- **Test BLCH has NO value.** BLCH is **not a security**; nobody makes any value
  or investment claim. The base is experimental mainnet-beta: relaxed PoW (k=4)
  is trivially forgeable and the network is 51%-attackable.
- **Bloch is ownerless and neutral.** Postern Labs is **one builder among many**
  with **no protocol privilege**.

Why this exists: the roadmap (§2.1 / Phase 0) notes that Bloch's existing
address-history indexer **does not roll back on reorg**, which makes it
undependable as shared infrastructure. This reference implementation demonstrates
the fix.

---

## The reorg-handling approach (explicit)

**Invariant:** the indexer's applied map `chain[height] -> hash` is always a
**prefix of the node's current selected chain**. Every sync tick enforces it:

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
npm run selftest     # offline reorg test (no node)

# Watch reorg handling against the built-in stub chain (no node needed):
INDEXER_STUB=true INDEXER_POLL_MS=1000 npm start

# Against a real node:
INDEXER_RPC_URL=http://127.0.0.1:16210/ npm start
```

## Read API

- `GET /health`
- `GET /status` — tip, blocksApplied, blocksRolledBack, reorgsHandled, counts.
- `GET /address/:addr/balance`
- `GET /address/:addr/utxos`
- `GET /address/:addr/history`
- `GET /utxo/:txid/:index`
- `GET /block/:height` — the indexer's applied hash at that height.

## Known limitations

- Single-writer, single JSON file; not tuned for large chains or concurrent
  writers. Swap in an embedded DB via the `IndexStore` interface for scale.
- Follows the node's **selected chain** by height; it does not index the full
  BlockDAG's non-selected (red) blocks.
- Assumes `getblockbyheight` returns the node's current selected block at each
  height (true for the node's storage model). Not audited; not load-tested.

## Naming

This is the **community edition**. Do not refer to it as "Postern OS", and never
use the name "BABA YAGA".
