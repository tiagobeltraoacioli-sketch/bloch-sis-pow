# Genesis-4 historical indexer

The explorer's historical API supplies exact input values, output values, fees,
validator stake, transaction lists, spent outpoints and paginated script-hash
history. It runs as a separate read-only process beside the keyless archival.
The validator processes and their data directories are not changed.

## Source and verification

`bloch-indexer` reads the archival's canonical `blocks.log`, the authenticated
genesis manifest and its carryover file. It uses the node's envelope and genesis
decoders, checks the carryover commitments, and seeds all opening allocations.
Genesis allocations are history events at height and slot zero, not invented
transactions in block bodies.

Every block is replayed through `Transition::compute_post_state_observed` with
real `bloch_crypto::crypto::verify` signature checks. This observer is a read-only
callback in the existing transition; the ordinary transition delegates to the
same implementation with an empty callback. After each applied transaction, the
indexer captures its actual output values and charged base plus priority fees.
It accepts the receipts only after the complete transition succeeds and its
computed state root equals the block header's root.

This handles funded deposits correctly: the stake is separate from the fee, and
change includes any unused fee reservation returned by consensus. Withdrawals
use the actual consensus-created output, including its backing and reward rules.
There is no independent copy of staking or reward arithmetic in the indexer.
Unknown or invalid transaction encodings stop indexing; they do not receive
invented transaction IDs or zero values.

## Stored data and reorganization handling

The in-memory index retains all created outputs, their values and script hashes,
spent heights, input value snapshots, transactions by block position, a secondary
TXID index, and chronological creation/spend events. Genesis-4 history includes
the opening ledger and every indexed block; it does not reconstruct pre-Genesis-4
activity from the old chain.

Transactions are uniquely identified by `(block_id, index)`. Repeated staking
messages can share a TXID: an ambiguous lookup returns HTTP 409 with all matches.
The explorer lets the reader select an occurrence.

The index watches file identity as well as length. A renamed or shortened log is
compared against the indexed block IDs. An undo journal restores both replay
state and historical tables before applying the winning branch. A same-block
create/spend pair is undone without resurrecting its intermediate output.
Before serving, startup qualification rolls back and replays up to 13 actual
archival blocks and compares all ledger tables with their initial contents.
The test never writes to the node's log.

The journal is bounded. A deeper fork or read/replay failure makes the historical
API unavailable while the process rebuilds from genesis. No approximate rollback
or guessed value is served. An API freshness lease also expires if the sync loop
stops making successful checks.

The index is rebuildable rather than a second durable chain database. Restarting
requires replay; operators should expect a period of unavailability during that
rebuild. Initial qualification of 70,405 blocks and 1,141 transactions took about
463 seconds on archival-1, with 128 retained undo states. This is a measurement
of that run, not a throughput guarantee.

## Explorer endpoints

All amounts are decimal strings of integer satoshis. The explorer uses BigInt;
no monetary value passes through floating point. Responses identify their
snapshot slot, height, block ID, source and verification method.

- `GET /health`: synchronization position and service health.
- `GET /transactions?limit=&cursor=`: newest transactions, bounded pages.
- `GET /tx/<txid>`: one receipt, 404 if absent, 409 if ambiguous.
- `GET /block/<block_id>/transactions`: that canonical block's complete receipts.
- `GET /utxos/<script_hash>?limit=&cursor=`: complete pageable unspent set.
- `GET /history/<script_hash>?limit=&cursor=`: creation/spend history, newest first.
- `GET /outpoint/<txid>/<vout>`: historical value and creation/spend positions.

Cursors bind an offset to a specific canonical block ID and height. Appended
blocks do not change the snapshot. If the anchor is reorganized, pagination
returns 409 and the reader restarts. Historical UTXO pages evaluate spending at
the snapshot height, so an output spent after page one does not vanish from later
pages. Transaction pages may contain fewer than the requested limit to keep the
response size bounded; the next cursor advances by the number actually returned.

HTTP 503 means unavailable or rebuilding, not that the transaction does not
exist. HTTP 404 refers only to the indexed canonical history. Finality and
production deposit-crediting requirements remain separate live observations;
a receipt or creation height alone does not authorize crediting a deposit.

## Operations

Build and test:

```sh
cargo test -p bloch-indexer
cargo test -p bloch-pos-committee
cargo build --release -p bloch-indexer
```

Example service command:

```sh
bloch-indexer serve \
  --log /home/ubuntu/g4/archival-next/blocks.log \
  --manifest /home/ubuntu/g4/mainnet.manifest \
  --carryover /home/ubuntu/g4/carryover.tsv \
  --bind 127.0.0.1:8091 --poll-ms 5000 --undo-depth 128
```

The production unit `bloch-historical-indexer-v2.service` enforces read-only filesystem access, no new
privileges, a two-CPU quota, an 8 GiB memory limit and bounded threads. The API
binds to loopback. HAProxy forwards only the `/indexer/` path to it; existing RPC
traffic keeps its original backend. Cloudflare Pages exposes a fixed-origin GET
allowlist with request budgets, response size and timeout limits, and no-store
responses. The Pages health route compares index position with the explorer's
corroborated archival head. Historical data comes from one archival process;
it is not a second independently operated observer.

Tests cover exact amounts beyond JavaScript's integer range, more than 1,000
outputs, snapshot conflicts, missing inputs, spent-value retention, same-slot
forks, intra-block spends, deep-fork refusal and read-only edge routing.

Release binary SHA-256: `731c1d9a5d2f978f1a3bc76a1dbcc1e21497c95486edb1ac7ef5eee0903bf60f`.
