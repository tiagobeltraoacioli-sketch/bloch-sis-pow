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
- `GET /script/<script_hash>/balance`: exact indexed eUTXO balance, UTXO count,
  height and chain tip for one reference.
- `GET /holders?limit=64`: largest positive script balances, sorted by exact
  satoshis and bounded to 256 rows. The response includes the number of funded
  script references and total indexed eUTXO satoshis. It is a ranking of script
  references, not people or proven wallet owners. Staked and delegated amounts
  are outside the eUTXO balance and are not included.

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

## Flag days

The indexer replays every block through the linked `bloch-pos-committee`
transition and checks the header's state root. It is therefore exactly as new
as the consensus code it was built from. At the native L2 activation (epoch
5850) the deployed binary predated the release that armed the gate; from the
first block of epoch 5850 every replay ended in `replayed state root mismatch`
and the API never came up.

What the binary now does when it meets a block it cannot apply:

- **Halts at the previous height** instead of exiting or rebuilding. The
  applied prefix stays in memory. `/status` (always HTTP 200) reports
  `serving: false`, `sync_error` and `halt {height, slot, epoch, block_id,
  reason}`; data routes answer 503. A halt is retried only when the log
  changes (a reorg may drop the block); it is never "fixed" by a rebuild from
  genesis, which would cost tens of minutes and reach the same refusal.
- **Says which rules it knows.** `bloch-indexer gates`, `/consensus` and
  `/status` print every activation gate compiled in, plus `gate_digest`
  (SHA3-256 over `name=epoch` lines). Release builds should export
  `BLOCH_INDEXER_GIT_COMMIT=$(git rev-parse HEAD)` so `build_commit` is set.
- **Refuses silent ledger drift.** After each replayed block the index's live
  output count must equal the consensus state's (O(1)), and no transaction may
  create an output past what the index models for its kind. Either failure
  halts with the transaction kinds involved. The check is disabled
  automatically if the opening ledgers disagree, or with `--no-ledger-check`.
- **Cannot compile past an unclassified transaction kind.** `kind_of`,
  `transfer_parts` and `created_output_bound` have no wildcard arms.
- **Cannot pass its tests past an unlisted gate.**
  `tests/consensus_gates.rs` fails when `params.rs` gains a
  `pub const *_EPOCH: u64` that `src/consensus.rs` does not list.

### Checklist for every hard fork

1. Build the indexer **from the node release commit that arms the gate**, or
   from a later one. Run `bloch-indexer gates` and check that the gate epochs
   match the release notes (an inert gate prints `inert`).
2. Deploy it **before** the activation epoch and let it finish its replay. A
   binary that already knows the armed gate replays history unchanged, because
   every gate is inert below its epoch.
3. For every new `PosTransaction` variant, decide its ledger effect in
   `index.rs`: which eUTXOs it spends (`transfer_parts`), how many outputs it
   can create (`created_output_bound`) and its stable kind name (`kind_of`, the
   same string the node's RPC uses). Add a fixture test.
4. List new gates in `src/consensus.rs`.
5. After activation, `/status` must show `serving: true`, `halt: null` and
   the tip past the activation epoch.

### What HF1, HF2 and HF3 require (2026-10-20)

| Change | Branch | Gate | Wire / state | Indexer must learn |
| --- | --- | --- | --- | --- |
| HF1 CF: claim finality on the chain's own checkpoint | `codex/native-claim-finality-20261019` | `NATIVE_CLAIM_FINALITY_ACTIVATION_EPOCH` | own checkpoint roots in the L2 leaf | Rebuild only (state root). No new tx. |
| HF1 p1a: frozen finality set, no-leak denominator | `codex/bloch-p1a-noleak-20261019` | `NATIVE_FINALITY_SET_ACTIVATION_EPOCH` | finality leaf | Rebuild only. |
| HF1 p2a: own-target FFG | `codex/bloch-p2a-owntarget-20261019`, `codex/hf1-owntarget-20261020` | `NATIVE_OWN_TARGET_ACTIVATION_EPOCH` / `HF1_OWN_TARGET_VOTES_EPOCH` (name differs per branch) | finality leaf | Rebuild only. `attested_target` counts *included* votes; after the gate a vote naming a foreign target is included but not counted by FFG. |
| HF2 p6: growth cap | `codex/bloch-p6-growthcap-20261019`, `codex/hf2-growthcap-20261020` | `NATIVE_GROWTH_CAP_ACTIVATION_EPOCH` | activation queue state | Rebuild only. |
| HF2 slashing v2 | in tree; p5a `codex/bloch-p5a-slashing-20261019` | `SLASHING_ECONOMICS_V2_ACTIVATION_EPOCH`; `NATIVE_SLASHING_ACTIVATION_EPOCH` is node-local relay policy | evidence stays tag `0x05` | Rebuild only. Penalties move stake, not eUTXOs; withdraw payouts already come from replay receipts. |
| HF3 KES registration | `codex/bloch-kes-port-20261019` | `KES_REGISTRATION_EPOCH`, `KES_ACTIVATION_EPOCH`, `KES_BOUND_SIGNING_EPOCH` (p8a) | tx `0x17` `KesRegister`; state `0x22` | Kind `kes_register`; no eUTXO effect. KES verification uses `SignatureVerifier::verify_kes`'s default, so `ArchiveVerifier` needs no change. |
| HF3 KES rotation (proposed) | `docs/KES-MAINNET-READINESS.md` on `codex/bloch-p8b-kesmainnet-20261019` | not yet defined | **proposed at `0x18`, which is allocated to `WithdrawalCredentialRotation`**; next free tx tag is `0x1B` | Kind name; no eUTXO effect expected. Tag must be re-allocated first. |
| HF3 suite `0x0003` (SLH-DSA + Falcon-1024) | `codex/bloch-p9a-slhdsa-20261019`, fee policy p9f | `NATIVE_SLHDSA_SUITE_ACTIVATION_EPOCH` | new key/signature suite; per-suite verify gas | Nothing in the index model (script hashes are suite-agnostic). The build must link the p9a `bloch-crypto`, otherwise replay refuses the first block with a `0x0003` signature. Fees come from replay receipts. |
| HF3 withdrawal-credential rotation | `codex/bloch-p9d-migration-20261019` + tag allocation `61ac024d` | `NATIVE_SLHDSA_SUITE_ACTIVATION_EPOCH` | tx `0x18` | Kind `withdrawal_credential_rotation`; no eUTXO effect. It changes where a later `Withdraw` pays; that output already comes from the receipt. |
| HF3 rescue commit | same | `LATTICE_EMERGENCY_ACTIVATION_EPOCH` | tx `0x19`; state `0x24` | Kind `pq_rescue_commit`; no eUTXO effect, fee-free. |
| HF3 rescue reveal | same | `LATTICE_EMERGENCY_ACTIVATION_EPOCH` | tx `0x1A` | Kind `pq_rescue_reveal`. **Spends `inputs`** (every output of the revealed key, both script forms) and **creates one output at vout 0** (`destination_script_hash`, value = inputs − fee, from the receipt). The pre-change indexer (`_ => 0` arms) would have kept the swept inputs as spendable and lost the output. |

The PQ variant handling is implemented and tested on
`codex/indexer-hf3-pq-20261020` (this branch plus the tag allocation). Merge
it into the HF3 release branch.

Release binary SHA-256: `731c1d9a5d2f978f1a3bc76a1dbcc1e21497c95486edb1ac7ef5eee0903bf60f`.
