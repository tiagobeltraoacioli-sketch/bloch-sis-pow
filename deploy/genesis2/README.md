# Genesis-2 fly deploy — status & runbook

Scaffolding for redeploying the Fly fleet onto the **Genesis-2 devnet**
(`ChainId::Genesis2Devnet`, SHA-256d PoW, carry-over ledger). Prepared by task
(A): **flag + configs wired, nothing deployed.**

## What is DONE (this commit)

- **`--genesis2` CLI flag** (`src/main.rs`). Selects `ChainId::Genesis2Devnet`,
  mutually exclusive with `--testnet` (exit 2 if both). This is the explicit node
  selector the `ChainId::Genesis2Devnet` doc mandates ("Selected ONLY by an
  explicit node flag, never by `for_network`").
- **Genesis-init gate** (`src/main.rs`). Under Genesis2Devnet, first boot ingests
  the carry-over set and then **fails loud** — because block 0 is undefined (see
  blocker 1) — instead of emitting the misleading "Module-SIS PoW invalid".
- **Fly templates** (`blochv-node-{7,8,10}.fly.toml` here): node-8 archival
  (`--archive`, no `--mine`), node-7/10 miners. All carry
  `--genesis2 --carryover-snapshot /bloch-data/carryover.tsv`, `--testnet` removed.

## BLOCKERS — must clear before any deploy (both are human decisions)

### 1. The Genesis-2 genesis block is not defined
`create_genesis_block` only builds the Module-SIS genesis. Genesis-2 needs a
**SHA-256d genesis with an empty `pow_solution`**: choose bits, timestamp, nonce,
coinbase, mine its PoW, and bake the constants. `bloch-genesis2` deliberately
refuses to make these consensus choices. Until this exists, a `--genesis2` node
stops at the gate above.

### 2. The carry-over snapshot TSV does not exist yet
Genesis2Devnet `chain_requires_carryover == true`, so every node refuses to start
without `--carryover-snapshot`. The file must hash (SHAKE-256 over raw bytes) to
`CARRYOVER_SNAPSHOT_ROOT`, with `CARRYOVER_UTXO_COUNT = 413_743` lines and
`CARRYOVER_TOTAL_SAT = 347_544_120_000_000_000`. Produce it from the node that
holds the ~408k state:

```
# on the node with full state (e.g. Edgevana node3 — the one that WORKS; freeze it first)
bloch-snapshot-utxo --data-dir <dir> > carryover.tsv
bloch-genesis2 --snapshot carryover.tsv --height 413743   # prints/confirms the constants
```

This is exactly the **408k carry-over verification** currently in progress. Do not
touch that node, and do not touch Edgevana **node3** (the working one) until told.

## Deploy procedure (ONLY after both blockers clear) — NOT RUN YET

For each app, place the verified `carryover.tsv` on its volume, then deploy:

```
# 1. put the blessed snapshot on the volume (once per app), e.g.:
fly ssh sftp shell -a blochv-node-8   # put carryover.tsv -> /bloch-data/carryover.tsv
# 2. (fresh chain-id ⇒ start from a CLEAN data-dir; testnet data must not be reused)
# 3. deploy the archival node FIRST, let it ingest + define tip, then the miners:
fly deploy -a blochv-node-8  -c deploy/genesis2/blochv-node-8.fly.toml
fly deploy -a blochv-node-7  -c deploy/genesis2/blochv-node-7.fly.toml
fly deploy -a blochv-node-10 -c deploy/genesis2/blochv-node-10.fly.toml
```

**Do NOT redeploy the Fly node running the 408k verification.** Confirm which app
that is before touching node-7/8/10.

## Verify after boot

```
fly logs -a blochv-node-8   # expect: carry-over VERIFIED + ingested, then archival serving
# on any node's data-dir:
bloch --verify-carryover --data-dir /bloch-data   # exit 0 = contains exactly the carried ledger
```
