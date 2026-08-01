# Merged Mining (AuxPoW) — Flag-Day Activation Runbook

How to take AuxPoW merged mining **live on mainnet**. Until this runbook is
executed, merged mining is **inert**: `AUXPOW_ACTIVATION_HEIGHT = u64::MAX`, and
`validate_pow` rejects any block carrying an `auxpow` (fail-closed). The full
code path (verifier, node `createauxblock`/`submitauxblock`, pool serve +
engine + socket handler) ships and is tested; activation is the only remaining
gate.

> **⚠️ BALANCES ARE SACRED.** Activation is a **binary swap + coordinated
> restart**, NOT a new chain. Every node relaunches on its **existing
> `--data-dir`** (chain + UTXO set intact) with the **same
> `--carryover-snapshot`**. Never wipe a data-dir, never start a fresh genesis.
> The regtest rehearsal (`scripts/regtest-merged-rehearsal.sh`) uses a throwaway
> datadir *by design*; the flag-day is the opposite.

## 0. Preconditions

- [ ] The regtest rehearsal has passed end-to-end (a merged block accepted) —
      `scripts/regtest-merged-rehearsal.sh` on a low-difficulty chain.
- [ ] The BTC-block relay for a `BtcAndBloch` win is either wired (segwit
      witness-commitment coinbase output + full segwit block serialization,
      validated against a live `bitcoind`) or explicitly out of scope for v1
      (the Bloch-security path — `submitauxblock` — does not need it).
- [ ] A pool with a live `bitcoind` + the merged proxy is ready
      (`BLOCH_POOL_MERGED=on`, BTC RPC creds, `BLOCH_POOL_BLOCH_ADDR`,
      `BLOCH_POOL_BTC_PAYOUT_SCRIPT`).
- [ ] The whole fleet is on one branch/commit and reachable (see the fleet
      inventory: founder node + miner-box + Edgevana nodes).

## 1. Choose the activation height

Pick `H = AUXPOW_ACTIVATION_HEIGHT` **comfortably in the future** — enough blocks
that the entire fleet can rebuild and restart BEFORE the chain reaches `H`. At
30 s blocks, 2880 blocks ≈ 24 h. A day of headroom is prudent.

```
current tip:      getblockcount on any node
H = tip + margin  (margin ≥ fleet-rebuild-time / 30s, e.g. +2880 for ~24h)
```

Edit `crates/bloch-crypto/src/core/mod.rs`:

```rust
#[cfg(not(feature = "auxpow-rehearsal"))]
pub const AUXPOW_ACTIVATION_HEIGHT: u64 = <H>;   // was u64::MAX
```

Commit + tag. **Do NOT** ship with the `auxpow-rehearsal` feature — that is
regtest-only (activation 0).

## 2. Build the flag-day binary (once)

```
cargo build --release --features node --bin bloch
cargo test  --features node                 # must be green
sha256sum target/release/bloch              # record the hash; the whole fleet runs THIS binary
```

Below `H` the new binary behaves **identically** to the current one (a block
with `auxpow` before `H` is rejected exactly as today), so it is safe to roll
out early. Activation happens purely by height.

## 3. Roll out to the fleet — swap binary, preserve data

For EACH node (founder, miner-box, Edgevana nodes), via a **systemd drop-in or
unit-file binary swap — never `pkill`+`setsid`**:

```bash
# 1. stage the new binary next to the old (do NOT overwrite a running one in place)
scp target/release/bloch  <node>:/home/ubuntu/bloch-flagday
# 2. point the unit at it (drop-in), keeping ALL existing flags incl. --data-dir + --carryover-snapshot
sudo systemctl edit <unit>       # or edit ExecStart to the new binary path
sudo systemctl daemon-reload
# 3. restart; the node reloads the DAG from --data-dir (balances intact)
sudo systemctl restart <unit>
# 4. VERIFY it came back on the same chain, same height range
curl ... getblockcount            # must be at/near the pre-restart tip, climbing
```

**Balance-preservation checks (per node, before vs after the swap):**

- [ ] `getblockcount` after ≥ before (node rejoined, did not reset to genesis).
- [ ] A spot-check balance of a known address (e.g. via `listtransactions` /
      the explorer) is unchanged across the swap.
- [ ] Log shows `DAG loaded from disk (integrity verified)` and
      `carry-over already ingested` — NOT a fresh carry-over import.
- [ ] `getblockhash <a fixed old height>` identical on every node (same chain).

Roll node-by-node; keep a quorum up so the chain never stalls. A node that must
rebuild from scratch **syncs first** from an archival peer to inherit the ledger
BEFORE it is allowed to mine.

## 4. Cross the flag-day

- Nothing special happens to the chain at `H` on its own — blocks keep coming
  from native SHA-256d miners. What changes: at/above `H`, a block carrying a
  valid `auxpow` is now ACCEPTED.
- Turn on the merged pool (`BLOCH_POOL_MERGED=on`) once the fleet is fully on the
  flag-day binary. Before `H` its `submitauxblock` calls are rejected
  (fail-closed) — harmless; after `H` they land.
- Watch: the first merged block's `getblock`/explorer should show an `auxpow`
  trailer, and `block_count` continues climbing normally.

## 5. Rollback

If a problem appears before `H`: revert the binary (swap back, same data-dir) —
no consensus change has taken effect yet, so this is a plain restart.

After `H`, once merged blocks are in the chain, rollback means a coordinated
downgrade is a **hard fork** (old binaries reject the `auxpow` blocks). Treat
crossing `H` as one-way; that is why step 0's rehearsal + step 3's per-node
verification are mandatory.

## Honest caveat (keep in all copy)

Merged mining secures Bloch only with the **fraction of BTC hashrate that opts
in**, and lets a large BTC miner attack at ~zero marginal cost. It is a
bootstrap lever, **not** a security guarantee. See `docs/MERGED-MINING.md`.
