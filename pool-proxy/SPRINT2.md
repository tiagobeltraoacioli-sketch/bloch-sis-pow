# Sprint 2 — bloch-pool-proxy

Sprint 2 upgrades the existing, green Stratum-V1 proxy in place: no new
dependencies, its own `[workspace]`, zero consensus links. Three real changes,
each grounded in the code:

- **G1 — real PPLNS accounting.** The Sprint-1 per-worker `Accounting` stub is
  replaced by a **pool-wide, interior-mutable `PplnsLedger`** (`src/pplns.rs`)
  shared as `Arc<PplnsLedger>` by every worker. Payout credit spans all miners
  (a payout share can only be computed pool-wide), exposed via a `/pplns` JSON
  query and aggregate Prometheus gauges. Accounting only — no custody, no
  payout sending.
- **G2 — re-dial-until-unique extranonce.** The log-only collision guard becomes
  a bounded re-dial loop (`src/extranonce.rs::claim_unique`): on a colliding
  node-assigned `extranonce1` the proxy re-dials the upstream up to
  `extranonce_redial_max` times to get a not-in-use value, falling back to
  log + count + serve. It never spins forever.
- **G3 — read-only DAG-frontier observer.** A dependency-free JSON-RPC client
  (`src/rpc.rs`) polls `getdaginfo` / `getblocktemplate` and exports DAG
  gauges. Multi-tip **steering** is documented as infeasible without a node
  change (see the verdict below); this ships only honest observability.

---

## New / changed environment variables

All variables layer over `ProxyConfig::default()`; an unset variable keeps the
default, and a set-but-unparseable variable is a hard startup `Config` error
(fail fast on a typo). Sprint-2 additions are marked **NEW**.

| Variable | Field | Default | Meaning |
|---|---|---|---|
| `BLOCH_POOL_LISTEN` | `listen_addr` | `0.0.0.0:3335` | Where miners connect. |
| `BLOCH_POOL_UPSTREAM` | `upstream_addr` | `127.0.0.1:3333` | Node Stratum endpoint. |
| `BLOCH_POOL_METRICS` | `metrics_addr` | `127.0.0.1:9333` | Prometheus + `/pplns` HTTP endpoint. |
| `BLOCH_POOL_KEEPALIVE_SECS` | `keepalive_idle` | `20` | Idle re-feed interval. |
| `BLOCH_POOL_HANDSHAKE_SECS` | `handshake_timeout` | `15` | Downstream handshake ceiling (slowloris guard). |
| `BLOCH_POOL_VARDIFF` | `vardiff_override` | `false` | Proxy-side vardiff override. |
| `BLOCH_POOL_PPLNS_WINDOW` | `pplns_window_shares` | `100000` | **G1** count cap of the pool-wide PPLNS window (0 disables retention). |
| `BLOCH_POOL_PPLNS_WINDOW_SECS` | `pplns_window_secs` | `0` | **NEW (G1)** time bound of the PPLNS window, seconds (0 disables the time bound). |
| `BLOCH_POOL_EXTRANONCE_REDIAL_MAX` | `extranonce_redial_max` | `3` | **NEW (G2)** max upstream re-dials to escape a colliding `extranonce1` before serving the overlap. `0` = never re-dial. |
| `BLOCH_POOL_RPC` | `rpc_addr` | `127.0.0.1:16210` | **NEW (G3)** node JSON-RPC address for the read-only DAG observer. |
| `BLOCH_POOL_RPC_POLL_SECS` | `rpc_poll_secs` | `10` | **NEW (G3)** DAG observer poll interval, seconds (must be ≥ 1). |
| `BLOCH_POOL_RPC_API_KEY` | `rpc_api_key` | *(none)* | **NEW (G3)** optional `X-API-Key` for the RPC poll; empty = no key. |
| `BLOCH_POOL_RPC_OBSERVER` | `rpc_observer_enabled` | `true` | **NEW (G3)** enable/disable the DAG observer (`1`/`true`/`on` vs `0`/`off`). |
| `BLOCH_POOL_MAX_WORKERS` | `max_workers` | `4096` | Concurrent downstream connection cap. |

---

## The metrics + `/pplns` HTTP endpoint

The endpoint on `metrics_addr` speaks minimal HTTP/1.1 and does **path-based
routing**:

- **`GET /pplns`** (any path starting with `/pplns`) → `200 application/json`.
  The body is `serde_json` of `ledger.credit()`: a JSON array of the current
  PPLNS window's per-worker payout credit. Each element is a `PplnsCredit`:

  ```json
  [
    { "worker": 1, "shares": 42, "weight": 512.0, "fraction": 0.63 },
    { "worker": 2, "shares": 25, "weight": 300.0, "fraction": 0.37 }
  ]
  ```

  - `worker` — the pool's monotonic worker id.
  - `shares` — accepted shares retained for that worker in the window.
  - `weight` — that worker's raw difficulty-weighted contribution (a
    non-positive difficulty counts as unit weight so credit is never lost).
  - `fraction` — normalized payout share; all fractions sum to ~1.0.

  An empty (or zero-weight) window returns `[]`. This is **accounting only** —
  the shape a downstream payout job consumes verbatim; the proxy sends no funds.

- **Any other path** (e.g. `GET /metrics`, `GET /`) → `200 text/plain` with the
  Prometheus exposition text, exactly as in Sprint 1.

The request head is read under a bounded time (`~5s`) and byte cap
(`8 KiB`), so a peer that connects and then stalls is answered `408` and
dropped rather than pinning a task; the end-of-head scan runs over the whole
accumulated buffer so the `\r\n\r\n` marker is never missed across reads.

### New Prometheus series (Sprint 2)

| Series | Type | Meaning |
|---|---|---|
| `bloch_pool_extranonce1_redials_total` | counter | **G2** upstream re-dials to escape a colliding `extranonce1`. |
| `bloch_pool_extranonce1_unresolved_total` | counter | **G2** workers served with an overlapping space after the re-dial budget was exhausted. |
| `bloch_pool_dag_tip_count` | gauge | **G3** current DAG tip count (frontier width); spikes = DAG widening. |
| `bloch_pool_dag_block_count` | gauge | **G3** total blocks in the node's DAG. |
| `bloch_pool_dag_tip_blue_score` | gauge | **G3** blue score of the node's selected tip. |
| `bloch_pool_dag_tip_height` | gauge | **G3** height of the node's selected tip. |
| `bloch_pool_template_parent_count` | gauge | **G3** parent count of the latest `getblocktemplate` (multi-parent width). |
| `bloch_pool_rpc_poll_failures_total` | counter | **G3** failed read-only RPC polls (node down/refusing). |
| `bloch_pool_pplns_window_shares` | gauge | **G1** accepted shares currently in the PPLNS window. |
| `bloch_pool_pplns_window_weight` | gauge | **G1** total difficulty weight in the window (payout denominator). |
| `bloch_pool_pplns_distinct_workers` | gauge | **G1** distinct workers with a share in the window. |

**Honesty note (advisor LOW):** `bloch_pool_blocks_found_total`'s HELP text is
downgraded to state it is a **Sprint-2 stub** — always `0` unless a future
block-detection hook lands. A stratum `result:true` cannot distinguish a solved
block from an ordinary accepted share, so operators must not read `0` as "the
pool never wins".

---

## G3 multi-tip feasibility — HONEST VERDICT

**Pool-influenced multi-tip is NOT achievable on this node without a node
change, and per-worker tip steering is a NO-OP by GhostDAG design.** Grounding
read directly in the node's code:

1. **Via stratum `:3333`** — `session.rs::install_fresh_template` builds every
   job's parents from `d.tips()` (ALL current DAG tips). There is **no** stratum
   message a miner/pool can send to select or subset tips; the node picks
   parents internally. Every job already merges every tip, so "mine different
   tips" is inherently a no-op.

2. **Via RPC `getblocktemplate` (`:16210`)** — it ALSO snapshots `d.tips()` as
   `parents` and accepts **no** `parents` argument. You cannot request a
   template built on specific / subset tips; parent selection is not part of the
   request.

3. **`submitblock`** requires a fully-assembled, PoW-solved block via
   `Block::from_bitcoin_bytes`. This proxy deliberately computes no SHA-256d and
   rebuilds no templates, and cannot without linking consensus (forbidden). So
   an "RPC-templated multi-parent job manager" is out: the RPC neither takes
   parent selection nor accepts share-derived work.

**Achievable slice G3 ships:** a read-only DAG-frontier **observer** that polls
`getdaginfo` (tip / tip_count / block_count / tip_blue_score / tip_height /
tips[]) and `getblocktemplate` (parents[] / height / blue_score) and exports the
`bloch_pool_dag_*`, `bloch_pool_template_parent_count`, and
`bloch_pool_rpc_poll_failures_total` series. This gives real, honest
DAG-widening / split visibility (tip_count spikes) with **zero fake steering**.

**Node change that TRUE multi-tip would require:** a new `getblocktemplate` that
accepts an explicit `parents` array to build a template on chosen/subset tips,
**plus** a per-parent share/submit path so share-derived work can be attributed
and submitted per parent. Neither exists today.

---

## Tests

- `cargo test` — 130 unit tests + 2 end-to-end integration tests pass.
- `tests/integration_pump.rs` drives the real `router::run_worker` pump (its
  Sprint-2 five-arg signature) against a mock node: it asserts an accepted share
  lands in the pool-wide `PplnsLedger`, that hostile downstream input
  (partial / oversize / malformed lines) terminates the worker without panicking,
  and that a forced `extranonce1` collision across two workers trips the G2
  re-dial / unresolved metrics.
- `src/metrics.rs` tests cover the `/pplns` JSON surface, the presence of every
  new gauge/counter over the wire, the request-head read timeout (`408`), and
  the `blocks_found` stub HELP text.
