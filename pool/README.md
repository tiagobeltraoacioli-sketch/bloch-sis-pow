# bloch-pool — reference mining pool for Bloch-SIS-PoW

A **reference, non-production** mining pool: SIS-native stratum dialect,
PPLNS share accounting with a maturity-gated credit lifecycle, a
journaled (restart-surviving) ledger, JSON-RPC upstream to a Bloch node,
and an honest-by-design dashboard. It ships with a reference CPU miner
(`bloch-pool-miner`) that doubles as runnable protocol documentation,
and a Shamir 2-of-3 seed-recovery utility (`bloch-pool-keyshard`) for
the procedural-custody workflow.

## Read this first (the honest part)

This section is a hard project ethos, not marketing copy. Do not soften
it when forking.

* **Bloch is mainnet beta and UNAUDITED.** A security audit is
  contracted but has not happened yet. The network is young and
  51%-attackable. Treat everything here accordingly.
* **The coin is not a security and not an asset.** There is no token
  sale and no listing. This pool **never custodies or sells the
  token** — it only *accounts* shares and lets miners point work at a
  node. No revenue line of this project touches the token; the pool's
  optional fee (default **0%**) is an operator setting, not a project
  revenue stream.
* **This is reference code.** It exists so there can be *many*
  independent pools, not one. It is deliberately a standalone cargo
  workspace so it can be vendored and forked without dragging in the
  node. Advisor-flagged holes have been closed (see the end of this
  file), but it remains unaudited and is not hardened for production.

### Solo vs pool

Solo mining is the default and needs **no pool**: `bloch --mine` on a
node mines standalone, and if you find a block you get the whole
reward. The pool is strictly **optional**. Its only honest purpose is
variance smoothing: a small miner who would find a solo block once a
month can instead earn a proportional slice of every block the pool
finds, via PPLNS. The expected income is the same (minus any pool fee);
only the variance changes. If your hashrate is large enough that solo
variance doesn't hurt, solo mine.

### Decentralization warning

A pool that grows past ~51% of network hashrate **is a 51%-attack
vector against the very network it serves** — regardless of the
operator's intentions, it is a single point of coercion, failure, and
censorship. This is the opposite of most pool marketing, on purpose:

* **Do not point your hashrate at the biggest pool.** Prefer small
  pools; leave a pool that is approaching a majority.
* **Run your own.** This code is MIT-licensed reference software
  precisely so forking and self-hosting is easy.
* **Solo mine when you can.** Every solo miner is a decentralization
  win.

The daemon prints this warning at startup, the dashboard shows it in a
banner, and the dashboard *actively estimates this pool's share of
network hashrate* — turning into an explicit "move your hashrate
elsewhere" warning as the pool approaches the majority line. Forks are
asked to keep all three. **Do not operate this pool at a scale
approaching 51% of the network.**

## Architecture

```text
  Bloch node (bloch --mine ... --rpc-port 16210)
    ▲  JSON-RPC: getblocktemplate / submitblock / getblockhash
    │
  bloch-pool
    ├── upstream   — RPC client; template polling; block submission;
    │                canonical-hash maturity checks
    ├── job        — template → coinbase(pool addr) → Block skeleton
    │                → 76-byte PoW preimage (BlockHeader::pow_preimage)
    ├── stratum    — miner-facing TCP server (SIS-native V1 dialect,
    │                address-ownership proof at authorize)
    ├── shares     — per-miner weighted share ledger + PPLNS window,
    │                JSONL-journaled; blocks credit only on maturity
    ├── payout     — pure payout math (PPLNS, fee_bps, default 0%)
    └── dashboard  — self-contained HTTP dashboard + /api/stats
    ▲                (incl. honest luck / share-of-network panel)
    │  stratum+tcp (newline JSON), default :3335
  miners (reference CPU miner: bloch-pool-miner)
```

The pool depends only on the two lean protocol crates (`bloch-crypto`,
`bloch-sis-pow`) — not on the full node. All work and submissions go
over the node's JSON-RPC.

### The SIS-native stratum dialect

The node's own Bitcoin-style Stratum V1/V2 server refuses to start
under Module-SIS: classic `mining.submit` params have no field for the
256-coefficient solution vector `s` that every valid block carries.
This pool keeps Stratum V1's framing (newline-delimited JSON, 24 KiB
line cap — PQ-sized for the hybrid pubkey/signature in authorize),
method names, session state machine and error codes, but the params are
SIS-native (full spec in `src/protocol.rs`):

| Method | Params / result |
|---|---|
| `mining.subscribe` | result `[[["mining.notify", sid]], nonce_base_hex, 0, challenge_hex]` — each session gets a disjoint 2^40-wide u64 nonce range starting at `nonce_base` (replaces extranonce; enforced at submit), plus a fresh 32-byte challenge for the ownership proof |
| `mining.authorize` | `[address, password, pubkey_hex, signature_hex]` — the username must be a valid Bloch bech32 address; by default the pool also requires proof the connection controls it: the hybrid ML-DSA-65 ‖ Falcon-1024 public key whose SHA3-256 hash is the address, and its signature over `"bloch-pool-authorize-v1" ‖ challenge` (same signature scheme as consensus, reused from `bloch-crypto`). Shares/credit are refused for an address the connection cannot prove it controls. `--no-auth-proof` disables |
| `mining.set_difficulty` | `[share_bits]` — compact bits the SHAKE-256 aux hash must meet for a share |
| `mining.notify` | `[job_id, preimage_hex, block_bits_hex, height, clean_jobs]` — `preimage_hex` is the 76-byte header preimage |
| `mining.submit` | `[address, job_id, nonce_hex(16), solution_hex(512)]` — `solution_hex` is the canonical `encode_s` encoding of `s` |

Share validation is the real consensus verifier
(`bloch_sis_pow::verify_regime`), pointed at the softer share target.
If a share's aux hash also meets the *block* target, it is assembled
into a full block and pushed to the node via `submitblock`. Shares are
credited to the **authorized** address, not the submit param.
Duplicate shares are keyed on the **preimage** (a share's true
identity), never cleared wholesale, and pruned with job retention — so
neither dedup-set churn nor two jobs cut with the same preimage can
double-credit one unit of work.

Note the PoW is **not lattice-hard**: Bloch-SIS-PoW is SHAKE-256
cumulative-work hashcash with a Module-SIS *structural gate*. Shares
here are plain hash-difficulty shares; no lattice bit-security number
attaches to any of this.

### PPLNS accounting and the credit lifecycle

Documented contract (kept in sync with `src/payout.rs` /
`src/shares.rs`):

1. The ledger retains the last `--pplns-window` shares (default 4096).
   No round resets — old shares age out naturally, which blunts
   pool-hopping.
2. Each share weighs the hashcash expected-work of the share bits
   (`work_from_bits`, the same formula the node uses for chain work),
   so a future vardiff pool credits proportionally out of the box.
3. When a block is found, the PPLNS window is **snapshotted at the
   winning share** — shares arriving during the node round-trip neither
   join nor evict that block's split. The fee is taken first
   (`reward * fee_bps / 10000`, floors, capped at 10%), the remainder
   is split pro-rata over the snapshot (floors), and rounding dust (at
   most `contributors − 1` sats) plus the fee is the pool take.
   `sum(miners) + pool_take == reward`, always — explicit, not hidden.
4. **Instant credit is gated behind maturity.** An accepted block is
   recorded *pending*; its credits are booked only once it is the
   canonical block at its height at `--confirm-depth` (default 10). A
   block that is orphaned/reorged out before maturity has its pending
   credit **dropped, never booked** — the ledger can't drift above what
   the pool actually holds.
5. **The ledger survives restarts.** Every accepted share and block
   event is appended to a JSONL journal (`--journal`, flushed per
   event) and replayed at startup — a restart cannot erase owed
   balances or the PPLNS window, and an operator cannot "time" restarts
   to harvest an empty window.
6. **Credits are ledger entries, not payments.** The block reward lands
   in the pool's on-chain address (subject to coinbase maturity);
   disbursing credits is a wallet transaction the operator makes
   manually — under the dual-control procedure below. This reference
   implements the accounting, not custody automation — and by project
   rule it never sells or lists the token.

### Custody (procedural M-of-N)

Pooled mining unavoidably means the pool address briefly custodies the
coinbase until disbursement. Here is the honest state of the art for
Bloch and what this reference ships:

* **Cryptographic threshold signing is not available.** Bloch's hybrid
  ML-DSA-65 ‖ Falcon-1024 signatures have no practical MPC/threshold
  construction today (2027+ research), and the chain is strictly
  single-signature P2PKH with **no script system** — on-chain k-of-n
  multisig requires a consensus change, roadmapped separately as
  **GIP-008**. Nothing in this pool pretends otherwise.
* **What ships instead is *procedural* M-of-N**, two parts:

  **1. Sharded seed recovery — `bloch-pool-keyshard`.** Split the
  pool wallet's 32-byte seed into 3 Shamir shares (any 2 reconstruct;
  one share alone reveals nothing) and hand one to each custodian:

  ```sh
  bloch-pool-keyshard split --seed-hex <64-hex seed>     # → 3 shares
  bloch-pool-keyshard recover --share <hex> --share <hex> # → the seed
  ```

  Honest label, exactly as the tool prints it: this is **key recovery
  for disaster resilience, not threshold signing**. At recovery (and
  at every signing) the seed exists whole in one process on one
  machine. Run both operations offline; clear shell history. The
  field math is the vetted `sharks` crate, not hand-rolled.

  **2. Dual-control disbursement procedure** (operational guidance,
  deliberately not enforced by code — the daemon is keyless):

  * The signing wallet lives on an **isolated machine** (no pool
    daemon, no inbound network); the seed is never on the pool host.
  * **Two people approve every disbursement**: one prepares the
    payout list from the dashboard/journal (`/api/stats` credits are
    exact strings; the JSONL journal is the audit trail), the second
    independently checks it against the journal before the
    transaction is signed.
  * **Minimize custodied float**: disburse frequently, so the pool
    address never accumulates more than a short window of matured
    rewards. The confirmation gate already keeps unmatured rewards
    out of "owed".
  * On operator change or suspected compromise: recover from 2
    shards, sweep to a fresh seed, re-shard, redistribute.

### The honest dashboard

`GET /` serves a self-contained HTML page (no external assets);
`GET /api/stats` serves the same numbers as JSON. It shows exactly what
the ledger knows — per-miner shares, confirmed credits, the estimated
next-block split, blocks with their pending/confirmed/orphaned status,
node-rejected submissions, and the explicit pool take — plus:

* an **honest luck panel**: expected blocks (Σ share-work / block-work)
  vs blocks actually found, pool-wide and **per miner** — so both bad
  luck and *statistical block withholding* are visible instead of
  indistinguishable;
* a rolling **share-of-network estimate** that escalates to a "move
  your hashrate elsewhere" warning as the pool nears the 51% line;
* node health (seconds since the last good template; new miners get no
  work from a stale tip).

Sat amounts in `/api/stats` are serialized as **strings**: JS numbers
lose exactness past 2^53, and an honesty tool must not do approximate
arithmetic on debts. The work-rate figure is labeled **candidates/s**
(one candidate = seed expansion + SIS residual gate + aux hash), not
bare hash/s, because that is what it actually measures.

## Building

The pool is a standalone workspace. It re-declares the node's
`[patch.crates-io]` for the vendored `pqcrypto-internals` fork (a
standalone workspace does not inherit the parent's patch table).

```sh
cd pool
cargo build --release
cargo test
```

## Running

You need a Bloch node with RPC enabled (`getblocktemplate` /
`submitblock` / `getblockhash`).

Pool daemon:

```sh
RUST_LOG=info bloch-pool \
  --pool-address bloch1q...      # required: where block rewards land
  --node-rpc http://127.0.0.1:16210 \
  --fee-bps 0 \                  # pool fee in basis points; capped at 1000 (10%)
  --share-bits 2100ffff \        # compact share difficulty (hex); fixed, no vardiff
  --pplns-window 4096 \          # PPLNS window size, in shares
  --confirm-depth 10 \           # blocks credit only once canonical at this depth
  --journal bloch-pool.journal \ # JSONL ledger journal ("" = memory-only, testing)
  --listen 0.0.0.0:3335 \        # miner-facing stratum
  --dashboard 127.0.0.1:8650 \   # dashboard HTTP (keep it loopback or proxied)
  --refresh-secs 5 \             # template poll interval (keep well under the 30 s block time)
  --coinbase-tag bloch-pool-ref/v0.1
  # --no-auth-proof              # disable the address-ownership proof (not recommended)
```

Reference miner:

```sh
bloch-pool-miner \
  --address bloch1q...           # required: your payout address
  --auth-seed <hex 32B seed> \   # wallet seed controlling --address (signs the
                                 # pool's ownership challenge; required unless the
                                 # pool runs --no-auth-proof)
  --auth-index 0 \               # optional: diversified-address index for the seed
  --pool 127.0.0.1:3335 \
  --max-shares 0 \               # exit after N accepted shares (0 = forever)
  --burst 200000                 # candidates per burst between socket polls
```

Operational behavior worth knowing:

* New jobs are cut when the tip changes (`clean_jobs = true` — old work
  can no longer win; miners restart their nonce search) and
  periodically (every `refresh-secs × 6`) to absorb mempool churn
  (miners keep their nonce cursor).
* Submissions may reference any of the last 8 jobs; older ones are
  rejected as stale. Submitted nonces must lie in the session's
  assigned 2^40 range.
* Sessions: 30 s to authorize, 600 s idle timeout, 240 submits/min cap,
  1024 global / 16 per-IP session caps, bounded (64-line) write queues
  — a client that stops reading is dropped, not buffered forever.
* The template is cross-checked against consensus: a node reporting a
  subsidy that disagrees with `block_subsidy_sat(height)` gets no job
  cut from it, and a template with any undecodable transaction is
  rejected whole (a silently dropped tx would make every block fail
  validation while miners' work is wasted).
* If the node is unreachable for longer than `refresh-secs × 12`, newly
  authorizing miners get no (stale) job until a fresh template arrives,
  and the dashboard shows the node as unreachable.

## Honest limits (what this reference is NOT)

* **Not audited, not production.** Same status as the chain itself.
* **No vardiff.** One fixed share difficulty for every miner. Fast
  miners waste round trips; slow miners wait long between shares.
* **Journal is append-only and grows forever.** Rotation/compaction is
  the operator's problem; the format is one JSON object per line,
  trivially archivable.
* **Confirmation is canonical-hash-at-height.** On a GhostDAG that is a
  conservative approximation of coinbase spendability, not a full
  blue-set proof.
* **Not fully hardened for hostile operators.** The *operator* is
  trusted: nothing stops a fork from lying on its dashboard — verify
  pools by their behavior, or run your own. Session caps, rate caps,
  bounded queues and the ownership proof harden the miner-facing side,
  but this has not seen adversarial production traffic.
* **No TLS.** Neither stratum nor the dashboard terminates TLS. If you
  expose either beyond localhost, put it behind a reverse proxy
  (nginx / caddy) and terminate TLS there. Keep the dashboard bound to
  loopback unless deliberately published.
* **Single upstream node, no failover.** If the node is down the pool
  logs, withholds stale work from new miners, and retries.
* **Manual payouts only** — see the credit lifecycle above. The pool
  daemon has no wallet and no keys, by design.

## Advisor findings — implemented

Three concurrent advisor reviews (see `docs/advisor-security.md`,
`docs/advisor-protocol.md`, `docs/advisor-tokenomics.md`) were triaged;
everything technically implementable was implemented:

* Maturity/confirmation gate: pending → confirmed/orphaned credit
  lifecycle at `--confirm-depth`, PPLNS split snapshotted at the find.
* Persistent ledger: flushed JSONL journal, replayed at startup.
* Preimage-keyed share dedup, retention-based pruning (no wholesale
  clears → no replay window).
* Global + per-IP session caps; bounded per-session write queues;
  dashboard read timeout (slowloris guard).
* Address-ownership proof at authorize (hybrid ML-DSA-65 ‖ Falcon-1024
  challenge signature; default on, `--no-auth-proof` to disable).
* Honest luck / expected-vs-found / share-of-network dashboard panel
  (statistical block-withholding visibility) + per-miner effort stats.
* Node-rejected block counter; node-health surfacing; stale-template
  gate for new miners.
* Template hardening: reward fields hard-error, tx decode failures
  reject the template, `bits` range-checked, subsidy cross-checked
  against consensus per height.
* Exact (string) sat serialization in `/api/stats`; work-rate horizon
  clamping.
* Nonce ranges: 24-bit cycling prefix over 2^40 ranges (no silent
  overflow), range enforced at submit as a cheap pre-verify filter.
* Reference miner: cursor kept across non-clean jobs, exact burst
  advance, signs the ownership challenge from `--auth-seed`.
* Procedural M-of-N custody: Shamir 2-of-3 seed recovery
  (`bloch-pool-keyshard`) + documented dual-control disbursement
  procedure (see "Custody" above).

## Advisor findings — deferred (human triage)

These await an explicit operator/maintainer decision — they are policy
or architecture calls, deliberately not imposed by this reference:

* **Cryptographic (not procedural) custody.** Procedural M-of-N is
  implemented (see "Custody"); the true end-states remain roadmapped:
  on-chain k-of-n multisig needs the GIP-008 consensus change, MPC
  threshold signing for the PQ hybrid scheme is 2027+ research, and
  paying top-K window contributors directly in the coinbase (zero
  custody, at the cost of coinbase size/dust policy) is a design
  decision for the maintainers. (tokenomics #10 Flag B)
* **Fee wording for fork operators.** A non-zero `fee_bps` on a fork is
  coin-denominated revenue for whoever runs that fork. The project's
  own deployments run `fee_bps = 0` per the "no revenue line touches
  the token" rule; the exact README/dashboard wording that third-party
  operators must carry for their own fees is a policy sentence the
  maintainers should settle. (tokenomics #10 Flag A)
* **Lifetime miner-map bounding.** `ShareLedger::miners` grows with
  every distinct address that ever lands a share (work-gated, so not
  free to inflate — but unbounded). Bounding it means choosing a policy
  for *dropping rows that may record owed credit*, which is not a call
  reference code should make silently. (security #7)
* **Dashboard request parsing** reads a single ≤2 KiB segment (GET-only,
  loopback-by-default; cosmetic). (protocol #9)
* **Miner reconnect/backoff** — the reference miner intentionally stays
  a single-connection smoke-test client. (protocol #8, large part)
