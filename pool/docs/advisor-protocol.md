# Advisor review — protocol correctness & liveness (distributed-systems lens)

Scope: `pool/src/{lib,main,protocol,job,shares,payout,state,stratum,upstream,dashboard}.rs`
and `pool/src/bin/miner.rs`, read against the real PoW/consensus in
`crates/bloch-sis-pow` and `crates/bloch-crypto`, plus the node's
`getblocktemplate`/`submitblock` seam (`src/rpc/mod.rs:561`) and
`accept_block` (`src/main.rs:1286`).

Overall the SIS-native dialect is **sound in its core flow**: a submit
carries `[address, job_id, nonce_hex(16), solution_hex(512)]`
(`protocol.rs:31-34`), the pool re-derives the preimage from `job_id`
and verifies with the *same* consensus verifier at a softer target
(`stratum.rs:281-284`, `verify_regime`), and the share target is
pool-global and committed inside the preimage's `bits`
(`job.rs:172-179`), so a miner cannot grind a softer target. Job → share
→ submit is well-defined and self-describing. The findings below are the
gaps, ranked most-severe first.

---

## 1. HIGH — The entire ledger is in-memory only; any restart or crash wipes all owed PPLNS credits and block history
**Where:** `state.rs:102-128` (all state in `PoolState`, no store),
`shares.rs:69-101` (`ShareLedger` is pure RAM), `main.rs:67-139` (no
signal handler, no persistence, no graceful shutdown), `Cargo.toml`
(no storage dependency).

**Failure sequence:** miners contribute shares for hours → the PPLNS
window, per-miner `credited_sat`, and `blocks_found` all live only in
`Mutex<ShareLedger>` → operator restarts the daemon (deploy, OOM,
`SIGINT`, node upgrade) → the process exits immediately (stratum::run is
just `.await`ed in `main`, no `tokio::signal`) → **every share credit
and every record of which block paid whom is gone.** A block reward that
already landed on-chain (subject to coinbase maturity) now has no ledger
saying how to split it. This is the one bug that directly loses miners
money the pool owes them.

**Fix — LARGE/debatable (defer to human):** persist the ledger. Minimum
viable: periodically (and on a `tokio::signal::ctrl_c()` shutdown path)
serialize `ShareLedger` (window + `miners` + `blocks_found`) to a JSON
file and reload on boot. A real deployment wants an append-only share
log. Either way this is a design addition, not a one-line patch — flag
for the operator, and at minimum document loudly that credits are
volatile.

---

## 2. MEDIUM-HIGH — Duplicate-share guard keys on `job_id`, so identical physical work can be credited twice across two live jobs that share a preimage
**Where:** dedup key is `(job_id, nonce, aux8)` in
`shares.rs:77`, `shares.rs:104-109`; inserted at `stratum.rs:302-307`.

**Failure sequence:** the preimage is
`version‖parents‖merkle‖timestamp‖bits` (`job.rs:32-34`,
`core/mod.rs:546`). The only field that distinguishes two templates with
the same tip+mempool is `timestamp = tmpl.cur_time`, which the node
reports in **whole seconds** (`rpc/mod.rs` `cur_time: now.as_secs()`). If
the tip changes twice inside one wall-clock second (plausible on a
GhostDAG with parallel blocks), the template loop cuts job A and job B
with **different `job_id`s but a byte-identical preimage**
(`main.rs:159-167`). A miner finds one `(nonce, s)` and submits it under
both ids: `find_job(A)` and `find_job(B)` both succeed, `verify_regime`
passes for both (same preimage), and the dedup keys `(A,nonce,aux8)` and
`(B,nonce,aux8)` differ → **both credited.** One unit of work, two
credits, diluting every honest miner in the PPLNS window.

Note the `aux` hash already binds the preimage, nonce, and `s`
(`verify.rs:146-157`), so `job_id` in the key only *loosens* it. There is
no legitimate case where the same `aux8` under two `job_id`s is two
distinct units of work.

**Fix — SMALL/safe (apply now):** drop `job_id` from the dedup key —
make it `(nonce, aux8)` (or just `aux8`). Change the `HashSet` type in
`shares.rs:77` and the `record_submission` signature/body
(`shares.rs:104-109`) and its call site (`stratum.rs:302-307`). Strictly
tightens dedup; the existing tests that use distinct `job`s with the same
`(nonce, aux)` (`shares.rs:210`) should be updated to reflect that
identical aux is now always a duplicate.

**Related, same file — LOW:** `record_submission` clears the whole dup
set at 65 536 entries (`shares.rs:105-107`). After a wipe, a share for a
job still inside the 8-job retention window can be replayed and
re-credited. The `(nonce, aux8)` change above narrows it; a per-job LRU
(the comment already admits this) would close it. Defer.

---

## 3. MEDIUM — Unbounded per-session output channel + no connection cap = trivial memory-exhaustion DoS
**Where:** `mpsc::unbounded_channel()` at `stratum.rs:73`; accept loop
inserts a session per connection with no cap at `stratum.rs:46-60`;
`main.rs` broadcasts a notify to every authorized session each tip change
(`main.rs:173-176`).

**Failure sequence:** a client subscribes+authorizes, then stops reading
its socket (or just stalls). The writer task (`stratum.rs:75-81`) blocks
on `write_all`, so nothing drains `rx`. Every `mining.notify` /
`set_difficulty` the pool pushes (`session.send_line`) queues into the
**unbounded** channel and is never freed until the 600 s idle timeout
(`IDLE_TIMEOUT_SECS`, `stratum.rs:39`) finally drops the session. N such
sockets → unbounded RAM growth for ~10 minutes each. Because `accept()`
is an uncapped loop, a connection flood also races the session-id counter
(see #5) and allocates state per connect with no backpressure.

**Fix — SMALL/safe (apply now):** (a) use a bounded channel
(`mpsc::channel(N)`, e.g. 256) and have `send_line` drop the message /
disconnect the session on `try_send` failure instead of buffering
forever; (b) add a `max_sessions` cap in the accept loop
(`stratum.rs:47-50`) — on exceed, close the socket immediately. Both are
localized.

---

## 4. MEDIUM — Node downtime: the pool serves a stale job forever with no age cap; miners burn work on a dead tip
**Where:** `template_loop` at `main.rs:144-183`; error arm just warns
(`main.rs:156`); `current_job()` keeps returning the last job
(`state.rs:138-140`).

**Failure sequence:** node goes down or starts erroring →
`get_block_template` returns `Err` each tick → the loop logs "node down?"
and sleeps (`main.rs:156,181`) — good, **no spin-loop**. But the last job
stays in `jobs` indefinitely, `current_job()` keeps handing it to newly
authorizing miners (`stratum.rs:199-201`), and every miner keeps grinding
a tip that may already be orphaned. If one finds a block-target share,
`submit_block` also fails against the dead node (`stratum.rs:337-339`) and
is only `warn!`-logged (`stratum.rs:356-360`) — the share was credited
but the block is lost. There is no staleness ceiling and no distinction
between "node briefly slow" and "node gone."

**Fix — SMALL/safe (apply now):** track the last successful template time
in `PoolState`; if it exceeds a threshold (e.g. `refresh_secs * N`), stop
handing `current_job()` to new subscribers and/or emit a `clean_jobs`
notify that pauses miners, and surface node-health in `/api/stats`
(`dashboard.rs:89-114`). The RPC client itself is otherwise robust:
required fields use `.ok_or` and malformed JSON returns `Err`
(`upstream.rs:88-130`), the 10 s `ureq` timeout (`upstream.rs:51`)
prevents a hang, and calls run under `spawn_blocking`
(`main.rs:151-153`) so a slow node can't block the runtime.

**Related — LOW:** `bits` is read as `u64` then cast `as u32`
(`upstream.rs:122`); a garbage oversized value truncates silently rather
than erroring. Tiny; validate range if you touch it.

---

## 5. MEDIUM — Nonce-range partitioning overflows after 2¹⁶ lifetime sessions, colliding two miners onto the same range
**Where:** `nonce_base = id << 48` at `state.rs:66`; ids are a
monotonic counter that never resets (`state.rs:110,130-132`); the pool
**never enforces** that a submitted nonce lies inside the session's
assigned range (`handle_submit`, `stratum.rs:218-321`).

**Failure sequence:** each session gets a disjoint 2⁴⁸-wide range, but
`id` keeps climbing for the pool's whole lifetime (every connect
increments it). At the 65 536th connection, `id << 48` overflows the u64
and wraps, so session *k* and session *k+65536* get the **same
`nonce_base`**. Both miners start at the same nonce over the same
preimage; the reference miner's candidate RNG is seeded purely from the
nonce (`solver.rs:166,236`), so they generate an **identical
candidate/share stream** → the second miner's every share is rejected as
a duplicate (#2 guard) and it earns nothing despite doing real work.
Reachable on any long-running pool.

**Fix — SMALL/safe but with a tradeoff (borderline; recommend applying):**
narrow the per-session width so the counter has far more headroom, e.g.
`nonce_base = id << 40` (2²⁴ ≈ 16.7 M sessions before wrap, each with a
2⁴⁰ range — a CPU miner needs ~weeks to exhaust 2⁴⁰). This is transparent
to clients (the miner reads `nonce_base` and never assumes a width,
`miner.rs:168-171`). A fuller fix (free-list of ranges, or seeding the
miner RNG with session entropy so equal ranges still diverge) is
LARGE/debatable — defer that part.

---

## 6. LOW-MEDIUM — Every submit spends a `spawn_blocking` verify, gated only by 240/min/session; no cheap pre-filter
**Where:** rate check then full verify at `stratum.rs:225-284`;
`SUBMIT_RATE_PER_MIN = 240` (`state.rs:24`).

**Failure sequence:** a decodable-but-invalid solution (valid hex, 512
bytes, real `job_id`) passes parse/decode and reaches `verify_regime` on
the blocking pool (`stratum.rs:281`). At 240/min/session that's 4/s/session
of forced ~1 ms lattice+SHAKE work; ~128 sustained hostile sessions can
saturate tokio's blocking pool. Not a wedge (verify is fast and capped),
but a cheap-to-mount amplification.

**Fix — SMALL/safe (apply now):** add near-free pre-checks before
`spawn_blocking` — reject if `nonce` is outside the session's assigned
range (`state.rs:66` gives base; width is known), and consider a lower
default submit cap. Combined with #3's connection cap this closes the
window.

---

## 7. LOW — Lock ordering is currently deadlock-free but undocumented and fragile
**Where:** `dashboard.rs:54-56` acquires `ledger` → `sessions` →
`jobs` (via `current_job()`) while all three guards are live;
`stratum.rs` and `main.rs` only ever hold one of these at a time
(`find_job` then a *separate* `ledger` lock in `handle_submit`,
`stratum.rs:265,299-309`). No path takes them in the opposite order, so
there is no inversion **today**. parking_lot mutexes don't poison, and no
lock is held across an `.await` (verify and submit both go through
`spawn_blocking`, `stratum.rs:281,337`). Good discipline overall.

**Fix — SMALL/safe (apply now):** add a one-line comment in `state.rs`
declaring the canonical acquisition order `jobs < ledger < sessions` (or
whatever you standardize) so a future edit doesn't introduce an
inversion. No code change required now.

---

## 8. LOW — Reference miner: imprecise cursor advance and full reset-to-base on every notify
**Where:** `miner.rs:145-149` (exhaustion advance) and
`miner.rs:202` (`*nonce_cursor = *nonce_base` on *every* notify, clean or
not).

**Detail:** on `AttemptsExhausted` the cursor advances by
`burst/candidates_per_nonce + 1`, which only approximates how many nonces
`mine()` actually consumed → occasional nonce re-scan → because
`mine()`'s RNG is nonce-deterministic (`solver.rs:236`), re-scanned
nonces reproduce identical candidates and waste cycles. And every
`mining.notify` resets the cursor to `nonce_base`, so the miner restarts
its search each job. This is **benign only because** `tmpl.cur_time`
changes the preimage on every template (so re-mined `(nonce,s)` yield a
new `aux` and aren't self-duplicates) — but it means the miner never
explores beyond the low end of its 2⁴⁸ range and does redundant work. It
correctly computes valid PoW via `bloch_sis_pow::solver::mine`
(`miner.rs:126`) and reconnection is not implemented (single connect;
`miner.rs:64`, exits on EOF `miner.rs:89-92`).

**Fix — SMALL/safe (apply now):** only reset the cursor on `clean == true`
notifies (parse `params[4]`), and advance the exhaustion cursor by the
exact nonces `mine()` reports consuming. LARGE/debatable: add reconnect
with backoff — fine to leave, since this binary is explicitly a
smoke-test client (`miner.rs:1-14`).

---

## 9. Nits (LOW)
- `dashboard.rs:29-35` parses the HTTP request from a single ≤2048-byte
  read; a request split across TCP segments or with >2 KB of headers
  mis-parses the path. GET-only localhost dashboard, so cosmetic. SMALL if
  you care: loop the read until you have the request line.
- `main.rs:114` clamps `refresh_secs` to ≥1 but there's no upper bound
  tying template freshness to the 30 s target block time
  (`difficulty.rs:21`); with a large `--refresh-secs` the pool serves
  work for tips that are many blocks stale before #4's cap would even
  engage. Document the recommended range.

---

### What is correct and should NOT be changed
- Coinbase construction matches consensus exactly: `Job::build` pays
  `subsidy + total_fees` and the founder-vesting output only when the
  template reports a delta (`job.rs:51-72`), which passes
  `validate_coinbase_value` (`core/mod.rs:1217`) — the pool uses the
  node's own subsidy/fee numbers rather than recomputing, so they agree.
- Share verification is the real consensus path at a softer target
  (`stratum.rs:281-284`), not a mock; block detection re-tests the same
  `aux` against the block target (`stratum.rs:314`). No target-grinding is
  possible — `bits` is inside the preimage (`job.rs:176-179`).
- Payout math conserves value across fee levels and odd splits, with
  overflow-safe `mul_div_floor` and dust explicitly assigned to the pool
  (`payout.rs:40-88`, tests `payout.rs:98-158`). No issue found here.
- Staleness signalling is present and reasonable: `clean_jobs` is set on
  tip change (`main.rs:159-176`), stale submits for aged-out jobs
  (>`JOB_RETENTION=8`) are rejected with code 21 and counted
  (`stratum.rs:265-272`, `state.rs:20`).
