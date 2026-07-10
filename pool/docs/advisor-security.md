# bloch-pool — adversarial security review

Read-only review of the reference pool (`pool/src/*.rs`, `pool/src/bin/miner.rs`).
Lens: how a hostile miner or network peer abuses **this** code. Ranked most-severe first.
Each finding cites `file:line`, the concrete attack (inputs → bad outcome), and a minimal fix
tagged **SMALL/safe (apply now)** or **LARGE/debatable (defer to human)**.

Two structural things the pool gets RIGHT (so we don't "fix" them):

- **Reward cannot be redirected.** Miners only ever submit `(nonce, solution)`
  (`stratum.rs:217`, `:333`). The pool assembles the block from its OWN template whose
  coinbase pays the pool address (`job.rs:51-72`), and the PoW preimage commits to that
  coinbase via the merkle root (`job.rs:77`, `:97`). Altering the payout would change the
  preimage and invalidate the share. Good.
- **No key/custody in the daemon.** Credits are ledger entries (`shares.rs:52-56`,
  `payout.rs:18-23`); disbursement is a manual operator wallet action. There is no automated
  payout path to steal from. Good.

---

## 1. CRITICAL — Unbounded, unauthenticated sessions → memory / FD / CPU exhaustion

**Where:** `stratum.rs:46-61` (accept loop inserts every connection into `pool.sessions`
with no cap and no per-IP limit); `stratum.rs:184-192` (`mining.authorize` only checks that
the username *parses* as a bech32 address — no signature, no proof of key ownership);
`stratum.rs:281-284` (each accepted submit runs the full `verify_regime` SHAKE/k-row
expansion in `spawn_blocking`); rate limit is **per session** only (`state.rs:24`, `:87-99`).

**Attack:** open N TCP connections (addresses are free to mint, so each can `subscribe` +
`authorize` instantly and dodge the 30 s auth-timeout that only culls *un*authorized
sessions, `stratum.rs:88`). Each session is an `Arc<Session>` + a spawned task + an
**unbounded** mpsc channel (see #2), held for up to `IDLE_TIMEOUT_SECS = 600` (`stratum.rs:39`).
There is no ceiling on session count, so:
- memory / file-descriptor exhaustion from raw connection count, and
- CPU exhaustion: the 240/min submit cap is per session, so N sessions each spray garbage
  solutions at 240/min → **N × 240/min** invocations of the expensive `verify_regime`
  (verification must run before validity is known — cheap to send, expensive to check).

**Fix (SMALL/safe):** add a global session cap and a per-IP cap in `stratum.rs:run()` before
inserting into `pool.sessions` — e.g. reject accept when `sessions.len() >= MAX_SESSIONS`
(pick ~1–2k) and when a peer-IP already holds >K sessions (K≈16). Close the socket
immediately on rejection. This bounds memory, FDs, and aggregate verify-CPU in one change.

**Fix (LARGE/defer):** optional proof-of-address-ownership on `authorize` (sign the session
id / a challenge with the address key) to make Sybil authorization costly. Debatable — hurts
casual miners; the caps above are the pragmatic mitigation.

---

## 2. HIGH — Unbounded writer channel → stalled reader inflates pool memory

**Where:** `stratum.rs:73` — `mpsc::unbounded_channel::<String>()` feeds the per-session
writer task; `send_line` (`state.rs:75-80`) never applies backpressure.

**Attack:** connect, `subscribe` + `authorize`, then stop reading from the socket (TCP recv
window closes). The pool keeps enqueuing every `mining.notify` (one per job, every few
seconds — `main.rs:173-176`) plus responses into the unbounded queue forever. Memory per
stalled session grows without limit; combine with #1 for a fast blow-up.

**Fix (SMALL/safe):** use a bounded channel (`mpsc::channel(CAP)`, CAP≈64) and on
`try_send`/full treat it as a dead-slow client: drop the session (`send_line` returns false →
the loop already breaks on false at `stratum.rs:102`). A miner that can't keep up with notify
traffic is not usefully mining anyway.

---

## 3. HIGH — Wholesale duplicate-set clear opens a share-replay / double-credit window

**Where:** `shares.rs:104-109` — when the dup guard reaches `MAX_DUP_ENTRIES = 65_536`
(`shares.rs:85`) it does `self.dup.clear()` (whole set wiped).

**Attack:** after the clear, any previously-accepted `(job_id, nonce, aux8)` is no longer
recorded, so `record_submission` returns `true` again and `record_share` credits it a second
time (`stratum.rs:304-308`). A share stays replayable as long as its `job_id` is still in the
8-job retention window (`state.rs:20`). On a busy pool the set fills and clears on its own,
so miners can re-submit their last-retention-window shares for **duplicate PPLNS credit** with
no new work; an attacker can also deliberately drive the set to the cap to trigger it.

**Fix (SMALL/safe):** never clear wholesale. Prune dup entries by job: when a job leaves the
retention window (`state.rs:147-155`, `push_job` pop_front), delete its dup entries. The set
is then bounded by `retained_jobs × shares_per_job` and no replay window ever opens. (Keying
dup entries on `job_id` already namespaces them, so a retention-driven sweep is a small,
local change to `ShareLedger`.)

---

## 4. HIGH — Block withholding is undetectable (inherent, but nothing surfaces it)

**Where:** `stratum.rs:313-318` — a block is submitted upstream ONLY if the miner chose to
submit the block-target solution. The pool never sees solutions the miner withholds, and
nothing compares expected vs. actual block cadence.

**Attack:** a miner submits share-target solutions (collects PPLNS credit) but discards any
solution that also meets `job.block_target`, sabotaging the pool's find rate while getting
paid. The code cannot distinguish a "share" from a withheld "block" it never received, and
has no variance/luck monitor (`est_work_rate`, `shares.rs:169-177`, is never compared to
realized block finds).

**Fix (LARGE/defer):** this is unsolvable at the share-protocol level for this scheme — the
honest mitigation is the project's own stance (many small pools, `lib.rs:6-15`). What the
reference *can* add: a dashboard "luck" panel — expected blocks = Σ(share weight) / network
work vs. actual `blocks_found` — so sustained under-performance (withholding or bad luck) is
at least visible. Defer: it's a real feature, not a one-line fix, and false-positive-prone at
low sample counts.

---

## 5. MEDIUM — Colliding job preimages let one unit of work be credited multiple times

**Where:** `main.rs:162-167` cuts a fresh `job_id` on every periodic refresh
(`ticks % 6 == 0`) even when the tip is unchanged; `job.rs:84-97` builds the preimage from
`timestamp = tmpl.cur_time` and the (unchanged) parents/merkle. The dup guard is keyed on
`job_id` (`shares.rs:77`, `:104-108`), NOT on the preimage.

**Attack:** if two retained jobs share an identical preimage — same parents, same mempool/
merkle, and same `cur_time` across two polls (possible when the node returns a coarse or
unchanged `cur_time`, or the tip is stale for a periodic cycle) — a single valid `(nonce,
solution)` verifies against BOTH. Submitting it under each `job_id` yields two accepted shares
(different dup keys) from one unit of work. Up to `JOB_RETENTION = 8` (`state.rs:20`)
duplicates if that many jobs share the preimage. This is a share-count inflation / unfair
PPLNS weighting vector; it does not require the clear in #3.

**Fix (SMALL/safe):** key the dup guard on the **preimage** (or a hash of it), not `job_id` —
`(preimage_hash, nonce, aux8)`. A share proves work over a preimage, so that is the correct
identity. Cheap change in `record_submission` + its one caller. (Bonus: also dedupe job
creation — skip `push_job` when the new job's preimage equals the current job's — but the
dup-key change is the security-critical part.)

---

## 6. MEDIUM — Dashboard socket has no read timeout → idle-hold / slowloris FD DoS

**Where:** `dashboard.rs:29-33` — `socket.read(&mut buf).await` with no timeout; a spawned
task per connection.

**Attack:** connect to the dashboard port and send nothing. `read` awaits forever, pinning a
task + FD. Unbounded such connections exhaust file descriptors (and can starve the whole
process). Unlike the stratum path, there is no `tokio::time::timeout` guarding this read
(compare `stratum.rs:93-96`).

**Fix (SMALL/safe):** wrap the read in `tokio::time::timeout(Duration::from_secs(5), ...)` and
drop the connection on timeout; optionally cap concurrent dashboard tasks. One-line-ish.

---

## 7. LOW/MEDIUM — `miners` ledger map grows unbounded for the pool's lifetime

**Where:** `shares.rs:78` (`miners: HashMap<String, MinerStats>`), inserted at
`shares.rs:119-124` and `:149-152`, never pruned.

**Attack / concern:** each distinct address that lands an accepted share (real work, so not
free) adds a permanent entry; evicted-from-window miners are deliberately retained
(`shares.rs:223-224`). Over a long-running pool, or under a low-but-sustained Sybil that
rotates fresh addresses while doing minimal work, the map and every `/api/stats` response
(`dashboard.rs:71-78` serializes ALL miners) grow without bound.

**Fix (SMALL/safe):** cap the number of retained lifetime miner rows (e.g. keep top-N by
weight + those active in the window) and/or paginate `/api/stats`. Low urgency because entry
creation is work-gated, but the unbounded growth + full serialization is worth bounding.

---

## 8. LOW — Nonce-range partitioning is cosmetic and overflows past 2^16 sessions

**Where:** `state.rs:66` `nonce_base = id << 48`; `handle_submit` (`stratum.rs:242-248`)
never checks the submitted nonce falls in the session's assigned `[nonce_base, +2^48)` range.

**Attack / concern:** the "disjoint 2^48 range per session" (`protocol.rs:19-21`) is advisory
only — a miner may submit any nonce. This is not a forgery (work is still real and verified),
so no theft; but the partitioning claim doesn't hold, and `id << 48` silently drops high bits
once `id ≥ 2^16`, so ranges start overlapping/wrapping after 65 536 sessions, causing honest
miners to duplicate effort.

**Fix (SMALL/safe):** either enforce `nonce_base ≤ nonce < nonce_base + 2^48` in
`handle_submit` (reject otherwise), or drop the disjoint-range language and document nonces as
unpartitioned. Given the dup guard already prevents literal replay, documenting is the minimal
honest fix; enforcing is stricter. Either way, guard the `id << 48` shift against overflow.

---

## 9. LOW — Dashboard cannot lie *structurally*, but two honesty gaps exist

**Where:** `dashboard.rs:53-115`. All figures derive from the verified-share ledger, so the
**reference** dashboard can't fabricate hashrate/luck without code edits — consistent with the
project ethos. Two caveats worth a doc note:

- `est_candidates_per_sec_10m` (`shares.rs:169-177`) divides windowed weight by a fixed 600 s,
  but the PPLNS window caps at `pplns_window` shares; under high volume, shares older than the
  cap are evicted and the rate **under-reports**. Honest-but-imprecise; the label already says
  "estimated". Leave as-is or compute the true elapsed span of the summed shares.
- No **pool-share-of-network** figure. The pool has `bits` from the template
  (`upstream.rs:31`) and its own work rate, so it *could* estimate and display its fraction of
  network hashrate — directly serving the "any pool near 51% is an attack vector" ethos
  (`lib.rs:6-10`). **LARGE/defer:** a real feature; today the ethos is served only by the
  static banner (`dashboard.rs:172-188`), which cannot warn when THIS pool actually gets large.

---

### Apply-now shortlist (safe, mechanical)
1. Global + per-IP session cap (#1).
2. Bounded writer channel, drop slow clients (#2).
3. Retention-driven dup pruning instead of wholesale clear (#3).
4. Dup key on preimage-hash, not job_id (#5).
5. Read timeout on the dashboard socket (#6).

### Defer to human (design calls)
- Withholding/luck variance panel (#4), address-ownership proof (#1), miner-map bounding policy
  (#7), nonce-range enforce-vs-document (#8), pool-share-of-network surfacing (#9).
