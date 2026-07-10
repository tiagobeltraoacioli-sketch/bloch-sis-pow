# Tokenomics & Payout-Fairness Review — bloch-pool (reference PPLNS pool)

Reviewer: tokenomics/payout-fairness advisor (fable5). Scope: `pool/src/*` read-only,
cross-checked against `crates/bloch-crypto/src/core/tokenomics_v2.rs`.
Findings ranked most-severe first. Each has a minimal fix marked
**SMALL/safe (apply now)** or **LARGE/debatable (defer to human)**.

Verdict up front: the core PPLNS math is correct and conservative
(`payout.rs` conserves every satoshi, fee floors in miners' favor, rolling
window with no round resets is genuinely hop-resistant). The real problems are
around the *edges* of the accounting — orphaned blocks, process restarts, the
duplicate-share guard, and silent template-parse defaults.

---

## 1. HIGH — Credits are booked the instant `submitblock` returns, with no orphan / red-block / maturity handling

**Where:** `pool/src/stratum.rs:342-354` (`submit_found_block` → `record_block` on `Ok`);
`pool/src/shares.rs:145-162` (`record_block` credits `credited_sat` immediately);
`pool/src/payout.rs:20-23` (docstring acknowledges maturity but nothing enforces it).

**Scenario → wrong payout:** The node accepts the block, `record_block` credits
`reward_sat` across the window immediately. Bloch is a GhostDAG chain
(`blue_score`, multi-`parents` in `job.rs:80-91`): a block can be accepted at
submit time and later end up **red / reorged out**, in which case its coinbase
is never spendable by the pool. The ledger's `credited_sat` totals then exceed
the coins the pool actually holds — the pool is silently insolvent, and either
the operator eats the loss or (worse) the *last* miners to be disbursed are
shorted. The comment at `stratum.rs:357-359` handles submit-time rejection but
nothing handles post-acceptance orphaning. There is also no coinbase-maturity
gate before credits count as "owed."

**Fix (SMALL/safe, apply now — disclosure layer):** Add an explicit
`confirmed: bool` (default `false`) to `FoundBlock` (`shares.rs:59-67`), expose
it in `/api/stats` (`dashboard.rs:80-87`), and add one line to the dashboard
footer (`dashboard.rs:199-204`): "Credits from a block are provisional until
its coinbase matures; an orphaned/red block's credits are reversed by the
operator." This makes the ledger honest about what it is.

**Fix (LARGE/debatable, defer to human — enforcement layer):** A confirmation
loop that polls the node (e.g. `getdaginfo` / a block-status RPC) until the
found block is N-deep blue, flipping `confirmed = true` or reversing the
per-miner credits (`credited_sat` saturating_sub of the recorded `payouts`).
Requires deciding the maturity depth and a reversal policy — human call.

---

## 2. HIGH — The entire debt ledger lives in RAM; a restart erases miners' owed balances and the PPLNS window

**Where:** `pool/src/shares.rs:69-101` (`ShareLedger` — no persistence anywhere);
`pool/src/state.rs:115-121` (fresh `ShareLedger::new` on every start).

**Scenario → unfair split / lost funds:** `credited_sat` is, per the pool's own
docs (`payout.rs:20-23`), the ledger of what the operator owes each miner.
A crash or routine restart zeroes it — coins already received in the pool
address now correspond to no recorded debt, i.e. they default to the operator.
The wiped PPLNS window is also a fairness hole: shares mined just before a
restart earn nothing if a block lands just after (empty window → 100%
`pool_take`, the exact case tested at `shares.rs:243-248`). A malicious
operator could even *time* restarts to harvest this. The dashboard footer
(`dashboard.rs:199-204`) does not disclose volatility.

**Fix (SMALL/safe, apply now):** (a) Append-only JSONL persistence of accepted
shares and found-block payouts (flush on `record_block`, periodic for shares),
reloaded at startup — ~40 lines, no behavior change on the hot path; at
minimum persist `miners` (`credited_sat`) and `blocks_found` on every
`record_block`. (b) One dashboard-footer sentence: "Ledger is in-memory in
this reference; the operator must snapshot credits before restarts." Do (b)
immediately even if (a) waits.

**Fix (LARGE/debatable):** Full WAL/db-backed ledger with window recovery.

---

## 3. MEDIUM — Wholesale `dup.clear()` lets already-paid shares be replayed and double-credited

**Where:** `pool/src/shares.rs:104-109` (`record_submission`: at 65,536 entries
the whole dedup set is cleared); interaction with `pool/src/state.rs:20`
(`JOB_RETENTION = 8` jobs, ≈4 minutes at the 30 s job cadence in
`main.rs:143-177`).

**Scenario → double payout:** The dedup set grows monotonically with every
accepted share pool-wide and is cleared *wholesale* at the cap. After a clear,
any `(job_id, nonce, aux8)` a miner submitted in the last ~4 minutes (jobs
still in retention) passes `record_submission` again and is credited a second
time at zero additional work — `record_share` at `stratum.rs:308` fires again.
A hoarding miner who watches `shares_accepted` on the public dashboard
(`dashboard.rs:108`) can predict the clear (it triggers at a known global
count) and replay a burst, inflating their window weight up to the 240/min
rate cap (`state.rs:24`). This is exactly the "outsized reward vs a steady
miner" gaming that PPLNS is supposed to prevent.

**Fix (SMALL/safe, apply now):** Scope dedup to live jobs instead of a global
set: key the structure as `HashMap<String /*job_id*/, HashSet<(u64, [u8;8])>>`
and drop a job's entry when the job leaves retention (`PoolState::push_job`,
`state.rs:147-155`, already knows the evicted job). Replay of an evicted job
is already impossible (`JobNotFoundOrStale`, `stratum.rs:265-273`), so
per-job scoping removes the replay window entirely and bounds memory by
retention, not by a global counter. No consensus or payout code touched.

---

## 4. MEDIUM — Template parsing silently defaults reward fields to 0 and silently drops undecodable transactions

**Where:** `pool/src/upstream.rs:124` (`subsidy_sat` → `unwrap_or(0)`),
`upstream.rs:127` (`total_fees` → `unwrap_or(0)`), `upstream.rs:123`
(`cur_time` → `unwrap_or(0)`), `upstream.rs:108-116` (transactions parsed with
three chained `filter_map`s — hex/decode failures vanish silently);
consumed at `pool/src/job.rs:51-54,105`.

**Scenario → zero-reward blocks / permanently wasted hashrate:** If a node
version renames or omits `subsidy_sat`, the pool builds a coinbase paying
`0 + fees` and credits miners from `reward_sat = 0` — miners' work is spent on
blocks worth nothing to them, with no error anywhere. Worse: if any mempool tx
fails `Transaction::from_stratum_bytes`, the block *omits* that tx but the
coinbase still claims the template's full `total_fees` — the coinbase
over-claims fees for a tx not in the block, `validate_coinbase_value` rejects
it at the node, and **every block attempt fails silently forever** (only the
`warn!` at `stratum.rs:359`); miners keep submitting shares that can never
convert to reward. Contrast: `height` and `bits` correctly hard-error
(`upstream.rs:120,122`).

**Fix (SMALL/safe, apply now):** In `get_block_template`, make `subsidy_sat`,
`total_fees`, and `cur_time` `ok_or("template missing …")?` like
`height`/`bits`, and convert the transaction `filter_map`s into a
`Result`-collecting loop that fails the whole template on any decode error
(the poll loop already handles `Err` gracefully at `main.rs:156`).
**Also SMALL:** in `Job::build`, cross-check
`tmpl.subsidy_sat == bloch_crypto::core::tokenomics_v2::block_subsidy_sat(tmpl.height)`
and log an error on mismatch — the pool then never trusts a divergent node
across a halving boundary (halvings at `HALVING_INTERVAL = 1_036_800`,
`tokenomics_v2.rs:75`, tail floor at `tokenomics_v2.rs:91-104`).

---

## 5. MEDIUM — PPLNS window is not snapshotted at block-find; it drifts during the submit RPC round-trip

**Where:** `pool/src/stratum.rs:313-318` (block detected in `handle_submit`,
then `submit_found_block` awaits a blocking RPC up to 10 s —
`upstream.rs:51`); `stratum.rs:343-344` (`record_block` reads the window only
*after* the node responds); window mutation in the meantime via
`shares.rs:112-124`.

**Scenario → wrong payout at the block boundary:** Between the block-winning
share's acceptance and the node's `submitblock` response, other shares keep
landing in the window. Each one (a) is paid out of a block it arrived too late
to contribute to, and (b) when the window is full, **evicts the oldest share**
(`shares.rs:114-116`) — a steady miner's share that genuinely backed the block
drops out of that block's split. With the default 4096-share window this is
sub-percent noise, but with a small window or a slow node it is a real,
systematic transfer from steady miners to whoever submits during the round
trip. Correct PPLNS pays the last N shares *as of the winning share*.

**Fix (SMALL/safe, apply now):** In `handle_submit`, capture
`let contribs = pool.ledger.lock().window_contributions();` at the moment
`hash_meets_target` passes (right before the `record_share`d winning share —
which is already in the window at `stratum.rs:308`, correctly including the
finder), pass `contribs` into `submit_found_block`, and add a
`record_block_with(contribs, …)` variant in `shares.rs` that skips the
internal re-read. Pure plumbing; payout math unchanged.

---

## 6. LOW — `credited_sat` (and other u64 sats) serialized as JSON numbers: silent precision loss in the dashboard above 2^53

**Where:** `pool/src/dashboard.rs:76` (`"credited_sat": st.credited_sat` as a
raw number; contrast line 74 where `weight` is correctly stringified);
also `reward_sat` at `dashboard.rs:83`.

**Scenario → misreported owed balance:** JS `Number` is exact only to 2^53
(≈ 9.0e15 sat ≈ 90 M BLOCH). At the initial 8,400 BLOCH subsidy
(`tokenomics_v2.rs:73`), a miner's lifetime credit crosses that after ~10,700
block-equivalents of credit — the dashboard then rounds the balance it claims
the pool owes. An honesty tool must not do approximate arithmetic on debts.

**Fix (SMALL/safe, apply now):** Serialize `credited_sat` (and `reward_sat`,
`pool_take_sat`, `est_next_block_sat`) as strings like `weight` already is;
`fmtSat` in the inline JS parses with `Number()` for display only (display
rounding is fine; the API must stay exact).

---

## 7. LOW — `est_work_rate` under-reports the pool work rate (and therefore overstates "bad luck")

**Where:** `pool/src/shares.rs:169-177`; displayed at `dashboard.rs:104`,
`dashboard.rs:228`.

**Scenario → misleading effort stat:** The 10-minute rate is computed *only
over shares still in the PPLNS window*. If the pool's share rate exceeds
`window_cap / 600` (≈ 6.8 shares/s at defaults), eviction cuts into the
10-minute horizon and the rate reads low; same during the first 10 minutes of
uptime (divides by the full `horizon_secs` regardless). Miners comparing
displayed rate to blocks found will infer worse luck than reality — the
opposite of the honest-luck requirement, even if unintentional.

**Fix (SMALL/safe, apply now):** Divide by
`min(horizon_secs, now - started_unix, now - oldest_share_in_window.unix)`
(floor at 1), or keep an O(1) rolling `(weight, timestamp)` accumulator
independent of the payout window. One function, no payout impact.

---

## 8. LOW — `nonce_base = id << 48` overflows after 65,536 sessions → honest miners' shares collide and are rejected as duplicates

**Where:** `pool/src/state.rs:52,67` (`nonce_base: id << 48`);
`state.rs:130-132` (monotonic session ids, never reused);
duplicate rejection at `stratum.rs:304-307`.

**Scenario → unfair rejection:** Session 65,537 computes `65_537u64 << 48`,
which wraps (release mode) to the same nonce base as session 1. Two honest
miners then grind overlapping nonce ranges; the slower one's identical
`(job, nonce, aux8)` finds are refused as duplicates — lost credit through no
fault of theirs. Reconnect-heavy miners burn ids fast, so this is reachable
in weeks, not years.

**Fix (SMALL/safe, apply now):** Allocate the 16-bit prefix as
`(id % 0xFFFF) + 1` *and* log a prominent warning on wrap, or (cleaner, still
small) hand out prefixes from a free-list released on session close
(`stratum.rs:58`). Collisions with a live session must be impossible;
collisions with dead sessions are harmless.

---

## 9. LOW — Node-rejected block submissions are invisible to miners

**Where:** `pool/src/stratum.rs:356-360` (rejection → `warn!` only; nothing in
the ledger or `/api/stats`).

**Scenario → unauditable losses:** If blocks are being rejected (race, or the
poisoned-template failure in finding 4), the dashboard shows normal shares and
zero blocks — indistinguishable from bad luck. Miners cannot audit whether the
pool is competent/honest about conversion of work into blocks.

**Fix (SMALL/safe, apply now):** Add `blocks_rejected: u64` (and optionally a
last-rejection reason string) to `ShareLedger`, increment in the `Err` arm,
expose it in `stats_json`'s `totals` block (`dashboard.rs:106-111`).

---

## 10. INFO — Project-rule and premine-honesty check (mostly PASSES; two items for the human)

**PPLNS core math — pass.** `payout.rs:40-61`: conservation is exact
(`miners.sum() + pool_take == reward_sat`, tested at `payout.rs:98-110`); the
fee floors *down* (miner-favorable, `payout.rs:43`); rounding dust is
explicit, bounded by `contributors − 1` sat, and displayed per block
(`dashboard.rs:85,241-243`). `mul_div_floor` (`payout.rs:70-88`) is
conservative under its overflow fallback (can only under-distribute to
`pool_take`, never over-pay). Window eviction is exact-N with no off-by-one
(`shares.rs:113-117`), the block-winning share is itself credited
(`stratum.rs:308` precedes `:314`), and the winner is credited to the
*authorized* address, not the spoofable submit param (`stratum.rs:260-262`).

**Pool-hopping — resists it, as designed.** Rolling count-based window at
fixed share difficulty with no round resets (`shares.rs:10-14`) gives every
share the same expected value regardless of timing; a hopper gains nothing
over a steady miner *except* via findings 2 (empty window after restart), 3
(dup replay), and 5 (round-trip drift) above — fix those and the hop
resistance is real.

**Reward integrity — pass.** `reward_sat` is never hardcoded: it is
`template.subsidy_sat + total_fees` per job (`job.rs:105`), the coinbase pays
exactly that (`job.rs:51-54`), and the node's `validate_coinbase_value`
recomputes subsidy/vesting from height (`job.rs:139-162` exercises it), so a
divergence across a halving cannot silently mispay — the block simply fails
(subject to finding 4's silent-default caveat).

**17% founder premine — handled honestly.** The pool constructs the founder
vesting output exactly per consensus (`job.rs:55-60`: exact
`founder_vesting_sat` to the template's founder hash, only when non-zero),
matching `tokenomics_v2.rs:152-224` (3.57B BLOCH = 17% of 21B nominal,
10-yr cliff + 480 monthly tranches, `FOUNDER_PREMINE_TOTAL_SAT` at
`tokenomics_v2.rs:52`). Nothing in the pool hides, skims, or contradicts the
premine; the miner-facing `reward_sat` correctly excludes the founder output
(it is additional issuance, not a deduction from miners). *Optional SMALL
polish:* one dashboard-footer sentence — "On monthly vesting boundaries the
coinbase additionally carries the consensus-mandated founder vesting tranche
(17% premine, 10-yr cliff / 40-yr monthly vest); this is chain consensus, not
a pool fee" — so funders/users see the disclosure where they look.

**Fee/no-token-revenue rule — compliant with two flags for the human:**
- The fee defaults to **0** (`main.rs:37-38`), is hard-capped at 10%
  (`payout.rs:35,41`; enforced again at config, `main.rs:80-83`), and is
  disclosed in three places (startup log `main.rs:117`, dashboard tile
  `dashboard.rs:233`, footer `dashboard.rs:200-202`). No hidden fee path
  exists — I traced every subtraction from `reward_sat`; only `fee` and
  rounding dust reach `pool_take`, both displayed.
- **Flag A (wording, SMALL):** a non-zero `fee_bps` is *coin-denominated*
  revenue for whoever operates a fork. For the project's own deployment the
  rule "no revenue line touches the token" means running with `fee_bps = 0`
  (the default) — worth one explicit sentence in README/dashboard: "The
  reference deployment charges 0; any fee a third-party operator sets is
  their service fee, in the open."
- **Flag B (custody, LARGE/debatable, defer to human):** the design has the
  pool address *custody* the coinbase until manual disbursement
  (`payout.rs:20-23`). It is disclosed, transitory, and inherent to
  centralized pooled mining — but it *is* custody of miners' coins. The
  decentralized alternative (paying the top-K window contributors directly as
  coinbase outputs) would eliminate custody entirely at the cost of coinbase
  size and dust rules. Human decision.
- No code path sells, lists, prices, or exchanges the coin; the dashboard
  actively states the coin "is worth nothing by design" (`dashboard.rs:179-181`).

---

## Suggested apply-now list for the pool-builder agent (all SMALL/safe)

1. Finding 3 — per-job dedup scoping (removes the replay double-credit).
2. Finding 4 — hard-error template fields + fail on tx decode + subsidy cross-check.
3. Finding 5 — snapshot `window_contributions()` at block-find.
4. Finding 1/2 disclosure lines — `confirmed` flag on `FoundBlock` + two footer sentences (provisional credits; in-memory ledger).
5. Finding 6 — stringify sat amounts in `/api/stats`.
6. Finding 9 — `blocks_rejected` counter.
7. Finding 7 — clamp `est_work_rate` horizon.
8. Finding 8 — session nonce-prefix free-list (or wrap-with-warning stopgap).

Deferred to human: orphan-reversal policy + maturity depth (1), persistent
ledger design (2), custody model / direct-coinbase payout (10, Flag B).
