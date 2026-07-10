//! Per-miner share accounting.
//!
//! A share is a `(nonce, s)` pair whose SHAKE-256 aux hash meets the
//! pool's SHARE target (easier than the block target). Shares are
//! **hash-difficulty shares** — the Module-SIS residual is a structural
//! gate every candidate must pass, not a security parameter, so share
//! weight is the plain hashcash expected-work of the share's compact
//! bits (`work_from_bits`, same formula the node's GhostDAG uses for
//! accumulated block work in `src/pow/mod.rs`).
//!
//! PPLNS window: the ledger retains the last `window_cap` shares. When
//! a block is found, the reward is split pro-rata over that window (see
//! payout.rs). Older shares age out naturally — no round resets, which
//! blunts pool-hopping.
//!
//! Credit lifecycle (advisor finding: no instant credit): a found block
//! is recorded **pending** with its PPLNS split snapshotted at the
//! moment of the find. Credits are only booked to `credited_sat` when
//! the block *confirms* (canonical at its height at `confirm_depth`);
//! an orphaned/red block's pending credit is dropped, never booked.
//!
//! Persistence (advisor finding: RAM-only ledger): every accepted
//! share and every block event is appended to a JSONL journal and
//! flushed, and the journal is replayed at startup — a restart no
//! longer erases miners' owed balances or the PPLNS window.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use bloch_sis_pow::bits_to_target;

use crate::payout::{split_reward, Payout};

/// Hashcash expected-work of a share/block at compact difficulty `bits`.
/// Mirrors the node's `pow::work_from_bits` exactly (u128 over the top
/// 16 target bytes) so pool weights and chain work share one unit.
pub fn work_from_bits(bits: u32) -> u128 {
    let target = bits_to_target(bits);
    let mut t_val: u128 = 0;
    for &b in target.as_bytes().iter().take(16) {
        t_val = (t_val << 8) | b as u128;
    }
    if t_val == 0 { u128::MAX } else { u128::MAX / t_val }
}

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

/// One accepted share in the PPLNS window.
#[derive(Clone, Debug)]
pub struct Share {
    pub address: String,
    pub weight:  u128,
    pub unix:    u64,
}

/// Lifetime per-miner stats (not windowed).
#[derive(Clone, Debug, Default)]
pub struct MinerStats {
    pub shares:          u64,
    pub weight:          u128,
    pub last_share_unix: u64,
    /// Sats credited from CONFIRMED blocks (PPLNS splits). Disbursement
    /// is an operator wallet action — see README "Payouts".
    pub credited_sat:    u64,
    /// Blocks whose aux hash met the block target attributable to this
    /// miner's expected work: `Σ share_weight / block_work`. Compared
    /// with `blocks_found` this makes statistical block withholding
    /// visible (a big-effort miner who never finds is a red flag).
    pub expected_blocks: f64,
    /// Block-target solutions this miner actually submitted.
    pub blocks_found:    u64,
}

/// Lifecycle of a block this pool found. Credits are booked only on
/// `Confirmed`; `Orphaned` blocks never credit anyone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockStatus {
    Pending,
    Confirmed,
    Orphaned,
}

impl BlockStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            BlockStatus::Pending   => "pending",
            BlockStatus::Confirmed => "confirmed",
            BlockStatus::Orphaned  => "orphaned",
        }
    }
}

/// A block this pool found, with the payout split snapshotted at the
/// moment of the find (PPLNS pays the last N shares *as of the winning
/// share*, not as of the node's submit response).
#[derive(Clone, Debug)]
pub struct FoundBlock {
    pub height:        u64,
    pub hash_hex:      String,
    pub reward_sat:    u64,
    pub unix:          u64,
    pub finder:        String,
    pub status:        BlockStatus,
    pub payouts:       Vec<(String, u64)>,
    pub pool_take_sat: u64,
}

pub struct ShareLedger {
    /// Compact share difficulty every session currently mines at.
    pub share_bits:   u32,
    pub fee_bps:      u16,
    window:           VecDeque<Share>,
    window_cap:       usize,
    /// Duplicate-share guard: (preimage, nonce, first 8 bytes of the
    /// aux hash). A share proves work over a PREIMAGE, so that — not
    /// the job id — is its identity: two retained jobs cut with the
    /// same preimage cannot double-credit one solution. Entries are
    /// work-gated (only verified shares insert) and pruned as jobs
    /// leave retention (`prune_dups`) — never cleared wholesale, which
    /// would re-open old shares for double credit.
    dup:              HashSet<(Vec<u8>, u64, [u8; 8])>,
    pub miners:       HashMap<String, MinerStats>,
    pub blocks_found: Vec<FoundBlock>,
    /// `submitblock` calls the node rejected outright — visible so
    /// miners can audit work-to-block conversion (bad luck looks
    /// identical to silent failure otherwise).
    pub blocks_rejected: u64,
    /// Pool-wide `Σ share_weight / block_work` — expected block finds
    /// implied by all accepted shares. `blocks_found / expected` is the
    /// pool's honest luck figure.
    pub expected_blocks: f64,
    pub started_unix: u64,
    pub shares_total: u64,
    pub stale_total:  u64,
    /// Append-only JSONL journal (None = memory-only, tests).
    journal:          Option<File>,
}

impl ShareLedger {
    pub fn new(share_bits: u32, fee_bps: u16, window_cap: usize) -> Self {
        Self {
            share_bits,
            fee_bps,
            window: VecDeque::with_capacity(window_cap.min(4096)),
            window_cap: window_cap.max(1),
            dup: HashSet::new(),
            miners: HashMap::new(),
            blocks_found: Vec::new(),
            blocks_rejected: 0,
            expected_blocks: 0.0,
            started_unix: now_unix(),
            shares_total: 0,
            stale_total: 0,
            journal: None,
        }
    }

    /// Ledger backed by a JSONL journal: replay `path` if it exists,
    /// then open it for appending. Every credit-relevant event is
    /// journaled + flushed so a restart cannot erase owed balances.
    pub fn with_journal(
        share_bits: u32, fee_bps: u16, window_cap: usize, path: &str,
    ) -> Result<Self, String> {
        let mut ledger = Self::new(share_bits, fee_bps, window_cap);
        if let Ok(contents) = std::fs::read_to_string(path) {
            for line in contents.lines() {
                ledger.replay(line);
            }
        }
        let file = OpenOptions::new().create(true).append(true).open(path)
            .map_err(|e| format!("journal {}: {}", path, e))?;
        ledger.journal = Some(file);
        Ok(ledger)
    }

    fn journal_append(&mut self, v: Value) {
        if let Some(f) = self.journal.as_mut() {
            let mut line = v.to_string();
            line.push('\n');
            if f.write_all(line.as_bytes()).and_then(|_| f.flush()).is_err() {
                // Loud, not silent: an unpersisted ledger is the exact
                // dishonesty the journal exists to prevent.
                log::error!("share journal write failed — persistence degraded");
            }
        }
    }

    /// Replay one journal line (startup only; never journals back).
    fn replay(&mut self, line: &str) {
        let Ok(v) = serde_json::from_str::<Value>(line) else { return };
        match v.get("t").and_then(|t| t.as_str()) {
            Some("share") => {
                let addr   = v.get("a").and_then(|x| x.as_str()).unwrap_or_default().to_string();
                let weight = v.get("w").and_then(|x| x.as_str())
                    .and_then(|s| s.parse::<u128>().ok()).unwrap_or(0);
                let unix   = v.get("u").and_then(|x| x.as_u64()).unwrap_or(0);
                let bits   = v.get("bb").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
                if !addr.is_empty() && weight > 0 {
                    self.apply_share(&addr, weight, bits, unix);
                }
            }
            Some("block") => {
                let payouts: Vec<(String, u64)> = v.get("po").and_then(|p| p.as_array())
                    .map(|arr| arr.iter().filter_map(|e| {
                        let a = e.get(0)?.as_str()?.to_string();
                        let s = e.get(1)?.as_str()?.parse::<u64>().ok()?;
                        Some((a, s))
                    }).collect())
                    .unwrap_or_default();
                self.apply_block_pending(FoundBlock {
                    height:        v.get("h").and_then(|x| x.as_u64()).unwrap_or(0),
                    hash_hex:      v.get("hash").and_then(|x| x.as_str()).unwrap_or_default().to_string(),
                    reward_sat:    v.get("r").and_then(|x| x.as_str())
                                       .and_then(|s| s.parse().ok()).unwrap_or(0),
                    unix:          v.get("u").and_then(|x| x.as_u64()).unwrap_or(0),
                    finder:        v.get("f").and_then(|x| x.as_str()).unwrap_or_default().to_string(),
                    status:        BlockStatus::Pending,
                    pool_take_sat: v.get("pt").and_then(|x| x.as_str())
                                       .and_then(|s| s.parse().ok()).unwrap_or(0),
                    payouts,
                });
            }
            Some("confirm") => {
                let hash = v.get("hash").and_then(|x| x.as_str()).unwrap_or_default();
                self.apply_confirm(hash);
            }
            Some("orphan") => {
                let hash = v.get("hash").and_then(|x| x.as_str()).unwrap_or_default();
                self.apply_orphan(hash);
            }
            Some("rejected") => self.blocks_rejected += 1,
            _ => {}
        }
    }

    /// Duplicate check + insert. Returns false if already seen.
    pub fn record_submission(&mut self, preimage: &[u8], nonce: u64, aux8: [u8; 8]) -> bool {
        self.dup.insert((preimage.to_vec(), nonce, aux8))
    }

    /// Drop dup entries whose preimage matches no retained job — called
    /// when a job leaves the retention window (state.rs `push_job`).
    /// A share for an evicted preimage is stale anyway, so forgetting
    /// it opens no replay; the set stays bounded by work in flight.
    pub fn prune_dups(&mut self, retained: &HashSet<Vec<u8>>) {
        self.dup.retain(|(preimage, _, _)| retained.contains(preimage));
    }

    fn apply_share(&mut self, address: &str, weight: u128, block_bits: u32, unix: u64) {
        if self.window.len() >= self.window_cap {
            self.window.pop_front();
        }
        self.window.push_back(Share { address: address.to_string(), weight, unix });

        // Expected-blocks accounting for the honest luck figure: this
        // share's weight as a fraction of one block's expected work.
        let exp = if block_bits != 0 {
            weight as f64 / work_from_bits(block_bits) as f64
        } else {
            0.0
        };
        self.expected_blocks += exp;

        let st = self.miners.entry(address.to_string()).or_default();
        st.shares += 1;
        st.weight = st.weight.saturating_add(weight);
        st.last_share_unix = unix;
        st.expected_blocks += exp;
        self.shares_total += 1;
    }

    /// Credit one accepted share to `address`. `block_bits` is the
    /// compact difficulty of the block the share was mined against
    /// (for the expected-blocks / luck accounting).
    pub fn record_share(&mut self, address: &str, weight: u128, block_bits: u32) {
        let t = now_unix();
        self.apply_share(address, weight, block_bits, t);
        self.journal_append(json!({
            "t": "share", "a": address, "w": weight.to_string(),
            "u": t, "bb": block_bits,
        }));
    }

    pub fn record_stale(&mut self) {
        self.stale_total += 1;
    }

    /// Aggregate the PPLNS window per address (input to payout math).
    pub fn window_contributions(&self) -> Vec<(String, u128)> {
        let mut agg: HashMap<&str, u128> = HashMap::new();
        for s in &self.window {
            let w = agg.entry(s.address.as_str()).or_insert(0);
            *w = w.saturating_add(s.weight);
        }
        let mut v: Vec<(String, u128)> =
            agg.into_iter().map(|(a, w)| (a.to_string(), w)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        v
    }

    fn apply_block_pending(&mut self, block: FoundBlock) {
        let st = self.miners.entry(block.finder.clone()).or_default();
        st.blocks_found += 1;
        self.blocks_found.push(block);
    }

    fn apply_confirm(&mut self, hash_hex: &str) -> Option<Vec<(String, u64)>> {
        let b = self.blocks_found.iter_mut()
            .find(|b| b.hash_hex == hash_hex && b.status == BlockStatus::Pending)?;
        b.status = BlockStatus::Confirmed;
        let payouts = b.payouts.clone();
        for (addr, amount) in &payouts {
            let st = self.miners.entry(addr.clone()).or_default();
            st.credited_sat = st.credited_sat.saturating_add(*amount);
        }
        Some(payouts)
    }

    fn apply_orphan(&mut self, hash_hex: &str) -> bool {
        match self.blocks_found.iter_mut()
            .find(|b| b.hash_hex == hash_hex && b.status == BlockStatus::Pending)
        {
            Some(b) => { b.status = BlockStatus::Orphaned; true }
            None => false,
        }
    }

    /// A block was accepted by the node: compute the PPLNS split over
    /// `contribs` — the window SNAPSHOT taken at the moment the winning
    /// share landed, so shares arriving during the submit round-trip
    /// neither join nor evict this block's split — and record the block
    /// as PENDING. Nothing is credited yet: credits are booked by
    /// `confirm_block` once the block matures, and dropped by
    /// `orphan_block` if it is reorged out.
    pub fn record_block_pending(
        &mut self,
        height:     u64,
        hash_hex:   String,
        reward_sat: u64,
        finder:     &str,
        contribs:   &[(String, u128)],
    ) -> Payout {
        let payout = split_reward(contribs, reward_sat, self.fee_bps);
        let unix = now_unix();
        self.apply_block_pending(FoundBlock {
            height,
            hash_hex: hash_hex.clone(),
            reward_sat,
            unix,
            finder: finder.to_string(),
            status: BlockStatus::Pending,
            payouts: payout.miners.clone(),
            pool_take_sat: payout.pool_take,
        });
        // u64 sats journal as strings: the journal is read back by us
        // (exact), and strings keep any external tooling out of the
        // JS 2^53 trap.
        let po: Vec<Value> = payout.miners.iter()
            .map(|(a, s)| json!([a, s.to_string()]))
            .collect();
        self.journal_append(json!({
            "t": "block", "h": height, "hash": hash_hex,
            "r": reward_sat.to_string(), "u": unix, "f": finder,
            "pt": payout.pool_take.to_string(), "po": po,
        }));
        payout
    }

    /// The block matured (canonical at `confirm_depth`): book its
    /// snapshotted credits. Returns the payouts booked, or None if the
    /// hash is unknown or not pending (idempotent).
    pub fn confirm_block(&mut self, hash_hex: &str) -> Option<Vec<(String, u64)>> {
        let payouts = self.apply_confirm(hash_hex)?;
        self.journal_append(json!({ "t": "confirm", "hash": hash_hex }));
        Some(payouts)
    }

    /// The block was reorged out / never became canonical: drop its
    /// pending credit. Returns false if unknown or not pending.
    pub fn orphan_block(&mut self, hash_hex: &str) -> bool {
        if !self.apply_orphan(hash_hex) {
            return false;
        }
        self.journal_append(json!({ "t": "orphan", "hash": hash_hex }));
        true
    }

    /// A `submitblock` the node rejected outright (race or bug).
    pub fn record_block_rejected(&mut self) {
        self.blocks_rejected += 1;
        self.journal_append(json!({ "t": "rejected" }));
    }

    /// Pending blocks awaiting maturity (for the confirmation loop).
    pub fn pending_blocks(&self) -> Vec<(u64, String)> {
        self.blocks_found.iter()
            .filter(|b| b.status == BlockStatus::Pending)
            .map(|b| (b.height, b.hash_hex.clone()))
            .collect()
    }

    /// Estimated pool work rate over the trailing `horizon_secs`:
    /// expected PoW candidates per second implied by accepted shares.
    /// (Honest label: for Bloch-SIS-PoW a "hash" is one full candidate
    /// evaluation — SHAKE seed expansion + residual check + aux hash —
    /// so this is candidates/s, not bare SHAKE calls/s.)
    ///
    /// Divides by the span actually covered — capped by uptime and by
    /// the oldest share still in the window — so window eviction or a
    /// young pool doesn't under-report the rate (honest-stat fix).
    pub fn est_work_rate(&self, horizon_secs: u64) -> f64 {
        if horizon_secs == 0 { return 0.0; }
        let now = now_unix();
        let cutoff = now.saturating_sub(horizon_secs);
        let w: u128 = self.window.iter()
            .filter(|s| s.unix >= cutoff)
            .map(|s| s.weight)
            .sum();
        let mut span = horizon_secs.min(now.saturating_sub(self.started_unix));
        if let Some(oldest) = self.window.front() {
            span = span.min(now.saturating_sub(oldest.unix.min(now)));
        }
        w as f64 / span.max(1) as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn work_from_bits_monotone_in_difficulty() {
        // Harder bits (smaller target) → more work per share.
        let easy = work_from_bits(0x2100ffff);
        let hard = work_from_bits(0x1d00ffff);
        assert!(hard > easy, "harder target must weigh more: {} vs {}", hard, easy);
    }

    #[test]
    fn shares_accumulate_per_miner() {
        let mut l = ShareLedger::new(0x2100ffff, 0, 100);
        l.record_share("alice", 10, 0x2100ffff);
        l.record_share("alice", 10, 0x2100ffff);
        l.record_share("bob", 10, 0x2100ffff);
        assert_eq!(l.miners["alice"].shares, 2);
        assert_eq!(l.miners["alice"].weight, 20);
        assert_eq!(l.miners["bob"].shares, 1);
        assert_eq!(l.shares_total, 3);
        assert!(l.expected_blocks > 0.0, "shares must accrue expected-blocks");
    }

    #[test]
    fn duplicate_submission_rejected() {
        let mut l = ShareLedger::new(0x2100ffff, 0, 100);
        assert!(l.record_submission(b"pre1", 5, [1; 8]));
        assert!(!l.record_submission(b"pre1", 5, [1; 8]), "same triple = duplicate");
        assert!(l.record_submission(b"pre1", 5, [2; 8]), "different solution = new share");
        assert!(l.record_submission(b"pre2", 5, [1; 8]), "different preimage = new share");
    }

    #[test]
    fn dup_prune_follows_job_retention() {
        let mut l = ShareLedger::new(0x2100ffff, 0, 100);
        assert!(l.record_submission(b"pre1", 5, [1; 8]));
        assert!(l.record_submission(b"pre2", 5, [1; 8]));
        let retained: HashSet<Vec<u8>> = [b"pre2".to_vec()].into_iter().collect();
        l.prune_dups(&retained);
        assert!(!l.record_submission(b"pre2", 5, [1; 8]), "retained entry survives prune");
        assert!(l.record_submission(b"pre1", 5, [1; 8]),
            "evicted preimage is forgotten (its job is stale anyway)");
    }

    #[test]
    fn window_evicts_oldest() {
        let mut l = ShareLedger::new(0x2100ffff, 0, 3);
        l.record_share("a", 1, 0x2100ffff);
        l.record_share("b", 1, 0x2100ffff);
        l.record_share("c", 1, 0x2100ffff);
        l.record_share("d", 1, 0x2100ffff); // evicts a
        let contribs = l.window_contributions();
        assert_eq!(contribs.len(), 3);
        assert!(!contribs.iter().any(|(addr, _)| addr == "a"));
        // Lifetime stats keep the evicted miner.
        assert_eq!(l.miners["a"].shares, 1);
    }

    #[test]
    fn block_credits_only_after_confirmation() {
        let mut l = ShareLedger::new(0x2100ffff, 0, 100);
        // alice 3 weight units, bob 1 → 75% / 25%.
        l.record_share("alice", 30, 0x2100ffff);
        l.record_share("bob", 10, 0x2100ffff);
        let contribs = l.window_contributions();
        let p = l.record_block_pending(7, "cafebabe".into(), 1_000, "alice", &contribs);
        assert_eq!(p.miners.len(), 2);
        // Pending: nothing booked yet.
        assert_eq!(l.miners["alice"].credited_sat, 0);
        assert_eq!(l.miners["bob"].credited_sat, 0);
        assert_eq!(l.miners["alice"].blocks_found, 1, "finder attribution is immediate");
        assert_eq!(l.blocks_found[0].status, BlockStatus::Pending);

        // Confirmation books the snapshot split.
        assert!(l.confirm_block("cafebabe").is_some());
        assert_eq!(l.miners["alice"].credited_sat, 750);
        assert_eq!(l.miners["bob"].credited_sat, 250);
        assert_eq!(p.pool_take, 0, "0% fee, exact split → nothing left for pool");
        assert_eq!(l.blocks_found[0].status, BlockStatus::Confirmed);
        // Idempotent: a second confirm books nothing.
        assert!(l.confirm_block("cafebabe").is_none());
        assert_eq!(l.miners["alice"].credited_sat, 750);
    }

    #[test]
    fn orphaned_block_never_credits() {
        let mut l = ShareLedger::new(0x2100ffff, 0, 100);
        l.record_share("alice", 10, 0x2100ffff);
        let contribs = l.window_contributions();
        l.record_block_pending(3, "deadbeef".into(), 1_000, "alice", &contribs);
        assert!(l.orphan_block("deadbeef"));
        assert_eq!(l.miners["alice"].credited_sat, 0);
        assert_eq!(l.blocks_found[0].status, BlockStatus::Orphaned);
        // Cannot confirm an orphaned block.
        assert!(l.confirm_block("deadbeef").is_none());
        assert_eq!(l.miners["alice"].credited_sat, 0);
    }

    #[test]
    fn payout_split_snapshotted_at_find() {
        let mut l = ShareLedger::new(0x2100ffff, 0, 100);
        l.record_share("alice", 10, 0x2100ffff);
        let contribs = l.window_contributions(); // snapshot: alice only
        // A late share lands during the (simulated) submit round-trip.
        l.record_share("bob", 1_000, 0x2100ffff);
        let p = l.record_block_pending(9, "feed".into(), 500, "alice", &contribs);
        assert_eq!(p.miners, vec![("alice".to_string(), 500)],
            "round-trip shares must not join the split");
    }

    #[test]
    fn block_with_no_shares_pays_pool() {
        let mut l = ShareLedger::new(0x2100ffff, 0, 100);
        let p = l.record_block_pending(1, "00".into(), 500, "", &[]);
        assert!(p.miners.is_empty());
        assert_eq!(p.pool_take, 500);
    }

    #[test]
    fn journal_roundtrip_restores_ledger() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("bloch-pool-journal-test-{}.jsonl", std::process::id()));
        let path_s = path.to_str().unwrap().to_string();
        let _ = std::fs::remove_file(&path);

        {
            let mut l = ShareLedger::with_journal(0x2100ffff, 0, 100, &path_s).unwrap();
            l.record_share("alice", 30, 0x2100ffff);
            l.record_share("bob", 10, 0x2100ffff);
            let contribs = l.window_contributions();
            l.record_block_pending(7, "aa".into(), 1_000, "alice", &contribs);
            l.confirm_block("aa");
            l.record_block_pending(8, "bb".into(), 1_000, "bob", &contribs);
            l.orphan_block("bb");
            l.record_block_rejected();
        }

        // Fresh process: replay the journal.
        let l = ShareLedger::with_journal(0x2100ffff, 0, 100, &path_s).unwrap();
        assert_eq!(l.miners["alice"].credited_sat, 750);
        assert_eq!(l.miners["bob"].credited_sat, 250);
        assert_eq!(l.miners["alice"].shares, 1);
        assert_eq!(l.miners["alice"].blocks_found, 1);
        assert_eq!(l.blocks_found.len(), 2);
        assert_eq!(l.blocks_found[0].status, BlockStatus::Confirmed);
        assert_eq!(l.blocks_found[1].status, BlockStatus::Orphaned);
        assert_eq!(l.blocks_rejected, 1);
        assert_eq!(l.shares_total, 2);
        // The PPLNS window survives too.
        let contribs = l.window_contributions();
        assert_eq!(contribs.len(), 2);
        assert_eq!(contribs[0], ("alice".to_string(), 30));

        let _ = std::fs::remove_file(&path);
    }
}
