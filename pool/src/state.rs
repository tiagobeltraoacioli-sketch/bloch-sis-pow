//! Shared pool state: config, current jobs, sessions, ledger, upstream.

use std::collections::{HashMap, HashSet};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::mpsc;

use bloch_sis_pow::{bits_to_target, Target};

use crate::job::Job;
use crate::shares::ShareLedger;
use crate::upstream::Upstream;

/// How many recent jobs a submission may still reference (mirrors the
/// node's per-session template retention idea, but pool-global since
/// all sessions share each job).
pub const JOB_RETENTION: usize = 8;

/// Submissions allowed per session per minute. More generous than the
/// node's solo cap (30/min) because pool shares are deliberately easy.
pub const SUBMIT_RATE_PER_MIN: u32 = 240;

#[derive(Clone, Debug)]
pub struct Config {
    pub node_rpc:      String,
    pub pool_address:  String,
    pub pool_spk:      Vec<u8>,
    pub fee_bps:       u16,
    pub share_bits:    u32,
    pub pplns_window:  usize,
    pub listen:        String,
    pub dashboard:     String,
    pub refresh_secs:  u64,
    pub coinbase_tag:  String,
    /// Blocks are credited only once canonical at this depth (PPLNS
    /// credits from an orphaned/red block are dropped, never booked).
    pub confirm_depth: u64,
    /// JSONL share/credit journal path (None = memory-only).
    pub journal:       Option<String>,
    /// Require miners to prove control of their payout address at
    /// authorize time (hybrid ML-DSA-65 ‖ Falcon-1024 signature over a
    /// per-session challenge). Default on; `--no-auth-proof` disables.
    pub require_auth_proof: bool,
}

/// Session state machine — mirrors the node's stratum session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionState {
    Fresh,
    Subscribed,
    Authorized,
}

pub struct Session {
    pub id:         u64,
    pub peer:       String,
    /// Start of this session's disjoint u64 nonce range: a 24-bit
    /// prefix over 2^40-wide ranges (a CPU miner needs weeks to
    /// exhaust 2^40). A plain `id << 48` would silently shift the
    /// prefix out past 2^16 sessions, colliding honest miners' ranges
    /// (advisor finding); cycling `(id - 1) % 0xff_ffff + 1` gives
    /// ~16.7 M sessions of headroom, and prefix reuse can only collide
    /// with long-closed sessions. Submits are range-checked in
    /// stratum.rs, so live ranges stay genuinely disjoint.
    pub nonce_base: u64,
    /// Fresh random challenge for the address-ownership proof
    /// (`mining.authorize` must sign it when `require_auth_proof`).
    pub challenge:  [u8; 32],
    pub state:      Mutex<SessionState>,
    pub address:    Mutex<Option<String>>,
    pub out:        Mutex<Option<mpsc::Sender<String>>>,
    // Sliding one-minute submit-rate window.
    submit_count:   AtomicU64,
    submit_window:  AtomicU64,
}

impl Session {
    pub fn new(id: u64, peer: String) -> Self {
        let mut challenge = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut challenge);
        Self {
            id,
            peer,
            nonce_base: ((id - 1) % 0xff_ffff + 1) << 40,
            challenge,
            state: Mutex::new(SessionState::Fresh),
            address: Mutex::new(None),
            out: Mutex::new(None),
            submit_count: AtomicU64::new(0),
            submit_window: AtomicU64::new(0),
        }
    }

    /// Queue a line for the writer task. Returns false if the session
    /// is gone OR its bounded queue is full — a client that cannot keep
    /// up with notify traffic is treated as dead (backpressure instead
    /// of unbounded buffering; see stratum.rs).
    pub fn send_line(&self, line: String) -> bool {
        match self.out.lock().as_ref() {
            Some(tx) => tx.try_send(line).is_ok(),
            None => false,
        }
    }

    pub fn is_authorized(&self) -> bool {
        *self.state.lock() == SessionState::Authorized
    }

    /// Simple per-minute rate limiter (mirrors the node's).
    pub fn check_submit_rate(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default().as_secs();
        let window = self.submit_window.load(Ordering::Relaxed);
        if now.saturating_sub(window) >= 60 {
            self.submit_window.store(now, Ordering::Relaxed);
            self.submit_count.store(1, Ordering::Relaxed);
            true
        } else {
            self.submit_count.fetch_add(1, Ordering::Relaxed) + 1 <= SUBMIT_RATE_PER_MIN as u64
        }
    }
}

/// A job older than this many refresh intervals means the node has
/// been unreachable long enough that handing the job to NEW miners
/// would burn their work on a likely-dead tip.
pub const STALE_TEMPLATE_FACTOR: u64 = 12;

/// Canonical lock-acquisition order when holding more than one of the
/// PoolState mutexes: `ledger` → `sessions` → `jobs` (the dashboard
/// snapshot takes all three in that order). Any path needing a
/// different order must DROP earlier guards first (see `push_job`).
pub struct PoolState {
    pub cfg:          Config,
    pub upstream:     Upstream,
    pub share_target: Target,
    /// Most-recent job last (VecDeque back). Bounded by JOB_RETENTION.
    pub jobs:         Mutex<VecDeque<Arc<Job>>>,
    pub ledger:       Mutex<ShareLedger>,
    pub sessions:     Mutex<HashMap<u64, Arc<Session>>>,
    /// Unix time of the last successful getblocktemplate (0 = never).
    last_template_unix: AtomicU64,
    next_session_id:  AtomicU64,
    next_job_id:      AtomicU64,
}

impl PoolState {
    /// Errs only if the share journal cannot be opened/replayed —
    /// running without the persistence the config asked for would be
    /// exactly the silent-ledger-loss hole the journal closes.
    pub fn new(cfg: Config) -> Result<Self, String> {
        let upstream = Upstream::new(cfg.node_rpc.clone());
        let ledger = match cfg.journal.as_deref() {
            Some(path) => ShareLedger::with_journal(
                cfg.share_bits, cfg.fee_bps, cfg.pplns_window, path)?,
            None => ShareLedger::new(cfg.share_bits, cfg.fee_bps, cfg.pplns_window),
        };
        Ok(Self {
            share_target: bits_to_target(cfg.share_bits),
            upstream,
            ledger: Mutex::new(ledger),
            jobs: Mutex::new(VecDeque::with_capacity(JOB_RETENTION)),
            sessions: Mutex::new(HashMap::new()),
            last_template_unix: AtomicU64::new(0),
            next_session_id: AtomicU64::new(1),
            next_job_id: AtomicU64::new(1),
            cfg,
        })
    }

    /// Record a successful template fetch (template_loop).
    pub fn note_template_ok(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default().as_secs();
        self.last_template_unix.store(now, Ordering::Relaxed);
    }

    /// Seconds since the last successful template (u64::MAX = never).
    pub fn template_age_secs(&self) -> u64 {
        let last = self.last_template_unix.load(Ordering::Relaxed);
        if last == 0 {
            return u64::MAX;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default().as_secs();
        now.saturating_sub(last)
    }

    /// Is the current job safe to hand to a NEW miner? False once the
    /// node has been unreachable for `refresh_secs * STALE_TEMPLATE_FACTOR`
    /// — a stale tip wastes their work with no path to a block.
    pub fn template_fresh(&self) -> bool {
        self.template_age_secs() <= self.cfg.refresh_secs.saturating_mul(STALE_TEMPLATE_FACTOR)
    }

    pub fn next_session_id(&self) -> u64 {
        self.next_session_id.fetch_add(1, Ordering::Relaxed)
    }

    pub fn next_job_id(&self) -> String {
        format!("{:x}", self.next_job_id.fetch_add(1, Ordering::Relaxed))
    }

    pub fn current_job(&self) -> Option<Arc<Job>> {
        self.jobs.lock().back().cloned()
    }

    pub fn find_job(&self, id: &str) -> Option<Arc<Job>> {
        self.jobs.lock().iter().rev().find(|j| j.id == id).cloned()
    }

    /// Install a new job and return it. Also prunes duplicate-share
    /// guard entries whose preimage matches no retained job.
    pub fn push_job(&self, job: Job) -> Arc<Job> {
        let job = Arc::new(job);
        let mut jobs = self.jobs.lock();
        if jobs.len() >= JOB_RETENTION {
            jobs.pop_front();
        }
        jobs.push_back(job.clone());
        let retained: HashSet<Vec<u8>> = jobs.iter().map(|j| j.preimage.clone()).collect();
        // Lock order: never hold jobs → ledger (the dashboard snapshot
        // holds ledger while reading jobs), so drop first.
        drop(jobs);
        self.ledger.lock().prune_dups(&retained);
        job
    }

    /// Snapshot of authorized sessions (notification targets).
    pub fn authorized_sessions(&self) -> Vec<Arc<Session>> {
        self.sessions.lock().values()
            .filter(|s| s.is_authorized())
            .cloned()
            .collect()
    }
}
