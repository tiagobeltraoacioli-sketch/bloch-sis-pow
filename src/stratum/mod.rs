//! Stratum V1 server — Sprint AA.1
//!
//! Solo mining server that speaks the Bitcoin-protocol stratum V1
//! JSON-RPC dialect. Enabled by `--stratum --stratum-mode solo` on
//! the node CLI.
//!
//! Architecture
//! ============
//!
//! ```text
//!   TCP listener (default 0.0.0.0:3333)
//!     │
//!     ▼
//!   accept loop spawns one tokio task per connection
//!     │
//!     ▼
//!   session::run(socket, ...)
//!     ├── reads line-delimited JSON requests
//!     ├── dispatches to protocol::handle_*
//!     └── writes responses + pushes mining.notify on tip changes
//!
//!   Template refresh (global):
//!     ├── tokio::select! on (tip_changed_rx | 60s timer)
//!     └── rebuilds Template, broadcasts to every session
//! ```
//!
//! Solo mode semantics
//! ===================
//! Every share a miner submits must meet the block target (not a
//! weaker pool-share target). This keeps the implementation tight:
//! no share accounting, no PPLNS, no payout logic. When a miner
//! finds a valid solution, the block pays 100% of the reward to the
//! address they authorized with.
//!
//! Pool mode (Sprint AA.2) will extend this by loosening the target
//! and adding share accounting. The module structure is designed to
//! share 90% of the code between solo and pool — only `submit.rs`
//! diverges.
//!
//! See docs/architecture/mining-header.md for the 80-byte header
//! projection that makes Bitcoin-protocol stratum viable here.

pub mod protocol;
pub mod session;
pub mod jobs;
pub mod submit;

// Re-exports
pub use protocol::{ErrorCode, StratumError, StratumRequest, StratumResponse};
pub use session::{Session, SessionState};
pub use jobs::{Template, compute_merkle_branch, walk_merkle_branch, stratum_txid_of_bytes};
pub use submit::{handle_submit, AcceptBlockFn};

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use parking_lot::{Mutex, RwLock};
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use log::{info, warn, error, debug};

/// Maximum concurrent sessions (CLI-overridable).
pub const DEFAULT_MAX_SESSIONS: usize = 256;

/// Template refresh interval when no tip change fires. Ensures
/// long idle periods still yield fresh mempool-aware jobs.
pub const TEMPLATE_REFRESH_MS: u64 = 60_000;

/// Default stratum port — matches every ASIC firmware's default.
pub const DEFAULT_STRATUM_PORT: u16 = 3333;

/// Handles that template builders need from the node: DAG state
/// (parents/tip/height), storage (current_bits, maturity), mempool
/// (fees + tx list), and the fixed coinbase attribution tag.
///
/// Wrapped in `Arc` in `StratumConfig` so cloning the config is
/// cheap for each session task.
pub struct TemplateContext {
    pub dag:          Arc<RwLock<crate::consensus::GhostDAG>>,
    pub store:        Arc<crate::storage::Storage>,
    pub mempool:      Arc<crate::mempool::Mempool>,
    pub coinbase_tag: String,
}

/// Stratum operating mode. Solo pays 100% of found blocks to the
/// miner who found them. Pool (AA.2, not yet implemented) divides
/// by shares.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StratumMode {
    /// Self-mining only — coinbase 100% to --miner-address.
    /// (V1 default; V2 sessions also fall back here when no fee_split set.)
    Solo,
    /// Pool mining — connected miners send `user_identity` (bloch1q...);
    /// coinbase pays (10000-fee_bps)/10000 to that miner, fee_bps/10000
    /// to --stratum-pool-fee-address. Use when offering pool service to
    /// 3rd-party miners with infrastructure fee.
    Pool,
    /// Solo-connect — like Pool but typically with a smaller fee_bps
    /// (e.g. 100 = 1%). Semantic tag for "solo miners using your stratum
    /// endpoint", distinct from Pool which implies share accounting.
    /// In Sprint 10-zeta the on-chain mechanics are identical to Pool;
    /// the distinction is only in coinbase tagging and fee_bps default.
    SoloConnect,
}

impl std::fmt::Display for StratumMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Solo        => write!(f, "solo"),
            Self::Pool        => write!(f, "pool"),
            Self::SoloConnect => write!(f, "solo-connect"),
        }
    }
}

impl std::str::FromStr for StratumMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "solo"         => Ok(Self::Solo),
            "pool"         => Ok(Self::Pool),
            "solo-connect" => Ok(Self::SoloConnect),
            "soloconnect"  => Ok(Self::SoloConnect),  // accept both spellings
            other          => Err(format!(
                "unknown stratum mode: {}. Use 'solo', 'pool', or 'solo-connect'.",
                other
            )),
        }
    }
}

/// Configuration for the stratum server, assembled from CLI flags.
#[derive(Clone)]
pub struct StratumConfig {
    pub bind_addr:     SocketAddr,
    pub mode:          StratumMode,
    pub max_sessions:  usize,
    /// Hardcoded tag written into coinbase script_sig. Useful for
    /// blockchain-explorer attribution and operator debugging.
    pub coinbase_tag:  String,
    /// Callback into the node's accept_block path. Invoked when a
    /// miner submits a share that meets the block target. When None,
    /// submit returns the AA.1-pt-1 placeholder error — only makes
    /// sense for protocol-level smoke testing without a live DAG.
    pub accept_block:  Option<Arc<submit::AcceptBlockFn>>,
    /// DAG / Storage / Mempool handles required to build templates.
    /// None for unit tests that don't exercise template generation.
    pub node_ctx:      Option<Arc<TemplateContext>>,
}

impl std::fmt::Debug for StratumConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StratumConfig")
            .field("bind_addr", &self.bind_addr)
            .field("mode", &self.mode)
            .field("max_sessions", &self.max_sessions)
            .field("coinbase_tag", &self.coinbase_tag)
            .field("accept_block", &self.accept_block.is_some())
            .field("node_ctx", &self.node_ctx.is_some())
            .finish()
    }
}

impl StratumConfig {
    pub fn solo_defaults() -> Self {
        Self {
            bind_addr:    format!("0.0.0.0:{}", DEFAULT_STRATUM_PORT).parse().unwrap(),
            mode:         StratumMode::Solo,
            max_sessions: DEFAULT_MAX_SESSIONS,
            coinbase_tag: "bloch-layer/v0.1".to_string(),
            accept_block: None,
            node_ctx:     None,
        }
    }
}

/// Event pushed on the broadcast channel when the DAG accepts a new
/// selected tip, so the stratum server can re-issue jobs.
#[derive(Clone, Debug)]
pub struct TipChanged {
    pub hash:       [u8; 32],
    pub height:     u64,
    pub blue_score: u64,
    pub parents:    Vec<[u8; 32]>,
    pub bits:       u32,
}

/// Registry of live sessions. Owned by the server; each session
/// task holds an Arc and unregisters itself on drop.
pub struct SessionRegistry {
    sessions: Mutex<Vec<Arc<Session>>>,
    max:      usize,
}

impl SessionRegistry {
    pub fn new(max: usize) -> Self {
        Self { sessions: Mutex::new(Vec::new()), max }
    }

    /// Attempt to register. Returns true if under the cap. The cap counts only
    /// LIVE (non-Dead) sessions: under ttl:2 churn a burst of sessions can be
    /// mid-teardown (Dead, but still registered during their up-to-2s writer
    /// join) — counting those would spuriously reject fresh MRR connections.
    pub fn register(&self, s: Arc<Session>) -> bool {
        let mut g = self.sessions.lock();
        let live = g.iter().filter(|x| !x.is_dead()).count();
        if live >= self.max { return false; }
        g.push(s);
        true
    }

    /// Remove a session by id. Called from session task cleanup.
    pub fn deregister(&self, id: u64) {
        let mut g = self.sessions.lock();
        g.retain(|s| s.id != id);
    }

    pub fn len(&self) -> usize {
        self.sessions.lock().len()
    }

    /// Count of LIVE (non-Dead) sessions — the number that counts against the
    /// connection cap. Excludes sessions in teardown so they don't starve
    /// fresh connections under ttl:2 churn.
    pub fn live_len(&self) -> usize {
        self.sessions.lock().iter().filter(|s| !s.is_dead()).count()
    }

    pub fn is_empty(&self) -> bool { self.len() == 0 }

    /// Snapshot of currently registered sessions.
    pub fn snapshot(&self) -> Vec<Arc<Session>> {
        self.sessions.lock().clone()
    }

    /// Snapshot of sessions that have completed subscribe + authorize
    /// and thus have a miner address stored. The tip-change and
    /// periodic-refresh hooks iterate over this subset — it makes no
    /// sense to push a template to a session that hasn't told us where
    /// the reward should go.
    pub fn authorized_sessions(&self) -> Vec<Arc<Session>> {
        self.sessions.lock().iter()
            .filter(|s| s.state() == SessionState::Authorized)
            .cloned()
            .collect()
    }
}

/// Top-level entry point. Spawn with `tokio::spawn(run(...))`.
///
/// Holds a TCP listener, accepts connections under the session cap,
/// spawns per-connection session tasks, and broadcasts tip-change
/// events to all active sessions.
pub async fn run(
    config:         StratumConfig,
    mut tip_rx:     broadcast::Receiver<TipChanged>,
) -> std::io::Result<()> {
    // ── Consensus safety guard (fail-closed) ──────────────────────────
    // The stratum server produces SHA-256d work: an 80-byte MiningHeader
    // and an EMPTY `pow_solution`. A node validates a block with the PoW
    // algorithm `pow_algorithm(node_chain_id())` selects — and ONLY
    // Genesis2Devnet maps to Sha256d. On any other chain-id (the default
    // when the node is launched without `--genesis2` is Mainnet ⇒
    // ModuleSis) the validator takes the Module-SIS arm, which requires a
    // 256-element `pow_solution`, and rejects EVERY block this server
    // mines as "invalid PoW" — silently burning all connected hashrate
    // (the ASIC symptom). The stratum's own share check is hard-coded
    // SHA-256d, so it accepts the share and only accept_block rejects it:
    // a self-inconsistent node. This is a startup misconfiguration, not a
    // runtime condition, so fail loud instead of mining un-acceptable work.
    let cid = crate::core::node_chain_id();
    if cid != crate::core::ChainId::Genesis2Devnet {
        error!(
            "stratum: refusing to start — node chain-id is {:?}, but the SHA-256d \
             stratum requires Genesis2Devnet. Blocks would be mined as SHA-256d yet \
             validated as Module-SIS and rejected ('invalid PoW'), wasting all \
             hashrate. Restart the node with --genesis2.",
            cid
        );
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "stratum requires --genesis2 (Sha256d PoW); refusing to mine un-acceptable blocks",
        ));
    }

    info!("stratum: binding {} mode={}", config.bind_addr, config.mode);
    let listener = TcpListener::bind(config.bind_addr).await?;
    info!("stratum: listening on {}", config.bind_addr);

    let registry = Arc::new(SessionRegistry::new(config.max_sessions));

    // Periodic template-refresh ticker. Fires every TEMPLATE_REFRESH_MS
    // even if no tip change — lets long-idle sessions absorb mempool
    // churn.
    let mut refresh_timer = tokio::time::interval(Duration::from_millis(TEMPLATE_REFRESH_MS));
    refresh_timer.tick().await; // consume the immediate tick

    let mut next_session_id: u64 = 1;

    loop {
        tokio::select! {
            // ── New connection ───────────────────────────────
            result = listener.accept() => {
                match result {
                    Ok((socket, peer_addr)) => {
                        let id = next_session_id;
                        next_session_id += 1;

                        if registry.live_len() >= config.max_sessions {
                            warn!("stratum: rejecting {} — session cap {} reached",
                                peer_addr, config.max_sessions);
                            drop(socket);
                            continue;
                        }

                        let session = Arc::new(Session::new(id, peer_addr));
                        if !registry.register(session.clone()) {
                            warn!("stratum: could not register session {} from {}", id, peer_addr);
                            drop(socket);
                            continue;
                        }

                        info!("stratum: session {} accepted from {} (total: {})",
                            id, peer_addr, registry.len());

                        let registry_clone = registry.clone();
                        let session_clone = session.clone();
                        let cb_clone = config.accept_block.clone();
                        let ctx_clone = config.node_ctx.clone();
                        tokio::spawn(async move {
                            if let Err(e) = session::run(session_clone, socket, cb_clone, ctx_clone).await {
                                warn!("stratum: session {} ended with error: {}", id, e);
                            } else {
                                info!("stratum: session {} closed cleanly", id);
                            }
                            registry_clone.deregister(id);
                        });
                    }
                    Err(e) => {
                        error!("stratum: accept error: {}", e);
                        // Brief backoff so we don't spin if the socket is borked.
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }

            // ── Tip changed ──────────────────────────────────
            evt = tip_rx.recv() => {
                match evt {
                    Ok(tip) => {
                        // Count what we will actually notify: the authorized
                        // subset (a session with no miner address gets no
                        // template). Logging registry.len() here used to
                        // mislabel the notify fan-out.
                        let authorized = registry.authorized_sessions();
                        info!("stratum: tip changed to h={} (notifying {} authorized of {} sessions)",
                            tip.height, authorized.len(), registry.len());
                        // Sprint 2.d: rebuild template per authorized session
                        // (each session has its own miner_spk in the coinbase
                        // output). clean_jobs=true so miners abandon the old
                        // work — it can no longer win at the new height.
                        if let Some(ref ctx) = config.node_ctx {
                            for s in authorized {
                                if let Err(reason) = session::install_fresh_template(&s, ctx, true) {
                                    warn!("stratum: session {} tip-change reinstall failed: {}",
                                          s.id, reason);
                                }
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!("stratum: tip broadcast lagged, dropped {} events", n);
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        warn!("stratum: tip broadcast closed; shutting down");
                        break;
                    }
                }
            }

            // ── Periodic refresh ─────────────────────────────
            _ = refresh_timer.tick() => {
                // Sprint 2.d: mempool-driven refresh. clean_jobs=false so
                // miners can keep working the current job alongside the
                // new one (submissions on the old job still count).
                if let Some(ref ctx) = config.node_ctx {
                    let n = registry.len();
                    if n > 0 {
                        debug!("stratum: periodic refresh for {} sessions", n);
                        for s in registry.authorized_sessions() {
                            if let Err(reason) = session::install_fresh_template(&s, ctx, false) {
                                warn!("stratum: session {} periodic refresh failed: {}",
                                      s.id, reason);
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────
// Sprint 10-zeta (Sprint AA.2) Phase 1 — Coinbase fee-split
// ─────────────────────────────────────────────────────────────────────

/// Coinbase fee-split configuration. When attached to a `Sv2Config` (or
/// future V1 config), the mined block's coinbase is emitted with TWO
/// outputs: `(reward * (10000 - fee_bps) / 10000)` to the miner_spk
/// derived from `user_identity`, and `(reward * fee_bps / 10000)` to
/// `fee_address`.
///
/// `fee_bps == 0` is rejected by `validate()` — use `StratumMode::Solo`
/// for the no-split path (single coinbase output, zero overhead).
///
/// `fee_bps > 1000` (10%) is rejected as a guardrail against typos that
/// would silently steal a large fraction of every block reward. The cap
/// can be revisited in a future sprint after operator feedback.
#[derive(Clone, Debug)]
pub struct FeeSplit {
    /// 20-byte pubkey hash of the fee recipient (from `Address::hash()`).
    pub fee_address: [u8; 20],
    /// Fee in basis points: 100 = 1%, 200 = 2%, 1000 = 10% (cap).
    pub fee_bps: u16,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FeeSplitError {
    #[error("fee_bps must be > 0; use StratumMode::Solo for no-split path")]
    FeeBpsZero,
    #[error("fee_bps {got} exceeds cap of 1000 (10%)")]
    FeeBpsTooHigh { got: u16 },
}

impl FeeSplit {
    /// Validate fee_bps is within (0, 1000].
    pub fn validate(&self) -> Result<(), FeeSplitError> {
        if self.fee_bps == 0 {
            return Err(FeeSplitError::FeeBpsZero);
        }
        if self.fee_bps > 1000 {
            return Err(FeeSplitError::FeeBpsTooHigh { got: self.fee_bps });
        }
        Ok(())
    }

    /// Compute (miner_amount, fee_amount) for a given total block reward.
    /// Uses u128 intermediate to prevent overflow on `reward * 10000` for
    /// any plausible reward value (current cap: ~1e10 satoshis × 10000
    /// = ~1e14, well within u128 range).
    pub fn split(&self, total_reward: u64) -> (u64, u64) {
        let fee = (total_reward as u128 * self.fee_bps as u128 / 10000) as u64;
        let miner = total_reward.saturating_sub(fee);
        (miner, fee)
    }
}

/// Generate the coinbase tag suffix for a given mode.
/// Examples:
///   ("bloch-worker/v0.1", Solo,         _  ) -> "bloch-worker/v0.1/solo"
///   ("bloch-worker/v0.1", Pool,         200) -> "bloch-worker/v0.1/pool-200bps"
///   ("bloch-worker/v0.1", SoloConnect,  100) -> "bloch-worker/v0.1/sc-100bps"
///
/// Bytes added: solo=5, pool=11-13, sc=9-11. Bitcoin coinbase script
/// has ~80-100 bytes free after height/extranonce/tag, so this fits.
pub fn coinbase_tag_for_mode(base_tag: &str, mode: StratumMode, fee_bps: u16) -> String {
    match mode {
        StratumMode::Solo        => format!("{}/solo",         base_tag),
        StratumMode::Pool        => format!("{}/pool-{}bps",   base_tag, fee_bps),
        StratumMode::SoloConnect => format!("{}/sc-{}bps",     base_tag, fee_bps),
    }
}

#[cfg(test)]
mod fee_split_tests {
    use super::*;

    fn dummy_addr() -> [u8; 20] { [0x42; 20] }

    #[test]
    fn validate_ok_at_minimum_fee() {
        let fs = FeeSplit { fee_address: dummy_addr(), fee_bps: 1 };
        assert!(fs.validate().is_ok());
    }

    #[test]
    fn validate_ok_at_cap() {
        let fs = FeeSplit { fee_address: dummy_addr(), fee_bps: 1000 };
        assert!(fs.validate().is_ok());
    }

    #[test]
    fn validate_rejects_zero() {
        let fs = FeeSplit { fee_address: dummy_addr(), fee_bps: 0 };
        assert_eq!(fs.validate(), Err(FeeSplitError::FeeBpsZero));
    }

    #[test]
    fn validate_rejects_over_cap() {
        let fs = FeeSplit { fee_address: dummy_addr(), fee_bps: 1001 };
        assert_eq!(fs.validate(), Err(FeeSplitError::FeeBpsTooHigh { got: 1001 }));
    }

    #[test]
    fn split_pool_fee_2pct() {
        // Pool fee at 2% (200 bps) of an arbitrary 5e8 satoshi reward.
        // NOTE: 5e8 sat = 5 BLOCH is a test value, NOT the real consensus block reward
        // (which is BLOCK_REWARD = 2381 BLOCH = 238_100_000_000 sat at height 0).
        // This tests the FeeSplit POOL FEE helper, not the consensus 93/5/2 split
        // (see src/core/mod.rs::tests::consensus_block_reward_split_93_5_2).
        let fs = FeeSplit { fee_address: dummy_addr(), fee_bps: 200 };
        let (miner, fee) = fs.split(500_000_000);
        assert_eq!(fee,   10_000_000);   // 2% pool fee = 0.1 BLOCH of a 5 BLOCH test reward
        assert_eq!(miner, 490_000_000);  // 98% to miner (this is pool fee math, not consensus reward split)
        assert_eq!(miner + fee, 500_000_000);
    }

    #[test]
    fn split_pool_fee_1pct_solo_connect() {
        let fs = FeeSplit { fee_address: dummy_addr(), fee_bps: 100 };
        let (miner, fee) = fs.split(500_000_000);
        assert_eq!(fee,   5_000_000);
        assert_eq!(miner, 495_000_000);
    }

    #[test]
    fn split_rounds_down_fee_favors_miner() {
        // 333 satoshis at 1% = 3.33 → integer division yields 3, miner gets 330
        let fs = FeeSplit { fee_address: dummy_addr(), fee_bps: 100 };
        let (miner, fee) = fs.split(333);
        assert_eq!(fee,   3);
        assert_eq!(miner, 330);
        assert_eq!(miner + fee, 333);
    }

    #[test]
    fn split_huge_reward_no_overflow() {
        // u64::MAX / 10000 ~= 1.8e15. Test at 1e15 satoshis = 10M BLOCH
        // (above the real BLOCK_REWARD of 2381 BLOCH) just to exercise
        // the u128 intermediate path.
        let fs = FeeSplit { fee_address: dummy_addr(), fee_bps: 1000 };
        let (miner, fee) = fs.split(1_000_000_000_000_000);
        assert_eq!(fee,   100_000_000_000_000);
        assert_eq!(miner, 900_000_000_000_000);
    }

    #[test]
    fn fromstr_accepts_all_three_modes() {
        use std::str::FromStr;
        assert_eq!(StratumMode::from_str("solo").unwrap(),         StratumMode::Solo);
        assert_eq!(StratumMode::from_str("pool").unwrap(),         StratumMode::Pool);
        assert_eq!(StratumMode::from_str("solo-connect").unwrap(), StratumMode::SoloConnect);
        assert_eq!(StratumMode::from_str("soloconnect").unwrap(),  StratumMode::SoloConnect);
        assert_eq!(StratumMode::from_str("POOL").unwrap(),         StratumMode::Pool);  // case-insensitive
    }

    #[test]
    fn fromstr_rejects_unknown() {
        use std::str::FromStr;
        let err = StratumMode::from_str("p2pool").unwrap_err();
        assert!(err.contains("p2pool"));
        assert!(err.contains("solo-connect"));
    }

    #[test]
    fn coinbase_tag_for_mode_format() {
        let base = "bloch-worker/v0.1";
        assert_eq!(coinbase_tag_for_mode(base, StratumMode::Solo,        0  ),
                   "bloch-worker/v0.1/solo");
        assert_eq!(coinbase_tag_for_mode(base, StratumMode::Pool,        200),
                   "bloch-worker/v0.1/pool-200bps");
        assert_eq!(coinbase_tag_for_mode(base, StratumMode::SoloConnect, 100),
                   "bloch-worker/v0.1/sc-100bps");
    }
}

