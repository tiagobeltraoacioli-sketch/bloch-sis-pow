//! Bloch drop-in Kaspa sync-negotiation layer (Phase 2). Additive over gossip.
pub mod frontier;
pub mod locator;
pub mod parent_fetch;
pub mod peer_state;

/// Max tip hashes we advertise / accept in one Tips frame. GHOSTDAG_K=10 caps
/// healthy anticone width; 256 is generous headroom. MUST equal
/// network::MAX_WIRE_TIPS (P4).
pub const MAX_ADVERTISED_TIPS: usize = 256;

/// Timeout after which an in-flight tip GetBlock is eligible for re-request.
pub const TIP_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// IBD-exit lag tolerance (blue_score). A node whose selected tip is within this
/// many blue_score of the best ANNOUNCED tip is treated as caught-up (normal
/// mining-lag / DAG-width, not a bulk backlog) and releases the IBD latch so it
/// keeps MINING. Without this, a trailing miner never satisfies the strict
/// verified frontier-reconciled gate while a peer mines continuously (the tip it
/// chases keeps moving), so it froze as a pure follower — the canary finding this
/// fixes. Tiny vs a real backlog (hundreds–thousands of blocks); K=10 caps
/// healthy anticone width, so 16 comfortably covers propagation + DAG width.
pub const IBD_EXIT_LAG: u64 = 16;
