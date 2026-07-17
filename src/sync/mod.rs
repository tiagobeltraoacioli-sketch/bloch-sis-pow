//! Bloch drop-in Kaspa sync-negotiation layer (Phase 2). Additive over gossip.
pub mod frontier;
pub mod locator;
pub mod peer_state;

/// Max tip hashes we advertise / accept in one Tips frame. GHOSTDAG_K=10 caps
/// healthy anticone width; 256 is generous headroom. MUST equal
/// network::MAX_WIRE_TIPS (P4).
pub const MAX_ADVERTISED_TIPS: usize = 256;

/// Timeout after which an in-flight tip GetBlock is eligible for re-request.
pub const TIP_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
