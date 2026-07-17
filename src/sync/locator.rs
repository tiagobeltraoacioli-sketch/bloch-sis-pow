//! Block-locator construction + common-ancestor resolution for the Kaspa
//! sync-negotiation layer (Phase 2). Additive over gossip; consensus-read-only.
//!
//! A locator is an exponential-backoff sample of the selected chain: dense near
//! the tip, sparse toward genesis. It lets a peer resolve the highest block we
//! share without walking the full chain.

/// Max locator entries. Exponential backoff over the selected chain needs only
/// ~log2(height) hashes; 64 covers 2^64 heights. MUST equal
/// `network::MAX_WIRE_LOCATOR` (P4).
pub const MAX_LOCATOR_LEN: usize = 64;

/// Build an exponential-backoff block locator from the selected chain.
///
/// `selected_chain` is tip-first → genesis-last, exactly as returned by
/// `consensus::GhostDAG::selected_chain()`. We sample index 0,1,2,3,5,9,17,...
/// (step doubles after the first few), ALWAYS including the tip (first) and the
/// genesis/oldest (last) element, capped at `MAX_LOCATOR_LEN`.
pub fn build_locator(selected_chain: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut out = Vec::new();
    if selected_chain.is_empty() {
        return out;
    }
    let n = selected_chain.len();
    let mut i = 0usize;
    let mut step = 1usize;
    let mut taken = 0usize;
    while i < n && taken + 1 < MAX_LOCATOR_LEN {
        out.push(selected_chain[i]);
        taken += 1;
        if taken >= 10 {
            step = step.saturating_mul(2); // start doubling after 10 dense samples
        }
        i += step;
    }
    // Always pin the oldest known block (genesis) as the backstop ancestor.
    let last = selected_chain[n - 1];
    if out.last() != Some(&last) {
        out.push(last);
    }
    out
}

/// Resolve the highest common ancestor from a received locator: the FIRST
/// (closest-to-tip) locator hash we already possess. `has_block` is the DAG
/// oracle. `None` => no shared history (peer on a foreign genesis).
pub fn find_common_ancestor<F: Fn(&[u8; 32]) -> bool>(
    locator: &[[u8; 32]],
    has_block: F,
) -> Option<[u8; 32]> {
    locator.iter().find(|h| has_block(h)).copied()
}
