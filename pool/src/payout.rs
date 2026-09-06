//! Payout math — PPLNS (Pay Per Last N Shares), pure functions.
//!
//! Scheme (documented contract, keep in sync with the README):
//!
//! 1. When the pool finds a block paying `reward_sat` (subsidy + fees,
//!    the coinbase output to the pool address), the pool fee is taken
//!    first: `fee = reward * fee_bps / 10000` (integer division,
//!    rounds DOWN — the fee never rounds against miners). Default
//!    `fee_bps = 0`; capped at 1000 (10%), mirroring the node's
//!    `FeeSplit` guardrail against typo'd fees.
//! 2. The remainder is split pro-rata over the aggregated weights of
//!    the last-N-shares window: `amount_i = net * w_i / W` (integer
//!    division, floors).
//! 3. Rounding dust (at most `contributors - 1` sats) plus the fee is
//!    the pool take. This is explicit, not hidden.
//!
//! Weights are hashcash expected-work units (`shares::work_from_bits`),
//! so a future vardiff pool credits proportionally out of the box.
//!
//! Honesty note: credits are LEDGER entries. The block reward lands in
//! the pool's on-chain address (and is subject to coinbase maturity);
//! disbursing credits is a wallet transaction the pool operator makes.
//! This reference implements the accounting, not custody automation.

/// Result of splitting one block reward.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payout {
    /// (address, sats) per contributor, in the input order.
    pub miners:    Vec<(String, u64)>,
    /// Fee + rounding dust. `miners.sum() + pool_take == reward_sat`.
    pub pool_take: u64,
}

/// Hard cap on the pool fee — same 10% guardrail as the node's FeeSplit.
pub const MAX_FEE_BPS: u16 = 1000;

/// `split_reward` was asked to split with a `fee_bps` above [`MAX_FEE_BPS`].
/// L-14 fix (audit finding): this used to be an `assert!` — sound reasoning
/// at config-load time (`main.rs` validates `fee_bps` at startup, so the
/// panic is unreachable from THAT call site), but `dashboard.rs` calls
/// `split_reward` on every `/api/stats` request with the live
/// `ledger.fee_bps`, an HTTP-request-triggered path with no local
/// revalidation of its own. A future code path that ever sets an
/// out-of-range `fee_bps` (a bug, a config-reload gap, a test double) turns
/// an accounting-estimate endpoint into a process-killing panic for every
/// caller. Returning `Result` lets every call site decide how to degrade —
/// none of them need to crash the process over a fee-bps question.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeeBpsExceedsCap {
    pub fee_bps: u16,
    pub cap: u16,
}

impl std::fmt::Display for FeeBpsExceedsCap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "fee_bps {} exceeds cap {}", self.fee_bps, self.cap)
    }
}

impl std::error::Error for FeeBpsExceedsCap {}

/// Split `reward_sat` across `contribs` (address, weight) minus the fee.
///
/// L-14 fix: returns `Err(FeeBpsExceedsCap)` instead of panicking when
/// `fee_bps > MAX_FEE_BPS` — validate at config time (`main.rs` already
/// does, at startup) AND handle the `Err` at every call site, since this is
/// also reachable from live request handling (`dashboard.rs`).
pub fn split_reward(
    contribs: &[(String, u128)],
    reward_sat: u64,
    fee_bps: u16,
) -> Result<Payout, FeeBpsExceedsCap> {
    if fee_bps > MAX_FEE_BPS {
        return Err(FeeBpsExceedsCap { fee_bps, cap: MAX_FEE_BPS });
    }

    let fee = (reward_sat as u128 * fee_bps as u128 / 10_000) as u64;
    let net = reward_sat - fee;

    let total_weight: u128 = contribs.iter().map(|(_, w)| *w).sum();
    if total_weight == 0 || net == 0 {
        // No contributors (or nothing to split): everything is pool take.
        return Ok(Payout { miners: Vec::new(), pool_take: reward_sat });
    }

    let mut miners = Vec::with_capacity(contribs.len());
    let mut distributed: u64 = 0;
    for (addr, w) in contribs {
        let amount = mul_div_floor(net, *w, total_weight);
        distributed += amount;
        miners.push((addr.clone(), amount));
    }

    Ok(Payout { miners, pool_take: reward_sat - distributed })
}

/// `net * w / total` with u128 weights, overflow-safe.
///
/// Fast path is exact. If `net * w` would overflow u128 (only possible
/// for astronomically large weights), both `w` and `total` are shifted
/// down equally — the ratio is preserved to within rounding, individual
/// amounts stay `<= net`, and `sum(floor(w_i >> s)) <= total >> s`
/// guarantees the distributed total never exceeds `net` (conservation).
fn mul_div_floor(net: u64, w: u128, total: u128) -> u64 {
    debug_assert!(w <= total);
    let n = net as u128;
    if let Some(prod) = n.checked_mul(w) {
        return (prod / total) as u64;
    }
    let mut w2 = w;
    let mut t2 = total;
    loop {
        w2 >>= 8;
        t2 >>= 8;
        if t2 == 0 {
            return 0;
        }
        if let Some(prod) = n.checked_mul(w2) {
            return (prod / t2) as u64;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(pairs: &[(&str, u128)]) -> Vec<(String, u128)> {
        pairs.iter().map(|(a, w)| (a.to_string(), *w)).collect()
    }

    #[test]
    fn conservation_always_holds() {
        // sum(miners) + pool_take == reward, across fee levels + odd splits.
        for fee_bps in [0u16, 1, 100, 250, 1000] {
            for reward in [0u64, 1, 333, 500_000_000, 238_100_000_000] {
                let contribs = c(&[("a", 7), ("b", 13), ("c", 1), ("d", 979)]);
                let p = split_reward(&contribs, reward, fee_bps).unwrap();
                let paid: u64 = p.miners.iter().map(|(_, v)| v).sum();
                assert_eq!(paid + p.pool_take, reward,
                    "conservation broke at fee={} reward={}", fee_bps, reward);
            }
        }
    }

    #[test]
    fn zero_fee_proportional_split() {
        let p = split_reward(&c(&[("alice", 3), ("bob", 1)]), 1_000, 0).unwrap();
        assert_eq!(p.miners, vec![("alice".to_string(), 750), ("bob".to_string(), 250)]);
        assert_eq!(p.pool_take, 0);
    }

    #[test]
    fn two_percent_fee() {
        // 2% of 500_000_000 = 10_000_000; net 490_000_000 split 50/50.
        let p = split_reward(&c(&[("a", 1), ("b", 1)]), 500_000_000, 200).unwrap();
        assert_eq!(p.miners[0].1, 245_000_000);
        assert_eq!(p.miners[1].1, 245_000_000);
        assert_eq!(p.pool_take, 10_000_000);
    }

    #[test]
    fn rounding_dust_goes_to_pool_explicitly() {
        // 100 sats over 3 equal miners: 33 each, 1 sat dust to pool.
        let p = split_reward(&c(&[("a", 1), ("b", 1), ("c", 1)]), 100, 0).unwrap();
        assert!(p.miners.iter().all(|(_, v)| *v == 33));
        assert_eq!(p.pool_take, 1);
    }

    #[test]
    fn single_miner_gets_everything_at_zero_fee() {
        let p = split_reward(&c(&[("solo", 42)]), 238_100_000_000, 0).unwrap();
        assert_eq!(p.miners[0].1, 238_100_000_000);
        assert_eq!(p.pool_take, 0);
    }

    #[test]
    fn no_contributors_all_to_pool() {
        let p = split_reward(&[], 1_000, 0).unwrap();
        assert!(p.miners.is_empty());
        assert_eq!(p.pool_take, 1_000);
    }

    #[test]
    fn huge_weights_no_overflow() {
        // u128 weights near the top: the u128 * u128 product path must
        // not be used naively — amounts stay in u64 because net <= u64.
        let big = u128::MAX / 4;
        let p = split_reward(&c(&[("a", big), ("b", big)]), u64::MAX, 0).unwrap();
        let paid: u64 = p.miners.iter().map(|(_, v)| v).sum();
        assert_eq!(paid + p.pool_take, u64::MAX);
    }

    /// L-14 regression: red before the fix (this panicked), green after
    /// (a clear `Err`, no unwind).
    #[test]
    fn fee_above_cap_returns_err_not_panic() {
        let err = split_reward(&c(&[("a", 1)]), 100, 1001).unwrap_err();
        assert_eq!(err, FeeBpsExceedsCap { fee_bps: 1001, cap: MAX_FEE_BPS });
        assert!(err.to_string().contains("exceeds cap"));
    }
}
