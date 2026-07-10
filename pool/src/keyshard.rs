//! Procedural M-of-N key RECOVERY — Shamir 2-of-3 over the operator's
//! 32-byte wallet seed.
//!
//! HONEST LABEL (do not soften): this is **key recovery, not threshold
//! signing**. Splitting the seed lets 3 custodians hold shares such
//! that any 2 can reconstruct it after a disaster, and no single share
//! reveals anything — but at recovery (and at signing) the seed exists
//! **in one place**. Bloch's hybrid ML-DSA-65 ‖ Falcon-1024 signatures
//! have no practical MPC/threshold construction today (2027+ research),
//! and the chain is single-signature P2PKH with no script system, so
//! on-chain k-of-n multisig needs a consensus change (roadmapped as
//! GIP-008 — not this crate's job). Until then, "M-of-N" for a pool is
//! *procedural*: sharded recovery + the dual-control disbursement
//! procedure in the README.
//!
//! Field math is NOT hand-rolled: `sharks` implements Shamir over
//! GF(256).

use sharks::{Share, Sharks};

/// Shares needed to reconstruct the seed.
pub const THRESHOLD: u8 = 2;
/// Shares dealt.
pub const SHARE_COUNT: usize = 3;

/// Split a 32-byte wallet seed into `SHARE_COUNT` Shamir shares, any
/// `THRESHOLD` of which reconstruct it. Each share is opaque bytes
/// (index ‖ GF(256) points); hand one to each custodian, never store
/// two together.
pub fn split_seed(seed: &[u8; 32]) -> Vec<Vec<u8>> {
    let sharks = Sharks(THRESHOLD);
    sharks.dealer(seed).take(SHARE_COUNT).map(|s| Vec::from(&s)).collect()
}

/// Recombine `THRESHOLD`+ shares back into the seed. The seed is
/// reconstructed in THIS process's memory — do it on an isolated,
/// offline machine (see README "Custody").
pub fn recover_seed(shares: &[Vec<u8>]) -> Result<[u8; 32], String> {
    let parsed: Vec<Share> = shares.iter()
        .map(|b| Share::try_from(b.as_slice())
            .map_err(|e| format!("malformed share: {}", e)))
        .collect::<Result<_, _>>()?;
    let secret = Sharks(THRESHOLD)
        .recover(parsed.iter())
        .map_err(|e| format!("recovery failed: {}", e))?;
    secret.try_into()
        .map_err(|_| "recovered secret is not 32 bytes (wrong shares?)".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn any_two_of_three_recover() {
        let seed = [42u8; 32];
        let shares = split_seed(&seed);
        assert_eq!(shares.len(), SHARE_COUNT);
        for (i, j) in [(0, 1), (0, 2), (1, 2)] {
            let picked = vec![shares[i].clone(), shares[j].clone()];
            assert_eq!(recover_seed(&picked).unwrap(), seed, "pair ({},{})", i, j);
        }
        // All three also work.
        assert_eq!(recover_seed(&shares).unwrap(), seed);
    }

    #[test]
    fn one_share_is_not_enough() {
        let seed = [7u8; 32];
        let shares = split_seed(&seed);
        assert!(recover_seed(&shares[..1].to_vec()).is_err(),
            "a single share must never reconstruct the seed");
    }

    #[test]
    fn shares_are_randomized_per_split() {
        // Same seed, two splits → different share bytes (fresh
        // polynomial each time), both still recover.
        let seed = [9u8; 32];
        let a = split_seed(&seed);
        let b = split_seed(&seed);
        assert_ne!(a[0], b[0], "dealer must use a fresh random polynomial");
        assert_eq!(recover_seed(&a[..2].to_vec()).unwrap(), seed);
        assert_eq!(recover_seed(&b[..2].to_vec()).unwrap(), seed);
    }
}
