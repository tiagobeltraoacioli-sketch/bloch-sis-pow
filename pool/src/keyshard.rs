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
//! Field math is NOT hand-rolled: `blahaj` implements Shamir over
//! GF(256). It replaced `sharks` 0.5.0 (RUSTSEC-2024-0398), whose
//! dealer drew polynomial coefficients uniformly from [1, 255] — never
//! 0 — so every share leaked one impossible value per byte of the
//! seed. `blahaj` is the advisory-recommended fork with the same API
//! and the SAME share wire format (`x || y_0..y_31`, GF(256) points),
//! coefficients uniform over [0, 255]. MIGRATION: shares already dealt
//! by the sharks-era binary recover unchanged (Lagrange interpolation
//! does not care how the dealer sampled); re-splitting the seed on the
//! fixed binary is still recommended to shed the historical bias.

use blahaj::{Share, Sharks};

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

    /// Regression test for RUSTSEC-2024-0398 (the `sharks` 0.5.0 bias
    /// this module shipped with). With THRESHOLD = 2 the dealer's
    /// polynomial is p(x) = a1*x + s per seed byte, so the share at
    /// x = 1 satisfies y = s XOR a1 (GF(256) addition is XOR), i.e.
    /// a1 = y XOR s. A correct dealer draws a1 uniformly from [0, 255];
    /// sharks drew it from [1, 255], so y could NEVER equal the seed
    /// byte. Observing a1 = 0 at least once over 600 splits x 32 byte
    /// positions (19,200 samples) therefore separates the two: under
    /// the fixed dealer P(never zero) = (255/256)^19200 < 1e-32, while
    /// under the biased dealer this test fails ALWAYS. Verified
    /// mutation-style: swapping the dependency back to sharks 0.5.0
    /// makes this test fail deterministically.
    #[test]
    fn coefficients_are_unbiased_rustsec_2024_0398() {
        assert_eq!(THRESHOLD, 2, "the a1 = y XOR s derivation below assumes threshold 2");
        let seed = [0u8; 32]; // s = 0 => share-at-x=1 bytes ARE the coefficients
        let mut saw_zero_coeff = false;
        'outer: for _ in 0..600 {
            let shares = split_seed(&seed);
            let share1 = shares.iter().find(|s| s[0] == 1)
                .expect("dealer must emit a share with index x = 1");
            // share layout: x || y_0..y_31 ; with s = 0, y_i == a1 for byte i.
            if share1[1..].iter().any(|&y| y == 0) {
                saw_zero_coeff = true;
                break 'outer;
            }
        }
        assert!(saw_zero_coeff,
            "polynomial coefficient 0 never observed in 19,200 samples: \
             the Shamir dealer is biased (RUSTSEC-2024-0398 class bug)");
    }

    /// Pins the share WIRE FORMAT so custodian shares dealt by the
    /// pre-fix (sharks) binary keep recovering: 33 bytes = x || 32
    /// GF(256) points, x starting at 1, recovery driven purely by the
    /// raw bytes handed back on argv.
    #[test]
    fn share_wire_format_is_stable_for_migration() {
        let seed: [u8; 32] = core::array::from_fn(|i| i as u8);
        let shares = split_seed(&seed);
        let mut xs: Vec<u8> = shares.iter().map(|s| s[0]).collect();
        xs.sort_unstable();
        assert_eq!(xs, vec![1, 2, 3], "share index bytes must be x = 1..=3");
        for s in &shares {
            assert_eq!(s.len(), 33, "share must be x || 32 points");
        }
        // Round-trip from raw bytes only (exactly what the CLI does).
        let raw: Vec<Vec<u8>> = shares[..2].iter().cloned().collect();
        assert_eq!(recover_seed(&raw).unwrap(), seed);
    }
}
