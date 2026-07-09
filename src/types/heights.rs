//! Block height and block count newtypes.
//!
//! Eliminates the count-vs-height ambiguity that surfaced in Sprint 1.5 L5
//! verification (2026-04-28): `getblockcount=1` and `tip_height=0` are both
//! correct but measure different units (cardinality vs zero-based index).
//!
//! Convention follows Bitcoin Core:
//!   - `BlockHeight` = zero-based index. Genesis = 0.
//!   - `BlockCount`  = 1-based cardinality. Chain with only genesis = 1.
//!
//! Invariant: `BlockCount == BlockHeight + 1` for any non-empty chain.

use serde::{Deserialize, Serialize};

/// Zero-based block index. Genesis block is `BlockHeight(0)`.
///
/// Use this for: tip height, finalized height (FFG), justified height (FFG),
/// epoch start/end heights, anything that names a specific block by position.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
#[repr(transparent)]
pub struct BlockHeight(pub u64);

impl BlockHeight {
    /// Height of the genesis block.
    pub const GENESIS: Self = Self(0);

    /// Convert to 1-based cardinality (Bitcoin `getblockcount` semantics).
    #[inline]
    pub const fn as_count(self) -> BlockCount {
        BlockCount(self.0 + 1)
    }

    /// Saturating successor. Useful in fork-choice / replay loops.
    #[inline]
    pub const fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }

    /// Saturating predecessor. Returns `GENESIS` when called on `GENESIS`.
    #[inline]
    pub const fn saturating_prev(self) -> Self {
        Self(self.0.saturating_sub(1))
    }

    /// Distance (number of blocks) between two heights, signed.
    /// Returns `None` on overflow.
    #[inline]
    pub fn distance_to(self, other: Self) -> Option<i64> {
        let a = i64::try_from(self.0).ok()?;
        let b = i64::try_from(other.0).ok()?;
        b.checked_sub(a)
    }
}

impl std::fmt::Display for BlockHeight {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "h={}", self.0)
    }
}

/// 1-based block cardinality. Chain with only genesis has `BlockCount(1)`.
///
/// Use this for: Bitcoin-compat `getblockcount` RPC, Prometheus
/// `bloch_block_count` gauge, anything that answers "how many blocks
/// exist". Internal DAG code should generally use `BlockHeight` instead.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
#[repr(transparent)]
pub struct BlockCount(pub u64);

impl BlockCount {
    /// Cardinality of an empty chain. Should not occur in practice
    /// (genesis is always present), but useful as a sentinel.
    pub const EMPTY: Self = Self(0);

    /// Cardinality of a chain containing only the genesis block.
    pub const GENESIS_ONLY: Self = Self(1);

    /// Convert to zero-based index. Returns `None` for an empty chain
    /// (since `BlockCount(0)` has no corresponding height).
    #[inline]
    pub const fn as_height(self) -> Option<BlockHeight> {
        match self.0.checked_sub(1) {
            Some(h) => Some(BlockHeight(h)),
            None => None,
        }
    }

    /// Convert to `i64` for Prometheus `IntGauge.set()`.
    /// Saturates at `i64::MAX` for absurdly long chains.
    #[inline]
    pub fn as_i64(self) -> i64 {
        i64::try_from(self.0).unwrap_or(i64::MAX)
    }
}

impl std::fmt::Display for BlockCount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "n={}", self.0)
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_only_chain_roundtrip() {
        // Genesis present, no other blocks: height=0, count=1.
        let h = BlockHeight::GENESIS;
        let c = h.as_count();
        assert_eq!(c, BlockCount(1));
        assert_eq!(c, BlockCount::GENESIS_ONLY);
        assert_eq!(c.as_height(), Some(BlockHeight(0)));
    }

    #[test]
    fn empty_chain_height_is_none() {
        // The pathological case: BlockCount(0) has no height.
        assert_eq!(BlockCount::EMPTY.as_height(), None);
        assert_eq!(BlockCount(0).as_height(), None);
    }

    #[test]
    fn arbitrary_roundtrip() {
        for n in [1u64, 2, 100, 2381, 210_000, 420_000, 1_000_000] {
            let c = BlockCount(n);
            let h = c.as_height().unwrap();
            assert_eq!(h.0, n - 1);
            assert_eq!(h.as_count(), c);
        }
    }

    #[test]
    fn saturating_arithmetic() {
        assert_eq!(BlockHeight::GENESIS.saturating_prev(), BlockHeight::GENESIS);
        assert_eq!(BlockHeight(5).saturating_prev(), BlockHeight(4));
        assert_eq!(BlockHeight(u64::MAX).next(), BlockHeight(u64::MAX));
        assert_eq!(BlockHeight(5).next(), BlockHeight(6));
    }

    #[test]
    fn distance() {
        assert_eq!(BlockHeight(10).distance_to(BlockHeight(15)), Some(5));
        assert_eq!(BlockHeight(15).distance_to(BlockHeight(10)), Some(-5));
        assert_eq!(BlockHeight(0).distance_to(BlockHeight(0)), Some(0));
    }

    #[test]
    fn ordering() {
        assert!(BlockHeight(0) < BlockHeight(1));
        assert!(BlockHeight(2381) < BlockHeight(210_000));
        assert!(BlockCount(1) < BlockCount(2));
    }

    #[test]
    fn serde_transparent() {
        // Critical for RPC compatibility: the wire format must be a bare
        // integer, not `{"BlockHeight": 5}` or similar.
        let h = BlockHeight(42);
        let s = serde_json::to_string(&h).unwrap();
        assert_eq!(s, "42");

        let c = BlockCount(43);
        let s = serde_json::to_string(&c).unwrap();
        assert_eq!(s, "43");

        let h2: BlockHeight = serde_json::from_str("42").unwrap();
        assert_eq!(h2, BlockHeight(42));
    }

    #[test]
    fn as_i64_saturates() {
        assert_eq!(BlockCount(0).as_i64(), 0);
        assert_eq!(BlockCount(1_000_000).as_i64(), 1_000_000);
        assert_eq!(BlockCount(u64::MAX).as_i64(), i64::MAX);
    }

    #[test]
    fn display_format() {
        assert_eq!(format!("{}", BlockHeight(5)), "h=5");
        assert_eq!(format!("{}", BlockCount(6)), "n=6");
    }
}
