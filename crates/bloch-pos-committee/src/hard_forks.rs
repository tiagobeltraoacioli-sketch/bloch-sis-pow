// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Hard forks 1, 2 and 3: the one list of activation gates
//!
//! Every activation constant introduced by the HF1/HF2/HF3 lines is listed in
//! [`HARD_FORK_GATES`], with the fork it belongs to. The constants themselves
//! stay where their code reads them (mostly `params.rs`); this module only
//! names them, checks the ordering rules between them at compile time, and
//! pins in tests what a release may arm.
//!
//! All of them ship `u64::MAX` (INERT). Arming is a founder decision taken in
//! one release commit; the exact edit per constant is in
//! `docs/HARD-FORKS-1-2-3-INTEGRATION.md`.
//!
//! ## Ordering rules ([`hard_fork_schedule_coherent`])
//!
//! - **HF1.** The frozen finality set requires claim finality, armed no
//!   later (`params::hf1_gates_coherent`). Claim finality may be armed alone
//!   (HF1 security review, M-5).
//! - **HF2 after HF1.** An armed HF2 gate requires claim finality armed and
//!   at least [`HF2_MIN_EPOCHS_AFTER_HF1`] epochs (24 h) after it, so a
//!   replacement release can still move HF2 once HF1 is live (schedule O4).
//! - **Registrations and allocations before the features that use them**:
//!   gates added by later lines (KES registration before enforcement, the
//!   SLH-DSA suite before the PQ migration that rotates to it, signature
//!   canonicalization before a new suite) extend this function when their
//!   line is merged.
//!
//! [`RELEASE_ARMABLE`] lists the gates the next release is allowed to arm.
//! `only_release_armable_gates_are_armed` fails if any other gate leaves
//! `u64::MAX`, so arming a gate outside the agreed scope cannot slip
//! through a one-line edit.

use crate::params;

/// Which hard fork a gate belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fork {
    Hf1,
    Hf2,
    Hf3,
}

/// One activation gate of the HF1/HF2/HF3 lines.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HardForkGate {
    pub name: &'static str,
    pub fork: Fork,
    pub epoch: u64,
    /// Node-local policy (read against the wall epoch, no state-transition
    /// effect) rather than a consensus rule.
    pub node_policy_only: bool,
}

impl HardForkGate {
    pub const fn armed(&self) -> bool {
        self.epoch != u64::MAX
    }
}

macro_rules! gate {
    ($fork:ident, $path:path, $policy:expr) => {
        HardForkGate { name: stringify!($path), fork: Fork::$fork, epoch: $path, node_policy_only: $policy }
    };
}

/// Every HF1/HF2/HF3 activation constant on this line.
pub const HARD_FORK_GATES: &[HardForkGate] = &[
    // HF1: L2 claim finality and the frozen finality set.
    gate!(Hf1, params::HF1_CLAIM_FINALITY_EPOCH, false),
    gate!(Hf1, params::HF1_FROZEN_FINALITY_SET_EPOCH, false),
    // HF2: slashing v2 (P5a evidence admission, node policy) and the
    // funded-activation growth cap.
    gate!(Hf2, params::HF2_SLASHING_V2_EPOCH, true),
    gate!(Hf2, params::NATIVE_SLASHING_ACTIVATION_EPOCH, true),
    gate!(Hf2, params::HF2_GROWTH_CAP_EPOCH, false),
];

/// Gates the next release may arm (owner decision 2026-10-20: claim
/// finality only). Everything else must stay `u64::MAX`.
pub const RELEASE_ARMABLE: &[&str] = &["params::HF1_CLAIM_FINALITY_EPOCH"];

/// Minimum spacing between HF1 claim finality and any HF2 gate (one day).
pub const HF2_MIN_EPOCHS_AFTER_HF1: u64 = 90;

const fn armed(e: u64) -> bool {
    e != u64::MAX
}

/// `hf2` is inert, or HF1 claim finality is armed and `hf2` is at least
/// [`HF2_MIN_EPOCHS_AFTER_HF1`] after it.
pub const fn hf2_after_hf1(claim_finality: u64, hf2: u64) -> bool {
    !armed(hf2) || (armed(claim_finality) && hf2 >= claim_finality.saturating_add(HF2_MIN_EPOCHS_AFTER_HF1))
}

/// The ordering rules between all HF1/HF2/HF3 gates (see the module docs).
pub const fn hard_fork_schedule_coherent(
    claim_finality: u64,
    frozen_set: u64,
    hf2_slashing: u64,
    hf2_growth_cap: u64,
) -> bool {
    params::hf1_gates_coherent(claim_finality, frozen_set)
        && hf2_after_hf1(claim_finality, hf2_slashing)
        && hf2_after_hf1(claim_finality, hf2_growth_cap)
}

const _: () = assert!(hard_fork_schedule_coherent(
    params::HF1_CLAIM_FINALITY_EPOCH,
    params::HF1_FROZEN_FINALITY_SET_EPOCH,
    params::HF2_SLASHING_V2_EPOCH,
    params::HF2_GROWTH_CAP_EPOCH,
));
// The P5a alias must follow the HF2 release switch.
const _: () = assert!(params::NATIVE_SLASHING_ACTIVATION_EPOCH == params::HF2_SLASHING_V2_EPOCH);

#[cfg(test)]
mod tests {
    use super::*;

    const M: u64 = u64::MAX;

    #[test]
    fn the_shipped_schedule_is_coherent() {
        assert!(hard_fork_schedule_coherent(
            params::HF1_CLAIM_FINALITY_EPOCH,
            params::HF1_FROZEN_FINALITY_SET_EPOCH,
            params::HF2_SLASHING_V2_EPOCH,
            params::HF2_GROWTH_CAP_EPOCH,
        ));
    }

    #[test]
    fn only_release_armable_gates_are_armed() {
        for g in HARD_FORK_GATES {
            if !RELEASE_ARMABLE.contains(&g.name) {
                assert!(!g.armed(), "{} is armed but outside this release's scope", g.name);
            }
        }
    }

    #[test]
    fn every_gate_is_listed_once() {
        for (i, a) in HARD_FORK_GATES.iter().enumerate() {
            for b in &HARD_FORK_GATES[i + 1..] {
                assert_ne!(a.name, b.name);
            }
        }
        for name in RELEASE_ARMABLE {
            assert!(HARD_FORK_GATES.iter().any(|g| g.name == *name), "{name} not a hard-fork gate");
        }
    }

    /// The indexer and the release kit discover gates by scanning `params.rs`
    /// for `pub const *_EPOCH: u64`; every HF gate defined there must be in
    /// the central list too.
    #[test]
    fn every_hf_gate_in_params_is_listed_here() {
        let src = include_str!("params.rs");
        for line in src.lines() {
            let Some(rest) = line.trim_start().strip_prefix("pub const ") else { continue };
            let name: String =
                rest.chars().take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '_').collect();
            if (name.starts_with("HF1_") || name.starts_with("HF2_") || name.starts_with("HF3_"))
                && name.ends_with("_EPOCH")
                && rest[name.len()..].trim_start().starts_with(": u64")
            {
                let full = format!("params::{name}");
                assert!(HARD_FORK_GATES.iter().any(|g| g.name == full), "{full} missing from HARD_FORK_GATES");
            }
        }
    }

    #[test]
    fn claim_finality_may_ship_alone() {
        assert!(hard_fork_schedule_coherent(6_460, M, M, M));
        assert!(hard_fork_schedule_coherent(0, M, M, M));
    }

    #[test]
    fn frozen_set_needs_claim_finality_no_later() {
        assert!(hard_fork_schedule_coherent(6_460, 6_460, M, M));
        assert!(hard_fork_schedule_coherent(6_460, 6_466, M, M));
        assert!(!hard_fork_schedule_coherent(M, 6_460, M, M));
        assert!(!hard_fork_schedule_coherent(6_466, 6_460, M, M));
    }

    #[test]
    fn hf2_needs_hf1_a_day_earlier() {
        assert!(hard_fork_schedule_coherent(6_460, M, 6_550, 6_550));
        assert!(hard_fork_schedule_coherent(6_460, M, 6_550, M));
        assert!(hard_fork_schedule_coherent(6_460, M, M, 6_550));
        // HF2 without HF1.
        assert!(!hard_fork_schedule_coherent(M, M, 6_550, M));
        assert!(!hard_fork_schedule_coherent(M, M, M, 6_550));
        // Less than one day after HF1.
        assert!(!hard_fork_schedule_coherent(6_460, M, 6_549, M));
        assert!(!hard_fork_schedule_coherent(6_460, M, M, 6_460));
        // Saturation: claim finality near the top never wraps.
        assert!(!hard_fork_schedule_coherent(M - 1, M, M - 2, M));
    }
}
