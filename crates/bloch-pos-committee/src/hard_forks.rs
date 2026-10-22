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
//!   (HF1 security review, M-5). Own-target votes require the frozen set,
//!   armed no later (schedule O2: without a frozen denominator, filtering
//!   foreign votes lowers counted participation on both sides of a split
//!   and speeds up minority finality under the leak).
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
    gate!(Hf1, params::HF1_OWN_TARGET_VOTES_EPOCH, false),
    // HF2: slashing v2 (P5a evidence admission, node policy) and the
    // funded-activation growth cap.
    gate!(Hf2, params::HF2_SLASHING_V2_EPOCH, true),
    gate!(Hf2, params::NATIVE_SLASHING_ACTIVATION_EPOCH, true),
    gate!(Hf2, params::HF2_GROWTH_CAP_EPOCH, false),
    // HF2 signatures: canonical encodings + suite-bound context for
    // consensus messages only, and the platform-independent ML-DSA rule.
    gate!(Hf2, params::SIG_CANONICAL_ACTIVATION_EPOCH, false),
    gate!(Hf2, params::MLDSA_PIN_ACTIVATION_EPOCH, false),
    // HF3: post-quantum suite migration (credential rotation 0x18) and the
    // lattice-break emergency (0x19/0x1A rescue, lattice spends frozen).
    gate!(Hf3, params::HF3_KES_EPOCH, false),
    gate!(Hf3, params::KES_REGISTRATION_EPOCH, false),
    gate!(Hf3, params::HF3_KES_ENFORCE_EPOCH, false),
    gate!(Hf3, params::KES_ACTIVATION_EPOCH, false),
    gate!(Hf3, params::HF3_SLH_SUITE_EPOCH, false),
    gate!(Hf3, params::HF3_PQ_MIGRATION_EPOCH, false),
    gate!(Hf3, params::LATTICE_EMERGENCY_ACTIVATION_EPOCH, false),
];

/// Gates that no scheduled release may arm (owner scope 2026-10-20: nothing
/// that changes how users deposit, transfer or withdraw). The lattice
/// emergency freezes lattice-key spends by design; it exists only for a
/// public break of both lattice families and needs its own decision.
pub const NEVER_IN_A_SCHEDULED_RELEASE: &[&str] = &["params::LATTICE_EMERGENCY_ACTIVATION_EPOCH"];

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
/// `later` is inert, or `earlier` is armed at the same epoch or before it.
pub const fn requires_no_later(earlier: u64, later: u64) -> bool {
    !armed(later) || (armed(earlier) && earlier <= later)
}

pub const fn hard_fork_schedule_coherent(
    claim_finality: u64,
    frozen_set: u64,
    own_target: u64,
    hf2_slashing: u64,
    hf2_growth_cap: u64,
    sig_canonical: u64,
    mldsa_pin: u64,
    kes_registration: u64,
    kes_enforcement: u64,
    slh_suite: u64,
    pq_migration: u64,
    lattice_emergency: u64,
) -> bool {
    params::hf1_gates_coherent(claim_finality, frozen_set)
        && requires_no_later(frozen_set, own_target)
        && hf2_after_hf1(claim_finality, hf2_slashing)
        && hf2_after_hf1(claim_finality, hf2_growth_cap)
        && hf2_after_hf1(claim_finality, sig_canonical)
        && hf2_after_hf1(claim_finality, mldsa_pin)
        && hf2_after_hf1(claim_finality, kes_registration)
        && requires_no_later(kes_registration, kes_enforcement)
        && hf2_after_hf1(claim_finality, slh_suite)
        && requires_no_later(slh_suite, pq_migration)
        && requires_no_later(pq_migration, lattice_emergency)
}

// The ML-DSA pin's QUALIFICATION-ONLY build arms it at 0 on purpose (full
// history under the pinned rule); it is never a release.
#[cfg(not(feature = "mldsa-pin-replay-qualification"))]
const _: () = assert!(hard_fork_schedule_coherent(
    params::HF1_CLAIM_FINALITY_EPOCH,
    params::HF1_FROZEN_FINALITY_SET_EPOCH,
    params::HF1_OWN_TARGET_VOTES_EPOCH,
    params::HF2_SLASHING_V2_EPOCH,
    params::HF2_GROWTH_CAP_EPOCH,
    params::SIG_CANONICAL_ACTIVATION_EPOCH,
    params::MLDSA_PIN_ACTIVATION_EPOCH,
    params::HF3_KES_EPOCH,
    params::HF3_KES_ENFORCE_EPOCH,
    params::HF3_SLH_SUITE_EPOCH,
    params::HF3_PQ_MIGRATION_EPOCH,
    params::LATTICE_EMERGENCY_ACTIVATION_EPOCH,
));
// The P5a alias must follow the HF2 release switch.
const _: () = assert!(params::NATIVE_SLASHING_ACTIVATION_EPOCH == params::HF2_SLASHING_V2_EPOCH);
// The KES aliases must follow the HF3 switches.
const _: () = assert!(params::KES_REGISTRATION_EPOCH == params::HF3_KES_EPOCH);
const _: () = assert!(params::KES_ACTIVATION_EPOCH == params::HF3_KES_ENFORCE_EPOCH);

#[cfg(test)]
mod tests {
    use super::*;

    const M: u64 = u64::MAX;

    #[test]
    fn the_shipped_schedule_is_coherent() {
        assert!(hard_fork_schedule_coherent(
            params::HF1_CLAIM_FINALITY_EPOCH,
            params::HF1_FROZEN_FINALITY_SET_EPOCH,
            params::HF1_OWN_TARGET_VOTES_EPOCH,
            params::HF2_SLASHING_V2_EPOCH,
            params::HF2_GROWTH_CAP_EPOCH,
            params::SIG_CANONICAL_ACTIVATION_EPOCH,
            params::MLDSA_PIN_ACTIVATION_EPOCH,
            params::HF3_KES_EPOCH,
            params::HF3_KES_ENFORCE_EPOCH,
            params::HF3_SLH_SUITE_EPOCH,
            params::HF3_PQ_MIGRATION_EPOCH,
            params::LATTICE_EMERGENCY_ACTIVATION_EPOCH,
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
    fn emergency_gates_are_never_release_armable() {
        for name in NEVER_IN_A_SCHEDULED_RELEASE {
            assert!(!RELEASE_ARMABLE.contains(name));
            let g = HARD_FORK_GATES.iter().find(|g| g.name == *name).expect("listed");
            assert!(!g.armed(), "{name} must stay u64::MAX");
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
        assert!(hard_fork_schedule_coherent(6_460, M, M, M, M, M, M, M, M, M, M, M));
        assert!(hard_fork_schedule_coherent(0, M, M, M, M, M, M, M, M, M, M, M));
    }

    #[test]
    fn frozen_set_needs_claim_finality_no_later() {
        assert!(hard_fork_schedule_coherent(6_460, 6_460, M, M, M, M, M, M, M, M, M, M));
        assert!(hard_fork_schedule_coherent(6_460, 6_466, M, M, M, M, M, M, M, M, M, M));
        assert!(!hard_fork_schedule_coherent(M, 6_460, M, M, M, M, M, M, M, M, M, M));
        assert!(!hard_fork_schedule_coherent(6_466, 6_460, M, M, M, M, M, M, M, M, M, M));
    }

    #[test]
    fn own_target_needs_the_frozen_set_no_later() {
        assert!(hard_fork_schedule_coherent(6_460, 6_460, 6_466, M, M, M, M, M, M, M, M, M));
        assert!(hard_fork_schedule_coherent(6_460, 6_460, 6_460, M, M, M, M, M, M, M, M, M));
        assert!(!hard_fork_schedule_coherent(6_460, M, 6_466, M, M, M, M, M, M, M, M, M));
        assert!(!hard_fork_schedule_coherent(6_460, 6_470, 6_466, M, M, M, M, M, M, M, M, M));
        assert!(!hard_fork_schedule_coherent(M, M, 6_466, M, M, M, M, M, M, M, M, M));
    }

    #[test]
    fn hf2_needs_hf1_a_day_earlier() {
        assert!(hard_fork_schedule_coherent(6_460, M, M, 6_550, 6_550, M, M, M, M, M, M, M));
        assert!(hard_fork_schedule_coherent(6_460, M, M, 6_550, M, M, M, M, M, M, M, M));
        assert!(hard_fork_schedule_coherent(6_460, M, M, M, 6_550, M, M, M, M, M, M, M));
        // HF2 without HF1.
        assert!(!hard_fork_schedule_coherent(M, M, M, 6_550, M, M, M, M, M, M, M, M));
        assert!(!hard_fork_schedule_coherent(M, M, M, M, 6_550, M, M, M, M, M, M, M));
        // Less than one day after HF1.
        assert!(!hard_fork_schedule_coherent(6_460, M, M, 6_549, M, M, M, M, M, M, M, M));
        assert!(!hard_fork_schedule_coherent(6_460, M, M, M, 6_460, M, M, M, M, M, M, M));
        // Signature gates follow the same rule.
        assert!(hard_fork_schedule_coherent(6_460, M, M, M, M, 6_550, 6_550, M, M, M, M, M));
        assert!(!hard_fork_schedule_coherent(M, M, M, M, M, 6_550, M, M, M, M, M, M));
        assert!(!hard_fork_schedule_coherent(M, M, M, M, M, M, 6_550, M, M, M, M, M));
        assert!(!hard_fork_schedule_coherent(6_460, M, M, M, M, 6_500, M, M, M, M, M, M));
        // HF3: the SLH-DSA suite a day after HF1; the PQ migration at or
        // after the suite; the emergency only after the migration.
        assert!(hard_fork_schedule_coherent(6_460, M, M, M, M, M, M, M, M, 6_562, M, M));
        assert!(hard_fork_schedule_coherent(6_460, M, M, M, M, M, M, M, M, 6_562, 6_562, M));
        assert!(!hard_fork_schedule_coherent(M, M, M, M, M, M, M, M, M, 6_562, M, M));
        assert!(!hard_fork_schedule_coherent(6_460, M, M, M, M, M, M, M, M, M, 6_562, M));
        assert!(!hard_fork_schedule_coherent(6_460, M, M, M, M, M, M, M, M, 6_570, 6_562, M));
        assert!(!hard_fork_schedule_coherent(6_460, M, M, M, M, M, M, M, M, M, M, 6_600));
        assert!(!hard_fork_schedule_coherent(6_460, M, M, M, M, M, M, M, M, 6_562, 6_600, 6_562));
        // HF3 KES: registration a day after HF1, enforcement only after it.
        assert!(hard_fork_schedule_coherent(6_460, M, M, M, M, M, M, 6_562, M, M, M, M));
        assert!(hard_fork_schedule_coherent(6_460, M, M, M, M, M, M, 6_562, 7_822, M, M, M));
        assert!(!hard_fork_schedule_coherent(6_460, M, M, M, M, M, M, M, 7_822, M, M, M));
        assert!(!hard_fork_schedule_coherent(M, M, M, M, M, M, M, 6_562, M, M, M, M));
        // Saturation: claim finality near the top never wraps.
        assert!(!hard_fork_schedule_coherent(M - 1, M, M, M - 2, M, M, M, M, M, M, M, M));
    }
}
