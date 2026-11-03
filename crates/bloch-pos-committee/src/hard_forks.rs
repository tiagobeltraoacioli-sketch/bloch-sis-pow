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
//! - **The L2 program after KES.** The swap to the next L2 program and its
//!   rollback are listed here too ([`Fork::L2Program`]), so that the checks
//!   below hold them to `u64::MAX`. [`l2_program_schedule_coherent`]: an armed
//!   swap comes strictly after the first KES period starts, one day of epochs
//!   after enforcement, so a replacement release can still move it once KES is
//!   live and the two state changes never share a boundary. A rollback needs an
//!   armed swap before it.
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
    /// The L2 program swap and its rollback, on no HF line of their own.
    L2Program,
    /// The reserved DA slot of the registered L2 DA key, on no HF line.
    L2DataAvailability,
    /// The L2 protocol fee on deposits and claims (L1 only), on no HF line.
    L2Revenue,
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
    // The next L2 program: inert, outside `RELEASE_ARMABLE`.
    gate!(L2Program, params::L2_NEXT_PROGRAM_EPOCH, false),
    gate!(L2Program, params::L2_PROGRAM_ROLLBACK_EPOCH, false),
    // The reserved DA slot: inert, outside `RELEASE_ARMABLE`.
    gate!(L2DataAvailability, params::L2_DA_RESERVED_SLOT_EPOCH, false),
    // L1 forced inclusion of L2 transactions: inert, outside `RELEASE_ARMABLE`.
    gate!(L2Program, params::L2_FORCED_INCLUSION_EPOCH, false),
    // The L2 protocol fee: inert, outside `RELEASE_ARMABLE`.
    gate!(L2Revenue, params::L2_REVENUE_EPOCH, false),
];

/// Gates that no scheduled release may arm (owner scope 2026-10-20: nothing
/// that changes how users deposit, transfer or withdraw). The lattice
/// emergency freezes lattice-key spends by design; it exists only for a
/// public break of both lattice families and needs its own decision.
pub const NEVER_IN_A_SCHEDULED_RELEASE: &[&str] = &["params::LATTICE_EMERGENCY_ACTIVATION_EPOCH"];

/// Gates the next release may arm (owner decision 2026-10-25: HF1, HF2 and
/// HF3 at E1 7180 / 7186, E2 7270, E3 7360, KES enforcement 8620; the
/// lattice emergency is never armed). Everything else must stay `u64::MAX`.
pub const RELEASE_ARMABLE: &[&str] = &[
    "params::HF1_CLAIM_FINALITY_EPOCH",
    "params::HF1_FROZEN_FINALITY_SET_EPOCH",
    "params::HF1_OWN_TARGET_VOTES_EPOCH",
    "params::HF2_SLASHING_V2_EPOCH",
    "params::NATIVE_SLASHING_ACTIVATION_EPOCH",
    "params::HF2_GROWTH_CAP_EPOCH",
    "params::SIG_CANONICAL_ACTIVATION_EPOCH",
    "params::MLDSA_PIN_ACTIVATION_EPOCH",
    "params::HF3_KES_EPOCH",
    "params::KES_REGISTRATION_EPOCH",
    "params::HF3_KES_ENFORCE_EPOCH",
    "params::KES_ACTIVATION_EPOCH",
    "params::HF3_SLH_SUITE_EPOCH",
    "params::HF3_PQ_MIGRATION_EPOCH",
];

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

/// Epochs from KES enforcement to the first KES period handover: an armed L2
/// program swap comes strictly after it (see the module docs).
pub const L2_PROGRAM_MIN_EPOCHS_AFTER_KES: u64 = 90;

/// `next` is inert, or strictly after [`L2_PROGRAM_MIN_EPOCHS_AFTER_KES`] past an
/// armed KES enforcement; `rollback` is inert, or strictly after an armed `next`.
pub const fn l2_program_schedule_coherent(kes_enforcement: u64, next: u64, rollback: u64) -> bool {
    (!armed(next) || (armed(kes_enforcement) && next > kes_enforcement.saturating_add(L2_PROGRAM_MIN_EPOCHS_AFTER_KES)))
        && (!armed(rollback) || (armed(next) && rollback > next))
}

/// An armed swap or rollback names final programs, not the candidate's examples.
pub const fn l2_program_may_arm(next: u64, rollback: u64, program_final: bool) -> bool {
    program_final || (!armed(next) && !armed(rollback))
}

/// The reserved DA slot is inert, or a DA key is registered for it. With no
/// key the rule would bind nothing (`da::reserved_key_at`), so an armed gate
/// without one is a release mistake, refused at compile time.
pub const fn l2_da_reserved_slot_may_arm(epoch: u64, key: Option<[u8; 32]>) -> bool {
    !armed(epoch) || key.is_some()
}

/// Forced inclusion needs a guest that executes the queue, so it is armed only
/// with a listed configuration, and never before the program swap that brings
/// that guest (the same epoch is allowed: the swap runs first in `close_epoch`).
///
/// It also needs, from this build's compiled values (review 164 R1 and the
/// revenue rule of 2026-11-02 22:30):
/// * [`PROGRAM_FALLBACK`]'s configuration listed as well, so that the rollback,
///   an emergency lever, can always be armed without halting the L2 on a due
///   record its guest cannot prove (the fallback is rebuilt with the rule
///   before forced inclusion ships);
/// * the protocol treasury set, which receives every charged surcharge.
///
/// [`PROGRAM_FALLBACK`]: crate::l2_settlement::mainnet::PROGRAM_FALLBACK
pub const fn l2_forced_inclusion_may_arm(forced: u64, next: u64, configured: bool) -> bool {
    l2_forced_inclusion_may_arm_with(
        forced,
        next,
        configured,
        listed(
            crate::l2_settlement::mainnet::FORCED_INCLUSION_CONFIGURATIONS,
            &crate::l2_settlement::mainnet::PROGRAM_FALLBACK.identities[0],
        ),
        treasury_is_real(crate::l2_settlement::mainnet::FORCED_INCLUSION_TREASURY),
    )
}

/// [`l2_forced_inclusion_may_arm`] with every input explicit.
pub const fn l2_forced_inclusion_may_arm_with(
    forced: u64,
    next: u64,
    configured: bool,
    fallback_listed: bool,
    treasury_set: bool,
) -> bool {
    !armed(forced) || (configured && fallback_listed && treasury_set && armed(next) && forced >= next)
}

/// A rollback must reinstate a program that can consume the forced queue: with
/// forced inclusion armed, an armed rollback needs [`PROGRAM_FALLBACK`]'s
/// configuration listed as implementing it. Otherwise every settlement after
/// the rollback would be refused while a record is due, which halts the L2.
///
/// [`PROGRAM_FALLBACK`]: crate::l2_settlement::mainnet::PROGRAM_FALLBACK
pub const fn l2_forced_rollback_may_arm(forced: u64, rollback: u64, fallback_listed: bool) -> bool {
    !armed(forced) || !armed(rollback) || fallback_listed
}

/// Whether `configuration` is in `list` (const).
pub const fn listed(list: &[[u8; 32]], configuration: &[u8; 32]) -> bool {
    let mut i = 0;
    while i < list.len() {
        let mut j = 0;
        while j < 32 && list[i][j] == configuration[j] {
            j += 1;
        }
        if j == 32 {
            return true;
        }
        i += 1;
    }
    false
}

/// The L2 protocol fee is inert, or it has a treasury (a real script hash, not
/// zero) and comes strictly after the first KES period, like the program swap,
/// so it never shares a boundary with the KES bind. It may share the swap's
/// epoch: it changes no L2 rule.
/// A protocol treasury is set and is not the zero hash. Shared by every rule
/// that pays the protocol treasury (`params::PROTOCOL_TREASURY_SCRIPT_HASH`).
pub const fn treasury_is_real(treasury: Option<[u8; 32]>) -> bool {
    match treasury {
        Some(t) => {
            let mut i = 0;
            let mut nonzero = false;
            while i < 32 {
                nonzero |= t[i] != 0;
                i += 1;
            }
            nonzero
        }
        None => false,
    }
}

pub const fn l2_revenue_may_arm(revenue: u64, kes_enforcement: u64, treasury: Option<[u8; 32]>) -> bool {
    if !armed(revenue) {
        return true;
    }
    treasury_is_real(treasury) && armed(kes_enforcement) && revenue > kes_enforcement.saturating_add(L2_PROGRAM_MIN_EPOCHS_AFTER_KES)
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
// A rehearsal compresses the schedule and uses the candidate on a private network.
#[cfg(not(feature = "l2-activation-rehearsal"))]
const _: () = assert!(l2_program_schedule_coherent(
    params::HF3_KES_ENFORCE_EPOCH,
    params::L2_NEXT_PROGRAM_EPOCH,
    params::L2_PROGRAM_ROLLBACK_EPOCH,
));
#[cfg(not(feature = "l2-activation-rehearsal"))]
const _: () = assert!(l2_program_may_arm(
    params::L2_NEXT_PROGRAM_EPOCH,
    params::L2_PROGRAM_ROLLBACK_EPOCH,
    crate::l2_settlement::mainnet::PROGRAM_NEXT_FINAL,
));
const _: () = assert!(l2_da_reserved_slot_may_arm(
    params::L2_DA_RESERVED_SLOT_EPOCH,
    crate::l2_settlement::da::REGISTERED_KEY,
));
#[cfg(not(feature = "l2-activation-rehearsal"))]
const _: () = assert!(l2_forced_inclusion_may_arm(
    params::L2_FORCED_INCLUSION_EPOCH,
    params::L2_NEXT_PROGRAM_EPOCH,
    listed(
        crate::l2_settlement::mainnet::FORCED_INCLUSION_CONFIGURATIONS,
        &crate::l2_settlement::mainnet::PROGRAM_NEXT.identities[0],
    ),
));
#[cfg(not(feature = "l2-activation-rehearsal"))]
const _: () = assert!(l2_forced_rollback_may_arm(
    params::L2_FORCED_INCLUSION_EPOCH,
    params::L2_PROGRAM_ROLLBACK_EPOCH,
    listed(
        crate::l2_settlement::mainnet::FORCED_INCLUSION_CONFIGURATIONS,
        &crate::l2_settlement::mainnet::PROGRAM_FALLBACK.identities[0],
    ),
));
const _: () = assert!(l2_revenue_may_arm(
    params::L2_REVENUE_EPOCH,
    params::HF3_KES_ENFORCE_EPOCH,
    crate::l2_revenue::TREASURY_SCRIPT_HASH,
));
// One treasury for every L1 protocol revenue rule (forced-inclusion surcharge,
// L2 crossing fee), and the crossing fee rides with the program swap.
const _: () = assert!(params::L2_REVENUE_EPOCH == params::L2_NEXT_PROGRAM_EPOCH);
const _: () = assert!(same_treasury(
    crate::l2_settlement::mainnet::FORCED_INCLUSION_TREASURY,
    crate::l2_revenue::TREASURY_SCRIPT_HASH,
));
const fn same_treasury(a: Option<[u8; 32]>, b: Option<[u8; 32]>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(x), Some(y)) => {
            let mut i = 0;
            while i < 32 {
                if x[i] != y[i] {
                    return false;
                }
                i += 1;
            }
            true
        }
        _ => false,
    }
}
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
    fn the_l2_program_gates_ship_inert_or_armed_by_the_release_kit() {
        // Inert: outside the release scope. Armed (only by
        // `scripts/hf-release/l2-rollback/arm.py`): inside it, with final programs.
        for name in ["params::L2_NEXT_PROGRAM_EPOCH", "params::L2_PROGRAM_ROLLBACK_EPOCH"] {
            let g = HARD_FORK_GATES.iter().find(|g| g.name == name).expect("listed");
            assert_eq!(g.fork, Fork::L2Program);
            assert!(!g.node_policy_only);
            assert_eq!(RELEASE_ARMABLE.contains(&name), g.armed(), "{name}");
            assert!(!g.armed() || crate::l2_settlement::mainnet::PROGRAM_NEXT_FINAL, "{name}");
        }
    }

    #[test]
    fn the_reserved_da_slot_ships_inert_outside_the_release_scope_and_needs_a_key() {
        let name = "params::L2_DA_RESERVED_SLOT_EPOCH";
        let g = HARD_FORK_GATES.iter().find(|g| g.name == name).expect("listed");
        assert_eq!(g.fork, Fork::L2DataAvailability);
        assert!(!g.armed() && !g.node_policy_only);
        assert!(!RELEASE_ARMABLE.contains(&name));
        assert_eq!(params::L2_DA_RESERVED_SLOT_EPOCH, M);
        assert_eq!(crate::l2_settlement::mainnet::DA_RESERVED_KEY, None, "TBD-owner");
        assert!(l2_da_reserved_slot_may_arm(M, None));
        assert!(!l2_da_reserved_slot_may_arm(9_000, None));
        assert!(l2_da_reserved_slot_may_arm(9_000, Some([7; 32])));
    }

    #[test]
    fn forced_inclusion_ships_inert_and_needs_a_guest_and_the_swap() {
        let g = HARD_FORK_GATES.iter().find(|g| g.name == "params::L2_FORCED_INCLUSION_EPOCH").expect("listed");
        assert_eq!(g.fork, Fork::L2Program);
        assert!(!g.armed() && !g.node_policy_only);
        assert!(!RELEASE_ARMABLE.contains(&"params::L2_FORCED_INCLUSION_EPOCH"));
        assert_eq!(params::L2_FORCED_INCLUSION_EPOCH, M);
        // It rides with the swap.
        assert_eq!(params::L2_FORCED_INCLUSION_EPOCH, params::L2_NEXT_PROGRAM_EPOCH);
        // A listed configuration is always the next program's: no other guest
        // could publish the inbox hash at the swap.
        use crate::l2_settlement::mainnet::{FORCED_INCLUSION_CONFIGURATIONS as LIST, PROGRAM_FALLBACK, PROGRAM_NEXT};
        assert!(LIST.iter().all(|c| *c == PROGRAM_NEXT.identities[0]), "only the next configuration may be listed");
        assert!(LIST.len() <= 1);
        assert!(listed(&[[1; 32], [2; 32]], &[2; 32]) && !listed(&[[1; 32]], &[2; 32]) && !listed(&[], &[2; 32]));
        // The rollback rule: an armed rollback under armed forced inclusion
        // needs a listed fallback configuration.
        assert!(l2_forced_rollback_may_arm(M, M, false));
        assert!(l2_forced_rollback_may_arm(10_060, M, false));
        assert!(l2_forced_rollback_may_arm(M, 10_100, false));
        assert!(!l2_forced_rollback_may_arm(10_060, 10_100, false));
        assert!(l2_forced_rollback_may_arm(10_060, 10_100, true));
        // The fallback either has the next configuration, or is the next rules
        // without forced inclusion and then unlisted: in that case no release
        // may arm a rollback together with forced inclusion.
        let fallback_listed = listed(LIST, &PROGRAM_FALLBACK.identities[0]);
        if PROGRAM_FALLBACK.identities[0] != PROGRAM_NEXT.identities[0] {
            assert!(listed(LIST, &PROGRAM_NEXT.identities[0]) && !fallback_listed);
            assert!(!l2_forced_rollback_may_arm(10_060, 10_100, fallback_listed));
        }
        assert!(l2_forced_rollback_may_arm(params::L2_FORCED_INCLUSION_EPOCH, params::L2_PROGRAM_ROLLBACK_EPOCH, fallback_listed));
        // Inert is always coherent.
        let may = l2_forced_inclusion_may_arm_with;
        assert!(may(M, M, false, false, false));
        assert!(may(M, 10_060, true, false, false));
        // No listed guest: refused, whatever the swap.
        assert!(!may(10_060, 10_060, false, true, true));
        // No swap, or a gate before the swap: refused.
        assert!(!may(10_060, M, true, true, true));
        assert!(!may(10_059, 10_060, true, true, true));
        // An unlisted fallback (review 164 R1) or no treasury: refused.
        assert!(!may(10_060, 10_060, true, false, true));
        assert!(!may(10_060, 10_060, true, true, false));
        // At or after the swap with listed guests and a treasury: allowed.
        assert!(may(10_060, 10_060, true, true, true));
        assert!(may(11_320, 10_060, true, true, true));
        // The compiled rule reads this build's values: the fallback is listed
        // (agent 216) but the treasury is TBD-owner, so nothing may arm.
        assert_eq!(crate::l2_settlement::mainnet::FORCED_INCLUSION_TREASURY, None);
        assert!(!l2_forced_inclusion_may_arm(10_060, 10_060, true));
        assert!(l2_forced_inclusion_may_arm(M, 10_060, true));
    }

    #[test]
    fn the_l2_revenue_fee_ships_inert_and_needs_a_treasury_after_kes() {
        let g = HARD_FORK_GATES.iter().find(|g| g.name == "params::L2_REVENUE_EPOCH").expect("listed");
        assert_eq!(g.fork, Fork::L2Revenue);
        assert!(!g.armed() && !g.node_policy_only);
        assert!(!RELEASE_ARMABLE.contains(&"params::L2_REVENUE_EPOCH"));
        assert_eq!(params::L2_REVENUE_EPOCH, M);
        assert_eq!(crate::l2_revenue::TREASURY_SCRIPT_HASH, None, "TBD-owner");
        let kes = params::HF3_KES_ENFORCE_EPOCH;
        let after = kes + L2_PROGRAM_MIN_EPOCHS_AFTER_KES + 1;
        // Inert is always coherent.
        assert!(l2_revenue_may_arm(M, kes, None));
        // No treasury, or the zero hash: refused.
        assert!(!l2_revenue_may_arm(after, kes, None));
        assert!(!l2_revenue_may_arm(after, kes, Some([0; 32])));
        // At or before the first KES period, or without KES: refused.
        for gate in [0, kes, kes + L2_PROGRAM_MIN_EPOCHS_AFTER_KES] {
            assert!(!l2_revenue_may_arm(gate, kes, Some([7; 32])), "{gate}");
        }
        assert!(!l2_revenue_may_arm(10_000, M, Some([7; 32])));
        assert!(l2_revenue_may_arm(after, kes, Some([7; 32])));
    }

    #[test]
    fn one_protocol_treasury_pays_both_revenue_rules_and_must_be_real_to_arm() {
        // One TBD-owner constant; both rules read it through their aliases.
        assert_eq!(params::PROTOCOL_TREASURY_SCRIPT_HASH, None, "TBD-owner");
        assert_eq!(crate::l2_settlement::mainnet::FORCED_INCLUSION_TREASURY, params::PROTOCOL_TREASURY_SCRIPT_HASH);
        assert_eq!(crate::l2_revenue::TREASURY_SCRIPT_HASH, params::PROTOCOL_TREASURY_SCRIPT_HASH);
        assert!(same_treasury(None, None) && same_treasury(Some([7; 32]), Some([7; 32])));
        assert!(!same_treasury(Some([7; 32]), None) && !same_treasury(Some([7; 32]), Some([8; 32])));
        // The crossing fee rides with the program swap.
        assert_eq!(params::L2_REVENUE_EPOCH, params::L2_NEXT_PROGRAM_EPOCH);
        // Unset or zero: neither gate may arm.
        assert!(!treasury_is_real(None) && !treasury_is_real(Some([0; 32])));
        assert!(treasury_is_real(Some([7; 32])));
        let (next, forced) = (10_060, 10_060);
        assert!(!l2_forced_inclusion_may_arm_with(forced, next, true, true, treasury_is_real(None)));
        assert!(!l2_forced_inclusion_may_arm_with(forced, next, true, true, treasury_is_real(Some([0; 32]))));
        assert!(l2_forced_inclusion_may_arm_with(forced, next, true, true, treasury_is_real(Some([7; 32]))));
    }

    #[test]
    fn the_l2_program_swap_comes_after_the_first_kes_period() {
        let kes = params::HF3_KES_ENFORCE_EPOCH;
        assert_eq!(kes, 8_620);
        assert!(l2_program_schedule_coherent(kes, M, M));
        // Enforcement, the bind two epochs later, and period 1 at e8710 are refused.
        for gate in [0, 7_360, kes, kes + 2, kes + L2_PROGRAM_MIN_EPOCHS_AFTER_KES] {
            assert!(!l2_program_schedule_coherent(kes, gate, M), "{gate}");
        }
        assert!(l2_program_schedule_coherent(kes, kes + L2_PROGRAM_MIN_EPOCHS_AFTER_KES + 1, M));
        // A swap needs KES armed at all.
        assert!(!l2_program_schedule_coherent(M, 10_000, M));
    }

    #[test]
    fn the_l2_program_rollback_needs_an_armed_swap_before_it() {
        let kes = params::HF3_KES_ENFORCE_EPOCH;
        assert!(l2_program_schedule_coherent(kes, 10_000, 10_001));
        for rollback in [0, 9_999, 10_000] {
            assert!(!l2_program_schedule_coherent(kes, 10_000, rollback), "{rollback}");
        }
        assert!(!l2_program_schedule_coherent(kes, M, 10_001));
    }

    #[test]
    fn an_armed_l2_program_gate_needs_final_programs() {
        assert!(l2_program_may_arm(M, M, false));
        assert!(l2_program_may_arm(10_000, 10_001, true));
        assert!(!l2_program_may_arm(10_000, M, false));
        assert!(!l2_program_may_arm(M, 10_001, false));
        assert!(
            l2_program_may_arm(params::L2_NEXT_PROGRAM_EPOCH, params::L2_PROGRAM_ROLLBACK_EPOCH, crate::l2_settlement::mainnet::PROGRAM_NEXT_FINAL),
            "an armed gate needs final programs"
        );
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
