// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Hard forks 1, 2 and 3: the one list of activation gates
//!
//! Every activation constant introduced by the HF1/HF2/HF3 lines is listed in
//! [`HARD_FORK_GATES`], with the fork it belongs to. The constants themselves
//! stay where their code reads them (mostly `params.rs`); this module only
//! names them, checks the ordering rules between them at compile time, and
//! pins in tests what a release may arm.
//!
//! A new gate ships `u64::MAX` (INERT). Arming is a founder decision taken in
//! one release commit; the exact edit per constant is in
//! `docs/HARD-FORKS-1-2-3-INTEGRATION.md`. The gates in [`RELEASE_ARMABLE`]
//! are armed (owner decision 2026-10-25); the values are in `params.rs`.
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
    // HF3 KES follow-up rules from the security review (FC-3/CR-1, CR-2,
    // CR-5). Listed so the RPC, the release-scope test and operators see
    // them; see `kes_follow_up_gates_cover_enforcement` for how they relate
    // to `HF3_KES_ENFORCE_EPOCH`.
    gate!(Hf3, params::ATTESTATION_SLOT_EPOCH_BINDING_ACTIVATION_EPOCH, false),
    gate!(Hf3, params::KES_FIRST_KEY_FLOOR_ACTIVATION_EPOCH, false),
    gate!(Hf3, params::KES_REGISTER_EPOCH_BINDING_EPOCH, false),
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

// ── KES follow-up gates versus KES enforcement (review round 2, GATE-02) ───
//
// Three rules repair defects that only bite once KES signatures are
// enforced: the vote slot-epoch binding (FC-3/CR-1), the first-key floor
// (CR-2) and the epoch-bound registration message (CR-5). Each has its own
// gate so the owner chooses the flag day, but a build that arms enforcement
// and leaves them inert ships the defects live.
//
// That combination exists today (enforcement 8620, all three `u64::MAX`), and
// arming is the owner's decision, so a hard const assertion cannot be added
// without either breaking the build or picking the epochs here. Instead:
//
// * [`KES_FOLLOW_UP_GATES_PENDING`] records, in one line, that the open
//   combination is known. While it is `true` the node prints
//   [`shipped_kes_follow_up_exposures`] at every boot.
// * `the_kes_follow_up_flag_matches_the_shipped_gates` fails as soon as the
//   flag and the constants disagree, in either direction, so the release
//   that arms the gates must flip the flag to `false` in the same commit.
// * Once it is `false`, the const assertion below makes the relation a
//   compile-time rule: the gates can no longer be un-armed, or enforcement
//   moved ahead of them, without a build failure.

/// Last epoch at which [`params::KES_REGISTER_EPOCH_BINDING_EPOCH`] still
/// precedes every pruning of retired KES key history: a retired tree can be
/// re-registered from an old signature only after it has left the history,
/// which is kept `KES_KEY_HISTORY_PERIODS` periods from enforcement on.
pub const fn kes_register_binding_deadline(enforcement: u64) -> u64 {
    enforcement.saturating_add(params::KES_KEY_HISTORY_PERIODS.saturating_mul(params::KES_PERIOD_EPOCHS))
}

/// The intended relation: KES enforcement is inert, or
///
/// * the vote slot-epoch binding is armed no later than enforcement,
/// * the first-key floor is armed no later than enforcement, and
/// * the registration epoch binding is armed no later than
///   [`kes_register_binding_deadline`].
pub const fn kes_follow_up_gates_cover_enforcement(
    enforcement: u64,
    slot_epoch_binding: u64,
    first_key_floor: u64,
    register_epoch_binding: u64,
) -> bool {
    !armed(enforcement)
        || (requires_no_later(slot_epoch_binding, enforcement)
            && requires_no_later(first_key_floor, enforcement)
            && armed(register_epoch_binding)
            && register_epoch_binding <= kes_register_binding_deadline(enforcement))
}

/// `true` while this line knowingly ships KES enforcement armed with at
/// least one follow-up gate not covering it (see the block comment above).
///
/// OWNER: when the release arms the three gates so that
/// [`kes_follow_up_gates_cover_enforcement`] holds, set this to `false` in
/// the same commit. That is the only edit; the test and the const assertion
/// do the rest.
pub const KES_FOLLOW_UP_GATES_PENDING: bool = true;

#[cfg(not(feature = "mldsa-pin-replay-qualification"))]
const _: () = assert!(
    KES_FOLLOW_UP_GATES_PENDING
        || kes_follow_up_gates_cover_enforcement(
            params::HF3_KES_ENFORCE_EPOCH,
            params::ATTESTATION_SLOT_EPOCH_BINDING_ACTIVATION_EPOCH,
            params::KES_FIRST_KEY_FLOOR_ACTIVATION_EPOCH,
            params::KES_REGISTER_EPOCH_BINDING_EPOCH,
        ),
    "KES enforcement is armed without the slot-epoch binding, the first-key floor or the registration binding covering it"
);

/// One KES follow-up rule that is not in force when the defect it repairs
/// becomes reachable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KesFollowUpExposure {
    /// The gate that does not cover enforcement.
    pub gate: &'static str,
    /// Its value (`u64::MAX`: inert).
    pub gate_epoch: u64,
    /// First epoch at which the exposure can exist.
    pub open_from_epoch: u64,
    /// What is exposed, for the operator.
    pub exposure: &'static str,
}

impl core::fmt::Display for KesFollowUpExposure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} is ", self.gate)?;
        if armed(self.gate_epoch) {
            write!(f, "armed at epoch {}, too late", self.gate_epoch)?;
        } else {
            write!(f, "NOT ARMED")?;
        }
        write!(f, ": open from epoch {} on: {}", self.open_from_epoch, self.exposure)
    }
}

/// The follow-up rules that do not cover `enforcement`, in gate order. Empty
/// exactly when [`kes_follow_up_gates_cover_enforcement`] holds.
pub fn kes_follow_up_exposures(
    enforcement: u64,
    slot_epoch_binding: u64,
    first_key_floor: u64,
    register_epoch_binding: u64,
) -> Vec<KesFollowUpExposure> {
    let mut out = Vec::new();
    if !armed(enforcement) {
        return out;
    }
    if !requires_no_later(slot_epoch_binding, enforcement) {
        out.push(KesFollowUpExposure {
            gate: "params::ATTESTATION_SLOT_EPOCH_BINDING_ACTIVATION_EPOCH",
            gate_epoch: slot_epoch_binding,
            open_from_epoch: enforcement,
            exposure: "once KES binds, a vote with a current slot and another target epoch is judged under                        different keys by gossip and by block validation (FC-3/CR-1): it stays block-valid under a                        retired static key, and equivocation evidence for it cannot be proven",
        });
    }
    if !requires_no_later(first_key_floor, enforcement) {
        out.push(KesFollowUpExposure {
            gate: "params::KES_FIRST_KEY_FLOOR_ACTIVATION_EPOCH",
            gate_epoch: first_key_floor,
            open_from_epoch: enforcement,
            exposure: "a validator that registers its first KES key after the bind cannot sign for the rest of                        that period, and what it signed with its static key before registering cannot be proven                        as evidence (CR-2)",
        });
    }
    let deadline = kes_register_binding_deadline(enforcement);
    if !armed(register_epoch_binding) || register_epoch_binding > deadline {
        out.push(KesFollowUpExposure {
            gate: "params::KES_REGISTER_EPOCH_BINDING_EPOCH",
            gate_epoch: register_epoch_binding,
            open_from_epoch: deadline,
            exposure: "every KES registration signed before this gate never expires and can be re-broadcast by                        anyone once its tree leaves the retired-key history, restoring a retired key (CR-5); the                        later the gate, the more such signatures exist",
        });
    }
    out
}

/// [`kes_follow_up_exposures`] for the constants this binary was built with.
/// The node prints each entry at boot.
pub fn shipped_kes_follow_up_exposures() -> Vec<KesFollowUpExposure> {
    kes_follow_up_exposures(
        params::HF3_KES_ENFORCE_EPOCH,
        params::ATTESTATION_SLOT_EPOCH_BINDING_ACTIVATION_EPOCH,
        params::KES_FIRST_KEY_FLOOR_ACTIVATION_EPOCH,
        params::KES_REGISTER_EPOCH_BINDING_EPOCH,
    )
}

// ── Gates that canonical history was not produced under (GATE-03) ──────────

/// A gate that has never been in force on the canonical chain, with the
/// value this binary was built with.
pub type UnarmedGate = (&'static str, u64);

macro_rules! unarmed {
    ($path:path) => {
        (stringify!($path), $path)
    };
}

/// Every consensus gate that was inert when the canonical chain produced its
/// history so far: blocks already on the chain were never checked against
/// the rule behind it, and may contain what it forbids.
///
/// Arming one of them at an epoch the chain has already passed does not
/// affect running nodes, but every restart and every deep reorg replays the
/// durable log under the compiled constants and then fails on the first old
/// block the new rule refuses. A gate on this list must therefore be armed
/// at a FUTURE epoch only, with the usual flag-day margin.
///
/// Two checks read the list:
///
/// * a build with a release-baked weak-subjectivity checkpoint refuses to
///   start when a listed gate is armed at or below the checkpoint's epoch
///   (`ws_boot::compiled_release_anchor`; a unit test checks the same against
///   the anchor file in every build). The anchor is finalized history, so
///   this is a certain error; it is a lower bound, not the chain head, so an
///   epoch above the anchor can still be in the past;
/// * when boot replay fails, the node names the listed gates armed at or
///   below the failing block's epoch.
///
/// Maintenance: a gate stays here after it is armed. Remove it only when the
/// release anchor is re-baked at an epoch above the gate, at which point the
/// rule is part of the anchored history.
/// `every_inert_gate_in_params_is_listed_as_unarmed` keeps the list complete.
pub const GATES_UNARMED_IN_CANONICAL_HISTORY: &[UnarmedGate] = &[
    unarmed!(params::ANCESTRY_SEED_ACTIVATION_EPOCH),
    unarmed!(params::DEPOSIT_ACTIVATION_EPOCH),
    unarmed!(params::FEE_STAKE_DECOUPLE_ACTIVATION_EPOCH),
    unarmed!(params::SLASHING_ECONOMICS_V2_ACTIVATION_EPOCH),
    unarmed!(params::DUST_RULE_ACTIVATION_EPOCH),
    unarmed!(params::TX_BYTES_BOUND_ACTIVATION_EPOCH),
    unarmed!(params::ATTESTATION_DEDUP_ACTIVATION_EPOCH),
    unarmed!(params::ATTESTATION_SLOT_EPOCH_BINDING_ACTIVATION_EPOCH),
    unarmed!(params::REWARDS_V2_ACTIVATION_EPOCH),
    unarmed!(params::FORKCHOICE_EQUIVOCATION_HORIZON_ACTIVATION_EPOCH),
    unarmed!(params::FORKCHOICE_SLOT_TIEBREAK_ACTIVATION_EPOCH),
    unarmed!(params::STAKING_TX_METERING_ACTIVATION_EPOCH),
    unarmed!(params::SIGHASH_NETWORK_BINDING_ACTIVATION_EPOCH),
    unarmed!(params::VALIDATOR_NETWORK_BINDING_ACTIVATION_EPOCH),
    unarmed!(params::FUNDED_DELEGATION_BOUND_ACTIVATION_EPOCH),
    unarmed!(params::FUNDED_VALIDATOR_CANCELLATION_ACTIVATION_EPOCH),
    unarmed!(params::ACTIVATION_QUEUE_V2_ACTIVATION_EPOCH),
    unarmed!(params::LATTICE_EMERGENCY_ACTIVATION_EPOCH),
    unarmed!(params::DUTY_ROSTER_RECOVERY_ACTIVATION_EPOCH),
    unarmed!(params::KES_FIRST_KEY_FLOOR_ACTIVATION_EPOCH),
    unarmed!(params::KES_REGISTER_EPOCH_BINDING_EPOCH),
    unarmed!(params::COMMISSION_UPDATE_LIMIT_ACTIVATION_EPOCH),
    unarmed!(params::L2_RELEASE_EXEMPTION_ACTIVATION_EPOCH),
];

/// The gates of `gates` armed at or below `epoch`, in list order.
pub fn gates_armed_at_or_below(gates: &[UnarmedGate], epoch: u64) -> Vec<UnarmedGate> {
    gates.iter().copied().filter(|(_, gate)| armed(*gate) && *gate <= epoch).collect()
}

/// `Err` naming every gate of [`GATES_UNARMED_IN_CANONICAL_HISTORY`] that
/// this binary arms at or below `anchor_epoch`, an epoch of finalized
/// canonical history (the release-baked weak-subjectivity checkpoint).
pub fn check_gates_above_anchored_history(gates: &[UnarmedGate], anchor_epoch: u64) -> Result<(), String> {
    let bad = gates_armed_at_or_below(gates, anchor_epoch);
    if bad.is_empty() {
        return Ok(());
    }
    let list: Vec<String> = bad.iter().map(|(name, epoch)| format!("{name} = {epoch}")).collect();
    Err(format!(
        "this build arms {} at or below epoch {anchor_epoch}, the finalized checkpoint it was released with.          That rule was not in force when those blocks were produced, so replaying canonical history would fail.          Arm the gate at a future epoch",
        list.join(", ")
    ))
}

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

    /// GATE-02. Today the relation does NOT hold and the flag says so; the
    /// release that arms the gates flips `KES_FOLLOW_UP_GATES_PENDING` and
    /// nothing else here.
    #[test]
    fn the_kes_follow_up_flag_matches_the_shipped_gates() {
        let covered = kes_follow_up_gates_cover_enforcement(
            params::HF3_KES_ENFORCE_EPOCH,
            params::ATTESTATION_SLOT_EPOCH_BINDING_ACTIVATION_EPOCH,
            params::KES_FIRST_KEY_FLOOR_ACTIVATION_EPOCH,
            params::KES_REGISTER_EPOCH_BINDING_EPOCH,
        );
        assert_eq!(
            covered, !KES_FOLLOW_UP_GATES_PENDING,
            "KES_FOLLOW_UP_GATES_PENDING is stale: the shipped gates {} cover KES enforcement.              Set the flag to {} in hard_forks.rs",
            if covered { "now" } else { "do not" },
            !covered,
        );
        // The boot warning is exactly the open part of the relation.
        assert_eq!(shipped_kes_follow_up_exposures().is_empty(), covered);
    }

    #[test]
    fn the_kes_follow_up_relation() {
        let deadline = kes_register_binding_deadline(8_620);
        assert_eq!(deadline, 8_620 + 365 * 90);
        // Enforcement inert: nothing to cover.
        assert!(kes_follow_up_gates_cover_enforcement(M, M, M, M));
        assert!(kes_follow_up_exposures(M, M, M, M).is_empty());
        // All three armed in time.
        assert!(kes_follow_up_gates_cover_enforcement(8_620, 8_620, 8_620, 8_620));
        assert!(kes_follow_up_gates_cover_enforcement(8_620, 8_500, 8_400, deadline));
        assert!(kes_follow_up_exposures(8_620, 8_500, 8_400, deadline).is_empty());
        // The shipped combination of 2026-11-10: every gate is reported.
        assert!(!kes_follow_up_gates_cover_enforcement(8_620, M, M, M));
        let open = kes_follow_up_exposures(8_620, M, M, M);
        assert_eq!(
            open.iter().map(|e| (e.gate, e.open_from_epoch)).collect::<Vec<_>>(),
            [
                ("params::ATTESTATION_SLOT_EPOCH_BINDING_ACTIVATION_EPOCH", 8_620),
                ("params::KES_FIRST_KEY_FLOOR_ACTIVATION_EPOCH", 8_620),
                ("params::KES_REGISTER_EPOCH_BINDING_EPOCH", deadline),
            ]
        );
        let text = open[0].to_string();
        assert!(text.contains("NOT ARMED") && text.contains("8620"), "{text}");
        // Each gate alone, inert or late.
        for (binding, floor, register, gate) in [
            (M, 8_620, 8_620, "params::ATTESTATION_SLOT_EPOCH_BINDING_ACTIVATION_EPOCH"),
            (8_621, 8_620, 8_620, "params::ATTESTATION_SLOT_EPOCH_BINDING_ACTIVATION_EPOCH"),
            (8_620, M, 8_620, "params::KES_FIRST_KEY_FLOOR_ACTIVATION_EPOCH"),
            (8_620, 8_621, 8_620, "params::KES_FIRST_KEY_FLOOR_ACTIVATION_EPOCH"),
            (8_620, 8_620, M, "params::KES_REGISTER_EPOCH_BINDING_EPOCH"),
            (8_620, 8_620, deadline + 1, "params::KES_REGISTER_EPOCH_BINDING_EPOCH"),
        ] {
            assert!(!kes_follow_up_gates_cover_enforcement(8_620, binding, floor, register), "{gate}");
            let open = kes_follow_up_exposures(8_620, binding, floor, register);
            assert_eq!(open.iter().map(|e| e.gate).collect::<Vec<_>>(), [gate]);
        }
        assert!(kes_follow_up_exposures(8_620, 8_621, 8_620, 8_620)[0].to_string().contains("too late"));
    }

    /// GATE-03: a gate that history was not produced under may not be armed
    /// at or below an epoch of that history.
    #[test]
    fn a_gate_armed_into_anchored_history_is_refused() {
        let gates: &[UnarmedGate] = &[("params::A_EPOCH", M), ("params::B_EPOCH", 7_360), ("params::C_EPOCH", 7_307)];
        assert!(check_gates_above_anchored_history(gates, 7_306).is_ok());
        assert_eq!(gates_armed_at_or_below(gates, 7_307), [("params::C_EPOCH", 7_307)]);
        let err = check_gates_above_anchored_history(gates, 7_400).unwrap_err();
        assert!(err.contains("params::B_EPOCH = 7360") && err.contains("params::C_EPOCH = 7307"), "{err}");
        assert!(err.contains("epoch 7400") && !err.contains("A_EPOCH"), "{err}");
        // Inert gates never trip, whatever the anchor.
        assert!(check_gates_above_anchored_history(&[("params::A_EPOCH", M)], M).is_ok());
        // As shipped, nothing on the list is armed at all.
        assert!(gates_armed_at_or_below(GATES_UNARMED_IN_CANONICAL_HISTORY, M - 1).is_empty());
    }

    /// The list is complete: every `*_EPOCH` gate that `params.rs` ships at
    /// `u64::MAX` is on it, and nothing is listed twice.
    #[test]
    fn every_inert_gate_in_params_is_listed_as_unarmed() {
        let src = include_str!("params.rs");
        for line in src.lines() {
            let Some(rest) = line.strip_prefix("pub const ") else { continue };
            let name: String =
                rest.chars().take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '_').collect();
            if name.ends_with("_EPOCH") && rest[name.len()..].trim() == ": u64 = u64::MAX;" {
                let full = format!("params::{name}");
                assert!(
                    GATES_UNARMED_IN_CANONICAL_HISTORY.iter().any(|(n, _)| *n == full),
                    "{full} is inert but missing from GATES_UNARMED_IN_CANONICAL_HISTORY"
                );
            }
        }
        for (i, (a, _)) in GATES_UNARMED_IN_CANONICAL_HISTORY.iter().enumerate() {
            for (b, _) in &GATES_UNARMED_IN_CANONICAL_HISTORY[i + 1..] {
                assert_ne!(a, b);
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
