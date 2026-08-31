//! Consensus vesting locks: the schedule as outputs, not as prose.
//!
//! # Why this module exists
//!
//! Genesis-4's manifest carries an `unlock_epoch` per allocation, and until
//! 2026-08-31 that field did exactly one thing: it perturbed the allocation's
//! txid. It never reached committed state — `EutxoEntry` had no lock field,
//! `apply_transfer` had no epoch gate — while three published documents said
//! the opposite ("an output is unspendable until the chain reaches that
//! epoch, so the schedule is enforced by every node"). The tokenomics_v4
//! vesting curves (`founder_vested_sat` and family) had zero callers outside
//! their own tests. A schedule in a spreadsheet is not a schedule; neither is
//! one in a doc comment.
//!
//! This module is the missing middle: it turns the curves into a
//! deterministic set of **tranche outputs**, each carrying the
//! `unlock_epoch` that [`crate::state_root::EutxoEntry`] now commits and the
//! transfer arms now enforce (`TransferReject::VestingLocked`).
//!
//! # The two ways a lock comes to exist
//!
//! 1. **A genesis manifest** whose allocations carry nonzero `unlock_epoch`s
//!    — honored from block 0 on any chain launched after this lands
//!    (`Manifest::allocation_outputs` now copies the field into the entry).
//! 2. **The flag day** ([`crate::params::VESTING_LOCK_ACTIVATION_EPOCH`]):
//!    at the boundary opening that epoch, `close_epoch` replaces each SEED
//!    TARGET outpoint that is still unspent with the tranches of
//!    [`tranche_schedule`]. Value is conserved exactly — the tranches sum to
//!    the allocation, asserted here and pinned by test.
//!
//! # What seeding cannot do, stated before anyone arms it
//!
//! Seeding locks an outpoint, not a balance. If an allocation outpoint has
//! been spent before the flag day, its coins sit under fresh txids the seed
//! table does not name, and the boundary walks past it — silently, by
//! design, because inventing a claim on someone's post-spend outputs would
//! be confiscation, not vesting. Measured 2026-08-31 (three fleet nodes,
//! epoch 1,599): **all five live-chain allocation outpoints are already
//! spent**, so on the current chain this mechanism, armed today, locks
//! nothing. It is shipped inert anyway, because the truthful version of the
//! published claim ("the schedule is enforced by every node") requires the
//! machinery to exist before the claim can ever be made again — for a future
//! genesis, or for buckets returned to pinned outpoints first.

use sha3::{Digest, Sha3_256};

use crate::params::SLOTS_PER_EPOCH;
use crate::tokenomics_v4 as t;

/// Domain tag for a genesis allocation's synthetic txid. THE single
/// definition — `bloch-pos-node`'s `Manifest::allocation_outputs` computes
/// its txids through [`genesis_alloc_txid`], and the flag-day seed table
/// derives the outpoints it targets the same way. Two copies of this
/// preimage would be two chances for them to disagree about which output is
/// which.
pub const DS_GENESIS_ALLOC: &[u8] = b"BLCH4:genesis-alloc\0";

/// Domain tag for a seeded vesting tranche's synthetic txid. Distinct from
/// [`DS_GENESIS_ALLOC`] so a tranche can never collide with the allocation
/// it replaced, and from every transaction txid (those are §5.4 digests over
/// transaction bytes, a different domain entirely).
pub const DS_VESTING_TRANCHE: &[u8] = b"BLCH4:vesting-tranche\0";

/// The synthetic txid of a genesis allocation output.
///
/// Deterministic from the allocation's own fields, so reordering a
/// manifest's allocation list cannot silently change which output is which.
pub fn genesis_alloc_txid(
    purpose: u8,
    script_hash: &[u8; 32],
    amount_sat: u128,
    unlock_epoch: u64,
) -> [u8; 32] {
    let mut h = Sha3_256::new();
    Digest::update(&mut h, DS_GENESIS_ALLOC);
    Digest::update(&mut h, [purpose]);
    Digest::update(&mut h, script_hash);
    Digest::update(&mut h, amount_sat.to_le_bytes());
    Digest::update(&mut h, unlock_epoch.to_le_bytes());
    h.finalize().into()
}

/// The synthetic txid of one seeded tranche.
///
/// Committed over everything that defines the tranche — bucket, position,
/// owner, value, unlock — so no two tranches, of this bucket or any other,
/// can land on one outpoint without a SHA3-256 collision.
pub fn tranche_txid(
    purpose: u8,
    index: u32,
    script_hash: &[u8; 32],
    value_sat: u64,
    unlock_epoch: u64,
) -> [u8; 32] {
    let mut h = Sha3_256::new();
    Digest::update(&mut h, DS_VESTING_TRANCHE);
    Digest::update(&mut h, [purpose]);
    Digest::update(&mut h, index.to_le_bytes());
    Digest::update(&mut h, script_hash);
    Digest::update(&mut h, value_sat.to_le_bytes());
    Digest::update(&mut h, unlock_epoch.to_le_bytes());
    h.finalize().into()
}

/// One slice of a bucket: this much value, spendable from this epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tranche {
    pub value_sat: u64,
    /// First epoch the slice may be spent; `0` means liquid immediately.
    pub unlock_epoch: u64,
}

/// The epoch in which a curve slot's value is actually spendable.
///
/// Rounded UP: the transfer gate compares against the block's epoch, and a
/// slot interior to an epoch must not unlock before the curve says it has
/// vested. The lock may therefore bind up to one epoch (16 minutes) longer
/// than the per-slot curve — always the conservative direction.
fn unlock_epoch_for_slot(slot: u64) -> u64 {
    slot.div_ceil(SLOTS_PER_EPOCH)
}

/// Monthly tranches under a vesting curve `v` (cumulative sat by slot),
/// covering months `1..=months` on the grid `cliff + k * MONTH_SLOTS`.
///
/// Month k's tranche carries what vested DURING month k — `v(k) − v(k−1)` on
/// the grid — and unlocks at the END of that month. Between grid points the
/// outputs lag the per-slot curve by construction: an output is one
/// indivisible value, so any output representation of a continuous curve is
/// a step function, and the steps are chosen to sit on or after the curve,
/// never before. The final month closes the telescope at `v(cliff +
/// months·MONTH)`, which the curves guarantee equals the bucket total.
fn monthly_tranches(v: impl Fn(u64) -> u128, cliff: u64, months: u64, out: &mut Vec<Tranche>) {
    let mut prev = v(cliff);
    for k in 1..=months {
        let s = cliff + k * t::MONTH_SLOTS;
        let now = v(s);
        let dv = now - prev;
        prev = now;
        if dv == 0 {
            continue;
        }
        out.push(Tranche {
            value_sat: u64::try_from(dv).expect("a monthly tranche exceeds u64 satoshis"),
            unlock_epoch: unlock_epoch_for_slot(s),
        });
    }
}

/// The tranche schedule for one allocation bucket, derived from the
/// tokenomics_v4 curves — their first consensus callers.
///
/// Returns `None` for a purpose with no vesting to express
/// ([`alloc_purpose::LIQUIDITY`] — liquidity is liquid by design, and
/// seeding it would churn its txid for nothing) and for unknown purposes.
/// The tranches of a `Some` sum EXACTLY to the bucket total; `close_epoch`'s
/// seeding asserts it again against the live outpoint's value, because value
/// conservation at a state rewrite is the one invariant that must not rest
/// on a single check.
pub fn tranche_schedule(purpose: u8) -> Option<Vec<Tranche>> {
    let mut out = Vec::new();
    match purpose {
        alloc_purpose::FOUNDER => {
            // 2-year cliff, 8-year linear: 96 monthly tranches.
            monthly_tranches(
                t::founder_vested_sat,
                t::FOUNDER_CLIFF_SLOTS,
                t::FOUNDER_VESTING_SLOTS / t::MONTH_SLOTS,
                &mut out,
            );
        }
        alloc_purpose::VC => {
            monthly_tranches(
                t::vc_vested_sat,
                t::VC_CLIFF_SLOTS,
                t::VC_VESTING_SLOTS / t::MONTH_SLOTS,
                &mut out,
            );
        }
        alloc_purpose::TEAM => {
            monthly_tranches(
                t::team_vested_sat,
                t::TEAM_CLIFF_SLOTS,
                t::TEAM_VESTING_SLOTS / t::MONTH_SLOTS,
                &mut out,
            );
        }
        alloc_purpose::MARKETING => {
            // 25% at TGE — liquid — then 24 monthly tranches over the rest.
            let tge = t::marketing_vested_sat(0);
            out.push(Tranche {
                value_sat: u64::try_from(tge).expect("marketing TGE exceeds u64 satoshis"),
                unlock_epoch: 0,
            });
            monthly_tranches(
                t::marketing_vested_sat,
                0,
                t::MARKETING_VESTING_SLOTS / t::MONTH_SLOTS,
                &mut out,
            );
        }
        _ => return None,
    }
    Some(out)
}

/// Purpose tags, duplicated here as a module-local mirror of
/// `bloch-pos-node`'s `genesis::alloc_purpose` — same values, pinned by test
/// there. They live in the node crate because the manifest does; the seeding
/// lives here because committed state does; the numbers must never diverge.
pub mod alloc_purpose {
    pub const FOUNDER: u8 = 0x01;
    pub const VC: u8 = 0x02;
    pub const TEAM: u8 = 0x03;
    pub const MARKETING: u8 = 0x04;
    pub const LIQUIDITY: u8 = 0x05;
}

/// One flag-day seed target: the genesis allocation outpoint to replace, as
/// it exists on the LIVE chain (whose manifest committed every bucket with
/// `unlock_epoch: 0`).
#[derive(Clone, Copy, Debug)]
pub struct SeedTarget {
    pub purpose: u8,
    /// The allocation's synthetic txid (vout is always 0).
    pub txid: [u8; 32],
    /// The value the outpoint must still hold — seeding refuses a partial
    /// or mutated match rather than guessing.
    pub value_sat: u64,
    pub script_hash: [u8; 32],
}

/// The founder script hash under the carryover's zero-extension rule.
fn founder_script() -> [u8; 32] {
    let mut s = [0u8; 32];
    s[..20].copy_from_slice(&t::FOUNDER_WITHDRAWAL_H160);
    s
}

/// The outpoints the flag day would seed, pinned to the live manifest's
/// values (all five buckets at the founder script, `unlock_epoch: 0`).
///
/// LIQUIDITY is absent on purpose: fully liquid is its function, and there
/// is no schedule to seed. An outpoint in this list that is already spent
/// when the flag day arrives is skipped — see the module docs for why that
/// is the only honest option, and the measured fact that on the current
/// chain it describes all four.
pub fn seed_targets() -> Vec<SeedTarget> {
    let script = founder_script();
    [
        (alloc_purpose::FOUNDER, t::FOUNDER_BLOCH),
        (alloc_purpose::VC, t::VC_BLOCH),
        (alloc_purpose::TEAM, t::TEAM_BLOCH),
        (alloc_purpose::MARKETING, t::MARKETING_BLOCH),
    ]
    .into_iter()
    .map(|(purpose, bloch)| {
        let amount_sat = bloch * t::SAT_PER_BLOCH;
        SeedTarget {
            purpose,
            txid: genesis_alloc_txid(purpose, &script, amount_sat, 0),
            value_sat: u64::try_from(amount_sat)
                .expect("an allocation exceeds u64 satoshis — see Manifest::check_supply"),
            script_hash: script,
        }
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn total(tranches: &[Tranche]) -> u128 {
        tranches.iter().map(|t| t.value_sat as u128).sum()
    }

    /// Every seedable bucket's tranches sum EXACTLY to the bucket — the
    /// conservation half of the flag-day rewrite.
    #[test]
    fn tranches_conserve_every_bucket() {
        for (purpose, bloch) in [
            (alloc_purpose::FOUNDER, t::FOUNDER_BLOCH),
            (alloc_purpose::VC, t::VC_BLOCH),
            (alloc_purpose::TEAM, t::TEAM_BLOCH),
            (alloc_purpose::MARKETING, t::MARKETING_BLOCH),
        ] {
            let tr = tranche_schedule(purpose).expect("seedable bucket has a schedule");
            assert_eq!(
                total(&tr),
                bloch * t::SAT_PER_BLOCH,
                "purpose {purpose:#x} tranches do not sum to the allocation"
            );
        }
    }

    /// Liquidity has no schedule, deliberately.
    #[test]
    fn liquidity_is_not_seeded() {
        assert_eq!(tranche_schedule(alloc_purpose::LIQUIDITY), None);
        assert!(seed_targets().iter().all(|s| s.purpose != alloc_purpose::LIQUIDITY));
    }

    /// The output steps never unlock BEFORE the per-slot curve: at every
    /// tranche's unlock slot boundary, the sum of tranches unlocked so far is
    /// at most what the curve has vested by the FIRST slot of that epoch's
    /// successor... conservatively: compare at the unlock epoch's first slot.
    #[test]
    fn tranches_never_beat_the_curve() {
        let curves: [(u8, fn(u64) -> u128); 4] = [
            (alloc_purpose::FOUNDER, t::founder_vested_sat),
            (alloc_purpose::VC, t::vc_vested_sat),
            (alloc_purpose::TEAM, t::team_vested_sat),
            (alloc_purpose::MARKETING, t::marketing_vested_sat),
        ];
        for (purpose, curve) in curves {
            let tr = tranche_schedule(purpose).unwrap();
            let mut unlocked: u128 = 0;
            for tranche in &tr {
                unlocked += tranche.value_sat as u128;
                // The earliest slot at which the gate lets this tranche move
                // is the first slot of `unlock_epoch`. The curve must have
                // vested at least this much by then.
                let first_spendable_slot = tranche.unlock_epoch * SLOTS_PER_EPOCH;
                assert!(
                    unlocked <= curve(first_spendable_slot),
                    "purpose {purpose:#x}: tranche unlocking at epoch {} releases {} sat \
                     but the curve has only vested {} by slot {}",
                    tranche.unlock_epoch,
                    unlocked,
                    curve(first_spendable_slot),
                    first_spendable_slot,
                );
            }
        }
    }

    /// Unlock epochs are non-decreasing within a bucket — the schedule is a
    /// stream, not a shuffle.
    #[test]
    fn tranche_unlocks_are_monotone() {
        for purpose in [
            alloc_purpose::FOUNDER,
            alloc_purpose::VC,
            alloc_purpose::TEAM,
            alloc_purpose::MARKETING,
        ] {
            let tr = tranche_schedule(purpose).unwrap();
            assert!(tr.windows(2).all(|w| w[0].unlock_epoch <= w[1].unlock_epoch));
        }
    }

    /// The four seed-target txids, pinned as KATs against the LIVE manifest's
    /// allocation outpoints — the exact ids measured spent on 2026-08-31.
    /// If this test moves, the seeding is aiming at outputs that never
    /// existed.
    #[test]
    fn seed_target_txids_match_the_live_manifest() {
        let hex = |b: &[u8; 32]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let want = [
            (alloc_purpose::FOUNDER, "6740c2124e11584b71399e8722425128cd8ee8f6c6232d256e2f3775edbdb4b2"),
            (alloc_purpose::VC, "a9e9271262fc022df8b0c9bc3109d45b3d1a2beec563c69cd0d390923636f400"),
            (alloc_purpose::TEAM, "745bf3f5e54d58a090e9af911f2c1f9e4356bfd48cb672cbad0b84c4336cfc6f"),
            (alloc_purpose::MARKETING, "3a2f9bf19db53affea4443c3b0d01544ae70cebb8804e95514e557686efa9b59"),
        ];
        let targets = seed_targets();
        assert_eq!(targets.len(), want.len());
        for ((purpose, expect), target) in want.iter().zip(&targets) {
            assert_eq!(target.purpose, *purpose);
            assert_eq!(hex(&target.txid), *expect);
        }
    }

    /// Distinct tranches get distinct outpoints, within and across buckets.
    #[test]
    fn tranche_txids_do_not_collide() {
        let mut seen = std::collections::BTreeSet::new();
        let script = founder_script();
        for purpose in [
            alloc_purpose::FOUNDER,
            alloc_purpose::VC,
            alloc_purpose::TEAM,
            alloc_purpose::MARKETING,
        ] {
            for (i, tr) in tranche_schedule(purpose).unwrap().iter().enumerate() {
                let id = tranche_txid(purpose, i as u32, &script, tr.value_sat, tr.unlock_epoch);
                assert!(seen.insert(id), "tranche txid collision at purpose {purpose:#x} #{i}");
            }
        }
    }
}
