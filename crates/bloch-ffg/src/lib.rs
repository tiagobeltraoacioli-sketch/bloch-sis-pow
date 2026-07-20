//! # bloch-ffg — static FFG committee + committee-governed activation (FOUNDATION)
//!
//! Implements the **static finality committee** designed in the study (§4-bis) and
//! the mechanism that makes it the **activation authority** for consensus upgrades
//! such as the native eUTXO VM (§5-quater step 6): a feature turns on only when a
//! **14-of-21** committee quorum has signed "activate `<feature>` at height H".
//!
//! Model (per the locked decision, §4-bis):
//! - **Static:** a fixed set of **21 named seats**, no rotation. Seats are
//!   **non-transferable** — they change only via [`fill_vacancy`].
//! - **Quorum:** **14-of-21** post-quantum signatures finalize a checkpoint or an
//!   activation. Signatures are per-seat and a seat cannot be double-counted.
//! - **Replacement only on exit:** a member who resigns / is long-offline / is
//!   removed for fault opens a [`Vacancy`]; it is filled from a pre-vetted candidate
//!   with a 14-of-remaining supermajority. If more than [`MAX_VACANCY`] seats are
//!   vacant, finality **pauses** (the base PoW keeps running regardless).
//!
//! > **Status: FOUNDATION. NOT wired into consensus.** Standalone + tests only.
//! > Signature verification is a host callback ([`SigVerifier`]) so the real
//! > ML-DSA-65‖Falcon-1024 verifier plugs in later. Unaudited.

#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};

/// Fixed committee size (§4-bis).
pub const COMMITTEE_SIZE: usize = 21;
/// Finality / activation quorum: 14-of-21.
pub const QUORUM: usize = 14;
/// Max simultaneous vacancies before finality pauses (§4-bis: >3 → pause).
pub const MAX_VACANCY: usize = 3;

/// A committee seat: a post-quantum public key, and whether it is currently filled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seat {
    pub pubkey: Vec<u8>,
    pub active: bool,
}

/// The static committee — exactly [`COMMITTEE_SIZE`] seats.
#[derive(Clone, Debug)]
pub struct Committee {
    pub seats: Vec<Seat>,
}

impl Committee {
    /// Seat a fresh committee from 21 pubkeys.
    pub fn new(pubkeys: Vec<Vec<u8>>) -> Result<Self, FfgError> {
        if pubkeys.len() != COMMITTEE_SIZE {
            return Err(FfgError::WrongSize(pubkeys.len()));
        }
        Ok(Committee {
            seats: pubkeys.into_iter().map(|pk| Seat { pubkey: pk, active: true }).collect(),
        })
    }
    pub fn active_count(&self) -> usize {
        self.seats.iter().filter(|s| s.active).count()
    }
    /// Finality is available only while no more than `MAX_VACANCY` seats are vacant.
    pub fn finality_available(&self) -> bool {
        self.active_count() >= COMMITTEE_SIZE - MAX_VACANCY
    }
}

/// Host-provided PQ signature verification (kept outside so this stays testable).
pub trait SigVerifier {
    fn verify(&self, msg: &[u8], pubkey: &[u8], sig: &[u8]) -> bool;
}

/// A signature attributed to a specific seat.
#[derive(Clone, Debug)]
pub struct SeatSig {
    pub seat: u8,
    pub sig: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FfgError {
    WrongSize(usize),
    NoQuorum { got: usize, need: usize },
    FinalityPaused,
    SeatOutOfRange(u8),
    SeatNotVacant(u8),
}

/// Count **distinct active seats** whose signature over `msg` verifies. A seat that
/// signs twice is counted once; inactive / out-of-range seats never count.
pub fn count_signers(c: &Committee, msg: &[u8], sigs: &[SeatSig], v: &dyn SigVerifier) -> usize {
    let mut seen = [false; COMMITTEE_SIZE];
    let mut n = 0;
    for s in sigs {
        let i = s.seat as usize;
        if i >= c.seats.len() || seen[i] {
            continue;
        }
        let seat = &c.seats[i];
        if seat.active && v.verify(msg, &seat.pubkey, &s.sig) {
            seen[i] = true;
            n += 1;
        }
    }
    n
}

/// True iff a 14-of-21 quorum signed `msg` AND finality is not paused.
pub fn has_quorum(c: &Committee, msg: &[u8], sigs: &[SeatSig], v: &dyn SigVerifier) -> bool {
    c.finality_available() && count_signers(c, msg, sigs, v) >= QUORUM
}

// ── Committee-governed feature activation (the point of "ativação com o comitê") ──

/// A consensus feature the committee can switch on at a coordinated height.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeatureActivation {
    pub feature: String,
    pub activation_height: u64,
}

/// The canonical, deterministic message the committee signs to activate a feature.
pub fn activation_message(a: &FeatureActivation) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(b"BLOCH-FFG-ACTIVATE-v1");
    h.update((a.feature.len() as u32).to_le_bytes());
    h.update(a.feature.as_bytes());
    h.update(a.activation_height.to_le_bytes());
    h.finalize().to_vec()
}

/// A feature is active at `current_height` iff the height is reached AND a committee
/// quorum authorized this exact (feature, height). This makes the **committee the
/// activation authority** — an upgrade cannot switch on without 14-of-21.
pub fn is_feature_active(
    c: &Committee,
    a: &FeatureActivation,
    sigs: &[SeatSig],
    v: &dyn SigVerifier,
    current_height: u64,
) -> bool {
    current_height >= a.activation_height && has_quorum(c, &activation_message(a), sigs, v)
}

// ── Checkpoint finality (finality-as-a-service, §4-bis / §5-ter de-risking) ──

/// A block the committee finalizes; below a finalized checkpoint, no reorg is valid.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub height: u64,
    pub block_hash: [u8; 32],
}

pub fn checkpoint_message(cp: &Checkpoint) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(b"BLOCH-FFG-FINAL-v1");
    h.update(cp.height.to_le_bytes());
    h.update(cp.block_hash);
    h.finalize().to_vec()
}

/// A checkpoint is finalized once a quorum signs it.
pub fn is_finalized(c: &Committee, cp: &Checkpoint, sigs: &[SeatSig], v: &dyn SigVerifier) -> bool {
    has_quorum(c, &checkpoint_message(cp), sigs, v)
}

// ── Replacement — only when a member leaves (§4-bis) ──

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExitReason {
    Resigned,
    ProlongedDowntime,
    RemovedForFault,
}

/// Open a vacancy: the seat goes inactive. (Removal-for-fault would also slash the
/// member's stake — out of scope for this foundation.)
pub fn open_vacancy(c: &mut Committee, seat: u8, _reason: ExitReason) -> Result<(), FfgError> {
    let i = seat as usize;
    let s = c.seats.get_mut(i).ok_or(FfgError::SeatOutOfRange(seat))?;
    s.active = false;
    Ok(())
}

/// The canonical message the remaining committee signs to approve a replacement:
/// "seat S → this pre-vetted candidate pubkey". Non-transferable: a seat changes key
/// only through this quorum-approved path.
pub fn replacement_message(seat: u8, candidate_pubkey: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(b"BLOCH-FFG-REPLACE-v1");
    h.update([seat]);
    h.update((candidate_pubkey.len() as u32).to_le_bytes());
    h.update(candidate_pubkey);
    h.finalize().to_vec()
}

/// Fill a vacant seat from a pre-vetted candidate, requiring a 14-of-remaining
/// supermajority approval. The seat must currently be vacant (deterministic
/// waitlist promotion happens off this call; here we bind the approved candidate).
pub fn fill_vacancy(
    c: &mut Committee,
    seat: u8,
    candidate_pubkey: Vec<u8>,
    approvals: &[SeatSig],
    v: &dyn SigVerifier,
) -> Result<(), FfgError> {
    let i = seat as usize;
    {
        let s = c.seats.get(i).ok_or(FfgError::SeatOutOfRange(seat))?;
        if s.active {
            return Err(FfgError::SeatNotVacant(seat));
        }
    }
    let msg = replacement_message(seat, &candidate_pubkey);
    let signers = count_signers(c, &msg, approvals, v);
    if signers < QUORUM {
        return Err(FfgError::NoQuorum { got: signers, need: QUORUM });
    }
    c.seats[i] = Seat { pubkey: candidate_pubkey, active: true };
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    /// Accepts a (msg, pk, sig) iff sig == b"SIG:" ‖ pk over that msg — a deterministic
    /// stand-in for the real PQ verifier (each seat's "signature" is derived from its key).
    struct MockVerifier;
    impl SigVerifier for MockVerifier {
        fn verify(&self, _msg: &[u8], pubkey: &[u8], sig: &[u8]) -> bool {
            let mut expect = b"SIG:".to_vec();
            expect.extend_from_slice(pubkey);
            sig == expect.as_slice()
        }
    }
    fn pk(i: usize) -> Vec<u8> {
        format!("seat-{i}").into_bytes()
    }
    fn good_sig(i: usize) -> Vec<u8> {
        let mut s = b"SIG:".to_vec();
        s.extend_from_slice(&pk(i));
        s
    }
    fn fresh_committee() -> Committee {
        Committee::new((0..COMMITTEE_SIZE).map(pk).collect()).unwrap()
    }
    /// signatures from seats `range`.
    fn sigs_from(seats: impl IntoIterator<Item = usize>) -> Vec<SeatSig> {
        seats.into_iter().map(|i| SeatSig { seat: i as u8, sig: good_sig(i) }).collect()
    }

    #[test]
    fn committee_construction() {
        assert!(Committee::new(vec![pk(0)]).is_err()); // wrong size
        let c = fresh_committee();
        assert_eq!(c.seats.len(), 21);
        assert_eq!(c.active_count(), 21);
        assert!(c.finality_available());
    }

    #[test]
    fn quorum_14_of_21() {
        let c = fresh_committee();
        let v = MockVerifier;
        let cp = Checkpoint { height: 500, block_hash: [7u8; 32] };
        let msg = checkpoint_message(&cp);

        // 14 distinct signers → finalized
        assert!(is_finalized(&c, &cp, &sigs_from(0..14), &v));
        // 13 → not
        assert!(!is_finalized(&c, &cp, &sigs_from(0..13), &v));
        // exactly 14 required, extra is fine
        assert!(is_finalized(&c, &cp, &sigs_from(0..21), &v));
    }

    #[test]
    fn a_seat_cannot_double_sign() {
        let c = fresh_committee();
        let v = MockVerifier;
        let msg = b"m".to_vec();
        // 13 distinct seats, but seat 0 appears 3 times → still only 13 counted
        let mut sigs = sigs_from(0..13);
        sigs.push(SeatSig { seat: 0, sig: good_sig(0) });
        sigs.push(SeatSig { seat: 0, sig: good_sig(0) });
        assert_eq!(count_signers(&c, &msg, &sigs, &v), 13);
    }

    #[test]
    fn forged_and_inactive_sigs_do_not_count() {
        let mut c = fresh_committee();
        let v = MockVerifier;
        let msg = b"m".to_vec();
        // seat 5 supplies a wrong signature; seat 6 is vacant
        open_vacancy(&mut c, 6, ExitReason::Resigned).unwrap();
        let mut sigs = sigs_from(0..14); // 0..13 valid... but 6 is vacant now
        sigs[5] = SeatSig { seat: 5, sig: b"forged".to_vec() };
        // seats 0..14 minus seat5(forged) minus seat6(vacant) = 12 valid
        assert_eq!(count_signers(&c, &msg, &sigs, &v), 12);
    }

    #[test]
    fn committee_governed_feature_activation() {
        let c = fresh_committee();
        let v = MockVerifier;
        let act = FeatureActivation { feature: "euvm".into(), activation_height: 1000 };
        let sigs = sigs_from(0..14);
        let msg = activation_message(&act);
        let ok_sigs: Vec<SeatSig> = (0..14).map(|i| SeatSig { seat: i as u8, sig: good_sig(i) }).collect();
        let _ = (msg, sigs);

        // before the height → not active even with quorum
        assert!(!is_feature_active(&c, &act, &ok_sigs, &v, 999));
        // at/after the height WITH quorum → active
        assert!(is_feature_active(&c, &act, &ok_sigs, &v, 1000));
        assert!(is_feature_active(&c, &act, &ok_sigs, &v, 5000));
        // at the height WITHOUT quorum (13 sigs) → NOT active (committee is the authority)
        let short: Vec<SeatSig> = (0..13).map(|i| SeatSig { seat: i as u8, sig: good_sig(i) }).collect();
        assert!(!is_feature_active(&c, &act, &short, &v, 2000));
    }

    #[test]
    fn vacancies_pause_finality() {
        let mut c = fresh_committee();
        let v = MockVerifier;
        let cp = Checkpoint { height: 1, block_hash: [0u8; 32] };
        // open 3 vacancies (active 18) → still available
        for s in [0u8, 1, 2] {
            open_vacancy(&mut c, s, ExitReason::ProlongedDowntime).unwrap();
        }
        assert!(c.finality_available());
        // a 4th vacancy (active 17) → finality pauses; no quorum possible
        open_vacancy(&mut c, 3, ExitReason::ProlongedDowntime).unwrap();
        assert!(!c.finality_available());
        assert!(!is_finalized(&c, &cp, &sigs_from(4..21), &v)); // even 17 signers can't finalize while paused
    }

    #[test]
    fn replacement_only_via_quorum() {
        let mut c = fresh_committee();
        let v = MockVerifier;
        // seat 10 leaves
        open_vacancy(&mut c, 10, ExitReason::RemovedForFault).unwrap();
        assert_eq!(c.active_count(), 20);

        let candidate = b"new-member-key".to_vec();
        // approvals come from ACTIVE seats only (seat 10 is vacant and cannot approve).
        let active_seats: Vec<usize> = (0..COMMITTEE_SIZE).filter(|&i| i != 10).collect();
        let approve14: Vec<SeatSig> = active_seats.iter().take(14).map(|&i| SeatSig { seat: i as u8, sig: good_sig(i) }).collect();
        let approve13: Vec<SeatSig> = active_seats.iter().take(13).map(|&i| SeatSig { seat: i as u8, sig: good_sig(i) }).collect();
        assert!(fill_vacancy(&mut c, 10, candidate.clone(), &approve13, &v).is_err());
        // 14 approvals → seat filled with the new key, active again
        assert!(fill_vacancy(&mut c, 10, candidate.clone(), &approve14, &v).is_ok());
        assert_eq!(c.active_count(), 21);
        assert_eq!(c.seats[10].pubkey, candidate);
        assert!(c.seats[10].active);

        // cannot "fill" an already-active seat (non-transferable except through vacancy)
        assert_eq!(
            fill_vacancy(&mut c, 10, b"hostile".to_vec(), &approve14, &v),
            Err(FfgError::SeatNotVacant(10))
        );
    }
}
