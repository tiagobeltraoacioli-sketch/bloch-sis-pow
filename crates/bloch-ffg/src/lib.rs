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
//!   removed for fault opens a vacancy; it is filled from a pre-vetted candidate
//!   with a 14-of-remaining supermajority. If more than [`MAX_VACANCY`] seats are
//!   vacant, finality **pauses** (the base PoW keeps running regardless).
//!
//! Three invariants make "14-of-21" mean what it says. Each was a real defect
//! (audit S-M4) before it was one:
//! - **Distinct keys.** The 21 seat pubkeys are pairwise distinct, enforced in
//!   [`Committee::new`] and again in [`fill_vacancy`]. Without this, one key can
//!   hold 14 seats and *be* the quorum on its own.
//! - **Bounded seats.** `seats` is private and only [`Committee::new`] builds one,
//!   so the length is always [`COMMITTEE_SIZE`]; [`count_signers`] additionally
//!   bounds the seat index it is handed.
//! - **Domain-bound messages.** Every signed message folds a [`MsgContext`]
//!   (chain-id ‖ epoch ‖ nonce) into its preimage, so an approval cannot be
//!   replayed onto another chain, another epoch, or a second time on the same
//!   seat. The context is an EXPLICIT verifier input derived from node state —
//!   never carried inside the message being checked, mirroring the sighash rule
//!   in `bloch_crypto::core` ("an attacker controls the message; they must not
//!   control the domain").
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

/// A committee seat: a post-quantum public key, whether it is currently filled,
/// and how many times it has been filled (the seat's replay nonce, see
/// [`fill_vacancy`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seat {
    pub pubkey: Vec<u8>,
    pub active: bool,
    pub replacements: u64,
}

/// The static committee — exactly [`COMMITTEE_SIZE`] seats with pairwise-distinct
/// pubkeys.
///
/// `seats` is deliberately **private**: the only way to obtain a `Committee` is
/// [`Committee::new`], so `seats.len() == COMMITTEE_SIZE` and key-distinctness hold
/// for the life of the value. When the field was public, a caller could grow the
/// vector past 21 and [`count_signers`] would index its fixed-size `seen` bitmap out
/// of bounds — a panic reachable from outside the crate.
#[derive(Clone, Debug)]
pub struct Committee {
    seats: Vec<Seat>,
}

impl Committee {
    /// Seat a fresh committee from 21 **distinct, non-empty** pubkeys.
    pub fn new(pubkeys: Vec<Vec<u8>>) -> Result<Self, FfgError> {
        if pubkeys.len() != COMMITTEE_SIZE {
            return Err(FfgError::WrongSize(pubkeys.len()));
        }
        for (i, pk) in pubkeys.iter().enumerate() {
            if pk.is_empty() {
                return Err(FfgError::EmptyPubkey(i));
            }
            if pubkeys[..i].contains(pk) {
                return Err(FfgError::DuplicatePubkey(i));
            }
        }
        Ok(Committee {
            seats: pubkeys
                .into_iter()
                .map(|pk| Seat { pubkey: pk, active: true, replacements: 0 })
                .collect(),
        })
    }
    /// Read-only view of the seats (the invariants above are why it is read-only).
    pub fn seats(&self) -> &[Seat] {
        &self.seats
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
    /// A pubkey already held by the seat at this index.
    DuplicatePubkey(usize),
    EmptyPubkey(usize),
    /// The supplied replay nonce is not the seat's current one — a replayed or
    /// premature approval.
    StaleNonce { got: u64, expected: u64 },
}

// ── Replay domain (audit S-M4) ───────────────────────────────────────────────

/// The replay domain every committee signature is bound to.
///
/// Folded into the front of each signed preimage as
/// `chain_id.to_le_bytes()(4) ‖ epoch.to_le_bytes()(8) ‖ nonce.to_le_bytes()(8)`.
/// Supplied by the **verifier** from node/committee state, never parsed out of the
/// message being verified.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MsgContext {
    /// Chain-ID registry value — the same u32 as `bloch_crypto::core::ChainId`
    /// (`to_u32()`), kept as a plain integer so this crate stays dependency-free.
    pub chain_id: u32,
    /// Committee epoch the signature is cast in.
    pub epoch: u64,
    /// Monotonic counter within (chain, epoch, message domain). For replacements
    /// this is the seat's `replacements` count and [`fill_vacancy`] checks it.
    pub nonce: u64,
}

/// Start a domain-separated hash: tag, then the replay context, then the body.
fn domain_hasher(tag: &[u8], ctx: &MsgContext) -> Sha256 {
    let mut h = Sha256::new();
    h.update(tag);
    h.update(ctx.chain_id.to_le_bytes());
    h.update(ctx.epoch.to_le_bytes());
    h.update(ctx.nonce.to_le_bytes());
    h
}

/// Count **distinct active seats** whose signature over `msg` verifies. A seat that
/// signs twice is counted once; inactive / out-of-range seats never count.
pub fn count_signers(c: &Committee, msg: &[u8], sigs: &[SeatSig], v: &dyn SigVerifier) -> usize {
    let mut seen = [false; COMMITTEE_SIZE];
    let mut n = 0;
    for s in sigs {
        let i = s.seat as usize;
        // `seat` is a u8, so bound it against BOTH the bitmap and the committee
        // before indexing either.
        if i >= COMMITTEE_SIZE || i >= c.seats.len() || seen[i] {
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

/// The canonical, deterministic message the committee signs to activate a feature,
/// bound to `ctx` (chain-id ‖ epoch ‖ nonce). The `v2` tag bumps the unbound `v1`
/// preimage that was replayable across chains and epochs.
pub fn activation_message(a: &FeatureActivation, ctx: &MsgContext) -> Vec<u8> {
    let mut h = domain_hasher(b"BLOCH-FFG-ACTIVATE-v2", ctx);
    h.update((a.feature.len() as u32).to_le_bytes());
    h.update(a.feature.as_bytes());
    h.update(a.activation_height.to_le_bytes());
    h.finalize().to_vec()
}

/// A feature is active at `current_height` iff the height is reached AND a committee
/// quorum authorized this exact (feature, height) **for this exact `ctx`**. This makes
/// the **committee the activation authority** — an upgrade cannot switch on without
/// 14-of-21, and an authorization for one chain/epoch does not carry to another.
pub fn is_feature_active(
    c: &Committee,
    a: &FeatureActivation,
    ctx: &MsgContext,
    sigs: &[SeatSig],
    v: &dyn SigVerifier,
    current_height: u64,
) -> bool {
    current_height >= a.activation_height && has_quorum(c, &activation_message(a, ctx), sigs, v)
}

// ── Checkpoint finality (finality-as-a-service, §4-bis / §5-ter de-risking) ──

/// A block the committee finalizes; below a finalized checkpoint, no reorg is valid.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub height: u64,
    pub block_hash: [u8; 32],
}

pub fn checkpoint_message(cp: &Checkpoint, ctx: &MsgContext) -> Vec<u8> {
    let mut h = domain_hasher(b"BLOCH-FFG-FINAL-v2", ctx);
    h.update(cp.height.to_le_bytes());
    h.update(cp.block_hash);
    h.finalize().to_vec()
}

/// A checkpoint is finalized once a quorum signs it for this `ctx`.
pub fn is_finalized(
    c: &Committee,
    cp: &Checkpoint,
    ctx: &MsgContext,
    sigs: &[SeatSig],
    v: &dyn SigVerifier,
) -> bool {
    has_quorum(c, &checkpoint_message(cp, ctx), sigs, v)
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
/// "seat S → this pre-vetted candidate pubkey", bound to `ctx`. Non-transferable: a
/// seat changes key only through this quorum-approved path, and `ctx.nonce` is the
/// seat's replacement count, so an approval is good for exactly one fill.
pub fn replacement_message(seat: u8, candidate_pubkey: &[u8], ctx: &MsgContext) -> Vec<u8> {
    let mut h = domain_hasher(b"BLOCH-FFG-REPLACE-v2", ctx);
    h.update([seat]);
    h.update((candidate_pubkey.len() as u32).to_le_bytes());
    h.update(candidate_pubkey);
    h.finalize().to_vec()
}

/// Fill a vacant seat from a pre-vetted candidate, requiring a 14-of-remaining
/// supermajority approval. The seat must currently be vacant (deterministic
/// waitlist promotion happens off this call; here we bind the approved candidate).
///
/// Three things are checked before the quorum, and each closes a way to get a key
/// seated without 14 honest approvals for *this* fill:
/// - the candidate key must be non-empty and **not already hold another seat**
///   (otherwise one key accumulates seats and eventually the quorum);
/// - `ctx.nonce` must equal the seat's current `replacements` count, so a set of
///   approvals cannot be replayed the next time the seat falls vacant;
/// - `ctx.chain_id` / `ctx.epoch` are inside the signed preimage, so approvals from
///   another chain or epoch simply do not verify.
pub fn fill_vacancy(
    c: &mut Committee,
    seat: u8,
    candidate_pubkey: Vec<u8>,
    ctx: &MsgContext,
    approvals: &[SeatSig],
    v: &dyn SigVerifier,
) -> Result<(), FfgError> {
    let i = seat as usize;
    let expected_nonce = {
        let s = c.seats.get(i).ok_or(FfgError::SeatOutOfRange(seat))?;
        if s.active {
            return Err(FfgError::SeatNotVacant(seat));
        }
        s.replacements
    };
    if candidate_pubkey.is_empty() {
        return Err(FfgError::EmptyPubkey(i));
    }
    // Distinctness is the invariant that makes 14-of-21 mean 14 keys. The seat
    // being filled is excluded: re-seating the departed key on its own seat keeps
    // the 21 keys pairwise distinct.
    if let Some((j, _)) = c
        .seats
        .iter()
        .enumerate()
        .find(|(j, s)| *j != i && s.pubkey == candidate_pubkey)
    {
        return Err(FfgError::DuplicatePubkey(j));
    }
    if ctx.nonce != expected_nonce {
        return Err(FfgError::StaleNonce { got: ctx.nonce, expected: expected_nonce });
    }
    let msg = replacement_message(seat, &candidate_pubkey, ctx);
    let signers = count_signers(c, &msg, approvals, v);
    if signers < QUORUM {
        return Err(FfgError::NoQuorum { got: signers, need: QUORUM });
    }
    c.seats[i] = Seat {
        pubkey: candidate_pubkey,
        active: true,
        replacements: expected_nonce + 1,
    };
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    /// Accepts a (msg, pk, sig) iff sig == b"SIG:" ‖ msg ‖ pk — a deterministic
    /// stand-in for the real PQ verifier. It binds the MESSAGE as well as the key,
    /// which is what lets the replay tests below mean anything: a signature made
    /// over one chain/epoch/nonce does not verify over another.
    struct MockVerifier;
    impl SigVerifier for MockVerifier {
        fn verify(&self, msg: &[u8], pubkey: &[u8], sig: &[u8]) -> bool {
            sig == sig_over(msg, pubkey).as_slice()
        }
    }
    fn sig_over(msg: &[u8], pubkey: &[u8]) -> Vec<u8> {
        let mut s = b"SIG:".to_vec();
        s.extend_from_slice(msg);
        s.extend_from_slice(pubkey);
        s
    }
    fn pk(i: usize) -> Vec<u8> {
        format!("seat-{i}").into_bytes()
    }
    fn good_sig(msg: &[u8], i: usize) -> Vec<u8> {
        sig_over(msg, &pk(i))
    }
    fn fresh_committee() -> Committee {
        Committee::new((0..COMMITTEE_SIZE).map(pk).collect()).unwrap()
    }
    /// signatures over `msg` from seats `seats`.
    fn sigs_from(msg: &[u8], seats: impl IntoIterator<Item = usize>) -> Vec<SeatSig> {
        seats
            .into_iter()
            .map(|i| SeatSig { seat: i as u8, sig: good_sig(msg, i) })
            .collect()
    }
    fn ctx(chain_id: u32, epoch: u64, nonce: u64) -> MsgContext {
        MsgContext { chain_id, epoch, nonce }
    }
    /// The everyday context: Genesis-3 mainnet, epoch 7, nonce 0.
    fn ctx0() -> MsgContext {
        ctx(0xB10C_0004, 7, 0)
    }

    #[test]
    fn committee_construction() {
        assert!(Committee::new(vec![pk(0)]).is_err()); // wrong size
        let c = fresh_committee();
        assert_eq!(c.seats().len(), 21);
        assert_eq!(c.active_count(), 21);
        assert!(c.finality_available());
    }

    // ── S-M4: one key must not be able to hold the quorum ──

    #[test]
    fn duplicate_pubkeys_are_rejected() {
        // The attack: 14 seats (= QUORUM) held by a single key, so its holder
        // finalizes anything alone.
        let mut keys: Vec<Vec<u8>> = (0..COMMITTEE_SIZE).map(pk).collect();
        for k in keys.iter_mut().take(QUORUM) {
            *k = b"one-key-to-rule-them".to_vec();
        }
        assert_eq!(Committee::new(keys).unwrap_err(), FfgError::DuplicatePubkey(1));

        // A single repeat is enough to be rejected...
        let mut keys: Vec<Vec<u8>> = (0..COMMITTEE_SIZE).map(pk).collect();
        keys[20] = pk(3);
        assert_eq!(Committee::new(keys).unwrap_err(), FfgError::DuplicatePubkey(20));

        // ...and an empty key is not a key.
        let mut keys: Vec<Vec<u8>> = (0..COMMITTEE_SIZE).map(pk).collect();
        keys[5] = Vec::new();
        assert_eq!(Committee::new(keys).unwrap_err(), FfgError::EmptyPubkey(5));
    }

    #[test]
    fn replacement_cannot_give_one_key_two_seats() {
        let mut c = fresh_committee();
        let v = MockVerifier;
        open_vacancy(&mut c, 10, ExitReason::Resigned).unwrap();
        let cx = ctx0();
        // Candidate key = the key already sitting in seat 3.
        let msg = replacement_message(10, &pk(3), &cx);
        let approvals = sigs_from(&msg, (0..COMMITTEE_SIZE).filter(|&i| i != 10).take(14));
        assert_eq!(
            fill_vacancy(&mut c, 10, pk(3), &cx, &approvals, &v),
            Err(FfgError::DuplicatePubkey(3))
        );
        // Even with a full quorum, and even though seat 10 is genuinely vacant.
        assert!(!c.seats()[10].active);
        assert_eq!(c.seats()[3].pubkey, pk(3));
        // Empty candidate is refused too.
        assert_eq!(
            fill_vacancy(&mut c, 10, Vec::new(), &cx, &approvals, &v),
            Err(FfgError::EmptyPubkey(10))
        );
    }

    // ── S-M4: seat indices are bounded (no OOB panic) ──

    #[test]
    fn out_of_range_seat_indices_never_panic() {
        let mut c = fresh_committee();
        let v = MockVerifier;
        let msg = b"m".to_vec();
        // u8 seat ids far past the committee are ignored, not indexed.
        let sigs = vec![
            SeatSig { seat: 21, sig: good_sig(&msg, 21) },
            SeatSig { seat: 200, sig: good_sig(&msg, 200) },
            SeatSig { seat: u8::MAX, sig: good_sig(&msg, 255) },
        ];
        assert_eq!(count_signers(&c, &msg, &sigs, &v), 0);
        assert_eq!(open_vacancy(&mut c, 21, ExitReason::Resigned), Err(FfgError::SeatOutOfRange(21)));

        // Regression for the original panic: `seen` is a fixed [bool; 21], so a
        // committee longer than 21 used to index it out of bounds. `seats` is now
        // private — only this in-crate test can even build such a value — and
        // `count_signers` bounds the index against COMMITTEE_SIZE regardless.
        c.seats.push(Seat { pubkey: pk(99), active: true, replacements: 0 });
        assert_eq!(c.seats.len(), 22);
        let over = vec![SeatSig { seat: 21, sig: good_sig(&msg, 99) }];
        assert_eq!(count_signers(&c, &msg, &over, &v), 0); // must not panic
    }

    #[test]
    fn quorum_14_of_21() {
        let c = fresh_committee();
        let v = MockVerifier;
        let cx = ctx0();
        let cp = Checkpoint { height: 500, block_hash: [7u8; 32] };
        let msg = checkpoint_message(&cp, &cx);

        // 14 distinct signers → finalized
        assert!(is_finalized(&c, &cp, &cx, &sigs_from(&msg, 0..14), &v));
        // 13 → not
        assert!(!is_finalized(&c, &cp, &cx, &sigs_from(&msg, 0..13), &v));
        // exactly 14 required, extra is fine
        assert!(is_finalized(&c, &cp, &cx, &sigs_from(&msg, 0..21), &v));
    }

    #[test]
    fn a_seat_cannot_double_sign() {
        let c = fresh_committee();
        let v = MockVerifier;
        let msg = b"m".to_vec();
        // 13 distinct seats, but seat 0 appears 3 times → still only 13 counted
        let mut sigs = sigs_from(&msg, 0..13);
        sigs.push(SeatSig { seat: 0, sig: good_sig(&msg, 0) });
        sigs.push(SeatSig { seat: 0, sig: good_sig(&msg, 0) });
        assert_eq!(count_signers(&c, &msg, &sigs, &v), 13);
    }

    #[test]
    fn forged_and_inactive_sigs_do_not_count() {
        let mut c = fresh_committee();
        let v = MockVerifier;
        let msg = b"m".to_vec();
        // seat 5 supplies a wrong signature; seat 6 is vacant
        open_vacancy(&mut c, 6, ExitReason::Resigned).unwrap();
        let mut sigs = sigs_from(&msg, 0..14); // 0..13 valid... but 6 is vacant now
        sigs[5] = SeatSig { seat: 5, sig: b"forged".to_vec() };
        // seats 0..14 minus seat5(forged) minus seat6(vacant) = 12 valid
        assert_eq!(count_signers(&c, &msg, &sigs, &v), 12);
    }

    #[test]
    fn committee_governed_feature_activation() {
        let c = fresh_committee();
        let v = MockVerifier;
        let cx = ctx0();
        let act = FeatureActivation { feature: "euvm".into(), activation_height: 1000 };
        let ok_sigs = sigs_from(&activation_message(&act, &cx), 0..14);

        // before the height → not active even with quorum
        assert!(!is_feature_active(&c, &act, &cx, &ok_sigs, &v, 999));
        // at/after the height WITH quorum → active
        assert!(is_feature_active(&c, &act, &cx, &ok_sigs, &v, 1000));
        assert!(is_feature_active(&c, &act, &cx, &ok_sigs, &v, 5000));
        // at the height WITHOUT quorum (13 sigs) → NOT active (committee is the authority)
        let short = sigs_from(&activation_message(&act, &cx), 0..13);
        assert!(!is_feature_active(&c, &act, &cx, &short, &v, 2000));
    }

    // ── S-M4: messages are bound to chain-id, epoch and nonce ──

    #[test]
    fn every_message_binds_chain_epoch_and_nonce() {
        let act = FeatureActivation { feature: "euvm".into(), activation_height: 1000 };
        let cp = Checkpoint { height: 500, block_hash: [7u8; 32] };
        let base = ctx0();
        for other in [
            ctx(0xB10C_0002, base.epoch, base.nonce), // different chain
            ctx(base.chain_id, base.epoch + 1, base.nonce), // different epoch
            ctx(base.chain_id, base.epoch, base.nonce + 1), // different nonce
        ] {
            assert_ne!(activation_message(&act, &base), activation_message(&act, &other));
            assert_ne!(checkpoint_message(&cp, &base), checkpoint_message(&cp, &other));
            assert_ne!(
                replacement_message(9, &pk(99), &base),
                replacement_message(9, &pk(99), &other)
            );
        }
        // The three domains never collide with each other either.
        assert_ne!(activation_message(&act, &base), checkpoint_message(&cp, &base));
    }

    #[test]
    fn a_quorum_does_not_replay_onto_another_chain_or_epoch() {
        let c = fresh_committee();
        let v = MockVerifier;
        let testnet = ctx(0xB10C_0002, 7, 0);
        let mainnet = ctx(0xB10C_0004, 7, 0);
        let next_epoch = ctx(0xB10C_0002, 8, 0);

        // A real 14-of-21 authorization, cast on testnet at epoch 7.
        let act = FeatureActivation { feature: "euvm".into(), activation_height: 1000 };
        let sigs = sigs_from(&activation_message(&act, &testnet), 0..14);
        assert!(is_feature_active(&c, &act, &testnet, &sigs, &v, 1000));
        // The same bytes carried to mainnet, or to the next epoch, authorize nothing.
        assert!(!is_feature_active(&c, &act, &mainnet, &sigs, &v, 1000));
        assert!(!is_feature_active(&c, &act, &next_epoch, &sigs, &v, 1000));

        // Same for a finalized checkpoint.
        let cp = Checkpoint { height: 500, block_hash: [7u8; 32] };
        let cp_sigs = sigs_from(&checkpoint_message(&cp, &testnet), 0..14);
        assert!(is_finalized(&c, &cp, &testnet, &cp_sigs, &v));
        assert!(!is_finalized(&c, &cp, &mainnet, &cp_sigs, &v));
        assert!(!is_finalized(&c, &cp, &next_epoch, &cp_sigs, &v));
    }

    #[test]
    fn replacement_approvals_are_good_for_exactly_one_fill() {
        let mut c = fresh_committee();
        let v = MockVerifier;
        let cx = ctx0(); // nonce 0 = seat 10 has never been replaced
        let candidate = b"new-member-key".to_vec();

        open_vacancy(&mut c, 10, ExitReason::RemovedForFault).unwrap();
        let msg = replacement_message(10, &candidate, &cx);
        let approvals = sigs_from(&msg, (0..COMMITTEE_SIZE).filter(|&i| i != 10).take(14));
        assert!(fill_vacancy(&mut c, 10, candidate.clone(), &cx, &approvals, &v).is_ok());
        assert_eq!(c.seats()[10].replacements, 1);

        // The seat falls vacant again. Replaying the SAME approvals is refused on
        // the nonce, before any signature is even looked at.
        open_vacancy(&mut c, 10, ExitReason::Resigned).unwrap();
        assert_eq!(
            fill_vacancy(&mut c, 10, candidate.clone(), &cx, &approvals, &v),
            Err(FfgError::StaleNonce { got: 0, expected: 1 })
        );
        // And with the correct nonce the replayed signatures no longer verify,
        // because the nonce is inside the signed preimage.
        let cx1 = ctx(cx.chain_id, cx.epoch, 1);
        assert_eq!(
            fill_vacancy(&mut c, 10, candidate.clone(), &cx1, &approvals, &v),
            Err(FfgError::NoQuorum { got: 0, need: QUORUM })
        );
        // Fresh approvals over the new nonce do work.
        let msg1 = replacement_message(10, &candidate, &cx1);
        let fresh = sigs_from(&msg1, (0..COMMITTEE_SIZE).filter(|&i| i != 10).take(14));
        assert!(fill_vacancy(&mut c, 10, candidate.clone(), &cx1, &fresh, &v).is_ok());
        assert_eq!(c.seats()[10].replacements, 2);
    }

    #[test]
    fn vacancies_pause_finality() {
        let mut c = fresh_committee();
        let v = MockVerifier;
        let cx = ctx0();
        let cp = Checkpoint { height: 1, block_hash: [0u8; 32] };
        let msg = checkpoint_message(&cp, &cx);
        // open 3 vacancies (active 18) → still available
        for s in [0u8, 1, 2] {
            open_vacancy(&mut c, s, ExitReason::ProlongedDowntime).unwrap();
        }
        assert!(c.finality_available());
        // a 4th vacancy (active 17) → finality pauses; no quorum possible
        open_vacancy(&mut c, 3, ExitReason::ProlongedDowntime).unwrap();
        assert!(!c.finality_available());
        // even 17 signers can't finalize while paused
        assert!(!is_finalized(&c, &cp, &cx, &sigs_from(&msg, 4..21), &v));
    }

    #[test]
    fn replacement_only_via_quorum() {
        let mut c = fresh_committee();
        let v = MockVerifier;
        let cx = ctx0();
        // seat 10 leaves
        open_vacancy(&mut c, 10, ExitReason::RemovedForFault).unwrap();
        assert_eq!(c.active_count(), 20);

        let candidate = b"new-member-key".to_vec();
        let msg = replacement_message(10, &candidate, &cx);
        // approvals come from ACTIVE seats only (seat 10 is vacant and cannot approve).
        let active_seats: Vec<usize> = (0..COMMITTEE_SIZE).filter(|&i| i != 10).collect();
        let approve14 = sigs_from(&msg, active_seats.iter().copied().take(14));
        let approve13 = sigs_from(&msg, active_seats.iter().copied().take(13));
        assert!(fill_vacancy(&mut c, 10, candidate.clone(), &cx, &approve13, &v).is_err());
        // 14 approvals → seat filled with the new key, active again
        assert!(fill_vacancy(&mut c, 10, candidate.clone(), &cx, &approve14, &v).is_ok());
        assert_eq!(c.active_count(), 21);
        assert_eq!(c.seats()[10].pubkey, candidate);
        assert!(c.seats()[10].active);

        // cannot "fill" an already-active seat (non-transferable except through vacancy)
        assert_eq!(
            fill_vacancy(&mut c, 10, b"hostile".to_vec(), &cx, &approve14, &v),
            Err(FfgError::SeatNotVacant(10))
        );
    }
}
