// SPDX-License-Identifier: AGPL-3.0-or-later
//
// ── Adversarial multi-branch FFG suite (p2b, 2026-10-19) ──────────────────
//
// Included into `l2_tests` (l2_settlement_tests.rs), so it drives the REAL
// transition (`Transition::apply_block`, `close_epoch`, the finality engine,
// step-8 inclusion, the L2 claim rule) through real blocks. Nothing here is a
// model; the only test doubles are the signature verifiers the rest of the
// crate's tests use (toy keys, a proof double).
//
// HOW A SPLIT IS BUILT. Branches are children of one parent state, each
// opened by its own block in the last pre-fork epoch, so their checkpoint
// roots differ from the next epoch on. Two openings: `l2_split` (blocks at
// different slots: an ordinary partition, RANDAO mixes and committee seats
// diverge) and `l2_split_same_slot` (one slot, one proposer, different
// bodies: mixes and seats stay identical, so every vote is portable). Each
// epoch every branch
// gets a boundary block (first slot, empty: it closes the previous epoch's
// tally) and a vote block (last slot) carrying the votes the scenario says
// that branch HEARS. A vote is `(voter, origin branch)`: it targets the
// origin's checkpoint and sources the origin's justified checkpoint, exactly
// what an honest validator on the origin signs. A "carried" foreign vote is
// the identical signed message; where the carrier seats the voter in another
// slot that message is inadmissible (step 8) and is dropped and counted.
//
// PARAMETERS (all scenarios):
// - Stake: every validator 200,000 BLCH (`setup_with`); equal weights, so
//   "k of n validators" is "k/n of stake".
// - L2 fixture (`split_claims::parent`): 4 validators, epoch 1, finalized
//   epoch 0, one matured withdrawal (leaf 2 of a 3-leaf tree) with escrow.
//   Fork slots 63/62(/61), or 63 for every branch (same-slot opening):
//   first post-fork checkpoint is epoch 2.
// - Genesis fixture (3-way): 3 validators, epoch 0, fork slots 31/30/29:
//   first post-fork checkpoint is epoch 1.
// - Rules: `mainnet_rules()` (what mainnet runs above epoch 2880: quorum
//   floor 1/2 of unleaked stake, leak recovery; seed look-ahead NOT armed, as
//   on mainnet) with the PRE-5700 leak quotient 64 so a leak resolves in
//   tens of epochs.
//   Mainnet's ETH-paced quotient (2,684,355) changes the epoch count, not the
//   outcome: `projection_*` below folds the same split through
//   `FinalityState` at mainnet epochs to give the mainnet numbers.
// - Horizon: at most `HORIZON` epochs per run.
// - Claim rule: `NATIVE_CLAIM_FINALITY_ACTIVATION_EPOCH` forced open where a
//   test says "armed" (the fix already on this branch), inert otherwise.
//
// SCENARIOS and what TODAY's rules do (pinned by the `today_*` tests):
// 1. Minority branch carrying majority votes (same-slot opening; epoch 2:
//    v0..v2 vote A and B = {v3} carries those messages; epoch 3: v1,v2
//    follow B): B finalizes A's epoch-2 checkpoint, which is not on B and
//    which A itself never finalized, with NO slashable pair. Inert claim
//    rule: the withdrawal pays on B; armed: refused. Over an ordinary
//    partition the seats diverge and the honest messages cannot be carried
//    (re-signing them at the carrier's seats is scenario 4).
// 2. Equal split 50/50 ({v0,v1} | {v2,v3}), no cross traffic, leak: BOTH
//    sides finalize their own epoch-7 checkpoint at the epoch-9 boundary;
//    one withdrawal pays on both EVEN WITH the claim rule armed. Mainnet
//    pace (projection): each half finalizes alone after 1,934 epochs
//    (~21 days); a 1/3 side after 2,733 (~30 days); 1/4 never (floor).
// 3. 3-way split (devnet4 2026-10-17 shape: one validator per branch): all
//    THREE finalize distinct epoch-9 checkpoints at the epoch-11 boundary.
// 4. Cross-branch double votes (v1, v2 vote A on A and B on B): both
//    finalize conflicting epoch-2 checkpoints without any leak; neither
//    branch sees an equivocation; the pair is slashable evidence and slashes
//    on the branch it is shown to. A branch that hears both votes (same-slot
//    opening) counts neither.
// 5. Late-joining branch after finality: A finalizes epoch 2 with all
//    stake; v2,v3 then move to B, a branch forked BEFORE that checkpoint.
//    Under the leak B finalizes its epoch-9 checkpoint, conflicting with A's
//    finalized one (a finality reversal for anyone who followed A); the moved votes
//    surround their A votes; the claim pays on A and again on B.
// 6. Stale source: a vote sourcing an old justified checkpoint is admitted
//    by step 8 but never counted. A vote sourcing a checkpoint that is NOT
//    on the carrier's chain counts once the carrier justified it (scenario
//    1, epoch 3: `today_votes_sourcing_a_checkpoint_not_on_the_chain_count`;
//    its post-fix half is in the scenario-1 post-fix test).
//
// POST-FIX tests (`#[ignore]`, `post_fix_*`): the intended behaviour after
// p2a (count only own-chain target votes) and p1a (frozen finality set, no
// leak in the denominator). Un-ignore after both merge:
//   - no branch ever justifies or finalizes a checkpoint that is not its own;
//   - in any split, at most one side finalizes a post-fork checkpoint;
//   - one withdrawal pays on at most one side.
// Scenario 4 has no p1a/p2a post-fix: two 3/4 quorums overlapping in 1/2 of
// the stake is FFG's accountable-safety bound (>= 1/3 provably slashable);
// the remedy is slashing (p5a), whose today-path is pinned below.

use std::collections::{BTreeMap, BTreeSet};

use crate::attestation::{Attestation as Att, AttestationData as Data, KeyLookup};

const SPE: u64 = crate::params::SLOTS_PER_EPOCH;
const fn first(e: u64) -> u64 {
    e * SPE
}
/// Upper bound on the epochs a leak scenario runs.
const HORIZON: u64 = 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Cp {
    epoch: u64,
    root: [u8; 32],
}

struct Branch {
    name: &'static str,
    st: CommittedState,
    chains: Vec<RandaoChain>,
    /// Blocks produced on this branch after the fork.
    own: BTreeSet<[u8; 32]>,
    /// This branch's checkpoint root per epoch (the head before the epoch's
    /// first slot, the root `Engine::checkpoint_root` has attesters vote).
    cps: BTreeMap<u64, [u8; 32]>,
    /// First epoch whose checkpoint differs between branches.
    fork_epoch: u64,
    /// (state epoch when observed, checkpoint): the first finalization of a
    /// post-fork checkpoint on this branch.
    first_final: Option<(u64, Cp)>,
    /// Every vote this branch included, for evidence.
    included: Vec<Att>,
    /// Foreign votes this branch heard but could not include: the voter's
    /// seat differs here, so the signed message is not admissible (step 8).
    dropped: usize,
}

impl Branch {
    fn fork(name: &'static str, parent: &CommittedState, chains: &[RandaoChain], slot: u64) -> Self {
        Self::fork_with(name, parent, chains, slot, &[])
    }
    fn fork_with(name: &'static str, parent: &CommittedState, chains: &[RandaoChain], slot: u64, atts: &[Att]) -> Self {
        let mut chains = split_claims::fork_chains(chains);
        let st = split_claims::block_with(parent, slot, atts, &[], &mut chains)
            .unwrap_or_else(|e| panic!("{name}: fork block at {slot}: {e:?}"));
        let mut own = BTreeSet::new();
        own.insert(*st.head.as_bytes());
        Branch {
            name,
            fork_epoch: crate::epoch_of(slot) + 1,
            st,
            chains,
            own,
            cps: BTreeMap::new(),
            first_final: None,
            included: Vec::new(),
            dropped: 0,
        }
    }
    fn push(&mut self, slot: u64, atts: &[Att], txs: &[PosTransaction]) {
        self.st = split_claims::block_with(&self.st, slot, atts, txs, &mut self.chains)
            .unwrap_or_else(|e| panic!("{}: block at {slot}: {e:?}", self.name));
        self.own.insert(*self.st.head.as_bytes());
        self.included.extend_from_slice(atts);
        let f = self.finalized();
        if self.first_final.is_none() && f.epoch >= self.fork_epoch {
            self.first_final = Some((self.st.epoch, f));
        }
    }
    fn justified(&self) -> Cp {
        let j = self.st.finality().justified;
        Cp { epoch: j.epoch, root: j.root }
    }
    fn finalized(&self) -> Cp {
        let f = self.st.finality().finalized;
        Cp { epoch: f.epoch, root: f.root }
    }
    fn vote_of(&self, v: u32, target_epoch: u64) -> Att {
        self.included
            .iter()
            .find(|a| a.validator == v && a.data.target_epoch == target_epoch)
            .unwrap_or_else(|| panic!("{}: no vote of v{v} for epoch {target_epoch}", self.name))
            .clone()
    }
}

/// Whether `root` was produced only on branches other than `i`.
fn foreign(br: &[Branch], i: usize, root: &[u8; 32]) -> bool {
    !br[i].own.contains(root) && br.iter().enumerate().any(|(j, b)| j != i && b.own.contains(root))
}

/// The slot of `v`'s committee in `st`'s current epoch (step 8's partition).
fn seat(st: &CommittedState, v: u32) -> u64 {
    let roster = st.consensus_roster_at(st.epoch);
    let partition = committees::epoch_committees(&st.seed_for_epoch(st.epoch), st.epoch, &roster);
    let i = partition
        .iter()
        .position(|c| c.contains(&v))
        .unwrap_or_else(|| panic!("v{v} has no seat in epoch {}", st.epoch));
    first(st.epoch) + i as u64
}

/// What `v` signs on `origin`: its seat there, origin's checkpoint as
/// target, `source` as source.
fn signed_vote(origin: &CommittedState, v: u32, target: [u8; 32], source: Cp) -> Att {
    let data = Data {
        slot: seat(origin, v),
        head: target,
        source_epoch: source.epoch,
        source_root: source.root,
        target_epoch: origin.epoch,
        target_root: target,
    };
    let pk = KeyLookup::pubkey(origin, v).expect("registered");
    Att { data, validator: v, signature: toy_sign(pk, &data.signing_root()) }
}

/// Who each carrier hears in one epoch: `(voter, origin branch)`.
type Plan<'a> = &'a dyn Fn(usize) -> Vec<(u32, usize)>;

/// One epoch on every branch: boundary block at `first(e)` (closes e-1),
/// then the vote block at `first(e+1)-1` carrying `plan(c)`.
fn run_epoch(br: &mut [Branch], e: u64, plan: Plan<'_>) {
    run_epoch_with_source(br, e, plan, &|_, j| j)
}

/// `run_epoch`, with the source each voter signs chosen by `source(origin,
/// origin's justified)` (scenario 6 signs stale sources).
fn run_epoch_with_source(br: &mut [Branch], e: u64, plan: Plan<'_>, source: &dyn Fn(usize, Cp) -> Cp) {
    let cps: Vec<[u8; 32]> = br.iter().map(|b| *b.st.head.as_bytes()).collect();
    for (i, b) in br.iter_mut().enumerate() {
        assert!(b.st.slot < first(e), "{}: already in epoch {e}", b.name);
        b.cps.insert(e, cps[i]);
        b.push(first(e), &[], &[]);
    }
    let sources: Vec<Cp> = br.iter().enumerate().map(|(i, b)| source(i, b.justified())).collect();
    // A foreign vote is the very message its origin signed; the carrier can
    // include it only if it seats the voter in the same slot (same seed).
    let heard: Vec<(Vec<Att>, usize)> = (0..br.len())
        .map(|c| {
            let mut dropped = 0;
            let atts = plan(c)
                .into_iter()
                .map(|(v, o)| signed_vote(&br[o].st, v, cps[o], sources[o]))
                .filter(|vote| {
                    let ok = seat(&br[c].st, vote.validator) == vote.data.slot;
                    dropped += usize::from(!ok);
                    ok
                })
                .collect();
            (atts, dropped)
        })
        .collect();
    for (b, (a, dropped)) in br.iter_mut().zip(heard) {
        b.dropped += dropped;
        b.push(first(e + 1) - 1, &a, &[]);
    }
}

/// The boundary block of epoch `e` on every branch (closes e-1's tally).
fn close(br: &mut [Branch], e: u64) {
    for b in br.iter_mut() {
        b.cps.insert(e, *b.st.head.as_bytes());
        b.push(first(e), &[], &[]);
    }
}

/// Whether the fixture's withdrawal (leaf 2) is admitted on `b`; if so it is
/// applied in a block and the payout checked.
fn claim_pays(b: &mut Branch) -> bool {
    let tx = split_claims::claim_on(&b.st);
    if b.st.l2_withdraw_claim_refusal(&tx).is_some() {
        return false;
    }
    let (recipient, sats) = wleaf(2);
    let before = b.st.balance_sat(&recipient);
    b.push(b.st.slot + 1, &[], &[claim(&tx)]);
    assert_eq!(b.st.balance_sat(&recipient), before + u128::from(sats), "{}: paid", b.name);
    true
}

/// The finality rules mainnet runs today, on this thread: the quorum floor
/// and leak recovery (`LEAK_RECOVERY_ACTIVATION_EPOCH` = 2880, live), with
/// the seed look-ahead left at the shipped `back = 1` (its gate,
/// `ANCESTRY_SEED_ACTIVATION_EPOCH`, is inert on mainnet; `gates_open_guard`
/// would arm it too). The leak quotient stays the pre-5700 64: see the
/// header.
fn mainnet_rules() -> impl Drop {
    struct Rules<G>(#[allow(dead_code)] G);
    impl<G> Drop for Rules<G> {
        fn drop(&mut self) {
            crate::params::rehearsal::LOOKAHEAD_ZERO.with(|c| c.set(false));
        }
    }
    let gates = crate::params::rehearsal::gates_open_guard();
    crate::params::rehearsal::LOOKAHEAD_ZERO.with(|c| c.set(true));
    Rules(gates)
}

/// Branches of the L2 fixture opened by blocks at DIFFERENT slots of epoch
/// 1 (63, 62, ...): an ordinary partition. Their RANDAO mixes, hence every
/// later epoch's committee seats, differ, so a foreign vote is includable
/// only where the voter happens to hold the same seat.
fn l2_split(names: &[&'static str]) -> Vec<Branch> {
    let (p, chains) = split_claims::parent();
    names
        .iter()
        .enumerate()
        .map(|(k, n)| Branch::fork(n, &p, &chains, first(2) - 1 - k as u64))
        .collect()
}

/// Branches of the L2 fixture opened by blocks at the SAME slot (63, one
/// proposer, one reveal: a proposer equivocation, or two bodies for one
/// slot), differing only in the epoch-1 votes they carry (branch k carries
/// v0..v(k-1)'s). The mixes, hence all later seats, stay identical while the
/// branches fill the same slots, so EVERY vote is portable as the very same
/// signed message: the most favourable case for carrying foreign votes.
fn l2_split_same_slot(names: &[&'static str]) -> Vec<Branch> {
    let (p, chains) = split_claims::parent();
    let j = Cp { epoch: p.finality().justified.epoch, root: p.finality().justified.root };
    let target = *p.head.as_bytes();
    names
        .iter()
        .enumerate()
        .map(|(k, n)| {
            let atts: Vec<Att> = (0..k as u32).map(|v| signed_vote(&p, v, target, j)).collect();
            Branch::fork_with(n, &p, &chains, first(2) - 1, &atts)
        })
        .collect()
}

/// Runs epochs `from..` until every branch finalized a post-fork
/// checkpoint or `HORIZON`; then closes the last epoch.
fn run_until_all_final(br: &mut [Branch], from: u64, plan: Plan<'_>) -> u64 {
    let mut e = from;
    while e < HORIZON && br.iter().any(|b| b.first_final.is_none()) {
        run_epoch(br, e, plan);
        e += 1;
    }
    close(br, e);
    e
}

fn summary(br: &[Branch]) -> String {
    br.iter()
        .map(|b| format!("{}: fin e{} first {:?} just e{} dropped {}", b.name, b.finalized().epoch, b.first_final.map(|(e, c)| (e, c.epoch)), b.justified().epoch, b.dropped))
        .collect::<Vec<_>>()
        .join(" | ")
}

// ── 1. Minority branch carrying the majority's votes ───────────────────────
//
// Same-slot opening (identical seats in epoch 2). Epoch 2: v0,v1,v2 vote A's
// checkpoint; B (whose only voter is v3) carries those three messages too.
// Epoch 3: v1,v2 follow B (fork choice moved them; nobody equivocates: one
// vote per epoch each, no surround) and, with v3, vote B's checkpoint
// sourcing B's justified checkpoint; v0 stays on A. Closed at 4.

fn s1_on(mut br: Vec<Branch>) -> Vec<Branch> {
    let e2 = |c: usize| match c {
        0 => vec![(0, 0), (1, 0), (2, 0)],
        _ => vec![(0, 0), (1, 0), (2, 0), (3, 1)],
    };
    run_epoch(&mut br, 2, &e2);
    let e3 = |c: usize| if c == 0 { vec![(0, 0)] } else { vec![(1, 1), (2, 1), (3, 1)] };
    run_epoch(&mut br, 3, &e3);
    close(&mut br, 4);
    br
}
fn s1() -> Vec<Branch> {
    s1_on(l2_split_same_slot(&["A", "B"]))
}

#[test]
fn today_minority_branch_carrying_majority_votes_finalizes_the_majority_checkpoint() {
    let _rules = mainnet_rules();
    let mut br = s1();
    let s = summary(&br);
    let a_cp = br[0].cps[&2];
    assert_ne!(a_cp, br[1].cps[&2]);
    assert_eq!(br[1].dropped, 0, "every carried vote is the message A's validators signed: {s}");
    // B justified A's epoch-2 checkpoint, its honest voters sourced it, and
    // B finalized it: a checkpoint that is not on B, and that A itself has
    // only justified.
    assert_eq!(br[1].finalized(), Cp { epoch: 2, root: a_cp }, "{s}");
    assert!(foreign(&br, 1, &a_cp));
    assert_eq!(br[1].justified(), Cp { epoch: 3, root: br[1].cps[&3] }, "{s}");
    assert_eq!((br[0].justified().epoch, br[0].finalized().epoch), (2, 0), "{s}");
    // No slashable pair: v1, v2 signed one vote per epoch, nothing surrounds.
    for v in [1, 2] {
        let ev = crate::slashing::SlashingEvidence { first: br[0].vote_of(v, 2), second: br[1].vote_of(v, 3) };
        assert_eq!(ev.offense(), Err(crate::slashing::EvidenceError::NotConflicting));
    }
    // Claim rule inert (mainnet today): the withdrawal pays on B, the branch
    // whose finality is borrowed; A has not finalized it.
    assert!(!claim_pays(&mut br[0]));
    assert!(claim_pays(&mut br[1]), "{s}");
}

/// Scenario 6's foreign SOURCE half: B's epoch-3 votes are honest from B's
/// view (they source B's justified checkpoint) and that source is A's.
#[test]
fn today_votes_sourcing_a_checkpoint_not_on_the_chain_count() {
    let _rules = mainnet_rules();
    let br = s1();
    let a_cp = br[0].cps[&2];
    let b3: Vec<&Att> = br[1].included.iter().filter(|a| a.data.target_epoch == 3).collect();
    assert_eq!(b3.len(), 3);
    assert!(b3.iter().all(|a| a.data.source_root == a_cp && a.data.target_root == br[1].cps[&3]));
    assert!(br[1].st.finality_engine.is_justified(&crate::finality::Checkpoint { epoch: 3, root: br[1].cps[&3] }));
}

#[test]
fn today_armed_claim_rule_refuses_the_claim_on_the_minority_branch() {
    let _rules = mainnet_rules();
    let _claims = crate::params::native_claim_finality_test::open();
    let mut br = s1();
    assert!(foreign(&br, 1, &br[1].finalized().root), "FFG still finalizes foreign on B");
    assert!(!claim_pays(&mut br[1]));
}

/// The same plan over an ORDINARY partition (fork blocks at different
/// slots): the seats differ from epoch 2 on, so A's votes are not
/// includable on B as the messages A's validators signed, and B finalizes
/// nothing foreign. Re-signing them at B's seats is a second vote for the
/// epoch (scenario 4, slashable); the 2026-10-19 reproduction (8c737382)
/// builds B's votes at B's seats, so outside a same-slot fork it is that
/// double-vote case. Seats also drift apart within an epoch or two of any
/// fork (rewards move the stake-weighted proposer draw, hence the mix), so
/// the honest-carry window is about one epoch.
#[test]
fn today_ordinary_partition_cannot_carry_honest_foreign_votes_into_finality() {
    let _rules = mainnet_rules();
    let br = s1_on(l2_split(&["A", "B"]));
    let s = summary(&br);
    eprintln!("s1b (ordinary partition): {s}");
    assert_eq!(br[1].dropped, 2, "two of A's three seats differ on B, one coincides: {s}");
    assert!(!foreign(&br, 1, &br[1].finalized().root), "{s}");
    assert!(!foreign(&br, 1, &br[1].justified().root), "{s}");
}

#[test]
#[ignore = "post-fix (p2a own-chain target votes): un-ignore after merge"]
fn post_fix_minority_branch_never_justifies_or_finalizes_a_foreign_checkpoint() {
    let _rules = mainnet_rules();
    let mut br = s1();
    let s = summary(&br);
    for i in 0..2 {
        assert!(!foreign(&br, i, &br[i].finalized().root), "{s}");
        assert!(!foreign(&br, i, &br[i].justified().root), "{s}");
    }
    let a_cp = br[0].cps[&2];
    assert!(br[1].included.iter().filter(|a| a.data.target_epoch == 3).all(|a| a.data.source_root != a_cp), "{s}");
    assert_eq!(br[1].first_final, None, "{s}");
    assert!(!claim_pays(&mut br[1]), "even with the claim rule inert");
}

// ── 2. Equal split 50/50 with the inactivity leak ─────────────────────────
//
// A = {v0,v1}, B = {v2,v3}, each votes only its own branch, no cross
// traffic. Finalized epoch at the fork: 0, so the leak bites from epoch 5.
// Runs from epoch 2 until both sides finalize (<= HORIZON).

/// Epoch whose checkpoint each side of the 50/50 split finalizes (pinned).
const S2_FINAL_EPOCH: u64 = 7;

fn s2() -> Vec<Branch> {
    let mut br = l2_split(&["A", "B"]);
    let plan = |c: usize| match c {
        0 => vec![(0, 0), (1, 0)],
        _ => vec![(2, 1), (3, 1)],
    };
    run_until_all_final(&mut br, 2, &plan);
    br
}

#[test]
fn today_equal_split_with_leak_finalizes_both_sides() {
    let _rules = mainnet_rules();
    let _claims = crate::params::native_claim_finality_test::open();
    let mut br = s2();
    let s = summary(&br);
    let (a, b) = (br[0].first_final.expect(&s), br[1].first_final.expect(&s));
    eprintln!("s2 (50/50 leak): {s}");
    assert_eq!((a.1.epoch, b.1.epoch), (S2_FINAL_EPOCH, S2_FINAL_EPOCH), "{s}");
    assert_eq!(a.0, b.0, "same boundary: {s}");
    assert_ne!(a.1.root, b.1.root);
    assert!(!foreign(&br, 0, &a.1.root) && !foreign(&br, 1, &b.1.root), "each finalized its OWN checkpoint");
    // The armed claim rule does not help: each finality is the chain's own.
    assert!(claim_pays(&mut br[0]) && claim_pays(&mut br[1]), "one withdrawal, two payouts");
}

#[test]
#[ignore = "post-fix (p1a frozen finality set, no leak in the denominator): un-ignore after merge"]
fn post_fix_equal_split_finalizes_at_most_one_side() {
    let _rules = mainnet_rules();
    let _claims = crate::params::native_claim_finality_test::open();
    let mut br = s2();
    let finals = br.iter().filter(|b| b.first_final.is_some()).count();
    assert!(finals <= 1, "{}", summary(&br));
    let paid = [claim_pays(&mut br[0]), claim_pays(&mut br[1])];
    assert!(paid.iter().filter(|p| **p).count() <= 1);
}

/// Mainnet pace (ETH-paced quotient, floor, recovery; epochs >= 7000):
/// the same 50/50 and 1/3 sides, folded through `FinalityState` alone (one
/// side's view: its own votes present, the rest absent). Gives the number
/// of epochs from the last finality to the side's own new finality.
fn projection(present: u32, n: u32) -> Option<u64> {
    use crate::finality::{Checkpoint as FCp, EpochVotes, FinalityState};
    let start = 7_000u64;
    let set: Vec<crate::sample::Validator> =
        (0..n).map(|index| crate::sample::Validator { index, effective_stake: sat(200_000) as u64 }).collect();
    let mut fs = FinalityState::new(FCp { epoch: start, root: [0xF0; 32] });
    for e in start + 1..start + 20_000 {
        let j = fs.current_justified();
        let votes: Vec<(u32, Data)> = (0..present)
            .map(|v| {
                (v, Data { slot: first(e), head: [e as u8; 32], source_epoch: j.epoch, source_root: j.root, target_epoch: e, target_root: [e as u8; 32] })
            })
            .collect();
        fs.process_epoch(&EpochVotes { epoch: e, active_set: &set, attestations: &votes }).unwrap();
        if fs.finalized().epoch > start {
            return Some(fs.finalized().epoch - start);
        }
    }
    None
}

#[test]
fn projection_today_mainnet_pace_half_and_third_finalize_alone() {
    let half = projection(2, 4).expect("1/2 finalizes alone");
    let third = projection(1, 3).expect("1/3 finalizes alone");
    let quarter = projection(1, 4);
    eprintln!("mainnet pace: 1/2 after {half} epochs, 1/3 after {third}, 1/4 {quarter:?}");
    // ~21 and ~30 days at 960 s/epoch; the floor stops a 1/4 side.
    assert!((1_500..2_500).contains(&half), "{half}");
    assert!((2_200..3_500).contains(&third), "{third}");
    assert_eq!(quarter, None);
}

// ── 3. Three-way split (devnet4, 2026-10-17) ──────────────────────────────
//
// 3 validators (1/3 each), one per branch, each votes only its own branch.
// Genesis fixture, fork in epoch 0, runs from epoch 1.

fn s3() -> Vec<Branch> {
    let (_, g, chains) = setup_with(3, ToyVerifier, &[]);
    let mut br: Vec<Branch> =
        ["A", "B", "C"].iter().enumerate().map(|(k, n)| Branch::fork(n, &g, &chains, first(1) - 1 - k as u64)).collect();
    let plan = |c: usize| vec![(c as u32, c)];
    run_until_all_final(&mut br, 1, &plan);
    br
}

#[test]
fn today_three_way_split_finalizes_all_three_branches() {
    let _rules = mainnet_rules();
    let br = s3();
    let s = summary(&br);
    eprintln!("s3 (3-way): {s}");
    let finals: Vec<(u64, Cp)> = br.iter().map(|b| b.first_final.expect(&s)).collect();
    assert!(finals.iter().all(|f| f.1.epoch == 9 && f.0 == 11), "epoch 9, three roots, boundary 11: {s}");
    let roots: BTreeSet<[u8; 32]> = finals.iter().map(|f| f.1.root).collect();
    assert_eq!(roots.len(), 3);
    for (i, f) in finals.iter().enumerate() {
        assert!(!foreign(&br, i, &f.1.root));
    }
}

#[test]
#[ignore = "post-fix (p1a frozen finality set, no leak in the denominator): un-ignore after merge"]
fn post_fix_three_way_split_finalizes_at_most_one_branch() {
    let _rules = mainnet_rules();
    let br = s3();
    assert!(br.iter().filter(|b| b.first_final.is_some()).count() <= 1, "{}", summary(&br));
}

// ── 4. Double votes across branches ───────────────────────────────────────
//
// v1, v2 vote A's checkpoint on A and B's on B (epochs 2..=3); v0 is on A
// only, v3 on B only. Each branch sees 3/4 of the stake for its own
// checkpoint and no leak is involved.

fn s4() -> Vec<Branch> {
    let mut br = l2_split(&["A", "B"]);
    let plan = |c: usize| match c {
        0 => vec![(0, 0), (1, 0), (2, 0)],
        _ => vec![(1, 1), (2, 1), (3, 1)],
    };
    for e in 2..=3 {
        run_epoch(&mut br, e, &plan);
    }
    close(&mut br, 4);
    br
}

#[test]
fn today_cross_branch_double_votes_finalize_conflicting_checkpoints_unseen() {
    let _rules = mainnet_rules();
    let _claims = crate::params::native_claim_finality_test::open();
    let _slash = crate::params::rehearsal::slashing_gate_open_guard();
    let mut br = s4();
    let (a, b) = (br[0].finalized(), br[1].finalized());
    assert_eq!((a.epoch, b.epoch), (2, 2), "{}", summary(&br));
    assert_ne!(a.root, b.root, "two finalized checkpoints at one epoch");
    for b in &br {
        assert!(b.st.finality_engine.leaked_total() == 0, "no leak involved");
    }
    // The pair is slashable evidence, but only a node holding BOTH branches
    // has it; each branch alone saw one honest-looking vote.
    let ev = crate::slashing::SlashingEvidence { first: br[0].vote_of(1, 2), second: br[1].vote_of(1, 2) };
    assert_eq!(ev.offense(), Ok(crate::slashing::SlashableOffense::DoubleVote));
    // Both branches pay the withdrawal (armed rule: each finality is own).
    assert!(claim_pays(&mut br[0]) && claim_pays(&mut br[1]));
    // Shown to B, the evidence slashes v1 there; B's finality stands.
    let tx = PosTransaction::SlashingEvidence(ev.into());
    let slot = br[1].st.slot + 1;
    br[1].push(slot, &[], &[tx]);
    assert!(br[1].st.validator_record(1).unwrap().slashed);
    assert_eq!(br[1].finalized(), b, "slashing does not revert finality");
}

/// Same-slot opening, epoch 2 only (identical seats): B hears A's votes of
/// v0..v2 AND B's votes of v1..v3. v1, v2 are equivocators in B's view and
/// count for neither target: 1/4 vs 1/4, nothing justified on B.
#[test]
fn today_double_vote_heard_on_one_branch_counts_for_neither_target() {
    let _rules = mainnet_rules();
    let mut br = l2_split_same_slot(&["A", "B"]);
    let plan = |c: usize| match c {
        0 => vec![(0, 0), (1, 0), (2, 0)],
        _ => vec![(0, 0), (1, 0), (2, 0), (1, 1), (2, 1), (3, 1)],
    };
    run_epoch(&mut br, 2, &plan);
    close(&mut br, 3);
    assert_eq!(br[1].dropped, 0);
    assert_eq!(br[0].justified(), Cp { epoch: 2, root: br[0].cps[&2] });
    assert_eq!(br[1].justified().epoch, 0, "{}", summary(&br));
}

// ── 5. Late-joining branch after finality ─────────────────────────────────
//
// Epochs 2..=3: all four vote A, A finalizes (2, a_cp); B (forked at epoch
// 1, before that checkpoint) has blocks but no votes. From epoch 4: v0,v1
// stay on A, v2,v3 move to B and vote B's checkpoints sourcing B's justified
// checkpoint (epoch 0). Runs until B finalizes (<= HORIZON).

fn s5() -> Vec<Branch> {
    let mut br = l2_split(&["A", "B"]);
    let before = |c: usize| if c == 0 { vec![(0, 0), (1, 0), (2, 0), (3, 0)] } else { vec![] };
    for e in 2..=3 {
        run_epoch(&mut br, e, &before);
    }
    let after = |c: usize| if c == 0 { vec![(0, 0), (1, 0)] } else { vec![(2, 1), (3, 1)] };
    let mut e = 4;
    while e < HORIZON && br[1].first_final.is_none() {
        run_epoch(&mut br, e, &after);
        e += 1;
    }
    close(&mut br, e);
    br
}

#[test]
fn today_late_joining_branch_finalizes_a_checkpoint_conflicting_with_the_finalized_one() {
    let _rules = mainnet_rules();
    let _claims = crate::params::native_claim_finality_test::open();
    let mut br = s5();
    let s = summary(&br);
    eprintln!("s5 (late join): {s}");
    let a_cp = br[0].cps[&2];
    assert_eq!(br[0].first_final.map(|f| f.1), Some(Cp { epoch: 2, root: a_cp }), "{s}");
    let (_, bf) = br[1].first_final.expect(&s);
    assert_eq!(bf.epoch, 9, "{s}");
    assert!(!br[1].own.contains(&a_cp) && !foreign(&br, 1, &bf.root), "B's finality does not descend from A's: {s}");
    // The moved votes surround their epoch-3 votes on A.
    let ev = crate::slashing::SlashingEvidence { first: br[0].vote_of(2, 3), second: br[1].vote_of(2, 4) };
    assert_eq!(ev.offense(), Ok(crate::slashing::SlashableOffense::SurroundVote));
    assert!(claim_pays(&mut br[0]) && claim_pays(&mut br[1]), "paid before and after the reversal");
}

#[test]
#[ignore = "post-fix (p1a frozen finality set, no leak in the denominator): un-ignore after merge"]
fn post_fix_late_joining_half_never_finalizes_against_the_finalized_checkpoint() {
    let _rules = mainnet_rules();
    let _claims = crate::params::native_claim_finality_test::open();
    let mut br = s5();
    assert_eq!(br[1].first_final, None, "{}", summary(&br));
    assert!(claim_pays(&mut br[0]));
    assert!(!claim_pays(&mut br[1]));
}

// ── 6. Votes with a stale source ──────────────────────────────────────────

/// One chain, all four validators. Epochs 2..=3 honest (finalizes 2); epoch
/// 4 every vote sources the fork-era checkpoint (epoch 0) instead of the
/// current justified (3): admitted by step 8, counted by nobody.
#[test]
fn today_stale_source_votes_are_admitted_but_never_counted() {
    let _rules = mainnet_rules();
    let mut br = l2_split(&["C"]);
    let stale = br[0].finalized();
    assert_eq!(stale.epoch, 0);
    let all = |_: usize| vec![(0, 0), (1, 0), (2, 0), (3, 0)];
    for e in 2..=3 {
        run_epoch(&mut br, e, &all);
    }
    run_epoch_with_source(&mut br, 4, &all, &|_, _| stale);
    assert_eq!(br[0].included.iter().filter(|a| a.data.source_epoch == 0 && a.data.target_epoch == 4).count(), 4);
    close(&mut br, 5);
    assert_eq!(br[0].justified().epoch, 3, "epoch 4 not justified: {}", summary(&br));
    assert_eq!(br[0].finalized().epoch, 2);
}
