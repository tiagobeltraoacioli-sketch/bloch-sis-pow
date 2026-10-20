// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deterministic multi-node partition harness over the REAL Genesis-4
//! transition (`Transition::apply_block` / `process_epoch` of this crate).
//!
//! DEV TOOLING ONLY. Nothing here is linked into a node; it is included by
//! `tests/partition.rs` and `examples/partition_sim.rs` through `#[path]`.
//!
//! # What is real and what is modelled
//!
//! Real (this crate's public API, unmodified): genesis, every block's state
//! transition including the attestation admission of step 8, the epoch
//! boundary (FFG tally, inactivity leak, leaked roster, quorum floor), the
//! proposer schedule (`schedule::proposer`), the committee partition
//! (`committees::epoch_committees`), RANDAO reveals and re-commits, and the
//! LMD-GHOST store (`forkchoice::Store::head`). Every activation gate is read
//! from `params` at whatever epoch the simulation is in, so the rules are the
//! rules of the branch the harness is compiled against.
//!
//! Modelled (mirrors `bloch-pos-node`'s engine, simplified):
//! - one node per validator, signatures accepted by a permissive verifier;
//! - per slot: deliver messages, fork choice, propose, deliver, fork choice,
//!   attest ("block early in the slot, attest after it", as Ethereum);
//! - attestation = `Engine::attest`: head = own head, source = rolled
//!   justified, target = own `checkpoint_root(e)` (last block strictly
//!   before the epoch's first slot);
//! - fork choice = `Engine::forkchoice_head`: `Store::head` from the canonical
//!   state's justified root, weights = canonical `active_validators()`. If
//!   that justified root is not a block the node holds, the engine finds no
//!   path and keeps its head (`needs_sync`); so does the harness ("stalled");
//! - finality latch = `Engine::ratchet_finalized` / `cut_below_finalized_latch`:
//!   a reorg whose common ancestor is below the node's own finalized height is
//!   refused and the branch dropped;
//! - slashing protection: a validator never signs a target epoch <= its last
//!   one, nor a source epoch below its last one, and proposes once per slot;
//! - network: per-phase partition groups, offline set, delivery delay (slots)
//!   inside a group, optional cross-partition attestation gossip (blocks stay
//!   inside the partition), and a full sync of each group when a phase starts
//!   (heal / reconnection).
//!
//! L2 claims are not executed (that needs a settlement fixture only the
//! crate's unit tests can build). The harness evaluates the consensus
//! predicate a claim is admitted under, as the native claim-finality rule
//! composes it: `withdrawal::record_finalized` (epochs only) and, from the
//! claim gate epoch ([`claim_gate_epoch`], `HF_CLAIM_GATE_EPOCH`), "the
//! finalized root is this chain's own checkpoint at that epoch". Both
//! predicates are always reported. The record is the common head at the
//! start of the split, i.e. a withdrawal both branches hold.
//!
//! # Activation epochs
//!
//! Gates are compile-time constants, so the harness warms a chain up to
//! `start_epoch` (one fully-attested block per epoch, finalizing each
//! epoch) and runs the scenario from there. Pick `start_epoch` at or above
//! the gate you want live (`PARTITION_START_EPOCH`, default 5860: above
//! ETH-paced leak 5700 and L2 5850).
//!
//! To evaluate a candidate whose gate is `u64::MAX` (inert), or any other
//! set of activation epochs, use `scripts/hf-verify/run-all.sh --override
//! NAME=EPOCH` (or `--arm NAME`, = start epoch): it copies the tree to a
//! scratch overlay, rewrites those `pub const` definitions there and runs the
//! harness against the overlay. The checked-in sources are never modified
//! and no consensus code carries a runtime switch.
#![allow(dead_code)]

use bloch_pos_committee::attestation::SignatureVerifier;
use bloch_pos_committee::forkchoice::{BlockTree, LatestMessage, Store};
use bloch_pos_committee::header::{BlockHeaderV4, BlockId, VERSION_G4};
use bloch_pos_committee::interfaces::{Checkpoint, ProposalEnvelope, StateReader, StateTransition};
use bloch_pos_committee::l2_settlement::withdrawal;
use bloch_pos_committee::state_root::EvmCommitment;
use bloch_pos_committee::{beacon, committees, derive, params, schedule};
use bloch_pos_committee::{
    epoch_of, Attestation, AttestationData, CommittedState, GenesisValidator, PosTransaction,
    RandaoChain, Transition, Validator, SLOTS_PER_EPOCH,
};
use sha3::{Digest, Sha3_256};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt::Write as _;
use std::sync::Arc;

pub type Root = [u8; 32];
const SPE: u64 = SLOTS_PER_EPOCH;
const SAT_PER_BLCH: u128 = 100_000_000;

/// Signatures are not under test here; the permissive verifier keeps the
/// harness free of the PQ stack, like every other test in this crate.
pub struct AcceptAll;
impl SignatureVerifier for AcceptAll {
    fn verify_with_key(&self, _: &[u8], _: &Root, _: &[u8]) -> bool {
        true
    }
}

fn h3(parts: &[&[u8]]) -> Root {
    let mut h = Sha3_256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

pub fn short(r: &Root) -> String {
    r[..4].iter().map(|b| format!("{b:02x}")).collect()
}

// ─── Configuration ───────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct NetConfig {
    /// Genesis stake per validator, in BLCH.
    pub stakes_blch: Vec<u64>,
    /// The epoch the scenario starts at (the warm-up finalizes up to here).
    pub start_epoch: u64,
}

/// Activation epoch of the native claim-finality rule ("the finalized root
/// is this chain's own checkpoint"), read from `HF_CLAIM_GATE_EPOCH`.
///
/// The harness does not execute L2 claims, it evaluates their predicate, so
/// it cannot read the branch's constant directly without failing to compile
/// on branches that do not define it. `scripts/hf-verify/run-all.sh` sets
/// the variable from the compiled branch's claim-finality constant
/// (`HF1_CLAIM_FINALITY_EPOCH` or `NATIVE_CLAIM_FINALITY_ACTIVATION_EPOCH`,
/// after any override);
/// unset or unparsable means inert (`u64::MAX`), the release behaviour.
pub fn claim_gate_epoch() -> u64 {
    std::env::var("HF_CLAIM_GATE_EPOCH").ok().and_then(|s| s.trim().parse().ok()).unwrap_or(u64::MAX)
}

/// `PARTITION_START_EPOCH` or 5860.
pub fn default_start_epoch() -> u64 {
    std::env::var("PARTITION_START_EPOCH").ok().and_then(|s| s.parse().ok()).unwrap_or(5_860)
}

#[derive(Clone, Debug)]
pub enum Dur {
    Epochs(u64),
    /// Until every group with an online member has a node whose head has
    /// finalized an epoch >= the phase's first epoch, then `then` more
    /// epochs; gives up after `max`.
    UntilEveryGroupFinalizes { max: u64, then: u64 },
}

#[derive(Clone, Debug)]
pub struct Phase {
    pub name: String,
    /// Gossip domains. Every validator must be in exactly one group or in
    /// `offline`.
    pub groups: Vec<Vec<u32>>,
    pub offline: Vec<u32>,
    /// Delivery delay inside a group, in slots (0 = same slot).
    pub delay: u64,
    /// Attestations gossip across groups (blocks do not): a branch that
    /// hears the other side's votes.
    pub cross_atts: bool,
    pub dur: Dur,
}

impl Phase {
    pub fn new(name: &str, groups: Vec<Vec<u32>>, dur: Dur) -> Self {
        Phase { name: name.into(), groups, offline: vec![], delay: 0, cross_atts: false, dur }
    }
    pub fn offline(mut self, v: Vec<u32>) -> Self {
        self.offline = v;
        self
    }
    pub fn delay(mut self, d: u64) -> Self {
        self.delay = d;
        self
    }
    pub fn cross_atts(mut self) -> Self {
        self.cross_atts = true;
        self
    }
}

#[derive(Clone, Debug)]
pub struct Scenario {
    pub name: String,
    pub net: NetConfig,
    pub phases: Vec<Phase>,
    /// Phase index at whose start the claim record (common head) is taken.
    pub claim_phase: usize,
    /// Print a status line every `heartbeat` epochs (0 = only on change).
    pub heartbeat: u64,
}

// ─── The block store and the real transition ────────────────────────────────

#[derive(Clone)]
pub struct Block {
    pub id: Root,
    pub parent: Root,
    pub slot: u64,
    pub height: u64,
    pub proposer: u32,
    env: Option<ProposalEnvelope>,
    atts: Vec<Attestation>,
    txs: Vec<PosTransaction>,
    /// (RANDAO generation, reveals used) per validator, after this block.
    randao: Vec<(u32, u32)>,
    /// (validator, signing root) already carried in this block's epoch on
    /// this chain, so a producer does not re-include them.
    included: Arc<BTreeSet<(u32, Root)>>,
}

pub struct Rolled {
    pub state: CommittedState,
    pub roster: Vec<Validator>,
    pub seed: Root,
    pub partition: Vec<Vec<u32>>,
}

struct RandaoGen {
    commitment: Root,
    reveals: Vec<Root>,
}

#[derive(Default, Debug, Clone)]
pub struct Stats {
    pub blocks: u64,
    pub replays: u64,
    pub recommits: u64,
}

pub struct World {
    tr: Transition<AcceptAll>,
    pub n: u32,
    pub blocks: HashMap<Root, Block>,
    states: HashMap<Root, Arc<CommittedState>>,
    pinned: HashSet<Root>,
    rolled: HashMap<(Root, u64), Arc<Rolled>>,
    randao: HashMap<(u32, u32), Arc<RandaoGen>>,
    pub genesis: Root,
    /// Effective stake per validator at the scenario start (the 100% of
    /// the `w%` column).
    pub genesis_stake: Vec<u64>,
    pub stats: Stats,
}

impl World {
    pub fn new(net: &NetConfig) -> Self {
        let n = net.stakes_blch.len() as u32;
        let mut w = World {
            tr: Transition::new(AcceptAll),
            n,
            blocks: HashMap::new(),
            states: HashMap::new(),
            pinned: HashSet::new(),
            rolled: HashMap::new(),
            randao: HashMap::new(),
            genesis: [0; 32],
            genesis_stake: vec![],
            stats: Stats::default(),
        };
        let vals: Vec<GenesisValidator> = (0..n)
            .map(|i| GenesisValidator {
                index: i,
                pubkey: h3(&[b"P7A:PK", &i.to_le_bytes()]).to_vec(),
                staked_sat: net.stakes_blch[i as usize] as u128 * SAT_PER_BLCH,
                randao_commitment: w.gen(i, 0).commitment,
                withdrawal_credentials: vec![i as u8; 20],
                commission_bps: 500,
            })
            .collect();
        let gh = BlockHeaderV4 {
            version: VERSION_G4,
            parent: [0; 32],
            state_root: [0; 32],
            body_root: [0; 32],
            slot: 0,
            proposer_index: 0,
            randao_reveal: [0; 32],
            randao_mix: [0; 32],
            justified_root: [0; 32],
            finalized_root: [0; 32],
            attestation_root: [0; 32],
            coherence_root: [0; 32],
        };
        let gid = BlockId::of(&gh);
        let st = CommittedState::genesis(
            gid,
            [0; 32],
            &vals,
            &[],
            [0x11; 32],
            [0x22; 32],
            [0x33; 32],
            EvmCommitment { account_root: [0x44; 32], receipts_root: [0x55; 32], gas_used: 0, base_fee_per_gas: 1 },
            &[],
        );
        let g = *gid.as_bytes();
        assert_eq!(st.head().as_bytes(), &g);
        w.genesis_stake = (0..n)
            .map(|i| st.active_validators().iter().find(|v| v.index == i).map_or(0, |v| v.effective_stake))
            .collect();
        w.genesis = g;
        w.blocks.insert(
            g,
            Block {
                id: g,
                parent: [0; 32],
                slot: 0,
                height: 0,
                proposer: 0,
                env: None,
                atts: vec![],
                txs: vec![],
                randao: vec![(0, 0); n as usize],
                included: Arc::new(BTreeSet::new()),
            },
        );
        w.states.insert(g, Arc::new(st));
        w.pinned.insert(g);
        w
    }

    fn gen(&mut self, v: u32, g: u32) -> Arc<RandaoGen> {
        self.randao
            .entry((v, g))
            .or_insert_with(|| {
                let mut c = RandaoChain::generate(h3(&[b"P7A:RANDAO", &v.to_le_bytes(), &g.to_le_bytes()]));
                let commitment = c.commitment();
                let mut reveals = Vec::with_capacity(params::RANDAO_CHAIN_LENGTH as usize);
                while let Some(r) = c.next_reveal() {
                    reveals.push(r);
                }
                Arc::new(RandaoGen { commitment, reveals })
            })
            .clone()
    }

    pub fn state(&mut self, id: &Root) -> Arc<CommittedState> {
        if let Some(s) = self.states.get(id) {
            return s.clone();
        }
        let mut path = vec![];
        let mut cur = *id;
        while !self.states.contains_key(&cur) {
            path.push(cur);
            cur = self.blocks[&cur].parent;
        }
        let mut st = self.states[&cur].clone();
        for b in path.into_iter().rev() {
            let blk = &self.blocks[&b];
            let next = self
                .tr
                .apply_block(&st, blk.env.as_ref().expect("non-genesis"), &blk.atts, &blk.txs)
                .expect("replay of a stored block");
            st = Arc::new(next);
            self.stats.replays += 1;
            self.states.insert(b, st.clone());
        }
        st
    }

    /// `Engine::rolled_to` + the duty view derived from it.
    pub fn rolled(&mut self, id: &Root, epoch: u64) -> Arc<Rolled> {
        if let Some(r) = self.rolled.get(&(*id, epoch)) {
            return r.clone();
        }
        let base = self.state(id);
        let mut st = (*base).clone();
        let mut cur = epoch_of(st.slot());
        while cur < epoch {
            st = self.tr.process_epoch(&st).expect("process_epoch is infallible");
            cur += 1;
        }
        let roster = st.active_validators();
        let seed = st.seed_for_epoch(epoch);
        let partition = committees::epoch_committees(&seed, epoch, &roster);
        let r = Arc::new(Rolled { state: st, roster, seed, partition });
        self.rolled.insert((*id, epoch), r.clone());
        r
    }

    pub fn height(&self, id: &Root) -> u64 {
        self.blocks[id].height
    }

    /// `a` is `b` or an ancestor of `b`.
    pub fn is_ancestor(&self, a: &Root, b: &Root) -> bool {
        let (Some(ba), Some(_)) = (self.blocks.get(a), self.blocks.get(b)) else { return false };
        let mut cur = *b;
        loop {
            let blk = &self.blocks[&cur];
            if blk.height <= ba.height {
                return cur == *a;
            }
            cur = blk.parent;
        }
    }

    pub fn common_ancestor(&self, a: &Root, b: &Root) -> Root {
        let (mut x, mut y) = (*a, *b);
        while x != y {
            let (hx, hy) = (self.blocks[&x].height, self.blocks[&y].height);
            if hx >= hy {
                x = self.blocks[&x].parent;
            }
            if hy >= hx {
                y = self.blocks[&y].parent;
            }
        }
        x
    }

    /// `Engine::checkpoint_root` on the chain ending at `head`.
    pub fn checkpoint_root(&self, head: &Root, epoch: u64) -> Root {
        let first = epoch * SPE;
        let mut cur = *head;
        loop {
            let b = &self.blocks[&cur];
            if b.slot < first || b.height == 0 {
                return cur;
            }
            cur = b.parent;
        }
    }

    /// Build, transition and store the block `proposer` makes at `slot` on
    /// `parent` carrying `atts`. Two passes, as a producer does: probe for the
    /// state root, then the real `apply_block`.
    pub fn build(&mut self, parent: &Root, slot: u64, proposer: u32, atts: Vec<Attestation>) -> Result<Root, String> {
        let pre = self.state(parent);
        let e = epoch_of(slot);
        let r = self.rolled(parent, e);
        let pb = self.blocks[parent].clone();
        let (g, used) = pb.randao[proposer as usize];
        let chain = self.gen(proposer, g);
        let reveal = *chain.reveals.get(used as usize).ok_or("randao chain spent")?;
        let mut randao = pb.randao.clone();
        let mut txs = vec![];
        if used + 1 == params::RANDAO_CHAIN_LENGTH {
            // The proposer spends its last reveal in this block, so its chain
            // is exhausted by step 10 and the re-commit is admissible here.
            let next = self.gen(proposer, g + 1);
            txs.push(PosTransaction::RandaoRecommit {
                validator: proposer,
                new_commitment: next.commitment,
                epoch: e,
                signature: vec![0u8; 96],
            });
            randao[proposer as usize] = (g + 1, 0);
            self.stats.recommits += 1;
        } else {
            randao[proposer as usize] = (g, used + 1);
        }
        let fin = r.state.finality();
        let tx_bytes: Vec<Vec<u8>> = txs.iter().map(PosTransaction::canonical_bytes).collect();
        let mut header = BlockHeaderV4 {
            version: VERSION_G4,
            parent: *parent,
            state_root: [0; 32],
            body_root: derive::body_root(&tx_bytes),
            slot,
            proposer_index: proposer,
            randao_reveal: reveal,
            randao_mix: beacon::mix_in(&r.state.randao_mix(), &reveal),
            justified_root: fin.justified.root,
            finalized_root: fin.finalized.root,
            attestation_root: derive::attestation_root(&atts),
            coherence_root: pre.coherence_root(),
        };
        let probe = ProposalEnvelope { header, proposer_sig: vec![0u8; 8] };
        let post = self.tr.compute_post_state(&pre, &probe, &atts, &txs).map_err(|e| format!("probe: {e:?}"))?;
        header.state_root = post.state_root();
        let env = ProposalEnvelope { header, proposer_sig: vec![0u8; 8] };
        let post = self.tr.apply_block(&pre, &env, &atts, &txs).map_err(|e| format!("apply: {e:?}"))?;
        let id = *post.head().as_bytes();
        let mut included = if epoch_of(pb.slot) == e && pb.height > 0 { (*pb.included).clone() } else { BTreeSet::new() };
        for a in &atts {
            included.insert((a.validator, a.data.signing_root()));
        }
        self.blocks.insert(
            id,
            Block {
                id,
                parent: *parent,
                slot,
                height: pb.height + 1,
                proposer,
                env: Some(env),
                atts,
                txs,
                randao,
                included: Arc::new(included),
            },
        );
        self.states.insert(id, Arc::new(post));
        self.stats.blocks += 1;
        Ok(id)
    }

    /// One fully-attested block at the last slot of every epoch up to
    /// `start_epoch`: every epoch justifies and the previous one finalizes.
    pub fn warmup(&mut self, start_epoch: u64) -> Root {
        let mut head = self.genesis;
        for e in 0..start_epoch {
            let slot = e * SPE + SPE - 1;
            let r = self.rolled(&head, e);
            let p = schedule::proposer(&r.seed, slot, &r.roster).expect("proposer");
            let mut atts = vec![];
            if e > 0 {
                let fin = r.state.finality();
                for (i, committee) in r.partition.iter().enumerate() {
                    for &v in committee {
                        atts.push(Attestation {
                            data: AttestationData {
                                slot: e * SPE + i as u64,
                                head,
                                source_epoch: fin.justified.epoch,
                                source_root: fin.justified.root,
                                target_epoch: e,
                                target_root: head,
                            },
                            validator: v,
                            signature: vec![],
                        });
                    }
                }
            }
            head = self.build(&head, slot, p, atts).unwrap_or_else(|err| panic!("warm-up epoch {e}: {err}"));
            if e % 64 == 0 {
                self.evict(&[head], slot);
            }
        }
        self.pinned.insert(head);
        head
    }

    /// Drop cached states that are not needed; any of them can be replayed.
    pub fn evict(&mut self, keep: &[Root], now_slot: u64) {
        let floor = now_slot.saturating_sub(2 * SPE);
        let keep: HashSet<Root> = keep.iter().copied().collect();
        let blocks = &self.blocks;
        let pinned = &self.pinned;
        self.states.retain(|id, _| pinned.contains(id) || keep.contains(id) || blocks[id].slot >= floor);
        self.rolled.clear();
    }
}

// ─── Nodes ──────────────────────────────────────────────────────────────────

pub struct Node {
    pub v: u32,
    known: HashSet<Root>,
    refused: HashSet<Root>,
    parents: HashMap<Root, Root>,
    children: HashMap<Root, Vec<Root>>,
    forks: HashSet<Root>,
    store: Store,
    pool: BTreeMap<(u32, Root), Attestation>,
    pub head: Root,
    pub latch: Option<(u64, Root)>,
    slow: bool,
    moved: bool,
    pub stalled: bool,
    last_vote: Option<(u64, u64)>,
    last_prop: Option<u64>,
    pub refusals: u64,
}

impl Node {
    fn new(v: u32, w: &World, tail: &[Root]) -> Self {
        let mut n = Node {
            v,
            known: HashSet::new(),
            refused: HashSet::new(),
            parents: HashMap::new(),
            children: HashMap::new(),
            forks: HashSet::new(),
            store: Store::new(),
            pool: BTreeMap::new(),
            head: *tail.last().unwrap(),
            latch: None,
            slow: true,
            moved: false,
            stalled: false,
            last_vote: None,
            last_prop: None,
            refusals: 0,
        };
        for id in tail {
            n.add(w, id);
        }
        n
    }

    fn add(&mut self, w: &World, id: &Root) {
        let b = &w.blocks[id];
        self.known.insert(*id);
        self.parents.insert(*id, b.parent);
        let kids = self.children.entry(b.parent).or_default();
        if let Err(pos) = kids.binary_search(id) {
            kids.insert(pos, *id);
        }
        if kids.len() >= 2 {
            self.forks.insert(b.parent);
            self.slow = true;
        }
        for a in &b.atts {
            self.store.observe(a.validator, LatestMessage { slot: a.data.slot, root: a.data.head });
        }
        if !self.slow && b.parent == self.head {
            self.head = *id;
            self.moved = true;
        } else {
            self.slow = true;
        }
    }

    /// Learn a block and whatever of its ancestry this node lacks (sync).
    fn learn_block(&mut self, w: &World, id: &Root) {
        if self.known.contains(id) || self.refused.contains(id) {
            return;
        }
        let mut path = vec![*id];
        let mut cur = w.blocks[id].parent;
        while !self.known.contains(&cur) {
            if self.refused.contains(&cur) || !w.blocks.contains_key(&cur) {
                return;
            }
            path.push(cur);
            cur = w.blocks[&cur].parent;
        }
        for b in path.into_iter().rev() {
            self.add(w, &b);
        }
    }

    fn learn_att(&mut self, a: &Attestation) {
        let key = (a.validator, a.data.signing_root());
        if self.pool.insert(key, a.clone()).is_none() {
            self.store.observe(a.validator, LatestMessage { slot: a.data.slot, root: a.data.head });
        }
    }

    /// `Engine::ratchet_finalized`.
    fn ratchet(&mut self, w: &mut World) {
        let fin = w.state(&self.head).finality().finalized;
        if !w.is_ancestor(&fin.root, &self.head) {
            return;
        }
        let h = w.height(&fin.root);
        if h == 0 {
            return;
        }
        match self.latch {
            Some((floor, _)) if floor >= h => {}
            _ => self.latch = Some((h, fin.root)),
        }
    }

    fn drop_subtree(&mut self, root: &Root) {
        if let Some(p) = self.parents.get(root).copied() {
            if let Some(k) = self.children.get_mut(&p) {
                k.retain(|c| c != root);
            }
        }
        let mut stack = vec![*root];
        while let Some(x) = stack.pop() {
            self.refused.insert(x);
            self.known.remove(&x);
            self.parents.remove(&x);
            if let Some(k) = self.children.remove(&x) {
                stack.extend(k);
            }
        }
    }

    /// `Engine::advance`: fork choice, latch, adopt.
    fn update_head(&mut self, w: &mut World) {
        if self.moved {
            self.moved = false;
            self.ratchet(w);
            let j = w.state(&self.head).finality().justified.root;
            if !self.known.contains(&j) {
                self.slow = true;
            }
        }
        if !self.slow {
            return;
        }
        for _ in 0..64 {
            let st = w.state(&self.head);
            let justified = st.finality().justified.root;
            if !self.known.contains(&justified) {
                self.stalled = true;
                break;
            }
            self.stalled = false;
            let roster = st.active_validators();
            for i in 0..w.n {
                self.store.set_stake(i, roster.iter().find(|v| v.index == i).map_or(0, |v| v.effective_stake));
            }
            let tree = BlockTree { parents: &self.parents };
            let target = self.store.head(&tree, justified, &self.children);
            if target == self.head || !w.blocks.contains_key(&target) {
                break;
            }
            let anc = w.common_ancestor(&self.head, &target);
            if let Some((floor, _)) = self.latch {
                if w.height(&anc) < floor {
                    self.refusals += 1;
                    if anc == target {
                        break;
                    }
                    let mut c = target;
                    while w.blocks[&c].parent != anc {
                        c = w.blocks[&c].parent;
                    }
                    self.drop_subtree(&c);
                    continue;
                }
            }
            self.head = target;
            self.ratchet(w);
        }
        let js = {
            let j = w.state(&self.head).finality().justified.root;
            w.blocks.get(&j).map_or(0, |b| b.slot)
        };
        let children = &self.children;
        let blocks = &w.blocks;
        self.forks.retain(|f| children.get(f).is_some_and(|k| k.len() >= 2) && blocks[f].slot >= js);
        self.slow = !self.forks.is_empty() || self.stalled;
    }

    fn prune(&mut self, w: &World, epoch: u64) {
        let keep_from = epoch.saturating_sub(2);
        self.pool.retain(|_, a| epoch_of(a.data.slot) >= keep_from);
        if let Some((floor, _)) = self.latch {
            let old: Vec<Root> = self
                .parents
                .keys()
                .filter(|id| w.blocks[*id].height + 1 < floor)
                .copied()
                .collect();
            for id in old {
                self.parents.remove(&id);
                self.children.remove(&id);
            }
        }
    }
}

// ─── Simulation ─────────────────────────────────────────────────────────────

enum Msg {
    Block(Root),
    Att(Attestation),
}

struct Envelope {
    at: u64,
    from: u32,
    to: u32,
    msg: Msg,
}

#[derive(Clone, Debug, Default)]
pub struct GroupResult {
    pub members: Vec<u32>,
    pub first_justified: Option<u64>,
    pub first_finalized: Option<u64>,
    pub finalized: Option<Checkpoint>,
    pub finalized_own_chain: bool,
    pub claim_payable_from: Option<u64>,
    pub head: Root,
    /// Distinct branches among the group's online nodes at the phase end.
    pub branches: usize,
}

#[derive(Clone, Debug, Default)]
pub struct PhaseResult {
    pub name: String,
    pub start_epoch: u64,
    pub end_epoch: u64,
    pub groups: Vec<GroupResult>,
}

#[derive(Clone, Debug, Default)]
pub struct Report {
    pub scenario: String,
    pub start_epoch: u64,
    pub phases: Vec<PhaseResult>,
    pub conflicting_finality: Vec<String>,
    pub foreign_finality: Vec<String>,
    pub double_payout: Vec<String>,
    pub double_payout_own_chain_rule: Vec<String>,
    pub stalls: Vec<String>,
    pub latch_refusals: u64,
    pub final_heads: Vec<Root>,
    pub stats: Stats,
    pub log: String,
}

impl Report {
    /// Order-independent digest of the outcome, for the determinism check.
    pub fn digest(&self) -> Root {
        let mut s = String::new();
        let _ = write!(s, "{:?}", self.phases.iter().map(|p| (&p.name, p.end_epoch, p.groups.iter().map(|g| (g.first_finalized, g.finalized, g.head)).collect::<Vec<_>>())).collect::<Vec<_>>());
        let _ = write!(s, "{:?}{:?}{:?}", self.conflicting_finality, self.double_payout, self.final_heads);
        h3(&[s.as_bytes()])
    }

    pub fn summary(&self) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "== {} (start epoch {}) ==", self.scenario, self.start_epoch);
        for p in &self.phases {
            let _ = writeln!(s, "  phase {:<22} epochs {}..{} ({} epochs)", p.name, p.start_epoch, p.end_epoch, p.end_epoch - p.start_epoch);
            for g in &p.groups {
                let rel = |x: Option<u64>| x.map_or("never".to_string(), |e| format!("e{} (+{})", e, e - p.start_epoch));
                let fin = g.finalized.map_or("-".into(), |c| format!("e{}:{}{}", c.epoch, short(&c.root), if g.finalized_own_chain { "" } else { " FOREIGN" }));
                let _ = writeln!(
                    s,
                    "    group {:?}: justifies {} finalizes {} | last finalized {} | claim payable {} | head {} | branches at end {}",
                    g.members,
                    rel(g.first_justified),
                    rel(g.first_finalized),
                    fin,
                    rel(g.claim_payable_from),
                    short(&g.head),
                    g.branches
                );
            }
        }
        let first = |v: &Vec<String>| v.first().cloned().unwrap_or_else(|| "none".into());
        let _ = writeln!(s, "  conflicting finality : {} event(s); first: {}", self.conflicting_finality.len(), first(&self.conflicting_finality));
        let _ = writeln!(s, "  foreign finality     : {} event(s); first: {}", self.foreign_finality.len(), first(&self.foreign_finality));
        let _ = writeln!(s, "  claim double payout  : {} epoch(s) (consensus rule of this build); first: {}", self.double_payout.len(), first(&self.double_payout));
        let _ = writeln!(s, "  .. under own-chain rule: {} epoch(s); first: {}", self.double_payout_own_chain_rule.len(), first(&self.double_payout_own_chain_rule));
        let _ = writeln!(s, "  stalls (justified root unknown to node): {}; latch refusals: {}", self.stalls.len(), self.latch_refusals);
        let heads: BTreeSet<String> = self.final_heads.iter().map(short).collect();
        let _ = writeln!(s, "  final distinct heads: {} {:?}", heads.len(), heads);
        let _ = writeln!(s, "  blocks built {}, replays {}, randao re-commits {}", self.stats.blocks, self.stats.replays, self.stats.recommits);
        let _ = writeln!(s, "{}", self.machine_line());
        s
    }

    /// One `HFV key=value ...` line for `scripts/hf-verify/run-all.sh`.
    pub fn machine_line(&self) -> String {
        let heads: BTreeSet<Root> = self.final_heads.iter().copied().collect();
        let first_fin = |gi: usize| -> String {
            self.phases.get(1).and_then(|p| p.groups.get(gi)).and_then(|g| g.first_finalized).map_or("never".into(), |e| e.to_string())
        };
        let groups = self.phases.get(1).map_or(0, |p| p.groups.len());
        let fins: Vec<String> = (0..groups).map(first_fin).collect();
        // Entries start with "e<epoch>:"; report the first one's epoch.
        let first = |v: &Vec<String>| -> String {
            v.first().and_then(|m| m.strip_prefix('e')).and_then(|m| m.split(':').next()).unwrap_or("-").to_string()
        };
        format!(
            "HFV scenario={:?} start={} claim_gate={} conflicting_finality={} first_conflict_e={} foreign_finality={} double_pay={} first_double_pay_e={} double_pay_own_chain_rule={} stalls={} latch_refusals={} final_heads={} split_first_finalized=[{}] blocks={}",
            self.scenario,
            self.start_epoch,
            match claim_gate_epoch() { u64::MAX => "inert".to_string(), e => e.to_string() },
            self.conflicting_finality.len(),
            first(&self.conflicting_finality),
            self.foreign_finality.len(),
            self.double_payout.len(),
            first(&self.double_payout),
            self.double_payout_own_chain_rule.len(),
            self.stalls.len(),
            self.latch_refusals,
            heads.len(),
            fins.join(","),
            self.stats.blocks
        )
    }
}

pub struct Sim {
    pub w: World,
    pub nodes: Vec<Node>,
    queue: Vec<Envelope>,
    pub report: Report,
    verbose: bool,
}

/// Claim predicate of `CommittedState::l2_record_finalized_for_claim`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ClaimView {
    consensus: bool,
    own_chain: bool,
}

impl Sim {
    pub fn new(net: &NetConfig, verbose: bool) -> Self {
        let mut w = World::new(net);
        let tip = w.warmup(net.start_epoch);
        let mut tail = vec![tip];
        while tail.len() < 6 {
            let p = w.blocks[tail.last().unwrap()].parent;
            if !w.blocks.contains_key(&p) {
                break;
            }
            tail.push(p);
        }
        tail.reverse();
        let r = w.rolled(&tip, net.start_epoch);
        w.genesis_stake = (0..w.n).map(|i| r.roster.iter().find(|v| v.index == i).map_or(0, |v| v.effective_stake)).collect();
        let mut nodes: Vec<Node> = (0..w.n).map(|v| Node::new(v, &w, &tail)).collect();
        for n in &mut nodes {
            n.update_head(&mut w);
        }
        Sim { w, nodes, queue: vec![], report: Report::default(), verbose }
    }

    fn log(&mut self, line: String) {
        if self.verbose {
            println!("{line}");
        }
        self.report.log.push_str(&line);
        self.report.log.push('\n');
    }

    fn group_of(phase: &Phase, v: u32) -> Option<usize> {
        if phase.offline.contains(&v) {
            return None;
        }
        phase.groups.iter().position(|g| g.contains(&v))
    }

    fn send(&mut self, phase: &Phase, t: u64, from: u32, msg: Msg) {
        let Some(gf) = Self::group_of(phase, from) else { return };
        let is_att = matches!(msg, Msg::Att(_));
        let targets: Vec<u32> = (0..self.w.n)
            .filter(|&to| to != from)
            .filter(|&to| match Self::group_of(phase, to) {
                Some(gt) => gt == gf || (is_att && phase.cross_atts),
                None => false,
            })
            .collect();
        for to in targets {
            let m = match &msg {
                Msg::Block(b) => Msg::Block(*b),
                Msg::Att(a) => Msg::Att(a.clone()),
            };
            self.queue.push(Envelope { at: t + phase.delay, from, to, msg: m });
        }
    }

    fn deliver(&mut self, phase: &Phase, t: u64) {
        let due: Vec<Envelope>;
        (due, self.queue) = std::mem::take(&mut self.queue).into_iter().partition(|m| m.at <= t);
        for m in due {
            let (Some(gf), Some(gt)) = (Self::group_of(phase, m.from), Self::group_of(phase, m.to)) else { continue };
            let node = &mut self.nodes[m.to as usize];
            match m.msg {
                Msg::Block(b) if gf == gt => node.learn_block(&self.w, &b),
                Msg::Att(a) if gf == gt || phase.cross_atts => node.learn_att(&a),
                _ => {}
            }
        }
    }

    /// Phase start: every group exchanges everything its members hold.
    fn sync_groups(&mut self, phase: &Phase) {
        for g in &phase.groups {
            let online: Vec<u32> = g.iter().copied().filter(|v| !phase.offline.contains(v)).collect();
            let mut blocks: Vec<Root> = online.iter().flat_map(|v| self.nodes[*v as usize].known.iter().copied()).collect::<HashSet<_>>().into_iter().collect();
            blocks.sort_by_key(|b| (self.w.blocks[b].height, *b));
            let atts: Vec<Attestation> = online.iter().flat_map(|v| self.nodes[*v as usize].pool.values().cloned()).collect();
            for v in &online {
                let node = &mut self.nodes[*v as usize];
                for b in &blocks {
                    node.learn_block(&self.w, b);
                }
                for a in &atts {
                    node.learn_att(a);
                }
            }
        }
    }

    fn propose(&mut self, phase: &Phase, t: u64) {
        let e = epoch_of(t);
        for v in 0..self.w.n {
            if Self::group_of(phase, v).is_none() {
                continue;
            }
            let head = self.nodes[v as usize].head;
            if self.w.blocks[&head].slot >= t || self.nodes[v as usize].last_prop == Some(t) {
                continue;
            }
            let r = self.w.rolled(&head, e);
            if schedule::proposer(&r.seed, t, &r.roster) != Some(v) {
                continue;
            }
            let included = self.w.blocks[&head].included.clone();
            let same_epoch = epoch_of(self.w.blocks[&head].slot) == e;
            let mut atts: Vec<Attestation> = self.nodes[v as usize]
                .pool
                .iter()
                .filter(|((_, sr), a)| {
                    epoch_of(a.data.slot) == e
                        && a.data.slot <= t
                        && a.data.source_epoch < a.data.target_epoch
                        && !(same_epoch && included.contains(&(a.validator, *sr)))
                        && r.partition.get((a.data.slot % SPE) as usize).is_some_and(|c| c.binary_search(&a.validator).is_ok())
                })
                .map(|(_, a)| a.clone())
                .collect();
            atts.sort_by_key(|a| (a.data.slot, a.validator, a.data.signing_root()));
            atts.truncate(params::MAX_ATTESTATIONS_PER_BLOCK);
            self.nodes[v as usize].last_prop = Some(t);
            if std::env::var("PARTITION_DEBUG").is_ok() {
                let foreign = atts.iter().filter(|a| !self.w.is_ancestor(&a.data.target_root, &head)).count();
                println!("dbg t{t} v{v} head {} atts {} foreign-target {} pool {}", short(&head), atts.len(), foreign, self.nodes[v as usize].pool.len());
            }
            match self.w.build(&head, t, v, atts) {
                Ok(id) => {
                    self.nodes[v as usize].learn_block(&self.w, &id);
                    self.send(phase, t, v, Msg::Block(id));
                }
                Err(err) => {
                    let line = format!("  !! e{e} slot {t}: validator {v} could not build: {err}");
                    self.log(line);
                }
            }
        }
    }

    fn attest(&mut self, phase: &Phase, t: u64) {
        let e = epoch_of(t);
        if e == 0 {
            return;
        }
        for v in 0..self.w.n {
            if Self::group_of(phase, v).is_none() {
                continue;
            }
            let head = self.nodes[v as usize].head;
            let r = self.w.rolled(&head, e);
            let on_duty = r.partition.get((t % SPE) as usize).is_some_and(|c| c.binary_search(&v).is_ok());
            if !on_duty {
                continue;
            }
            let fin = r.state.finality();
            let data = AttestationData {
                slot: t,
                head,
                source_epoch: fin.justified.epoch,
                source_root: fin.justified.root,
                target_epoch: e,
                target_root: self.w.checkpoint_root(&head, e),
            };
            if data.source_epoch >= data.target_epoch {
                continue;
            }
            let node = &mut self.nodes[v as usize];
            if let Some((s, tg)) = node.last_vote {
                if data.target_epoch <= tg || data.source_epoch < s {
                    continue;
                }
            }
            node.last_vote = Some((data.source_epoch, data.target_epoch));
            let att = Attestation { data, validator: v, signature: vec![] };
            node.learn_att(&att);
            self.send(phase, t, v, Msg::Att(att));
        }
    }

    fn heads_update(&mut self, phase: &Phase) {
        for v in 0..self.w.n {
            if Self::group_of(phase, v).is_some() {
                self.nodes[v as usize].update_head(&mut self.w);
            }
        }
    }

    fn claim_view(&mut self, record: &Root, head: &Root) -> Option<ClaimView> {
        if !self.w.is_ancestor(record, head) {
            return None;
        }
        let st = self.w.state(head);
        let fin = st.finality().finalized;
        let tip_h = self.w.height(head);
        let rec_h = self.w.height(record);
        let base = withdrawal::record_finalized(rec_h, tip_h, st.slot(), fin.epoch);
        let own = base && self.w.checkpoint_root(head, fin.epoch) == fin.root;
        let gated = params::epoch_gate_active(epoch_of(st.slot()), claim_gate_epoch());
        Some(ClaimView { consensus: if gated { own } else { base }, own_chain: own })
    }

    pub fn run(scn: &Scenario, verbose: bool) -> Report {
        let mut sim = Sim::new(&scn.net, verbose);
        sim.report.scenario = scn.name.clone();
        sim.report.start_epoch = scn.net.start_epoch;
        let stakes: Vec<String> = sim.w.genesis_stake.iter().map(|s| format!("{}", *s as u128 / SAT_PER_BLCH)).collect();
        let line = format!(
            "== {} : {} validators, effective stake at start (BLCH) {:?}, warm-up to epoch {} ({} blocks) ==",
            scn.name, sim.w.n, stakes, scn.net.start_epoch, sim.w.stats.blocks
        );
        sim.log(line);
        let mut epoch = scn.net.start_epoch;
        let mut record: Option<Root> = None;
        let mut seen_final: Vec<(Checkpoint, u32)> = vec![];
        let mut prev_line: Vec<String> = vec![];
        for (pi, phase) in scn.phases.iter().enumerate() {
            let mut covered: Vec<u32> = phase.groups.iter().flatten().chain(phase.offline.iter()).copied().collect();
            covered.sort_unstable();
            covered.dedup();
            assert_eq!(covered, (0..sim.w.n).collect::<Vec<_>>(), "phase {} must place every validator", phase.name);
            sim.sync_groups(phase);
            sim.heads_update(phase);
            if pi == scn.claim_phase {
                record = Some(sim.nodes[0].head);
            }
            let start = epoch;
            let line = format!(
                "-- phase '{}' from e{}: groups {:?} offline {:?} delay {} cross-atts {}",
                phase.name, start, phase.groups, phase.offline, phase.delay, phase.cross_atts
            );
            sim.log(line);
            let mut groups: Vec<GroupResult> = phase.groups.iter().map(|g| GroupResult { members: g.clone(), ..Default::default() }).collect();
            let (max, then) = match phase.dur {
                Dur::Epochs(n) => (n, 0),
                Dur::UntilEveryGroupFinalizes { max, then } => (max, then),
            };
            let mut done_at: Option<u64> = None;
            while epoch < start + max {
                if let Some(d) = done_at {
                    if epoch >= d + then {
                        break;
                    }
                }
                for t in epoch * SPE..(epoch + 1) * SPE {
                    sim.deliver(phase, t);
                    sim.heads_update(phase);
                    sim.propose(phase, t);
                    sim.deliver(phase, t);
                    sim.heads_update(phase);
                    sim.attest(phase, t);
                    sim.deliver(phase, t);
                }
                // ── end of epoch: observe ──
                let mut lines = vec![];
                let mut claim_pay: Vec<(u32, Root, ClaimView)> = vec![];
                for (gi, g) in phase.groups.iter().enumerate() {
                    let online: Vec<u32> = g.iter().copied().filter(|v| !phase.offline.contains(v)).collect();
                    if online.is_empty() {
                        continue;
                    }
                    let mut best: Option<(u64, u32)> = None;
                    for &v in &online {
                        let head = sim.nodes[v as usize].head;
                        let st = sim.w.state(&head);
                        let f = st.finality();
                        if sim.nodes[v as usize].stalled {
                            let line = format!("e{epoch} node {v} stalled: justified {} unknown", short(&f.justified.root));
                            if sim.report.stalls.len() < 50 {
                                sim.report.stalls.push(line);
                            }
                        }
                        // Finality bookkeeping, conflicting and foreign.
                        if f.finalized.epoch >= scn.net.start_epoch.saturating_sub(2) && !seen_final.iter().any(|(c, _)| *c == f.finalized) {
                            for (c, by) in seen_final.clone() {
                                let (lo, hi) = if c.epoch <= f.finalized.epoch { (c, f.finalized) } else { (f.finalized, c) };
                                if !sim.w.is_ancestor(&lo.root, &hi.root) {
                                    sim.report.conflicting_finality.push(format!(
                                        "e{epoch}: node {v} finalized e{}:{} conflicting with e{}:{} (node {by})",
                                        f.finalized.epoch, short(&f.finalized.root), c.epoch, short(&c.root)
                                    ));
                                }
                            }
                            seen_final.push((f.finalized, v));
                        }
                        let own = sim.w.is_ancestor(&f.finalized.root, &head);
                        if !own {
                            let msg = format!("e{epoch}: node {v} finalized e{}:{} which is not on its own chain", f.finalized.epoch, short(&f.finalized.root));
                            if !sim.report.foreign_finality.iter().any(|m| m.ends_with(&msg[msg.find(':').unwrap()..])) {
                                sim.report.foreign_finality.push(msg);
                            }
                        }
                        let gr = &mut groups[gi];
                        if f.justified.epoch >= start && gr.first_justified.is_none() {
                            gr.first_justified = Some(epoch);
                        }
                        if f.finalized.epoch >= start && gr.first_finalized.is_none() {
                            gr.first_finalized = Some(epoch);
                            let line = format!(
                                "   e{epoch} (+{}): group {:?} FINALIZES e{}:{} ({})",
                                epoch - start, g, f.finalized.epoch, short(&f.finalized.root), if own { "own chain" } else { "FOREIGN checkpoint" }
                            );
                            sim.log(line);
                        }
                        if best.is_none_or(|(fe, _)| f.finalized.epoch > fe) {
                            best = Some((f.finalized.epoch, v));
                            gr.finalized = Some(f.finalized);
                            gr.finalized_own_chain = own;
                            gr.head = head;
                        }
                        if let Some(rec) = record {
                            if let Some(cv) = sim.claim_view(&rec, &head) {
                                if cv.consensus && gr.claim_payable_from.is_none() {
                                    gr.claim_payable_from = Some(epoch);
                                }
                                claim_pay.push((v, head, cv));
                            }
                        }
                    }
                    // One timeline entry per branch inside the group: members
                    // sharing this epoch's checkpoint root are on one branch.
                    let mut clusters: BTreeMap<Root, Vec<u32>> = BTreeMap::new();
                    for &v in &online {
                        let head = sim.nodes[v as usize].head;
                        clusters.entry(sim.w.checkpoint_root(&head, epoch)).or_default().push(v);
                    }
                    groups[gi].branches = clusters.len();
                    for members in clusters.values() {
                        let head = sim.nodes[members[0] as usize].head;
                        let st = sim.w.state(&head);
                        let f = st.finality();
                        let r = sim.w.rolled(&head, epoch);
                        let w: Vec<String> = (0..sim.w.n)
                            .map(|i| {
                                let s = r.roster.iter().find(|x| x.index == i).map_or(0, |x| x.effective_stake);
                                let g0 = sim.w.genesis_stake[i as usize].max(1);
                                format!("{}", (s as u128 * 100 / g0 as u128))
                            })
                            .collect();
                        lines.push(format!("{:?} j=e{} f=e{} w%=[{}]", members, f.justified.epoch, f.finalized.epoch, w.join(",")));
                    }
                    let _ = best;
                }
                // Claim double payout: two groups, conflicting heads, both payable.
                for (i, a) in claim_pay.iter().enumerate() {
                    for b in &claim_pay[i + 1..] {
                        if sim.w.is_ancestor(&a.1, &b.1) || sim.w.is_ancestor(&b.1, &a.1) {
                            continue;
                        }
                        if a.2.consensus && b.2.consensus {
                            let m = format!("e{epoch}: nodes {} and {} (conflicting heads {} / {})", a.0, b.0, short(&a.1), short(&b.1));
                            if !sim.report.double_payout.iter().any(|x| x.starts_with(&format!("e{epoch}:"))) {
                                sim.report.double_payout.push(m);
                            }
                        }
                        if a.2.own_chain && b.2.own_chain {
                            let m = format!("e{epoch}: nodes {} and {} (conflicting heads {} / {})", a.0, b.0, short(&a.1), short(&b.1));
                            if !sim.report.double_payout_own_chain_rule.iter().any(|x| x.starts_with(&format!("e{epoch}:"))) {
                                sim.report.double_payout_own_chain_rule.push(m);
                            }
                        }
                    }
                }
                let changed = lines.iter().map(|l| l.split(" w%").next().unwrap().to_string()).collect::<Vec<_>>() != prev_line;
                if changed || (scn.heartbeat > 0 && (epoch - start) % scn.heartbeat == 0) {
                    let line = format!("  e{epoch} (+{}) {}", epoch - start, lines.join(" | "));
                    sim.log(line);
                    prev_line = lines.iter().map(|l| l.split(" w%").next().unwrap().to_string()).collect();
                }
                if done_at.is_none() && matches!(phase.dur, Dur::UntilEveryGroupFinalizes { .. }) {
                    let all = groups.iter().zip(&phase.groups).all(|(gr, g)| gr.first_finalized.is_some() || g.iter().all(|v| phase.offline.contains(v)));
                    if all {
                        done_at = Some(epoch + 1);
                    }
                }
                epoch += 1;
                for v in 0..sim.w.n {
                    let n = &mut sim.nodes[v as usize];
                    n.prune(&sim.w, epoch);
                }
                let keep: Vec<Root> = sim.nodes.iter().map(|n| n.head).collect();
                sim.w.evict(&keep, epoch * SPE);
            }
            sim.report.phases.push(PhaseResult { name: phase.name.clone(), start_epoch: start, end_epoch: epoch, groups });
        }
        sim.report.latch_refusals = sim.nodes.iter().map(|n| n.refusals).sum();
        sim.report.final_heads = sim.nodes.iter().map(|n| n.head).collect();
        sim.report.stats = sim.w.stats.clone();
        sim.report
    }
}

// ─── Scenarios ──────────────────────────────────────────────────────────────

fn all(n: u32) -> Vec<u32> {
    (0..n).collect()
}

fn net(stakes: Vec<u64>, start_epoch: u64) -> NetConfig {
    NetConfig { stakes_blch: stakes, start_epoch }
}

/// Names accepted by [`scenario`].
pub const SCENARIOS: &[&str] = &["split2", "split3", "split50", "offline", "heal-both", "solo3", "votes-cross", "delay"];

/// `max` caps every open-ended phase (epochs).
pub fn scenario(name: &str, start_epoch: u64, max: u64) -> Option<Scenario> {
    let until = Dur::UntilEveryGroupFinalizes { max, then: 2 };
    let s = match name {
        // 60/40 split, run until both sides finalize (or `max`), then heal.
        "split2" => Scenario {
            name: "2-way split 60/40 (5 equal validators)".into(),
            net: net(vec![1_000; 5], start_epoch),
            phases: vec![
                Phase::new("connected", vec![all(5)], Dur::Epochs(3)),
                Phase::new("split 3|2", vec![vec![0, 1, 2], vec![3, 4]], until),
                Phase::new("healed", vec![all(5)], Dur::Epochs(8)),
            ],
            claim_phase: 1,
            heartbeat: 250,
        },
        // Three equal thirds.
        "split3" => Scenario {
            name: "3-way split 1/3 each (6 equal validators)".into(),
            net: net(vec![1_000; 6], start_epoch),
            phases: vec![
                Phase::new("connected", vec![all(6)], Dur::Epochs(3)),
                Phase::new("split 2|2|2", vec![vec![0, 1], vec![2, 3], vec![4, 5]], until),
                Phase::new("healed", vec![all(6)], Dur::Epochs(8)),
            ],
            claim_phase: 1,
            heartbeat: 250,
        },
        // Exact 50/50 by stake and by count: neither side holds 2/3, so
        // finality on either side can only come from the inactivity leak.
        "split50" => Scenario {
            name: "2-way split 50/50 (4 equal validators)".into(),
            net: net(vec![1_000; 4], start_epoch),
            phases: vec![
                Phase::new("connected", vec![all(4)], Dur::Epochs(3)),
                Phase::new("split 2|2", vec![vec![0, 1], vec![2, 3]], until),
                Phase::new("healed", vec![all(4)], Dur::Epochs(8)),
            ],
            claim_phase: 1,
            heartbeat: 250,
        },
        // 40% offline (no partition): the online 60% must leak them out.
        "offline" => Scenario {
            name: "40% offline, 60% connected (5 equal validators)".into(),
            net: net(vec![1_000; 5], start_epoch),
            phases: vec![
                Phase::new("connected", vec![all(5)], Dur::Epochs(3)),
                Phase::new("2 of 5 offline", vec![vec![0, 1, 2], vec![3], vec![4]], until).offline(vec![3, 4]),
                Phase::new("back online", vec![all(5)], Dur::Epochs(8)),
            ],
            claim_phase: 1,
            heartbeat: 250,
        },
        // Unequal 50/50 by stake with unequal counts; heal only after both
        // sides have finalized on their own.
        "heal-both" => Scenario {
            name: "50/50 split by stake, heal after both sides finalize".into(),
            net: net(vec![3_000, 1_000, 1_000, 1_000], start_epoch),
            phases: vec![
                Phase::new("connected", vec![all(4)], Dur::Epochs(3)),
                Phase::new("split {0}|{1,2,3}", vec![vec![0], vec![1, 2, 3]], until),
                Phase::new("healed", vec![all(4)], Dur::Epochs(16)),
            ],
            claim_phase: 1,
            heartbeat: 250,
        },
        // Three validators, each alone.
        "solo3" => Scenario {
            name: "3 validators, each alone".into(),
            net: net(vec![1_000; 3], start_epoch),
            phases: vec![
                Phase::new("connected", vec![all(3)], Dur::Epochs(3)),
                Phase::new("each alone", vec![vec![0], vec![1], vec![2]], until),
                Phase::new("healed", vec![all(3)], Dur::Epochs(8)),
            ],
            claim_phase: 1,
            heartbeat: 250,
        },
        // Blocks partitioned 70/30, votes cross.
        "votes-cross" => Scenario {
            name: "70/30 split, attestations cross the partition".into(),
            net: net(vec![1_000; 10], start_epoch),
            phases: vec![
                Phase::new("connected", vec![all(10)], Dur::Epochs(3)),
                Phase::new("split 7|3 + votes", vec![(0..7).collect(), (7..10).collect()], Dur::Epochs(12)).cross_atts(),
                Phase::new("healed", vec![all(10)], Dur::Epochs(6)),
            ],
            claim_phase: 1,
            heartbeat: 0,
        },
        // Connected but slow: 2-slot gossip delay, forks inside one network.
        "delay" => Scenario {
            name: "connected, 2-slot gossip delay (6 validators)".into(),
            net: net(vec![1_000; 6], start_epoch),
            phases: vec![
                Phase::new("connected", vec![all(6)], Dur::Epochs(2)),
                Phase::new("delay 2 slots", vec![all(6)], Dur::Epochs(12)).delay(2),
            ],
            claim_phase: 1,
            heartbeat: 0,
        },
        _ => return None,
    };
    Some(s)
}
