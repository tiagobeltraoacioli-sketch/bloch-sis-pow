// SPDX-License-Identifier: AGPL-3.0-or-later

//! The consensus engine: one thread owning all consensus state, driven by the
//! slot timer and by network events — nothing else mutates state
//! (integration plan §1.1). The wall clock enters exactly here, at the timer;
//! every rule below it is the pure crate's.
//!
//! ## Which composition seam this engine binds
//!
//! One, and now there is only one to bind. The pure crate used to ship a
//! second, complete block validator — `derive::validate_block`, over
//! `ParentState`/`ChainState`, with its own frozen error order and no caller.
//! It was deleted on 2026-08-12 (the checklist comparison is in `derive.rs`
//! where it stood); `derive` keeps only the shared derivation functions, which
//! `produce.rs` stamps with and `transition` checks against.
//!
//! This engine binds `Transition`/`CommittedState`: the seam that implements
//! the frozen `StateTransition`/`StateReader` traits, composes finality, and —
//! since 2026-08-12 — judges the header's body/attestation/coherence
//! commitments itself. The two `derive::*` root calls below are an early
//! cheap reject before a state clone, not a second opinion: they are the same
//! functions the transition checks with.
//!
//! ## Producer = validator, structurally
//!
//! The producer fills `state_root` by running `Transition::compute_post_state`
//! — the *same* function `apply_block` is defined as — on the same parent
//! state, then every block (own or peer) passes `apply_block` under the real
//! hybrid verifier before it is stored or broadcast. A node that rejects its
//! own block panics loudly: that is the h28080 seam and it must never be
//! shrugged past.
//!
//! ## Fork choice — LMD-GHOST
//!
//! Canonical is whatever [`forkchoice::Store::head`] selects: walk from the
//! **justified** checkpoint and take the heaviest child at every step, where
//! weight is the total effective stake of validators whose *latest* message is
//! that block or a descendant. `advance` then makes the canonical chain match
//! that head, extending when the head descends from it and reorganising (by
//! replaying from genesis — never trusting an unvalidated branch) when it does
//! not.
//!
//! This replaces longest-valid-chain, which resolved competing forks by whoever
//! extended first. That rule is not merely weaker, it is *wrong under PoS*: it
//! lets a proposer with no attested support drag the chain by building fast,
//! and it gives an attacker who can produce blocks a way to override a branch
//! the honest majority has already voted for. Length is not the security
//! statement in proof of stake; attested stake is.
//!
//! Two properties come from starting the walk at the justified checkpoint
//! rather than at genesis: finalised history can never be reorganised out, and
//! the walk is bounded by the unfinalised suffix instead of the whole chain.
//!
//! The store is **rebuilt from scratch on every head computation** rather than
//! carried as mutable node state. That is the §5.5 posture applied where it is
//! cheapest to get wrong: a cached fork-choice store is exactly the kind of
//! node-local mutable state that made two honest nodes disagree in the
//! `expected_bits` incident. Rebuilding is O(blocks x attestations) per call
//! and, on a devnet, free; when it stops being free the fix is an incremental
//! store with a test proving it equals the rebuild, not a cache with a comment.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bloch_pos_committee::attestation::{Attestation, AttestationData};
use bloch_pos_committee::beacon::{mix_in, RandaoChain};
use bloch_pos_committee::forkchoice::{BlockTree, LatestMessage, Store as FcStore};
use bloch_pos_committee::gossip::{AttestationPool, GossipDecision};
use bloch_pos_committee::header::{BlockEnvelope, BlockHeaderV4, BlockId, Body, VERSION_G4};
use bloch_pos_committee::interfaces::{ProposalEnvelope, StateReader, StateTransition};
use bloch_pos_committee::schedule::first_slot_of_epoch;
use bloch_pos_committee::transition::{CommittedState, PosTransaction, Transition};
use bloch_pos_committee::{committees, derive, epoch_of, schedule};

use crate::genesis::{Manifest, GENESIS_MIX};
use crate::keys::{HybridVerifier, Keystore, ProbeVerifier};
use crate::net::{self, EngineQueue, NetEvent, Origin, Verdict};
use crate::rpc::{self, Admitted, Finality, Json, RpcCall, RpcError, RpcRequest, RpcResult};
use crate::store::Store;

/// Everything that reaches the consensus thread from outside it.
///
/// One channel, three sources now: the two transports both feed `Net`, and the
/// RPC feeds `Rpc`. Answering a query from *inside* the thread that owns the
/// state — rather than from a copy kept alongside it — is why this wrapper
/// exists; see [`crate::rpc::EngineBackend`].
pub enum EngineEvent {
    /// A network event and its reservation in [`EngineQueue`]. The permit
    /// travels WITH the event and is dropped at the end of the match arm that
    /// handles it, so the quota measures work not yet done rather than events
    /// not yet dequeued — which is what the old hand-written counter claimed
    /// to do and did not.
    Net(NetEvent, net::Permit),
    Rpc(RpcCall),
}

/// Which transport the node runs.
///
/// `Devnet` is still the default: a 64-validator devnet across five hosts
/// finalized on it and that result must stay reproducible by running the same
/// command. `Libp2p` is the production stack (see [`crate::p2p`]) and is what
/// anything reachable from outside a firewall must use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    Devnet,
    Libp2p,
}

pub struct Config {
    pub data_dir: PathBuf,
    pub genesis_path: PathBuf,
    pub transport: Transport,
    /// Devnet transport: the TCP port the full mesh listens on.
    pub listen: u16,
    /// Devnet transport: the address the mesh listener binds. `127.0.0.1`
    /// unless `--listen-addr` says otherwise — see the warning on
    /// [`crate::net::start`] before binding anything routable.
    pub listen_addr: String,
    /// Devnet transport: `host:port` peers.
    pub peers: Vec<String>,
    /// libp2p transport: multiaddrs to listen on.
    pub p2p_listen: Vec<String>,
    /// libp2p transport: multiaddrs to dial (`/ip4/…/tcp/…/p2p/<peer-id>`).
    pub p2p_peers: Vec<String>,
    /// libp2p transport: connection ceiling.
    pub max_peers: usize,
    /// libp2p transport: zero the IP-colocation score penalty.
    pub behind_proxy: bool,
    pub stop_at_slot: Option<u64>,
    pub ws: crate::ws_boot::WsConfig,
    /// The Genesis-3 balance snapshot, when the manifest commits to one. It is
    /// a separate file rather than a manifest field because it is tens of
    /// megabytes and the manifest is the thing every node hashes; the
    /// manifest's `CarryoverCommitment` is what binds the two together.
    /// Required exactly when the manifest carries a commitment — see the
    /// refusals at the top of [`run`].
    pub carryover_path: Option<PathBuf>,
    /// Address the JSON-RPC server binds, and its port. `127.0.0.1` unless
    /// `--rpc-bind` says otherwise: the RPC authenticates nothing, so a
    /// routable bind is an explicit act plus a firewall. `None` port disables
    /// the server entirely.
    pub rpc_bind: String,
    pub rpc_port: Option<u16>,
}

/// Forward libp2p's decoded events onto the engine channel, admitting each one
/// into [`EngineQueue`] on the way.
///
/// **This hop is the libp2p path's only ceiling.** `p2p::Loop::emit` sends into
/// an unbounded channel and counts nothing, so before this the production
/// transport had no admission control at all — while the engine's
/// hand-written decrement fired for its events anyway, subtracting from a
/// counter nobody had incremented and wrapping it to ~2^64.
///
/// Admitting here rather than inside `p2p.rs` keeps that module speaking plain
/// `NetEvent` — its tests read the raw events — and puts the quota on the one
/// thread both transports already pass through. This thread does nothing but
/// forward, so it is a hop and not a second queue in front of a sleeping
/// consumer.
///
/// A free function and not a closure so it can be tested: see
/// `libp2p_admission_tests`.
fn forward_admitted(
    net_rx: mpsc::Receiver<NetEvent>,
    tx: mpsc::Sender<EngineEvent>,
    queue: Arc<EngineQueue>,
) {
    for ev in net_rx {
        let bytes = ev.wire_bytes();
        let Some(permit) = EngineQueue::admit_event(&queue, &ev, bytes) else {
            continue; // shed: counted, and logged if the limiter allows
        };
        if tx.send(EngineEvent::Net(ev, permit)).is_err() {
            return; // engine gone; nothing left to deliver to
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

const NO_TXS: [PosTransaction; 0] = [];

/// Ceiling on mempool entries. Not a policy — a bound, so an unauthenticated
/// devnet transport cannot turn into unbounded memory. Real admission control
/// (fees, per-sender limits, eviction by price) is `gossip.rs` work.
const MEMPOOL_MAX: usize = 4_096;

/// Transactions a proposal will carry at most, independent of the consensus
/// byte cap it is also checked against.
const MAX_TXS_PER_BLOCK: usize = 256;

/// Decode a block body's transactions.
///
/// A receiver MUST recompute the post-state from the same transactions the
/// proposer committed to. Passing an empty slice here — which is what this
/// node did until now — means every block carrying transactions either
/// diverges or, since the body_root check landed, is rejected outright.
fn body_transactions(env: &BlockEnvelope) -> Result<Vec<PosTransaction>, String> {
    env.body
        .transactions
        .iter()
        .map(|bytes| {
            PosTransaction::from_canonical_bytes(bytes)
                .map_err(|e| format!("undecodable transaction in block body: {e}"))
        })
        .collect()
}

struct Engine {
    manifest: Manifest,
    state: CommittedState,
    tr: Transition<HybridVerifier>,
    tr_probe: Transition<ProbeVerifier>,
    verifier: HybridVerifier,
    /// The validator this node signs as, or `None` in observer mode.
    ///
    /// An observer follows the chain, applies every block and serves the RPC,
    /// and signs nothing. It exists so the public endpoint does not have to be
    /// a validator: restarting whatever serves the RPC takes minutes — the
    /// node reingests the carryover, pays the cold state-root cost and replays
    /// the chain — and during that window the endpoint is simply down.
    ///
    /// The alternative, pointing the endpoint at a spare copy of a validator's
    /// keystore, is how you equivocate and get slashed. There is no safe
    /// version of that, so there is this.
    keys: Option<Keystore>,
    /// Every structurally-valid block seen, canonical or not, by id.
    /// Unpruned — fine for a devnet, listed as a limitation.
    blocks: BTreeMap<[u8; 32], BlockEnvelope>,
    /// Canonical chain, ascending slot, genesis first.
    chain: Vec<(u64, BlockId)>,
    /// Canonical ids (incl. genesis).
    canonical: BTreeSet<[u8; 32]>,
    /// Attestations available to fork choice and to the next proposal, keyed
    /// by content so duplicates collapse. This is the *aggregation* store.
    pool: BTreeMap<(u32, [u8; 32]), Attestation>,
    /// The *admission* gate in front of `pool`:
    /// [`AttestationPool`](bloch_pos_committee::gossip::AttestationPool) from
    /// the pure crate — dedup, the equivocation cap, slashing-pair capture,
    /// and the pending queue for attestations whose block has not landed yet.
    ///
    /// The two are different objects on purpose. `att_pool` decides *whether a
    /// message may be believed and relayed* and answers in the three verbs
    /// gossipsub understands; `pool` holds the attestations that survived, in
    /// the shape fork choice and block production want. Before this was wired
    /// the node did its own ad-hoc dedup-and-verify inline, and the whole
    /// Hold verb — the one that keeps an attestation racing ahead of its block
    /// from being scored as an offence — did not exist here at all.
    att_pool: AttestationPool,
    /// Wall-clock slot, refreshed by the slot loop. `att_pool` never reads a
    /// clock (that is its determinism rule), so the node supplies one.
    wall_slot: u64,
    /// Transactions waiting for a block, keyed by canonical bytes so a
    /// duplicate gossip collapses instead of being included twice.
    ///
    /// Devnet mempool, and the limitations are the point: no fee ordering (it
    /// is insertion-ordered), no per-sender limit, no eviction beyond
    /// `MEMPOOL_MAX`, and admission checks only that the bytes decode. A
    /// public network needs all four; `gossip.rs` in the pure crate is where
    /// that belongs and it is still not wired.
    mempool: BTreeMap<Vec<u8>, PosTransaction>,
    store: Store,
    net: net::Net,
    head_slot: Arc<AtomicU64>,
    /// False during boot replay: no log appends, no broadcasts, no logs.
    live: bool,
    needs_sync: bool,
    last_applied_ms: u64,
    booted_ms: u64,
    /// The weak-subjectivity anchor this node booted under (epoch, root), and
    /// whether it is the node's ONLY defense (it had no finality of its own).
    /// `None` until `ws_boot::boot` has run.
    ws_anchor: Option<(u64, [u8; 32])>,
    ws_anchor_hard: bool,
    /// A forward WS_CONFLICT is announced once, not every block.
    ws_conflict_reported: bool,
    /// The inbound quota, read-only from here. Carried so `getchaininfo` can
    /// report depth and shed counts: a counter only visible inside the process
    /// is a counter nobody checks, and that invisibility is half of why silent
    /// shedding hid a block-delivery failure for weeks.
    queue: Arc<EngineQueue>,
}

/// Why a transaction was turned away at the door.
///
/// The distinction is load-bearing, not cosmetic: one of these means "ask me
/// again in a moment" and the other means "these bytes will never be
/// admitted, stop sending them". Collapsing both into one RPC code is how an
/// operator ends up growing the mempool to fix a bad signature.
#[derive(Debug, PartialEq, Eq)]
enum Refusal {
    /// The mempool is full. The transaction was NOT judged invalid.
    AtCapacity,
    /// `admissible` refused it on its merits. Retrying is pointless.
    Invalid(&'static str),
}

impl Refusal {
    /// The human-readable reason, for tests and logs. Callers that need to
    /// ACT on the difference must match the variant, not read this string.
    fn reason(&self) -> &'static str {
        match self {
            Refusal::AtCapacity => "mempool is at capacity",
            Refusal::Invalid(why) => why,
        }
    }
}


impl Engine {
    // ── Derivations over the canonical chain ────────────────────────────────

    fn head_id(&self) -> BlockId {
        self.chain
            .last()
            .expect("chain contains at least genesis")
            .1
    }

    fn head_slot_now(&self) -> u64 {
        self.chain
            .last()
            .expect("chain contains at least genesis")
            .0
    }

    /// Clone of the canonical state with epoch accounting rolled forward to
    /// `epoch` — the exact rolling `apply_block` performs internally, so the
    /// duty view here can never disagree with validation.
    fn rolled_to(&self, epoch: u64) -> CommittedState {
        let mut st = self.state.clone();
        // Invariant: the canonical state's open epoch is its head's epoch —
        // only apply_block advances it, and apply_block rolls exactly there.
        let mut cur = epoch_of(st.slot());
        while cur < epoch {
            st = self
                .tr
                .process_epoch(&st)
                .expect("process_epoch is infallible");
            cur += 1;
        }
        st
    }

    /// The sortition/partition seed for `epoch`, per the transition's own
    /// rule: the boundary mix of `epoch - 1`, genesis mix for epoch 0.
    fn seed_for(rolled: &CommittedState, epoch: u64) -> [u8; 32] {
        if epoch == 0 {
            GENESIS_MIX
        } else {
            rolled.randao_mix_at(epoch - 1).unwrap_or(GENESIS_MIX)
        }
    }

    /// Checkpoint root of `epoch` on the canonical chain: the latest block
    /// strictly BEFORE the epoch's first slot (genesis for epoch 0/1 starts).
    ///
    /// Strictly-before is load-bearing: attesters attest at slot start, so
    /// the committee of the epoch's first slot cannot yet see that slot's
    /// block. A convention including the first-slot block would make early
    /// and late attesters of the same epoch vote different targets, splitting
    /// the tally below 2/3 — exactly the stall the first devnet run showed
    /// (justification frozen at epoch 1). The pre-boundary block is fixed for
    /// the whole epoch, so every honest attester votes the same root; the
    /// finality gadget only compares roots and does not care which epoch the
    /// checkpoint block itself sits in.
    fn checkpoint_root(&self, epoch: u64) -> [u8; 32] {
        let first = first_slot_of_epoch(epoch).unwrap_or(u64::MAX);
        let mut root = *self.chain[0].1.as_bytes();
        for (slot, id) in &self.chain {
            if *slot >= first {
                break;
            }
            root = *id.as_bytes();
        }
        root
    }

    /// This node's OWN finalized root at `epoch`, or `None` if its finality
    /// has not reached that epoch — exactly the input
    /// [`ws::cross_check`](bloch_pos_committee::ws::cross_check) declares.
    /// "Own" is load-bearing: the root comes from this node's replayed
    /// canonical chain under the same checkpoint convention its attesters
    /// vote, never from anything a peer or a publication asserted.
    fn own_finalized_root_at(&self, epoch: u64) -> Option<[u8; 32]> {
        (epoch <= self.state.finality().finalized.epoch).then(|| self.checkpoint_root(epoch))
    }

    /// Forward enforcement of the boot anchor (§5). Once this node's own
    /// finality reaches the anchor's epoch, the two must agree.
    ///
    /// Two outcomes, and the difference is the whole structural limit on the
    /// signers' power. A node that booted on its OWN finality treats a
    /// contradiction as the WS_CONFLICT alarm and keeps running — a
    /// checkpoint never reorganizes it. A node that had nothing of its own
    /// (`anchor_is_hard`) has only the anchor between it and a forged
    /// history, so a contradiction is fatal: it is following a chain that
    /// disagrees with the one thing it trusted.
    fn enforce_ws_anchor(&mut self) {
        let Some((epoch, root)) = self.ws_anchor else {
            return;
        };
        if self.ws_conflict_reported {
            return;
        }
        let Some(local) = self.own_finalized_root_at(epoch) else {
            return;
        };
        use bloch_pos_committee::ws::{cross_check, WeakSubjectivityCheckpoint, WS_FORMAT_VERSION};
        // Only `epoch`/`block_root` are read by cross_check; the rest of the
        // artifact is not re-litigated here (it was verified at boot).
        let probe = WeakSubjectivityCheckpoint {
            version: WS_FORMAT_VERSION,
            network_id: 0,
            genesis_root: [0u8; 32],
            epoch,
            block_root: root,
            state_root: [0u8; 32],
            validator_set_root: [0u8; 32],
            issued_at: 0,
            signer_set_id: 0,
        };
        if let bloch_pos_committee::ws::CrossCheck::Conflict {
            local_root,
            published_root,
        } = cross_check(Some(local), &probe)
        {
            self.ws_conflict_reported = true;
            eprintln!(
                "WS_CONFLICT at epoch {epoch}: this node finalized {} where its \
                 weak-subjectivity anchor says {}.",
                crate::codec::hex32(&local_root),
                crate::codec::hex32(&published_root),
            );
            if self.ws_anchor_hard {
                eprintln!(
                    "FATAL: this node synced with no finality of its own — the anchor \
                     was its only defense against a forged history, and the chain it \
                     followed contradicts it. Stopping rather than serving a history \
                     nothing vouches for. Re-check the checkpoint digest across \
                     independent publication channels before restarting."
                );
                std::process::exit(1);
            }
            eprintln!(
                "Own finality stands: NOT reorganizing (a checkpoint can never override \
                 a running node's finality). Alert the operator and compare the \
                 published digest across independent channels."
            );
        }
    }

    /// This validator's RANDAO chain, positioned at its committed reveal
    /// count on the CANONICAL chain (= how many canonical blocks it
    /// proposed). Regenerated from the seed on every use: a reorg can drop
    /// our own blocks, so an incrementally-advanced local chain would drift
    /// from what the committed state expects the next reveal to open.
    ///
    /// Only ever called from the proposing path, which an observer never
    /// reaches — hence the expect rather than an Option return threaded
    /// through a caller that cannot be in this state.
    fn randao_positioned(&self) -> RandaoChain {
        let keys = self
            .keys
            .as_ref()
            .expect("randao_positioned is proposer-only");
        let mine = self.chain.iter().skip(1).filter(|(_, id)| {
            self.blocks
                .get(id.as_bytes())
                .is_some_and(|e| e.header.proposer_index == keys.index)
        });
        let count = mine.count();
        let mut chain = RandaoChain::generate(keys.randao_seed);
        for _ in 0..count {
            chain.next_reveal();
        }
        chain
    }

    // ── Duties ──────────────────────────────────────────────────────────────

    fn attest(&mut self, slot: u64) {
        // An observer holds no key and therefore has no duty.
        let Some(keys) = self.keys.as_ref() else {
            return;
        };
        let index = keys.index;
        let e = epoch_of(slot);
        if e == 0 {
            // Epoch 0's checkpoint is genesis — justified by definition;
            // a vote for it would be source==target, which is invalid.
            return;
        }
        let rolled = self.rolled_to(e);
        let roster = rolled.active_validators();
        let seed = Self::seed_for(&rolled, e);
        let committee = committees::committee_for_slot(&seed, slot, &roster);
        if committee.binary_search(&index).is_err() {
            return;
        }
        let fin = rolled.finality();
        let data = AttestationData {
            slot,
            head: *self.head_id().as_bytes(),
            source_epoch: fin.justified.epoch,
            source_root: fin.justified.root,
            target_epoch: e,
            target_root: self.checkpoint_root(e),
        };
        let signature = self
            .keys
            .as_ref()
            .expect("checked above")
            .sign(&data.signing_root());
        let att = Attestation {
            data,
            validator: index,
            signature,
        };
        self.pool
            .insert((att.validator, att.data.signing_root()), att.clone());
        self.net.broadcast(net::att_frame(&att));
        println!(
            "[slot {slot}] attested (epoch {e}, head {}, target {})",
            crate::codec::hex8(&data.head),
            crate::codec::hex8(&data.target_root)
        );
    }

    fn propose(&mut self, slot: u64) {
        let Some(keys) = self.keys.as_ref() else {
            return;
        };
        let index = keys.index;
        let e = epoch_of(slot);
        let rolled = self.rolled_to(e);
        let roster = rolled.active_validators();
        let seed = Self::seed_for(&rolled, e);
        if schedule::proposer(&seed, slot, &roster) != Some(index) {
            return;
        }

        // Attestations this block may carry: current epoch, not from the
        // future, author in its slot's committee (the same predicate the
        // transition enforces at step 8, applied as the producer's filter so
        // one bad pool entry cannot poison the block — the dust-tx lesson).
        let atts: Vec<Attestation> = self
            .pool
            .values()
            .filter(|a| {
                epoch_of(a.data.slot) == e
                    && a.data.slot <= slot
                    && a.data.source_epoch < a.data.target_epoch
                    && committees::committee_for_slot(&seed, a.data.slot, &roster)
                        .binary_search(&a.validator)
                        .is_ok()
            })
            .cloned()
            .collect();

        let randao = self.randao_positioned();
        let Some(reveal) = randao.peek_reveal() else {
            eprintln!(
                "[slot {slot}] RANDAO chain spent — cannot propose (re-commit path not wired)"
            );
            return;
        };
        let fin = rolled.finality();
        let mut header = BlockHeaderV4 {
            version: VERSION_G4,
            parent: *self.head_id().as_bytes(),
            state_root: [0u8; 32],
            body_root: derive::body_root(&[]),
            slot,
            proposer_index: index,
            randao_reveal: reveal,
            randao_mix: mix_in(&rolled.randao_mix(), &reveal),
            justified_root: fin.justified.root,
            finalized_root: fin.finalized.root,
            attestation_root: derive::attestation_root(&atts),
            // Derived from the parent's committed pool roots, not zeroed. The
            // transition checks this (step 3b) since 2026-08-12; a zeroed field
            // was accepted before only because nothing checked it.
            coherence_root: self.state.coherence_root(),
        };

        // The post-state, from the SAME function validation runs. The probe
        // verifier only skips signature checks (the state does not depend on
        // them); the block still faces the real verifier in apply_block.
        // What this block will carry. Selected before the post-state, because
        // the post-state must be computed over exactly these — the header
        // commits to their body_root and every verifier recomputes from them.
        // Select, then DROP whatever the transition refuses — never abandon
        // the block.
        //
        // # Why this loop exists
        //
        // Until 2026-08-13 a proposer computed the post-state over its whole
        // selection and gave up if the transition said no. One transaction the
        // mempool had admitted but consensus would refuse therefore stopped
        // every proposer that picked it up, and the chain halted. It happened
        // on the live testnet: a zero-input transfer submitted through the
        // public RPC produced `produce refused: Transfer(0, NoInputs)` at
        // proposer after proposer, and production stopped at slot 69 while
        // every node stayed up and kept attesting.
        //
        // That is a denial of service costing one unauthenticated request, and
        // it is the same shape as the Genesis-3 dust transaction that poisoned
        // every block containing it. The mempool should not have admitted it —
        // and admission is being tightened separately — but a proposer must
        // not depend on that. Liveness cannot rest on the mempool being right;
        // a block with fewer transactions is always better than no block.
        //
        // Each refusal drops exactly one transaction and retries, so the loop
        // is bounded by the selection size and terminates: the empty selection
        // always computes.
        let mut txs = self.select_transactions(bloch_pos_committee::epoch_of(slot));
        let (post, tx_bytes) = loop {
            let tx_bytes: Vec<Vec<u8>> = txs.iter().map(PosTransaction::canonical_bytes).collect();
            header.body_root = derive::body_root(&tx_bytes);
            let probe = ProposalEnvelope {
                header: header.clone(),
                proposer_sig: Vec::new(),
            };
            match self
                .tr_probe
                .compute_post_state(&self.state, &probe, &atts, &txs)
            {
                Ok(p) => break (p, tx_bytes),
                Err(err) => {
                    let Some(bad) = txs.pop() else {
                        // Empty and still refused: the fault is not in any
                        // transaction, so proposing is genuinely impossible.
                        eprintln!("[slot {slot}] produce refused with no transactions: {err:?}");
                        return;
                    };
                    eprintln!(
                        "[slot {slot}] dropping a transaction the transition refuses ({err:?}); \
                         proposing without it"
                    );
                    // Out of the mempool too, or the next proposer inherits the
                    // same halt this loop just avoided.
                    self.mempool.remove(&bad.canonical_bytes());
                }
            }
        };
        header.state_root = post.state_root();

        let proposer_sig = self
            .keys
            .as_ref()
            .expect("checked above")
            .sign(&header.proposal_signing_root());
        let env = BlockEnvelope {
            header,
            proposer_sig,
            body: Body {
                transactions: tx_bytes,
                attestations: atts,
            },
        };
        let id = env.block_id();
        println!(
            "[slot {slot}] proposing block {} ({} attestations, {} txs, mempool {})",
            crate::codec::hex8(id.as_bytes()),
            env.body.attestations.len(),
            env.body.transactions.len(),
            self.mempool.len()
        );
        // Captured before `env` moves into ingest: if the transition refuses
        // this block, these are the bytes to drop from the mempool.
        let produced_txs: Vec<Vec<u8>> = env.body.transactions.clone();
        let env_tx_count = produced_txs.len();
        self.ingest(env);
        // h28080: a producer whose own node did not adopt its block is a
        // producer/validator split inside one process. It must be LOUD — but it
        // must not be fatal.
        //
        // This was `assert_eq!`, and a panic here was remotely reachable: the
        // probe accepts any signature, the real verifier does not, so one
        // transfer with a garbage signature made every proposer kill itself in
        // its own slot. The signature check in `admissible` closes that
        // particular door; this closes the CLASS. Any future divergence between
        // what the probe priced and what the transition accepts now costs one
        // missed slot and a log line, not a node.
        //
        // The transactions go too. Keeping them would rebuild the same block
        // next slot and lose that one as well.
        if self.head_id() != id {
            eprintln!(
                "[slot {slot}] REFUSED OWN BLOCK {} — the transition did not adopt what this \
                 node just produced (h28080 class). Dropping its {} transaction(s) and \
                 continuing; this slot is lost, the node is not.",
                crate::codec::hex8(id.as_bytes()),
                env_tx_count,
            );
            for encoded in &produced_txs {
                self.mempool.remove(encoded);
            }
            return;
        }
        let env = self
            .blocks
            .get(id.as_bytes())
            .expect("just ingested")
            .clone();
        self.net.broadcast(net::block_frame(&env));
    }

    // ── Block ingestion: store, then advance canonical as far as possible ──

    fn ingest(&mut self, env: BlockEnvelope) {
        let id = *env.block_id().as_bytes();
        if self.blocks.contains_key(&id) || self.canonical.contains(&id) {
            return;
        }
        // A cheap early reject before the block reaches the transition, using
        // the same `derive::*` functions the transition checks with — one
        // definition, called twice, not two definitions. The transition is the
        // authority (step 3b); this only avoids paying for a state clone on a
        // block that is obviously mismatched.
        if env.header.attestation_root != derive::attestation_root(&env.body.attestations)
            || env.header.body_root != derive::body_root(&env.body.transactions)
        {
            eprintln!(
                "reject {}: body/attestation commitment mismatch",
                crate::codec::hex8(&id)
            );
            return;
        }
        // A block carrying transactions used to be rejected here, because the
        // node had no tx codec and failing closed was the honest response. The
        // codec exists now (`PosTransaction::from_canonical_bytes`), so the
        // check that replaces it is decodability: bytes this build cannot read
        // must not reach the transition, since the proposer's post-state would
        // then be unreproducible.
        if let Err(e) = body_transactions(&env) {
            eprintln!("reject {}: {e}", crate::codec::hex8(&id));
            return;
        }
        if env.header.slot == 0 {
            return; // genesis is synthesized, never received
        }
        self.blocks.insert(id, env);
        self.advance();
        // The block is queryable now, so attestations parked on it can be
        // re-run. `advance()` first: an attestation released here votes on
        // fork choice, and it should see the chain the block already moved.
        self.release_held(id);
    }

    // ── Fork choice: LMD-GHOST ──────────────────────────────────────────────

    /// The LMD-GHOST head over every block this node has seen, canonical or
    /// not.
    ///
    /// Rebuilt from scratch each call (see the module docs on why there is no
    /// cached store). Deterministic despite the map iteration: `Store::observe`
    /// keeps the highest-slot message per validator and bars any validator that
    /// signed two different heads in one slot, so the resulting store is a
    /// function of the message *set*, never of arrival order — the property
    /// that was found violated in `forkchoice.rs` on 2026-08-11 and fixed
    /// there. Sibling lists are sorted so the tie-break is stable too.
    fn forkchoice_head(&self) -> [u8; 32] {
        lmd_ghost_head(
            &self.blocks,
            self.pool.values(),
            &self.state.active_validators(),
            self.state.finality().justified.root,
        )
    }

    /// The chain of stored blocks from `target` down to the nearest canonical
    /// ancestor, ancestor-child first, together with that ancestor.
    ///
    /// `None` means the lineage is incomplete — the node is missing blocks and
    /// must sync before it can judge the branch. Returning `None` rather than
    /// guessing is the fail-closed half of the rule: a branch is adopted only
    /// after being replayed and validated in full.
    fn path_to_canonical(&self, target: [u8; 32]) -> Option<([u8; 32], Vec<BlockEnvelope>)> {
        if self.canonical.contains(&target) {
            return Some((target, Vec::new()));
        }
        let mut branch = Vec::new();
        let mut cur = target;
        // Bounded by the number of stored blocks: a cycle (which a malicious
        // peer could otherwise induce) terminates instead of hanging.
        for _ in 0..=self.blocks.len() {
            match self.blocks.get(&cur) {
                Some(env) => {
                    branch.push(env.clone());
                    cur = env.header.parent;
                    if self.canonical.contains(&cur) {
                        branch.reverse();
                        return Some((cur, branch));
                    }
                }
                None => return None,
            }
        }
        None
    }

    /// Make the canonical chain equal the LMD-GHOST head.
    ///
    /// Three cases, and the third is the one longest-chain could not express:
    /// the head descends from the current head (extend), the head is on another
    /// branch (reorg), or the head is an *ancestor* of the current head —
    /// weight moved to a sibling and the chain must give blocks back. That last
    /// case is a legitimate LMD-GHOST outcome and is handled by reorganising to
    /// an empty branch.
    fn advance(&mut self) {
        // Bounded: every iteration either advances the canonical head or
        // deletes an invalid block, and both are finite.
        for _ in 0..=(self.blocks.len().saturating_mul(2) + 2) {
            let target = self.forkchoice_head();
            let head = *self.head_id().as_bytes();
            if target == head {
                return;
            }
            let Some((ancestor, branch)) = self.path_to_canonical(target) else {
                // Missing lineage: ask the mesh, and keep the chain we have
                // rather than adopting something we cannot validate.
                self.needs_sync = true;
                return;
            };
            if ancestor == head && !branch.is_empty() {
                // Pure extension: apply in order, no replay needed.
                let mut progressed = false;
                for env in &branch {
                    if !self.apply_canonical(env) {
                        self.blocks.remove(env.block_id().as_bytes());
                        break;
                    }
                    progressed = true;
                }
                if !progressed {
                    continue;
                }
            } else if !self.do_reorg(ancestor, branch) {
                continue; // offending block removed; recompute
            }
        }
    }


    /// Admit a transaction to the mempool and pass it on.
    ///
    /// Admission is deliberately thin here — the bytes already decoded at the
    /// network edge, and that is the whole check. What is missing is named in
    /// the `mempool` field's doc rather than half-built: no fee floor, no
    /// per-sender accounting, no replacement policy. Re-broadcast only on
    /// first sight, so a transaction traverses the mesh once instead of
    /// echoing between every pair of peers.
    /// Returns what became of the transaction, so a caller that has someone to
    /// answer to — the RPC — can say. The gossip path ignores the result: a
    /// peer is not waiting on a verdict, and a duplicate arriving twice over a
    /// full mesh is the normal case rather than a fault.
    fn on_transaction(&mut self, tx: PosTransaction) -> Result<Admitted, Refusal> {
        let key = tx.canonical_bytes();
        if self.mempool.contains_key(&key) {
            return Ok(Admitted::Duplicate);
        }
        if self.mempool.len() >= MEMPOOL_MAX {
            return Err(Refusal::AtCapacity);
        }
        // Refuse the shapes consensus can never apply.
        //
        // Admission used to check duplicate-and-capacity only, so anything
        // that decoded got in. One transaction consensus would never apply
        // halted the live testnet: every proposer that selected it failed to
        // produce, and the chain stopped at slot 69 with every node up and
        // still attesting. Cost of the attack: one unauthenticated request.
        //
        // This is deliberately a STRUCTURAL check, not a full validity check.
        // A complete answer means running the transition, which needs a
        // candidate header this path has no reason to build. What it catches
        // is the class that was actually exploited — a transfer that spends
        // nothing or pays no one, which no state can make applicable.
        //
        // It does NOT catch a transfer whose signature is wrong, whose inputs
        // do not exist, or which fails conservation. Those still reach the
        // mempool and are dropped by the proposer, which is why the proposer's
        // guard is the one that carries liveness and this one only reduces
        // waste. Two checks, neither trusting the other.
        //
        // The epoch handed down is the WALL-CLOCK epoch, read here through
        // the `wall_slot()` METHOD (the clock against the manifest's genesis)
        // and never the `wall_slot` FIELD: the field is refreshed by the slot
        // loop, and on the RPC path — which converges here through
        // `serve_rpc`'s SendRawTransaction arm — nothing guarantees the loop
        // has run this tick. Why wall and not the head's epoch is argued at
        // the TransferV2 arm of `admissible` itself, next to the gate it
        // feeds. Gossip (`NetEvent::Transaction`) and RPC both land in this
        // one call, so one call site carries the whole decision.
        admissible(&tx, epoch_of(self.wall_slot())).map_err(Refusal::Invalid)?;
        let mut frame = vec![net::FRAME_TX];
        frame.extend_from_slice(&key);
        self.mempool.insert(key, tx);
        self.net.broadcast(frame);
        Ok(Admitted::New)
    }

    /// Transactions for the block this node is about to propose.
    ///
    /// Insertion order, bounded by both [`MAX_TXS_PER_BLOCK`] and the
    /// consensus byte cap. Insertion order is not a fee market: a real
    /// proposer sorts by what the transaction pays, and doing that here before
    /// transfers carry a value format would be inventing an ordering over a
    /// field nobody sets yet.
    ///
    /// `epoch` is the epoch of the slot being produced, because the byte cap
    /// is flag-day gated. Packing against the wrong era is not symmetric: the
    /// old cap after activation only wastes capacity, but the new cap before
    /// it builds a block every other node rejects — so the epoch comes from
    /// the slot this proposer is building for, not from anything ambient.
    fn select_transactions(&self, epoch: u64) -> Vec<PosTransaction> {
        let cap = bloch_pos_committee::fee_market::max_block_tx_bytes(epoch);
        let mut out = Vec::new();
        let mut bytes = 0u64;
        for (encoded, tx) in self.mempool.iter() {
            if out.len() >= MAX_TXS_PER_BLOCK {
                break;
            }
            let n = encoded.len() as u64;
            if bytes + n > cap {
                break;
            }
            bytes += n;
            out.push(tx.clone());
        }
        out
    }

    /// Apply one block that extends the current head. True on success.
    fn apply_canonical(&mut self, env: &BlockEnvelope) -> bool {
        let id = env.block_id();
        let envelope = ProposalEnvelope {
            header: env.header.clone(),
            proposer_sig: env.proposer_sig.clone(),
        };
        let before = self.state.finality();
        let txs = match body_transactions(env) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("apply refused: {e}");
                return false;
            }
        };
        match self
            .tr
            .apply_block(&self.state, &envelope, &env.body.attestations, &txs)
        {
            Ok(post) => {
                self.state = post;
                self.canonical.insert(*id.as_bytes());
                self.chain.push((env.header.slot, id));
                self.head_slot.store(env.header.slot, Ordering::Relaxed);
                self.last_applied_ms = now_ms();
                for a in &env.body.attestations {
                    self.pool.remove(&(a.validator, a.data.signing_root()));
                }
                // Included is included — drop them from the mempool by the
                // same bytes they were keyed under.
                for encoded in &env.body.transactions {
                    self.mempool.remove(encoded);
                }
                let cur_e = epoch_of(self.state.slot());
                self.pool.retain(|_, a| epoch_of(a.data.slot) >= cur_e);

                if self.live {
                    if let Err(e) = self.store.append(env) {
                        eprintln!("FATAL: block log append failed: {e}");
                        std::process::exit(1);
                    }
                    let after = self.state.finality();
                    println!(
                        "[slot {}] applied {} by v{} — head root {}, justified e{}, finalized e{}",
                        env.header.slot,
                        crate::codec::hex8(id.as_bytes()),
                        env.header.proposer_index,
                        crate::codec::hex8(&self.state.state_root()),
                        after.justified.epoch,
                        after.finalized.epoch,
                    );
                    if after.justified.epoch > before.justified.epoch {
                        println!(
                            "*** JUSTIFIED epoch {} ({})",
                            after.justified.epoch,
                            crate::codec::hex8(&after.justified.root)
                        );
                    }
                    if after.finalized.epoch > before.finalized.epoch {
                        println!(
                            "*** FINALIZED epoch {} ({})",
                            after.finalized.epoch,
                            crate::codec::hex8(&after.finalized.root)
                        );
                        // New own finality may now reach the anchor's epoch.
                        self.enforce_ws_anchor();
                    }
                }
                true
            }
            Err(err) => {
                if self.live {
                    eprintln!(
                        "reject {} at slot {}: {err:?}",
                        crate::codec::hex8(id.as_bytes()),
                        env.header.slot
                    );
                }
                false
            }
        }
    }

    /// Adopt `branch` (attached at canonical `ancestor`) by replaying the
    /// whole candidate chain from genesis through the same transition. True
    /// if adopted; false if a branch block failed validation (it is removed).
    fn do_reorg(&mut self, ancestor: [u8; 32], branch: Vec<BlockEnvelope>) -> bool {
        let cut = self
            .chain
            .iter()
            .position(|(_, id)| id.as_bytes() == &ancestor)
            .expect("ancestor is canonical");
        let prefix: Vec<BlockEnvelope> = self.chain[1..=cut]
            .iter()
            .map(|(_, id)| {
                self.blocks
                    .get(id.as_bytes())
                    .expect("canonical block stored")
                    .clone()
            })
            .collect();

        let mut st = self.manifest.genesis_state();
        for env in &prefix {
            let envelope = ProposalEnvelope {
                header: env.header.clone(),
                proposer_sig: env.proposer_sig.clone(),
            };
            let txs = body_transactions(env)
                .expect("a canonical block's body decoded when it was applied");
            st = self
                .tr
                .apply_block(&st, &envelope, &env.body.attestations, &txs)
                .expect("canonical prefix replay cannot fail (it applied before)");
        }
        for env in &branch {
            let envelope = ProposalEnvelope {
                header: env.header.clone(),
                proposer_sig: env.proposer_sig.clone(),
            };
            let txs = match body_transactions(env) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("reorg candidate rejected at slot {}: {e}", env.header.slot);
                    return false;
                }
            };
            match self
                .tr
                .apply_block(&st, &envelope, &env.body.attestations, &txs)
            {
                Ok(post) => st = post,
                Err(err) => {
                    eprintln!(
                        "reorg candidate {} invalid at slot {}: {err:?}",
                        crate::codec::hex8(env.block_id().as_bytes()),
                        env.header.slot
                    );
                    self.blocks.remove(env.block_id().as_bytes());
                    return false;
                }
            }
        }

        // Adopt.
        let old_head = self.head_slot_now();
        self.state = st;
        self.chain.truncate(cut + 1);
        let mut canonical: BTreeSet<[u8; 32]> =
            self.chain.iter().map(|(_, id)| *id.as_bytes()).collect();
        for env in &branch {
            let id = env.block_id();
            canonical.insert(*id.as_bytes());
            self.chain.push((env.header.slot, id));
        }
        self.canonical = canonical;
        self.head_slot
            .store(self.head_slot_now(), Ordering::Relaxed);
        self.last_applied_ms = now_ms();
        let cur_e = epoch_of(self.state.slot());
        self.pool.retain(|_, a| epoch_of(a.data.slot) >= cur_e);
        if self.live {
            let canonical_envs: Vec<BlockEnvelope> = self.chain[1..]
                .iter()
                .map(|(_, id)| self.blocks.get(id.as_bytes()).expect("stored").clone())
                .collect();
            if let Err(e) = self.store.rewrite(&canonical_envs) {
                eprintln!("FATAL: block log rewrite failed: {e}");
                std::process::exit(1);
            }
            println!(
                "REORG: adopted branch of {} blocks at ancestor {} (head slot {} -> {}), root {}",
                branch.len(),
                crate::codec::hex8(&ancestor),
                old_head,
                self.head_slot_now(),
                crate::codec::hex8(&self.state.state_root()),
            );
            // A reorg can move the finalized root at the anchor's epoch.
            self.enforce_ws_anchor();
        }
        true
    }

    // ── Attestation admission, through the pure crate's gossip policy ───────

    /// Run one arriving attestation through
    /// [`AttestationPool`](bloch_pos_committee::gossip::AttestationPool) and
    /// report the resulting verdict to the transport.
    ///
    /// The mapping is the one `gossip.rs` states, and the type split is what
    /// enforces it: `Accept` relays and feeds consensus, `Ignore` and `Hold`
    /// drop in silence, and **only `Reject` may reach a peer penalty**. That
    /// distinction is not a nicety — the 2026-08-07 mesh collapsed twice from
    /// scoring honest peers, and the commonest honest event on this network
    /// (an attestation arriving milliseconds before the block it votes for) is
    /// precisely the one a naive implementation calls invalid.
    fn on_attestation(&mut self, att: Attestation, origin: Origin, wall_epoch: u64) {
        let e = epoch_of(att.data.slot);
        // Narrower than `gossip.rs`'s own two-epoch window, and for a reason
        // that belongs to the node, not the policy: committee membership must
        // come from committed state, and this node can only roll its canonical
        // state *forward* (`rolled_to`). It therefore cannot derive the
        // committee of an epoch already behind its head, so an attestation
        // from one is unjudgeable rather than invalid — Ignore, never Reject.
        // Reconstructing past-epoch committees (the pool would then accept the
        // full 64-slot window) needs per-epoch seed/roster history, which is
        // storage work, not policy work.
        if e != wall_epoch && e != wall_epoch + 1 {
            self.net.report(&origin, Verdict::Ignore);
            return;
        }
        // `att_pool` is moved out for the call so the lookups below can borrow
        // the chain immutably; it is put back before returning.
        let mut pool = std::mem::take(&mut self.att_pool);
        let decision = self.judge(&mut pool, att.clone(), e);
        self.att_pool = pool;
        self.apply_decision(att, decision, &origin);
    }

    /// One pass of the pure pipeline: window → checkpoint sanity → dedup and
    /// equivocation cap → committee membership → blocks known → signature.
    fn judge(&self, pool: &mut AttestationPool, att: Attestation, epoch: u64) -> GossipDecision {
        let rolled = self.rolled_to(epoch);
        let roster = rolled.active_validators();
        let seed = Self::seed_for(&rolled, epoch);
        let committees_at = |slot: u64| committees::committee_for_slot(&seed, slot, &roster);
        // "Do we have this block?" — canonical ids include genesis, which is
        // synthesized and never stored as an envelope; `blocks` holds every
        // structurally-valid block seen, canonical or not. A vote for a block
        // on a losing branch is still a vote we can verify.
        let known =
            |root: &[u8; 32]| self.canonical.contains(root) || self.blocks.contains_key(root);
        pool.process(att, self.wall_slot, &committees_at, &known, &self.verifier)
    }

    fn apply_decision(&mut self, att: Attestation, decision: GossipDecision, origin: &Origin) {
        match decision {
            GossipDecision::Accept { slashing_candidate } => {
                if let Some(ev) = slashing_candidate {
                    // Captured, not processed. The slashing pipeline
                    // (`SlashingState::process`, evidence transactions) is not
                    // wired in this binary — saying so here beats a silent
                    // drop that looks like nothing happened.
                    eprintln!(
                        "EQUIVOCATION captured: validator {} signed two attestations for slot {} \
                         (slashing pipeline NOT wired — evidence is logged, not prosecuted)",
                        ev.second.validator, ev.second.data.slot,
                    );
                }
                self.pool
                    .insert((att.validator, att.data.signing_root()), att);
                self.net.report(origin, Verdict::Accept);
            }
            GossipDecision::Ignore(_) => self.net.report(origin, Verdict::Ignore),
            GossipDecision::Hold { .. } => {
                // Parked. NOT relayed: this node does not forward what it
                // cannot yet validate. It is replayed by `release_held` when
                // the block lands, and relayed then.
                self.net.report(origin, Verdict::Ignore);
            }
            GossipDecision::Reject(reason) => {
                eprintln!("attestation from v{} REJECTED: {reason:?}", att.validator);
                self.net.report(origin, Verdict::Reject);
            }
        }
    }

    /// A block landed: replay every attestation that was waiting on it.
    ///
    /// Called after the block is queryable, which is what
    /// [`AttestationPool::on_block`] requires — earlier and the waiters would
    /// simply be re-held. Released Accepts are relayed here, since they were
    /// deliberately not relayed while parked.
    fn release_held(&mut self, root: [u8; 32]) {
        if self.att_pool.pending_len() == 0 {
            return;
        }
        let mut pool = std::mem::take(&mut self.att_pool);
        let released = {
            let rolled_epoch = epoch_of(self.wall_slot);
            let rolled = self.rolled_to(rolled_epoch);
            let roster = rolled.active_validators();
            let seed = Self::seed_for(&rolled, rolled_epoch);
            let committees_at = |slot: u64| committees::committee_for_slot(&seed, slot, &roster);
            let known = |r: &[u8; 32]| self.canonical.contains(r) || self.blocks.contains_key(r);
            pool.on_block(
                &root,
                self.wall_slot,
                &committees_at,
                &known,
                &self.verifier,
            )
        };
        self.att_pool = pool;
        for (att, decision) in released {
            if let GossipDecision::Accept { .. } = decision {
                let frame = net::att_frame(&att);
                self.pool
                    .insert((att.validator, att.data.signing_root()), att);
                if self.live {
                    // Relay now: it was held, so nobody downstream got it from
                    // us. A duplicate publish is refused locally and costs
                    // nothing.
                    self.net.broadcast(frame);
                }
            }
        }
    }

    // ── RPC service ─────────────────────────────────────────────────────────
    //
    // Answered on the consensus thread, between duties. Every method reads the
    // committed state this thread owns, so no query can observe a half-applied
    // block and no reader can be served a stale copy. The formatting lives in
    // `rpc.rs` as free functions of their inputs; what is here is only the
    // lookup — which block, which record, which outputs.

    /// The slot the wall clock is in, by the manifest's own cadence.
    ///
    /// `max(1)` on the divisor because a zero `slot_ms` in a hand-edited
    /// manifest must not turn a query into a division-by-zero panic. The slot
    /// loop would reach the same division first, but "would panic elsewhere" is
    /// not a reason for this path to panic here.
    fn wall_slot(&self) -> u64 {
        now_ms().saturating_sub(self.manifest.genesis_time_ms) / self.manifest.slot_ms.max(1)
    }

    /// Wall-clock seconds a slot corresponds to. Display only — derived from
    /// the manifest's cadence, never a consensus field (the header has no time).
    fn slot_timestamp_secs(&self, slot: u64) -> u64 {
        self.manifest
            .genesis_time_ms
            .saturating_add(slot.saturating_mul(self.manifest.slot_ms))
            / 1000
    }

    /// Canonical height of a block id — its position on the canonical chain,
    /// genesis at 0. `None` for a block this node has stored but not adopted.
    fn height_of(&self, id: &[u8; 32]) -> Option<u64> {
        self.chain
            .iter()
            .position(|(_, cid)| cid.as_bytes() == id)
            .map(|p| p as u64)
    }

    /// Slot of a canonical block named by root, if this node has it canonical.
    fn slot_of_canonical_root(&self, root: &[u8; 32]) -> Option<u64> {
        self.chain
            .iter()
            .find(|(_, id)| id.as_bytes() == root)
            .map(|(s, _)| *s)
    }

    /// Where a block stands against this node's own checkpoints.
    ///
    /// The comparison is by slot against the checkpoint blocks' slots, not by
    /// epoch: the checkpoint convention this node attests under puts the
    /// checkpoint at the last block strictly *before* an epoch's first slot, so
    /// "in a finalized epoch" and "at or below the finalized checkpoint" are
    /// different sets and only the second is what finality actually covers.
    fn finality_of(&self, slot: u64, canonical: bool) -> Finality {
        if !canonical {
            return Finality::NotCanonical;
        }
        let fin = self.state.finality();
        if self
            .slot_of_canonical_root(&fin.finalized.root)
            .is_some_and(|s| slot <= s)
        {
            Finality::Finalized
        } else if self
            .slot_of_canonical_root(&fin.justified.root)
            .is_some_and(|s| slot <= s)
        {
            Finality::Justified
        } else {
            Finality::Canonical
        }
    }

    /// Canonical height of the finalized checkpoint — the height below which
    /// this node's history is settled.
    fn finalized_height(&self) -> Option<u64> {
        self.height_of(&self.state.finality().finalized.root)
    }

    /// The genesis block as an envelope.
    ///
    /// Genesis is synthesised from the manifest and never stored in `blocks`
    /// (`ingest` refuses slot 0), so a lookup that lands on it has nothing to
    /// return. Rebuilding it from `Manifest::genesis_header` — the same
    /// function `genesis_id` derives identity from — lets height 0 answer in
    /// the ordinary block shape instead of being a special case clients must
    /// handle.
    fn genesis_envelope(&self) -> BlockEnvelope {
        BlockEnvelope {
            header: self.manifest.genesis_header(),
            proposer_sig: Vec::new(),
            body: Body {
                transactions: Vec::new(),
                attestations: Vec::new(),
            },
        }
    }

    /// Look up one block by id, genesis included.
    fn envelope_by_id(&self, id: &[u8; 32]) -> Option<BlockEnvelope> {
        if self.chain[0].1.as_bytes() == id {
            return Some(self.genesis_envelope());
        }
        self.blocks.get(id).cloned()
    }

    fn block_reply(&self, env: &BlockEnvelope) -> Json {
        let id = *env.block_id().as_bytes();
        let canonical = self.canonical.contains(&id);
        rpc::block_json(
            env,
            self.height_of(&id),
            self.finality_of(env.header.slot, canonical),
            self.slot_timestamp_secs(env.header.slot),
        )
    }

    fn serve_rpc(&mut self, req: RpcRequest) -> RpcResult {
        match req {
            RpcRequest::ChainInfo => Ok(rpc::chain_info_json(
                &self.state,
                &self.head_id(),
                self.chain.len() as u64 - 1,
                self.finalized_height(),
                self.wall_slot(),
                self.state.validator_count(),
                self.mempool.len(),
                self.blocks.len(),
                &self.queue.stats(),
            )),

            RpcRequest::BlockCount => {
                let fin = self.state.finality();
                Ok(rpc::block_count_json(
                    self.chain.len() as u64 - 1,
                    self.head_slot_now(),
                    self.finalized_height(),
                    fin.justified.epoch,
                    fin.finalized.epoch,
                ))
            }

            RpcRequest::BlockBySlot(slot) => {
                let Some((_, id)) = self.chain.iter().find(|(s, _)| *s == slot) else {
                    // A slot with no canonical block is the ordinary PoS case —
                    // a proposer missed its turn — and is reported as its own
                    // code so a scanner advances instead of alerting.
                    return Err(RpcError::new(
                        rpc::SLOT_EMPTY,
                        format!(
                            "no canonical block at slot {slot} (head is at slot {}); \
                             a slot with no block is a missed proposal, not an error",
                            self.head_slot_now()
                        ),
                    ));
                };
                let id = *id.as_bytes();
                let env = self.envelope_by_id(&id).ok_or_else(|| {
                    RpcError::new(
                        rpc::BLOCK_NOT_FOUND,
                        format!("slot {slot} names a block this node no longer stores"),
                    )
                })?;
                Ok(self.block_reply(&env))
            }

            RpcRequest::BlockById(id) => {
                let env = self.envelope_by_id(&id).ok_or_else(|| {
                    RpcError::new(
                        rpc::BLOCK_NOT_FOUND,
                        format!(
                            "no block {} is known to this node",
                            crate::codec::hex32(&id)
                        ),
                    )
                })?;
                Ok(self.block_reply(&env))
            }

            RpcRequest::Validator(index) => {
                let rec = self.state.validator_record(index).ok_or_else(|| {
                    RpcError::new(
                        rpc::VALIDATOR_NOT_FOUND,
                        format!(
                            "validator {index} is not in the committed registry ({} registered)",
                            self.state.validator_count()
                        ),
                    )
                })?;
                let effective = self
                    .state
                    .active_validators()
                    .iter()
                    .find(|v| v.index == index)
                    .map(|v| v.effective_stake);
                Ok(rpc::validator_json(
                    &rec,
                    effective,
                    epoch_of(self.state.slot()),
                ))
            }

            RpcRequest::ValidatorCount => Ok(Json::obj(vec![
                ("total", Json::u(self.state.validator_count() as u64)),
                (
                    "active",
                    Json::u(self.state.active_validators().len() as u64),
                ),
                (
                    "total_active_stake_sat",
                    Json::sat(self.state.total_active_stake_sat()),
                ),
            ])),

            RpcRequest::Balance(script_hash) => Ok(rpc::balance_json(&self.state, &script_hash)),

            RpcRequest::Utxos { script_hash, limit } => {
                Ok(rpc::utxos_json(&self.state, &script_hash, limit))
            }

            RpcRequest::TxOut { txid, vout } => Ok(rpc::txout_json(&self.state, &txid, vout)),

            RpcRequest::SendRawTransaction(tx) => match self.on_transaction(tx.clone()) {
                Ok(outcome) => Ok(rpc::submitted_json(&tx, outcome)),
                // The two refusals are not the same fact and must not carry
                // the same advice. "Retry later" is correct for a full
                // mempool and actively harmful for a refused transaction:
                // the founder's consolidation sweep submits hundreds of
                // thousands of transfers through this method, and an
                // operator told to retry bytes that can NEVER be admitted
                // chases capacity while the real fault — an unverifiable
                // signature, an empty witness table — goes unread. Before
                // this, every refusal returned MEMPOOL_FULL with the words
                // "the transaction was not judged invalid" appended, which
                // for an invalid transaction was simply false.
                Err(Refusal::AtCapacity) => Err(RpcError::new(
                    rpc::MEMPOOL_FULL,
                    format!(
                        "mempool is at capacity ({MEMPOOL_MAX} entries); retry later — \
                         the transaction was not judged invalid"
                    ),
                )),
                Err(Refusal::Invalid(why)) => Err(RpcError::new(
                    rpc::TX_REFUSED,
                    format!("{why} — this transaction cannot be admitted; retrying \
                             the same bytes will not help"),
                )),
            },

            RpcRequest::MempoolInfo => Ok(rpc::mempool_info_json(
                self.mempool.len(),
                MEMPOOL_MAX,
                self.mempool.keys().map(Vec::len).sum(),
                self.state.next_base_fee(),
            )),
        }
    }
}

// ── Entry point ─────────────────────────────────────────────────────────────

/// How often replay reports progress. Ten seconds is short enough that an
/// operator watching a stalled fleet gets an answer quickly, and long enough
/// that the log of a multi-hour replay stays readable.
const REPLAY_PROGRESS_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

pub fn run(cfg: Config) -> io::Result<()> {
    let (mut manifest, digest) = Manifest::load(&cfg.genesis_path)?;

    // The opening ledger, before anything else touches the manifest. A
    // manifest that commits to a carryover is not usable until the snapshot
    // is in hand, and a snapshot offered to a manifest that commits to none
    // is a category error — both are refusals rather than warnings, because
    // the failure they prevent is a chain that starts, runs, and is wrong.
    match (&manifest.carryover, &cfg.carryover_path) {
        (Some(c), Some(path)) => {
            let entries = c.entry_count;
            let snap = manifest.ingest_carryover(path)?;
            println!(
                "carryover: {entries} outputs, {} sat carried (x100/21 of {} G3 sat, \
                 {} sat of split remainder to the largest output); set root {}",
                snap.total_sat,
                snap.g3_total_sat,
                snap.dust_sat,
                crate::codec::hex8(&snap.set_root),
            );
        }
        (Some(c), None) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "this genesis commits to a carryover of {} outputs ({} sat) but no \
                     --carryover <snapshot.tsv> was given; starting without it would open \
                     the chain with a zero balance for every holder",
                    c.entry_count, c.total_sat,
                ),
            ));
        }
        (None, Some(_)) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "--carryover was given but this genesis commits to no carryover; \
                 the manifest's digest says nothing about that file, so nothing would \
                 hold the balances it contains to anything",
            ));
        }
        (None, None) => {}
    }

    // No keystore in the data dir is not a misconfiguration — it selects
    // observer mode. Any other read error still is, and is reported: a node
    // that silently downgraded to observer because its key was unreadable
    // would stop attesting and look healthy doing it.
    let keys = match Keystore::load(&cfg.data_dir) {
        Ok(k) => Some(k),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            println!(
                "observer mode: no keystore in {}. This node follows the chain, applies \
                 every block and serves the RPC. It does not propose and does not attest.",
                cfg.data_dir.display()
            );
            None
        }
        Err(e) => return Err(e),
    };
    let verifier = HybridVerifier::new(manifest.pubkeys());

    // Identity sanity: the keystore must be the validator the manifest says.
    if let Some(keys) = keys.as_ref() {
        match manifest.validators.iter().find(|v| v.index == keys.index) {
            Some(v) if v.pubkey == keys.pubkey => {}
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "keystore does not match the genesis manifest's validator set",
                ))
            }
        }
        if RandaoChain::generate(keys.randao_seed).commitment()
            != manifest.validators[keys.index as usize].randao_commitment
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "local RANDAO chain does not open the manifest's committed head",
            ));
        }
    }

    let store = Store::open(&cfg.data_dir, &digest)?;
    let genesis_state = manifest.genesis_state();
    let genesis_id = manifest.genesis_id();
    println!(
        "bloch-pos node — {}, genesis {} (state root {}), network digest {}",
        match keys.as_ref() {
            Some(k) => format!("validator {}", k.index),
            None => "observer (no keystore, signs nothing)".to_string(),
        },
        crate::codec::hex8(genesis_id.as_bytes()),
        crate::codec::hex8(&genesis_state.state_root()),
        crate::codec::hex8(&digest),
    );

    let logged = store.read_all()?;
    let head_slot = Arc::new(AtomicU64::new(0));
    // Network events queued but not yet handled, metered separately per class
    // — see `net::EngineQueue`. Blocks and attestations used to share one cap
    // of 4096, which is how a flood of stale attestations silently ate the
    // quota that arriving blocks needed and left 61 of 64 validators unable to
    // deliver one.
    let queue = Arc::new(EngineQueue::new());
    let (tx, rx) = mpsc::channel::<EngineEvent>();
    // The transports speak NetEvent and know nothing about the RPC; the engine
    // consumes one channel. Rather than teach both transports the engine's
    // event type — coupling the network layer to a queue it has no business
    // knowing about — a forwarder wraps their events on the way in. One thread
    // and one hop, and each side keeps the shape it was designed with.
    let (net_tx, net_rx) = mpsc::channel::<NetEvent>();
    {
        let tx = tx.clone();
        let queue = queue.clone();
        std::thread::spawn(move || forward_admitted(net_rx, tx, queue));
    }
    let net = match cfg.transport {
        Transport::Devnet => net::Net::Devnet(net::start(
            &cfg.listen_addr,
            cfg.listen,
            cfg.peers.clone(),
            tx.clone(),
            cfg.data_dir.clone(),
            head_slot.clone(),
            queue.clone(),
        )?),
        Transport::Libp2p => {
            let parse = |s: &str, what: &str| -> io::Result<crate::p2p::Multiaddr> {
                s.parse().map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("{what} `{s}` is not a multiaddr: {e}"),
                    )
                })
            };
            let mut listen = Vec::new();
            for a in &cfg.p2p_listen {
                listen.push(parse(a, "--p2p-listen")?);
            }
            let mut peers = Vec::new();
            for a in &cfg.p2p_peers {
                peers.push(parse(a, "--p2p-peer")?);
            }
            let handle = crate::p2p::start(
                crate::p2p::Config {
                    listen,
                    peers,
                    data_dir: cfg.data_dir.clone(),
                    max_peers: cfg.max_peers,
                    behind_proxy: cfg.behind_proxy,
                },
                net_tx,
                head_slot.clone(),
            )?;
            println!("p2p: node identity {}", handle.peer_id);
            net::Net::Libp2p(handle)
        }
    };

    let mut engine = Engine {
        state: genesis_state,
        tr: Transition::new(verifier.clone()),
        tr_probe: Transition::new(ProbeVerifier),
        verifier,
        keys,
        blocks: BTreeMap::new(),
        chain: vec![(0, genesis_id)],
        canonical: BTreeSet::from([*genesis_id.as_bytes()]),
        pool: BTreeMap::new(),
        att_pool: AttestationPool::new(),
        wall_slot: 0,
        mempool: BTreeMap::new(),
        store,
        net,
        head_slot,
        live: false,
        needs_sync: false,
        last_applied_ms: now_ms(),
        booted_ms: now_ms(),
        ws_anchor: None,
        ws_anchor_hard: false,
        ws_conflict_reported: false,
        queue: queue.clone(),
        manifest,
    };

    // ── Replay: restart returns to the same state, by re-running the same
    // transition over the same inputs. ──
    //
    // Progress is reported while this runs, and that is not a nicety. Replay
    // re-applies the whole chain, and every block re-derives the state root
    // over the full committed state — 0.59s per block at Genesis-4's carryover
    // size, so a 12,200-block chain is hours. Throughout, the RPC does not
    // answer and the node logs nothing, which makes "still working" and
    // "wedged" indistinguishable from the outside. That ambiguity cost real
    // hours of investigation on 2026-08-21: a validator was down and there was
    // no way to tell whether it was progressing, stuck, or minutes from
    // finishing. An operator needs a rate and a remainder to decide whether to
    // wait or intervene, and neither existed.
    let n_logged = logged.len();
    if n_logged > 0 {
        println!(
            "replaying {n_logged} blocks from the log — the RPC stays silent until this finishes"
        );
    }
    let replay_started = std::time::Instant::now();
    let mut last_report = replay_started;
    for (i, env) in logged.into_iter().enumerate() {
        engine.ingest(env);
        // Time-based, not every-N-blocks: block cost varies by an order of
        // magnitude with how many transactions a block carries, so a fixed
        // count reports in bursts and then goes quiet exactly when the work is
        // heaviest — the opposite of what an operator needs.
        if last_report.elapsed() >= REPLAY_PROGRESS_INTERVAL {
            let done = i + 1;
            let elapsed = replay_started.elapsed().as_secs_f64();
            let rate = if elapsed > 0.0 { done as f64 / elapsed } else { 0.0 };
            let left = n_logged - done;
            println!(
                "replay {done}/{n_logged} ({:.1}%) — head slot {}, {rate:.1} blocks/s, ~{} min left",
                100.0 * done as f64 / n_logged as f64,
                engine.state.slot(),
                if rate > 0.0 { (left as f64 / rate / 60.0).ceil() as u64 } else { 0 },
            );
            last_report = std::time::Instant::now();
        }
    }
    engine.live = true;
    if n_logged > 0 {
        println!(
            "replayed {} blocks: head slot {}, state root {}, justified e{}, finalized e{}",
            n_logged,
            engine.state.slot(),
            crate::codec::hex8(&engine.state.state_root()),
            engine.state.finality().justified.epoch,
            engine.state.finality().finalized.epoch,
        );
    }
    engine
        .head_slot
        .store(engine.state.slot(), Ordering::Relaxed);

    // ── Weak subjectivity: may the node sync at all? (§4.2) ──
    //
    // Runs AFTER replay, because the question the boot decision asks — how old
    // is this node's own finalized knowledge — is only answerable once the
    // database has been replayed. Before this point the node has done nothing
    // but read its own disk; it performs no duty and follows no peer until the
    // gate says it may.
    //
    // The wall-clock epoch comes from the MANIFEST's slot clock, not from
    // `ws::wallclock_epoch` (which assumes the mainnet 30 s cadence): a devnet
    // running 500 ms slots would otherwise be judged 60× younger than it is,
    // and the age compared against the window must be measured on the same
    // clock the node's own epochs are numbered by. The NTP caveat of §1
    // applies here verbatim — a clock set backward makes a stale node look
    // fresh.
    {
        let genesis_ms = engine.manifest.genesis_time_ms;
        let slot_ms = engine.manifest.slot_ms;
        let wall_slot = now_ms().saturating_sub(genesis_ms) / slot_ms;
        let wall_epoch = epoch_of(wall_slot);
        let fin = engine.state.finality().finalized;
        // Genesis is "finalized by definition", not knowledge this node
        // witnessed. Only a finalized epoch above 0 is own finality — treating
        // the genesis checkpoint as own finality would let every fresh node
        // skip the gate, which is the whole point of the gate.
        let has_local_finality = fin.epoch > 0;
        let network_id = crate::ws_boot::network_id_of(&digest);
        let genesis_root = *genesis_id.as_bytes();
        // The genesis block IS the first weak-subjectivity anchor: trusting it
        // is trusting the manifest this node already loaded to exist at all.
        // This is what keeps a fresh devnet booting with no ceremony.
        let g_anchor = bloch_pos_committee::ws::genesis_anchor(
            network_id,
            genesis_root,
            engine.manifest.genesis_state().state_root(),
            [0u8; 32], // no validator-set SMT root exposed at this milestone
            genesis_ms / 1000,
        );
        let canonical = engine.canonical.clone();
        let local_at: Vec<(u64, [u8; 32])> = (0..=fin.epoch)
            .filter_map(|e| engine.own_finalized_root_at(e).map(|r| (e, r)))
            .collect();
        let outcome = crate::ws_boot::boot(
            &cfg.ws,
            &cfg.data_dir,
            network_id,
            &genesis_root,
            &g_anchor,
            wall_epoch,
            has_local_finality,
            (fin.epoch, fin.root),
            |e| local_at.iter().find(|(k, _)| *k == e).map(|(_, r)| *r),
            |root| canonical.contains(root),
        )?;
        match outcome {
            Ok(ws) => {
                for w in &ws.warnings {
                    println!("{w}");
                }
                println!(
                    "weak subjectivity: anchored at epoch {} ({}), {} own finality",
                    ws.anchor_epoch,
                    crate::codec::hex8(&ws.anchor_root),
                    if ws.anchor_is_hard { "WITHOUT" } else { "with" },
                );
                engine.ws_anchor = Some((ws.anchor_epoch, ws.anchor_root));
                engine.ws_anchor_hard = ws.anchor_is_hard;
                engine.enforce_ws_anchor();
            }
            Err(msg) => return Err(io::Error::new(io::ErrorKind::PermissionDenied, msg)),
        }
    }

    // ── The JSON-RPC server ──
    //
    // Started HERE, after replay and after the weak-subjectivity gate, and the
    // order is the point: until this line the engine is not reading its event
    // channel, so a request arriving earlier would block a client for the whole
    // of boot. It also means the node never answers a query before it has
    // decided it is allowed to follow this chain at all — a node that served
    // `getchaininfo` during boot would be publishing a head it had not yet
    // earned the right to have.
    if let Some(port) = cfg.rpc_port {
        let backend = Arc::new(crate::rpc::EngineBackend::new(tx.clone()));
        match crate::rpc::serve(&cfg.rpc_bind, port, backend) {
            Ok(addr) => {
                println!("JSON-RPC listening on http://{addr}");
                if !addr.ip().is_loopback() {
                    // Not a log line among log lines: this port has no
                    // authentication and `sendrawtransaction` is a write.
                    eprintln!(
                        "WARNING: the RPC is bound to {}, which is not loopback. It has \
                         NO authentication, NO rate limiting and NO authorisation — \
                         anything that can reach this port can read the node's full \
                         state and submit transactions. Restrict it at the firewall to \
                         the clients that are meant to reach it.",
                        addr.ip()
                    );
                }
            }
            Err(e) => {
                // A node that was asked for an RPC and could not bind must not
                // quietly run without one: the operator would find out from a
                // client's timeouts.
                return Err(io::Error::new(
                    e.kind(),
                    format!("cannot bind the RPC to {}:{port}: {e}", cfg.rpc_bind),
                ));
            }
        }
    }

    // ── The slot loop ──
    let genesis_ms = engine.manifest.genesis_time_ms;
    let slot_ms = engine.manifest.slot_ms;
    let mut last_attested: u64 = engine.state.slot();
    let mut last_built: u64 = engine.state.slot();
    let mut last_sync_req: u64 = 0;

    loop {
        let now = now_ms();
        if now < genesis_ms {
            std::thread::sleep(Duration::from_millis((genesis_ms - now).min(200)));
            continue;
        }
        let slot = (now - genesis_ms) / slot_ms;
        let slot_start = genesis_ms + slot * slot_ms;
        let wall_epoch = epoch_of(slot);
        if slot != engine.wall_slot {
            engine.wall_slot = slot;
            // Drop everything the acceptance window has moved past. The pool
            // reads no clock of its own, so this is the only thing that bounds
            // it — without the call its `seen` map grows with uptime.
            engine.att_pool.prune(slot);
        }

        if let Some(stop) = cfg.stop_at_slot {
            if slot >= stop {
                let fin = engine.state.finality();
                println!(
                    "STOP at slot {stop}: head slot {}, {} blocks, state root {}, justified e{} ({}), finalized e{} ({})",
                    engine.state.slot(),
                    engine.chain.len() - 1,
                    crate::codec::hex32(&engine.state.state_root()),
                    fin.justified.epoch,
                    crate::codec::hex8(&fin.justified.root),
                    fin.finalized.epoch,
                    crate::codec::hex8(&fin.finalized.root),
                );
                return Ok(());
            }
        }

        // Boot grace: give the mesh one round of sync before performing
        // duties, so a restarted proposer does not build on a stale head.
        let in_grace = now.saturating_sub(engine.booted_ms) < 2 * slot_ms;

        if !in_grace && slot > last_attested {
            engine.attest(slot);
            last_attested = slot;
        }
        let propose_at = slot_start + slot_ms / 3;
        if !in_grace && now >= propose_at && slot > last_built {
            engine.propose(slot);
            last_built = slot;
        }

        // Sync when behind or when a stored branch has holes. Rate-limited;
        // idempotent on the receiving side (dedup discards repeats).
        let behind = engine.state.slot() + 1 < slot
            && now.saturating_sub(engine.last_applied_ms) > 2 * slot_ms;
        if (behind || engine.needs_sync) && now.saturating_sub(last_sync_req) > 2 * slot_ms {
            engine
                .net
                .broadcast(net::get_blocks_frame(engine.state.slot()));
            engine.needs_sync = false;
            last_sync_req = now;
        }

        let next_deadline = if slot > last_built && now < propose_at {
            propose_at
        } else {
            slot_start + slot_ms
        };
        let wait = next_deadline.saturating_sub(now_ms()).clamp(1, 500);
        match rx.recv_timeout(Duration::from_millis(wait)) {
            Ok(ev) => {
                let mut pending = vec![ev];
                while let Ok(more) = rx.try_recv() {
                    pending.push(more);
                }
                for ev in pending {
                    // No release step: each `Net` event carries its permit, and
                    // binding it in the arm holds the quota until the arm ends
                    // — after the work, not on dequeue. The version this
                    // replaces subtracted here, before the `match`, under a
                    // comment claiming the opposite.
                    match ev {
                        EngineEvent::Net(NetEvent::Block(env), _permit) => engine.ingest(env),
                        EngineEvent::Net(NetEvent::Attestation(att, origin), _permit) => {
                            engine.on_attestation(att, origin, wall_epoch)
                        }
                        EngineEvent::Net(NetEvent::Transaction(tx), _permit) => {
                            // Gossip has nobody to answer to; the verdict is the
                            // RPC's concern, not a peer's.
                            let _ = engine.on_transaction(tx);
                        }
                        EngineEvent::Rpc(call) => {
                            let result = engine.serve_rpc(call.req);
                            // A client that hung up between asking and being
                            // answered is normal, not an error worth logging.
                            let _ = call.reply.send(result);
                        }
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "network channel closed",
                ));
            }
        }
    }
}

/// LMD-GHOST head over `blocks`, given the loose attestations in `pool`, the
/// stake-weighted `validators`, and the `justified` root the walk starts from.
///
/// A free function of its inputs, not a method over node state, for the reason
/// §5.5 gives: a consensus-relevant value must be derivable from arguments so
/// it can be reasoned about and tested without standing up a node. It is also
/// what makes the divergence from longest-chain testable at all — see
/// `forkchoice_tests::weight_beats_length` at the bottom of this file.
pub fn lmd_ghost_head<'a>(
    blocks: &BTreeMap<[u8; 32], BlockEnvelope>,
    pool: impl Iterator<Item = &'a Attestation>,
    validators: &[bloch_pos_committee::sample::Validator],
    justified: [u8; 32],
) -> [u8; 32] {
    let mut parents: HashMap<[u8; 32], [u8; 32]> = HashMap::new();
    let mut children: HashMap<[u8; 32], Vec<[u8; 32]>> = HashMap::new();
    for (id, env) in blocks {
        parents.insert(*id, env.header.parent);
        children.entry(env.header.parent).or_default().push(*id);
    }
    for kids in children.values_mut() {
        kids.sort_unstable();
    }

    let mut fc = FcStore::new();
    // Weight is the stake the CANONICAL state committed. A competing branch may
    // commit a different validator set; using its numbers would let a branch
    // vote itself heavier, so the fork choice reads one set — the one this node
    // has validated — exactly as Ethereum weights by the justified state.
    for v in validators {
        fc.set_stake(v.index, v.effective_stake);
    }
    for env in blocks.values() {
        for att in &env.body.attestations {
            fc.observe(
                att.validator,
                LatestMessage {
                    slot: att.data.slot,
                    root: att.data.head,
                },
            );
        }
    }
    // Attestations seen on the wire but not yet in any block count too: that is
    // what makes the head responsive within a slot instead of one block behind.
    for att in pool {
        fc.observe(
            att.validator,
            LatestMessage {
                slot: att.data.slot,
                root: att.data.head,
            },
        );
    }

    let tree = BlockTree { parents: &parents };
    fc.head(&tree, justified, &children)
}

/// Whether the mempool will hold `tx` at all.
///
/// A free function, not a method, so it can be tested without standing up an
/// engine — the checks are a pure function of the transaction and the
/// caller's `wall_epoch`, nothing else, and a rule that needs a running node
/// to exercise is a rule that stops being exercised.
///
/// `wall_epoch` is the admitting node's WALL-CLOCK epoch
/// (`epoch_of(self.wall_slot())` at the call site in `on_transaction`), and
/// it exists for exactly one arm: the `TransferV2` flag-day gate below. It is
/// in EPOCHS, not slots — `TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH`
/// (params.rs:150) is an epoch, and a caller passing a raw slot would be
/// early by `SLOTS_PER_EPOCH` (32×). The boundary test pins the unit by
/// deriving both sides of the flag day from slots via `epoch_of`.
///
/// Deliberately STRUCTURAL, not a validity check. A complete answer means
/// running the transition, which needs a candidate header this path has no
/// reason to build. What it catches is the class that has actually been
/// exploited or is currently exploitable.
pub(crate) fn admissible(tx: &PosTransaction, wall_epoch: u64) -> Result<(), &'static str> {
    match tx {
        // Staking messages are refused outright until bonding is funded from
        // the eUTXO set.
        //
        // `Deposit` carries no signature and spends no output: it names an
        // `amount_sat` and the transition registers a validator holding it.
        // `transition.rs` documents the gap ("a deposit creates bonded stake
        // without destroying spendable coins"), which was tolerable while the
        // two pools only ever met on a devnet. On a live chain behind a public
        // endpoint it is stake minted from nothing — measured on 2026-08-13 at
        // 25,000 BLOCH per unauthenticated request, roughly forty-six requests
        // to a third of the active stake and stop finality, a hundred and
        // eighty to two thirds and take the chain.
        //
        // This is a node-side refusal, not a consensus rule: a block that
        // already carries a deposit still applies it. It closes the path anyone
        // can reach and buys time to close the real one — giving deposits and
        // withdrawals eUTXO inputs and outputs, which is a wire-format change
        // and needs a flag day.
        PosTransaction::Deposit { .. } => Err(
            "deposits are not accepted: bonding is not yet funded from the UTXO set, \
             so a deposit would create stake without spending coins",
        ),
        PosTransaction::Delegate { .. } => Err(
            "delegations are not accepted: bonding is not yet funded from the UTXO set, \
             so a delegation would create stake without spending coins",
        ),
        // One transaction consensus would never apply halted the live testnet:
        // every proposer that selected it failed to produce, and the chain
        // stopped at slot 69 with every node up and still attesting. Cost of
        // the attack: one unauthenticated request.
        PosTransaction::Transfer {
            inputs, outputs, ..
        } => {
            if inputs.is_empty() {
                return Err("transfer has no inputs — it spends nothing and cannot apply");
            }
            if outputs.is_empty() {
                return Err("transfer has no outputs — it pays no one and cannot apply");
            }
            // THE SIGNATURE IS CHECKED HERE, BEFORE THE MEMPOOL, AND THIS IS WHY.
            //
            // The producer prices its own block with `ProbeVerifier`, whose
            // verify_with_key returns true for anything (keys.rs). A Transfer's spend
            // signature is checked THROUGH that injected verifier
            // (transition.rs, "Authorisation: the expensive check, last"), so a
            // transfer with a valid shape and a garbage signature passes the probe,
            // goes into a proposed block, and is then refused by the real
            // HybridVerifier during ingest. The head does not move, and the
            // assert below used to turn that into a panic — one transaction, and
            // every node that proposed it died in its own slot.
            //
            // Refusing at the mempool door is what stops it PROPAGATING. The
            // signature is the expensive check and it is deliberately last, after
            // the two free ones above.
            let signing_root = tx.spend_signing_root();
            for i in inputs {
                if !bloch_crypto::crypto::verify(&i.pubkey, &signing_root, &i.signature) {
                    return Err("transfer carries a signature that does not verify");
                }
            }
            Ok(())
        }
        // TransferV2 (tag 0x06): admitted from its flag day, refused before
        // it — the era decides, and WHICH era to read differs on the two
        // sides of the mempool door.
        //
        // Consensus gates this format on COMMITTED state rolled to the
        // block's own epoch (`apply_transaction`'s FormatNotActive arm,
        // transition.rs:1706–1718) and must: deriving a consensus verdict
        // from anything node-local is how the 2026-08-08 `expected_bits`
        // fork happened. Admission is NOT consensus — it is node-local
        // policy, and it answers a different question: "can some FUTURE
        // block apply this?". Every block is proposed for a wall-clock slot
        // (the slot loop, `run`), so every block that could carry this
        // transaction has an epoch >= the admitting node's wall epoch; from
        // wall epoch 800 onward no future block answers FormatNotActive.
        // Reading the HEAD's epoch here instead would strand exactly the
        // nodes the post-flag-day carryover sweep (426,194 inputs) must
        // relay through: a syncing or lagging node has a head epochs behind
        // the wall and would refuse the format after activation — the
        // "admitted too late, never propagates" failure. The residue of the
        // wall-clock choice is only boundary skew: a fast clock admits and
        // gossips seconds before its peers activate. Peers refuse without
        // penalty (the gossip path answers to nobody — `on_transaction`'s
        // caller ignores the verdict), and a still-799 proposer that
        // selects it probe-drops it from the mempool one transaction at a
        // time instead of stalling (the drop-and-retry loop in `propose`,
        // the slot-69 lesson). Early side costs one ejected, resendable
        // transaction; late side costs the sweep. The asymmetry decides.
        PosTransaction::TransferV2 {
            keys,
            inputs,
            outputs,
            ..
        } => {
            // The gate first, and pre-activation the refusal is today's,
            // byte for byte: before epoch 800 this arm's behaviour is the
            // CONTROL and must not move.
            if wall_epoch < bloch_pos_committee::params::TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH {
                return Err(
                    "deduplicated transfers (tag 0x06) are not active: the format ships \
                     behind a flag day (TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH) that this \
                     chain has not reached",
                );
            }
            // Cheap-first from here, mirroring the Transfer arm above and
            // the consensus arm this one fronts for (`apply_transfer_v2`,
            // transition.rs:2017–2130): structure, then table discipline,
            // then — last and only then — signatures. This path is
            // unauthenticated, so an invalid shape must cost zero hybrid
            // verifications (~145 µs each, measured 2026-08-21).
            if inputs.is_empty() {
                return Err("transfer has no inputs — it spends nothing and cannot apply");
            }
            if outputs.is_empty() {
                return Err("transfer has no outputs — it pays no one and cannot apply");
            }
            // An empty witness table would make the signature loop below
            // pass VACUOUSLY — zero verifications, admitted, gossiped — so a
            // shape consensus can never apply (every input must index into
            // the table) would traverse the mesh for free. That is the
            // mempool-stuffing class this function exists to refuse, and
            // the check is load-bearing, not defensive.
            if keys.is_empty() {
                return Err(
                    "deduplicated transfer carries no witness keys — nothing authorises it",
                );
            }
            // Stateless mirror of the table disciplines consensus enforces
            // and has mutation-proven (transition.rs:2043–2094 —
            // DuplicateWitnessKey, BadKeyIndex, WitnessKeyUnused). The one
            // V2 consensus check that CANNOT run here is ScriptMismatch: it
            // reads the spent outputs' committed `script_hash`
            // (transition.rs:2077), and this function is deliberately
            // stateless. Like V1's unknown-input case, that class reaches
            // the mempool and dies in the proposer's probe.
            let mut distinct: BTreeSet<&[u8]> = BTreeSet::new();
            for k in keys {
                if !distinct.insert(k.pubkey.as_slice()) {
                    return Err(
                        "deduplicated transfer repeats a witness key — one entry per owner",
                    );
                }
            }
            let mut used = vec![false; keys.len()];
            for i in inputs {
                let Some(slot) = used.get_mut(i.key_index as usize) else {
                    return Err("transfer input names a witness index outside the table");
                };
                *slot = true;
            }
            if used.iter().any(|u| !*u) {
                return Err(
                    "witness table carries an entry no input references — unpaid padding",
                );
            }
            // THE SIGNATURES, LAST — same placement and same reason as the
            // Transfer arm above, but ONE verification per TABLE ENTRY,
            // never per input. That is the format's entire point and the
            // exact economy consensus runs (`apply_transfer_v2`,
            // "Authorisation: the expensive check, last — ONCE PER OWNER"):
            // the signing root covers every spend point, so one signature
            // per key authorises all of that key's inputs. Admitting an
            // unverified table would hand an attacker free propagation of
            // garbage that every proposer then pays to drop.
            let signing_root = tx.spend_signing_root();
            for k in keys {
                if !bloch_crypto::crypto::verify(&k.pubkey, &signing_root, &k.signature) {
                    return Err("transfer carries a signature that does not verify");
                }
            }
            Ok(())
        }
        // Exit is UNAUTHENTICATED: its arm in transition.rs checks registry
        // state and never touches a verifier, and this catch-all used to admit
        // it. Sixty-four Exit messages would set exit_epoch on all sixty-four
        // validators, and an exit cannot be revoked (`exit_epoch != u64::MAX`
        // is refused), so the roster would empty and every bond lock for
        // 2,080 epochs. Refused until the message carries a signature that
        // binds it to the validator's own key.
        PosTransaction::Exit { .. } => Err(
            "exits are not accepted: the Exit message is not authenticated, \
             so anyone could retire any validator irreversibly",
        ),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod forkchoice_tests {
    use super::*;
    use bloch_pos_committee::sample::Validator;

    fn header(parent: [u8; 32], slot: u64, marker: u8) -> BlockHeaderV4 {
        BlockHeaderV4 {
            version: VERSION_G4,
            parent,
            state_root: [marker; 32],
            body_root: [0u8; 32],
            slot,
            proposer_index: 0,
            randao_reveal: [0u8; 32],
            randao_mix: [0u8; 32],
            justified_root: [0u8; 32],
            finalized_root: [0u8; 32],
            attestation_root: [0u8; 32],
            coherence_root: [0u8; 32],
        }
    }

    fn attest(validator: u32, slot: u64, head: [u8; 32]) -> Attestation {
        Attestation {
            validator,
            data: AttestationData {
                slot,
                head,
                source_epoch: 0,
                source_root: [0u8; 32],
                target_epoch: 0,
                target_root: head,
            },
            signature: Vec::new(),
        }
    }

    /// Build `blocks` from `(parent, slot, marker, attestations)` tuples,
    /// returning the map and each block's id in order.
    fn chain_of(
        specs: Vec<([u8; 32], u64, u8, Vec<Attestation>)>,
    ) -> (BTreeMap<[u8; 32], BlockEnvelope>, Vec<[u8; 32]>) {
        let mut blocks = BTreeMap::new();
        let mut ids = Vec::new();
        for (parent, slot, marker, atts) in specs {
            let h = header(parent, slot, marker);
            let id = *BlockId::of(&h).as_bytes();
            blocks.insert(
                id,
                BlockEnvelope {
                    header: h,
                    proposer_sig: Vec::new(),
                    body: Body {
                        transactions: Vec::new(),
                        attestations: atts,
                    },
                },
            );
            ids.push(id);
        }
        (blocks, ids)
    }

    fn vals(n: u32) -> Vec<Validator> {
        (0..n)
            .map(|index| Validator {
                index,
                effective_stake: 100,
            })
            .collect()
    }

    /// **The reason this fork choice was changed.** A branch three blocks long
    /// with one attester loses to a branch one block long with three.
    ///
    /// Under longest-valid-chain — what the node ran until now — the head is
    /// the tip of the long branch, and a proposer who can produce blocks fast
    /// overrides whatever the honest majority has voted for. Length is not the
    /// security statement in proof of stake; attested stake is. Without this
    /// test, swapping the implementations would be a claim rather than a
    /// change: the cooperative devnet passes either way, because on a chain
    /// with no forks the two rules agree.
    /// The exposure this closes: a `Deposit` names an amount, carries no
    /// signature, and spends no output. Until bonding is funded from the eUTXO
    /// set, admitting one is admitting stake minted from nothing.
    #[test]
    fn staking_messages_are_refused_until_bonding_is_funded() {
        let deposit = PosTransaction::Deposit {
            pubkey: vec![0u8; 32],
            amount_sat: 25_000 * 100_000_000,
            randao_commitment: [7u8; 32],
            withdrawal_credentials: vec![1u8; 20],
            commission_bps: 0,
        };
        let err = admissible(&deposit, 0).expect_err("a deposit must not be admitted");
        assert!(
            err.contains("not yet funded"),
            "the refusal must say why: {err}"
        );

        let delegate = PosTransaction::Delegate {
            delegator: 0,
            validator: 0,
            amount_sat: 1,
            eligible: true,
        };
        assert!(
            admissible(&delegate, 0).is_err(),
            "a delegation must not be admitted either"
        );
    }

    /// The transfer guard that already existed, pinned so the refactor into a
    /// free function cannot quietly drop it — this is the check that stopped
    /// the one-request halt at slot 69.
    #[test]
    fn a_transfer_that_spends_nothing_is_refused() {
        let empty = PosTransaction::Transfer {
            inputs: vec![],
            outputs: vec![bloch_pos_committee::transition::TransferOutput {
                value: 1,
                script_hash: [0u8; 32],
            }],
            tx_bytes: 0,
            tip_millisat_per_gas: 0,
        };
        assert!(
            admissible(&empty, 0).is_err(),
            "a transfer with no inputs must not be admitted"
        );
    }

    #[test]
    fn weight_beats_length() {
        let g = [0x99u8; 32]; // the justified root the walk starts from

        // Long branch: three blocks, one attester on the tip.
        // Short branch: one block, three attesters.
        let (mut blocks, long_ids) = chain_of(vec![(g, 1, 1, vec![])]);
        let a1 = long_ids[0];
        let (more, a_rest) = chain_of(vec![(a1, 2, 2, vec![])]);
        blocks.extend(more);
        let a2 = a_rest[0];
        let (more, a_rest) = chain_of(vec![(a2, 3, 3, vec![])]);
        blocks.extend(more);
        let a3 = a_rest[0];

        let (short, short_ids) = chain_of(vec![(g, 1, 9, vec![])]);
        blocks.extend(short);
        let b1 = short_ids[0];
        assert_ne!(a1, b1, "the two branches must actually be siblings");

        let validators = vals(4);
        // Validator 0 attests the long tip; 1, 2 and 3 attest the short one.
        let pool = vec![
            attest(0, 3, a3),
            attest(1, 1, b1),
            attest(2, 1, b1),
            attest(3, 1, b1),
        ];

        let head = lmd_ghost_head(&blocks, pool.iter(), &validators, g);
        assert_eq!(
            head, b1,
            "fork choice followed length instead of attested weight — LMD-GHOST is not wired"
        );

        // And the converse, so the assertion above is not passing for some
        // incidental reason: move the weight and the head moves with it.
        let pool_flipped = vec![
            attest(0, 3, a3),
            attest(1, 3, a3),
            attest(2, 3, a3),
            attest(3, 1, b1),
        ];
        assert_eq!(
            lmd_ghost_head(&blocks, pool_flipped.iter(), &validators, g),
            a3
        );
    }

    /// The head is a function of the message *set*. Feeding the same
    /// attestations in a different order must not move it — the property whose
    /// violation in `Store::observe` made two honest nodes with identical
    /// inputs compute different heads (found 2026-08-11).
    #[test]
    fn head_is_independent_of_attestation_order() {
        let g = [0x99u8; 32];
        let (mut blocks, ids) = chain_of(vec![(g, 1, 1, vec![])]);
        let a1 = ids[0];
        let (short, sids) = chain_of(vec![(g, 1, 9, vec![])]);
        blocks.extend(short);
        let b1 = sids[0];

        let validators = vals(4);
        let mut pool = vec![attest(0, 1, a1), attest(1, 1, b1), attest(2, 1, b1)];
        let first = lmd_ghost_head(&blocks, pool.iter(), &validators, g);
        pool.reverse();
        let second = lmd_ghost_head(&blocks, pool.iter(), &validators, g);
        assert_eq!(first, second);
    }

    /// Attestations from validators the canonical state does not know carry no
    /// weight. Otherwise a branch could invent voters — the fork choice reads
    /// one validator set, not the one each branch commits.
    #[test]
    fn unknown_validators_carry_no_weight() {
        let g = [0x99u8; 32];
        let (mut blocks, ids) = chain_of(vec![(g, 1, 1, vec![])]);
        let a1 = ids[0];
        let (short, sids) = chain_of(vec![(g, 1, 9, vec![])]);
        blocks.extend(short);
        let b1 = sids[0];

        // Only validator 0 exists; it votes the long-branch block. Fifty
        // invented voters back the other one.
        let validators = vals(1);
        let mut pool = vec![attest(0, 1, a1)];
        pool.extend((100..150u32).map(|v| attest(v, 1, b1)));
        assert_eq!(lmd_ghost_head(&blocks, pool.iter(), &validators, g), a1);
    }

    /// An equivocator is barred entirely, not counted for either side. With the
    /// remaining honest stake tied, the tie-break is the larger root — the only
    /// property that matters being that every node breaks it the same way.
    #[test]
    fn equivocator_weight_is_discarded() {
        let g = [0x99u8; 32];
        let (mut blocks, ids) = chain_of(vec![(g, 1, 1, vec![])]);
        let a1 = ids[0];
        let (short, sids) = chain_of(vec![(g, 1, 9, vec![])]);
        blocks.extend(short);
        let b1 = sids[0];

        let validators = vals(2);
        // Validator 1 signs both heads in the same slot; validator 0 backs a1.
        let pool = vec![attest(0, 1, a1), attest(1, 1, a1), attest(1, 1, b1)];
        let head = lmd_ghost_head(&blocks, pool.iter(), &validators, g);
        assert_eq!(
            head, a1,
            "the equivocator was counted, or the honest vote was dropped"
        );
    }
}

#[cfg(test)]
mod admission_authorisation {
    use super::*;
    use bloch_pos_committee::transition::{TransferInput, TransferOutput};

    /// A transfer signed for real, and the same transfer with the signature
    /// corrupted. Both must reach `admissible` — one accepted, one refused.
    fn signed_transfer() -> (PosTransaction, Vec<u8>) {
        let (pk, sk) = bloch_crypto::crypto::generate_keypair_from_seed(&[9u8; 32])
            .expect("hybrid keypair from a fixed seed");
        let mut tx = PosTransaction::Transfer {
            inputs: vec![TransferInput {
                txid: [0x11u8; 32],
                vout: 0,
                pubkey: pk.clone(),
                signature: Vec::new(),
            }],
            outputs: vec![TransferOutput {
                value: 1_000,
                script_hash: [0x22u8; 32],
            }],
            tx_bytes: 0,
            tip_millisat_per_gas: 0,
        };
        let root = tx.spend_signing_root();
        let sig = bloch_crypto::crypto::sign(&sk, &root).expect("sign the spend root");
        if let PosTransaction::Transfer { inputs, .. } = &mut tx {
            inputs[0].signature = sig.clone();
        }
        (tx, sig)
    }

    #[test]
    fn a_correctly_signed_transfer_is_still_admitted() {
        // THE REGRESSION THAT WOULD MATTER MOST. A signature check that refuses
        // everything stops the chain accepting any transfer at all — worse than
        // the hole it closes.
        let (tx, _) = signed_transfer();
        assert!(
            admissible(&tx, 0).is_ok(),
            "a validly signed transfer must still reach the mempool"
        );
        // V1 is EPOCH-INDEPENDENT, on both sides of the TransferV2 flag day
        // (params.rs:150). Part of the pre-activation control: teaching the
        // epoch to `admissible` must change nothing about the format the
        // chain already runs on.
        assert!(
            admissible(
                &tx,
                bloch_pos_committee::params::TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH
            )
            .is_ok(),
            "a V1 transfer must be admitted identically after the V2 flag day"
        );
    }

    #[test]
    fn a_garbage_signature_is_refused_before_the_mempool() {
        let (mut tx, sig) = signed_transfer();
        if let PosTransaction::Transfer { inputs, .. } = &mut tx {
            // One flipped byte: the shape stays valid, the signature does not.
            let mut bad = sig;
            bad[0] ^= 0xFF;
            inputs[0].signature = bad;
        }
        let err = admissible(&tx, 0).expect_err("a bad signature must not be admitted");
        assert!(
            err.contains("signature"),
            "the refusal must name the reason, got: {err}"
        );
    }

    #[test]
    fn an_unauthenticated_exit_is_refused() {
        let err = admissible(&PosTransaction::Exit { validator: 0 }, 0)
            .expect_err("Exit carries no signature and must not be admitted");
        assert!(err.contains("not authenticated"), "got: {err}");
    }

    // ── TransferV2 admission: the flag-day arm ──────────────────────────────
    //
    // Every rule below carries its control half in the same test, and each
    // was proven by mutation on 2026-08-22 (session logged per test): the
    // rule under test was disabled in `admissible`'s TransferV2 arm, the
    // named test failed, the mutation was reverted, and the suite went green
    // again. A test that survives the disabling of its own rule is
    // decorative, and decorative tests are how this codebase already shipped
    // one consensus regression.

    use bloch_pos_committee::params::TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH as V2_FLAG_DAY;
    use bloch_pos_committee::transition::{TransferInputV2, WitnessKey};

    /// A `TransferV2` signed for real: `n` inputs owned by ONE key, one
    /// witness-table entry — the single-owner many-input shape the format
    /// exists for. The signing root covers spend points, outputs and the two
    /// fee terms only (`fold_spend`, transition.rs), NOT the table — the
    /// table is witness — so tests below may mutate the table afterwards
    /// without invalidating the signature, which is exactly what the
    /// discipline tests need (and mirrors what a malicious relay can do).
    fn signed_transfer_v2(n: u32) -> PosTransaction {
        let (pk, sk) = bloch_crypto::crypto::generate_keypair_from_seed(&[9u8; 32])
            .expect("hybrid keypair from a fixed seed");
        let inputs: Vec<TransferInputV2> = (0..n)
            .map(|vout| TransferInputV2 {
                txid: [0x11u8; 32],
                vout,
                key_index: 0,
            })
            .collect();
        let mut tx = PosTransaction::TransferV2 {
            keys: vec![WitnessKey {
                pubkey: pk,
                signature: Vec::new(),
            }],
            inputs,
            outputs: vec![TransferOutput {
                value: 1_000,
                script_hash: [0x22u8; 32],
            }],
            tx_bytes: 0,
            tip_millisat_per_gas: 0,
        };
        let root = tx.spend_signing_root();
        let sig = bloch_crypto::crypto::sign(&sk, &root).expect("sign the spend root");
        if let PosTransaction::TransferV2 { keys, .. } = &mut tx {
            keys[0].signature = sig;
        }
        tx
    }

    /// The flag day itself, with the unit pinned: both epochs are DERIVED
    /// FROM SLOTS via `epoch_of`, because the gate compares EPOCHS against
    /// `TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH` (params.rs:150) and a call
    /// site that handed it a raw wall SLOT would activate 32× early —
    /// silently, since both are bare u64s.
    ///
    /// Mutation log (2026-08-22): gate `<` → `<=` — the admit half dies;
    /// arm reverted to the old unconditional Err — the admit half dies;
    /// gate deleted — the refuse half dies.
    #[test]
    fn v2_is_refused_the_epoch_before_the_flag_day_and_admitted_at_it() {
        use bloch_pos_committee::SLOTS_PER_EPOCH;
        let last_slot_before = V2_FLAG_DAY * SLOTS_PER_EPOCH - 1;
        let first_slot_at = V2_FLAG_DAY * SLOTS_PER_EPOCH;
        assert_eq!(epoch_of(last_slot_before), V2_FLAG_DAY - 1);
        assert_eq!(epoch_of(first_slot_at), V2_FLAG_DAY);

        let tx = signed_transfer_v2(4);
        // CONTROL half — pre-activation IS today's behaviour, and today's
        // refusal string, on the same transaction bytes.
        let err = admissible(&tx, epoch_of(last_slot_before))
            .expect_err("one epoch before the flag day the format must still be refused");
        assert!(
            err.contains("not active"),
            "the pre-activation refusal must be today's, got: {err}"
        );
        // The change under test: the same bytes cross the door at 800.
        assert!(
            admissible(&tx, epoch_of(first_slot_at)).is_ok(),
            "at the flag-day epoch a validly signed V2 must be admitted"
        );
    }

    /// (b) of the task: the table signatures are verified AT ADMISSION, the
    /// way the Transfer arm verifies per-input ones — otherwise an attacker
    /// fills every mempool on the mesh with garbage for free after the flag
    /// day, and every proposer pays to probe-drop it.
    ///
    /// Mutation log (2026-08-22): verify loop deleted from the V2 arm —
    /// this test dies (the good-signature control half survives, proving
    /// the death is the loop's).
    #[test]
    fn v2_signature_is_checked_before_the_mempool() {
        let good = signed_transfer_v2(4);
        assert!(
            admissible(&good, V2_FLAG_DAY).is_ok(),
            "control: the correctly signed sweep must be admitted"
        );
        let mut bad = good.clone();
        if let PosTransaction::TransferV2 { keys, .. } = &mut bad {
            // One flipped byte: shape and table stay valid, signature not.
            keys[0].signature[0] ^= 0xFF;
        }
        let err = admissible(&bad, V2_FLAG_DAY)
            .expect_err("a bad table signature must not be admitted");
        assert!(err.contains("signature"), "got: {err}");
    }

    /// An empty witness table must be refused BY NAME. The signature loop
    /// alone passes vacuously over `keys = []` (zero verifications); the
    /// index-bounds check below it would still catch the shape (any input's
    /// `key_index` misses an empty table), which is why this test pins the
    /// REFUSAL MESSAGE and not just the refusal: it proves the dedicated
    /// check fired, and keeps the two rules independent instead of one
    /// silently load-bearing for the other.
    ///
    /// Mutation log (2026-08-22): `keys.is_empty()` check deleted — this
    /// test dies on the message assertion (the shape is then refused as a
    /// bad index, which is the wrong reason told to the wrong sender).
    #[test]
    fn v2_empty_witness_table_is_refused_not_vacuously_passed() {
        let good = signed_transfer_v2(2);
        assert!(
            admissible(&good, V2_FLAG_DAY).is_ok(),
            "control: the same transaction with its table populated is admitted"
        );
        let mut empty = good.clone();
        if let PosTransaction::TransferV2 { keys, .. } = &mut empty {
            keys.clear();
        }
        let err = admissible(&empty, V2_FLAG_DAY)
            .expect_err("an empty witness table must not be admitted");
        assert!(err.contains("no witness keys"), "got: {err}");
    }

    /// Stateless mirror of consensus's `DuplicateWitnessKey`
    /// (transition.rs:2043–2052). The duplicate entry carries the SAME valid
    /// signature and every entry is referenced, so only the duplicate rule
    /// can be what refuses it — the control is the identical transaction
    /// before the table was doubled.
    ///
    /// Mutation log (2026-08-22): duplicate check deleted — this test dies
    /// (the doubled table verifies twice and is admitted).
    #[test]
    fn v2_duplicate_witness_key_is_refused() {
        let good = signed_transfer_v2(2);
        assert!(admissible(&good, V2_FLAG_DAY).is_ok(), "control");
        let mut dup = good.clone();
        if let PosTransaction::TransferV2 { keys, inputs, .. } = &mut dup {
            let copy = keys[0].clone();
            keys.push(copy);
            // Both entries referenced, so WitnessKeyUnused cannot be the
            // refusal; both signatures valid, so neither can the verify loop.
            inputs[1].key_index = 1;
        }
        let err = admissible(&dup, V2_FLAG_DAY)
            .expect_err("a repeated witness key must not be admitted");
        assert!(err.contains("repeats a witness key"), "got: {err}");
    }

    /// Stateless mirror of consensus's `BadKeyIndex` (transition.rs:2071).
    ///
    /// Mutation log (2026-08-22): bounds refusal weakened to ignore
    /// out-of-range indices — this test dies (entry 0 is still referenced by
    /// input 0, coverage passes, the signature passes, admitted).
    #[test]
    fn v2_out_of_table_key_index_is_refused() {
        let good = signed_transfer_v2(2);
        assert!(admissible(&good, V2_FLAG_DAY).is_ok(), "control");
        let mut bad = good.clone();
        if let PosTransaction::TransferV2 { inputs, .. } = &mut bad {
            // key_index is witness data outside the signing root
            // (transition.rs, `TransferInputV2::key_index` doc), so this is
            // a mutation a relay can make without touching the signature.
            inputs[1].key_index = 7;
        }
        let err = admissible(&bad, V2_FLAG_DAY)
            .expect_err("an input pointing outside the table must not be admitted");
        assert!(err.contains("outside the table"), "got: {err}");
    }

    /// Stateless mirror of consensus's `WitnessKeyUnused`
    /// (transition.rs:2088–2094): an unreferenced entry is relay-stuffable
    /// padding. The control half re-points an input at the second entry —
    /// same two keys, both signatures valid over the same root — and IS
    /// admitted, proving the refusal was about the dangling entry and not
    /// about carrying a second owner at all.
    ///
    /// Mutation log (2026-08-22): coverage check deleted — the refuse half
    /// dies (both signatures verify and the padded table is admitted).
    #[test]
    fn v2_unreferenced_table_entry_is_refused() {
        let good = signed_transfer_v2(2);
        let root = good.spend_signing_root();
        let (pk2, sk2) = bloch_crypto::crypto::generate_keypair_from_seed(&[10u8; 32])
            .expect("second hybrid keypair");
        let sig2 = bloch_crypto::crypto::sign(&sk2, &root).expect("second signature");

        let mut padded = good.clone();
        if let PosTransaction::TransferV2 { keys, .. } = &mut padded {
            keys.push(WitnessKey {
                pubkey: pk2,
                signature: sig2,
            });
        }
        let err = admissible(&padded, V2_FLAG_DAY)
            .expect_err("a table entry no input references must not be admitted");
        assert!(err.contains("no input references"), "got: {err}");

        // CONTROL: reference the second entry and the same table passes.
        // (Admission cannot know whose script_hash each input commits to —
        // that is consensus's ScriptMismatch, which needs state; see the
        // arm's comment.)
        let mut both = padded.clone();
        if let PosTransaction::TransferV2 { inputs, .. } = &mut both {
            inputs[1].key_index = 1;
        }
        assert!(
            admissible(&both, V2_FLAG_DAY).is_ok(),
            "the identical table with every entry referenced must be admitted"
        );
    }

    /// The V1 structural floor, carried over: a V2 that spends nothing or
    /// pays no one is refused post-activation too, before any signature is
    /// bought. Control is the untouched fixture.
    ///
    /// Mutation log (2026-08-22): `inputs.is_empty()` deleted — the
    /// no-inputs half dies; `outputs.is_empty()` deleted — the no-outputs
    /// half dies.
    #[test]
    fn v2_empty_inputs_or_outputs_are_refused() {
        let good = signed_transfer_v2(2);
        assert!(admissible(&good, V2_FLAG_DAY).is_ok(), "control");

        let mut no_in = good.clone();
        if let PosTransaction::TransferV2 { inputs, .. } = &mut no_in {
            inputs.clear();
        }
        let err = admissible(&no_in, V2_FLAG_DAY)
            .expect_err("a V2 with no inputs must not be admitted");
        assert!(err.contains("no inputs"), "got: {err}");

        let mut no_out = good.clone();
        if let PosTransaction::TransferV2 { outputs, .. } = &mut no_out {
            outputs.clear();
        }
        let err = admissible(&no_out, V2_FLAG_DAY)
            .expect_err("a V2 with no outputs must not be admitted");
        assert!(err.contains("no outputs"), "got: {err}");
    }
}

/// (c) and (d) of the flag-day task, end to end on a REAL `Engine`: the
/// single-owner many-input sweep enters by BOTH real entry paths — the RPC
/// (`serve_rpc`'s SendRawTransaction arm, after the exact
/// `from_canonical_bytes(canonical_bytes())` round-trip rpc.rs performs) and
/// gossip (`on_transaction`, the body of the `NetEvent::Transaction` arm;
/// both paths converge on that one function) — survives the mempool, and
/// comes out of `select_transactions`, which IS the content of a proposal
/// (`propose` packs exactly its return). Application at epoch ≥ 800 is
/// proven by the transition suite (transition.rs, "TransferV2: deduplicated
/// witnesses behind their own flag day"), which this harness deliberately
/// does not duplicate: standing up a proposing validator here would re-test
/// consensus to prove an admission property.
///
/// No mocked clock anywhere: the wall epoch is real `now_ms()` against a
/// manifest whose `genesis_time_ms` is placed in the past — the same knob
/// production uses — so `wall_slot()`/`epoch_of` run the very code the live
/// node runs.
#[cfg(test)]
mod transfer_v2_end_to_end {
    use super::*;
    use bloch_pos_committee::params::TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH as V2_FLAG_DAY;
    use bloch_pos_committee::state_root::{EutxoEntry, EvmCommitment};
    use bloch_pos_committee::transition::{TransferInputV2, TransferOutput, WitnessKey};
    use bloch_pos_committee::SLOTS_PER_EPOCH;
    use sha3::{Digest, Sha3_256};

    /// A real `Engine`: real `Store` on disk, real devnet transport bound to
    /// an ephemeral port with zero peers (broadcast walks an empty peer
    /// list, so gossiping an admitted transaction is a no-op instead of a
    /// hang), observer mode (no keystore), and a genesis state that actually
    /// HOLDS `entries` — the outputs the sweep spends. `epochs_past` places
    /// `genesis_time_ms` so the node's real wall epoch is at least that
    /// (+2 slots of margin so the epoch cannot regress mid-test).
    fn engine_at_wall_epoch(epochs_past: u64, entries: &[EutxoEntry]) -> Engine {
        let slot_ms = 500u64;
        let back_ms = epochs_past
            .saturating_mul(SLOTS_PER_EPOCH)
            .saturating_add(2)
            .saturating_mul(slot_ms);
        let manifest = Manifest {
            genesis_time_ms: now_ms().saturating_sub(back_ms),
            slot_ms,
            validators: Vec::new(),
            cohort: Vec::new(),
            carryover: None,
            allocations: Vec::new(),
            carryover_entries: Vec::new(),
        };
        let genesis_id = manifest.genesis_id();
        // `CommittedState::genesis` directly rather than
        // `manifest.genesis_state()`: the opening balances are the test's
        // fixture, not a carryover snapshot with a commitment to honour.
        let state = CommittedState::genesis(
            genesis_id,
            GENESIS_MIX,
            &[],
            &[],
            [0u8; 32],
            [0u8; 32],
            [0u8; 32],
            EvmCommitment {
                account_root: [0u8; 32],
                receipts_root: [0u8; 32],
                gas_used: 0,
                base_fee_per_gas: 0,
            },
            entries,
        );
        // Unique throwaway data dir per engine — two engines in one test
        // must never share a store.
        static DIR_SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "bloch-pos-v2-e2e-{}-{}",
            std::process::id(),
            DIR_SEQ.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir_all(&dir).expect("create the test data dir");
        let store = Store::open(&dir, &[0u8; 32]).expect("open the test store");
        let (events, _rx) = mpsc::channel::<EngineEvent>();
        // `_rx` drops here: nothing dials this node, and the accept loop
        // exits quietly on a closed channel.
        let head_slot = Arc::new(AtomicU64::new(0));
        let queue = Arc::new(EngineQueue::new());
        let net = net::Net::Devnet(
            net::start(
                "127.0.0.1",
                0, // ephemeral port: bind for real, listen to nobody
                Vec::new(),
                events,
                dir.clone(),
                head_slot.clone(),
                queue.clone(),
            )
            .expect("bind the devnet transport on an ephemeral port"),
        );
        let verifier = HybridVerifier::new(Vec::new());
        Engine {
            manifest,
            state,
            tr: Transition::new(verifier.clone()),
            tr_probe: Transition::new(ProbeVerifier),
            verifier,
            keys: None,
            blocks: BTreeMap::new(),
            chain: vec![(0, genesis_id)],
            canonical: BTreeSet::from([*genesis_id.as_bytes()]),
            pool: BTreeMap::new(),
            att_pool: AttestationPool::new(),
            wall_slot: 0,
            mempool: BTreeMap::new(),
            store,
            net,
            head_slot,
            live: true,
            needs_sync: false,
            last_applied_ms: now_ms(),
            booted_ms: now_ms(),
            ws_anchor: None,
            ws_anchor_hard: false,
            ws_conflict_reported: false,
            queue,
        }
    }

    /// The motivating shape, funded: `n` outputs of 8,400 BLCH (the
    /// carryover denomination) under ONE key, and the V2 sweep spending all
    /// of them through a ONE-entry witness table with one real hybrid
    /// signature — the whole economy of the format. Returns the entries so
    /// the engine's genesis can hold the very outputs being swept.
    fn sweep_fixture(n: u32) -> (Vec<EutxoEntry>, PosTransaction) {
        let (pk, sk) = bloch_crypto::crypto::generate_keypair_from_seed(&[42u8; 32])
            .expect("hybrid keypair from a fixed seed");
        let script_hash: [u8; 32] = Sha3_256::digest(&pk).into();
        let entries: Vec<EutxoEntry> = (0..n)
            .map(|vout| EutxoEntry {
                txid: [0x33u8; 32],
                vout,
                value: 8_400 * 100_000_000, // 8,400 BLCH at 8 decimals
                script_hash,
            })
            .collect();
        let inputs: Vec<TransferInputV2> = entries
            .iter()
            .map(|e| TransferInputV2 {
                txid: e.txid,
                vout: e.vout,
                key_index: 0,
            })
            .collect();
        let mut tx = PosTransaction::TransferV2 {
            keys: vec![WitnessKey {
                pubkey: pk,
                signature: Vec::new(),
            }],
            inputs,
            outputs: vec![TransferOutput {
                value: 1_000,
                script_hash,
            }],
            // Admission is stateless and deliberately does not police the
            // declared size — that is consensus's UnderdeclaredSize
            // (transition.rs:2037), exercised by the transition suite.
            tx_bytes: 0,
            tip_millisat_per_gas: 0,
        };
        let root = tx.spend_signing_root();
        let sig = bloch_crypto::crypto::sign(&sk, &root).expect("sign the spend root");
        if let PosTransaction::TransferV2 { keys, .. } = &mut tx {
            keys[0].signature = sig;
        }
        (entries, tx)
    }

    /// (c): after the flag day the sweep enters by RPC AND by gossip,
    /// survives the mempool, and is what selection hands the proposer.
    ///
    /// Mutation log (2026-08-22): arm reverted to unconditional Err — dies
    /// on every assertion below; call site handed `epoch_of(head)` instead
    /// of the wall epoch — dies too, but only because this harness's head
    /// sits at genesis; a cheap lagging-NODE test does not exist and that
    /// limit is recorded at the arm's comment, not papered over here.
    #[test]
    fn v2_sweep_enters_by_rpc_and_gossip_and_comes_out_in_selection() {
        let (entries, tx) = sweep_fixture(16);

        // ── RPC path ────────────────────────────────────────────────────────
        let mut rpc_node = engine_at_wall_epoch(V2_FLAG_DAY + 1, &entries);
        let wall_epoch = epoch_of(rpc_node.wall_slot());
        assert!(
            wall_epoch >= V2_FLAG_DAY,
            "harness: wall epoch must be past the flag day, got {wall_epoch}"
        );
        // The exact decode rpc.rs performs on `sendrawtransaction` bytes.
        let bytes = tx.canonical_bytes();
        let decoded = PosTransaction::from_canonical_bytes(&bytes)
            .expect("the V2 canonical encoding must round-trip (the rpc.rs decode)");
        assert_eq!(decoded, tx, "round-trip must reproduce the transaction");
        let out = rpc_node.serve_rpc(RpcRequest::SendRawTransaction(decoded));
        assert!(out.is_ok(), "sendrawtransaction must admit the sweep: {out:?}");
        assert_eq!(rpc_node.mempool.len(), 1, "the sweep must sit in the mempool");

        // ── Gossip path, on a FRESH engine ──────────────────────────────────
        let mut gossip_node = engine_at_wall_epoch(V2_FLAG_DAY + 1, &entries);
        assert_eq!(
            gossip_node.on_transaction(tx.clone()),
            Ok(Admitted::New),
            "the gossip path must admit the sweep"
        );
        // Surviving the mempool: a second delivery collapses to Duplicate
        // instead of being refused or double-inserted.
        assert_eq!(
            gossip_node.on_transaction(tx.clone()),
            Ok(Admitted::Duplicate),
            "a re-gossiped sweep must be a duplicate, not a refusal"
        );
        assert_eq!(gossip_node.mempool.len(), 1);

        // ── ...and out into a proposal ──────────────────────────────────────
        // `select_transactions(epoch)` is the proposal's content — `propose`
        // packs exactly its return — and the epoch passed is the epoch of
        // the slot being produced for, which for a live proposer is a wall
        // slot: the same era admission just judged by.
        let selected = gossip_node.select_transactions(epoch_of(gossip_node.wall_slot()));
        assert_eq!(
            selected,
            vec![tx.clone()],
            "the admitted sweep must be selected into the next proposal"
        );
        let selected_rpc = rpc_node.select_transactions(epoch_of(rpc_node.wall_slot()));
        assert_eq!(selected_rpc, vec![tx]);
    }

    /// (d): before the flag day NOTHING changes — this is the photograph of
    /// today's behaviour, taken with the same harness, the same transaction
    /// bytes, and a manifest whose genesis is now (wall epoch 0). Both entry
    /// paths refuse with today's message, the mempool stays empty, selection
    /// stays empty.
    ///
    /// Mutation log (2026-08-22): flag-day gate deleted from the arm — this
    /// test dies on every assertion; it is the half that keeps the
    /// activation an activation instead of an unconditional opening.
    #[test]
    fn v2_sweep_is_refused_everywhere_before_the_flag_day() {
        let (entries, tx) = sweep_fixture(16);
        let mut node = engine_at_wall_epoch(0, &entries);
        assert_eq!(
            epoch_of(node.wall_slot()),
            0,
            "harness: a fresh genesis must put the wall clock in epoch 0"
        );

        // Gossip path: refused with today's string.
        let err = node
            .on_transaction(tx.clone())
            .expect_err("pre-activation, the gossip path must refuse V2");
        assert!(
            err.reason().contains("deduplicated transfers (tag 0x06) are not active"),
            "the refusal must be today's, byte for byte its opening clause: {}",
            err.reason()
        );

        // RPC path: refused too, as an error the client sees.
        let out = node.serve_rpc(RpcRequest::SendRawTransaction(tx.clone()));
        assert!(
            out.is_err(),
            "pre-activation, sendrawtransaction must refuse V2: {out:?}"
        );

        // And nothing propagates: no mempool entry, nothing to select — the
        // sweep does not exist to this era's node, exactly as today.
        assert!(node.mempool.is_empty(), "the mempool must stay empty");
        assert!(
            node.select_transactions(0).is_empty(),
            "selection must stay empty"
        );

        // THE POINT OF THE ERROR CODE: a refused transaction must not be
        // reported as a full mempool. The founder's sweep submits hundreds of
        // thousands of transfers through this method; "retry later" against
        // bytes that can never be admitted sends the operator after capacity
        // while the real fault goes unread.
        let RpcResult::Err(e) = node.serve_rpc(RpcRequest::SendRawTransaction(tx.clone())) else {
            panic!("a refused transaction must produce an RPC error");
        };
        assert_eq!(e.code, rpc::TX_REFUSED, "refused is not full: {e:?}");
        assert!(
            !e.message.contains("retry later"),
            "a refused transaction must not be told to retry later: {}",
            e.message
        );

        // THE CONTROL: a genuinely full mempool still reports MEMPOOL_FULL,
        // and there "retry later" is the correct advice. Without this half,
        // the assertion above could be satisfied by never reporting a full
        // mempool at all.
        let mut full = node;
        for i in 0..MEMPOOL_MAX {
            full.mempool.insert(vec![0xEE, (i >> 8) as u8, i as u8], tx.clone());
        }
        let RpcResult::Err(e2) = full.serve_rpc(RpcRequest::SendRawTransaction(tx.clone()))
        else {
            panic!("a full mempool must produce an RPC error");
        };
        assert_eq!(e2.code, rpc::MEMPOOL_FULL, "full is not refused: {e2:?}");
        assert!(
            e2.message.contains("retry later"),
            "a full mempool SHOULD advise retrying: {}",
            e2.message
        );
    }
}

#[cfg(test)]
mod libp2p_admission_tests {
    //! The production transport's admission, which nothing covered until the
    //! mutation run: deleting the quota check from the forwarder left the whole
    //! suite green, and that is precisely the state libp2p shipped in.

    use super::*;
    use crate::net::{Class, EngineQueue, NetEvent};
    use bloch_pos_committee::attestation::{Attestation, AttestationData};
    use bloch_pos_committee::header::{BlockEnvelope, BlockHeaderV4, Body};

    fn envelope(slot: u64) -> BlockEnvelope {
        BlockEnvelope {
            header: BlockHeaderV4 {
                version: 4,
                parent: [0u8; 32],
                state_root: [0u8; 32],
                body_root: [0u8; 32],
                slot,
                proposer_index: 17,
                randao_reveal: [0u8; 32],
                randao_mix: [0u8; 32],
                justified_root: [0u8; 32],
                finalized_root: [0u8; 32],
                attestation_root: [0u8; 32],
                coherence_root: [0u8; 32],
            },
            proposer_sig: vec![7u8; 64],
            body: Body { attestations: Vec::new(), transactions: Vec::new() },
        }
    }

    fn attestation(slot: u64) -> NetEvent {
        NetEvent::Attestation(
            Attestation {
                data: AttestationData {
                    slot,
                    head: [0u8; 32],
                    source_epoch: 0,
                    source_root: [0u8; 32],
                    target_epoch: 0,
                    target_root: [0u8; 32],
                },
                validator: 3,
                signature: vec![9u8; 4_800],
            },
            crate::net::Origin::none(),
        )
    }

    /// Drain the forwarder to completion over a fixed input.
    fn forward(queue: &Arc<EngineQueue>, evs: Vec<NetEvent>) -> Vec<EngineEvent> {
        let (net_tx, net_rx) = mpsc::channel::<NetEvent>();
        let (tx, rx) = mpsc::channel::<EngineEvent>();
        for e in evs {
            net_tx.send(e).expect("the forwarder has not started yet");
        }
        drop(net_tx); // closing the input is what ends the loop
        forward_admitted(net_rx, tx, queue.clone());
        let mut out = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            out.push(ev);
        }
        out
    }

    /// The motivating case again, on the production transport this time: with
    /// the attestation quota saturated, a block still gets through.
    #[test]
    fn a_block_still_arrives_on_libp2p_while_attestations_are_saturated() {
        let queue = Arc::new(EngineQueue::new());
        let (att_items, _) = (2048usize, ());
        let _flood: Vec<_> = (0..att_items)
            .filter_map(|_| EngineQueue::admit(&queue, Class::Attestation, 4_929))
            .collect();
        assert_eq!(_flood.len(), att_items, "the attestation class must really be full");

        let out = forward(&queue, vec![attestation(1), NetEvent::Block(envelope(25_750))]);
        assert_eq!(out.len(), 1, "the attestation is shed, the block is not");
        match &out[0] {
            EngineEvent::Net(NetEvent::Block(env), _) => {
                assert_eq!(env.header.slot, 25_750)
            }
            _ => panic!("the survivor must be the block"),
        }
        assert_eq!(queue.stats().attestation.shed, 1, "and the shed attestation is counted");
    }

    /// The CONTROL: the forwarder is a ceiling, not a funnel. Saturate BLOCKS
    /// and the block it forwards must be shed and counted — otherwise the
    /// libp2p path is the unbounded channel it used to be.
    #[test]
    fn the_libp2p_forwarder_sheds_and_counts_when_the_block_quota_is_full() {
        let queue = Arc::new(EngineQueue::new());
        let _full: Vec<_> = (0..1024usize)
            .filter_map(|_| EngineQueue::admit(&queue, Class::Block, 700))
            .collect();
        assert_eq!(_full.len(), 1024, "the block class must really be full");

        let out = forward(&queue, vec![NetEvent::Block(envelope(9))]);
        assert!(out.is_empty(), "a block over the block quota must not reach the engine");
        assert_eq!(queue.stats().block.shed, 1, "and it must leave a trace");
    }

    /// The forwarder must charge each event to its own class and to its real
    /// size — it is the only place the libp2p path is measured, so an event
    /// mis-sized here is a ceiling that is wrong by exactly that much.
    #[test]
    fn the_forwarder_charges_each_event_to_its_own_class_and_size() {
        let queue = Arc::new(EngineQueue::new());
        let block = NetEvent::Block(envelope(4));
        let att = attestation(4);
        let (bb, ab) = (block.wire_bytes(), att.wire_bytes());

        let held = forward(&queue, vec![block, att]);
        assert_eq!(held.len(), 2);
        let s = queue.stats();
        assert_eq!(s.block.items, 1, "one block on the block meter");
        assert_eq!(s.block.bytes, bb, "charged its real wire size");
        assert_eq!(s.attestation.items, 1, "one attestation on the attestation meter");
        assert_eq!(s.attestation.bytes, ab);

        drop(held);
        let s = queue.stats();
        assert_eq!(s.block.items + s.attestation.items, 0, "and the permits give it all back");
        assert_eq!(s.block.bytes + s.attestation.bytes, 0);
    }
}
