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
use crate::net::{self, NetEvent, Origin, Verdict};
use crate::rpc::{self, Admitted, Finality, Json, RpcCall, RpcError, RpcRequest, RpcResult};
use crate::store::Store;

/// Everything that reaches the consensus thread from outside it.
///
/// One channel, three sources now: the two transports both feed `Net`, and the
/// RPC feeds `Rpc`. Answering a query from *inside* the thread that owns the
/// state — rather than from a copy kept alongside it — is why this wrapper
/// exists; see [`crate::rpc::EngineBackend`].
pub enum EngineEvent {
    Net(NetEvent),
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
        let mut txs = self.select_transactions();
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
    fn on_transaction(&mut self, tx: PosTransaction) -> Result<Admitted, &'static str> {
        let key = tx.canonical_bytes();
        if self.mempool.contains_key(&key) {
            return Ok(Admitted::Duplicate);
        }
        if self.mempool.len() >= MEMPOOL_MAX {
            return Err("mempool is at capacity");
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
        admissible(&tx)?;
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
    fn select_transactions(&self) -> Vec<PosTransaction> {
        let mut out = Vec::new();
        let mut bytes = 0u64;
        for (encoded, tx) in self.mempool.iter() {
            if out.len() >= MAX_TXS_PER_BLOCK {
                break;
            }
            let n = encoded.len() as u64;
            if bytes + n > bloch_pos_committee::fee_market::MAX_BLOCK_TX_BYTES {
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
                    // Snapshot on the epoch boundary. Not every block: the
                    // encoding walks the whole eUTXO set (~452k entries at
                    // genesis), so doing it per block would put that cost on
                    // the hot path 120 times an epoch to save the same work
                    // once. Once per 32 slots bounds a restart's replay to at
                    // most one epoch — 16 minutes of chain instead of seven
                    // hours — which is the whole point.
                    //
                    // A failed write is a warning, never fatal: the node is
                    // fully functional without a snapshot, and the block log
                    // above is the thing that must not fail.
                    if epoch_of(env.header.slot) != epoch_of(env.header.slot.saturating_sub(1)) {
                        if let Err(e) = self.store.save_snapshot(&self.state.encode_snapshot()) {
                            eprintln!("snapshot: could not write at slot {}: {e}", env.header.slot);
                        }
                    }
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

            RpcRequest::SendRawTransaction(tx) => match self.on_transaction(tx.clone()) {
                Ok(outcome) => Ok(rpc::submitted_json(&tx, outcome)),
                Err(why) => Err(RpcError::new(
                    rpc::MEMPOOL_FULL,
                    format!(
                        "{why} ({MEMPOOL_MAX} entries); retry later — the \
                             transaction was not judged invalid"
                    ),
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
    let (tx, rx) = mpsc::channel::<EngineEvent>();
    // The transports speak NetEvent and know nothing about the RPC; the engine
    // consumes one channel. Rather than teach both transports the engine's
    // event type — coupling the network layer to a queue it has no business
    // knowing about — a forwarder wraps their events on the way in. One thread
    // and one hop, and each side keeps the shape it was designed with.
    let (net_tx, net_rx) = mpsc::channel::<NetEvent>();
    {
        let tx = tx.clone();
        std::thread::spawn(move || {
            for ev in net_rx {
                if tx.send(EngineEvent::Net(ev)).is_err() {
                    return; // engine gone; nothing left to deliver to
                }
            }
        });
    }
    let net = match cfg.transport {
        Transport::Devnet => net::Net::Devnet(net::start(
            &cfg.listen_addr,
            cfg.listen,
            cfg.peers.clone(),
            tx.clone(),
            cfg.data_dir.clone(),
            head_slot.clone(),
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
        manifest,
    };

    // ── Snapshot: skip the part of the replay we can prove we already know. ──
    //
    // A snapshot is a **cache, never an authority**. It is loaded, its state
    // root is recomputed from the decoded state, and that root is compared
    // against the root the block header at that slot already commits to. A
    // corrupt file, a truncated write, a tampered copy or a snapshot from
    // another chain all fail that comparison and the node replays from genesis
    // exactly as it does today. No consensus rule changes and nothing new goes
    // on the wire, so there is no flag day.
    //
    // Why it is worth the code: replay was measured at 29 slots/min, and the
    // rate decays as the eUTXO set grows. At height 12,050 that is about seven
    // hours before a restarted node is useful, which on 2026-08-19 turned a
    // half-hour security fix into a two-day roll-out.
    let mut replay_from = 0usize;
    if let Some(bytes) = engine.store.load_snapshot()? {
        match adopt_snapshot(&bytes, &logged) {
            Some((state, upto)) => {
                engine.state = state;
                replay_from = upto;
                println!(
                    "snapshot: adopted state at slot {} (root {} matches the header), \
                     replaying {} block(s) instead of {}",
                    engine.state.slot(),
                    crate::codec::hex8(&engine.state.state_root()),
                    logged.len() - upto,
                    logged.len(),
                );
            }
            None => {
                // Loud, and then harmless: the node does the slow thing.
                eprintln!(
                    "snapshot: refused (does not match the chain in this data dir) — \
                     discarding it and replaying from genesis"
                );
                let _ = engine.store.discard_snapshot();
            }
        }
    }

    // ── Replay: restart returns to the same state, by re-running the same
    // transition over the same inputs. ──
    let n_logged = logged.len() - replay_from;
    for env in logged.into_iter().skip(replay_from) {
        engine.ingest(env);
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
                    match ev {
                        EngineEvent::Net(NetEvent::Block(env)) => engine.ingest(env),
                        EngineEvent::Net(NetEvent::Attestation(att, origin)) => {
                            engine.on_attestation(att, origin, wall_epoch)
                        }
                        EngineEvent::Net(NetEvent::Transaction(tx)) => {
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
/// engine — the checks are a pure function of the transaction and nothing
/// else, and a rule that needs a running node to exercise is a rule that stops
/// being exercised.
///
/// Deliberately STRUCTURAL, not a validity check. A complete answer means
/// running the transition, which needs a candidate header this path has no
/// reason to build. What it catches is the class that has actually been
/// exploited or is currently exploitable.
pub(crate) fn admissible(tx: &PosTransaction) -> Result<(), &'static str> {
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
        let err = admissible(&deposit).expect_err("a deposit must not be admitted");
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
            admissible(&delegate).is_err(),
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
            admissible(&empty).is_err(),
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
            admissible(&tx).is_ok(),
            "a validly signed transfer must still reach the mempool"
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
        let err = admissible(&tx).expect_err("a bad signature must not be admitted");
        assert!(
            err.contains("signature"),
            "the refusal must name the reason, got: {err}"
        );
    }

    #[test]
    fn an_unauthenticated_exit_is_refused() {
        let err = admissible(&PosTransaction::Exit { validator: 0 })
            .expect_err("Exit carries no signature and must not be admitted");
        assert!(err.contains("not authenticated"), "got: {err}");
    }
}

/// Decide whether a snapshot may be adopted, and if so return the state and
/// how many logged blocks it lets the caller skip.
///
/// # The check, and why it is the whole story
///
/// Three things must line up before a byte of this state is used:
///
/// 1. The snapshot names a slot that appears in **this** node's block log. If
///    it does not, the file describes a chain we do not have.
/// 2. The header at that slot derives the block id the snapshot claims. The
///    id is derived the only legal way — `BlockId::of` — and passed into the
///    decoder, which compares rather than reconstructs; a snapshot from a
///    sibling branch at the same slot dies here, before the eUTXO set is even
///    allocated.
/// 3. The state root recomputed from the decoded state equals the root that
///    same header commits to. **This is the proof.** The header was signed by
///    a proposer and attested by a committee, so the root in it is a claim the
///    network already made; a snapshot that reproduces it is the state the
///    network agreed on, whatever the file's provenance. A snapshot that does
///    not is discarded, and no amount of it having been written by this node
///    five minutes ago changes that.
///
/// Returning `None` is never fatal — it costs a replay, which is what the node
/// did before this existed.
fn adopt_snapshot(
    bytes: &[u8],
    logged: &[BlockEnvelope],
) -> Option<(CommittedState, usize)> {
    use bloch_pos_committee::header::BlockId;

    // Peek at the slot without trusting anything else in the file: magic, then
    // the u64 that `encode_snapshot` writes first.
    if bytes.len() < 16 || &bytes[..8] != bloch_pos_committee::snapshot::SNAP_MAGIC {
        return None;
    }
    let snap_slot = u64::from_le_bytes(bytes[8..16].try_into().ok()?);

    // Genesis needs no snapshot, and adopting one for slot 0 would skip
    // nothing while adding a way to get genesis wrong.
    if snap_slot == 0 {
        return None;
    }

    // (1) Find that slot in our own log. `position` rather than a search by
    // height: the log is the chain this node actually holds.
    let idx = logged.iter().position(|e| e.header.slot == snap_slot)?;
    let header = &logged[idx].header;

    // (2) Derive the id the one legal way and let the decoder compare.
    let head = BlockId::of(header);
    let state = CommittedState::decode_snapshot(bytes, head).ok()?;

    // A decoded state that disagrees with the header about *which slot this
    // is* would be a decoder bug rather than a bad file, but the check costs
    // nothing and the alternative is a silent off-by-one in the skip count.
    if state.slot() != snap_slot {
        return None;
    }

    // (3) The proof: the root the network committed to at this height.
    if state.state_root() != header.state_root {
        return None;
    }

    // There is deliberately no separate "is this our network" test here: the
    // root just matched a header out of *this* log, and `Store::open` already
    // refused the data dir if it belonged to another genesis. A third check
    // would only restate those two.

    // Everything up to and including `idx` is now accounted for by the state.
    Some((state, idx + 1))
}

#[cfg(test)]
mod snapshot_adoption {
    //! What [`adopt_snapshot`] must refuse.
    //!
    //! **Scope, stated rather than left to be discovered:** these cover the
    //! refusals. The accepting path is not exercised here, because a
    //! `CommittedState` at a slot above zero cannot be built from this crate —
    //! the struct's fields are private to the committee crate and its only
    //! public constructor is `genesis`, which is slot 0, which this function
    //! refuses by design. The encode/decode round trip is pinned in
    //! `bloch_pos_committee::transition::snapshot_round_trip`, and adoption
    //! itself is proven by a node booting and printing the `snapshot: adopted`
    //! line. That is a weaker guarantee than a test and is worth closing when
    //! the committee crate grows a test-only state constructor.

    use super::*;
    use bloch_pos_committee::header::{BlockHeaderV4, VERSION_G4};

    fn hdr(slot: u64, state_root: [u8; 32]) -> BlockHeaderV4 {
        BlockHeaderV4 {
            version: VERSION_G4,
            parent: [0u8; 32],
            state_root,
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

    fn env(slot: u64, state_root: [u8; 32]) -> BlockEnvelope {
        BlockEnvelope {
            header: hdr(slot, state_root),
            proposer_sig: Vec::new(),
            body: Body { transactions: Vec::new(), attestations: Vec::new() },
        }
    }

    /// A snapshot whose slot is not in this node's log describes a chain we do
    /// not have. It must not be adopted, however well-formed it is.
    #[test]
    fn a_slot_this_node_never_logged_is_refused() {
        let mut bytes = bloch_pos_committee::snapshot::SNAP_MAGIC.to_vec();
        bytes.extend_from_slice(&7_000u64.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 64]);
        let log = vec![env(1, [1u8; 32]), env(2, [2u8; 32])];
        assert!(adopt_snapshot(&bytes, &log).is_none());
    }

    /// Genesis needs no snapshot. Adopting one would skip nothing and add a
    /// way to get genesis wrong.
    #[test]
    fn a_genesis_snapshot_is_refused() {
        let mut bytes = bloch_pos_committee::snapshot::SNAP_MAGIC.to_vec();
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 64]);
        let log = vec![env(0, [0u8; 32]), env(1, [1u8; 32])];
        assert!(adopt_snapshot(&bytes, &log).is_none());
    }

    /// Anything that is not a snapshot, and anything too short to carry a
    /// slot, is refused before a decode is attempted.
    #[test]
    fn a_file_that_is_not_a_snapshot_is_refused() {
        let log = vec![env(1, [1u8; 32])];
        assert!(adopt_snapshot(b"", &log).is_none());
        assert!(adopt_snapshot(b"BPOSSNP1", &log).is_none()); // magic, no slot
        assert!(adopt_snapshot(b"NOTASNAP________", &log).is_none());
    }

    /// The load-bearing one: a file that parses but whose state does not
    /// reproduce the root the header commits to. Here the payload after the
    /// slot is garbage, so the decode fails; the point of the test is that no
    /// state escapes without the header having agreed to it.
    #[test]
    fn a_snapshot_that_does_not_match_the_header_is_refused() {
        let mut bytes = bloch_pos_committee::snapshot::SNAP_MAGIC.to_vec();
        bytes.extend_from_slice(&2u64.to_le_bytes());
        bytes.extend_from_slice(&[0xAB; 256]);
        let log = vec![env(1, [1u8; 32]), env(2, [2u8; 32])];
        assert!(adopt_snapshot(&bytes, &log).is_none());
    }

    /// An empty log cannot support any snapshot — there is no header to check
    /// one against.
    #[test]
    fn an_empty_log_adopts_nothing() {
        let mut bytes = bloch_pos_committee::snapshot::SNAP_MAGIC.to_vec();
        bytes.extend_from_slice(&1u64.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 64]);
        assert!(adopt_snapshot(&bytes, &[]).is_none());
    }
}
