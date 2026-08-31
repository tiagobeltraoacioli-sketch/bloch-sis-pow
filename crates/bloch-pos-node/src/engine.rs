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

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
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

/// How many recently-applied canonical post-states are retained so a reorg
/// can start from the fork point instead of from genesis.
///
/// **This is a memory budget, and on this fleet memory is the binding
/// constraint** — the boxes are already one-validator-per-host because they
/// run out of RAM. A `CommittedState` is dominated by its eUTXO set (the
/// Genesis-3 carryover is ~452k outputs) and two states share nothing
/// structurally: MEASURED at 128 MB resident each, `--release`, on a
/// Genesis-3-sized set. That is why this is two and not thirty-two.
///
/// Two costs ONE extra copy, not two. The newest entry is the live state
/// itself — `apply_canonical` files the very `Arc` it just installed, so that
/// slot is shared and free — and the one behind it is the single real copy.
/// A depth-1 reorg needs the head's PARENT, so one retained ancestor is the
/// smallest window that buys anything at all, and this is it.
///
/// Two is chosen against the reorgs that happen — depth 1, occasionally 2 —
/// and NOT as a guess at the worst case. Everything deeper falls back to the
/// replay from genesis this node has always done, which is what makes a small
/// window safe rather than merely cheap: the window is an optimisation with a
/// correct slow path underneath it, never a limit on what can be reorganised.
const REORG_STATE_WINDOW: usize = 2;

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

/// The canonical committed state, plus the memo of epoch-rolled copies of it.
///
/// # Why this is a type and not two fields on `Engine`
///
/// The memo is a cache in front of a consensus derivation, which is the class
/// of thing that split this network before: `expected_bits` was node-local
/// state that two honest binaries could disagree about. A rolled state judges
/// attestations against a committee; hand back one rolled from a state that
/// has since moved and the node accepts votes from the wrong committee while
/// its peers reject them. So the invalidation must not be something a future
/// caller can forget.
///
/// It cannot be forgotten here, because `state` is private to this module and
/// [`StateCell::set`] is the ONLY way to write it — and `set` both bumps the
/// generation and empties the memo. There is no assignment path that skips
/// either. Reads go through `Deref`, so every existing `self.state.foo()`
/// still reads the live state and nothing else.
///
/// # The memo key, and why it is complete
///
/// The key is `(generation, epoch)`, and that is exactly the set of inputs:
///
/// 1. `rolled_to(epoch)` is a pure function of `(state, epoch)`. Its whole
///    body is "clone the state, then apply `process_epoch` until the open
///    epoch reaches `epoch`". `Transition::process_epoch` is
///    `Ok(pre.close_epoch())` — it does not touch the injected verifier, reads
///    no clock, opens no file, and `CommittedState` is a plain value with no
///    interior mutability (its own type doc says so). Same state, same epoch,
///    same bytes out, always.
/// 2. `generation` identifies the state value. It starts at zero and is
///    incremented by every writer of `state` — `set` and `set_arc`, and the
///    module has no third — so two different states never share a generation
///    within a process. What the argument needs is not "one writer" but "no
///    writer that skips the bump", which is a property of the two that exist
///    and must be re-checked if a third is ever added.
/// 3. Nothing else is read. Not the chain, not the block store, not the pool,
///    not the wall clock — the function's signature is the proof, since it
///    takes only the epoch and the rolling closure.
///
/// So `(generation, epoch)` determines the result, which is what "sound key"
/// means. The writers clearing the memo is belt AND braces: even the entry
/// that could not be returned is not left lying around.
///
/// This is deliberately NOT the fork-choice store's posture (rebuilt every
/// call, module docs above). The difference is that a fork-choice store
/// accumulates across messages and can therefore *drift*; a rolled state is a
/// deterministic function of one value this type owns and can watch change.
mod state_cell {
    use std::cell::RefCell;
    use std::ops::Deref;
    use std::sync::Arc;

    use bloch_pos_committee::epoch_of;
    use bloch_pos_committee::interfaces::StateReader;
    use bloch_pos_committee::transition::CommittedState;

    /// Rolled epochs retained. `on_attestation` refuses anything outside
    /// `{wall_epoch, wall_epoch + 1}`, and the head is normally in one of
    /// them, so the live working set is one or two entries; four is slack for
    /// a node whose head lags its wall clock. The memo is dropped whole on
    /// every applied block anyway, so this bounds a burst, not a lifetime.
    ///
    /// **It is also a memory budget, and it is the larger of the two this
    /// module spends.** Each entry is a whole `CommittedState`, structurally
    /// sharing nothing with the live one, so a full memo is `MEMO_CAP` extra
    /// copies — the same unit [`REORG_STATE_WINDOW`] is counted in, four
    /// times over. It is transient where the retention window is steady
    /// state, but the peak is what an OOM kills on.
    ///
    /// MEASURED on this tree by `bench::bench_state_footprint` (`--release`,
    /// Genesis-3-sized eUTXO set, RSS delta over four clones): **60 MB per
    /// state**, so a full memo is ~240 MB and the two features together peak
    /// around 300 MB per validator above the pre-change baseline.
    ///
    /// That 60 MB does NOT match the 128 MB in [`REORG_STATE_WINDOW`]'s doc.
    /// Both are real measurements of the same quantity on different hosts
    /// (this one is macOS/arm64); RSS for a heap this shape is an allocator
    /// artifact as much as a data size. Neither number has been taken on an
    /// Edgevana box, and on a fleet running EIGHT validators per host the
    /// per-host multiple is what matters, so **measure there before trusting
    /// either figure for capacity planning.** Recorded rather than
    /// reconciled, because reconciling them here would mean picking one
    /// without evidence.
    const MEMO_CAP: usize = 4;

    struct Entry {
        generation: u64,
        epoch: u64,
        rolled: Arc<CommittedState>,
    }

    pub(super) struct StateCell {
        state: Arc<CommittedState>,
        /// Bumped by every writer of `state`. There are exactly two — `set`
        /// and `set_arc` — and they do identical bookkeeping: replace the
        /// state, bump this, empty the memo. Two entry points because the
        /// reorg path already holds its post-state behind an `Arc` (the
        /// snapshot ring keeps one) and should not pay a copy to install it.
        /// The memo key's soundness rests on there being NO writer that does
        /// less than these two, not on there being only one.
        generation: u64,
        memo: RefCell<Vec<Entry>>,
    }

    impl StateCell {
        pub(super) fn new(state: CommittedState) -> Self {
            StateCell {
                state: Arc::new(state),
                generation: 0,
                memo: RefCell::new(Vec::new()),
            }
        }

        /// Replace the canonical state. The only writer, and the reason the
        /// memo key is sound: it moves the generation and drops the memo in
        /// the same breath, so no caller can advance the state and leave a
        /// rolled copy of the old one reachable.
        pub(super) fn set(&mut self, state: CommittedState) {
            self.state = Arc::new(state);
            self.generation = self.generation.wrapping_add(1);
            self.memo.get_mut().clear();
        }

        /// Same, for a state that is already shared — the reorg path builds
        /// its post-states behind `Arc` so the snapshot ring can keep one
        /// without a copy. Identical bookkeeping: generation moves, memo
        /// empties. There is no writer that does less.
        pub(super) fn set_arc(&mut self, state: Arc<CommittedState>) {
            self.state = state;
            self.generation = self.generation.wrapping_add(1);
            self.memo.get_mut().clear();
        }

        /// The live state as a shared handle, for the one caller that must
        /// keep it alive alongside the cell (the reorg snapshot ring).
        /// Ordinary reads go through `Deref` and stay borrows.
        pub(super) fn arc(&self) -> Arc<CommittedState> {
            Arc::clone(&self.state)
        }

        /// Which state this is. Test surface — the memo key's identity half,
        /// exposed so a test can pin that it moves when the state does.
        #[cfg(test)]
        pub(super) fn generation(&self) -> u64 {
            self.generation
        }

        /// Plant an entry in the memo by hand. TEST ONLY, and only so a test
        /// can prove the generation half of the key is load-bearing: an entry
        /// planted under a stale generation must never be returned, and the
        /// same entry planted under the live one must be, or the test that
        /// asserts the first is passing vacuously.
        #[cfg(test)]
        pub(super) fn plant(&self, generation: u64, epoch: u64, rolled: CommittedState) {
            self.memo.borrow_mut().push(Entry {
                generation,
                epoch,
                rolled: Arc::new(rolled),
            });
        }

        /// The canonical state with epoch accounting rolled forward to
        /// `epoch`, memoized on `(generation, epoch)`.
        ///
        /// `roll` is `process_epoch`, passed in rather than reached for, so
        /// this module cannot read anything but the state it owns — the
        /// signature IS the argument that the key is complete.
        ///
        /// Returns `Arc` rather than a clone because the callers only read
        /// (duty roster, seed, finality view). On a Genesis-3-sized state the
        /// clone alone was tens of milliseconds, per attestation.
        pub(super) fn rolled_to<F>(&self, epoch: u64, roll: F) -> Arc<CommittedState>
        where
            F: Fn(&CommittedState) -> CommittedState,
        {
            // The canonical state's open epoch is its head's epoch — only
            // `apply_block` advances it, and it rolls exactly there. Asking
            // for that epoch or an earlier one is the identity, which is what
            // the uncached loop did too (its `while cur < epoch` never ran).
            let base_epoch = epoch_of(self.state.slot());
            if epoch <= base_epoch {
                return Arc::clone(&self.state);
            }

            let mut memo = self.memo.borrow_mut();
            if let Some(hit) = memo
                .iter()
                .find(|e| e.generation == self.generation && e.epoch == epoch)
            {
                return Arc::clone(&hit.rolled);
            }

            // Roll from the furthest already-rolled epoch below the target
            // instead of from the state — sound because that is precisely
            // what the loop would have produced on the way there:
            // `rolled(n + 1) == process_epoch(rolled(n))` by construction.
            let mut cur_epoch = base_epoch;
            let mut cur = Arc::clone(&self.state);
            if let Some(best) = memo
                .iter()
                .filter(|e| {
                    e.generation == self.generation && e.epoch > cur_epoch && e.epoch < epoch
                })
                .max_by_key(|e| e.epoch)
            {
                cur_epoch = best.epoch;
                cur = Arc::clone(&best.rolled);
            }
            while cur_epoch < epoch {
                cur = Arc::new(roll(&cur));
                cur_epoch += 1;
                memo.push(Entry {
                    generation: self.generation,
                    epoch: cur_epoch,
                    rolled: Arc::clone(&cur),
                });
            }
            // Evict the lowest epochs first: they are the cheapest to rebuild
            // (fewest rolls from the base) and the least likely to be asked
            // for again, since the traffic walks forward.
            while memo.len() > MEMO_CAP {
                memo.remove(0);
            }
            cur
        }
    }

    impl Deref for StateCell {
        type Target = CommittedState;

        fn deref(&self) -> &CommittedState {
            &self.state
        }
    }
}

use state_cell::StateCell;

/// The end-to-end replay benchmark (`src/engine/replay_bench.rs`).
///
/// A CHILD module of `engine`, and that is the whole reason it can exist:
/// `Engine` and its fields are private to this module, so a benchmark in
/// `tests/` could not drive `ingest`/`advance`/`apply_canonical` at all and
/// would have had to reimplement them — measuring the reimplementation. A
/// child module sees its ancestors' private items, so nothing here has to be
/// widened for it. `cfg(test)`: not in the binary, asserts no consensus
/// property, changes no behaviour.
#[cfg(test)]
mod replay_bench;

struct Engine {
    manifest: Manifest,
    state: StateCell,
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
    /// Post-states of the most recently applied canonical blocks, oldest
    /// first, keyed by block id — [`REORG_STATE_WINDOW`] of them.
    ///
    /// Keyed by block id and NOT by height, which is what makes it survive a
    /// reorg without an invalidation rule: a block's post-state is a pure
    /// function of the block and its ancestry, and the id commits to that
    /// ancestry transitively, so an entry can never be "the right height on
    /// the wrong branch". A block that leaves the canonical chain and later
    /// returns has the same post-state both times.
    recent_states: VecDeque<([u8; 32], Arc<CommittedState>)>,
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
    /// Loose attestations dropped from `pool` because the block that carried
    /// them became canonical — a removal fork choice cannot see, since it also
    /// reads every stored block's body.
    ///
    /// Monotone, and it exists only so [`Engine::forkchoice_inputs`] can tell
    /// that kind of pool shrinkage apart from the epoch `retain`, which fork
    /// choice very much can see. See the argument there.
    fc_covered_removals: u64,
}

/// A fingerprint of the four values `lmd_ghost_head` reads, so `advance` can
/// tell whether recomputing it could possibly return anything new.
///
/// Not a cache across calls — it is rebuilt from scratch inside each
/// `advance`, because the completeness argument on
/// [`Engine::forkchoice_inputs`] only holds for the duration of one.
#[derive(PartialEq, Eq)]
struct ForkChoiceInputs {
    blocks: usize,
    pool: u64,
    justified: [u8; 32],
    validators: Vec<bloch_pos_committee::sample::Validator>,
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

    /// The committed state root at the head, READ rather than recomputed.
    ///
    /// `getchaininfo` used to call `state.state_root()` here, on the
    /// consensus thread, for every caller — a rebuild of every non-eUTXO
    /// component of the committed state tree, most of it the validator
    /// registry's ~3,749-byte hybrid pubkeys. MEASURED by
    /// `bench_chain_info_json` at Genesis-4's size (452,726 eUTXO leaves, 64
    /// validators): **32.6 ms cold, 3.0 ms warm**, against 0.040 / 0.015 ms
    /// once the root is handed in. Roughly 815x cold, 200x warm.
    ///
    /// **Those are not the 733 ms the incident was reported at, and the gap is
    /// not explained here.** On 2026-08-21 n21 (45.76.89.225) left rotation
    /// with `-32004 consensus thread did not answer within 10s`, answering
    /// after 10.7 s at a box load average of 1.01 — one thread eaten while the
    /// wallet, the explorer and 48 migrated validators polled it. But this
    /// tree already carries `229d95a6`/`22751083`, which keep the eUTXO
    /// subtree inside `CommittedState` and make this call incremental; the
    /// from-scratch rebuild those commits removed measures 80.9 s on the same
    /// box (`perf_state_root_breakdown`). 733 ms is between the two and
    /// matches neither. Whoever owns n21 should check which binary it runs
    /// before crediting this change with that incident: if n21 predates
    /// `229d95a6`, the fix for 733 ms is that commit, not this one.
    ///
    /// It had already hashed it because `apply_block` returns `Ok(post)` on
    /// exactly one condition: `post.compute_root() == header.state_root`
    /// (transition.rs step 12). Every block on this chain passed that, so for
    /// any head this node adopted the header field IS `state.state_root()`,
    /// bit for bit. `apply_canonical`'s log line and `do_reorg`'s take the
    /// same shortcut for the same reason; this is the third.
    ///
    /// That argument covers the header of a block. What it does not cover by
    /// inspection is that `self.state` is always the HEAD's post-state — a
    /// reorg replaces both, a boot has neither — so `head_root_tests` walks
    /// the real block path (ordinary blocks, two epoch boundaries, reorgs on
    /// both sides of the snapshot window, and an empty-branch give-back) and
    /// asserts the equality at every step rather than arguing it.
    ///
    /// # Genesis
    ///
    /// `ingest` returns early on slot 0 — "genesis is synthesized, never
    /// received" — so genesis is canonical, is the head at boot, and is NOT in
    /// `blocks`. The lookup misses, and the answer is the computed root: it is
    /// the ONLY value that keeps this change transport-only, since it is
    /// exactly what the RPC returned there before. `unwrap_or_default()` would
    /// have published 32 zero bytes as an answer, which is the failure this
    /// whole change exists to avoid. The cost is the old cost, paid on a chain
    /// of length one — genesis state, before any block, is small — and it is
    /// paid until the first block arrives and never again.
    fn head_state_root(&self) -> [u8; 32] {
        match self.blocks.get(self.head_id().as_bytes()) {
            Some(env) => env.header.state_root,
            None => self.state.state_root(),
        }
    }

    /// The canonical state with epoch accounting rolled forward to `epoch` —
    /// the exact rolling `apply_block` performs internally, so the duty view
    /// here can never disagree with validation.
    ///
    /// Memoized on `(state generation, epoch)` by [`StateCell`], whose docs
    /// carry the argument that the key is complete. It has to be: this is
    /// called once per ARRIVING ATTESTATION (`judge`), it used to clone a
    /// Genesis-3-sized state and re-run `process_epoch` every time, and most
    /// of those attestations name the same epoch as the one before.
    ///
    /// Shared rather than cloned. Every caller reads — roster, seed, finality
    /// view — and none mutates, which the `Arc` now enforces.
    fn rolled_to(&self, epoch: u64) -> Arc<CommittedState> {
        // Instrumentation only; compiled out without `perf-timing`. This spans
        // the whole call, memo HIT included, so the phase total reads as the
        // effective cost of the duty view — which is the number the memo was
        // built to move. On a hit the span is the lookup and nothing else.
        let _perf = bloch_pos_committee::perf::span(bloch_pos_committee::perf::Phase::RolledTo);
        self.state.rolled_to(epoch, |st| {
            self.tr
                .process_epoch(st)
                .expect("process_epoch is infallible")
        })
    }

    /// The uncached derivation, kept verbatim as the reference the memo is
    /// tested against. Not on any live path — if it ever grows a caller,
    /// something has gone wrong with the one above.
    #[cfg(test)]
    fn rolled_to_uncached(&self, epoch: u64) -> CommittedState {
        let mut st = (*self.state).clone();
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

    /// The sortition/partition seed for `epoch` — **the transition's own
    /// function**, not a copy of its expression.
    ///
    /// It used to be a re-derivation here:
    /// `if epoch == 0 { GENESIS_MIX } else { rolled.randao_mix_at(epoch - 1)
    /// .unwrap_or(GENESIS_MIX) }`. That is byte-for-byte what
    /// [`CommittedState::seed_for_epoch`] evaluates — `randao_mix_at` is
    /// `boundary_mixes.get`, and `Manifest::genesis_state` passes the very
    /// `GENESIS_MIX` constant in as the state's `genesis_mix` — so this is a
    /// refactor and not a change. It is worth making because the two are the
    /// duty view and the consensus authority for the SAME quantity: a node
    /// that proposes off one and is validated against the other produces
    /// blocks its own transition rejects. The look-ahead lives in that one
    /// function now, so a second copy here would have been a consensus rule
    /// the node silently did not take.
    ///
    /// # The anchor, and when this is the right function to call
    ///
    /// `rolled` is this node's own head rolled forward. That is CORRECT for
    /// the node's own duties — `propose` and `attest` build on the node's
    /// head, so the head IS the parent the transition will evaluate against,
    /// and producer and validator cannot disagree. It is WRONG for judging
    /// somebody else's attestation, which belongs to whatever branch its
    /// author was on. Use [`Self::seed_for_attestation`] there.
    fn seed_for(rolled: &CommittedState, epoch: u64) -> [u8; 32] {
        rolled.seed_for_epoch(epoch)
    }

    /// The committed mix at the close of epoch `epoch - 1`, read off the
    /// ANCESTRY of `from` rather than off this node's head.
    ///
    /// Walks selected-parent from `from` to the last block strictly before
    /// `first_slot_of_epoch(epoch)` and returns that block's
    /// `header.randao_mix`. That field is consensus-checked (the transition
    /// refuses a block whose mix is not `mix_in(parent_mix, reveal)`), and
    /// `close_epoch` records `boundary_mixes[c] = randao_mix` at the instant
    /// `c` closes — so the last block below `first_slot_of(c + 1)` carries
    /// exactly the boundary mix of `c`. No state is cloned and `process_epoch`
    /// is not run.
    ///
    /// `None` means "this node cannot see that far back on that branch" —
    /// the block is missing. That is an UNJUDGEABLE input, never an invalid
    /// one, and the caller must treat it as such.
    fn ancestral_boundary_mix(&self, from: &[u8; 32], epoch: u64) -> Option<[u8; 32]> {
        let first = first_slot_of_epoch(epoch)?;
        let genesis = *self.chain[0].1.as_bytes();
        let mut cur = *from;
        // Bounded by the stored block count: every step moves strictly to a
        // parent, and `blocks` is finite, so a cycle cannot spin forever.
        for _ in 0..=self.blocks.len() {
            if cur == genesis {
                return Some(GENESIS_MIX);
            }
            let env = self.blocks.get(&cur)?;
            if env.header.slot < first {
                return Some(env.header.randao_mix);
            }
            cur = env.header.parent;
        }
        None
    }

    /// The sortition seed for an attestation, anchored to the ATTESTATION's
    /// own branch instead of this node's head.
    ///
    /// `target_root` is, by this node's own checkpoint convention, the last
    /// block strictly before the first slot of `epoch` on the attester's
    /// branch. So the seed is the boundary mix of `epoch - 1 - L` read from
    /// that block's ancestry, which is precisely what
    /// [`CommittedState::seed_for_epoch`] would compute when the attestation's
    /// slot is validated inside a block on that branch.
    ///
    /// This is the fix for the 2026-08-24 `NotInCommittee` flood. The old code
    /// judged every arriving attestation against a committee derived from how
    /// much of the chain THIS node had downloaded, so an honest vote from a
    /// validator that really was in the committee was answered with a peer
    /// penalty. Two nodes on the same branch now derive the same committee for
    /// the same attestation no matter how far apart their heads are.
    ///
    /// `None` = unjudgeable from what this node holds. The caller must Ignore,
    /// never Reject: `gossip.rs` justifies its `NotInCommittee` Reject with
    /// "both ends compute membership from the same finalized state", and a
    /// node that cannot reach the branch is not in a position to make that
    /// claim about anybody.
    fn seed_for_attestation(&self, target_root: &[u8; 32], epoch: u64) -> Option<[u8; 32]> {
        match epoch.checked_sub(committees::MIN_SEED_LOOKAHEAD_EPOCHS) {
            None => Some(GENESIS_MIX),
            Some(src) => self.ancestral_boundary_mix(target_root, src),
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
    /// Everything [`lmd_ghost_head`] reads, in a form cheap enough to compare
    /// on every turn of `advance`'s loop.
    ///
    /// The two state inputs are compared by value. The two collection inputs
    /// are compared by COUNT, and that is a complete comparison only because
    /// of an invariant that holds inside `advance` and nowhere else: **within
    /// one `advance` call, `blocks` and `pool` can only shrink.** Nothing on
    /// that path inserts — `ingest` inserts the block before calling in,
    /// `on_attestation` runs on a different event — so `apply_canonical`,
    /// `do_reorg` and the invalid-block removal only ever take entries out. A
    /// set that only loses elements is unchanged exactly when its size is.
    ///
    /// `fc_covered_removals` is added back to the pool count for the one kind
    /// of shrinkage fork choice cannot observe: an attestation dropped because
    /// the block carrying it became canonical is still counted, from that
    /// block's body. Adding the running total keeps the sum invariant across
    /// those and lets it fall — forcing a recompute — for the epoch `retain`,
    /// which drops attestations no stored block carries.
    ///
    /// If a future edit inserts into either collection inside `advance`, this
    /// stops being sound. That is why the invariant is written down here
    /// rather than assumed. The neutrality half of the claim is pinned by
    /// `an_attestation_its_block_carries_is_free_to_leave_the_pool`, which
    /// also carries the control showing the epoch `retain` is NOT neutral.
    fn forkchoice_inputs(&self) -> ForkChoiceInputs {
        ForkChoiceInputs {
            blocks: self.blocks.len(),
            pool: self.pool.len() as u64 + self.fc_covered_removals,
            justified: self.state.finality().justified.root,
            validators: self.state.active_validators(),
        }
    }

    fn forkchoice_head(&self) -> [u8; 32] {
        // Instrumentation only; compiled out without `perf-timing`.
        let _perf = bloch_pos_committee::perf::span(bloch_pos_committee::perf::Phase::ForkChoice);
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
        // Fork choice is recomputed at the top of every iteration, and the
        // last iteration exists only to confirm the head stopped moving. That
        // confirmation is NOT free and it is NOT redundant: `apply_canonical`
        // advances `self.state`, which moves the justified root and can move
        // the active validator set, and it prunes `self.pool`. All three are
        // fork-choice inputs, so the value really can change and the loop
        // really is the convergence.
        //
        // What is skippable is the case where none of them moved, and
        // `forkchoice_inputs` is what decides that. Reusing the previous
        // answer there is not an approximation — `lmd_ghost_head` is a pure
        // function of exactly those inputs (that is why §5.5 made it a free
        // function), so equal inputs mean an equal head, bit for bit.
        let mut memo: Option<(ForkChoiceInputs, [u8; 32])> = None;
        // Bounded: every iteration either advances the canonical head or
        // deletes an invalid block, and both are finite.
        for _ in 0..=(self.blocks.len().saturating_mul(2) + 2) {
            let inputs = self.forkchoice_inputs();
            let target = match &memo {
                Some((seen, head)) if *seen == inputs => *head,
                _ => self.forkchoice_head(),
            };
            memo = Some((inputs, target));
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
                self.state.set(post);
                // Snapshot for the reorg path. Free: this is the state that
                // was just built, kept by handle, not copied.
                let snapshot = self.state.arc();
                self.remember_state(*id.as_bytes(), snapshot);
                self.canonical.insert(*id.as_bytes());
                self.chain.push((env.header.slot, id));
                self.head_slot.store(env.header.slot, Ordering::Relaxed);
                self.last_applied_ms = now_ms();
                // Counted, because `advance` needs to tell this shrinkage
                // apart from the `retain` four lines down. These attestations
                // leave the loose pool and stay visible to fork choice, which
                // observes every stored block's body as well as the pool, and
                // `env` is one of the stored blocks. The `retain` below drops
                // attestations nothing else carries — that one fork choice
                // does see.
                for a in &env.body.attestations {
                    if self
                        .pool
                        .remove(&(a.validator, a.data.signing_root()))
                        .is_some()
                    {
                        self.fc_covered_removals += 1;
                    }
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
                    // The head root is FREE here, and it used to cost a whole
                    // state-root computation.
                    //
                    // `apply_block` returns `Ok(post)` on exactly one
                    // condition: `post.compute_root() == header.state_root`
                    // (transition.rs step 12). `self.state` IS that `post`.
                    // So the header field printed here is bit-for-bit the
                    // value `self.state.state_root()` recomputed — the same
                    // number, from the check that already ran, instead of a
                    // second full walk of the state tree for a log line.
                    //
                    // A proposer paid this three times a slot: once stamping
                    // its own header, once inside `apply_block`'s check, and
                    // once here. This is the third one, deleted. The other
                    // two are the producer=validator seam and must both stay.
                    println!(
                        "[slot {}] applied {} by v{} — head root {}, justified e{}, finalized e{}",
                        env.header.slot,
                        crate::codec::hex8(id.as_bytes()),
                        env.header.proposer_index,
                        crate::codec::hex8(&env.header.state_root),
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

    /// Keep a canonical block's post-state for the reorg path. Oldest out
    /// first; see [`REORG_STATE_WINDOW`] for why the window is small.
    fn remember_state(&mut self, id: [u8; 32], state: Arc<CommittedState>) {
        self.recent_states.push_back((id, state));
        while self.recent_states.len() > REORG_STATE_WINDOW {
            self.recent_states.pop_front();
        }
    }

    /// The committed post-state of a canonical block: from the snapshot ring
    /// if it is still retained, otherwise by replaying to it.
    ///
    /// The two are the same value, and that is not an assumption — a block's
    /// post-state is `apply_block` folded over its ancestry from genesis, the
    /// fold is deterministic (the pure crate's whole posture), and both
    /// branches here name the same block. The snapshot is that answer already
    /// computed once; the replay recomputes it. Retention is therefore a
    /// speed decision with no consensus content, which is exactly the
    /// property `reorg_state_tests` pins.
    fn state_at_canonical(&self, id: [u8; 32]) -> Arc<CommittedState> {
        if let Some((_, st)) = self.recent_states.iter().find(|(bid, _)| *bid == id) {
            return Arc::clone(st);
        }
        Arc::new(self.replay_to(id))
    }

    /// Rebuild a canonical block's post-state from genesis, re-executing the
    /// whole prefix through the same transition.
    ///
    /// This is what `do_reorg` used to do unconditionally, kept whole. It is
    /// now the fallback for a reorg deeper than [`REORG_STATE_WINDOW`], and
    /// it is also the reference the snapshot path is tested against — the
    /// slow path staying correct is what lets the fast path be small.
    fn replay_to(&self, id: [u8; 32]) -> CommittedState {
        let cut = self
            .chain
            .iter()
            .position(|(_, cid)| cid.as_bytes() == &id)
            .expect("replay target is canonical");
        let prefix: Vec<BlockEnvelope> = self.chain[1..=cut]
            .iter()
            .map(|(_, cid)| {
                self.blocks
                    .get(cid.as_bytes())
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
        st
    }

    /// Adopt `branch`, attached at canonical `ancestor`. True if adopted;
    /// false if a branch block failed validation (it is removed).
    ///
    /// **From the fork point, not from genesis.** This used to rebuild the
    /// genesis state and re-execute the entire canonical prefix on every
    /// reorg at any depth, so giving one block back and taking one cost a
    /// full replay of the chain. The branch is still validated block by block
    /// through the real `apply_block` — nothing about what gets adopted
    /// changes; only where the fold starts does.
    fn do_reorg(&mut self, ancestor: [u8; 32], branch: Vec<BlockEnvelope>) -> bool {
        // Instrumentation only; compiled out without `perf-timing`. Self time
        // only — the `apply_block` calls below are attributed to their own
        // phases, so this reads as "reorg overhead beyond re-execution". Note
        // that since the fold now starts at the fork point, the replay this
        // used to charge here is mostly gone rather than moved.
        let _perf = bloch_pos_committee::perf::span(bloch_pos_committee::perf::Phase::Reorg);
        let cut = self
            .chain
            .iter()
            .position(|(_, id)| id.as_bytes() == &ancestor)
            .expect("ancestor is canonical");

        let base = self.state_at_canonical(ancestor);
        // Post-states of the branch, so the ring is refilled for the branch
        // that just won without recomputing anything.
        let mut applied: Vec<([u8; 32], Arc<CommittedState>)> = Vec::with_capacity(branch.len());
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
            let pre: &CommittedState = applied.last().map_or(&*base, |(_, st)| st);
            match self
                .tr
                .apply_block(pre, &envelope, &env.body.attestations, &txs)
            {
                Ok(post) => applied.push((*env.block_id().as_bytes(), Arc::new(post))),
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
        let st = applied
            .last()
            .map_or_else(|| Arc::clone(&base), |(_, st)| Arc::clone(st));

        // Adopt.
        let old_head = self.head_slot_now();
        self.state.set_arc(st);
        // The ring described the branch that just lost. Rebuild it from the
        // one that won: `ancestor` is canonical again by construction, and
        // the branch's post-states were just computed above.
        self.recent_states.clear();
        self.remember_state(ancestor, base);
        for (id, post) in applied {
            self.remember_state(id, post);
        }
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
            // Free for the same reason as `apply_canonical`'s: every block
            // in `branch` passed `apply_block`, so the adopted head's header
            // carries the post-state root already checked against it. Only a
            // reorg to an EMPTY branch has no header to read it from, and
            // only when the ancestor is genesis is it not in `blocks`.
            let head_root = match branch.last() {
                Some(env) => env.header.state_root,
                None => self
                    .blocks
                    .get(&ancestor)
                    .map(|env| env.header.state_root)
                    .unwrap_or_else(|| self.state.state_root()),
            };
            println!(
                "REORG: adopted branch of {} blocks at ancestor {} (head slot {} -> {}), root {}",
                branch.len(),
                crate::codec::hex8(&ancestor),
                old_head,
                self.head_slot_now(),
                crate::codec::hex8(&head_root),
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
        // THE SEED COMES FROM THE ATTESTATION'S BRANCH, not from this node's
        // head. If we cannot reach that branch we cannot derive the committee,
        // and an attestation we cannot judge is Ignored — never Rejected, and
        // therefore never scored against the peer that relayed it. A syncing
        // node used to Reject its way through every attestation on the network
        // and graylist the very peers feeding it blocks.
        let Some(seed) = self.seed_for_attestation(&att.data.target_root, epoch) else {
            return GossipDecision::Ignore(bloch_pos_committee::gossip::IgnoreReason::Unjudgeable);
        };
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
                self.head_state_root(),
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
    // Network events queued but not yet handled. The transport reads it to
    // decide when to shed rather than queue — see `net::send_to_engine`. It is
    // decremented below, after each event is actually processed, so "in flight"
    // means exactly that and not "ever sent".
    let inflight = Arc::new(std::sync::atomic::AtomicUsize::new(0));
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
            inflight.clone(),
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
        state: StateCell::new(genesis_state),
        tr: Transition::new(verifier.clone()),
        tr_probe: Transition::new(ProbeVerifier),
        verifier,
        keys,
        blocks: BTreeMap::new(),
        chain: vec![(0, genesis_id)],
        canonical: BTreeSet::from([*genesis_id.as_bytes()]),
        recent_states: VecDeque::new(),
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
        fc_covered_removals: 0,
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
                    // Every `EngineEvent::Net` was counted into `inflight` by
                    // the transport; releasing it here — after handling, not on
                    // dequeue — is what makes the cap mean "work the engine has
                    // not done yet".
                    if matches!(ev, EngineEvent::Net(_)) {
                        inflight.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
                    }
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
    let (fc, parents, children) = forkchoice_store(blocks, pool, validators);
    let tree = BlockTree { parents: &parents };
    fc.head(&tree, justified, &children)
}

/// [`lmd_ghost_head`] through the pre-2026-08-23 O(V·D²) fork choice.
///
/// The differential oracle, and nothing else:
/// `head_matches_the_reference_implementation` feeds both this and
/// [`lmd_ghost_head`] the same randomised
/// DAGs and asserts the selected head is identical. Without it the rewrite of
/// `Store::head` would be a claim about a consensus-relevant value rather than
/// a tested property — and the 2026-08-08 fork is what that costs.
/// Test-only: the binary must not carry an O(V·D²) fork choice it can reach.
#[cfg(test)]
pub fn lmd_ghost_head_reference<'a>(
    blocks: &BTreeMap<[u8; 32], BlockEnvelope>,
    pool: impl Iterator<Item = &'a Attestation>,
    validators: &[bloch_pos_committee::sample::Validator],
    justified: [u8; 32],
) -> [u8; 32] {
    let (fc, parents, children) = forkchoice_store(blocks, pool, validators);
    let tree = BlockTree { parents: &parents };
    fc.head_reference(&tree, justified, &children)
}

/// The fork-choice inputs, assembled: the store of latest messages, the parent
/// map and the sibling lists. Shared by the two entry points above so they
/// cannot drift — a differential test whose two sides observe different
/// message sets proves nothing.
#[allow(clippy::type_complexity)]
fn forkchoice_store<'a>(
    blocks: &BTreeMap<[u8; 32], BlockEnvelope>,
    pool: impl Iterator<Item = &'a Attestation>,
    validators: &[bloch_pos_committee::sample::Validator],
) -> (
    FcStore,
    HashMap<[u8; 32], [u8; 32]>,
    HashMap<[u8; 32], Vec<[u8; 32]>>,
) {
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

    (fc, parents, children)
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
        //
        // That flag day now EXISTS: `DEPOSIT_FUNDING_ACTIVATION_EPOCH`
        // (params.rs) arms the funded `DepositV2` (tag 0x07, the arm below)
        // and retires this unfunded shape as consensus on the same switch.
        // This refusal stays even after it binds — post-flag-day the format
        // is consensus-invalid anyway, and pre-flag-day it is the stopgap.
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
        // DepositV2 (tag 0x07, the FUNDED deposit): admitted from its flag
        // day, refused before it — wall-clock epoch on this side of the
        // mempool door, committed epoch on the consensus side, for exactly
        // the reasons written on the TransferV2 arm above. Load-bearing
        // either way: without this arm the catch-all below would ADMIT the
        // format, and pre-flag-day that is mempool stuffing (every proposer
        // pays to probe-drop what consensus must refuse), while post-flag-day
        // an unverified PoP or witness would ride to the proposer for free.
        PosTransaction::DepositV2 { inputs, pubkey, proof_of_possession, .. } => {
            if wall_epoch < bloch_pos_committee::params::DEPOSIT_FUNDING_ACTIVATION_EPOCH {
                return Err(
                    "funded deposits (tag 0x07) are not active: the format ships behind \
                     a flag day (DEPOSIT_FUNDING_ACTIVATION_EPOCH) that this chain has \
                     not reached",
                );
            }
            // Cheap-first, mirroring the consensus arm (`apply_deposit_v2`):
            // structure, then the two signature families — this path is
            // unauthenticated, so an invalid shape must cost zero hybrid
            // verifications.
            if inputs.is_empty() {
                return Err("deposit spends no outputs — the bond it names would be minted, \
                            not funded, and consensus refuses it");
            }
            // The PoP: the validator key over the §7.1 root. One derivation,
            // shared with consensus (`deposit_pop_signing_root`); `None`
            // means the framed pubkey does not parse, which no block can
            // ever apply.
            let Some(pop_root) = tx.deposit_pop_signing_root() else {
                return Err("deposit validator key is not a suite-framed hybrid public key");
            };
            if !bloch_crypto::crypto::verify(pubkey, &pop_root, proof_of_possession) {
                return Err("deposit proof of possession does not verify under its own key");
            }
            // The funding witnesses, over the deposit's own domain-tagged
            // root — same placement and same reason as the Transfer arm.
            let signing_root = tx.spend_signing_root();
            for i in inputs {
                if !bloch_crypto::crypto::verify(&i.pubkey, &signing_root, &i.signature) {
                    return Err("deposit carries a funding signature that does not verify");
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

    // ── The 2026-08-23 rewrite, checked from the node's own entry point ─────

    /// splitmix64, so the randomised DAG below is reproducible and adds no
    /// dependency (the committee crate's property suite uses the same one).
    struct Rng(u64);

    impl Rng {
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }

        fn below(&mut self, n: u64) -> u64 {
            ((self.next_u64() as u128 * n as u128) >> 64) as u64
        }
    }

    /// **The differential test at the node's boundary.** `Store::head` was
    /// rewritten from O(V·D²) to a bottom-up accumulation; the committee
    /// crate's `forkchoice_head_matches_the_reference_implementation` pins the
    /// two against each other on synthetic parent maps, and this pins them on
    /// what the node actually feeds it — real `BlockEnvelope`s, attestations
    /// carried in block bodies as well as loose in the pool, and the parent
    /// map and sibling lists built by `forkchoice_store`.
    ///
    /// Fork choice selects the head. If these two ever disagree the change is
    /// a hard fork rather than a speed-up, which is the whole reason the old
    /// algorithm was kept as `lmd_ghost_head_reference` instead of deleted.
    #[test]
    fn head_matches_the_reference_implementation() {
        let mut rng = Rng(0x0806_2308_5EED_5EED);
        let g = [0x99u8; 32];
        for round in 0..120u64 {
            // A random forest over genesis: every block picks an earlier block
            // or genesis as its parent, so forks, long branches and single
            // blocks all occur.
            let n = 1 + rng.below(24) as usize;
            let mut blocks: BTreeMap<[u8; 32], BlockEnvelope> = BTreeMap::new();
            let mut ids: Vec<[u8; 32]> = Vec::new();
            for i in 0..n {
                let parent = if i == 0 || rng.below(4) == 0 {
                    g
                } else {
                    ids[rng.below(i as u64) as usize]
                };
                // Some blocks carry attestations in the body — the half of the
                // message set that never passes through the pool.
                let n_atts = rng.below(3) as usize;
                let atts: Vec<Attestation> = (0..n_atts)
                    .map(|_| {
                        let v = rng.below(8) as u32;
                        let slot = 1 + rng.below(4);
                        let head = if ids.is_empty() || rng.below(4) == 0 {
                            g
                        } else {
                            ids[rng.below(ids.len() as u64) as usize]
                        };
                        attest(v, slot, head)
                    })
                    .collect();
                let (one, one_id) = chain_of(vec![(parent, i as u64 + 1, i as u8, atts)]);
                blocks.extend(one);
                ids.push(one_id[0]);
            }

            // Loose attestations, including votes for blocks that do not
            // exist and same-slot pairs that make a validator an equivocator.
            let n_loose = rng.below(12) as usize;
            let pool: Vec<Attestation> = (0..n_loose)
                .map(|_| {
                    let v = rng.below(8) as u32;
                    let slot = 1 + rng.below(4);
                    let head = match rng.below(6) {
                        0 => [rng.next_u64() as u8; 32], // never seen
                        1 => g,
                        _ => ids[rng.below(ids.len() as u64) as usize],
                    };
                    attest(v, slot, head)
                })
                .collect();

            // Uniform stake on half the rounds so sibling weights tie and the
            // tie-break — not the arithmetic — decides the head.
            let validators: Vec<Validator> = if round % 2 == 0 {
                vals(8)
            } else {
                (0..8u32)
                    .map(|index| Validator {
                        index,
                        effective_stake: 1 + rng.below(1_000_000),
                    })
                    .collect()
            };

            for justified in [g, ids[rng.below(ids.len() as u64) as usize]] {
                assert_eq!(
                    lmd_ghost_head(&blocks, pool.iter(), &validators, justified),
                    lmd_ghost_head_reference(&blocks, pool.iter(), &validators, justified),
                    "round {round}: the rewritten fork choice selected a \
                     different head than the one it replaced"
                );
            }
        }
    }

    /// **Why `apply_canonical` may drop an attestation from the pool without
    /// forcing `advance` to recompute.** Fork choice observes every stored
    /// block's body *and* the loose pool. An attestation that leaves the pool
    /// because the block carrying it became canonical is therefore still
    /// observed, from that block — the head cannot move.
    ///
    /// That is the entire justification for `fc_covered_removals` in
    /// `Engine::forkchoice_inputs`. The second half of the test is the
    /// control: an attestation no stored block carries is NOT free to drop,
    /// which is why the epoch `retain` on the next line still invalidates the
    /// memo.
    #[test]
    fn an_attestation_its_block_carries_is_free_to_leave_the_pool() {
        let g = [0x99u8; 32];
        let validators = vals(4);

        // Two siblings. Validators 0 and 1 back `heavy`; validator 2 backs
        // `light`. The attestations for `heavy` ride inside `heavy`'s body.
        let (blocks_a, a_ids) = chain_of(vec![(g, 1, 1, Vec::new())]);
        let light = a_ids[0];
        let carried = vec![attest(0, 1, light), attest(1, 1, light)];
        let (blocks_b, b_ids) = chain_of(vec![(g, 1, 9, carried.clone())]);
        let mut blocks = blocks_a;
        blocks.extend(blocks_b);
        let carrier = b_ids[0];
        // The carried votes name `light`, so `light` wins while they count.
        let with_pool: Vec<Attestation> = carried.clone();
        let without_pool: Vec<Attestation> = Vec::new();
        assert_eq!(
            lmd_ghost_head(&blocks, with_pool.iter(), &validators, g),
            lmd_ghost_head(&blocks, without_pool.iter(), &validators, g),
            "dropping from the pool an attestation the stored block {} still \
             carries moved the head — `fc_covered_removals` would be unsound",
            crate::codec::hex8(&carrier)
        );

        // Control, on a block set with NOTHING in any body: two siblings and
        // one loose vote for the lexicographically smaller of them. With the
        // vote it wins on weight; without it the pair is a zero-zero tie and
        // the tie-break hands the head to the other one. So an attestation no
        // stored block carries is emphatically NOT free to drop — which is why
        // the epoch `retain` in `apply_canonical` still invalidates the memo.
        let (mut bare, x_ids) = chain_of(vec![(g, 1, 0x11, Vec::new())]);
        let (bare_b, y_ids) = chain_of(vec![(g, 1, 0x22, Vec::new())]);
        bare.extend(bare_b);
        let (smaller, larger) = if x_ids[0] < y_ids[0] {
            (x_ids[0], y_ids[0])
        } else {
            (y_ids[0], x_ids[0])
        };
        let loose = vec![attest(0, 1, smaller)];
        assert_eq!(
            lmd_ghost_head(&bare, loose.iter(), &validators, g),
            smaller,
            "the loose vote did not carry its block"
        );
        assert_eq!(
            lmd_ghost_head(&bare, [].iter(), &validators, g),
            larger,
            "the control is not controlling: dropping an uncarried \
             attestation must be able to move the head, or the epoch `retain` \
             would need no invalidation"
        );
    }

    /// Wall-clock cost of one `lmd_ghost_head`, old shape against new, at the
    /// depths the problem was measured at. `#[ignore]`d — it is a measurement,
    /// not an assertion, and the reference takes minutes at depth 4,096.
    ///
    ///   cargo test --release -p bloch-pos-node -- --ignored --nocapture \
    ///       perf_lmd_ghost_head_by_depth
    #[test]
    #[ignore]
    fn perf_lmd_ghost_head_by_depth() {
        use std::time::Instant;
        let g = [0x99u8; 32];
        let n_validators = 64u32;
        let validators = vals(n_validators);

        for depth in [256u64, 512, 1024, 4096] {
            // A spine with a childless sibling at every level, so the descent
            // runs the full depth and has a comparison to make each step.
            let mut blocks: BTreeMap<[u8; 32], BlockEnvelope> = BTreeMap::new();
            let mut spine: Vec<[u8; 32]> = Vec::new();
            let mut parent = g;
            for d in 0..depth {
                let (two, ids) = chain_of(vec![
                    (parent, d + 1, 0, Vec::new()),
                    (parent, d + 1, 1, Vec::new()),
                ]);
                blocks.extend(two);
                // The lexicographically larger sibling is the spine, so the
                // tie-break cannot short-circuit the descent.
                let (hi, _lo) = if ids[0] > ids[1] {
                    (ids[0], ids[1])
                } else {
                    (ids[1], ids[0])
                };
                spine.push(hi);
                parent = hi;
            }
            // Votes spread down the spine.
            let pool: Vec<Attestation> = (0..n_validators)
                .map(|v| {
                    let d = (v as u64 * depth / n_validators as u64) as usize;
                    attest(v, 1, spine[d.min(spine.len() - 1)])
                })
                .collect();

            let t = Instant::now();
            let new_head = lmd_ghost_head(&blocks, pool.iter(), &validators, g);
            let new_ms = t.elapsed().as_secs_f64() * 1000.0;

            let t = Instant::now();
            let old_head = lmd_ghost_head_reference(&blocks, pool.iter(), &validators, g);
            let old_ms = t.elapsed().as_secs_f64() * 1000.0;

            // Split the surviving cost, because there are two of them and only
            // one was rewritten: `forkchoice_store` rebuilds the parent map,
            // the sibling lists and the whole message set on every call (O(N)
            // in stored blocks, and it is what makes a REPLAY quadratic in
            // chain length), and `Store::head` then walks it. Reporting the
            // total alone would hide which one is left.
            let t = Instant::now();
            let (fc, parents, children) = forkchoice_store(&blocks, pool.iter(), &validators);
            let build_ms = t.elapsed().as_secs_f64() * 1000.0;
            let tree = BlockTree { parents: &parents };
            let t = Instant::now();
            let split_head = fc.head(&tree, g, &children);
            let descend_ms = t.elapsed().as_secs_f64() * 1000.0;

            assert_eq!(new_head, old_head, "depth {depth}: heads differ");
            assert_eq!(new_head, split_head, "depth {depth}: split path differs");
            println!(
                "depth {depth:5}  blocks {:6}  old {old_ms:10.2} ms   new {new_ms:8.3} ms   \
                 speedup {:6.0}x   [of new: store-rebuild {build_ms:7.3} ms, \
                 descent {descend_ms:7.3} ms]",
                blocks.len(),
                old_ms / new_ms.max(1e-9),
            );
        }
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
        let inflight = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let net = net::Net::Devnet(
            net::start(
                "127.0.0.1",
                0, // ephemeral port: bind for real, listen to nobody
                Vec::new(),
                events,
                dir.clone(),
                head_slot.clone(),
                inflight,
            )
            .expect("bind the devnet transport on an ephemeral port"),
        );
        let verifier = HybridVerifier::new(Vec::new());
        Engine {
            manifest,
            state: StateCell::new(state),
            tr: Transition::new(verifier.clone()),
            tr_probe: Transition::new(ProbeVerifier),
            verifier,
            keys: None,
            blocks: BTreeMap::new(),
            chain: vec![(0, genesis_id)],
            canonical: BTreeSet::from([*genesis_id.as_bytes()]),
            recent_states: VecDeque::new(),
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
            fc_covered_removals: 0,
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

/// A real, proposing `Engine`, for tests that must drive the actual block
/// path rather than a stand-in.
///
/// One genesis validator whose hybrid key this node holds, so this node is
/// the proposer AND the whole committee at every slot: `propose(slot)` always
/// fires and the block it builds is validated by the real
/// `Transition::apply_block` under the real ML-DSA-65 ‖ Falcon-1024 verifier.
/// That is what makes a claim measured here a claim about production code.
#[cfg(test)]
mod perf_support {
    use super::*;
    use crate::genesis::ManifestValidator;
    use bloch_pos_committee::beacon::RandaoChain;

    const SAT_PER_BLOCH: u128 = 100_000_000;

    /// Throwaway data dir, deleted when the returned guard drops.
    pub(super) struct TestDir(pub PathBuf);

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Build the engine. `slot_ms` and `genesis_time_ms` are irrelevant to
    /// every path exercised here — `propose`, `ingest` and `do_reorg` all take
    /// the slot as an argument and read no clock — so the manifest's cadence
    /// is set to something plausible and then not depended upon.
    pub(super) fn proposing_engine() -> (Engine, TestDir) {
        static DIR_SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "bloch-pos-perf-{}-{}",
            std::process::id(),
            DIR_SEQ.fetch_add(1, Ordering::Relaxed),
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create the test data dir");

        let ks = Keystore::generate(&dir, 0).expect("generate a devnet keystore");
        let manifest = Manifest {
            genesis_time_ms: now_ms(),
            slot_ms: 1_000,
            validators: vec![ManifestValidator {
                index: 0,
                stake_sat: 200_000 * SAT_PER_BLOCH,
                randao_commitment: RandaoChain::generate(ks.randao_seed).commitment(),
                pubkey: ks.pubkey.clone(),
                withdrawal_credentials: Vec::new(),
                commission_bps: 0,
            }],
            cohort: Vec::new(),
            carryover: None,
            allocations: Vec::new(),
            carryover_entries: Vec::new(),
        };
        let genesis_id = manifest.genesis_id();
        let state = manifest.genesis_state();
        let store = Store::open(&dir, &[0u8; 32]).expect("open the test store");
        let (events, _rx) = mpsc::channel::<EngineEvent>();
        let head_slot = Arc::new(AtomicU64::new(0));
        let inflight = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let net = net::Net::Devnet(
            net::start(
                "127.0.0.1",
                0, // ephemeral port: bind for real, listen to nobody
                Vec::new(),
                events,
                dir.clone(),
                head_slot.clone(),
                inflight,
            )
            .expect("bind the devnet transport on an ephemeral port"),
        );
        let verifier = HybridVerifier::new(manifest.pubkeys());
        let engine = Engine {
            manifest,
            state: StateCell::new(state),
            tr: Transition::new(verifier.clone()),
            tr_probe: Transition::new(ProbeVerifier),
            verifier,
            keys: Some(ks),
            blocks: BTreeMap::new(),
            chain: vec![(0, genesis_id)],
            canonical: BTreeSet::from([*genesis_id.as_bytes()]),
            recent_states: VecDeque::new(),
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
            // A fresh engine has dropped nothing from an empty pool, so the
            // running total is zero — the same value `boot`'s literal uses.
            // Not a placeholder: `forkchoice_inputs` reads this as
            // `pool.len() + this`, and starting it anywhere but 0 would
            // offset the very first comparison against a pool that really is
            // empty.
            fc_covered_removals: 0,
        };
        (engine, TestDir(dir))
    }
}

/// **Win 3's proof.** A proposer used to compute the whole committed state
/// root THREE times for one slot; it now computes it twice, and the two that
/// remain are the two that carry a rule.
///
/// The three were: stamping the header (`propose`, from the probe's
/// post-state), the transition's own step-12 check inside `apply_block`, and
/// a third for the `applied …` log line. The first two are the
/// producer=validator seam — the producer must commit a root and then face
/// the same check every peer will run — so neither may go. The third was a
/// display of a number the second had already proved equal to
/// `header.state_root`, which the log now prints directly.
///
/// The assertion is a COUNT, not a duration: it fails on the old code and
/// passes on the new one on any box, at any load. A timing test would only
/// have said "faster on this machine today".
#[cfg(test)]
mod root_budget_tests {
    use super::*;
    use bloch_pos_committee::transition::root_computations;

    #[test]
    fn a_proposer_spends_two_state_roots_per_slot_not_three() {
        let (mut engine, _dir) = perf_support::proposing_engine();

        let before = root_computations();
        engine.propose(1);
        let spent = root_computations() - before;

        assert_eq!(
            engine.chain.len(),
            2,
            "the harness must actually have produced and adopted a block — \
             a proposer that produced nothing would spend no roots and pass \
             this test for the wrong reason"
        );
        assert_eq!(
            spent, 2,
            "one proposed slot must cost exactly two state-root computations: \
             the header stamp and the transition's step-12 check. Three means \
             the log line's root came back; one means a check went missing."
        );

        // And the value the log prints is still the head's real root — the
        // whole basis for deleting the computation.
        let head = engine
            .blocks
            .get(engine.head_id().as_bytes())
            .expect("the adopted block is stored");
        let recomputed_before = root_computations();
        assert_eq!(
            head.header.state_root,
            engine.state.state_root(),
            "the header root the log now prints must equal the recomputed \
             state root, or the log is lying about the head"
        );
        assert_eq!(
            root_computations() - recomputed_before,
            1,
            "the check above must itself cost exactly one root, or the \
             counter is not counting what this test claims it counts"
        );
    }

    /// The same budget over several consecutive slots, so a one-off cannot
    /// pass: `n` proposed slots cost exactly `2n` roots.
    #[test]
    fn the_budget_holds_across_consecutive_slots() {
        let (mut engine, _dir) = perf_support::proposing_engine();
        let before = root_computations();
        for slot in 1..=5 {
            engine.propose(slot);
        }
        assert_eq!(
            engine.chain.len(),
            6,
            "five proposed slots must land five blocks on genesis"
        );
        assert_eq!(
            root_computations() - before,
            10,
            "five slots must cost ten state-root computations, not fifteen"
        );
    }
}

/// What the deleted work actually cost, on a state the size the fleet runs.
///
/// `#[ignore]`d: it is a measurement, not an assertion, and it builds a
/// Genesis-3-sized balance set (hundreds of thousands of outputs), which is
/// seconds of setup no ordinary test run should pay. Run it with
/// `cargo test --release -p bloch-pos-node -- --ignored --nocapture bench_`.
///
/// A devnet state roots in microseconds; mainnet's does not, and the number
/// that matters is mainnet's. The size below is the Genesis-3 carryover's own
/// output count, so the figure is the fleet's, not a toy's.
#[cfg(test)]
mod bench {
    use super::*;
    use bloch_pos_committee::state_root::{EutxoEntry, EvmCommitment};
    use std::time::Instant;

    /// The Genesis-3 carryover's output count, per `CARRYOVER-SNAPSHOT.md`.
    const MAINNET_EUTXOS: u32 = 452_133;

    fn mainnet_sized_state(n: u32) -> CommittedState {
        let entries: Vec<EutxoEntry> = (0..n)
            .map(|i| EutxoEntry {
                txid: {
                    let mut t = [0u8; 32];
                    t[..4].copy_from_slice(&i.to_le_bytes());
                    t
                },
                vout: i % 8,
                value: 8_400 * 100_000_000,
                script_hash: {
                    let mut h = [0u8; 32];
                    h[..4].copy_from_slice(&(i % 4096).to_le_bytes());
                    h
                },
            })
            .collect();
        CommittedState::genesis(
            BlockId::of(&BlockHeaderV4 {
                version: VERSION_G4,
                parent: [0u8; 32],
                state_root: [0u8; 32],
                body_root: [0u8; 32],
                slot: 0,
                proposer_index: 0,
                randao_reveal: [0u8; 32],
                randao_mix: [0u8; 32],
                justified_root: [0u8; 32],
                finalized_root: [0u8; 32],
                attestation_root: [0u8; 32],
                coherence_root: [0u8; 32],
            }),
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
            &entries,
        )
    }

    /// A carryover-sized state that also carries a REGISTRY.
    ///
    /// [`mainnet_sized_state`] leaves `validators` empty, which is fine for
    /// the benches that only move eUTXOs but wrong for anything measuring a
    /// whole state root: the registry is most of the non-eUTXO tree, and each
    /// record hashes a hybrid ML-DSA-65 ‖ Falcon-1024 pubkey (~3,749 B) into
    /// its leaf. Sized and shaped after `tests/replay_hotpath_perf.rs`'s
    /// fixture so the two are comparable.
    fn carryover_state_with_validators(n: u32, validators: u32) -> CommittedState {
        let entries: Vec<EutxoEntry> = (0..n)
            .map(|i| EutxoEntry {
                txid: {
                    let mut t = [0u8; 32];
                    t[..4].copy_from_slice(&i.to_le_bytes());
                    t
                },
                vout: i % 8,
                value: 8_400 * 100_000_000,
                script_hash: {
                    let mut h = [0u8; 32];
                    h[..4].copy_from_slice(&(i % 4096).to_le_bytes());
                    h
                },
            })
            .collect();
        let vs: Vec<bloch_pos_committee::transition::GenesisValidator> = (0..validators)
            .map(|i| bloch_pos_committee::transition::GenesisValidator {
                index: i,
                // The real hybrid pubkey length. It is hashed whole into the
                // leaf, so the length is part of what is being measured.
                pubkey: vec![(i % 251) as u8; 3_749],
                staked_sat: 32 * 100_000_000,
                randao_commitment: {
                    let mut c = [0u8; 32];
                    c[..4].copy_from_slice(&i.to_le_bytes());
                    c
                },
                withdrawal_credentials: vec![0xAB; 32],
                commission_bps: 500,
            })
            .collect();
        CommittedState::genesis(
            BlockId::of(&BlockHeaderV4 {
                version: VERSION_G4,
                parent: [0u8; 32],
                state_root: [0u8; 32],
                body_root: [0u8; 32],
                slot: 0,
                proposer_index: 0,
                randao_reveal: [0u8; 32],
                randao_mix: [0u8; 32],
                justified_root: [0u8; 32],
                finalized_root: [0u8; 32],
                attestation_root: [0u8; 32],
                coherence_root: [0u8; 32],
            }),
            GENESIS_MIX,
            &vs,
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
            &entries,
        )
    }

    fn median(mut v: Vec<u128>) -> u128 {
        v.sort_unstable();
        v[v.len() / 2]
    }

    /// **What `getchaininfo` costs to build, before and after.**
    ///
    /// `chain_info_json` computed the committed state root on the consensus
    /// thread for every caller. The 2026-08-21 n21 incident (`-32004 consensus
    /// thread did not answer within 10s`, answered after 10.7 s, box load
    /// average 1.01 — not CPU-bound, one thread eaten) is what prompted this,
    /// but see [`Engine::head_state_root`]: the 733 ms it was reported at does
    /// NOT reproduce on this tree, which already has the incremental eUTXO
    /// subtree. What this bench measures is what the call costs HERE.
    ///
    /// Sized at 452,726 eUTXO leaves — the Genesis-4 carryover's own count,
    /// the same constant `tests/replay_hotpath_perf.rs` calls `CARRYOVER_N`.
    /// The 452,133 above it is Genesis-3's and is left alone.
    ///
    /// BEFORE is not a paraphrase: it is `state.state_root()` followed by the
    /// same `chain_info_json` call, which is exactly what the old body did
    /// (the root computation was the first thing inside it). AFTER hands in
    /// the head header's root. Everything else about the two is identical, so
    /// the difference is the walk and nothing else.
    ///
    /// **Cold vs warm is the whole reason this is not a one-liner.**
    /// `state_root.rs` keeps a THREAD-LOCAL memo of singleton subtree roots,
    /// so the second call on a thread is artificially fast and reporting only
    /// that would understate what a freshly-spawned RPC worker pays. Each cold
    /// figure below is the FIRST call on a thread that has never rooted
    /// anything; the warm figures are medians over repeats on one thread.
    #[test]
    #[ignore]
    fn bench_chain_info_json() {
        /// The Genesis-4 carryover's output count.
        const CARRYOVER_N: u32 = 452_726;
        /// Roughly the live Genesis-4 set: 12 classic + 49 Fly, per
        /// `tests/replay_hotpath_perf.rs`, which uses the same 64.
        const N_VALIDATORS: u32 = 64;

        // NOT `mainnet_sized_state`, and the difference is the whole
        // measurement. That helper registers NO validators, and the validator
        // records are what the non-eUTXO half of the tree is made of — each
        // one serializes a ~3,749-byte hybrid pubkey into its leaf. With an
        // empty registry this bench reported a BEFORE of 0.1 ms, which is not
        // a fast node, it is an empty one. `perf_state_root_breakdown`'s
        // fixture has 202 non-eUTXO leaves and costs 5.8 ms for the same call.
        let st = carryover_state_with_validators(CARRYOVER_N, N_VALIDATORS);
        let head = st.head();

        // The header value the engine now reads. Computed once here, off the
        // measured path, exactly as `apply_block` computed it once on the way
        // in.
        let header_root = st.state_root();

        let before = |st: &CommittedState| -> u128 {
            let t = Instant::now();
            let root = st.state_root();
            let v = crate::rpc::chain_info_json(st, &head, root, 0, Some(0), 0, 1, 0, 1);
            let us = t.elapsed().as_micros();
            std::hint::black_box(v);
            us
        };
        let after = |st: &CommittedState| -> u128 {
            let t = Instant::now();
            let v = crate::rpc::chain_info_json(st, &head, header_root, 0, Some(0), 0, 1, 0, 1);
            let us = t.elapsed().as_micros();
            std::hint::black_box(v);
            us
        };

        // ── COLD: one call each, on a thread with an empty singleton memo ──
        let (cold_before, cold_after) = std::thread::scope(|sc| {
            let b = sc.spawn(|| before(&st));
            let b = b.join().expect("cold BEFORE thread");
            let a = sc.spawn(|| after(&st));
            let a = a.join().expect("cold AFTER thread");
            (b, a)
        });

        // ── WARM: medians on this thread, memo populated by the first call ──
        let _ = before(&st);
        let warm_before = median((0..7).map(|_| before(&st)).collect());
        let _ = after(&st);
        let warm_after = median((0..7).map(|_| after(&st)).collect());

        let ms = |us: u128| us as f64 / 1_000.0;
        println!(
            "getchaininfo response construction @ n = {CARRYOVER_N} eUTXOs \
             + {N_VALIDATORS} validators (Genesis-4 carryover)"
        );
        println!(
            "  BEFORE (root recomputed): cold {:>8.1} ms   warm {:>8.1} ms",
            ms(cold_before),
            ms(warm_before)
        );
        println!(
            "  AFTER  (root handed in) : cold {:>8.3} ms   warm {:>8.3} ms",
            ms(cold_after),
            ms(warm_after)
        );

        // Byte-identical, which is what makes this transport-only. Asserted
        // rather than printed: a bench that quietly changed the answer would
        // be measuring the wrong thing to begin with.
        let a = crate::rpc::chain_info_json(&st, &head, header_root, 0, Some(0), 0, 1, 0, 1);
        let b = {
            let root = st.state_root();
            crate::rpc::chain_info_json(&st, &head, root, 0, Some(0), 0, 1, 0, 1)
        };
        assert_eq!(
            a.to_string(),
            b.to_string(),
            "the handed-in root produced a different response body than the recomputed one"
        );
    }

    #[test]
    #[ignore]
    fn bench_state_root() {
        let st = mainnet_sized_state(MAINNET_EUTXOS);
        let mut samples = Vec::new();
        for _ in 0..7 {
            let t = Instant::now();
            let _ = st.state_root();
            samples.push(t.elapsed().as_micros());
        }
        println!(
            "state_root over {MAINNET_EUTXOS} eUTXOs: median {} us (min {}, max {})",
            median(samples.clone()),
            samples.iter().min().unwrap(),
            samples.iter().max().unwrap()
        );
    }

    /// The whole of Win 1, end to end: what one arriving attestation used to
    /// cost `judge` before it could even look at a committee, and what it
    /// costs now. `epoch` = head epoch is the identity roll (a bare clone
    /// before, an `Arc` bump now); `epoch` = head epoch + 1 is the one that
    /// also ran `process_epoch`.
    #[test]
    #[ignore]
    fn bench_rolled_to() {
        let st = mainnet_sized_state(MAINNET_EUTXOS);
        let tr = Transition::new(ProbeVerifier);
        let roll = |s: &CommittedState| tr.process_epoch(s).expect("infallible");

        // BEFORE: the pre-change body, verbatim.
        let uncached = |epoch: u64| {
            let mut cur_state = st.clone();
            let mut cur = epoch_of(cur_state.slot());
            while cur < epoch {
                cur_state = roll(&cur_state);
                cur += 1;
            }
            cur_state
        };
        for target in [0u64, 1] {
            let mut samples = Vec::new();
            for _ in 0..7 {
                let t = Instant::now();
                let out = uncached(target);
                samples.push(t.elapsed().as_micros());
                std::hint::black_box(&out);
            }
            println!(
                "BEFORE rolled_to(head_epoch + {target}): median {} us",
                median(samples)
            );
        }

        // AFTER: the memo. First call is the miss that pays; the rest are
        // what the other attestations in the same flight actually see.
        let cell = StateCell::new(st.clone());
        for target in [0u64, 1] {
            let t = Instant::now();
            let out = cell.rolled_to(target, roll);
            let miss = t.elapsed().as_micros();
            std::hint::black_box(&out);
            let mut samples = Vec::new();
            for _ in 0..64 {
                let t = Instant::now();
                let out = cell.rolled_to(target, roll);
                samples.push(t.elapsed().as_nanos());
                std::hint::black_box(&out);
            }
            println!(
                "AFTER  rolled_to(head_epoch + {target}): miss {miss} us, \
                 hit median {} ns",
                median(samples.iter().map(|n| *n as u128).collect::<Vec<_>>())
            );
        }
    }

    /// Resident bytes one Genesis-3-sized `CommittedState` costs — the price
    /// of one slot in [`REORG_STATE_WINDOW`]. Read from the OS, not from
    /// `size_of`, because the cost is the allocator's and not the struct's.
    #[test]
    #[ignore]
    fn bench_state_footprint() {
        fn rss_kb() -> u64 {
            let out = std::process::Command::new("ps")
                .args(["-o", "rss=", "-p", &std::process::id().to_string()])
                .output()
                .expect("ps");
            String::from_utf8_lossy(&out.stdout).trim().parse().unwrap_or(0)
        }
        let base = mainnet_sized_state(MAINNET_EUTXOS);
        let before = rss_kb();
        let held: Vec<CommittedState> = (0..4).map(|_| base.clone()).collect();
        let after = rss_kb();
        println!(
            "4 extra Genesis-3-sized states: RSS {before} kB -> {after} kB \
             ({} MB each)",
            (after.saturating_sub(before)) / 4 / 1024
        );
        std::hint::black_box(&held);
    }

    /// Win 2's shape: the base state a reorg starts from, computed the old
    /// way (replay every canonical block from genesis) and the new way (a
    /// retained snapshot), as the chain gets longer.
    ///
    /// Devnet-sized state, so the absolute numbers are small — the finding is
    /// the SHAPE. The old cost grows with chain height and the new one does
    /// not, which is the whole change; on a chain with a Genesis-3 carryover
    /// every one of those `apply_block` calls also carries the state root
    /// measured above.
    #[test]
    #[ignore]
    fn bench_reorg_base_state() {
        for height in [10u64, 30, 60] {
            let (mut engine, _dir) = perf_support::proposing_engine();
            for slot in 1..=height {
                engine.propose(slot);
            }
            let parent = *engine.chain[engine.chain.len() - 2].1.as_bytes();
            assert!(
                engine.recent_states.iter().any(|(id, _)| *id == parent),
                "the parent must be in the window for the AFTER measurement"
            );

            let mut old = Vec::new();
            for _ in 0..5 {
                let t = Instant::now();
                let st = engine.replay_to(parent);
                old.push(t.elapsed().as_micros());
                std::hint::black_box(&st);
            }
            let mut new = Vec::new();
            for _ in 0..5 {
                let t = Instant::now();
                let st = engine.state_at_canonical(parent);
                new.push(t.elapsed().as_micros());
                std::hint::black_box(&st);
            }
            println!(
                "reorg base state at height {height}, depth 1: BEFORE (replay from genesis) \
                 median {} us, AFTER (snapshot) median {} us",
                median(old),
                median(new)
            );
        }
    }

    #[test]
    #[ignore]
    fn bench_clone_and_process_epoch() {
        let st = mainnet_sized_state(MAINNET_EUTXOS);
        let tr = Transition::new(ProbeVerifier);
        let mut clones = Vec::new();
        let mut rolls = Vec::new();
        for _ in 0..7 {
            let t = Instant::now();
            let c = st.clone();
            clones.push(t.elapsed().as_micros());
            let t = Instant::now();
            let _ = tr.process_epoch(&c).expect("infallible");
            rolls.push(t.elapsed().as_micros());
        }
        println!(
            "clone over {MAINNET_EUTXOS} eUTXOs: median {} us; process_epoch: median {} us",
            median(clones),
            median(rolls)
        );
    }
}

/// **Win 1's proof.** The memoized rolled state must be the SAME STATE the
/// uncached derivation produces — not merely a state, and not a state that
/// was right a block ago.
///
/// This is the change in this branch that could silently become a consensus
/// change. A rolled state supplies the duty roster and the sortition seed, so
/// serving a stale one makes this node judge attestations against a committee
/// no other node is using: it accepts what peers reject and rejects what peers
/// accept, from an honest binary, with no error anywhere. That is the shape of
/// the `expected_bits` split of 2026-08-08, which is why the key is
/// `(generation, epoch)` and why these tests exist in this form.
///
/// `rolled_to_uncached` is the pre-change body, kept verbatim, so "identical"
/// here means identical to the code that shipped and not to a paraphrase of
/// it. Comparison is by `PartialEq` over the whole `CommittedState` — every
/// field, committed or not — rather than by state root, so a divergence in
/// something the root does not cover still fails.
#[cfg(test)]
mod rolled_memo_tests {
    use super::*;

    /// Across forty proposed slots — which crosses an epoch boundary — and
    /// for four target epochs at each of them, the memoized answer equals the
    /// freshly-derived one.
    ///
    /// The state advances on every iteration, so this is the invalidation
    /// path exercised forty times over: a memo that failed to notice a block
    /// would be serving the previous slot's roster by the second assertion.
    #[test]
    fn the_memo_is_bit_identical_to_the_uncached_derivation() {
        let (mut engine, _dir) = perf_support::proposing_engine();
        let mut crossed = false;
        for slot in 1..=40u64 {
            engine.propose(slot);
            let base = epoch_of(engine.state.slot());
            crossed |= base >= 1;
            for target in base..=base + 3 {
                let memoized = engine.rolled_to(target);
                let fresh = engine.rolled_to_uncached(target);
                assert_eq!(
                    *memoized, fresh,
                    "slot {slot}: the memoized roll to epoch {target} is not the state the \
                     uncached derivation produces"
                );
                // Asked twice, the memo now HAS to answer from itself — and
                // it must answer the same thing.
                assert_eq!(
                    *engine.rolled_to(target),
                    fresh,
                    "slot {slot}: the second, memo-served roll to epoch {target} diverged"
                );
            }
        }
        assert!(
            crossed,
            "the run must actually cross an epoch boundary, or this proves nothing about \
             rolling across one"
        );
        assert_eq!(
            engine.chain.len(),
            41,
            "forty proposed slots must land forty blocks on genesis"
        );
    }

    /// A block moves the state, and the rolled view of the *same* epoch must
    /// move with it.
    ///
    /// The `assert_ne!` is the half that makes this a test: if rolling to a
    /// fixed epoch gave the same answer before and after a block, a memo
    /// keyed on the epoch alone would be correct and there would be nothing
    /// to prove.
    #[test]
    fn a_block_invalidates_the_rolled_view_of_the_same_epoch() {
        let (mut engine, _dir) = perf_support::proposing_engine();
        for slot in 1..=3 {
            engine.propose(slot);
        }
        let target = epoch_of(engine.state.slot()) + 1;

        let before = engine.rolled_to(target).state_root();
        let gen_before = engine.state.generation();

        engine.propose(4);
        assert_eq!(engine.chain.len(), 5, "slot 4 must have landed");
        assert_ne!(
            engine.state.generation(),
            gen_before,
            "an applied block must move the generation, or the key's identity half is inert"
        );

        let after = engine.rolled_to(target);
        assert_ne!(
            before,
            after.state_root(),
            "rolling to epoch {target} must give a different state once a block has landed — \
             if it does not, this test cannot detect a stale memo"
        );
        assert_eq!(
            *after,
            engine.rolled_to_uncached(target),
            "after the state moved, the memo must serve the NEW roll"
        );
    }

    /// The generation half of the key is load-bearing, proved by planting a
    /// wrong answer under it.
    ///
    /// First half: an entry for the right epoch carrying the wrong state, but
    /// tagged with a generation that is not the live one, must be ignored —
    /// this is exactly the entry a naive epoch-only key would have returned.
    ///
    /// Second half is the control, and without it the first proves nothing: a
    /// memo that is never consulted at all would also pass. The identical
    /// entry under the LIVE generation IS returned, so the lookup is real and
    /// what rejected the first entry was the generation.
    #[test]
    fn a_stale_generation_is_never_served_and_a_live_one_is() {
        let (mut engine, _dir) = perf_support::proposing_engine();
        for slot in 1..=3 {
            engine.propose(slot);
        }
        let base = epoch_of(engine.state.slot());
        let target = base + 1;
        let control_target = base + 2;

        let honest = engine.rolled_to_uncached(target);
        // A state that is emphatically not the answer for `target`.
        let poison = engine.rolled_to_uncached(base + 9);
        assert_ne!(
            poison.state_root(),
            honest.state_root(),
            "fixture: the planted state must differ from the honest one"
        );

        let live = engine.state.generation();
        assert!(live > 0, "fixture: blocks must have moved the generation");

        // ── the stale entry ────────────────────────────────────────────────
        engine
            .state
            .plant(live.wrapping_sub(1), target, poison.clone());
        assert_eq!(
            *engine.rolled_to(target),
            honest,
            "a rolled state memoized against a DIFFERENT state was served — this is the \
             wrong-committee bug the key exists to prevent"
        );

        // ── the control ───────────────────────────────────────────────────
        engine.state.plant(live, control_target, poison.clone());
        assert_eq!(
            engine.rolled_to(control_target).state_root(),
            poison.state_root(),
            "an entry under the LIVE generation was not served, so the test above passed \
             because nothing reads the memo rather than because the key rejected the entry"
        );
    }
}

/// **Win 2's proof.** A reorg that starts from a retained snapshot must land
/// on exactly the state and the head that replaying from genesis lands on.
///
/// The retention window is an optimisation with a correct slow path
/// underneath it, and both halves are tested here: that the fast path agrees
/// with the slow one wherever it applies, and that a reorg deeper than the
/// window really does fall through to the slow one rather than quietly
/// serving something else. The `assert_eq!` on the hit/miss is what stops the
/// second claim from being a comment.
#[cfg(test)]
mod reorg_state_tests {
    use super::*;

    /// A chain and a real competing branch, built with the node's own APIs
    /// and nothing else: propose a rival on the fork point, hand it back with
    /// a reorg to an empty branch (a legitimate LMD-GHOST outcome — weight
    /// moved to a sibling and the chain gives blocks back), then outrun it by
    /// `depth` canonical blocks. What is left is a stored, valid block whose
    /// parent sits `depth` below the head.
    pub(super) fn forked(depth: u64) -> (Engine, perf_support::TestDir, [u8; 32], BlockEnvelope) {
        let (mut engine, dir) = perf_support::proposing_engine();
        engine.propose(1);
        let fork_point = *engine.head_id().as_bytes();

        engine.propose(2);
        let rival = engine
            .blocks
            .get(engine.head_id().as_bytes())
            .expect("the rival was just proposed and adopted")
            .clone();
        assert!(
            engine.do_reorg(fork_point, Vec::new()),
            "handing the rival back must succeed"
        );
        assert_eq!(
            *engine.head_id().as_bytes(),
            fork_point,
            "after giving the block back the head is the fork point"
        );

        // Take the rival OUT of the block store while the canonical branch is
        // built.
        //
        // Not tidiness — determinism. `propose` ends in `ingest`, which runs
        // fork choice over every stored block; the rival and the new block are
        // siblings with no attestations, so LMD-GHOST breaks a zero-weight tie
        // by block id, and the id depends on this run's throwaway keystore.
        // Left in, the fixture re-adopts the rival on some runs and the test
        // then compares a state against itself. It was caught by the
        // `assert_ne!` fixture guard below, which is the entire reason that
        // guard is there.
        let rival_id = *rival.block_id().as_bytes();
        engine
            .blocks
            .remove(&rival_id)
            .expect("the rival is stored until this line removes it");

        for slot in 3..3 + depth {
            engine.propose(slot);
        }

        // Back in: the test needs it stored to reorg onto it.
        engine.blocks.insert(rival_id, rival.clone());
        assert!(
            !engine.canonical.contains(&rival_id),
            "the rival must be off the canonical chain when the fixture is handed over"
        );
        assert_eq!(
            engine.chain.len() as u64,
            2 + depth,
            "genesis, the fork point, and {depth} blocks above it"
        );
        (engine, dir, fork_point, rival)
    }

    /// At every canonical depth, in a shuffled order, the snapshot answer and
    /// the replay answer are the same state — and the ring is holding exactly
    /// the depths it claims to.
    #[test]
    fn the_snapshot_and_the_replay_agree_at_every_canonical_depth() {
        let (mut engine, _dir) = perf_support::proposing_engine();
        for slot in 1..=6 {
            engine.propose(slot);
        }
        assert_eq!(engine.chain.len(), 7);

        // A deterministic shuffle, so no depth is only ever visited in the
        // order the ring happens to like.
        let mut order: Vec<usize> = (1..engine.chain.len()).collect();
        let mut seed = 0x9E37_79B9_7F4A_7C15u64;
        for i in (1..order.len()).rev() {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let j = (seed >> 33) as usize % (i + 1);
            order.swap(i, j);
        }

        for idx in order {
            let id = *engine.chain[idx].1.as_bytes();
            let depth = engine.chain.len() - 1 - idx;
            let retained = engine.recent_states.iter().any(|(bid, _)| *bid == id);
            assert_eq!(
                retained,
                depth < REORG_STATE_WINDOW,
                "depth {depth}: the ring must retain exactly the last \
                 {REORG_STATE_WINDOW} blocks — if it retained more, the deep \
                 cases below would never exercise the replay fallback"
            );
            assert_eq!(
                *engine.state_at_canonical(id),
                engine.replay_to(id),
                "depth {depth}: the snapshot and the replay-from-genesis \
                 disagree about the same block's post-state"
            );
        }
    }

    /// A real reorg at depths on both sides of the retention window lands on
    /// the state and head the pre-change path lands on.
    ///
    /// `expected` is computed with `replay_to` plus `apply_block` over the
    /// branch, which IS the body `do_reorg` had before this change — so this
    /// compares against the old code, not against a paraphrase of it.
    #[test]
    fn a_reorg_lands_where_replay_from_genesis_lands() {
        let mut saw_hit = false;
        let mut saw_fallback = false;
        for depth in 1..=5u64 {
            let (mut engine, _dir, fork_point, rival) = forked(depth);

            let expected = {
                let base = engine.replay_to(fork_point);
                let envelope = ProposalEnvelope {
                    header: rival.header.clone(),
                    proposer_sig: rival.proposer_sig.clone(),
                };
                let txs = body_transactions(&rival).expect("the rival's body decodes");
                engine
                    .tr
                    .apply_block(&base, &envelope, &rival.body.attestations, &txs)
                    .expect("the rival is valid on its own parent")
            };
            assert_ne!(
                *engine.state, expected,
                "depth {depth}: fixture — the reorg must actually move the state, or this \
                 test would pass without the reorg happening at all"
            );

            let hit = engine
                .recent_states
                .iter()
                .any(|(id, _)| *id == fork_point);
            if hit {
                saw_hit = true;
            } else {
                saw_fallback = true;
            }
            assert_eq!(
                hit,
                depth < REORG_STATE_WINDOW as u64,
                "depth {depth}: the fork point should be retained iff it is inside the window"
            );

            assert!(
                engine.do_reorg(fork_point, vec![rival.clone()]),
                "depth {depth}: the reorg must be adopted"
            );
            assert_eq!(
                *engine.state, expected,
                "depth {depth}: the reorg landed on a DIFFERENT state than replaying from \
                 genesis would have — this is a consensus divergence, not a slow path"
            );
            assert_eq!(
                engine.head_id(),
                rival.block_id(),
                "depth {depth}: the head must be the adopted branch tip"
            );
            assert_eq!(
                engine.chain.len(),
                3,
                "depth {depth}: genesis, the fork point, the rival"
            );
            // The ring must now describe the branch that WON. A ring still
            // holding the abandoned branch would make the next reorg start
            // from a state on a chain this node no longer has.
            for (id, st) in engine.recent_states.iter() {
                assert_eq!(
                    **st,
                    engine.replay_to(*id),
                    "depth {depth}: the ring kept a post-state that is not this block's"
                );
                assert!(
                    engine.canonical.contains(id),
                    "depth {depth}: the ring kept a block that is not canonical"
                );
            }
        }
        assert!(
            saw_hit && saw_fallback,
            "the sweep must exercise BOTH the retained snapshot and the replay fallback \
             (hit: {saw_hit}, fallback: {saw_fallback})"
        );
    }
}

/// **The invariant `getchaininfo` is about to rest on.**
///
/// `chain_info_json` used to recompute the committed state root on the
/// consensus thread for every caller — MEASURED at 32.6 ms cold / 3.0 ms warm
/// at Genesis-4's size, see [`Engine::head_state_root`], which also records
/// why that is not the 733 ms the 2026-08-21 n21 incident was reported at.
///
/// The head block's HEADER already carries that root. `apply_block` returns
/// `Ok(post)` on exactly one condition — `post.compute_root() ==
/// header.state_root` (transition.rs step 12) — so for any head this node
/// adopted, the header field and `state.state_root()` are the same 32 bytes.
/// `apply_canonical`'s log line and `do_reorg`'s already lean on that.
///
/// What that argument does NOT cover by inspection is whether `self.state` is
/// always the *head's* post-state: a reorg replaces both, and a boot has a
/// head with no header at all. Those are the paths that would make the RPC
/// lie silently rather than loudly, and `getchaininfo` is what integrators and
/// exchanges read. So they are pinned here, against the real block path —
/// `propose`/`ingest`/`do_reorg`, the production transition, the production
/// ML-DSA-65 ‖ Falcon-1024 verifier — rather than argued.
#[cfg(test)]
mod head_root_tests {
    use super::*;

    /// The equality, at whatever the engine's head is right now.
    ///
    /// Returns the header root so a caller can also pin that it MOVED, which
    /// is what stops "the roots agree" from passing on a chain that never
    /// advanced.
    fn assert_invariant(engine: &Engine, ctx: &str) -> [u8; 32] {
        let head = engine.head_id();
        let env = engine
            .blocks
            .get(head.as_bytes())
            .unwrap_or_else(|| panic!("{ctx}: the head must be a stored block here"));
        let computed = engine.state.state_root();
        assert_eq!(
            env.header.state_root, computed,
            "{ctx}: the head header's committed root and the engine's live state root \
             disagree at slot {} — `getchaininfo` reading the header would publish a \
             root that is not this node's state",
            env.header.slot
        );
        // And the accessor `getchaininfo` actually calls, so this pins the
        // shipped code path and not just the property it rests on.
        assert_eq!(
            engine.head_state_root(),
            computed,
            "{ctx}: `head_state_root` disagrees with the recomputed root"
        );
        computed
    }

    /// Ordinary blocks AND an epoch boundary, on the real proposal path.
    ///
    /// The slots are sparse on purpose. `propose` takes the slot as an
    /// argument and this fixture's single validator is the proposer at every
    /// one of them, so 31 → 32 crosses from epoch 0 into epoch 1 (and 63 → 64
    /// into epoch 2) for the price of two blocks instead of thirty. The
    /// boundary is where `apply_block` rolls epoch accounting into the
    /// post-state, so it is the step most likely to move the state out from
    /// under a header — which is why it is here and not left to a comment.
    #[test]
    fn the_head_header_root_is_the_committed_state_root_across_an_epoch_boundary() {
        let (mut engine, _dir) = perf_support::proposing_engine();

        let slots = [1u64, 2, 3, 30, 31, 32, 33, 63, 64, 65];
        let mut seen_epochs = BTreeSet::new();
        let mut roots = BTreeSet::new();
        let mut applied = 0usize;

        for slot in slots {
            let before = engine.chain.len();
            engine.propose(slot);
            assert_eq!(
                engine.chain.len(),
                before + 1,
                "fixture: slot {slot} did not extend the chain, so nothing was checked there"
            );
            applied += 1;
            let root = assert_invariant(&engine, &format!("after proposing slot {slot}"));
            // Read off the ENGINE's committed state, not off the slot this
            // loop asked for — otherwise the epoch-coverage assertion below
            // would only be restating the literal array above.
            seen_epochs.insert(epoch_of(engine.state.slot()));
            roots.insert(root);
        }

        assert_eq!(applied, slots.len(), "fixture: every slot must have applied");
        assert!(
            seen_epochs.len() >= 3,
            "fixture: the sweep must cross at least two epoch boundaries, saw epochs {seen_epochs:?}"
        );
        assert!(
            roots.len() > 1,
            "fixture: the state root never moved across {applied} blocks — the equality \
             above would then be one constant compared with itself"
        );
    }

    /// A REORG, at depths on both sides of the snapshot retention window.
    ///
    /// `reorg_state_tests::forked` builds a real competing branch with the
    /// node's own APIs; `do_reorg` adopts it through the production
    /// `apply_block`. The reorg is proved to have actually happened rather
    /// than no-opped four ways: the head id must change to the rival's, the
    /// pre-reorg head must leave the canonical set, `chain.len()` must
    /// collapse from `2 + depth` to 3, and the whole `CommittedState` must
    /// compare unequal across the call.
    ///
    /// **The state, not the state ROOT — and that distinction is a real
    /// property of Genesis-4, found here.** `ConsensusState` (state_root.rs
    /// §5.5, the closed list `compute_root` builds the tree from) carries no
    /// head block id and no slot; the finest time it commits is the epoch,
    /// through the RANDAO window. So two SIBLING blocks in one epoch with
    /// empty bodies commit the SAME 32 bytes, and this sweep hits that at
    /// depth 1: head slot 3 -> 2 with the root unmoved at both ends. The
    /// invariant still held there — it is the root that is coarse, not the
    /// engine that is wrong. Anyone reading `getchaininfo` should note that
    /// `state_root` does NOT identify the head; `block_id`, in the same
    /// object, does.
    #[test]
    fn a_reorg_leaves_the_head_header_root_equal_to_the_committed_state_root() {
        let mut saw_snapshot_hit = false;
        let mut saw_replay_fallback = false;

        for depth in 1..=5u64 {
            let (mut engine, _dir, fork_point, rival) = reorg_state_tests::forked(depth);
            let ctx = format!("depth {depth}");

            let before_head = engine.head_id();
            let before_state = (*engine.state).clone();
            assert_invariant(&engine, &format!("{ctx}: before the reorg"));

            if engine
                .recent_states
                .iter()
                .any(|(id, _)| *id == fork_point)
            {
                saw_snapshot_hit = true;
            } else {
                saw_replay_fallback = true;
            }

            assert!(
                engine.do_reorg(fork_point, vec![rival.clone()]),
                "{ctx}: the reorg must be adopted"
            );

            // It really reorged, not no-opped.
            assert_eq!(
                engine.head_id(),
                rival.block_id(),
                "{ctx}: the head must be the adopted branch tip"
            );
            assert_ne!(
                engine.head_id(),
                before_head,
                "{ctx}: the head did not move, so no reorg was exercised"
            );
            assert_eq!(
                engine.chain.len(),
                3,
                "{ctx}: genesis, the fork point, the rival — the canonical chain must have \
                 been truncated, not extended"
            );

            assert!(
                !engine.canonical.contains(before_head.as_bytes()),
                "{ctx}: the pre-reorg head is still canonical, so nothing was given back"
            );
            assert_ne!(
                *engine.state, before_state,
                "{ctx}: the committed state did not change across the reorg — the check \
                 after it would then be the same comparison as the one before"
            );

            assert_invariant(&engine, &format!("{ctx}: after the reorg"));
        }

        assert!(
            saw_snapshot_hit && saw_replay_fallback,
            "the sweep must exercise BOTH the retained-snapshot reorg and the \
             replay-from-genesis fallback (hit: {saw_snapshot_hit}, fallback: \
             {saw_replay_fallback})"
        );
    }

    /// The empty branch: LMD-GHOST moved weight to a sibling and the chain
    /// gives a block BACK. The new head is then a block this node already had
    /// — a different write path into `state` (`set_arc` from the snapshot
    /// ring, not `set` from a fresh `apply_block`) and the one place a stale
    /// header could survive an unchanged block store.
    #[test]
    fn giving_a_block_back_leaves_the_head_header_root_equal_to_the_committed_state_root() {
        let (mut engine, _dir) = perf_support::proposing_engine();
        engine.propose(1);
        let fork_point = *engine.head_id().as_bytes();
        let at_fork = assert_invariant(&engine, "at the fork point");

        engine.propose(2);
        let ahead = assert_invariant(&engine, "one block above the fork point");
        assert_ne!(at_fork, ahead, "fixture: the second block must move the root");

        assert!(
            engine.do_reorg(fork_point, Vec::new()),
            "handing the block back must succeed"
        );
        assert_eq!(
            *engine.head_id().as_bytes(),
            fork_point,
            "the head is the fork point again"
        );

        let back = assert_invariant(&engine, "after giving the block back");
        assert_eq!(
            back, at_fork,
            "giving a block back must restore the state that block's parent committed"
        );
    }

    /// **Genesis, the one head with no header to read.**
    ///
    /// `ingest` returns early on slot 0 — "genesis is synthesized, never
    /// received" — so at boot the head is canonical, is the state's own head,
    /// and is NOT in `blocks`. A lookup there returns `None`, and letting that
    /// fall into `unwrap_or_default()` would publish 32 zero bytes as if it
    /// were an answer. This pins that the situation is real, so the fallback
    /// in `head_state_root` is not dead code guarding an impossible case.
    #[test]
    fn at_boot_the_head_is_genesis_and_genesis_has_no_stored_header() {
        let (engine, _dir) = perf_support::proposing_engine();
        assert!(
            engine.blocks.is_empty(),
            "a fresh engine has no stored blocks"
        );
        assert_eq!(engine.chain.len(), 1, "the chain is genesis alone");
        assert!(
            engine.blocks.get(engine.head_id().as_bytes()).is_none(),
            "genesis is synthesized and is never in `blocks` — the header lookup MUST \
             miss here, and the fallback below is what answers"
        );

        // The fallback answers with the value the RPC returned before the
        // change, which is what makes this transport-only rather than a new
        // behaviour at boot. Both halves matter: it must equal the computed
        // root, and it must NOT be the all-zero root `unwrap_or_default()`
        // would have produced.
        assert_eq!(
            engine.head_state_root(),
            engine.state.state_root(),
            "at genesis the fallback must return the computed root — the same bytes \
             `getchaininfo` returned here before"
        );
        assert_ne!(
            engine.head_state_root(),
            [0u8; 32],
            "the genesis answer must not be the default-initialised root"
        );
    }
}

/// **The anchor defect, on one fixture.**
///
/// The consensus AUTHORITY for the seed is
/// [`CommittedState::seed_for_epoch`], evaluated by `apply_block` on the state
/// the block is applied against — its parent's, because step 2 refuses any
/// other (`WrongParent`). That is ancestry, and two nodes applying the same
/// block to the same parent cannot disagree about it.
///
/// The node's DUTY view evaluates the same function on `rolled_to(epoch)`,
/// which is this node's OWN head rolled forward. When the head is not the
/// judged block's parent — a node three blocks behind, a node whose head sits
/// on a sibling branch — the duty view and the authority part company, and the
/// node rejects honest votes as `NotInCommittee` while every rule it is
/// applying is the right rule.
///
/// The fixture below moves ONLY the head, on ONE branch, with no fork and no
/// disagreement about any block, and shows the seed and the partition move
/// with it. That is the whole defect: the anchor, not the expression.
///
/// It needs no flag day to fix — the target value is the one consensus already
/// defines — which is why it is deliberately NOT bundled with the look-ahead
/// gate this branch also carries.
#[cfg(test)]
mod duty_view_anchor {
    use super::*;
    use crate::genesis::ManifestValidator;
    use bloch_pos_committee::SLOTS_PER_EPOCH;
    use bloch_pos_committee::beacon::RandaoChain;

    const SAT_PER_BLOCH: u128 = 100_000_000;

    struct Dir(PathBuf);
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A devnet engine whose REGISTRY holds `n` validators while this node
    /// holds the key for index 0 only.
    ///
    /// `perf_support::proposing_engine` registers one validator, and one
    /// validator is not enough for this test: `epoch_committees` partitions
    /// the roster, and the only permutation of a one-element roster is the
    /// identity, so its partition is the same for every seed. The first
    /// version of this test asserted the partition moved, and its own fixture
    /// guard failed — which is the guard doing its job rather than a
    /// comparator that quietly proves nothing.
    ///
    /// The other `n - 1` validators never sign: they exist to give the
    /// partition something to permute. Production is therefore sparse — node 0
    /// proposes only in the slots it is drawn for — which is what a real
    /// validator's view looks like anyway.
    fn engine_with_registry(n: u32) -> (Engine, Dir) {
        static DIR_SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = Dir(std::env::temp_dir().join(format!(
            "bloch-anchor-{}-{}",
            std::process::id(),
            DIR_SEQ.fetch_add(1, Ordering::Relaxed)
        )));
        let _ = std::fs::remove_dir_all(&dir.0);
        std::fs::create_dir_all(&dir.0).expect("create the test data dir");

        let keys: Vec<Keystore> = (0..n)
            .map(|i| {
                Keystore::generate(&dir.0.join(format!("v{i}")), i)
                    .expect("generate a devnet keystore")
            })
            .collect();
        let manifest = Manifest {
            genesis_time_ms: now_ms(),
            slot_ms: 1_000,
            validators: keys
                .iter()
                .map(|ks| ManifestValidator {
                    index: ks.index,
                    stake_sat: 200_000 * SAT_PER_BLOCH,
                    randao_commitment: RandaoChain::generate(ks.randao_seed).commitment(),
                    pubkey: ks.pubkey.clone(),
                    withdrawal_credentials: Vec::new(),
                    commission_bps: 0,
                })
                .collect(),
            cohort: Vec::new(),
            carryover: None,
            allocations: Vec::new(),
            carryover_entries: Vec::new(),
        };
        let genesis_id = manifest.genesis_id();
        let state = manifest.genesis_state();
        let store = Store::open(&dir.0, &[0u8; 32]).expect("open the test store");
        let (events, _rx) = mpsc::channel::<EngineEvent>();
        let head_slot = Arc::new(AtomicU64::new(0));
        let inflight = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let net = net::Net::Devnet(
            net::start(
                "127.0.0.1",
                0,
                Vec::new(),
                events,
                dir.0.clone(),
                head_slot.clone(),
                inflight,
            )
            .expect("bind the devnet transport on an ephemeral port"),
        );
        let verifier = HybridVerifier::new(manifest.pubkeys());
        let ks0 = Keystore::load(&dir.0.join("v0")).expect("re-load validator 0");
        let engine = Engine {
            manifest,
            state: StateCell::new(state),
            tr: Transition::new(verifier.clone()),
            tr_probe: Transition::new(ProbeVerifier),
            verifier,
            keys: Some(ks0),
            blocks: BTreeMap::new(),
            chain: vec![(0, genesis_id)],
            canonical: BTreeSet::from([*genesis_id.as_bytes()]),
            recent_states: VecDeque::new(),
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
            fc_covered_removals: 0,
        };
        (engine, dir)
    }

    #[test]
    fn giving_three_blocks_back_moves_the_duty_view_seed_and_the_partition() {
        let (mut engine, _dir) = engine_with_registry(8);
        // Sparse production: this node proposes only in the slots it is drawn
        // for, so the loop runs until the HEAD is in epoch 2 rather than for a
        // fixed block count.
        for slot in 1..=(SLOTS_PER_EPOCH * 3) {
            engine.propose(slot);
        }
        let head_epoch = epoch_of(engine.state.slot());
        assert!(
            head_epoch >= 2,
            "the head only reached epoch {head_epoch}; the fixture needs epoch 2"
        );
        assert!(
            engine.chain.len() >= 5,
            "only {} blocks were produced — too few to give three back",
            engine.chain.len() - 1
        );

        let e = head_epoch + 1;
        let rolled = engine.rolled_to(e);
        let seed_caught_up = Engine::seed_for(&rolled, e);
        let partition_caught_up =
            committees::epoch_committees(&seed_caught_up, e, &rolled.active_validators());

        // Give three blocks back. Same branch, same rules, same everything —
        // three blocks less of it. This is what "a node that is behind" is.
        let ancestor = *engine.chain[engine.chain.len() - 4].1.as_bytes();
        let before = engine.chain.len();
        assert!(
            engine.do_reorg(ancestor, Vec::new()),
            "handing three blocks back on the node's own branch must succeed"
        );
        assert_eq!(engine.chain.len(), before - 3);

        let rolled_behind = engine.rolled_to(e);
        let seed_behind = Engine::seed_for(&rolled_behind, e);
        let partition_behind =
            committees::epoch_committees(&seed_behind, e, &rolled_behind.active_validators());

        assert_ne!(
            seed_caught_up, seed_behind,
            "THE DEFECT: the duty-view seed for epoch {e} changed because this node's HEAD \
             moved, on a branch nobody disputes"
        );
        assert_ne!(
            partition_caught_up, partition_behind,
            "the seed moved but the partition did not — widen the fixture, because as \
             written this test would not notice the bug it exists to show"
        );

        // The number that matters for the flood: how many of the epoch's 32
        // committees changed membership because this node's head moved.
        let moved = partition_caught_up
            .iter()
            .zip(partition_behind.iter())
            .filter(|(a, b)| a != b)
            .count();
        println!(
            "duty-view anchor: giving 3 blocks back changed {moved} of {} slot committees \
             in epoch {e}, on one undisputed branch",
            partition_caught_up.len()
        );
        assert!(moved > 0);
    }
}
