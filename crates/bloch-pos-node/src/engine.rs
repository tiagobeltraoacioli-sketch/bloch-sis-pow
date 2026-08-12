// SPDX-License-Identifier: AGPL-3.0-or-later

//! The consensus engine: one thread owning all consensus state, driven by the
//! slot timer and by network events — nothing else mutates state
//! (integration plan §1.1). The wall clock enters exactly here, at the timer;
//! every rule below it is the pure crate's.
//!
//! ## Which composition seam this engine binds
//!
//! The pure crate ships **two** parallel producer/validator seams:
//! `transition.rs` (`Transition` + `CommittedState` — epochs, finality,
//! rewards, fork-choice accumulation) and `derive.rs`/`produce.rs`
//! (`ParentState`/`ChainState`). Their committed state roots are **not**
//! byte-compatible (they commit different beacon-mix windows), so a node must
//! bind exactly one. This engine binds `Transition`/`CommittedState`, the
//! seam that implements the frozen `StateTransition`/`StateReader` traits and
//! composes finality; the header's body/attestation commitments — which
//! `Transition` deliberately does not judge — are checked here through
//! `derive::body_root`/`derive::attestation_root`, the single definitions of
//! those roots. The unreconciled two-seam situation is flagged in the task
//! report; do not "fix" it here by re-deriving anything.
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
//! ## Fork choice — honest scope
//!
//! Canonical is the highest-slot fully-valid chain this node knows
//! (longest-valid-chain, adopted by replaying the branch from genesis). This
//! is NOT the designed LMD-GHOST fork choice: the transition accumulates
//! attestation weight in committed state, but no `forkchoice::Store` head
//! walk is wired at the node level yet, so competing equal-length forks
//! resolve by whoever extends first rather than by attested weight. Enough
//! for a cooperative devnet; listed as missing for mainnet in the report.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bloch_pos_committee::attestation::{Attestation, AttestationData};
use bloch_pos_committee::beacon::{mix_in, RandaoChain};
use bloch_pos_committee::header::{BlockEnvelope, BlockHeaderV4, BlockId, Body, VERSION_G4};
use bloch_pos_committee::interfaces::{ProposalEnvelope, StateReader, StateTransition};
use bloch_pos_committee::schedule::first_slot_of_epoch;
use bloch_pos_committee::transition::{CommittedState, PosTransaction, Transition};
use bloch_pos_committee::{committees, derive, epoch_of, schedule};

use crate::genesis::{Manifest, GENESIS_MIX};
use crate::keys::{HybridVerifier, Keystore, ProbeVerifier};
use crate::net::{self, NetEvent};
use crate::store::Store;

pub struct Config {
    pub data_dir: PathBuf,
    pub genesis_path: PathBuf,
    pub listen: u16,
    pub peers: Vec<String>,
    pub stop_at_slot: Option<u64>,
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

const NO_TXS: [PosTransaction; 0] = [];

struct Engine {
    manifest: Manifest,
    state: CommittedState,
    tr: Transition<HybridVerifier>,
    tr_probe: Transition<ProbeVerifier>,
    verifier: HybridVerifier,
    keys: Keystore,
    /// Every structurally-valid block seen, canonical or not, by id.
    /// Unpruned — fine for a devnet, listed as a limitation.
    blocks: BTreeMap<[u8; 32], BlockEnvelope>,
    /// Canonical chain, ascending slot, genesis first.
    chain: Vec<(u64, BlockId)>,
    /// Canonical ids (incl. genesis).
    canonical: BTreeSet<[u8; 32]>,
    /// Attestation pool, keyed by content so duplicates collapse.
    pool: BTreeMap<(u32, [u8; 32]), Attestation>,
    store: Store,
    net: net::Net,
    head_slot: Arc<AtomicU64>,
    /// False during boot replay: no log appends, no broadcasts, no logs.
    live: bool,
    needs_sync: bool,
    last_applied_ms: u64,
    booted_ms: u64,
}

impl Engine {
    // ── Derivations over the canonical chain ────────────────────────────────

    fn head_id(&self) -> BlockId {
        self.chain.last().expect("chain contains at least genesis").1
    }

    fn head_slot_now(&self) -> u64 {
        self.chain.last().expect("chain contains at least genesis").0
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
            st = self.tr.process_epoch(&st).expect("process_epoch is infallible");
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

    /// This validator's RANDAO chain, positioned at its committed reveal
    /// count on the CANONICAL chain (= how many canonical blocks it
    /// proposed). Regenerated from the seed on every use: a reorg can drop
    /// our own blocks, so an incrementally-advanced local chain would drift
    /// from what the committed state expects the next reveal to open.
    fn randao_positioned(&self) -> RandaoChain {
        let mine = self.chain.iter().skip(1).filter(|(_, id)| {
            self.blocks
                .get(id.as_bytes())
                .is_some_and(|e| e.header.proposer_index == self.keys.index)
        });
        let count = mine.count();
        let mut chain = RandaoChain::generate(self.keys.randao_seed);
        for _ in 0..count {
            chain.next_reveal();
        }
        chain
    }

    // ── Duties ──────────────────────────────────────────────────────────────

    fn attest(&mut self, slot: u64) {
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
        if committee.binary_search(&self.keys.index).is_err() {
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
        let signature = self.keys.sign(&data.signing_root());
        let att = Attestation { data, validator: self.keys.index, signature };
        self.pool.insert((att.validator, att.data.signing_root()), att.clone());
        self.net.broadcast(net::att_frame(&att));
        println!(
            "[slot {slot}] attested (epoch {e}, head {}, target {})",
            crate::codec::hex8(&data.head),
            crate::codec::hex8(&data.target_root)
        );
    }

    fn propose(&mut self, slot: u64) {
        let e = epoch_of(slot);
        let rolled = self.rolled_to(e);
        let roster = rolled.active_validators();
        let seed = Self::seed_for(&rolled, e);
        if schedule::proposer(&seed, slot, &roster) != Some(self.keys.index) {
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
            eprintln!("[slot {slot}] RANDAO chain spent — cannot propose (re-commit path not wired)");
            return;
        };
        let fin = rolled.finality();
        let mut header = BlockHeaderV4 {
            version: VERSION_G4,
            parent: *self.head_id().as_bytes(),
            state_root: [0u8; 32],
            body_root: derive::body_root(&[]),
            slot,
            proposer_index: self.keys.index,
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
        let probe = ProposalEnvelope { header: header.clone(), proposer_sig: Vec::new() };
        let post = match self.tr_probe.compute_post_state(&self.state, &probe, &atts, &NO_TXS) {
            Ok(p) => p,
            Err(err) => {
                eprintln!("[slot {slot}] produce refused: {err:?}");
                return;
            }
        };
        header.state_root = post.state_root();

        let proposer_sig = self.keys.sign(&header.proposal_signing_root());
        let env = BlockEnvelope {
            header,
            proposer_sig,
            body: Body { transactions: Vec::new(), attestations: atts },
        };
        let id = env.block_id();
        println!(
            "[slot {slot}] proposing block {} ({} attestations)",
            crate::codec::hex8(id.as_bytes()),
            env.body.attestations.len()
        );
        self.ingest(env);
        // h28080: a producer whose own node did not adopt its block is a
        // producer/validator split inside one process. Loud, immediately.
        assert_eq!(
            self.head_id(),
            id,
            "own produced block was not adopted by own transition (h28080 class)"
        );
        let env = self.blocks.get(id.as_bytes()).expect("just ingested").clone();
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
            eprintln!("reject {}: body/attestation commitment mismatch", crate::codec::hex8(&id));
            return;
        }
        if !env.body.transactions.is_empty() {
            // The devnet's tx codec does not exist yet; a block carrying
            // transactions is from a different build. Fail closed.
            eprintln!("reject {}: transactions not supported at this milestone", crate::codec::hex8(&id));
            return;
        }
        if env.header.slot == 0 {
            return; // genesis is synthesized, never received
        }
        self.blocks.insert(id, env);
        self.advance();
    }

    /// Extend the canonical chain with any stored child of the head; when no
    /// child exists, consider adopting a strictly longer stored branch
    /// (replayed from genesis before adoption — never trusted unvalidated).
    fn advance(&mut self) {
        loop {
            let head = *self.head_id().as_bytes();
            // Lowest-slot stored child of the head first: deterministic, and
            // the earliest child is what an honest chain would have built.
            let child = self
                .blocks
                .values()
                .filter(|e| e.header.parent == head && !self.canonical.contains(e.block_id().as_bytes()))
                .min_by_key(|e| e.header.slot)
                .cloned();
            if let Some(env) = child {
                if !self.apply_canonical(&env) {
                    self.blocks.remove(env.block_id().as_bytes());
                }
                continue;
            }
            match self.best_reorg_path() {
                Some((ancestor, branch)) => {
                    if !self.do_reorg(ancestor, branch) {
                        continue; // offending block removed; try again
                    }
                    continue;
                }
                None => break,
            }
        }
    }

    /// Apply one block that extends the current head. True on success.
    fn apply_canonical(&mut self, env: &BlockEnvelope) -> bool {
        let id = env.block_id();
        let envelope =
            ProposalEnvelope { header: env.header.clone(), proposer_sig: env.proposer_sig.clone() };
        let before = self.state.finality();
        match self.tr.apply_block(&self.state, &envelope, &env.body.attestations, &NO_TXS) {
            Ok(post) => {
                self.state = post;
                self.canonical.insert(*id.as_bytes());
                self.chain.push((env.header.slot, id));
                self.head_slot.store(env.header.slot, Ordering::Relaxed);
                self.last_applied_ms = now_ms();
                for a in &env.body.attestations {
                    self.pool.remove(&(a.validator, a.data.signing_root()));
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

    /// The best stored branch strictly longer than the canonical head, with
    /// complete lineage down to a canonical ancestor. Returns the ancestor id
    /// and the branch (ancestor-child first).
    fn best_reorg_path(&mut self) -> Option<([u8; 32], Vec<BlockEnvelope>)> {
        let head_slot = self.head_slot_now();
        let mut tips: Vec<&BlockEnvelope> = self
            .blocks
            .values()
            .filter(|e| !self.canonical.contains(e.block_id().as_bytes()) && e.header.slot > head_slot)
            .collect();
        tips.sort_by_key(|e| std::cmp::Reverse(e.header.slot));
        for tip in tips {
            let mut branch = vec![tip.clone()];
            let mut cur = tip.header.parent;
            loop {
                if self.canonical.contains(&cur) {
                    branch.reverse();
                    return Some((cur, branch));
                }
                match self.blocks.get(&cur) {
                    Some(p) if !self.canonical.contains(p.block_id().as_bytes()) => {
                        branch.push(p.clone());
                        cur = p.header.parent;
                    }
                    _ => {
                        // Lineage incomplete: ask the mesh for what we miss.
                        self.needs_sync = true;
                        break;
                    }
                }
            }
        }
        None
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
            .map(|(_, id)| self.blocks.get(id.as_bytes()).expect("canonical block stored").clone())
            .collect();

        let mut st = self.manifest.genesis_state();
        for env in &prefix {
            let envelope = ProposalEnvelope {
                header: env.header.clone(),
                proposer_sig: env.proposer_sig.clone(),
            };
            st = self
                .tr
                .apply_block(&st, &envelope, &env.body.attestations, &NO_TXS)
                .expect("canonical prefix replay cannot fail (it applied before)");
        }
        for env in &branch {
            let envelope = ProposalEnvelope {
                header: env.header.clone(),
                proposer_sig: env.proposer_sig.clone(),
            };
            match self.tr.apply_block(&st, &envelope, &env.body.attestations, &NO_TXS) {
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
        self.head_slot.store(self.head_slot_now(), Ordering::Relaxed);
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
        }
        true
    }

    // ── Attestation admission ───────────────────────────────────────────────

    fn on_attestation(&mut self, att: Attestation, wall_epoch: u64) {
        let key = (att.validator, att.data.signing_root());
        if self.pool.contains_key(&key) {
            return;
        }
        let e = epoch_of(att.data.slot);
        if e != wall_epoch && e != wall_epoch + 1 {
            return; // stale or far-future: never includable from here
        }
        if att.data.source_epoch >= att.data.target_epoch || att.data.target_epoch != e {
            return;
        }
        let rolled = self.rolled_to(e);
        let roster = rolled.active_validators();
        let seed = Self::seed_for(&rolled, e);
        let committee = committees::committee_for_slot(&seed, att.data.slot, &roster);
        if committee.binary_search(&att.validator).is_err() {
            return;
        }
        use bloch_pos_committee::attestation::SignatureVerifier as _;
        if !self.verifier.verify(att.validator, &att.data.signing_root(), &att.signature) {
            eprintln!("attestation from v{} failed hybrid verify", att.validator);
            return;
        }
        self.pool.insert(key, att);
    }
}

// ── Entry point ─────────────────────────────────────────────────────────────

pub fn run(cfg: Config) -> io::Result<()> {
    let (manifest, digest) = Manifest::load(&cfg.genesis_path)?;
    let keys = Keystore::load(&cfg.data_dir)?;
    let verifier = HybridVerifier::new(manifest.pubkeys());

    // Identity sanity: the keystore must be the validator the manifest says.
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

    let store = Store::open(&cfg.data_dir, &digest)?;
    let genesis_state = manifest.genesis_state();
    let genesis_id = manifest.genesis_id();
    println!(
        "bloch-pos devnet node — validator {}, genesis {} (state root {}), network digest {}",
        keys.index,
        crate::codec::hex8(genesis_id.as_bytes()),
        crate::codec::hex8(&genesis_state.state_root()),
        crate::codec::hex8(&digest),
    );

    let logged = store.read_all()?;
    let head_slot = Arc::new(AtomicU64::new(0));
    let (tx, rx) = mpsc::channel::<NetEvent>();
    let net = net::start(cfg.listen, cfg.peers.clone(), tx, cfg.data_dir.clone(), head_slot.clone())?;

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
        store,
        net,
        head_slot,
        live: false,
        needs_sync: false,
        last_applied_ms: now_ms(),
        booted_ms: now_ms(),
        manifest,
    };

    // ── Replay: restart returns to the same state, by re-running the same
    // transition over the same inputs. ──
    let n_logged = logged.len();
    for env in logged {
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
    engine.head_slot.store(engine.state.slot(), Ordering::Relaxed);

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
        let behind =
            engine.state.slot() + 1 < slot && now.saturating_sub(engine.last_applied_ms) > 2 * slot_ms;
        if (behind || engine.needs_sync) && now.saturating_sub(last_sync_req) > 2 * slot_ms {
            engine.net.broadcast(net::get_blocks_frame(engine.state.slot()));
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
                        NetEvent::Block(env) => engine.ingest(env),
                        NetEvent::Attestation(att) => engine.on_attestation(att, wall_epoch),
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "network channel closed"));
            }
        }
    }
}
