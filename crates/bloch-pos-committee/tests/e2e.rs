// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-to-end devnet-in-a-test: N validators producing and finalizing real
//! blocks over several epochs, with block production feeding the state
//! transition.
//!
//! ## Why this file exists
//!
//! The one property no synthetic-block test can pin: **a block assembled by
//! the producer must pass the state transition on the SAME state.** On
//! 2026-08-09 at h28080 the live mainnet stalled for 50 minutes because the
//! producer stamped a value into its own block that the validator path of the
//! very same node then rejected — producer and validator disagreeing inside
//! one process. A test that only validates hand-built blocks never exercises
//! that seam; this file makes `produce → transition` on shared state the
//! central assertion, executed at every slot of every scenario.
//!
//! ## Wiring status (read before touching)
//!
//! DEV-1's `transition.rs` (the crate's `StateTransition` implementation) and
//! DEV-2's `produce.rs` (block production) have **not landed yet**. Until
//! they do, this file runs against the frozen Phase-1 traits in
//! `interfaces.rs` through a reference harness built ONLY from the crate's
//! shipped primitives (`schedule`, `sample`, `beacon`, `finality`,
//! `state_root`, `attestation`). The two swap points are marked:
//!
//! - `SWAP POINT (DEV-1)`: replace `harness::RefTransition` (and its
//!   `NodeState`) with the real `StateTransition` implementor.
//! - `SWAP POINT (DEV-2)`: replace `harness::produce` with the real
//!   production entry point.
//!
//! The scenario assertions are written against `StateReader` /
//! `StateTransition` and against on-chain facts (headers, roots, finality),
//! so they survive the swap unchanged.
//!
//! ## Determinism contract
//!
//! No clock, no threads, no RNG. Every "random" value derives from fixed
//! byte-string seeds through SHA3/SHAKE, so a failure replays bit-identically
//! forever. A consensus test that depends on timing cannot reproduce the
//! failures that matter — the 2026-08-08 `expected_bits` split and the
//! h28080 producer/validator split were both order/state bugs, not races.

use bloch_pos_committee::interfaces::{
    ProposalReject, StateReader, StateTransition, TransitionError,
};
use bloch_pos_committee::schedule::last_slot_of_epoch;
use bloch_pos_committee::{
    epoch_committee, epoch_of, epoch_schedule, mix_in, slot_subcommittee, SLOTS_PER_EPOCH,
};
use std::collections::BTreeSet;
use std::sync::OnceLock;

mod harness {
    //! The reference devnet: an in-memory chain of one logical network, run
    //! with zero I/O. Everything consensus-relevant is a pure function of the
    //! genesis constants and the block sequence — the §5.5 rule the whole
    //! migration is shaped by.

    use bloch_pos_committee::attestation::{validate as validate_attestation, SignatureVerifier};
    use bloch_pos_committee::finality::{Checkpoint as FCheckpoint, FinalityState as FinState};
    use bloch_pos_committee::interfaces::{
        BlockHeaderV4, BlockId, Checkpoint as ICheckpoint, FinalityState as IFinalityState,
        KeyVerifier, ProposalEnvelope, ProposalReject, StateReader, StateTransition,
        TransitionError, ValidatorRecord as IValidatorRecord,
    };
    use bloch_pos_committee::params::{DS_BLOCK, DS_PROPOSE};
    use bloch_pos_committee::schedule::{first_slot_of_epoch, last_slot_of_epoch};
    use bloch_pos_committee::state_root::{
    CheckpointRecord, ConsensusState, EutxoEntry, EvmCommitment, FinalityRecord, LeakRecord, ParticipationRecord, PendingVoteRecord, RandaoMix, ValidatorRecord as SrValidatorRecord, state_root as compute_state_root,
    };
    use bloch_pos_committee::{
        epoch_committee, epoch_of, is_epoch_boundary, process_reveal, proposer, Attestation,
        AttestationData, EpochVotes, RandaoChain, RevealState, Validator, SLOTS_PER_EPOCH,
    };
    use sha3::{Digest, Sha3_256};
    use std::collections::BTreeMap;

    // ── Fixed devnet parameters (the "seed" of every scenario) ──────────────

    /// Validator count. Below `COMMITTEE_SIZE` (128) on purpose: a young
    /// network where the epoch committee is the whole set, which is exactly
    /// the regime Genesis-4 launches into.
    pub const N_VALIDATORS: u32 = 12;
    /// Genesis-4 block version (§5.3).
    pub const BLOCK_VERSION: u32 = 0xB10C_0005;
    /// Genesis beacon mix — all zeros, like the pre-first-reveal accumulator.
    pub const GENESIS_MIX: [u8; 32] = [0u8; 32];

    /// Foreign component roots carried through every block unchanged (§6.6.2:
    /// carried, never recomputed). Constants here because taint/coherence are
    /// DEV-3/C1 state this harness does not model.
    const TAINT_ROOT: [u8; 32] = [0x11; 32];
    const COHERENCE_ACC_ROOT: [u8; 32] = [0x22; 32];
    const COHERENCE_NUL_ROOT: [u8; 32] = [0x33; 32];
    const EVM_COMMITMENT: EvmCommitment = EvmCommitment {
        account_root: [0x44; 32],
        receipts_root: [0x55; 32],
        gas_used: 0,
        base_fee_per_gas: 1,
    };

    // ── Deterministic crypto stubs ──────────────────────────────────────────
    //
    // The crate never links the PQ stack by design (`SignatureVerifier` /
    // `KeyVerifier` docs): signature verification is an injected capability.
    // The e2e injects deterministic SHA3 stubs — same posture the crate's own
    // unit tests take, and it keeps this file free of the 4.6 KB hybrid while
    // still exercising the "signature checked, and checked last" ordering.

    fn h3(parts: &[&[u8]]) -> [u8; 32] {
        let mut h = Sha3_256::new();
        for p in parts {
            h.update(p);
        }
        h.finalize().into()
    }

    pub fn stub_pubkey(index: u32) -> Vec<u8> {
        h3(&[b"E2E:PUBKEY", &index.to_le_bytes()]).to_vec()
    }

    pub fn stub_key_sign(pubkey: &[u8], signing_root: &[u8; 32]) -> Vec<u8> {
        h3(&[b"E2E:PROPSIG", pubkey, signing_root]).to_vec()
    }

    fn stub_att_sign(validator: u32, signing_root: &[u8; 32]) -> Vec<u8> {
        h3(&[b"E2E:ATTSIG", &validator.to_le_bytes(), signing_root]).to_vec()
    }

    /// The injected proposer-key verifier (frozen `KeyVerifier` boundary).
    pub struct StubKeys;
    impl KeyVerifier for StubKeys {
        fn verify(&self, pubkey: &[u8], signing_root: &[u8; 32], signature: &[u8]) -> bool {
            signature == stub_key_sign(pubkey, signing_root).as_slice()
        }
    }

    /// The injected attestation verifier (frozen `SignatureVerifier` boundary).
    pub struct StubAttSigs;
    impl SignatureVerifier for StubAttSigs {
        fn verify(&self, validator: u32, signing_root: &[u8; 32], signature: &[u8]) -> bool {
            signature == stub_att_sign(validator, signing_root).as_slice()
        }
        /// Mirrors this mock's `verify`: a test double that accepted
        /// spends more easily than attestations would hide the very
        /// forgery the spend path must refuse.
        fn verify_with_key(&self, _pk: &[u8], root: &[u8; 32], sig: &[u8]) -> bool {
            self.verify(0, root, sig)
        }
    }

    // ── Canonical header hashing: DELEGATED to `header.rs` ─────────────────
    //
    // This harness carried its own `header_bytes` / `block_id` /
    // `proposal_signing_root` as a stand-in while `header.rs` was being
    // written. It is gone. A test that derives block identity its OWN way
    // cannot catch a divergence in the way production derives it — it would
    // agree with itself and pass over exactly the bug it exists to find. The
    // third copy of the canonical layout is precisely how the `pow_hash` /
    // `block_hash` split happened on the live chain.

    pub fn block_id(h: &BlockHeaderV4) -> BlockId {
        BlockId::of(h)
    }

    pub fn proposal_signing_root(h: &BlockHeaderV4) -> [u8; 32] {
        h.proposal_signing_root()
    }

    fn body_root_of(tx_ids: &[[u8; 32]]) -> [u8; 32] {
        let mut parts: Vec<&[u8]> = vec![b"E2E:BODY"];
        for t in tx_ids {
            parts.push(t);
        }
        h3(&parts)
    }

    fn attestation_root_of(atts: &[Attestation]) -> [u8; 32] {
        let mut acc = h3(&[b"E2E:ATTROOT"]);
        for a in atts {
            acc = h3(&[&acc, &a.validator.to_le_bytes(), &a.data.signing_root()]);
        }
        acc
    }

    // ── The committed node state (stand-in for DEV-1's state object) ────────

    /// One registry entry. Static for the whole run: this devnet has no
    /// deposits/exits/rewards, so stake never moves — which also means any
    /// state-root divergence the tests catch is a *transition* bug, not a
    /// stake-accounting artifact.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct RegEntry {
        pub index: u32,
        pub stake: u64,
        pub pubkey: Vec<u8>,
    }

    /// The post-state of one block, and the only thing a consensus rule may
    /// read (frozen `StateReader` boundary). Plain owned value: cloning it IS
    /// forking the universe, which is what the delivery-order scenario does.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct NodeState {
        /// Slot of the block whose post-state this is (0 = genesis).
        pub slot: u64,
        /// Head block id.
        pub head: BlockId,
        /// Epoch whose accounting is currently open.
        pub current_epoch: u64,
        /// Running beacon accumulator (moves on every accepted reveal).
        pub mix: [u8; 32],
        /// Beacon mix fixed at each epoch's opening — the value that seeds
        /// that epoch's sortition (§6.3). Pruned to the trailing window.
        pub seed_mixes: BTreeMap<u64, [u8; 32]>,
        /// Per-validator RANDAO chain heads, as committed (§6.3).
        pub reveal_states: BTreeMap<u32, RevealState>,
        /// The validator registry.
        pub registry: Vec<RegEntry>,
        /// Attestation participation, current open epoch.
        pub part_current: BTreeMap<u32, bool>,
        /// Attestation participation, previous epoch.
        pub part_previous: BTreeMap<u32, bool>,
        /// Votes carried by blocks of the open epoch, waiting for the
        /// epoch-boundary tally. Blocks are the only way votes enter state:
        /// `StateTransition::process_epoch` takes no vote argument, so the
        /// tally must read committed inputs — never a node-local vote pool.
        pub pending_votes: Vec<(u32, AttestationData)>,
        /// First block id of each recent epoch — the checkpoint roots.
        pub checkpoints: BTreeMap<u64, BlockId>,
        /// The concrete finality gadget state (pure fold over vote history).
        pub finality: FinState,
        /// Justified checkpoint before the last justification advance —
        /// `StateReader::finality()` needs it (Casper two-round bookkeeping).
        pub prev_justified: FCheckpoint,
    }

    /// Genesis is a block, so its id is derived from its header like any
    /// other's — not invented from a label.
    pub fn genesis_id() -> BlockId {
        BlockId::of(&BlockHeaderV4 {
            version: bloch_pos_committee::header::VERSION_G4,
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
        })
    }

    /// Build the genesis state for `n` validators whose RANDAO commitments
    /// are `commitments[i]`.
    pub fn genesis_state(commitments: &[[u8; 32]]) -> NodeState {
        let registry: Vec<RegEntry> = (0..commitments.len() as u32)
            .map(|i| RegEntry {
                index: i,
                // Uneven stakes (1x/2x/3x) so the sortition's stake weighting
                // is actually load-bearing in every scenario.
                stake: (u64::from(i) % 3 + 1) * 1_000_000_000,
                pubkey: stub_pubkey(i),
            })
            .collect();
        let reveal_states = commitments
            .iter()
            .enumerate()
            .map(|(i, c0)| (i as u32, RevealState::register(*c0)))
            .collect();
        let part: BTreeMap<u32, bool> =
            registry.iter().map(|r| (r.index, false)).collect();
        let g = genesis_id();
        NodeState {
            slot: 0,
            head: g,
            current_epoch: 0,
            mix: GENESIS_MIX,
            seed_mixes: BTreeMap::from([(0u64, GENESIS_MIX)]),
            reveal_states,
            registry,
            part_current: part.clone(),
            part_previous: part,
            pending_votes: Vec::new(),
            checkpoints: BTreeMap::from([(0u64, g)]),
            // Genesis is justified and finalized by definition — finality
            // needs a root of trust to link from.
            finality: FinState::new(FCheckpoint { epoch: 0, root: *g.as_bytes() }),
            prev_justified: FCheckpoint { epoch: 0, root: *g.as_bytes() },
        }
    }

    impl NodeState {
        /// Sampling view of the registry (§4.1-capped effective stakes; no
        /// taint in this devnet, so effective == bonded).
        pub fn active(&self) -> Vec<Validator> {
            self.registry
                .iter()
                .map(|r| Validator { index: r.index, effective_stake: r.stake })
                .collect()
        }
    }

    /// The committed state root, recomputed from components on every call —
    /// deliberately no cache (the §5.5 pattern ban: a stale memoized root is
    /// exactly how `expected_bits` diverged). The block id remains chain
    /// topology, not a state component (it cannot be: it is the id of the
    /// header that carries this root) — but since the 2026-08-11 §5.5
    /// extension the finality bookkeeping, the pending boundary votes and the
    /// per-validator RANDAO chain positions ARE components, and this harness
    /// commits its real ones, so the convergence scenarios below exercise
    /// them.
    pub fn root_of(s: &NodeState) -> [u8; 32] {
        let eutxos: Vec<EutxoEntry> = (0..4u8)
            .map(|i| EutxoEntry {
                txid: h3(&[b"E2E:UTXO", &[i]]),
                vout: u32::from(i),
                value: 1_000 + u64::from(i),
                script_hash: h3(&[b"E2E:SCRIPT", &[i]]),
            })
            .collect();
        let validators: Vec<SrValidatorRecord> = s
            .registry
            .iter()
            .map(|r| SrValidatorRecord {
                index: r.index,
                pubkey: r.pubkey.clone(),
                stake: r.stake,
                activation_epoch: 0,
                exit_epoch: u64::MAX,
                slashed: false,
                randao_commitment: s
                    .reveal_states
                    .get(&r.index)
                    .map(|rs| rs.commitment)
                    .unwrap_or([0u8; 32]),
                reveals_used: s
                    .reveal_states
                    .get(&r.index)
                    .map(|rs| rs.reveals_used)
                    .unwrap_or(0),
                withdrawable_epoch: u64::MAX,
                withdrawal_credentials: Vec::new(),
                // This devnet harness has no delegation, so the rate is
                // committed as zero — committed, not omitted.
                commission_bps: 0,
            })
            .collect();
        let cp = |c: FCheckpoint| CheckpointRecord { epoch: c.epoch, root: c.root };
        let finality = FinalityRecord {
            justified: s.finality.justified_checkpoints().map(cp).collect(),
            current_justified: cp(s.finality.current_justified()),
            previous_justified: cp(s.prev_justified),
            finalized: cp(s.finality.finalized()),
            leaked: s
                .finality
                .leaked_stakes()
                .map(|(validator, leaked_sat)| LeakRecord { validator, leaked_sat })
                .collect(),
            next_epoch: s.finality.next_epoch(),
        };
        let pending_votes: Vec<PendingVoteRecord> = s
            .pending_votes
            .iter()
            .map(|(validator, d)| PendingVoteRecord {
                validator: *validator,
                signing_root: d.signing_root(),
                slot: d.slot,
                head: d.head,
                source_epoch: d.source_epoch,
                source_root: d.source_root,
                target_epoch: d.target_epoch,
                target_root: d.target_root,
            })
            .collect();
        let cur: Vec<ParticipationRecord> = s
            .part_current
            .iter()
            .map(|(v, a)| ParticipationRecord { validator_index: *v, attested: *a })
            .collect();
        let prev: Vec<ParticipationRecord> = s
            .part_previous
            .iter()
            .map(|(v, a)| ParticipationRecord { validator_index: *v, attested: *a })
            .collect();
        // Committed beacon history: the last two epoch-boundary seeds plus
        // the running accumulator, keyed as the *provisional* seed of the
        // next epoch (it becomes exactly that at the boundary). Committing
        // the running mix is what makes every block move the state root —
        // and what lets the tests catch a producer whose stamped root lags
        // one reveal behind the validator's.
        let mut mixes: Vec<RandaoMix> = s
            .seed_mixes
            .iter()
            .rev()
            .take(2)
            .map(|(e, m)| RandaoMix { epoch: *e, mix: *m })
            .collect();
        mixes.push(RandaoMix { epoch: s.current_epoch + 1, mix: s.mix });
        compute_state_root(&ConsensusState {
            eutxos: &eutxos,
            validators: &validators,
            current_participation: &cur,
            previous_participation: &prev,
            randao_mixes: &mixes,
            finality: &finality,
            pending_votes: &pending_votes,
            // This devnet harness has no LMD store, no staking transactions
            // and no fee flow, so these components are genuinely empty here —
            // committed as empty, not omitted.
            fc_messages: &[],
            fc_equivocators: &[],
            deposit_queue: &[],
            delegations: &[],
            pending_fees: &[],
            taint_root: TAINT_ROOT,
            coherence_accumulator_root: COHERENCE_ACC_ROOT,
            coherence_nullifier_root: COHERENCE_NUL_ROOT,
            // Pre-activation anchor policy: empty record, no leaf — this
            // harness runs below the flag day, like the live fleet.
            coherence_anchors: bloch_pos_committee::state_root::CoherenceAnchorRecord::default(),
            evm: EVM_COMMITMENT,
            // This devnet harness pays no issuance, so the counter stays at
            // its genesis value for the whole run — committed, not omitted.
            issued_sat: bloch_pos_committee::tokenomics_v4::GENESIS_ISSUED_SAT,
            // This harness shields nothing, so the turnstile counter stays at
            // its genesis zero for the whole run — committed, not omitted.
            shielded_pool_sat: 0,
            applied_evidence: &[],
            slash_window: &[],
            delegator_slash_losses: &[],
            // No transactions in this harness, so the market never moves off
            // its genesis floor — committed at the floor, not omitted.
            base_fee: bloch_pos_committee::BaseFeeRecord {
                base_fee_millisat_per_gas:
                    bloch_pos_committee::MIN_BASE_FEE_MILLISAT_PER_GAS,
                gas_used: 0,
                tx_bytes: 0,
            },
            delegator_fee_rewards: &[],
        })
    }

    // ── Frozen-boundary implementation: StateReader ─────────────────────────

    impl StateReader for NodeState {
        fn slot(&self) -> u64 {
            self.slot
        }
        fn state_root(&self) -> [u8; 32] {
            root_of(self)
        }
        fn active_validators(&self) -> Vec<Validator> {
            self.active()
        }
        fn validator_record(&self, index: u32) -> Option<IValidatorRecord> {
            let r = self.registry.get(index as usize)?;
            Some(IValidatorRecord {
                index: r.index,
                pubkey: r.pubkey.clone(),
                staked_sat: u128::from(r.stake),
                randao_commitment: self.reveal_states.get(&r.index)?.commitment,
                withdrawal_credentials: Vec::new(),
                activation_epoch: 0,
                exit_epoch: u64::MAX,
                withdrawable_epoch: u64::MAX,
                slashed: false,
                commission_bps: 0,
            })
        }
        fn total_active_stake_sat(&self) -> u128 {
            self.registry.iter().map(|r| u128::from(r.stake)).sum()
        }
        fn randao_mix(&self) -> [u8; 32] {
            self.mix
        }
        fn randao_mix_at(&self, epoch: u64) -> Option<[u8; 32]> {
            self.seed_mixes.get(&epoch).copied()
        }
        fn finality(&self) -> IFinalityState {
            let conv = |c: FCheckpoint| ICheckpoint { epoch: c.epoch, root: c.root };
            IFinalityState {
                previous_justified: conv(self.prev_justified),
                justified: conv(self.finality.current_justified()),
                finalized: conv(self.finality.finalized()),
            }
        }
    }

    // ── Frozen-boundary implementation: StateTransition ─────────────────────
    //
    // SWAP POINT (DEV-1): when `transition.rs` lands, its implementor (and
    // its `State`) replaces `RefTransition`/`NodeState` here; every scenario
    // below is written against the trait and survives the swap.

    #[derive(Default)]
    pub struct RefTransition;

    impl StateTransition for RefTransition {
        type State = NodeState;
        type Transaction = ();

        /// Apply one block. Validation order is part of the frozen contract
        /// (error order is consensus-visible): cheap structural checks first,
        /// the hybrid signature after them, and the state root LAST — the
        /// root check is the h28080 seam, and it must judge the fully-built
        /// post-state, not a partially-validated one.
        fn apply_block(
            &self,
            pre: &NodeState,
            envelope: &ProposalEnvelope,
            attestations: &[Attestation],
            _transactions: &[()],
        ) -> Result<NodeState, TransitionError> {
            let h = &envelope.header;
            if h.version != BLOCK_VERSION {
                return Err(TransitionError::Proposal(ProposalReject::WrongVersion));
            }
            if h.slot <= pre.slot {
                return Err(TransitionError::NonMonotonicSlot);
            }
            // Parent linkage is fork-choice's job, not the transition's: the
            // frozen error enum deliberately has no "wrong parent" variant,
            // and the drivers below only apply blocks that extend the head.
            assert_eq!(&h.parent, pre.head.as_bytes(), "driver must only apply blocks extending the head");
            let epoch = epoch_of(h.slot);
            // Epoch accounting is split from block application on purpose
            // (`process_epoch` runs even when the boundary slot is empty);
            // the caller must have caught up before applying.
            assert_eq!(epoch, pre.current_epoch, "caller must process_epoch before applying");

            // 1. Sortition: the proposer must be the validator drawn for the
            //    slot from the PARENT chain's committed seed mix — never from
            //    the applying node's own view of "now" (§5.5).
            let seed = *pre.seed_mixes.get(&epoch).expect("seed mix for the open epoch");
            if Some(h.proposer_index) != proposer(&seed, h.slot, &pre.active()) {
                return Err(TransitionError::Proposal(ProposalReject::NotScheduledProposer));
            }

            // 2. Beacon: the reveal must open the proposer's committed chain
            //    head, and the header's mix must equal the fold — one
            //    function does both so state and mix can never advance
            //    separately (a split waiting to happen otherwise).
            let rs = pre.reveal_states.get(&h.proposer_index).expect("registered proposer");
            let (new_rs, new_mix) = process_reveal(rs, &pre.mix, &h.randao_reveal)
                .map_err(|_| TransitionError::Proposal(ProposalReject::BadRandaoReveal))?;
            if new_mix != h.randao_mix {
                return Err(TransitionError::Proposal(ProposalReject::BadRandaoReveal));
            }

            // 3. Proposer signature, via the injected KeyVerifier boundary.
            //    After the cheap checks (DoS ordering, same as attestation
            //    validation), before anything state-mutating.
            let keys: &dyn KeyVerifier = &StubKeys;
            let pk = &pre.registry[h.proposer_index as usize].pubkey;
            if !keys.verify(pk, &proposal_signing_root(h), &envelope.proposer_sig) {
                return Err(TransitionError::Proposal(ProposalReject::BadSignature));
            }

            // 4. A block may never contradict — let alone un-finalize — the
            //    parent state's finality.
            let j = pre.finality.current_justified();
            let f = pre.finality.finalized();
            if h.justified_root != j.root || h.finalized_root != f.root {
                return Err(TransitionError::FinalityRegression);
            }

            // 5. Attestations: header binding first, then per-vote committee
            //    membership + signature via the crate's own validate().
            if h.attestation_root != attestation_root_of(attestations) {
                // Index 0 stands for "the carried set does not match the
                // header's commitment to it".
                return Err(TransitionError::Attestation(0));
            }
            let committee = if epoch >= 1 {
                epoch_committee(&seed, epoch, &pre.active())
            } else {
                Vec::new()
            };
            for (i, a) in attestations.iter().enumerate() {
                if a.data.target_epoch != epoch {
                    return Err(TransitionError::Attestation(i as u32));
                }
                validate_attestation(a, &committee, h.slot, &StubAttSigs)
                    .map_err(|_| TransitionError::Attestation(i as u32))?;
            }

            // 6. Build the post-state and judge the header's root against it.
            //    LAST, and against the same committed components the producer
            //    must have used — this comparison is the h28080 regression
            //    test in function form.
            let mut post = pre.clone();
            post.slot = h.slot;
            post.mix = new_mix;
            post.reveal_states.insert(h.proposer_index, new_rs);
            post.pending_votes.extend(attestations.iter().map(|a| (a.validator, a.data)));
            if root_of(&post) != h.state_root {
                return Err(TransitionError::StateRootMismatch);
            }

            // Chain topology (not committed under the state root).
            let id = block_id(h);
            post.head = id;
            post.checkpoints.entry(epoch).or_insert(id);
            Ok(post)
        }

        /// Close the open epoch: tally the votes the epoch's blocks carried,
        /// roll participation, freeze the next epoch's seed mix. Runs even
        /// when the boundary slot was empty — a skipped slot must not skip
        /// the epoch's accounting (a withheld proposal would otherwise be a
        /// lever over everyone's finality).
        fn process_epoch(&self, pre: &NodeState) -> Result<NodeState, TransitionError> {
            let e = pre.current_epoch;
            let mut post = pre.clone();

            if e >= 1 {
                // Epoch 0's checkpoint is genesis — justified and finalized
                // by definition, nothing to vote on.
                let seed = *pre.seed_mixes.get(&e).expect("seed mix for the closing epoch");
                let members = epoch_committee(&seed, e, &pre.active());
                let committee: Vec<Validator> = pre
                    .active()
                    .into_iter()
                    .filter(|v| members.binary_search(&v.index).is_ok())
                    .collect();
                post.prev_justified = post.finality.current_justified();
                post.finality
                    .process_epoch(&EpochVotes {
                        epoch: e,
                        active_set: &committee,
                        attestations: &pre.pending_votes,
                    })
                    .expect("epochs are processed densely and in order");
            }

            // Participation roll-over: who voted for this epoch's target
            // becomes "previous"; the new epoch opens all-absent.
            let mut part_e: BTreeMap<u32, bool> =
                pre.registry.iter().map(|r| (r.index, false)).collect();
            for (v, d) in &pre.pending_votes {
                if d.target_epoch == e {
                    part_e.insert(*v, true);
                }
            }
            post.part_previous = part_e;
            post.part_current = pre.registry.iter().map(|r| (r.index, false)).collect();
            post.pending_votes.clear();

            // The running mix, as it stands at the boundary, becomes the seed
            // for the next epoch's sortition (§6.3): the schedule is knowable
            // exactly one epoch ahead, no earlier.
            post.seed_mixes.insert(e + 1, post.mix);
            while post.seed_mixes.len() > 3 {
                post.seed_mixes.pop_first();
            }
            while post.checkpoints.len() > 2 {
                post.checkpoints.pop_first();
            }
            post.current_epoch = e + 1;
            Ok(post)
        }
    }

    // ── Reference block production ──────────────────────────────────────────
    //
    // SWAP POINT (DEV-2): when `produce.rs` lands, this function is replaced
    // by its entry point. The shape to preserve: the producer derives the
    // header's `state_root` by running THE SAME state update the validator
    // path runs, on THE SAME parent state. h28080 happened because those two
    // computations drifted apart inside one node.

    pub fn produce(
        pre: &NodeState,
        slot: u64,
        proposer_index: u32,
        chain: &mut RandaoChain,
        atts: &[Attestation],
    ) -> ProposalEnvelope {
        let reveal = chain.next_reveal().expect("randao chain spent");
        let rs = pre.reveal_states[&proposer_index];
        let (new_rs, new_mix) =
            process_reveal(&rs, &pre.mix, &reveal).expect("own reveal must open own commitment");

        // The producer's post-state: the identical mutation apply_block
        // performs, so the stamped root and the validated root are one
        // computation, not two implementations that must agree by luck.
        let mut post = pre.clone();
        post.slot = slot;
        post.mix = new_mix;
        post.reveal_states.insert(proposer_index, new_rs);
        post.pending_votes.extend(atts.iter().map(|a| (a.validator, a.data)));
        let state_root = root_of(&post);

        let j = pre.finality.current_justified();
        let f = pre.finality.finalized();
        let header = BlockHeaderV4 {
            version: BLOCK_VERSION,
            parent: *pre.head.as_bytes(),
            state_root,
            body_root: body_root_of(&[]),
            slot,
            proposer_index,
            randao_reveal: reveal,
            randao_mix: new_mix,
            justified_root: j.root,
            finalized_root: f.root,
            attestation_root: attestation_root_of(atts),
            coherence_root: COHERENCE_NUL_ROOT,
        };
        let sig = stub_key_sign(
            &pre.registry[proposer_index as usize].pubkey,
            &proposal_signing_root(&header),
        );
        ProposalEnvelope { header, proposer_sig: sig }
    }

    /// A block as it travels: envelope plus the attestations its body carries.
    #[derive(Clone)]
    pub struct BlockPackage {
        pub envelope: ProposalEnvelope,
        pub atts: Vec<Attestation>,
    }

    /// Honest epoch-boundary votes: every committee member (minus the offline
    /// one, if any) votes source = current justified, target = this epoch's
    /// checkpoint. Built by the validator-duty layer (this driver), included
    /// in the boundary block — blocks are the only channel into the tally.
    pub fn epoch_votes(st: &NodeState, e: u64, offline: Option<u32>) -> Vec<Attestation> {
        let Some(target) = st.checkpoints.get(&e) else {
            // A fully empty epoch has no checkpoint to vote for; the gadget
            // simply sees no votes and finality lags one epoch.
            return Vec::new();
        };
        let seed = st.seed_mixes[&e];
        let members = epoch_committee(&seed, e, &st.active());
        let src = st.finality.current_justified();
        let slot = last_slot_of_epoch(e).expect("epoch in range");
        members
            .into_iter()
            .filter(|v| Some(*v) != offline)
            .map(|v| {
                let data = AttestationData {
                    slot,
                    head: *target.as_bytes(),
                    source_epoch: src.epoch,
                    source_root: src.root,
                    target_epoch: e,
                    target_root: *target.as_bytes(),
                };
                Attestation { data, validator: v, signature: stub_att_sign(v, &data.signing_root()) }
            })
            .collect()
    }

    // ── The devnet driver ───────────────────────────────────────────────────

    /// Everything one run produced, for the scenarios to dissect.
    pub struct RunLog {
        pub epochs: u64,
        pub genesis: NodeState,
        pub blocks: Vec<BlockPackage>,
        /// Slots that produced no block, and why they are supposed to exist.
        pub skipped: Vec<u64>,
        /// Full seed-mix history (epoch -> mix), unpruned — the state itself
        /// only keeps the trailing window, but the scenarios need all of it.
        pub seeds: BTreeMap<u64, [u8; 32]>,
        pub state: NodeState,
        /// One (pre-state, produced block) pair captured mid-run for the
        /// negative controls.
        pub sample: Option<(NodeState, BlockPackage)>,
        /// The validator taken down in the offline scenario, if any.
        pub offline_validator: Option<u32>,
    }

    /// Run `epochs` epochs of the devnet. If `offline_epoch` is set, the
    /// validator scheduled to propose that epoch's FIRST slot is offline for
    /// the whole epoch (guaranteeing at least one skipped slot): it neither
    /// proposes nor votes while down.
    ///
    /// THE CENTRAL ASSERTION lives in this loop: every produced block is
    /// applied via `StateTransition::apply_block` to the exact state it was
    /// produced from, and must pass. This is the producer/validator seam that
    /// broke at h28080, exercised at every single slot.
    pub fn run_chain(epochs: u64, offline_epoch: Option<u64>) -> RunLog {
        // Validator-side RANDAO secrets, from fixed seeds: determinism means
        // a failing slot replays identically forever.
        let mut chains: BTreeMap<u32, RandaoChain> = (0..N_VALIDATORS)
            .map(|i| (i, RandaoChain::generate(h3(&[b"E2E:RANDAO-SEED", &i.to_le_bytes()]))))
            .collect();
        let commitments: Vec<[u8; 32]> =
            (0..N_VALIDATORS).map(|i| chains[&i].commitment()).collect();
        let genesis = genesis_state(&commitments);
        let t = RefTransition;

        let mut st = genesis.clone();
        let mut blocks = Vec::new();
        let mut skipped = Vec::new();
        let mut seeds = BTreeMap::from([(0u64, GENESIS_MIX)]);
        let mut sample = None;
        let mut offline_validator: Option<u32> = None;

        let last_slot = epochs * SLOTS_PER_EPOCH - 1;
        for slot in 1..=last_slot {
            // Epoch accounting catches up BEFORE the slot — including across
            // boundary slots that ended up empty.
            while epoch_of(slot) > st.current_epoch {
                st = t.process_epoch(&st).expect("epoch processing");
                seeds.insert(st.current_epoch, st.seed_mixes[&st.current_epoch]);
            }
            let e = epoch_of(slot);
            let seed = st.seed_mixes[&e];

            if offline_epoch == Some(e) && offline_validator.is_none() {
                // Take down whoever the beacon scheduled for the epoch's
                // first slot — chosen by the chain itself, not by the test,
                // so the scenario cannot quietly stop covering the skip path.
                offline_validator =
                    proposer(&seed, first_slot_of_epoch(e).expect("in range"), &st.active());
            }

            let Some(p) = proposer(&seed, slot, &st.active()) else {
                skipped.push(slot);
                continue;
            };
            if offline_epoch == Some(e) && offline_validator == Some(p) {
                // The offline proposer's slot is simply skipped: no block, no
                // reveal, the mix carries over unchanged (the priced RANDAO
                // withholding bias), and nobody waits for anybody.
                skipped.push(slot);
                continue;
            }

            let atts = if is_epoch_boundary(slot) && e >= 1 {
                let off = if offline_epoch == Some(e) { offline_validator } else { None };
                epoch_votes(&st, e, off)
            } else {
                Vec::new()
            };

            let env = produce(&st, slot, p, chains.get_mut(&p).expect("chain"), &atts);
            let pkg = BlockPackage { envelope: env, atts };
            if sample.is_none() && e == 1 {
                sample = Some((st.clone(), pkg.clone()));
            }

            // ← THE central assertion: produce feeds transition, same state.
            st = t
                .apply_block(&st, &pkg.envelope, &pkg.atts, &[])
                .expect("a block assembled by produce MUST pass transition on the same state");
            blocks.push(pkg);
        }
        // Close the final epoch so its votes are tallied.
        while st.current_epoch < epochs {
            st = t.process_epoch(&st).expect("epoch processing");
            seeds.insert(st.current_epoch, st.seed_mixes[&st.current_epoch]);
        }

        RunLog {
            epochs,
            genesis,
            blocks,
            skipped,
            seeds,
            state: st,
            sample,
            offline_validator,
        }
    }

    /// Re-sign a (possibly tampered) header with the stub key of whoever the
    /// header names as proposer. The negative controls use this so each
    /// tampering trips the check under test, not the signature check.
    pub fn resign(env: &mut ProposalEnvelope, pre: &NodeState) {
        let pk = &pre.registry[env.header.proposer_index as usize].pubkey;
        env.proposer_sig = stub_key_sign(pk, &proposal_signing_root(&env.header));
    }

    /// Replay `deliveries` (any order) onto a fresh node: buffer what does
    /// not extend the head yet, apply what does, catch epoch accounting up
    /// lazily. This is a sync-from-peers loop with zero I/O.
    pub fn replay(deliveries: &[BlockPackage], epochs: u64, genesis: &NodeState) -> NodeState {
        let t = RefTransition;
        let mut st = genesis.clone();
        let mut applied = vec![false; deliveries.len()];
        loop {
            let mut progress = false;
            for i in 0..deliveries.len() {
                if applied[i] {
                    continue;
                }
                let b = &deliveries[i];
                if &b.envelope.header.parent != st.head.as_bytes() {
                    continue; // parent not known yet — stays buffered
                }
                while epoch_of(b.envelope.header.slot) > st.current_epoch {
                    st = t.process_epoch(&st).expect("epoch processing");
                }
                st = t
                    .apply_block(&st, &b.envelope, &b.atts, &[])
                    .expect("a block valid on node A must be valid on node B");
                applied[i] = true;
                progress = true;
            }
            if !progress {
                break;
            }
        }
        assert!(applied.iter().all(|&a| a), "every delivered block must eventually apply");
        while st.current_epoch < epochs {
            st = t.process_epoch(&st).expect("epoch processing");
        }
        st
    }
}

use harness::*;

// SWAP POINT (DEV-1): the transition implementation the scenarios run.
#[allow(dead_code)]
type ActiveTransition = harness::RefTransition;

/// The honest baseline run, computed once (deterministic, so sharing it
/// across tests changes nothing except wall time).
fn honest_run() -> &'static RunLog {
    static RUN: OnceLock<RunLog> = OnceLock::new();
    RUN.get_or_init(|| run_chain(6, None))
}

/// THE test this file exists for. A block assembled by `produce` must pass
/// `apply_block` on the SAME state it was produced from — the seam that broke
/// mainnet for 50 minutes at h28080, where the producer stamped a value its
/// own node's validator then rejected. The positive half runs at every slot
/// of every scenario (inside `run_chain`); here it is re-asserted explicitly
/// on a captured pair, plus the negative controls proving the transition
/// actually judges each field (a check that cannot fail is not a check).
#[test]
fn produced_block_passes_transition_on_the_same_state() {
    let log = honest_run();
    let (pre, pkg) = log.sample.as_ref().expect("sample captured in epoch 1");
    let t = ActiveTransition::default();

    // Positive: same block, same state, must apply — and the applied state
    // must commit exactly the root the producer stamped.
    let post = t
        .apply_block(pre, &pkg.envelope, &pkg.atts, &[])
        .expect("produced block must pass transition on the same state");
    assert_eq!(post.state_root(), pkg.envelope.header.state_root);
    assert_eq!(post.head, block_id(&pkg.envelope.header));

    // h28080 regression shape: the producer signs a header whose state_root
    // is not what the transition computes. Properly signed (so the signature
    // check passes) — the root comparison itself must catch it.
    let mut bad = pkg.clone();
    bad.envelope.header.state_root[0] ^= 0x01;
    resign(&mut bad.envelope, pre);
    assert!(matches!(
        t.apply_block(pre, &bad.envelope, &bad.atts, &[]),
        Err(TransitionError::StateRootMismatch)
    ));

    // Same block against a DIFFERENT state (the end-of-run state): the other
    // half of the h28080 lesson — a block is only valid relative to the state
    // it was built on, and the transition must say so, not shrug.
    assert!(matches!(
        t.apply_block(&log.state, &pkg.envelope, &pkg.atts, &[]),
        Err(TransitionError::NonMonotonicSlot)
    ));

    // A proposer the sortition did not draw must be rejected even with a
    // valid signature — schedule is consensus, identity is not enough.
    let mut wrong = pkg.clone();
    wrong.envelope.header.proposer_index =
        (wrong.envelope.header.proposer_index + 1) % N_VALIDATORS;
    resign(&mut wrong.envelope, pre);
    assert!(matches!(
        t.apply_block(pre, &wrong.envelope, &wrong.atts, &[]),
        Err(TransitionError::Proposal(ProposalReject::NotScheduledProposer))
    ));

    // A reveal that does not open the proposer's committed chain head: the
    // beacon is preimage-bound, so this is the grinding door staying shut.
    let mut forged = pkg.clone();
    forged.envelope.header.randao_reveal[7] ^= 0x01;
    resign(&mut forged.envelope, pre);
    assert!(matches!(
        t.apply_block(pre, &forged.envelope, &forged.atts, &[]),
        Err(TransitionError::Proposal(ProposalReject::BadRandaoReveal))
    ));

    // And a header mutated WITHOUT re-signing dies on the signature — the
    // envelope binds the proposer to every header byte.
    let mut unsigned = pkg.clone();
    unsigned.envelope.header.coherence_root[0] ^= 0x01;
    assert!(matches!(
        t.apply_block(pre, &unsigned.envelope, &unsigned.atts, &[]),
        Err(TransitionError::Proposal(ProposalReject::BadSignature))
    ));
}

/// Liveness + safety over time: with all validators honest the chain must
/// advance through 3+ epochs and actually FINALIZE — justification alone is
/// revocable, and a devnet that only justifies would hide a broken
/// consecutive-justification link (the two-round Casper core).
#[test]
fn chain_advances_and_finalizes_across_epochs_with_all_honest() {
    let log = honest_run();
    let epochs = log.epochs;

    // Every slot produced a block: 12 staked validators, nobody offline.
    assert!(log.skipped.is_empty(), "no slot may be skipped with all honest");
    assert_eq!(log.blocks.len() as u64, epochs * SLOTS_PER_EPOCH - 1);
    assert_eq!(log.state.slot, epochs * SLOTS_PER_EPOCH - 1);

    // The chain is linear and each block extends the previous — no forks in
    // a single-producer-per-slot honest run.
    let mut head = harness::genesis_id();
    for b in &log.blocks {
        assert_eq!(&b.envelope.header.parent, head.as_bytes());
        head = block_id(&b.envelope.header);
    }
    assert_eq!(log.state.head, head);

    // Finality marched: epoch E's votes justify E; consecutive justification
    // finalizes E-1. After `epochs` epochs the ceiling is epochs-1 justified
    // / epochs-2 finalized, and honest votes must reach exactly that.
    let fin = StateReader::finality(&log.state);
    assert_eq!(fin.justified.epoch, epochs - 1, "last closed epoch must be justified");
    assert_eq!(fin.finalized.epoch, epochs - 2, "its predecessor must be finalized");
    assert!(fin.finalized.epoch >= 2, "at least 3 epochs advanced and finality followed");
    // The finalized checkpoint is a real block of this chain, not a phantom:
    // it is that epoch's first block.
    assert_eq!(
        &fin.finalized.root,
        block_id(
            &log.blocks
                .iter()
                .find(|b| epoch_of(b.envelope.header.slot) == fin.finalized.epoch)
                .expect("finalized epoch has blocks")
                .envelope
                .header
        )
        .as_bytes()
    );
}

/// An offline proposer must cost exactly its own slots — nothing else. No
/// stall, no waiting, and the beacon mix carries over unchanged across the
/// gap (the priced one-bit withholding bias, not a third outcome). PoW had no
/// such failure mode (someone else just found the block); slot-based PoS
/// makes "the leader is down" a scheduled event, so the skip path is
/// consensus-critical, not an edge case.
#[test]
fn offline_proposer_skips_its_slots_without_stalling_the_chain() {
    let epochs = 6u64;
    let offline_epoch = 2u64;
    let log = run_chain(epochs, Some(offline_epoch));
    let down = log.offline_validator.expect("an offline validator was drawn");

    // At least one slot skipped (the epoch's first slot by construction),
    // every skip inside the offline epoch, and each skipped slot really was
    // scheduled to the offline validator — recomputed from the committed
    // seed, because the schedule is public and any node can check it.
    assert!(!log.skipped.is_empty());
    let vals = log.state.active();
    for &s in &log.skipped {
        assert_eq!(epoch_of(s), offline_epoch, "skips must be confined to the offline epoch");
        let seed = log.seeds[&offline_epoch];
        assert_eq!(
            bloch_pos_committee::proposer(&seed, s, &vals),
            Some(down),
            "slot {s} was skipped but was not the offline validator's"
        );
    }

    // The chain did not stall: blocks exist in the offline epoch and in every
    // epoch after it, and production resumed for the rest of the run.
    for e in 0..epochs {
        assert!(
            log.blocks.iter().any(|b| epoch_of(b.envelope.header.slot) == e),
            "epoch {e} must still contain blocks"
        );
    }
    assert_eq!(
        log.blocks.len() as u64 + log.skipped.len() as u64,
        epochs * SLOTS_PER_EPOCH - 1,
        "every slot is either a block or a recorded skip — no slot vanishes"
    );

    // Beacon continuity across gaps: each block's mix folds the previous
    // BLOCK's mix, so a skipped slot contributed nothing — withholding is a
    // carry-over, never an alternative value.
    let mut prev_mix = harness::GENESIS_MIX;
    for b in &log.blocks {
        assert_eq!(
            b.envelope.header.randao_mix,
            mix_in(&prev_mix, &b.envelope.header.randao_reveal),
            "mix must carry over unchanged across skipped slots"
        );
        prev_mix = b.envelope.header.randao_mix;
    }

    // The offline validator came back: its vote appears in a later epoch's
    // boundary block (it is in every epoch committee of this small set).
    let returned = log.blocks.iter().any(|b| {
        epoch_of(b.envelope.header.slot) > offline_epoch
            && b.atts.iter().any(|a| a.validator == down)
    });
    assert!(returned, "the offline validator must resume voting after its epoch");

    // And finality still completed. Worst case the offline epoch's boundary
    // proposer was the downed validator (votes lost, that epoch unjustified);
    // the gadget then re-justifies from the older source and finality resumes
    // one epoch late — lag, never deadlock.
    let fin = StateReader::finality(&log.state);
    assert!(
        fin.finalized.epoch >= epochs - 3,
        "finality must resume after the offline epoch (got {})",
        fin.finalized.epoch
    );
    assert!(fin.justified.epoch > offline_epoch, "justification must move past the outage");
}

/// The committee draw must rotate with the beacon every epoch, and within any
/// one epoch every validator must hold exactly one seat. A static partition
/// would let a targeted attacker (or a correlated failure) own the same seats
/// forever; a duplicate seat would let one validator vote twice — the
/// malformed-registry bug the sampler's dedup exists for (found 2026-08-11).
#[test]
fn committee_partition_rotates_each_epoch_and_every_validator_serves_exactly_once() {
    let log = honest_run();
    let vals = log.state.active();

    let mut epoch_rosters: Vec<Vec<u32>> = Vec::new();
    let mut subcommittee_partitions: Vec<Vec<Vec<u32>>> = Vec::new();
    let mut covered: BTreeSet<u32> = BTreeSet::new();

    for e in 0..log.epochs {
        let seed = log.seeds[&e];

        // Epoch committee: with N < COMMITTEE_SIZE the whole set serves —
        // and must serve EXACTLY once each. Sorted-distinct is the canonical
        // encoding two nodes cannot disagree on.
        let committee = epoch_committee(&seed, e, &vals);
        assert_eq!(
            committee,
            (0..N_VALIDATORS).collect::<Vec<u32>>(),
            "epoch {e}: every validator must hold exactly one committee seat"
        );

        // Per-slot fork-choice subcommittees: 8 seats out of 12 per slot,
        // each a fresh weighted draw. No duplicate members within a draw.
        let mut slots: Vec<Vec<u32>> = Vec::new();
        for i in 0..SLOTS_PER_EPOCH {
            let slot = e * SLOTS_PER_EPOCH + i;
            let sub = slot_subcommittee(&seed, slot, &vals);
            assert_eq!(sub.len(), 8, "epoch {e} slot {slot}: subcommittee must fill its seats");
            let distinct: BTreeSet<u32> = sub.iter().copied().collect();
            assert_eq!(distinct.len(), sub.len(), "epoch {e} slot {slot}: one seat per validator");
            covered.extend(sub.iter().copied());
            slots.push(sub);
        }
        subcommittee_partitions.push(slots);

        // The proposer roster is knowable from the same seed — one epoch
        // ahead, no further (the exposure window §6.4 accepts).
        let sched = epoch_schedule(&seed, e, &vals).expect("epoch in range");
        epoch_rosters.push(sched.proposers.iter().map(|p| p.expect("staked set")).collect());
    }

    // Rotation: the beacon's evolving mix must actually reshuffle both the
    // slot partition and the proposer roster between epochs. Identical
    // consecutive epochs would mean the reveals stopped reaching the seed —
    // dead randomness, schedulable forever by anyone.
    for e in 0..(log.epochs as usize - 1) {
        assert_ne!(
            subcommittee_partitions[e],
            subcommittee_partitions[e + 1],
            "epochs {e} and {} drew identical slot partitions — the beacon is not rotating",
            e + 1
        );
        assert_ne!(
            epoch_rosters[e],
            epoch_rosters[e + 1],
            "epochs {e} and {} drew identical proposer rosters",
            e + 1
        );
    }

    // Coverage: over the run, the weighted draw must not starve anyone —
    // every validator, including the 1x-stake ones, serves somewhere.
    assert_eq!(
        covered,
        (0..N_VALIDATORS).collect::<BTreeSet<u32>>(),
        "every validator must serve in at least one subcommittee across the run"
    );
}

/// Two nodes applying the same blocks in different DELIVERY orders must end
/// on the bit-identical state root. This is the network-shaped variant of the
/// 2026-08-08 consensus split: `expected_bits` made a node's state a function
/// of its local history rather than of the chain, and byte-identical binaries
/// diverged. Here node B receives blocks shuffled and node C fully reversed;
/// both buffer, apply in the only order the parent links allow, and must land
/// exactly where node A did.
#[test]
fn state_root_converges_across_delivery_orders() {
    let log = honest_run();
    let n = log.blocks.len();

    // Deterministic shuffle: a stride permutation coprime with n visits every
    // index exactly once. No RNG — a failing order must replay forever.
    let stride = [7usize, 11, 13, 17, 19]
        .into_iter()
        .find(|s| gcd(*s, n) == 1)
        .expect("some stride is coprime");
    let shuffled: Vec<_> = (0..n).map(|i| log.blocks[(i * stride + 3) % n].clone()).collect();
    let reversed: Vec<_> = log.blocks.iter().rev().cloned().collect();
    assert_ne!(
        shuffled.first().unwrap().envelope.header.slot,
        log.blocks.first().unwrap().envelope.header.slot,
        "the shuffle must actually change the arrival order"
    );

    let node_b = replay(&shuffled, log.epochs, &log.genesis);
    let node_c = replay(&reversed, log.epochs, &log.genesis);

    // The consensus-visible value first: the committed root, bit-identical.
    assert_eq!(node_b.state_root(), log.state.state_root(), "node B root diverged");
    assert_eq!(node_c.state_root(), log.state.state_root(), "node C root diverged");
    // And the whole state object: same head, same finality, same beacon, same
    // participation — arrival order must leave no residue anywhere.
    assert_eq!(node_b, log.state, "node B state diverged beyond the root");
    assert_eq!(node_c, log.state, "node C state diverged beyond the root");

    // The finality each node reports through the frozen reader is the same
    // finality — what the L2 anchor and sync-from-checkpoint will consume.
    let fa = StateReader::finality(&log.state);
    let fb = StateReader::finality(&node_b);
    assert_eq!(fa.finalized.root, fb.finalized.root);
    assert_eq!(fa.justified.root, fb.justified.root);
}

fn gcd(a: usize, b: usize) -> usize {
    if b == 0 {
        a
    } else {
        gcd(b, a % b)
    }
}
