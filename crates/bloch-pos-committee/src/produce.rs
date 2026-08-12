// SPDX-License-Identifier: AGPL-3.0-or-later

//! Block production under PoS: assemble a [`BlockEnvelope`] for one slot.
//!
//! ## Producer and validator are the same arithmetic
//!
//! Every header field this module stamps comes out of a `pub` function in
//! [`crate::derive`] — the *same* functions [`crate::derive::validate_block`]
//! checks the field against. This is not stylistic reuse: at h28080 this
//! mainnet stood still for 50 minutes because the block producer stamped a
//! value one way while the validation path of the *same node* derived it
//! another way, so the node rejected every block it built. The invariant this
//! file maintains is therefore structural: `produce` contains **no derivation
//! logic of its own** — it sequences calls into `transition` and refuses early
//! when the answer is "this block would be rejected". If you find yourself
//! adding a computation here instead of calling (or adding) one in
//! `transition`, you are re-creating h28080.
//!
//! ## Refusal over doomed assembly
//!
//! A producer that is not the scheduled proposer, or whose RANDAO chain does
//! not open the committed head, could still assemble a syntactically perfect
//! envelope — one that every honest node (including its own) will reject,
//! after the producer has burned a reveal and signed a header. `produce`
//! refuses instead: all fallible checks run **before** anything is consumed
//! or signed.
//!
//! ## The reveal is single-use — by construction, not by convention
//!
//! Revealing the same chain preimage under two different headers for one slot
//! *is* proposer equivocation (two signed headers, same slot — slashable,
//! §7.3), and the accidental path to it is exactly "call produce twice for
//! the same slot". [`ProducerRandao`] therefore enforces at the type level
//! that one reveal leaves the producer per slot, ever: consumption is
//! recorded at the moment a header becomes buildable, and any later request
//! for the same (or an earlier) slot is refused, even across restarts of the
//! surrounding logic as long as the tracker lives. Re-producing after a crash
//! needs a fresh tracker on purpose — that is the moment an operator must
//! decide whether a signed header may already exist.
//!
//! ## Signing is injected
//!
//! The hybrid ML-DSA-65 ‖ Falcon-1024 stack is C via FFI (PQClean); linking
//! it would drag native code into every test run and violate this crate's
//! standalone posture. Like [`crate::attestation::SignatureVerifier`], the
//! signature is produced through the [`ProposerSigner`] trait and never
//! inspected here.

use crate::attestation::{Attestation, SignatureVerifier};
use crate::beacon::{BeaconError, RandaoChain};
use crate::header::{BlockEnvelope, BlockHeaderV4, Body, VERSION_G4};
use crate::derive::{self, ParentState, RandaoRejection};

/// Injected block signing, mirror of [`SignatureVerifier`]: the producer
/// hands out a signing root and receives opaque signature bytes. The
/// implementation owns the hybrid secret key; this crate never sees it.
pub trait ProposerSigner {
    /// Sign the proposer signing root
    /// ([`BlockHeaderV4::proposal_signing_root`], `DS_PROPOSE` domain).
    /// Must sign with **both** halves of the hybrid suite (§6.2).
    fn sign(&self, signing_root: &[u8; 32]) -> Vec<u8>;
}

/// Why `produce` refused to build a block. Refusals are cheap and safe;
/// every variant means "the block you asked for would have been rejected (or
/// slashable), so nothing was consumed or signed" — except where noted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProduceError {
    /// `slot` does not advance past the parent — the validator's
    /// `NonMonotonicSlot` refusal, applied before assembly.
    SlotNotAfterParent { slot: u64, parent_slot: u64 },
    /// This validator is not the proposer the parent state schedules for
    /// `slot`. Carries who is, so a mis-configured validator client logs the
    /// disagreement instead of a bare "no".
    NotScheduledProposer { scheduled: Option<u32> },
    /// The parent state has no committed RANDAO chain head for this
    /// validator — it cannot legally reveal anything.
    UnknownRevealState,
    /// The local chain is spent (all `RANDAO_CHAIN_LENGTH` reveals used); a
    /// re-commit transaction must land before this validator proposes again.
    RevealChainSpent,
    /// A reveal was already released for this slot (or a later one). Refused
    /// unconditionally: a second reveal under a second header for the same
    /// slot is proposer equivocation — slashable — and this refusal is the
    /// producer-side fence against reaching it by accident.
    RevealAlreadyUsed { slot: u64, last_used: u64 },
    /// The local chain's next reveal does not open the *committed* head — the
    /// local chain and the chain the network registered have diverged (wrong
    /// seed, missed re-commit, restored stale backup). Nothing was consumed.
    RevealRejected(BeaconError),
}

/// The producer's RANDAO chain with slot-consumption tracking.
///
/// Wraps the raw [`RandaoChain`] so that release of a reveal is tied to a
/// slot, exactly once: [`RandaoChain::next_reveal`] alone would happily hand
/// out a fresh preimage on every call, and two calls for one slot yield two
/// *different* reveals — two different headers for the same slot, i.e.
/// equivocation manufactured out of a retry loop. The tracker makes the
/// second request fail instead.
pub struct ProducerRandao {
    chain: RandaoChain,
    /// Highest slot a reveal has been released for. Monotone: producing for
    /// an older slot after a newer one is also refused, because the chain
    /// position has moved past what that older slot's header would need.
    last_reveal_slot: Option<u64>,
}

impl ProducerRandao {
    /// Wrap a freshly generated (or re-generated from seed) chain.
    pub fn new(chain: RandaoChain) -> Self {
        ProducerRandao { chain, last_reveal_slot: None }
    }

    /// The public commitment `c_0` of the underlying chain — what the
    /// validator's registration (or re-commit) transaction carries.
    pub fn commitment(&self) -> [u8; 32] {
        self.chain.commitment()
    }

    /// The reveal that *would* be used for `slot` — no consumption.
    ///
    /// Enforces the single-use rule at the earliest possible moment, so that
    /// even the read path cannot be used to build two candidate headers for
    /// one slot in parallel.
    fn candidate_for(&self, slot: u64) -> Result<[u8; 32], ProduceError> {
        if let Some(last) = self.last_reveal_slot {
            if slot <= last {
                return Err(ProduceError::RevealAlreadyUsed { slot, last_used: last });
            }
        }
        self.chain.peek_reveal().ok_or(ProduceError::RevealChainSpent)
    }

    /// Point of no return: advance the chain and record `slot` as spent.
    /// Called by [`produce`] only after every check has passed — from here on
    /// a header carrying this reveal exists, so the slot must never yield a
    /// second one.
    fn mark_consumed(&mut self, slot: u64, reveal: &[u8; 32]) {
        let advanced = self.chain.next_reveal();
        // candidate_for peeked this exact value moments ago; a mismatch means
        // the tracker was bypassed and the equivocation fence is broken.
        debug_assert_eq!(advanced.as_ref(), Some(reveal), "reveal consumed out from under produce");
        let _ = advanced;
        self.last_reveal_slot = Some(slot);
    }
}

/// Produce the block for `slot` on top of `parent`, as validator
/// `proposer_index`.
///
/// On success the returned envelope satisfies
/// [`crate::derive::validate_block`] for the same `parent` and `verifier`
/// — that equivalence is pinned by this module's tests, because it is the
/// deliverable: a producer whose own validator refuses its blocks halts the
/// chain (h28080).
///
/// Inputs beyond the parent state:
///
/// - `randao` — this validator's chain, with single-use tracking. Consumed
///   (one reveal) only on success.
/// - `collected_attestations` — whatever gossip delivered. They are
///   *filtered* through the exact inclusion predicate the validator enforces
///   ([`derive::validate_included_attestation`]); an invalid attestation
///   is dropped rather than poisoning the block, the lesson of the dust-tx
///   incident where one bad mempool entry failed every block that carried it.
/// - `transactions` — opaque, already-ordered canonical bytes; this crate
///   commits them and carries them, DEV-1's transition executes them.
/// - `signer` / `verifier` — the injected crypto boundary; see module docs.
#[allow(clippy::too_many_arguments)] // the argument list is the §5.5 contract: everything explicit, nothing ambient
pub fn produce(
    parent: &ParentState<'_>,
    slot: u64,
    proposer_index: u32,
    randao: &mut ProducerRandao,
    collected_attestations: &[Attestation],
    transactions: &[Vec<u8>],
    signer: &dyn ProposerSigner,
    verifier: &dyn SignatureVerifier,
) -> Result<BlockEnvelope, ProduceError> {
    // ── Refusals first: nothing below this block consumes or signs. ──
    //
    // 1. Structure: the same monotonicity rule validate_block enforces.
    if slot <= parent.header.slot {
        return Err(ProduceError::SlotNotAfterParent { slot, parent_slot: parent.header.slot });
    }
    // 2. Schedule: if the parent state does not draw us for this slot, any
    //    block we assembled would be rejected by every node including our
    //    own — refuse instead of manufacturing a doomed (and reveal-burning)
    //    envelope. Same derivation the validator runs: derive::scheduled_proposer.
    let scheduled = derive::scheduled_proposer(parent, slot);
    if scheduled != Some(proposer_index) {
        return Err(ProduceError::NotScheduledProposer { scheduled });
    }
    // 3. The candidate reveal — peeked, not consumed, so refusal paths below
    //    leave the chain position untouched.
    let reveal = randao.candidate_for(slot)?;
    // 4. Verify the reveal against the *committed* head and fold the mix —
    //    through the one shared randao_transition, which pins the previous
    //    mix to the parent header's committed value. If our local chain
    //    diverged from what the network registered, this is where we find
    //    out — before consuming anything.
    let (_advanced_state, new_mix) = derive::randao_transition(parent, proposer_index, &reveal)
        .map_err(|e| match e {
            RandaoRejection::UnknownValidatorChain => ProduceError::UnknownRevealState,
            RandaoRejection::Beacon(b) => ProduceError::RevealRejected(b),
        })?;

    // ── Assembly: every stamped value comes from derive::*. ──
    //
    // Attestations: keep exactly those the validator will accept, judged by
    // the validator's own predicate. Input order is preserved — the caller's
    // collection order is part of the block content the proposer chose.
    let attestations: Vec<Attestation> = collected_attestations
        .iter()
        .filter(|att| {
            derive::validate_included_attestation(parent, slot, att, verifier).is_ok()
        })
        .cloned()
        .collect();

    let (justified_root, finalized_root) = derive::expected_finality(parent);
    let header = BlockHeaderV4 {
        version: VERSION_G4,
        // The parent id through the single §5.4 derivation path — no stored
        // or cached identifier is ever trusted over re-derivation.
        parent: *parent.header.id().as_bytes(),
        state_root: derive::post_state_root(parent, slot, new_mix, &attestations),
        body_root: derive::body_root(transactions),
        slot,
        proposer_index,
        randao_reveal: reveal,
        randao_mix: new_mix,
        justified_root,
        finalized_root,
        attestation_root: derive::attestation_root(&attestations),
        coherence_root: derive::expected_coherence(parent),
    };

    // ── Point of no return: a header now exists for this slot. Record the
    // reveal as spent *before* signing, so even a panicking signer cannot
    // leave the tracker believing the slot is still fresh. ──
    randao.mark_consumed(slot, &reveal);

    let proposer_sig = signer.sign(&header.proposal_signing_root());
    Ok(BlockEnvelope {
        header,
        proposer_sig,
        body: Body { transactions: transactions.to_vec(), attestations },
    })
}

// ────────────────────────────────────────────────────────────────────────────
// Tests — the deliverable's contract: what produce builds, validate accepts.
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::AttestationData;
    use crate::beacon::RevealState;
    use crate::header::BlockId;
    use crate::interfaces::{ProposalReject, TransitionError};
    use crate::state_root::{
        CheckpointRecord, EvmCommitment, FinalityRecord, ParticipationRecord, RandaoMix,
        ValidatorRecord,
    };
    use crate::derive::{validate_block, ChainState};
    use sha3::{Digest, Sha3_256};

    // ── Mock crypto: deterministic stand-in for the injected hybrid suite ──
    //
    // sign/verify agree by construction (both recompute the same digest), so
    // the tests exercise the real signing-root plumbing without linking the
    // PQ stack — the same reason SignatureVerifier exists at all.

    fn mock_sig(validator: u32, signing_root: &[u8; 32]) -> Vec<u8> {
        let mut h = Sha3_256::new();
        h.update(b"mock-hybrid-sig");
        h.update(validator.to_le_bytes());
        h.update(signing_root);
        h.finalize().to_vec()
    }

    struct MockCrypto;
    impl SignatureVerifier for MockCrypto {
        fn verify(&self, validator: u32, signing_root: &[u8; 32], signature: &[u8]) -> bool {
            signature == mock_sig(validator, signing_root).as_slice()
        }
    }

    struct MockSigner(u32);
    impl ProposerSigner for MockSigner {
        fn sign(&self, signing_root: &[u8; 32]) -> Vec<u8> {
            mock_sig(self.0, signing_root)
        }
    }

    // ── Fixture: a 4-validator chain, parent at slot 39 (epoch 1) ──

    /// Block slot under test: 40, i.e. epoch 1 — high enough that the
    /// sortition seed comes from real committed history (epoch 0's entry)
    /// and attestations can carry a monotone source(0) → target(1) vote.
    const SLOT: u64 = 40;
    const PARENT_SLOT: u64 = 39;
    /// Accumulated mix committed at the parent (folded by the child).
    const PARENT_MIX: [u8; 32] = [0xBB; 32];
    /// Epoch-0 closing mix — seeds every epoch-1 draw.
    const SEED_MIX: [u8; 32] = [0xAA; 32];

    fn chain_seed(validator: u32) -> [u8; 32] {
        [validator as u8 + 1; 32]
    }

    fn producer_randao(validator: u32) -> ProducerRandao {
        ProducerRandao::new(RandaoChain::generate(chain_seed(validator)))
    }

    fn fixture() -> (ChainState, BlockHeaderV4, Vec<(u32, RevealState)>) {
        let registry: Vec<ValidatorRecord> = (0..4u32)
            .map(|i| ValidatorRecord {
                index: i,
                pubkey: vec![i as u8; 8],
                stake: 100_000_000_000 * (4 - i as u64), // skewed, nonzero
                activation_epoch: 0,
                exit_epoch: u64::MAX,
                slashed: false,
                // Carried by this seam (see ChainState docs): committed
                // values, advanced by the transition, not here.
                randao_commitment: [i as u8; 32],
                reveals_used: 0,
                withdrawable_epoch: u64::MAX,
                withdrawal_credentials: Vec::new(),
            })
            .collect();
        let genesis_cp = CheckpointRecord { epoch: 0, root: [0u8; 32] };
        let chain = ChainState {
            eutxos: Vec::new(),
            registry,
            current_participation: (0..4u32)
                .map(|i| ParticipationRecord { validator_index: i, attested: false })
                .collect(),
            previous_participation: (0..4u32)
                .map(|i| ParticipationRecord { validator_index: i, attested: true })
                .collect(),
            randao_mixes: vec![
                RandaoMix { epoch: 0, mix: SEED_MIX },
                RandaoMix { epoch: 1, mix: PARENT_MIX },
            ],
            finality: FinalityRecord {
                justified: vec![genesis_cp],
                current_justified: genesis_cp,
                previous_justified: genesis_cp,
                finalized: genesis_cp,
                leaked: Vec::new(),
                next_epoch: 1,
            },
            pending_votes: Vec::new(),
            fc_messages: Vec::new(),
            fc_equivocators: Vec::new(),
            deposit_queue: Vec::new(),
            delegations: Vec::new(),
            pending_fees: Vec::new(),
            taint_root: [0x11; 32],
            coherence_accumulator_root: [0x12; 32],
            coherence_nullifier_root: [0x13; 32],
            applied_evidence: Vec::new(),
            slash_window: Vec::new(),
            delegator_slash_losses: Vec::new(),
            evm: EvmCommitment {
                account_root: [0x14; 32],
                receipts_root: [0x15; 32],
                gas_used: 0,
                base_fee_per_gas: 1,
            },
            issued_sat: crate::tokenomics_v4::GENESIS_ISSUED_SAT,
        };
        let parent_header = BlockHeaderV4 {
            version: VERSION_G4,
            parent: [0x01; 32],
            state_root: [0x02; 32],
            body_root: [0x03; 32],
            slot: PARENT_SLOT,
            proposer_index: 0,
            randao_reveal: [0x04; 32],
            randao_mix: PARENT_MIX,
            justified_root: [0x05; 32],
            finalized_root: [0x06; 32],
            attestation_root: [0x07; 32],
            coherence_root: [0x08; 32],
        };
        // Committed chain heads: each validator registered the commitment of
        // the very chain producer_randao() regenerates from its seed.
        let reveal_states: Vec<(u32, RevealState)> = (0..4u32)
            .map(|i| (i, RevealState::register(RandaoChain::generate(chain_seed(i)).commitment())))
            .collect();
        (chain, parent_header, reveal_states)
    }

    /// Attestations for the parent slot from the full slot subcommittee,
    /// signed by the mock suite — plus helpers to reach the scheduled
    /// proposer.
    fn collected_attestations(parent: &ParentState<'_>) -> Vec<Attestation> {
        let att_slot = PARENT_SLOT;
        let seed = derive::sortition_seed(parent, att_slot).expect("seed committed");
        let active =
            derive::active_validators(&parent.chain.registry, crate::epoch_of(SLOT));
        let committee = crate::slot_subcommittee(&seed, att_slot, &active);
        committee
            .iter()
            .map(|&v| {
                let data = AttestationData {
                    slot: att_slot,
                    head: *parent.header.id().as_bytes(),
                    source_epoch: 0,
                    source_root: parent.header.justified_root,
                    target_epoch: 1,
                    target_root: *parent.header.id().as_bytes(),
                };
                let signature = mock_sig(v, &data.signing_root());
                Attestation { data, validator: v, signature }
            })
            .collect()
    }

    fn txs() -> Vec<Vec<u8>> {
        vec![vec![0xDE, 0xAD], vec![0xBE, 0xEF, 0x01]]
    }

    /// Full happy-path production against a freshly built fixture. Returns
    /// everything needed to validate what came out.
    fn produce_ok() -> (ChainState, BlockHeaderV4, Vec<(u32, RevealState)>, BlockEnvelope, u32) {
        let (chain, pheader, reveals) = fixture();
        let envelope;
        let proposer;
        {
            let parent = ParentState { header: &pheader, chain: &chain, reveal_states: &reveals };
            proposer = derive::scheduled_proposer(&parent, SLOT).expect("stake is nonzero");
            let mut atts = collected_attestations(&parent);
            // One garbage attestation in the gossip haul: wrong signature.
            // The producer must filter it, not carry it into a doomed block.
            let mut bogus = atts[0].clone();
            bogus.signature = vec![0xFF; 8];
            atts.push(bogus);
            envelope = produce(
                &parent,
                SLOT,
                proposer,
                &mut producer_randao(proposer),
                &atts,
                &txs(),
                &MockSigner(proposer),
                &MockCrypto,
            )
            .expect("scheduled proposer with a matching chain must produce");
        }
        (chain, pheader, reveals, envelope, proposer)
    }

    // ── THE test: producer and validator agree ──

    #[test]
    fn produced_block_passes_the_validators_check() {
        let (chain, pheader, reveals, envelope, proposer) = produce_ok();
        let parent = ParentState { header: &pheader, chain: &chain, reveal_states: &reveals };

        // The deliverable: the block the producer assembles is accepted by
        // the transition validator, same parent state, same verifier. This
        // is the h28080 regression test — producer and validator inside one
        // node must be the same arithmetic.
        assert_eq!(validate_block(&parent, &envelope, &MockCrypto), Ok(()));

        // The bogus gossip attestation was filtered, the 4 valid ones kept.
        assert_eq!(envelope.body.attestations.len(), 4);
        // Transactions carried verbatim.
        assert_eq!(envelope.body.transactions, txs());
        // And the header names the validator that built it.
        assert_eq!(envelope.header.proposer_index, proposer);
        assert_eq!(envelope.header.slot, SLOT);
    }

    // ── Refusals ──

    #[test]
    fn refuses_when_not_the_scheduled_proposer() {
        let (chain, pheader, reveals) = fixture();
        let parent = ParentState { header: &pheader, chain: &chain, reveal_states: &reveals };
        let scheduled = derive::scheduled_proposer(&parent, SLOT).unwrap();
        let intruder = (scheduled + 1) % 4;

        let mut randao = producer_randao(intruder);
        let refusal = produce(
            &parent,
            SLOT,
            intruder,
            &mut randao,
            &[],
            &[],
            &MockSigner(intruder),
            &MockCrypto,
        );
        // Refused with the schedule disagreement spelled out — not an
        // assembled block that every node would then reject.
        assert_eq!(refusal.err(), Some(ProduceError::NotScheduledProposer { scheduled: Some(scheduled) }));
        // And the refusal consumed nothing: the intruder's chain is intact.
        assert_eq!(randao.last_reveal_slot, None);
        assert_eq!(randao.chain.remaining(), crate::params::RANDAO_CHAIN_LENGTH);
    }

    #[test]
    fn refuses_an_invalid_reveal_without_consuming_it() {
        let (chain, pheader, reveals) = fixture();
        let parent = ParentState { header: &pheader, chain: &chain, reveal_states: &reveals };
        let proposer = derive::scheduled_proposer(&parent, SLOT).unwrap();

        // A chain regenerated from the WRONG seed: its reveals do not open
        // the commitment the network registered (stale backup / lost seed).
        let mut wrong_chain = ProducerRandao::new(RandaoChain::generate([0x99; 32]));
        let refusal = produce(
            &parent,
            SLOT,
            proposer,
            &mut wrong_chain,
            &[],
            &[],
            &MockSigner(proposer),
            &MockCrypto,
        );
        assert_eq!(
            refusal.err(),
            Some(ProduceError::RevealRejected(BeaconError::InvalidReveal)),
            "a reveal that does not open the committed head must refuse production"
        );
        // Nothing consumed: the chain can still serve once re-synced.
        assert_eq!(wrong_chain.last_reveal_slot, None);
        assert_eq!(wrong_chain.chain.remaining(), crate::params::RANDAO_CHAIN_LENGTH);
    }

    #[test]
    fn refuses_a_spent_chain() {
        let (chain, pheader, reveals) = fixture();
        let parent = ParentState { header: &pheader, chain: &chain, reveal_states: &reveals };
        let proposer = derive::scheduled_proposer(&parent, SLOT).unwrap();

        let mut spent = producer_randao(proposer);
        while spent.chain.next_reveal().is_some() {}
        let refusal = produce(
            &parent,
            SLOT,
            proposer,
            &mut spent,
            &[],
            &[],
            &MockSigner(proposer),
            &MockCrypto,
        );
        assert_eq!(refusal.err(), Some(ProduceError::RevealChainSpent));
    }

    /// The equivocation fence: one reveal per slot, ever. A second produce
    /// call for the same slot — retry loop, double timer, whatever — must
    /// fail rather than release a second (different!) reveal under a second
    /// header, which would be slashable proposer equivocation.
    #[test]
    fn a_second_production_for_the_same_slot_is_refused() {
        let (chain, pheader, reveals) = fixture();
        let parent = ParentState { header: &pheader, chain: &chain, reveal_states: &reveals };
        let proposer = derive::scheduled_proposer(&parent, SLOT).unwrap();
        let mut randao = producer_randao(proposer);

        let first = produce(
            &parent,
            SLOT,
            proposer,
            &mut randao,
            &[],
            &[],
            &MockSigner(proposer),
            &MockCrypto,
        );
        assert!(first.is_ok());

        // Same slot, same everything — refused at the tracker, before any
        // header can come into existence.
        let second = produce(
            &parent,
            SLOT,
            proposer,
            &mut randao,
            &[],
            &[],
            &MockSigner(proposer),
            &MockCrypto,
        );
        assert_eq!(second.err(), Some(ProduceError::RevealAlreadyUsed { slot: SLOT, last_used: SLOT }));

        // The tracker itself also refuses *earlier* slots (a cross-fork
        // replay of an old slot is the other accidental-equivocation path):
        // once a reveal left for slot N, no slot ≤ N can obtain one.
        assert_eq!(
            randao.candidate_for(SLOT - 1),
            Err(ProduceError::RevealAlreadyUsed { slot: SLOT - 1, last_used: SLOT })
        );
        // A later slot remains servable — the fence is per-slot, not a jam.
        assert!(randao.candidate_for(SLOT + 1).is_ok());
    }

    /// Early refusals must not burn the reveal: a slot-structure refusal
    /// followed by a correct call succeeds with the same tracker.
    #[test]
    fn early_refusal_leaves_the_reveal_available() {
        let (chain, pheader, reveals) = fixture();
        let parent = ParentState { header: &pheader, chain: &chain, reveal_states: &reveals };
        let proposer = derive::scheduled_proposer(&parent, SLOT).unwrap();
        let mut randao = producer_randao(proposer);

        // Asking for the parent's own slot: structural refusal, step 1.
        let refusal = produce(
            &parent,
            PARENT_SLOT,
            proposer,
            &mut randao,
            &[],
            &[],
            &MockSigner(proposer),
            &MockCrypto,
        );
        assert_eq!(
            refusal.err(),
            Some(ProduceError::SlotNotAfterParent { slot: PARENT_SLOT, parent_slot: PARENT_SLOT })
        );

        // The same tracker still produces the real slot — nothing was spent.
        let ok = produce(
            &parent,
            SLOT,
            proposer,
            &mut randao,
            &[],
            &[],
            &MockSigner(proposer),
            &MockCrypto,
        );
        assert!(ok.is_ok(), "an early refusal must not have consumed the reveal");
    }

    // ── Determinism ──

    /// Two independently constructed but identical (state, slot) inputs must
    /// yield byte-identical blocks: same header, same id, same signature,
    /// same commitments. Anything less means the producer holds hidden state
    /// — the §5.5 bug class.
    #[test]
    fn same_state_and_slot_produce_the_same_block() {
        let (_, _, _, a, _) = produce_ok();
        let (_, _, _, b, _) = produce_ok();
        assert_eq!(a.header, b.header, "headers must be bit-identical");
        assert_eq!(a.block_id(), b.block_id());
        assert_eq!(a.proposer_sig, b.proposer_sig);
        assert_eq!(a.body.transactions, b.body.transactions);
        assert_eq!(
            derive::attestation_root(&a.body.attestations),
            derive::attestation_root(&b.body.attestations),
        );
    }

    // ── Identity ──

    /// The produced header and the block's identity are the same fact: the
    /// envelope's id is BlockId::of(header) — the single §5.4 derivation —
    /// and the header's parent field is the parent's id through that same
    /// derivation. No second identifier ever enters the pipeline.
    #[test]
    fn produced_header_matches_the_derived_block_id() {
        let (_, pheader, _, envelope, _) = produce_ok();
        assert_eq!(envelope.block_id(), BlockId::of(&envelope.header));
        assert_eq!(envelope.block_id(), envelope.header.id());
        assert_eq!(envelope.header.parent, *pheader.id().as_bytes());
        // The signature covers the DS_PROPOSE root, not the id (§6.1).
        assert_eq!(envelope.signing_root(), envelope.header.proposal_signing_root());
        assert!(MockCrypto.verify(
            envelope.header.proposer_index,
            &envelope.signing_root(),
            &envelope.proposer_sig
        ));
    }

    // ── The agreement is load-bearing: any drift is caught ──

    /// Tamper with each derived header field of a valid produced block and
    /// assert the validator rejects with the matching reason. This is the
    /// negative image of THE test above: it proves validate_block actually
    /// checks every value produce stamps — so if either side ever diverges,
    /// a test fails here rather than a mainnet halting at the next h28080.
    #[test]
    fn any_tampered_field_is_rejected_by_the_validator() {
        let (chain, pheader, reveals, envelope, _) = produce_ok();
        let parent = ParentState { header: &pheader, chain: &chain, reveal_states: &reveals };

        let cases: Vec<(&str, Box<dyn Fn(&mut BlockEnvelope)>, TransitionError)> = vec![
            (
                "parent",
                Box::new(|e| e.header.parent[0] ^= 1),
                TransitionError::WrongParent,
            ),
            (
                "slot regression",
                Box::new(|e| e.header.slot = PARENT_SLOT),
                TransitionError::NonMonotonicSlot,
            ),
            (
                "proposer_index",
                Box::new(|e| e.header.proposer_index ^= 1),
                TransitionError::Proposal(ProposalReject::NotScheduledProposer),
            ),
            (
                "version",
                Box::new(|e| e.header.version = 0xB10C_0004),
                TransitionError::Proposal(ProposalReject::WrongVersion),
            ),
            (
                "randao_reveal",
                Box::new(|e| e.header.randao_reveal[0] ^= 1),
                TransitionError::Proposal(ProposalReject::BadRandaoReveal),
            ),
            (
                "randao_mix",
                Box::new(|e| e.header.randao_mix[0] ^= 1),
                TransitionError::Proposal(ProposalReject::BadRandaoReveal),
            ),
            (
                "attestation_root",
                Box::new(|e| e.header.attestation_root[0] ^= 1),
                TransitionError::AttestationRootMismatch,
            ),
            (
                "body_root",
                Box::new(|e| e.header.body_root[0] ^= 1),
                TransitionError::BodyRootMismatch,
            ),
            (
                "justified_root",
                Box::new(|e| e.header.justified_root[0] ^= 1),
                TransitionError::FinalityRegression,
            ),
            (
                "finalized_root",
                Box::new(|e| e.header.finalized_root[0] ^= 1),
                TransitionError::FinalityRegression,
            ),
            (
                "coherence_root",
                Box::new(|e| e.header.coherence_root[0] ^= 1),
                TransitionError::CoherenceRootMismatch,
            ),
            (
                "state_root",
                Box::new(|e| e.header.state_root[0] ^= 1),
                TransitionError::StateRootMismatch,
            ),
            (
                "proposer_sig",
                Box::new(|e| e.proposer_sig[0] ^= 1),
                TransitionError::Proposal(ProposalReject::BadSignature),
            ),
            (
                "smuggled attestation",
                Box::new(|e| {
                    let mut extra = e.body.attestations[0].clone();
                    extra.signature = vec![0xFF; 8];
                    e.body.attestations.push(extra);
                }),
                TransitionError::Attestation(4),
            ),
        ];

        for (name, tamper, expected) in cases {
            let mut mutated = envelope.clone();
            tamper(&mut mutated);
            assert_eq!(
                validate_block(&parent, &mutated, &MockCrypto),
                Err(expected),
                "tampering `{name}` must be rejected with the matching reason"
            );
        }
    }
}
