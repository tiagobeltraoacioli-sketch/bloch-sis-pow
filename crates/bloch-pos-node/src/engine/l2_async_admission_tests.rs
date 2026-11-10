// SPDX-License-Identifier: AGPL-3.0-or-later
//! Mempool admission of asynchronous L2 settlements (0x13) on a real engine:
//! the proof verification is metered like every other admission check.
use super::*;
use bloch_pos_committee::l2_settlement::{Policy, Transaction, STATEMENT_TAG};
use verification::L2_PROOF_VERIFICATION_UNITS;

const TEMPLATE: &[u8; 590] = include_bytes!("../../../bloch-l2-proof/tests/fixtures/empty.values");
const S: usize = STATEMENT_TAG.len();
const REFUSED: Refusal = Refusal::Invalid("L2 settlement policy, source, successor or proof failed");

fn field(offset: usize) -> [u8; 32] {
    TEMPLATE[S + offset..S + offset + 32].try_into().unwrap()
}

/// A proposing engine whose genesis carries an asynchronous L2, two blocks
/// in: the second block froze the settlement source, so a settlement can
/// pass every check that precedes the proof.
fn engine_with_frozen_source() -> (Engine, perf_support::TestDir) {
    let (mut node, dir) = perf_support::proposing_engine();
    let genesis = (*node.state.arc()).clone();
    let mut policy = Policy {
        identities: std::array::from_fn(|i| field(i * 32)),
        proof_policy: bloch_l2_proof::policy_commitment(),
        chain_id: 700771,
        initial_l2_parent: field(272),
        initial_l2_state: field(304),
        attestor_set: [0; 32],
    };
    policy.identities[0] = genesis.admission_network_domain().expect("bound genesis");
    policy.identities[1] = *genesis.head().as_bytes();
    node.state.set(genesis.configure_l2_genesis_async(policy).expect("L2 genesis"));
    node.propose(1);
    node.propose(2);
    assert_eq!(node.state.slot(), 2);
    assert!(node.state.l2_settlement().unwrap().frozen_source().is_some());
    (node, dir)
}

/// A settlement that matches the engine's committed policy, source and
/// successor, carrying `proof`.
fn settlement(node: &Engine, proof: [u8; 356]) -> Transaction {
    let l2 = node.state.l2_settlement().unwrap();
    let source = l2.frozen_source().unwrap();
    let mut statement = TEMPLATE.to_vec();
    for (i, id) in l2.policy().identities.iter().enumerate() {
        statement[S + i * 32..S + (i + 1) * 32].copy_from_slice(id);
    }
    for (offset, value) in [(400, source.block), (448, source.commitment), (480, source.inbox_root)] {
        statement[S + offset..S + offset + 32].copy_from_slice(&value);
    }
    statement[S + 432..S + 440].copy_from_slice(&source.slot.to_be_bytes());
    statement[S + 440..S + 448].copy_from_slice(&source.height.to_be_bytes());
    Transaction { proof_policy: l2.policy().proof_policy, statement, proof }
}

fn wire(tx: Transaction) -> PosTransaction {
    PosTransaction::L2SettlementAsync(Box::new(tx))
}

#[test]
fn invalid_proof_spends_allowance_and_the_same_bytes_are_barred() {
    let _clock = validator_lifecycle::clock_at(3);
    let (mut node, _dir) = engine_with_frozen_source();
    let slot = node.wall_slot();
    let source = Some([0xC1; 32]);
    let before = node.gossip_verifier.budget_used_at(slot);

    let tx = wire(settlement(&node, [2; 356]));
    let key = tx.canonical_bytes();
    assert_eq!(node.on_transaction_from(tx.clone(), source), Err(REFUSED));
    assert_eq!(
        node.gossip_verifier.budget_used_at(slot),
        before + L2_PROOF_VERIFICATION_UNITS,
        "the refused proof was charged to the slot allowance",
    );
    assert!(node.rejected.contains_key(&key));

    // The identical bytes are answered from the bar, from any source, at no
    // allowance.
    let barred = Refusal::PreviouslyRefused { until_slot: slot + REJECTION_TTL_SLOTS };
    assert_eq!(node.on_transaction_from(tx.clone(), source), Err(barred));
    assert_eq!(
        node.on_transaction_from(tx, Some([0xC2; 32])),
        Err(Refusal::PreviouslyRefused { until_slot: slot + REJECTION_TTL_SLOTS }),
    );
    assert_eq!(node.gossip_verifier.budget_used_at(slot), before + L2_PROOF_VERIFICATION_UNITS);
    assert_eq!(node.rejected_hits, 2);
    assert!(node.mempool.is_empty());
}

#[test]
fn refusals_that_need_no_proof_spend_no_allowance_and_are_not_barred() {
    let _clock = validator_lifecycle::clock_at(3);
    let (mut node, _dir) = engine_with_frozen_source();
    let slot = node.wall_slot();
    let before = node.gossip_verifier.budget_used_at(slot);
    // Policy, source, successor: each refused before the proof.
    for offset in [S, S + 448, S + 264] {
        let mut changed = settlement(&node, [2; 356]);
        changed.statement[offset] ^= 1;
        let tx = wire(changed);
        let key = tx.canonical_bytes();
        assert_eq!(node.on_transaction_from(tx, Some([0xC3; 32])), Err(REFUSED), "offset {offset}");
        assert!(!node.rejected.contains_key(&key), "a head-dependent refusal is not a bar");
    }
    assert_eq!(node.gossip_verifier.budget_used_at(slot), before);
}

#[test]
fn a_source_that_spent_its_allowance_is_limited_before_the_proof() {
    let _clock = validator_lifecycle::clock_at(3);
    let (mut node, _dir) = engine_with_frozen_source();
    let slot = node.wall_slot();
    let noisy = Some([0xC4; 32]);
    let before = node.gossip_verifier.budget_used_at(slot);
    let per_source = GOSSIP_VERIFICATIONS_PER_SOURCE_PER_SLOT / L2_PROOF_VERIFICATION_UNITS;
    assert!(per_source >= 1, "one source can always have a proof verified");
    for n in 0..per_source {
        let tx = wire(settlement(&node, [n as u8 + 2; 356]));
        assert_eq!(node.on_transaction_from(tx, noisy), Err(REFUSED));
    }
    let spent = before + per_source * L2_PROOF_VERIFICATION_UNITS;
    assert_eq!(node.gossip_verifier.budget_used_at(slot), spent);

    // The next distinct settlement from that source is shed: retryable, no
    // allowance reserved (so no proof verification ran), and not barred.
    let next = wire(settlement(&node, [0xEE; 356]));
    let key = next.canonical_bytes();
    assert_eq!(
        node.on_transaction_from(next.clone(), noisy),
        Err(Refusal::GossipVerificationLimited { until_slot: slot + 1 }),
    );
    assert_eq!(node.gossip_verifier.budget_used_at(slot), spent);
    assert!(!node.rejected.contains_key(&key), "local overload is not a verdict on the transaction");

    // Another source still has its own share for the very same bytes.
    assert_eq!(node.on_transaction_from(next, Some([0xC5; 32])), Err(REFUSED));
    assert_eq!(node.gossip_verifier.budget_used_at(slot), spent + L2_PROOF_VERIFICATION_UNITS);
    assert!(node.rejected.contains_key(&key));
}

/// The engine's verifier is the real Groth16 one and no proof fixture binds
/// this test chain, so the accepting path is driven through the same two
/// pieces admission composes: the committed L2 state's preflight and the
/// budgeted verifier, here over a proof double.
#[test]
fn a_valid_settlement_passes_the_metered_preflight() {
    struct ProofDouble;
    impl SignatureVerifier for ProofDouble {
        fn verify_with_key(&self, _: &[u8], _: &[u8; 32], _: &[u8]) -> bool { false }
        fn verify_l2_settlement(&self, _: &[u8; 32], _: &[u8; 32], _: &[u8], proof: &[u8]) -> bool {
            proof == [1; 356]
        }
    }
    let _clock = validator_lifecycle::clock_at(3);
    let (node, _dir) = engine_with_frozen_source();
    let l2 = node.state.l2_settlement().unwrap();
    let before = l2.clone();
    let gossip = verification::GossipVerifier::new(ProofDouble);
    let budget = |source: [u8; 32]| {
        gossip.budgeted_for_source(
            3,
            GOSSIP_VERIFICATIONS_TOTAL_PER_SLOT,
            Some(source),
            GOSSIP_VERIFICATIONS_PER_SOURCE_PER_SLOT,
        )
    };
    let verifier = budget([0xC6; 32]);
    assert_eq!(l2.validate_async(&settlement(&node, [1; 356]), &verifier), Ok(()));
    assert!(!verifier.limited());
    drop(verifier);
    assert_eq!(gossip.budget_used_at(3), L2_PROOF_VERIFICATION_UNITS);
    assert_eq!(*l2, before, "the preflight leaves the committed L2 state untouched");
}
