// SPDX-License-Identifier: AGPL-3.0-or-later
//! Node-local handling of L2 transactions between the mempool door and the
//! proposal (review EXE-1, EXE-2, EXE-3, V2-1), on a real engine: a pending
//! settlement follows the head, a refused transaction does not cost the block
//! the transactions it displaced, and deposits, DA batches and claims are
//! judged against committed state before they are admitted, selected or
//! allowed to hold an input.
use super::l2_async_admission_tests::{engine_with_frozen_source_funded, settlement, wire};
use super::proposal_revalidation_tests::{funds_of, spend};
use super::*;

const S: usize = bloch_pos_committee::l2_settlement::STATEMENT_TAG.len();

fn pending_settlements(node: &Engine) -> usize {
    node.mempool.values().filter(|tx| matches!(tx, PosTransaction::L2SettlementAsync(_))).count()
}

/// EXE-2: a settlement admitted against an earlier head (here: placed in the
/// pool with a statement that is not the successor of this head) is not the
/// proposer's selection, and is evicted when the next head is adopted, so it
/// no longer refuses newer proofs as "already pending".
#[test]
fn a_pending_settlement_the_head_moved_past_is_not_selected_and_is_evicted() {
    let _clock = validator_lifecycle::clock_at(3);
    let funds = funds_of(2);
    let (mut node, _dir) = engine_with_frozen_source_funded(&funds);
    let transfer = spend(&funds[0], 9_000, 0, node.state.next_base_fee_at(0));
    assert_eq!(node.on_transaction(transfer.clone()), Ok(Admitted::New));

    let mut passed = settlement(&node, [2; 356]);
    passed.statement[S + 264] ^= 1;
    let stale = wire(passed);
    let stale_key = stale.canonical_bytes();
    node.mempool.insert(stale_key.clone(), stale);
    assert_eq!(pending_settlements(&node), 1);

    assert_eq!(node.select_transactions(0), vec![transfer.clone()]);
    node.propose(3);
    assert_eq!(node.state.slot(), 3);
    assert_eq!(node.tx_slot_index.get(&transfer.txid()), Some(&3), "the block carried the transfer");
    assert!(!node.mempool.contains_key(&stale_key), "evicted with the adopted head");
    assert_eq!(pending_settlements(&node), 0);
    assert!(!node.rejected.contains_key(&stale_key), "eviction is retention, never a bar");
}

/// EXE-2 keeps what can still apply: a settlement that matches the head stays
/// pending across the recheck and is the whole selection.
#[test]
fn a_pending_settlement_that_matches_the_head_is_kept_and_selected() {
    let _clock = validator_lifecycle::clock_at(3);
    let (mut node, _dir) = engine_with_frozen_source_funded(&[]);
    let matching = wire(settlement(&node, [2; 356]));
    let key = matching.canonical_bytes();
    node.mempool.insert(key.clone(), matching.clone());
    node.revalidate_lifecycle_mempool();
    assert!(node.mempool.contains_key(&key));
    assert_eq!(node.select_transactions(0), vec![matching]);
}

/// EXE-1 (re-selection): the probe refuses the one transaction that was the
/// whole selection. The proposer drops and bars it, selects again, and the
/// block carries the pending transfer instead of going out empty.
#[test]
fn a_transaction_the_probe_refuses_does_not_cost_the_block_its_transactions() {
    let _clock = validator_lifecycle::clock_at(3);
    let funds = funds_of(2);
    let (mut node, _dir) = engine_with_frozen_source_funded(&funds);
    let transfer = spend(&funds[0], 9_000, 0, node.state.next_base_fee_at(0));
    assert_eq!(node.on_transaction(transfer.clone()), Ok(Admitted::New));
    // Statement matches the head; the proof does not verify (as if it had
    // reached the pool without admission).
    let unproven = wire(settlement(&node, [2; 356]));
    let key = unproven.canonical_bytes();
    node.mempool.insert(key.clone(), unproven.clone());
    assert_eq!(node.select_transactions(0), vec![unproven]);

    node.propose(3);
    assert_eq!(node.state.slot(), 3, "the block was produced");
    assert_eq!(
        node.tx_slot_index.get(&transfer.txid()),
        Some(&3),
        "the transfer displaced by the refused transaction is in the block",
    );
    assert!(!node.mempool.contains_key(&key));
    assert!(node.rejected.contains_key(&key), "the refused transaction is barred");
}

#[cfg(feature = "devnet-l2-user-txs")]
mod funded_l2_transactions {
    use super::*;
    use bloch_pos_committee::l2_settlement::withdrawal::TREE_DEPTH;
    use bloch_pos_committee::state_root::EutxoEntry;
    use bloch_pos_committee::transition::l2_deposit::MIN_L2_DEPOSIT_SAT;
    use bloch_pos_committee::transition::{
        FundingInput, L2DataAvailability, L2Deposit, L2WithdrawClaim, TransferOutput,
    };

    /// The key `funds_of` locks its outputs to.
    const OWNER: u8 = 71;
    const CHAIN: u64 = 700771;
    const ABSENT: ([u8; 32], u32) = ([0xEE; 32], 0);

    fn keypair(seed: u8) -> (Vec<u8>, Vec<u8>) {
        bloch_crypto::crypto::generate_keypair_from_seed(&[seed; 32]).unwrap()
    }
    fn script(pk: &[u8]) -> [u8; 32] {
        Sha3_256::digest(pk).into()
    }
    fn sign(sk: &[u8], root: &[u8; 32]) -> Vec<u8> {
        bloch_crypto::crypto::sign(sk, root).unwrap()
    }
    fn domain(node: &Engine) -> [u8; 32] {
        node.state.admission_network_domain().expect("bound genesis")
    }
    fn fee_of(node: &Engine, tx_bytes: u64) -> u64 {
        let charge = fee_market::charge(
            fee_market::TxClass::Eutxo { inputs: 1 },
            tx_bytes,
            node.state.next_base_fee_at(0),
            0,
        );
        (charge.base_fee_sat + charge.priority_fee_sat).try_into().unwrap()
    }
    fn batch(body: &[u8]) -> Vec<u8> {
        let mut out = 1u32.to_be_bytes().to_vec();
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    /// A deposit of the minimum amount by key `seed` spending `point`. With
    /// `value` it declares its real size and conserves value at the current
    /// base fee; without, it is the review's unpayable shape: the highest
    /// tip and a whole block of declared bytes.
    fn deposit(node: &Engine, seed: u8, point: ([u8; 32], u32), value: Option<u64>, recipient: u8) -> L2Deposit {
        let (pk, sk) = keypair(seed);
        let mut tx = L2Deposit {
            network_domain: domain(node),
            funding_pubkey: pk.clone(),
            inputs: vec![FundingInput { txid: point.0, vout: point.1 }],
            amount_sat: MIN_L2_DEPOSIT_SAT,
            recipient: [recipient; 20],
            change: TransferOutput { value: 0, script_hash: script(&pk) },
            tx_bytes: fee_market::max_block_tx_bytes(0),
            tip_millisat_per_gas: u128::MAX,
            signature: Vec::new(),
        };
        if let Some(value) = value {
            tx.tip_millisat_per_gas = 0;
            tx.tx_bytes = (tx.canonical_bytes().len() + bloch_crypto::crypto::max_signature_len()) as u64;
            tx.change.value = value - MIN_L2_DEPOSIT_SAT - fee_of(node, tx.tx_bytes);
        }
        tx.signature = sign(&sk, &tx.intent_root());
        tx
    }

    fn data_availability(node: &Engine, seed: u8, point: ([u8; 32], u32), value: Option<u64>) -> L2DataAvailability {
        let (pk, sk) = keypair(seed);
        let mut tx = L2DataAvailability {
            network_domain: domain(node),
            funding_pubkey: pk.clone(),
            inputs: vec![FundingInput { txid: point.0, vout: point.1 }],
            l2_chain_id: CHAIN,
            l2_block_number: 1,
            payload: batch(&[seed, 0xc0]),
            change: TransferOutput { value: 0, script_hash: script(&pk) },
            tx_bytes: fee_market::max_block_tx_bytes(0),
            tip_millisat_per_gas: u128::MAX,
            signature: Vec::new(),
        };
        if let Some(value) = value {
            tx.tip_millisat_per_gas = 0;
            tx.tx_bytes = (tx.canonical_bytes().len() + bloch_crypto::crypto::max_signature_len()) as u64;
            tx.change.value = value - fee_of(node, tx.tx_bytes);
        }
        tx.signature = sign(&sk, &tx.intent_root());
        tx
    }

    /// A well-formed claim of a leaf no settlement ever added, funded by
    /// nothing, at the highest tip and a whole block of declared bytes.
    fn unpayable_claim(node: &Engine, seed: u8) -> L2WithdrawClaim {
        let (pk, sk) = keypair(seed);
        let recipient = [0x17; 32];
        let mut tx = L2WithdrawClaim {
            network_domain: domain(node),
            funding_pubkey: pk.clone(),
            inputs: vec![FundingInput { txid: ABSENT.0, vout: ABSENT.1 }],
            l2_chain_id: CHAIN,
            index: 0,
            l1_recipient: recipient,
            sats: MIN_L2_DEPOSIT_SAT,
            siblings: [[0; 32]; TREE_DEPTH],
            release: TransferOutput { value: MIN_L2_DEPOSIT_SAT, script_hash: recipient },
            change: TransferOutput { value: 0, script_hash: script(&pk) },
            tx_bytes: fee_market::max_block_tx_bytes(0),
            tip_millisat_per_gas: u128::MAX,
            attestation: None,
            signature: Vec::new(),
        };
        tx.signature = sign(&sk, &tx.intent_root());
        tx
    }

    fn engine(funds: &[EutxoEntry]) -> (Engine, perf_support::TestDir) {
        let (node, dir) = engine_with_frozen_source_funded(funds);
        let l2 = node.state.l2_settlement().unwrap();
        assert!(l2.deposits_enabled() && l2.user_transactions());
        (node, dir)
    }

    fn refused(outcome: Result<Admitted, Refusal>) -> bool {
        matches!(outcome, Err(Refusal::Invalid(_) | Refusal::StateDependent(_)))
    }

    /// EXE-1: a deposit and a claim signed by a throwaway key, funded by
    /// nothing, at the highest tip and declaring a whole block of bytes, are
    /// refused at the door; and if they are in the pool anyway they are not
    /// selected, so the block still carries the paying transfer.
    #[test]
    fn unpayable_deposits_and_claims_are_refused_and_never_selected() {
        let _clock = validator_lifecycle::clock_at(3);
        let funds = funds_of(2);
        let (mut node, _dir) = engine(&funds);
        let transfer = spend(&funds[0], 9_000, 0, node.state.next_base_fee_at(0));
        assert_eq!(node.on_transaction(transfer.clone()), Ok(Admitted::New));

        let unpayable = [
            PosTransaction::L2Deposit(deposit(&node, 91, ABSENT, None, 0x42)),
            PosTransaction::L2WithdrawClaim(unpayable_claim(&node, 92)),
        ];
        for tx in &unpayable {
            assert!(refused(node.on_transaction_from(tx.clone(), Some([0xD0; 32]))));
        }
        // The same without the absurd price: still nothing backs them.
        let mut modest = deposit(&node, 91, ABSENT, None, 0x43);
        modest.tip_millisat_per_gas = 0;
        modest.tx_bytes = (modest.canonical_bytes().len() + bloch_crypto::crypto::max_signature_len()) as u64;
        modest.signature = sign(&keypair(91).1, &modest.intent_root());
        assert!(matches!(
            node.on_transaction(PosTransaction::L2Deposit(modest)),
            Err(Refusal::StateDependent(_)),
        ));
        assert_eq!(node.mempool.len(), 1);

        for tx in unpayable {
            node.mempool.insert(tx.canonical_bytes(), tx);
        }
        assert_eq!(node.select_transactions(0), vec![transfer.clone()]);
        node.propose(3);
        assert_eq!(node.state.slot(), 3);
        assert_eq!(node.tx_slot_index.get(&transfer.txid()), Some(&3));
    }

    /// EXE-1: five unpayable DA batches at the highest tip do not take the
    /// per-block DA slots from one honest batch.
    #[test]
    fn unpayable_da_batches_do_not_take_the_da_slots() {
        let _clock = validator_lifecycle::clock_at(3);
        let funds = funds_of(2);
        let (mut node, _dir) = engine(&funds);
        let honest = PosTransaction::L2DataAvailability(data_availability(
            &node, OWNER, (funds[0].txid, funds[0].vout), Some(funds[0].value),
        ));
        assert_eq!(node.on_transaction(honest.clone()), Ok(Admitted::New));
        for seed in 101..106 {
            let tx = PosTransaction::L2DataAvailability(data_availability(&node, seed, ABSENT, None));
            assert!(refused(node.on_transaction(tx.clone())));
            node.mempool.insert(tx.canonical_bytes(), tx);
        }
        assert_eq!(node.mempool.len(), 6);
        assert_eq!(node.select_transactions(0), vec![honest.clone()]);
        node.propose(3);
        assert_eq!(node.tx_slot_index.get(&honest.txid()), Some(&3));
        assert_eq!(node.state.l2_settlement().unwrap().data_availability().len(), 1);
    }

    /// V2-1: a deposit by a key that does not own the input it names is
    /// refused before it can reserve that input, and one already in the pool
    /// does not hold the input against its owner. A deposit by the owner is
    /// admitted, holds its input, and is included.
    #[test]
    fn only_the_owner_of_an_input_can_reserve_it_with_an_l2_transaction() {
        let _clock = validator_lifecycle::clock_at(3);
        let funds = funds_of(2);
        let (mut node, _dir) = engine(&funds);
        let fee = node.state.next_base_fee_at(0);
        let point = (funds[0].txid, funds[0].vout);

        // Priced exactly, so ownership is the only thing wrong with it.
        let squatter = PosTransaction::L2Deposit(deposit(&node, 99, point, Some(funds[0].value), 0x42));
        assert_eq!(
            node.on_transaction(squatter.clone()),
            Err(Refusal::Invalid("L2 deposit key does not own its input")),
        );
        assert!(node.mempool.is_empty());
        assert!(!node.mempool.spends_outpoint(&point));

        let squatter_key = squatter.canonical_bytes();
        node.mempool.insert(squatter_key.clone(), squatter);
        let owner_transfer = spend(&funds[0], 9_000, 0, fee);
        assert_eq!(node.on_transaction(owner_transfer.clone()), Ok(Admitted::New));
        assert!(!node.mempool.contains_key(&squatter_key), "the unbacked entry yielded the input");

        let own_point = (funds[1].txid, funds[1].vout);
        let own = PosTransaction::L2Deposit(deposit(&node, OWNER, own_point, Some(funds[1].value), 0x42));
        assert_eq!(node.on_transaction(own.clone()), Ok(Admitted::New));
        assert!(matches!(
            node.on_transaction(spend(&funds[1], 9_000, 0, fee)),
            Err(Refusal::StateDependent(_)),
        ));
        node.propose(3);
        assert_eq!(node.tx_slot_index.get(&own.txid()), Some(&3));
        assert_eq!(node.tx_slot_index.get(&owner_transfer.txid()), Some(&3));
        assert_eq!(node.state.l2_settlement().unwrap().escrow_sat(), u128::from(MIN_L2_DEPOSIT_SAT));
    }

    /// EXE-3: the funding signature of an L2 transaction is verified under
    /// the sender's allowance. Deposits that pass the state preflight but
    /// carry a bad signature are charged to their source, which is shed once
    /// its failure allowance is spent; another source is unaffected.
    #[test]
    fn l2_funding_signatures_draw_on_the_senders_allowance() {
        let _clock = validator_lifecycle::clock_at(3);
        let funds = funds_of(1);
        let (mut node, _dir) = engine(&funds);
        let slot = node.wall_slot();
        let point = (funds[0].txid, funds[0].vout);
        let forged = |node: &Engine, recipient: u8| {
            let mut tx = deposit(node, OWNER, point, Some(funds[0].value), recipient);
            tx.signature[0] ^= 1;
            PosTransaction::L2Deposit(tx)
        };
        let noisy = Some([0xD1; 32]);
        let before = node.gossip_verifier.budget_used_at(slot);
        for i in 0..GOSSIP_VERIFICATION_FAILURES_PER_SOURCE_PER_SLOT {
            assert_eq!(
                node.on_transaction_from(forged(&node, 1 + i as u8), noisy),
                Err(Refusal::Invalid("invalid L2 deposit hybrid PQ authorization")),
            );
        }
        let spent = before + GOSSIP_VERIFICATION_FAILURES_PER_SOURCE_PER_SLOT;
        assert_eq!(node.gossip_verifier.budget_used_at(slot), spent, "one unit per verification");
        for i in 0..4u8 {
            assert_eq!(
                node.on_transaction_from(forged(&node, 0x80 + i), noisy),
                Err(Refusal::GossipVerificationLimited { until_slot: slot + 1 }),
            );
        }
        assert_eq!(node.gossip_verifier.budget_used_at(slot), spent, "no verification ran for a shed source");
        // Another source still has its own allowance, and a valid deposit
        // from it is admitted.
        let valid = PosTransaction::L2Deposit(deposit(&node, OWNER, point, Some(funds[0].value), 0x42));
        assert_eq!(node.on_transaction_from(valid, Some([0xD2; 32])), Ok(Admitted::New));
        assert_eq!(node.gossip_verifier.budget_used_at(slot), spent + 1);
    }
}
