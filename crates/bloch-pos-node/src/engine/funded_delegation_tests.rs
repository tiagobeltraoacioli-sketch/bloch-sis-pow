// SPDX-License-Identifier: AGPL-3.0-or-later
//! Real hybrid authorization and isolated positive-path delegation rehearsal.
//! Every key and balance here belongs to a disposable synthetic genesis.
use super::*;
use crate::keys::Unlock;
use bloch_pos_committee::transition::{
    FundedDelegate, FundedDelegationWithdraw, FundedUndelegate, FundingInput, TransferOutput,
    ValidatorCommissionUpdate,
};

fn fixture() -> (Engine, perf_support::TestDir, Keystore, FundedDelegate) {
    let (mut node, dir) = perf_support::proposing_engine();
    let owner =
        Keystore::generate_with(&dir.0.join("delegator"), 1, &Unlock::PlaintextOptIn).unwrap();
    let mut tx = FundedDelegate {
        network_domain: [0; 32],
        valid_until_epoch: 100,
        funding_pubkey: owner.pubkey.clone(),
        inputs: vec![FundingInput {
            txid: [0; 32],
            vout: 0,
        }],
        validator_pubkey_hash: Sha3_256::digest(&node.keys.as_ref().unwrap().pubkey).into(),
        amount_sat: bloch_pos_committee::delegation::MIN_DELEGATION_SAT,
        change: TransferOutput {
            value: 50_000,
            script_hash: [0x82; 32],
        },
        max_base_fee_millisat_per_gas: 100,
        tip_millisat_per_gas: 0,
        tx_bytes: 0,
        funding_signature: Vec::new(),
    };
    tx.tx_bytes = tx.reserved_tx_bytes();
    node.manifest
        .allocations
        .push(crate::genesis::GenesisAllocation {
            purpose: crate::genesis::alloc_purpose::LIQUIDITY,
            script_hash: Sha3_256::digest(&owner.pubkey).into(),
            amount_sat: tx.required_funding_sat().unwrap(),
            unlock_epoch: 0,
        });
    let opening = node.manifest.opening_balances();
    tx.inputs[0] = FundingInput {
        txid: opening[0].txid,
        vout: opening[0].vout,
    };
    node.state = StateCell::new(node.manifest.genesis_state());
    tx.network_domain = node.state.admission_network_domain().unwrap();
    tx.funding_signature = owner.sign(&tx.signing_root());
    (node, dir, owner, tx)
}

fn commission(node: &Engine, epoch: u64) -> ValidatorCommissionUpdate {
    let mut tx = ValidatorCommissionUpdate {
        network_domain: node.state.admission_network_domain().unwrap(),
        epoch,
        validator: 0,
        commission_bps: 500,
        signature: Vec::new(),
    };
    tx.signature = node.keys.as_ref().unwrap().sign(&tx.signing_root());
    tx
}

fn undelegate(owner: &Keystore, network_domain: [u8; 32], epoch: u64) -> FundedUndelegate {
    let mut tx = FundedUndelegate {
        network_domain,
        epoch,
        delegator_id: 0,
        position: 0,
        funding_pubkey: owner.pubkey.clone(),
        signature: Vec::new(),
    };
    tx.signature = owner.sign(&tx.signing_root());
    tx
}

fn withdrawal(owner: &Keystore, network_domain: [u8; 32], epoch: u64) -> FundedDelegationWithdraw {
    let mut tx = FundedDelegationWithdraw {
        network_domain,
        epoch,
        delegator_id: 0,
        position: 0,
        funding_pubkey: owner.pubkey.clone(),
        destination_script_hash: [0x95; 32],
        max_base_fee_millisat_per_gas: 100,
        signature: Vec::new(),
    };
    tx.signature = owner.sign(&tx.signing_root());
    tx
}

#[test]
fn real_hybrid_delegate_binds_both_algorithms_and_every_spending_field() {
    let (_node, _dir, _owner, tx) = fixture();
    let verifier = HybridVerifier::new();
    tx.verify_authorization(&verifier).unwrap();
    assert_eq!(
        PosTransaction::from_canonical_bytes(&tx.canonical_bytes()),
        Ok(PosTransaction::FundedDelegate(tx.clone()))
    );
    for offset in [14, 4 + 3309 + 10] {
        let mut forged = tx.clone();
        forged.funding_signature[offset] ^= 1;
        assert!(forged.verify_authorization(&verifier).is_err());
    }
    for field in 0..8 {
        let mut forged = tx.clone();
        match field {
            0 => forged.network_domain[0] ^= 1,
            1 => forged.valid_until_epoch += 1,
            2 => forged.inputs[0].vout += 1,
            3 => forged.validator_pubkey_hash[0] ^= 1,
            4 => forged.amount_sat += 1,
            5 => forged.change.script_hash[0] ^= 1,
            6 => forged.change.value += 1,
            7 => forged.max_base_fee_millisat_per_gas += 1,
            _ => unreachable!(),
        }
        assert!(
            forged.verify_authorization(&verifier).is_err(),
            "field {field}"
        );
    }
}

#[test]
fn real_hybrid_exit_and_withdrawal_are_owner_and_role_bound() {
    let (node, _dir, owner, tx) = fixture();
    let verifier = HybridVerifier::new();
    let exit = undelegate(&owner, tx.network_domain, 4);
    let payout = withdrawal(&owner, tx.network_domain, 2054);
    exit.verify_authorization(&verifier).unwrap();
    payout.verify_authorization(&verifier).unwrap();
    for wire in [
        PosTransaction::FundedUndelegate(exit.clone()),
        PosTransaction::FundedDelegationWithdraw(payout.clone()),
    ] {
        assert_eq!(
            PosTransaction::from_canonical_bytes(&wire.canonical_bytes()),
            Ok(wire)
        );
    }
    for offset in [14, 4 + 3309 + 10] {
        let mut forged = exit.clone();
        forged.signature[offset] ^= 1;
        assert!(forged.verify_authorization(&verifier).is_err());
        let mut forged = payout.clone();
        forged.signature[offset] ^= 1;
        assert!(forged.verify_authorization(&verifier).is_err());
    }
    let mut redirected = payout.clone();
    redirected.destination_script_hash[0] ^= 1;
    assert!(redirected.verify_authorization(&verifier).is_err());
    let mut wrong_epoch = exit.clone();
    wrong_epoch.epoch += 1;
    assert!(wrong_epoch.verify_authorization(&verifier).is_err());
    let mut other_position = payout.clone();
    other_position.position += 1;
    assert!(other_position.verify_authorization(&verifier).is_err());
    let mut wrong_role = exit.clone();
    wrong_role.signature = payout.signature;
    assert!(wrong_role.verify_authorization(&verifier).is_err());
    let mut operator = exit.clone();
    operator.signature = node.keys.as_ref().unwrap().sign(&operator.signing_root());
    assert!(
        operator.verify_authorization(&verifier).is_err(),
        "operator cannot withdraw the owner's principal"
    );
}

#[test]
fn real_hybrid_commission_requires_the_validator_and_binds_rate() {
    let (node, _dir, owner, _tx) = fixture();
    let verifier = HybridVerifier::new();
    let tx = commission(&node, 0);
    let key = &node.keys.as_ref().unwrap().pubkey;
    assert!(verifier.verify_with_key(key, &tx.signing_root(), &tx.signature));
    assert_eq!(
        PosTransaction::from_canonical_bytes(&tx.canonical_bytes()),
        Ok(PosTransaction::ValidatorCommissionUpdate(tx.clone()))
    );
    for offset in [14, 4 + 3309 + 10] {
        let mut forged = tx.clone();
        forged.signature[offset] ^= 1;
        assert!(!verifier.verify_with_key(key, &forged.signing_root(), &forged.signature));
    }
    let mut raised = tx.clone();
    raised.commission_bps += 1;
    assert!(!verifier.verify_with_key(key, &raised.signing_root(), &raised.signature));
    assert!(!verifier.verify_with_key(key, &tx.signing_root(), &owner.sign(&tx.signing_root())));
}

#[test]
fn preactivation_node_refuses_all_four_signed_intents_without_state_or_pool_changes() {
    let (mut node, _dir, owner, tx) = fixture();
    let wires = [
        PosTransaction::ValidatorCommissionUpdate(commission(&node, 0)),
        PosTransaction::FundedUndelegate(undelegate(&owner, tx.network_domain, 0)),
        PosTransaction::FundedDelegationWithdraw(withdrawal(&owner, tx.network_domain, 0)),
        PosTransaction::FundedDelegate(tx),
    ];
    let root = node.state.state_root();
    let _clock = validator_lifecycle::clock_at(1);
    for wire in wires {
        for epoch in [0, 4329, 4527] {
            assert!(admissible(&wire, epoch).unwrap_err().contains("not active"));
        }
        assert!(node.on_transaction(wire).is_err());
        assert!(node.mempool.is_empty());
        assert_eq!(node.state.state_root(), root);
    }
}

/// This test is compiled only in a disposable source copy with the funded
/// delegation gate set to epoch zero. All other gates and delays are unchanged.
#[test]
#[ignore = "requires scripts/rehearse-funded-delegation.py isolated compilation"]
fn real_hybrid_funded_delegation_full_lifecycle() {
    assert_eq!(
        bloch_pos_committee::params::FUNDED_DELEGATION_ACTIVATION_EPOCH,
        0
    );
    let (mut node, _dir, owner, tx) = fixture();
    let (mut observer, _observer_dir) = perf_support::proposing_engine();
    observer.keys = None;
    observer.manifest = Manifest::decode(&node.manifest.encode()).unwrap();
    observer.state = StateCell::new(observer.manifest.genesis_state());
    observer.chain = vec![(0, observer.manifest.genesis_id())];
    observer.canonical = BTreeSet::from([*observer.manifest.genesis_id().as_bytes()]);

    fn drive(node: &mut Engine, observer: &mut Engine, slot: u64) {
        let _clock = validator_lifecycle::clock_at(slot);
        node.wall_slot = slot;
        observer.wall_slot = slot;
        node.attest(slot);
        let before = node.head_id();
        node.propose(slot);
        assert_ne!(node.head_id(), before, "validator must produce at {slot}");
        observer.ingest(node.blocks[node.head_id().as_bytes()].clone());
        assert_eq!(node.state.slot(), slot);
        assert_eq!(node.head_id(), observer.head_id());
        assert_eq!(node.state.state_root(), observer.state.state_root());
    }
    {
        let _clock = validator_lifecycle::clock_at(1);
        node.on_transaction(PosTransaction::ValidatorCommissionUpdate(commission(
            &node, 0,
        )))
        .unwrap();
    }
    drive(&mut node, &mut observer, 1);
    assert_eq!(node.state.validator_record(0).unwrap().commission_bps, 500);
    {
        let _clock = validator_lifecycle::clock_at(2);
        node.on_transaction(PosTransaction::FundedDelegate(tx.clone()))
            .unwrap();
    }
    drive(&mut node, &mut observer, 2);
    assert!(node
        .state
        .utxo(&tx.inputs[0].txid, tx.inputs[0].vout)
        .is_none());
    assert!(node
        .state
        .utxo(&PosTransaction::FundedDelegate(tx.clone()).txid(), 0)
        .is_some());
    for slot in 3..=128 {
        drive(&mut node, &mut observer, slot);
    }
    assert!(
        node.state.delegator_issuance_reward_sat(0) > 0,
        "funded owner must receive issuance"
    );
    let exit = undelegate(&owner, tx.network_domain, 4);
    {
        let _clock = validator_lifecycle::clock_at(129);
        node.on_transaction(PosTransaction::FundedUndelegate(exit))
            .unwrap();
    }
    drive(&mut node, &mut observer, 129);
    for slot in 130..=193 {
        drive(&mut node, &mut observer, slot);
    }
    let early = PosTransaction::FundedDelegationWithdraw(withdrawal(&owner, tx.network_domain, 6));
    {
        let _clock = validator_lifecycle::clock_at(194);
        // Mempool policy may reject now or the block selector may discard it;
        // either way consensus must never create this premature payout.
        let _ = node.on_transaction(early.clone());
    }
    drive(&mut node, &mut observer, 194);
    assert!(node.state.utxo(&early.txid(), 0).is_none());
    let maturity = 5
        + bloch_pos_committee::delegation::COOLDOWN_EPOCHS
        + bloch_pos_committee::staking::WITHDRAWAL_DELAY_EPOCHS;
    // Preserve the real withdrawal delay. Advance by one signed block/vote
    // each epoch instead of shortening constants or editing committed state.
    for epoch in 7..=maturity {
        drive(&mut node, &mut observer, epoch * SLOTS_PER_EPOCH);
    }
    let payout = withdrawal(&owner, tx.network_domain, maturity);
    let expected = tx.amount_sat
        + node.state.delegator_fee_reward_sat(0)
        + node.state.delegator_issuance_reward_sat(0)
        - node.state.delegator_slash_loss_sat(0)
        - payout.charge(node.state.next_base_fee()).base_fee_sat;
    let wire = PosTransaction::FundedDelegationWithdraw(payout.clone());
    let slot = maturity * SLOTS_PER_EPOCH + 1;
    {
        let _clock = validator_lifecycle::clock_at(slot);
        node.on_transaction(wire.clone()).unwrap();
    }
    drive(&mut node, &mut observer, slot);
    let paid = node
        .state
        .utxo(&wire.txid(), 0)
        .expect("mature owner-authorized payout");
    assert_eq!(u128::from(paid.value), expected);
    assert_eq!(paid.script_hash, payout.destination_script_hash);
    assert_eq!(node.state.delegator_issuance_reward_sat(0), 0);
    let mut repeated = payout;
    repeated.destination_script_hash[0] ^= 1;
    repeated.signature = owner.sign(&repeated.signing_root());
    let repeated = PosTransaction::FundedDelegationWithdraw(repeated);
    {
        let _clock = validator_lifecycle::clock_at(slot + 1);
        let _ = node.on_transaction(repeated.clone());
    }
    drive(&mut node, &mut observer, slot + 1);
    assert!(
        node.state.utxo(&repeated.txid(), 0).is_none(),
        "principal cannot be paid twice"
    );
    assert_eq!(
        node.replay_to(*node.head_id().as_bytes()).state_root(),
        node.state.state_root()
    );
    assert_eq!(
        observer
            .replay_to(*observer.head_id().as_bytes())
            .state_root(),
        observer.state.state_root()
    );
    println!("full lifecycle passed: commission=500bps, withdrawal_delay={} epochs, final_epoch={maturity}, blocks={}",
        bloch_pos_committee::staking::WITHDRAWAL_DELAY_EPOCHS, node.head_height());
}

/// Fast state-aware RPC/gossip admission checks in the same isolated gate-zero fixture.
#[test]
#[ignore = "requires a disposable funded-delegation gate-zero build"]
fn funded_delegation_admission_refuses_forgery_and_reserves_inputs() {
    assert_eq!(bloch_pos_committee::params::FUNDED_DELEGATION_ACTIVATION_EPOCH, 0);
    let (mut node, _dir, owner, tx) = fixture();
    let _clock = validator_lifecycle::clock_at(1);
    assert_eq!(rpc::funded_delegation_json(&node.state, 0).to_string(), "null");
    let root = node.state.state_root();
    let mut forged = tx.clone();
    forged.funding_signature[14] ^= 1;
    assert!(node.on_transaction(PosTransaction::FundedDelegate(forged)).is_err());
    let mut commission_tx = commission(&node, 0);
    commission_tx.signature = owner.sign(&commission_tx.signing_root());
    assert!(node.on_transaction(PosTransaction::ValidatorCommissionUpdate(commission_tx)).is_err());
    assert!(node.on_transaction(PosTransaction::FundedUndelegate(undelegate(&owner, tx.network_domain, 0))).is_err());
    assert!(node.on_transaction(PosTransaction::FundedDelegationWithdraw(withdrawal(&owner, tx.network_domain, 0))).is_err());
    assert!(node.mempool.is_empty());
    assert_eq!(root, node.state.state_root());
    node.on_transaction(PosTransaction::FundedDelegate(tx.clone())).unwrap();
    let mut conflicting = tx.clone();
    conflicting.change.script_hash[0] ^= 1;
    conflicting.funding_signature = owner.sign(&conflicting.signing_root());
    assert!(node.on_transaction(PosTransaction::FundedDelegate(conflicting)).is_err());
    assert_eq!(node.mempool.len(), 1);
    assert_eq!(root, node.state.state_root());
}
