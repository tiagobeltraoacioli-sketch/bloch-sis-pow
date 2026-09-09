use crate::params::funded_admission_rehearsal::run;
use crate::transition::funded::{
    ADMISSION_PQ_KEY_BYTES, ADMISSION_PQ_SIGNATURE_MAX, MAX_FUNDING_INPUTS,
};

fn pq_key(tag: u8) -> Vec<u8> {
    let mut pk = vec![tag; ADMISSION_PQ_KEY_BYTES];
    pk[..4].copy_from_slice(&[0xb1, 0x0c, 1, 0]);
    pk
}
fn auth_sign(pk: &[u8], root: &[u8; 32]) -> Vec<u8> {
    let mut sig = vec![0x55; ADMISSION_PQ_SIGNATURE_MAX];
    sig[..4].copy_from_slice(&[0xb1, 0x0c, 1, 0]);
    sig[4..36].copy_from_slice(&toy_sign(pk, root));
    sig
}
struct AuthVerifier;
impl SignatureVerifier for AuthVerifier {
    fn verify_with_key(&self, pk: &[u8], root: &[u8; 32], sig: &[u8]) -> bool {
        // Existing block fixtures use toy_sign; the funded envelope checker
        // independently requires full-length suite-1 authorizations.
        sig == auth_sign(pk, root) || sig == toy_sign(pk, root)
    }
}
fn authorize(tx: &mut FundedDeposit) {
    tx.tx_bytes = tx.reserved_tx_bytes();
    tx.funding_signature = auth_sign(&tx.funding_pubkey, &tx.funding_root());
    tx.proof_of_possession = auth_sign(&tx.validator_pubkey, &tx.possession_root());
}
fn deposit(tag: u8) -> FundedDeposit {
    let mut tx = FundedDeposit {
        network_domain: [0x91; 32],
        valid_until_epoch: 50,
        funding_pubkey: pq_key(0xf1),
        inputs: vec![FundingInput {
            txid: [tag; 32],
            vout: 0,
        }],
        validator_pubkey: pq_key(tag),
        amount_sat: staking::MIN_DEPOSIT_SAT,
        randao_commitment: RandaoChain::generate([tag; 32]).commitment(),
        withdrawal_credentials: [0x81; 32],
        commission_bps: 500,
        change: TransferOutput {
            value: 50_000,
            script_hash: [0x82; 32],
        },
        max_base_fee_millisat_per_gas: 100,
        tip_millisat_per_gas: 5,
        tx_bytes: 0,
        funding_signature: Vec::new(),
        proof_of_possession: Vec::new(),
    };
    authorize(&mut tx);
    tx
}
fn fixture(txs: &[FundedDeposit]) -> (Transition<AuthVerifier>, CommittedState, Vec<RandaoChain>) {
    let opening: Vec<_> = txs
        .iter()
        .map(|tx| crate::state_root::EutxoEntry {
            txid: tx.inputs[0].txid,
            vout: 0,
            value: tx.required_funding_sat().unwrap().try_into().unwrap(),
            script_hash: Sha3_256::digest(&tx.funding_pubkey).into(),
        })
        .collect();
    let (transition, mut state, chains) = setup_with(8, AuthVerifier, &opening);
    state.admission_network_domain = Some([0x91; 32]);
    (transition, state, chains)
}
fn apply(state: &mut CommittedState, tx: &FundedDeposit) -> Result<fee_market::TxCharge, TxReject> {
    state.apply_transaction(
        &PosTransaction::FundedDeposit(tx.clone()),
        sat(1_600_000),
        10,
        &AuthVerifier,
    )
}

#[test]
fn funded_wire_roundtrip_and_witness_independent_identity() {
    let tx = deposit(20);
    let wire = PosTransaction::FundedDeposit(tx.clone());
    assert_eq!(
        PosTransaction::from_canonical_bytes(&wire.canonical_bytes()),
        Ok(wire.clone())
    );
    let mut unsigned = tx.clone();
    unsigned.funding_signature.clear();
    unsigned.proof_of_possession.clear();
    assert_eq!(
        wire.txid(),
        PosTransaction::FundedDeposit(unsigned.clone()).txid()
    );
    assert_eq!(unsigned.funding_root(), tx.funding_root());
    assert_ne!(tx.funding_root(), tx.possession_root());
    assert!(unsigned.verify_authorizations(&AuthVerifier).is_err());
    assert!(PosTransaction::from_canonical_bytes(&unsigned.canonical_bytes()).is_ok());
    for n in 0..wire.canonical_bytes().len() {
        assert!(
            PosTransaction::from_canonical_bytes(&wire.canonical_bytes()[..n]).is_err(),
            "prefix {n}"
        );
    }
    let mut extra = wire.canonical_bytes();
    extra.push(0);
    assert_eq!(
        PosTransaction::from_canonical_bytes(&extra),
        Err(TxDecodeError::TrailingBytes)
    );
}

#[test]
fn funded_decoder_bounds_lengths_before_allocating() {
    let tx = deposit(21);
    let bytes = tx.canonical_bytes();
    for offset in [41usize, 45 + ADMISSION_PQ_KEY_BYTES] {
        let mut attack = bytes.clone();
        attack[offset..offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(PosTransaction::from_canonical_bytes(&attack).is_err());
    }
    let mut tx = tx;
    tx.inputs = (0..=MAX_FUNDING_INPUTS)
        .map(|i| FundingInput {
            txid: [21; 32],
            vout: i as u32,
        })
        .collect();
    authorize(&mut tx);
    assert!(PosTransaction::from_canonical_bytes(&tx.canonical_bytes()).is_err());
}

#[test]
fn funded_gate_is_closed_even_at_maximum_epoch_and_legacy_stays_closed() {
    assert!(!crate::params::funded_validator_admission_active(u64::MAX));
    let tx = deposit(22);
    let (_, mut state, _) = fixture(std::slice::from_ref(&tx));
    let root = state.state_root();
    assert_eq!(
        apply(&mut state, &tx),
        Err(TxReject::FundedDeposit(FundedDepositReject::NotActive))
    );
    assert_eq!(state.state_root(), root);
    run(|| {
        assert!(!CommittedState::unfunded_bonding_active(0));
        assert!(apply(&mut state, &tx).is_ok());
        assert_eq!(
            state.apply_transaction(
                &PosTransaction::Exit { validator: 8 },
                sat(1_600_000),
                10,
                &AuthVerifier
            ),
            Err(TxReject::StakingNotActive)
        );
    });
    assert!(!crate::params::funded_validator_admission_active(0));
}

#[test]
fn funded_apply_conserves_value_refunds_fee_budget_and_rejects_replay() {
    run(|| {
        let tx = deposit(23);
        let (_, mut state, _) = fixture(std::slice::from_ref(&tx));
        let before = state.accounted_supply_sat();
        let charge = apply(&mut state, &tx).unwrap();
        assert!(state.utxo(&[23; 32], 0).is_none());
        let change = state
            .utxo(&PosTransaction::FundedDeposit(tx.clone()).txid(), 0)
            .unwrap();
        assert_eq!(
            u128::from(change.value),
            u128::from(tx.change.value) + tx.charge(100).base_fee_sat - charge.base_fee_sat
        );
        assert_eq!(
            before,
            state.accounted_supply_sat() + charge.base_fee_sat + charge.priority_fee_sat
        );
        assert_eq!(state.validator_record(8).unwrap().staked_sat, tx.amount_sat);
        assert_eq!(
            state.validator_index_by_pubkey(&tx.validator_pubkey),
            Some(8)
        );
        assert_eq!(
            state.validator_record(8).unwrap().activation_epoch,
            u64::MAX
        );
        let root = state.state_root();
        assert!(apply(&mut state, &tx).is_err());
        assert_eq!(root, state.state_root());
    });
}

#[test]
fn funded_rejections_are_atomic_and_both_roles_bind_every_field() {
    run(|| {
        let good = deposit(24);
        let (_, original, _) = fixture(std::slice::from_ref(&good));
        let mutations: &[fn(&mut FundedDeposit)] = &[
            |t| t.network_domain[0] ^= 1,
            |t| t.valid_until_epoch += 1,
            |t| t.funding_pubkey[50] ^= 1,
            |t| t.inputs[0].vout += 1,
            |t| t.validator_pubkey[50] ^= 1,
            |t| t.amount_sat += 1,
            |t| t.randao_commitment[0] ^= 1,
            |t| t.withdrawal_credentials[0] ^= 1,
            |t| t.commission_bps += 1,
            |t| t.change.value += 1,
            |t| t.change.script_hash[0] ^= 1,
            |t| t.max_base_fee_millisat_per_gas += 1,
            |t| t.tip_millisat_per_gas += 1,
            |t| t.tx_bytes += 1,
            |t| t.funding_signature[100] ^= 1,
            |t| t.proof_of_possession[100] ^= 1,
        ];
        for mutate in mutations {
            let mut tx = good.clone();
            mutate(&mut tx);
            assert!(tx.verify_authorizations(&AuthVerifier).is_err());
            let mut state = original.clone();
            let root = state.state_root();
            assert!(apply(&mut state, &tx).is_err());
            assert_eq!(root, state.state_root());
            assert_eq!(
                original.accounted_supply_sat(),
                state.accounted_supply_sat()
            );
        }
        let mut duplicate = good.clone();
        duplicate.inputs.push(duplicate.inputs[0].clone());
        authorize(&mut duplicate);
        let mut state = original.clone();
        assert!(apply(&mut state, &duplicate).is_err());
        let mut expired = original.clone();
        expired.epoch = 51;
        assert_eq!(
            apply(&mut expired, &good),
            Err(TxReject::FundedDeposit(FundedDepositReject::Expired))
        );
        let mut wrong = original.clone();
        wrong.admission_network_domain = None;
        assert_eq!(
            apply(&mut wrong, &good),
            Err(TxReject::FundedDeposit(FundedDepositReject::Network))
        );
        let mut state = original.clone();
        assert_eq!(
            state.apply_transaction(
                &PosTransaction::FundedDeposit(good.clone()),
                sat(1_600_000),
                101,
                &AuthVerifier
            ),
            Err(TxReject::FundedDeposit(FundedDepositReject::FeeCap))
        );
        let mut over = good.clone();
        over.amount_sat = staking::MIN_DEPOSIT_SAT + 1;
        authorize(&mut over);
        assert_eq!(
            apply(&mut state, &over),
            Err(TxReject::FundedDeposit(FundedDepositReject::Stake))
        );
    });
}

#[test]
fn funded_multiblock_replay_activation_churn_and_new_proposer() {
    run(|| {
        let deposits: Vec<_> = (30..35).map(deposit).collect();
        let (transition, mut state, mut chains) = fixture(&deposits);
        let genesis = state.clone();
        let gap = state.supply_gap_sat();
        let txs: Vec<_> = deposits
            .iter()
            .cloned()
            .map(PosTransaction::FundedDeposit)
            .collect();
        let b = build_block(&transition, &state, 1, &[], &txs, &mut chains);
        state = transition.apply_block(&state, &b, &[], &txs).unwrap();
        let charged: u128 = deposits
            .iter()
            .map(|tx| {
                let c = tx.charge(genesis.next_base_fee());
                c.base_fee_sat + c.priority_fee_sat
            })
            .sum();
        let credited: u128 = state.pending_fee_rewards.values().sum();
        assert_eq!(
            gap - state.supply_gap_sat(),
            (charged - credited) as i128,
            "only the existing fee burn, never the new bonds, may change the supply offset"
        );
        assert_eq!(state.validator_count(), 13);
        assert_eq!(state.active_validators().len(), 8);
        assert_eq!(
            state.state_root(),
            transition
                .apply_block(&genesis, &b, &[], &txs)
                .unwrap()
                .state_root()
        );
        for tag in 30..35 {
            chains.push(RandaoChain::generate([tag; 32]));
        }
        let mut replay = genesis;
        replay = transition.apply_block(&replay, &b, &[], &txs).unwrap();
        let mut saw_new = false;
        let mut target_root = [0; 32];
        for slot in 2..=450 {
            let atts = if slot % SLOTS_PER_EPOCH == SLOTS_PER_EPOCH - 1 && state.epoch >= 1 {
                full_epoch_attestations(&state, target_root)
            } else { Vec::new() };
            let b = build_block(&transition, &state, slot, &atts, &[], &mut chains);
            state = transition.apply_block(&state, &b, &atts, &[]).unwrap();
            replay = transition.apply_block(&replay, &b, &atts, &[]).unwrap();
            if slot % SLOTS_PER_EPOCH == 0 { target_root = *state.head.as_bytes(); }
            assert_eq!(
                state.state_root(),
                replay.state_root(),
                "replay diverged at slot {slot}"
            );
            if slot < 8 * SLOTS_PER_EPOCH {
                assert!(b.header.proposer_index < 8);
            }
            if slot == 8 * SLOTS_PER_EPOCH {
                assert_eq!(state.active_validators().len(), 12);
            }
            if slot == 9 * SLOTS_PER_EPOCH {
                assert_eq!(state.active_validators().len(), 13);
            }
            saw_new |= b.header.proposer_index >= 8;
        }
        assert!(saw_new, "a funded, activated key must be able to propose");
        assert!(state.finality().finalized.epoch > 0, "activation requires finalized funding");
        assert!(state.supply_gap_sat() <= gap);
    });
}

#[test]
fn funded_ordering_assigns_indices_by_branch_without_changing_queue_order() {
    run(|| {
        let a = deposit(41);
        let b = deposit(42);
        let (_, original, _) = fixture(&[a.clone(), b.clone()]);
        let mut left = original.clone();
        let mut right = original;
        apply(&mut left, &a).unwrap();
        apply(&mut left, &b).unwrap();
        apply(&mut right, &b).unwrap();
        apply(&mut right, &a).unwrap();
        assert_eq!(left.validator_index_by_pubkey(&a.validator_pubkey), Some(8));
        assert_eq!(
            right.validator_index_by_pubkey(&a.validator_pubkey),
            Some(9)
        );
        assert_eq!(
            staking::resolve_activations(&left.deposit_history, 10),
            staking::resolve_activations(&right.deposit_history, 10)
        );
    });
}

#[test]
fn activation_scheduler_matches_epoch_scan_and_handles_extreme_gaps() {
    fn reference(deposits: &[staking::QueuedDeposit], epoch: u64) -> Vec<([u8; 32], u64)> {
        let mut pending = deposits.to_vec();
        pending.sort_by_key(|d| (d.deposit_epoch, d.pubkey_hash));
        let mut result = Vec::new();
        for e in 0..=epoch {
            let mut count = 0;
            pending.retain(|d| {
                if count < staking::MAX_ACTIVATIONS_PER_EPOCH
                    && d.deposit_epoch
                        .saturating_add(staking::ACTIVATION_DELAY_EPOCHS)
                        <= e
                {
                    result.push((d.pubkey_hash, e));
                    count += 1;
                    false
                } else {
                    true
                }
            });
        }
        result
    }
    for seed in 0..64u64 {
        let queue: Vec<_> = (0..40u64)
            .map(|i| staking::QueuedDeposit {
                pubkey_hash: [i as u8; 32],
                deposit_epoch: (i * 73 + seed * 19) % 61,
                amount_sat: staking::MIN_DEPOSIT_SAT,
            })
            .collect();
        for epoch in [0, 8, 17, 50, 100] {
            assert_eq!(
                staking::resolve_activations(&queue, epoch),
                reference(&queue, epoch)
            );
        }
    }
    let queue: Vec<_> = (0..5)
        .map(|i| staking::QueuedDeposit {
            pubkey_hash: [i; 32],
            deposit_epoch: u64::MAX - 4,
            amount_sat: staking::MIN_DEPOSIT_SAT,
        })
        .collect();
    assert_eq!(staking::resolve_activations(&queue, u64::MAX).len(), 4);
    assert!(staking::resolve_activations(&queue, u64::MAX - 1).is_empty());
}

#[test]
fn funded_multiple_inputs_use_committed_values_and_one_funding_authority() {
    run(|| {
        let mut tx = deposit(51);
        tx.inputs.push(FundingInput {
            txid: [52; 32],
            vout: 0,
        });
        authorize(&mut tx);
        let (_, mut state, _) = fixture(std::slice::from_ref(&tx));
        let first = state.utxo(&[51; 32], 0).unwrap().clone();
        state.eutxos.remove(&([51; 32], 0));
        state.eutxos.insert(crate::state_root::EutxoEntry {
            value: first.value - 20_000,
            ..first.clone()
        });
        state.eutxos.insert(crate::state_root::EutxoEntry {
            txid: [52; 32],
            value: 20_000,
            ..first
        });
        let original = state.clone();
        let root = state.state_root();
        for value in [19_999, 20_001] {
            let mut forged_value = original.clone();
            let second = forged_value.utxo(&[52; 32], 0).unwrap().clone();
            forged_value.eutxos.remove(&([52; 32], 0));
            forged_value
                .eutxos
                .insert(crate::state_root::EutxoEntry { value, ..second });
            assert_eq!(
                apply(&mut forged_value, &tx),
                Err(TxReject::FundedDeposit(FundedDepositReject::Conservation))
            );
        }
        let mut wrong_owner = original.clone();
        let second = wrong_owner.utxo(&[52; 32], 0).unwrap().clone();
        wrong_owner.eutxos.remove(&([52; 32], 0));
        wrong_owner.eutxos.insert(crate::state_root::EutxoEntry {
            script_hash: [0x21; 32],
            ..second
        });
        assert_eq!(
            apply(&mut wrong_owner, &tx),
            Err(TxReject::FundedDeposit(FundedDepositReject::Ownership))
        );
        let mut disorder = tx.clone();
        disorder.inputs.reverse();
        authorize(&mut disorder);
        assert_eq!(
            apply(&mut state, &disorder),
            Err(TxReject::FundedDeposit(FundedDepositReject::Shape))
        );
        assert_eq!(state.state_root(), root);
        let charged = apply(&mut state, &tx).unwrap();
        assert!(state.utxo(&[51; 32], 0).is_none() && state.utxo(&[52; 32], 0).is_none());
        assert_eq!(
            original.accounted_supply_sat(),
            state.accounted_supply_sat() + charged.base_fee_sat + charged.priority_fee_sat
        );
        let mut full = original;
        let rec = full.validators[&0].clone();
        full.validators.insert(u32::MAX, rec);
        assert_eq!(
            apply(&mut full, &tx),
            Err(TxReject::FundedDeposit(FundedDepositReject::RegistryFull))
        );
    });
}

#[test]
fn unfinalized_funding_never_activates_even_after_the_delay() {
    crate::params::funded_admission_rehearsal::run(|| {
        let tx = deposit(47);
        let (t, mut state, _) = fixture(std::slice::from_ref(&tx));
        apply(&mut state, &tx).unwrap();
        for _ in 0..20 { state = t.process_epoch(&state).unwrap(); }
        assert_eq!(state.finality().finalized.epoch, 0);
        assert_eq!(state.validator_record(8).unwrap().activation_epoch, u64::MAX);
        assert_eq!(state.active_validators().len(), 8);
    });
}

#[test]
fn finality_recovery_activates_without_backdating_or_bypassing_churn() {
    run(|| {
        let deposits: Vec<_> = (50..55).map(deposit).collect();
        let (t, mut state, mut chains) = fixture(&deposits);
        for tx in &deposits { apply(&mut state, tx).unwrap(); }
        for _ in 0..20 { state = t.process_epoch(&state).unwrap(); }
        assert!(state.validators.values().filter(|v| v.index >= 8)
            .all(|v| v.activation_epoch == u64::MAX));
        for tag in 50..55 { chains.push(RandaoChain::generate([tag; 32])); }
        let mut target = [0; 32];
        for slot in (20 * SLOTS_PER_EPOCH)..=(23 * SLOTS_PER_EPOCH) {
            let atts = if slot % SLOTS_PER_EPOCH == SLOTS_PER_EPOCH - 1 {
                full_epoch_attestations(&state, target)
            } else { Vec::new() };
            let b = build_block(&t, &state, slot, &atts, &[], &mut chains);
            state = t.apply_block(&state, &b, &atts, &[]).unwrap();
            if slot % SLOTS_PER_EPOCH == 0 { target = *state.head.as_bytes(); }
        }
        let epochs: Vec<_> = state.validators.values().filter(|v| v.index >= 8)
            .map(|v| v.activation_epoch).collect();
        assert_eq!(epochs.iter().filter(|e| **e == 22).count(), 4);
        assert_eq!(epochs.iter().filter(|e| **e == 23).count(), 1);
        assert!(state.finality().finalized.epoch >= 20);
    });
}
