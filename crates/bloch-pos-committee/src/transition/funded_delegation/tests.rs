use crate::params::funded_delegation_rehearsal;
use crate::transition::funded::{ADMISSION_PQ_KEY_BYTES, ADMISSION_PQ_SIGNATURE_MAX};

fn pq_key(tag: u8) -> Vec<u8> {
    let mut key = vec![tag; ADMISSION_PQ_KEY_BYTES];
    key[..4].copy_from_slice(&[0xb1, 0x0c, 1, 0]);
    key
}

fn auth_sign(key: &[u8], root: &[u8; 32]) -> Vec<u8> {
    let mut signature = vec![0x55; ADMISSION_PQ_SIGNATURE_MAX];
    signature[..4].copy_from_slice(&[0xb1, 0x0c, 1, 0]);
    signature[4..36].copy_from_slice(&toy_sign(key, root));
    signature
}

struct AuthVerifier;

impl SignatureVerifier for AuthVerifier {
    fn verify_with_key(&self, key: &[u8], root: &[u8; 32], signature: &[u8]) -> bool {
        signature == auth_sign(key, root)
    }
}

fn funded_delegate(input: FundingInput) -> FundedDelegate {
    let mut tx = FundedDelegate {
        network_domain: [0x91; 32],
        valid_until_epoch: 50,
        funding_pubkey: pq_key(0xf1),
        inputs: vec![input],
        validator_pubkey_hash: Sha3_256::digest(vec![0; 8]).into(),
        amount_sat: delegation::MIN_DELEGATION_SAT,
        change: TransferOutput {
            value: crate::params::MIN_TRANSFER_OUTPUT_SAT,
            script_hash: [0x82; 32],
        },
        max_base_fee_millisat_per_gas: fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS,
        tip_millisat_per_gas: 0,
        tx_bytes: 0,
        funding_signature: Vec::new(),
    };
    tx.tx_bytes = tx.reserved_tx_bytes();
    tx.funding_signature = auth_sign(&tx.funding_pubkey, &tx.signing_root());
    tx
}

fn fixture() -> (CommittedState, FundedDelegate) {
    let input = FundingInput {
        txid: [0x31; 32],
        vout: 0,
    };
    let tx = funded_delegate(input.clone());
    let opening = crate::state_root::EutxoEntry {
        txid: input.txid,
        vout: input.vout,
        value: tx.required_funding_sat().unwrap().try_into().unwrap(),
        script_hash: Sha3_256::digest(&tx.funding_pubkey).into(),
    };
    let (_, mut state, _) = setup_with(8, AuthVerifier, &[opening]);
    state.admission_network_domain = Some(tx.network_domain);
    (state, tx)
}

fn commission_update(state: &CommittedState, commission_bps: u128) -> ValidatorCommissionUpdate {
    let mut tx = ValidatorCommissionUpdate {
        network_domain: state.admission_network_domain.unwrap(),
        epoch: state.epoch,
        validator: 0,
        commission_bps,
        signature: Vec::new(),
    };
    let key = &state.validators[&0].pubkey;
    tx.signature = auth_sign(key, &tx.signing_root());
    tx
}

#[test]
fn lifecycle_is_inert_without_rehearsal() {
    let (mut state, tx) = fixture();
    let before = state.clone();
    assert_eq!(
        state.apply_funded_delegate(
            &tx,
            fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS,
            &AuthVerifier,
        ),
        Err(FundedDelegationReject::NotActive)
    );
    assert_eq!(state, before);
}

#[test]
fn commission_update_is_inert_and_atomic_without_rehearsal() {
    let (mut state, _) = fixture();
    let tx = commission_update(&state, 500);
    let before = state.clone();
    assert_eq!(
        state.apply_validator_commission_update(&tx, &AuthVerifier),
        Err(FundedDelegationReject::NotActive)
    );
    assert_eq!(state, before);
}

#[test]
fn validator_can_set_five_percent_before_delegation() {
    let _gate = funded_delegation_rehearsal::open();
    let (mut state, _) = fixture();
    state.validators.get_mut(&0).unwrap().commission_bps = 0;
    let before_root = state.state_root();
    let tx = commission_update(&state, 500);
    state
        .apply_validator_commission_update(&tx, &AuthVerifier)
        .unwrap();
    assert_eq!(state.validators[&0].commission_bps, 500);
    assert_ne!(state.state_root(), before_root);

    let mut forged = commission_update(&state, 400);
    forged.signature[40] ^= 1;
    let before = state.clone();
    assert_eq!(
        state.apply_validator_commission_update(&forged, &AuthVerifier),
        Err(FundedDelegationReject::Signature)
    );
    assert_eq!(state, before);
}

#[test]
fn commission_cannot_increase_after_delegation_but_can_decrease() {
    let _gate = funded_delegation_rehearsal::open();
    let (mut state, _) = fixture();
    state.validators.get_mut(&0).unwrap().commission_bps = 500;
    state.delegations.push(Delegation {
        delegator: 88,
        validator: 0,
        amount_sat: delegation::MIN_DELEGATION_SAT,
        requested_epoch: state.epoch,
        deactivate_epoch: None,
        eligible: true,
    });

    let increase = commission_update(&state, 600);
    let before = state.clone();
    assert_eq!(
        state.apply_validator_commission_update(&increase, &AuthVerifier),
        Err(FundedDelegationReject::CommissionIncreaseWithDelegations)
    );
    assert_eq!(state, before);

    let decrease = commission_update(&state, 400);
    state
        .apply_validator_commission_update(&decrease, &AuthVerifier)
        .unwrap();
    assert_eq!(state.validators[&0].commission_bps, 400);
}

#[test]
fn all_ninety_five_commissions_change_without_changing_principal_or_supply() {
    let _gate = funded_delegation_rehearsal::open();
    let (_, mut state, _) = setup_with(96, AuthVerifier, &[]);
    state.admission_network_domain = Some([0x91; 32]);
    for record in state.validators.values_mut() {
        record.commission_bps = 0;
    }
    // The controlled fleet excludes registry index 65, which belongs to
    // another operator. Local expansion labels are not registry indices.
    state.validators.get_mut(&65).unwrap().commission_bps = 177;
    let principal: Vec<_> = state.validators.values().map(|r| r.staked_sat).collect();
    let supply = state.accounted_supply_sat();
    let opening_root = state.state_root();
    for validator in (0..65).chain(66..96) {
        let mut tx = ValidatorCommissionUpdate {
            network_domain: state.admission_network_domain.unwrap(),
            epoch: state.epoch,
            validator,
            commission_bps: 500,
            signature: Vec::new(),
        };
        tx.signature = auth_sign(&state.validators[&validator].pubkey, &tx.signing_root());
        let wire = PosTransaction::ValidatorCommissionUpdate(tx.clone()).canonical_bytes();
        assert_eq!(
            PosTransaction::from_canonical_bytes(&wire).unwrap(),
            PosTransaction::ValidatorCommissionUpdate(tx.clone())
        );
        state
            .apply_validator_commission_update(&tx, &AuthVerifier)
            .unwrap();
        assert_eq!(state.accounted_supply_sat(), supply);
    }
    assert!(state
        .validators
        .values()
        .filter(|r| r.index != 65)
        .all(|r| r.commission_bps == 500));
    assert_eq!(state.validators[&65].commission_bps, 177);
    assert_eq!(
        state
            .validators
            .values()
            .map(|r| r.staked_sat)
            .collect::<Vec<_>>(),
        principal
    );
    assert_ne!(state.state_root(), opening_root);
}

#[test]
fn commission_rejects_wrong_network_epoch_key_rate_and_replay_atomically() {
    let _gate = funded_delegation_rehearsal::open();
    let (mut state, _) = fixture();
    for record in state.validators.values_mut() {
        record.commission_bps = 0;
    }
    let original = commission_update(&state, 500);
    for (case, expected) in [
        (0, FundedDelegationReject::Network),
        (1, FundedDelegationReject::Epoch),
        (2, FundedDelegationReject::Signature),
        (3, FundedDelegationReject::Shape),
        (4, FundedDelegationReject::Validator),
    ] {
        let mut tx = original.clone();
        match case {
            0 => tx.network_domain[0] ^= 1,
            1 => tx.epoch += 1,
            2 => tx.validator = 1,
            3 => tx.commission_bps = 10_001,
            4 => tx.validator = u32::MAX,
            _ => unreachable!(),
        }
        let before = state.clone();
        assert_eq!(
            state.apply_validator_commission_update(&tx, &AuthVerifier),
            Err(expected)
        );
        assert_eq!(state, before);
    }
    state
        .apply_validator_commission_update(&original, &AuthVerifier)
        .unwrap();
    let before = state.clone();
    assert_eq!(
        state.apply_validator_commission_update(&original, &AuthVerifier),
        Err(FundedDelegationReject::Commission)
    );
    assert_eq!(state, before);
}

#[test]
fn funded_pending_position_blocks_commission_increase_before_any_weight_activates() {
    let _gate = funded_delegation_rehearsal::open();
    let (mut state, delegate) = fixture();
    state.validators.get_mut(&0).unwrap().commission_bps = 0;
    state
        .apply_funded_delegate(
            &delegate,
            fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS,
            &AuthVerifier,
        )
        .unwrap();
    assert_eq!(
        delegation::Registry::resolve(&state.delegations, state.epoch).total_active(),
        0
    );
    let update = commission_update(&state, 500);
    let before = state.clone();
    assert_eq!(
        state.apply_validator_commission_update(&update, &AuthVerifier),
        Err(FundedDelegationReject::CommissionIncreaseWithDelegations)
    );
    assert_eq!(state, before);
}

#[test]
fn commission_before_funded_delegation_preserves_principal_and_rate() {
    let _gate = funded_delegation_rehearsal::open();
    let (mut state, delegate) = fixture();
    state.validators.get_mut(&0).unwrap().commission_bps = 0;
    let update = commission_update(&state, 500);
    state
        .apply_validator_commission_update(&update, &AuthVerifier)
        .unwrap();
    state
        .apply_funded_delegate(
            &delegate,
            fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS,
            &AuthVerifier,
        )
        .unwrap();
    assert_eq!(state.validators[&0].commission_bps, 500);
    assert_eq!(state.delegations[0].amount_sat, delegate.amount_sat);
}

#[test]
fn large_funded_batches_conserve_funding_and_keep_distinct_owners() {
    let _gate = funded_delegation_rehearsal::open();
    for (validators, amount_blch) in [
        ((66..96u32).collect::<Vec<_>>(), 10_000_000u128),
        ((66..96u32).collect::<Vec<_>>(), 500_000_000u128),
        (
            (0..65u32).chain(66..96).collect::<Vec<_>>(),
            500_000_000u128,
        ),
    ] {
        let (_, mut state, _) = setup_with(140, AuthVerifier, &[]);
        state.admission_network_domain = Some([0x91; 32]);
        let base_fee = fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS;
        let mut spent_fees = 0;
        let mut opening_supply = state.accounted_supply_sat();
        for &validator in &validators {
            let input = FundingInput {
                txid: [validator as u8; 32],
                vout: 0,
            };
            let mut tx = funded_delegate(input.clone());
            tx.funding_pubkey = pq_key(validator as u8);
            tx.validator_pubkey_hash =
                Sha3_256::digest(&state.validators[&validator].pubkey).into();
            tx.amount_sat = amount_blch * 100_000_000;
            tx.funding_signature = auth_sign(&tx.funding_pubkey, &tx.signing_root());
            let funding = tx.required_funding_sat().unwrap();
            state.eutxos.insert(crate::state_root::EutxoEntry {
                txid: input.txid,
                vout: input.vout,
                value: funding.try_into().unwrap(),
                script_hash: Sha3_256::digest(&tx.funding_pubkey).into(),
            });
            opening_supply += funding;
            let charge = state
                .apply_funded_delegate(&tx, base_fee, &AuthVerifier)
                .unwrap();
            spent_fees += charge.base_fee_sat;
            assert_eq!(state.accounted_supply_sat(), opening_supply - spent_fees);
        }
        assert_eq!(state.delegations.len(), validators.len());
        assert_eq!(state.funded_delegation_owners.len(), validators.len());
        assert_eq!(
            state.delegations.iter().map(|d| d.amount_sat).sum::<u128>(),
            amount_blch * 100_000_000 * validators.len() as u128
        );
        assert_eq!(
            delegation::Registry::resolve(&state.delegations, state.epoch).total_active(),
            0
        );
        for (position, d) in state.delegations.iter().enumerate() {
            assert_eq!(d.delegator, position as u32);
            assert_eq!(d.validator, validators[position]);
            assert_eq!(
                state.funded_delegation_owners[&d.delegator],
                Sha3_256::digest(pq_key(d.validator as u8)).as_slice()
            );
        }
    }
}

#[test]
fn creation_rejections_are_atomic_and_owner_bound() {
    let _gate = funded_delegation_rehearsal::open();
    let base_fee = fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS;

    let (mut state, mut bad_signature) = fixture();
    bad_signature.funding_signature[40] ^= 1;
    let before = state.clone();
    assert_eq!(
        state.apply_funded_delegate(&bad_signature, base_fee, &AuthVerifier),
        Err(FundedDelegationReject::Signature)
    );
    assert_eq!(state, before);

    let (mut state, mut wrong_owner) = fixture();
    wrong_owner.funding_pubkey = pq_key(0xf2);
    wrong_owner.funding_signature =
        auth_sign(&wrong_owner.funding_pubkey, &wrong_owner.signing_root());
    let before = state.clone();
    assert_eq!(
        state.apply_funded_delegate(&wrong_owner, base_fee, &AuthVerifier),
        Err(FundedDelegationReject::Ownership)
    );
    assert_eq!(state, before);

    let (mut state, mut unbalanced) = fixture();
    unbalanced.amount_sat += 1;
    unbalanced.funding_signature =
        auth_sign(&unbalanced.funding_pubkey, &unbalanced.signing_root());
    let before = state.clone();
    assert_eq!(
        state.apply_funded_delegate(&unbalanced, base_fee, &AuthVerifier),
        Err(FundedDelegationReject::Conservation)
    );
    assert_eq!(state, before);
}

fn provision_delegation(
    state: &mut CommittedState,
    tag: u8,
    validator: u32,
    amount: u128,
) -> FundedDelegate {
    let input = FundingInput {
        txid: [tag; 32],
        vout: 0,
    };
    let mut tx = funded_delegate(input.clone());
    tx.valid_until_epoch = state.epoch + 1;
    tx.validator_pubkey_hash = Sha3_256::digest(&state.validators[&validator].pubkey).into();
    tx.amount_sat = amount;
    tx.funding_signature = auth_sign(&tx.funding_pubkey, &tx.signing_root());
    state.eutxos.insert(crate::state_root::EutxoEntry {
        txid: input.txid,
        vout: 0,
        value: tx.required_funding_sat().unwrap().try_into().unwrap(),
        script_hash: Sha3_256::digest(&tx.funding_pubkey).into(),
    });
    tx
}

#[test]
fn fixed_limit_counts_pending_positions_per_validator_and_rejects_excess_atomically() {
    use funded_delegation::MAX_FUNDED_DELEGATION_PER_VALIDATOR_SAT as LIMIT;
    let _gate = funded_delegation_rehearsal::open();
    let (mut state, _) = fixture();
    let base_fee = fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS;
    let oversized = provision_delegation(&mut state, 0x51, 0, LIMIT + 1);
    let before = state.clone();
    assert_eq!(
        state.apply_funded_delegate(&oversized, base_fee, &AuthVerifier),
        Err(FundedDelegationReject::DelegationLimit)
    );
    assert_eq!(state, before);

    for (tag, amount) in [(0x52, LIMIT * 3 / 5), (0x53, LIMIT * 2 / 5)] {
        let tx = provision_delegation(&mut state, tag, 0, amount);
        state
            .apply_funded_delegate(&tx, base_fee, &AuthVerifier)
            .unwrap();
    }
    assert_eq!(
        delegation::Registry::resolve(&state.delegations, state.epoch).total_active(),
        0
    );
    let extra = provision_delegation(&mut state, 0x54, 0, delegation::MIN_DELEGATION_SAT);
    let before = state.clone();
    assert_eq!(
        state.apply_funded_delegate(&extra, base_fee, &AuthVerifier),
        Err(FundedDelegationReject::DelegationLimit)
    );
    assert_eq!(state, before);

    let another = provision_delegation(&mut state, 0x55, 1, LIMIT);
    state
        .apply_funded_delegate(&another, base_fee, &AuthVerifier)
        .unwrap();
    assert_eq!(
        state
            .delegations
            .iter()
            .filter(|d| d.validator == 0)
            .map(|d| d.amount_sat)
            .sum::<u128>(),
        LIMIT
    );
    assert_eq!(
        state
            .delegations
            .iter()
            .filter(|d| d.validator == 1)
            .map(|d| d.amount_sat)
            .sum::<u128>(),
        LIMIT
    );
}

#[test]
fn fixed_limit_capacity_returns_only_after_owner_withdrawal() {
    use funded_delegation::MAX_FUNDED_DELEGATION_PER_VALIDATOR_SAT as LIMIT;
    let _gate = funded_delegation_rehearsal::open();
    let (mut state, _) = fixture();
    let base_fee = fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS;
    let tx = provision_delegation(&mut state, 0x61, 0, LIMIT);
    state
        .apply_funded_delegate(&tx, base_fee, &AuthVerifier)
        .unwrap();
    let mut exit = FundedUndelegate {
        network_domain: tx.network_domain,
        epoch: state.epoch,
        delegator_id: 0,
        position: 0,
        funding_pubkey: tx.funding_pubkey.clone(),
        signature: Vec::new(),
    };
    exit.signature = auth_sign(&exit.funding_pubkey, &exit.signing_root());
    state.apply_funded_undelegate(&exit, &AuthVerifier).unwrap();
    while state.funded_delegation_lifecycle[&0].0 == u64::MAX {
        state = state.close_epoch();
    }
    state.epoch = state.funded_delegation_lifecycle[&0].0 + staking::WITHDRAWAL_DELAY_EPOCHS;
    let blocked = provision_delegation(&mut state, 0x62, 0, delegation::MIN_DELEGATION_SAT);
    let before = state.clone();
    assert_eq!(
        state.apply_funded_delegate(&blocked, base_fee, &AuthVerifier),
        Err(FundedDelegationReject::DelegationLimit)
    );
    assert_eq!(state, before);

    let mut withdrawal = FundedDelegationWithdraw {
        network_domain: tx.network_domain,
        epoch: state.epoch,
        delegator_id: 0,
        position: 0,
        funding_pubkey: tx.funding_pubkey,
        destination_script_hash: [0x63; 32],
        max_base_fee_millisat_per_gas: base_fee,
        signature: Vec::new(),
    };
    withdrawal.signature = auth_sign(&withdrawal.funding_pubkey, &withdrawal.signing_root());
    state
        .apply_funded_delegation_withdrawal(&withdrawal, base_fee, &AuthVerifier)
        .unwrap();
    let replacement = provision_delegation(&mut state, 0x64, 0, LIMIT);
    state
        .apply_funded_delegate(&replacement, base_fee, &AuthVerifier)
        .unwrap();
    assert_eq!(state.delegations.len(), 2);
    assert!(state.funded_delegation_lifecycle[&0].1);
}

#[test]
fn fixed_limit_weight_does_not_collapse_when_equal_funded_validators_are_added() {
    use funded_delegation::MAX_FUNDED_DELEGATION_PER_VALIDATOR_SAT as LIMIT;
    let (_, mut state, _) = setup_with(140, AuthVerifier, &[]);
    state.genesis_cohort.clear();
    let amount = 10_000_000 * tokenomics_v4::SAT_PER_BLOCH;
    for count in [30, 35, 36, 95] {
        state.delegations = (0..count)
            .map(|index| Delegation {
                delegator: index,
                validator: index,
                amount_sat: amount,
                requested_epoch: 0,
                deactivate_epoch: None,
                eligible: true,
            })
            .collect();
        let legacy = state.duty_roster_at(0);
        {
            let _gate = funded_delegation_rehearsal::open();
            let funded = state.duty_roster_at(0);
            for validator in funded.iter().take(count as usize) {
                assert_eq!(
                    u128::from(validator.effective_stake),
                    state.validators[&validator.index].staked_sat + amount
                );
            }
        }
        assert_eq!(
            state.duty_roster_at(0),
            legacy,
            "pre-activation weights must remain unchanged"
        );
    }
    let positions = [Delegation {
        delegator: 0,
        validator: 0,
        amount_sat: LIMIT + 1,
        requested_epoch: 0,
        deactivate_epoch: None,
        eligible: true,
    }];
    let registry = delegation::Registry::resolve(&positions, 0);
    assert_eq!(
        u128::from(registry.validators_with_absolute_cap(LIMIT)[0].effective_stake),
        LIMIT
    );
    assert_eq!(
        registry.validators_with_absolute_cap(0)[0].effective_stake,
        0
    );
}

#[test]
fn funded_issuance_pays_five_percent_commission_without_counting_stake_twice() {
    let _gate = funded_delegation_rehearsal::open();
    let (mut state, _) = fixture();
    state.validators.get_mut(&0).unwrap().commission_bps = 500;
    let tx = provision_delegation(
        &mut state,
        0x71,
        0,
        10_000_000 * tokenomics_v4::SAT_PER_BLOCH,
    );
    state
        .apply_funded_delegate(
            &tx,
            fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS,
            &AuthVerifier,
        )
        .unwrap();
    state = state.close_epoch();
    for index in 0..8 {
        state.current_participation.insert(index, true);
    }
    let registry = delegation::Registry::resolve(&state.delegations, state.epoch);
    assert!(registry.total_active() > 0);
    assert!(
        registry.total_active() < tx.amount_sat,
        "exercise partially activated principal"
    );
    let initial_supply = state.accounted_supply_sat();
    let issued = state.issued_sat();
    let first_slot = state.epoch * SLOTS_PER_EPOCH;
    let budget: u128 = (first_slot..first_slot + SLOTS_PER_EPOCH)
        .map(tokenomics_v4::validator_reward_decay_sat)
        .sum();
    let charged = state.close_epoch();
    let mut no_commission = state.clone();
    no_commission.validators.get_mut(&0).unwrap().commission_bps = 0;
    let uncharged = no_commission.close_epoch();
    let gross = uncharged.delegator_issuance_reward_sat(0);
    let net = charged.delegator_issuance_reward_sat(0);
    assert!(
        gross > 0 && net > 0,
        "the funded gate alone must credit issuance"
    );
    let commission = gross * 500 / 10_000;
    assert_eq!(gross - net, commission);
    assert_eq!(
        charged.validators[&0].staked_sat - uncharged.validators[&0].staked_sat,
        commission
    );
    assert_eq!(charged.issued_sat(), uncharged.issued_sat());
    assert!(
        charged.issued_sat() - issued <= budget,
        "delegated weight must not mint twice"
    );
    assert_eq!(
        charged.accounted_supply_sat() - initial_supply,
        charged.issued_sat() - issued
    );
    assert_eq!(charged.delegations[0].amount_sat, tx.amount_sat);
}

#[test]
fn funded_gate_does_not_change_epoch_roots_without_delegations() {
    let (mut state, _) = fixture();
    for index in 0..8 {
        state.current_participation.insert(index, true);
    }
    let historical = state.close_epoch();
    let _gate = funded_delegation_rehearsal::open();
    let candidate = state.close_epoch();
    assert_eq!(candidate, historical);
    assert_eq!(candidate.state_root(), historical.state_root());
}

#[test]
fn funded_position_round_trips_principal_rewards_losses_and_fee() {
    let _gate = funded_delegation_rehearsal::open();
    let (mut state, tx) = fixture();
    let base_fee = fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS;
    let before_creation = state.accounted_supply_sat();
    let creation_charge = state
        .apply_funded_delegate(&tx, base_fee, &AuthVerifier)
        .unwrap();
    assert_eq!(state.delegations.len(), 1);
    assert_eq!(state.funded_delegation_owners.len(), 1);
    assert_eq!(
        state.accounted_supply_sat(),
        before_creation
            .checked_sub(creation_charge.base_fee_sat)
            .unwrap()
    );

    let delegator_id = state.delegations[0].delegator;
    let mut undelegate = FundedUndelegate {
        network_domain: tx.network_domain,
        epoch: state.epoch,
        delegator_id,
        position: 0,
        funding_pubkey: tx.funding_pubkey.clone(),
        signature: Vec::new(),
    };
    undelegate.signature = auth_sign(&undelegate.funding_pubkey, &undelegate.signing_root());
    state
        .apply_funded_undelegate(&undelegate, &AuthVerifier)
        .unwrap();
    assert_eq!(state.funded_delegation_lifecycle[&0].0, u64::MAX);
    while state.funded_delegation_lifecycle[&0].0 == u64::MAX {
        state = state.close_epoch();
    }
    let inactive_since = state.funded_delegation_lifecycle[&0].0;

    let loss = 7;
    let fee_reward = 19;
    let issuance_reward = 23;
    state.delegator_slash_losses.insert(delegator_id, loss);
    state.delegator_fee_rewards.insert(delegator_id, fee_reward);
    state
        .delegator_issuance_rewards
        .insert(delegator_id, issuance_reward);
    state.epoch = inactive_since + staking::WITHDRAWAL_DELAY_EPOCHS;

    let mut withdrawal = FundedDelegationWithdraw {
        network_domain: tx.network_domain,
        epoch: state.epoch,
        delegator_id,
        position: 0,
        funding_pubkey: tx.funding_pubkey.clone(),
        destination_script_hash: [0x92; 32],
        max_base_fee_millisat_per_gas: base_fee,
        signature: Vec::new(),
    };
    withdrawal.signature = auth_sign(&withdrawal.funding_pubkey, &withdrawal.signing_root());
    let withdrawal_charge = withdrawal.charge(base_fee);
    let expected = tx
        .amount_sat
        .checked_sub(loss)
        .unwrap()
        .checked_add(fee_reward + issuance_reward)
        .unwrap()
        .checked_sub(withdrawal_charge.base_fee_sat)
        .unwrap();
    let before_withdrawal = state.accounted_supply_sat();
    state
        .apply_funded_delegation_withdrawal(&withdrawal, base_fee, &AuthVerifier)
        .unwrap();
    let output = state
        .utxo(
            &PosTransaction::FundedDelegationWithdraw(withdrawal.clone()).txid(),
            0,
        )
        .unwrap();
    assert_eq!(u128::from(output.value), expected);
    assert!(state.funded_delegation_lifecycle[&0].1);
    assert_eq!(state.delegator_slash_loss_sat(delegator_id), 0);
    assert_eq!(state.delegator_fee_reward_sat(delegator_id), 0);
    assert_eq!(state.delegator_issuance_reward_sat(delegator_id), 0);
    assert_eq!(
        state.accounted_supply_sat(),
        before_withdrawal
            .checked_sub(withdrawal_charge.base_fee_sat)
            .unwrap()
    );
    assert_eq!(
        state.apply_funded_delegation_withdrawal(&withdrawal, base_fee, &AuthVerifier),
        Err(FundedDelegationReject::AlreadyWithdrawn)
    );
}

#[test]
fn crowded_exit_waits_for_the_churn_budget_to_finish_draining() {
    let _gate = funded_delegation_rehearsal::open();
    let (mut state, tx) = fixture();
    let delegator_id = 77;
    let amount_sat = 20_000_000u128 * tokenomics_v4::SAT_PER_BLOCH;
    state.delegations = vec![Delegation {
        delegator: delegator_id,
        validator: 0,
        amount_sat,
        requested_epoch: 0,
        deactivate_epoch: Some(1),
        eligible: true,
    }];
    state
        .funded_delegation_owners
        .insert(delegator_id, Sha3_256::digest(&tx.funding_pubkey).into());
    state
        .funded_delegation_lifecycle
        .insert(0, (u64::MAX, false));
    let nominal_cooldown_end = 1 + delegation::COOLDOWN_EPOCHS;
    while state.epoch < nominal_cooldown_end {
        state = state.close_epoch();
    }
    assert_eq!(state.epoch, nominal_cooldown_end);
    assert!(
        delegation::Registry::resolve(&state.delegations, state.epoch)
            .activated_sat(&state.delegations[0])
            > 0
    );
    assert_eq!(state.funded_delegation_lifecycle[&0].0, u64::MAX);

    while state.funded_delegation_lifecycle[&0].0 == u64::MAX {
        state = state.close_epoch();
    }
    assert!(state.funded_delegation_lifecycle[&0].0 > nominal_cooldown_end);
    assert_eq!(
        delegation::Registry::resolve(&state.delegations, state.epoch)
            .activated_sat(&state.delegations[0]),
        0
    );
}

// ── Security review ST-1: bounded delegation state ──────────────────────────
// (`params::FUNDED_DELEGATION_BOUND_ACTIVATION_EPOCH`)

use crate::params::funded_delegation_bound_rehearsal;

fn signed_undelegate(state: &CommittedState, owner: &FundedDelegate, position: u32) -> FundedUndelegate {
    let mut tx = FundedUndelegate {
        network_domain: owner.network_domain,
        epoch: state.epoch,
        delegator_id: position,
        position,
        funding_pubkey: owner.funding_pubkey.clone(),
        signature: Vec::new(),
    };
    tx.signature = auth_sign(&tx.funding_pubkey, &tx.signing_root());
    tx
}

fn signed_withdrawal(
    state: &CommittedState,
    owner: &FundedDelegate,
    position: u32,
) -> FundedDelegationWithdraw {
    let mut tx = FundedDelegationWithdraw {
        network_domain: owner.network_domain,
        epoch: state.epoch,
        delegator_id: position,
        position,
        funding_pubkey: owner.funding_pubkey.clone(),
        destination_script_hash: [0x92; 32],
        max_base_fee_millisat_per_gas: fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS,
        signature: Vec::new(),
    };
    tx.signature = auth_sign(&tx.funding_pubkey, &tx.signing_root());
    tx
}

/// Deactivate `position`, let it drain, wait out the withdrawal delay and
/// withdraw it, all through the real transactions and real epoch boundaries.
fn withdraw_through_the_lifecycle(mut state: CommittedState, owner: &FundedDelegate, position: u32) -> CommittedState {
    let base_fee = fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS;
    let exit = signed_undelegate(&state, owner, position);
    state.apply_funded_undelegate(&exit, &AuthVerifier).unwrap();
    while state.funded_delegation_lifecycle[&position].0 == u64::MAX {
        state = state.close_epoch();
    }
    let mature = state.funded_delegation_lifecycle[&position].0 + staking::WITHDRAWAL_DELAY_EPOCHS;
    while state.epoch < mature {
        state = state.close_epoch();
    }
    let withdrawal = signed_withdrawal(&state, owner, position);
    state
        .apply_funded_delegation_withdrawal(&withdrawal, base_fee, &AuthVerifier)
        .unwrap();
    assert!(state.funded_delegation_lifecycle[&position].1);
    state
}

/// Three funded positions (indices 0, 1, 2 behind validators 0, 1, 0) with
/// position 0 fully withdrawn. Built with only the funded-delegation gate
/// open, so it is a state today's rules can produce.
fn state_with_a_withdrawn_position() -> (CommittedState, FundedDelegate) {
    let (mut state, first) = fixture();
    let base_fee = fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS;
    state.apply_funded_delegate(&first, base_fee, &AuthVerifier).unwrap();
    for (tag, validator, amount_blch) in [(0x41, 1, 25u128), (0x42, 0, 1_000)] {
        let tx = provision_delegation(
            &mut state,
            tag,
            validator,
            amount_blch * tokenomics_v4::SAT_PER_BLOCH,
        );
        state.apply_funded_delegate(&tx, base_fee, &AuthVerifier).unwrap();
    }
    let state = withdraw_through_the_lifecycle(state, &first, 0);
    assert_eq!(state.delegations.len(), 3);
    (state, first)
}

/// Append `count` synthetic funded positions behind `validator`, as if they
/// had been created long ago: record plus owner entry, sequential ids.
fn fill_positions(state: &mut CommittedState, validator: u32, count: usize) {
    for _ in 0..count {
        let id = state.delegations.len() as u32;
        state.delegations.push(Delegation {
            delegator: id,
            validator,
            amount_sat: delegation::MIN_DELEGATION_SAT,
            requested_epoch: 0,
            deactivate_epoch: None,
            eligible: true,
        });
        state.funded_delegation_owners.insert(id, [0x77; 32]);
    }
}

#[test]
fn funded_delegation_bound_gate_is_inert() {
    assert_eq!(crate::params::FUNDED_DELEGATION_BOUND_ACTIVATION_EPOCH, u64::MAX);
    for epoch in [0, 4_669, 7_400, u64::MAX - 1, u64::MAX] {
        assert!(!crate::params::funded_delegation_bound_active(epoch));
    }
    let _bound = funded_delegation_bound_rehearsal::open();
    assert!(crate::params::funded_delegation_bound_active(0));
}

/// With the gate inert a boundary prunes nothing: the withdrawn record, its
/// owner and its lifecycle entry are all still state, and still committed
/// (touching the withdrawn record moves the root).
#[test]
fn inert_bound_gate_keeps_withdrawn_positions_committed_and_roots_unchanged() {
    let _gate = funded_delegation_rehearsal::open();
    let (state, _) = state_with_a_withdrawn_position();
    assert!(state.delegations.iter().all(|d| !d.is_pruned()));

    let closed = state.close_epoch();
    assert_eq!(closed.delegations, state.delegations);
    assert_eq!(closed.funded_delegation_owners, state.funded_delegation_owners);
    assert_eq!(closed.funded_delegation_lifecycle, state.funded_delegation_lifecycle);
    // One delegation leaf, one owner leaf per position; one lifecycle leaf
    // for the position that was deactivated. Nothing left the tree.
    assert_eq!(closed.delegations.len(), 3);
    assert_eq!(closed.funded_delegation_owners.len(), 3);
    assert_eq!(closed.funded_delegation_lifecycle.len(), 1);

    let mut touched = closed.clone();
    touched.delegations[0].amount_sat += 1;
    assert_ne!(touched.state_root(), closed.state_root());

    // The pruning entry point is only reachable behind the gate; called
    // directly on this state it would prune, so the gate is what holds it.
    let mut forced = closed.clone();
    forced.prune_withdrawn_funded_delegations(forced.epoch);
    assert!(forced.delegations[0].is_pruned());
    assert_ne!(forced.state_root(), closed.state_root());
}

/// With the gate armed, the next boundary takes the withdrawn position out
/// of the fold and out of the root, and nothing else changes.
#[test]
fn armed_bound_prunes_withdrawn_positions_from_the_fold_and_the_root() {
    let _gate = funded_delegation_rehearsal::open();
    let (state, owner) = state_with_a_withdrawn_position();
    let base_fee = fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS;
    let withdrawn_id = state.delegations[0].delegator;
    let control = state.close_epoch();

    let _bound = funded_delegation_bound_rehearsal::open();
    let mut pruned = state.close_epoch();

    // The slot is the tombstone; its owner and lifecycle entries are gone.
    assert!(pruned.delegations[0].is_pruned());
    assert_eq!(pruned.delegations.len(), 3, "positions keep their indices");
    assert_eq!(pruned.delegations[1..], control.delegations[1..]);
    assert!(!pruned.funded_delegation_owners.contains_key(&withdrawn_id));
    assert!(!pruned.funded_delegation_lifecycle.contains_key(&0));
    assert_eq!(pruned.funded_delegation_owners.len(), 2);

    // Out of the fold: the resolver's queue no longer holds it...
    let in_fold = |s: &CommittedState| {
        s.delegations
            .iter()
            .filter(|d| d.eligible && d.amount_sat >= delegation::MIN_DELEGATION_SAT)
            .count()
    };
    assert_eq!((in_fold(&control), in_fold(&pruned)), (3, 2));
    // ...and nobody else can tell: same registry, same rosters, same supply,
    // now and across the boundaries that follow.
    let (mut with, mut without) = (control.clone(), pruned.clone());
    for _ in 0..4 {
        assert_eq!(
            delegation::Registry::resolve(&without.delegations, without.epoch),
            delegation::Registry::resolve(&with.delegations, with.epoch)
        );
        assert_eq!(without.duty_roster_at(without.epoch), with.duty_roster_at(with.epoch));
        assert_eq!(without.accounted_supply_sat(), with.accounted_supply_sat());
        assert_eq!(without.validators, with.validators);
        assert_eq!(without.delegator_issuance_rewards, with.delegator_issuance_rewards);
        (with, without) = (with.close_epoch(), without.close_epoch());
    }

    // Out of the root: three leaves fewer (record, owner, lifecycle).
    assert_eq!(control.state_tree().len() - pruned.state_tree().len(), 3);
    assert_ne!(pruned.state_root(), control.state_root());

    // The pruned slot is not a position: no view, no second withdrawal, no
    // deactivation, each refused without touching state.
    assert!(pruned.funded_delegation_view(0).is_none());
    assert!(pruned.funded_delegation_view(1).is_some());
    let before = pruned.clone();
    let again = signed_withdrawal(&pruned, &owner, 0);
    assert_eq!(
        pruned.apply_funded_delegation_withdrawal(&again, base_fee, &AuthVerifier),
        Err(FundedDelegationReject::Ownership)
    );
    let exit = signed_undelegate(&pruned, &owner, 0);
    assert_eq!(
        pruned.apply_funded_undelegate(&exit, &AuthVerifier),
        Err(FundedDelegationReject::Ownership)
    );
    assert_eq!(pruned, before);

    // A boundary with nothing withdrawn prunes nothing.
    let next = pruned.close_epoch();
    assert_eq!(next.delegations, pruned.delegations);
    assert_eq!(next.funded_delegation_owners, pruned.funded_delegation_owners);

    // The next position still gets the next index and the next identifier.
    let tx = provision_delegation(&mut pruned, 0x43, 1, delegation::MIN_DELEGATION_SAT);
    pruned.apply_funded_delegate(&tx, base_fee, &AuthVerifier).unwrap();
    assert_eq!(pruned.delegations.len(), 4);
    assert_eq!(pruned.delegations[3].delegator, 3);
    assert!(pruned.delegations[0].is_pruned());
}

/// A tombstone carries delegator id 0. The owner of the real delegator 0
/// must not be able to address a pruned slot with it.
#[test]
fn a_pruned_slot_cannot_be_addressed_through_the_tombstone_identifier() {
    let _gate = funded_delegation_rehearsal::open();
    let (mut state, first) = fixture();
    let base_fee = fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS;
    state.apply_funded_delegate(&first, base_fee, &AuthVerifier).unwrap();
    // Position 0 belongs to delegator 0 and is live; slot 1 is pruned.
    state.delegations.push(Delegation::PRUNED);
    fill_positions(&mut state, 1, 1);
    assert_eq!(state.delegations[0].delegator, 0);

    let before = state.clone();
    let mut exit = signed_undelegate(&state, &first, 1);
    exit.delegator_id = 0;
    exit.signature = auth_sign(&exit.funding_pubkey, &exit.signing_root());
    assert_eq!(
        state.apply_funded_undelegate(&exit, &AuthVerifier),
        Err(FundedDelegationReject::Position)
    );
    let mut withdrawal = signed_withdrawal(&state, &first, 1);
    withdrawal.delegator_id = 0;
    withdrawal.signature = auth_sign(&withdrawal.funding_pubkey, &withdrawal.signing_root());
    assert_eq!(
        state.apply_funded_delegation_withdrawal(&withdrawal, base_fee, &AuthVerifier),
        Err(FundedDelegationReject::Position)
    );
    assert!(state.funded_delegation_view(1).is_none());
    assert_eq!(state, before);
}

/// The last record and the record with the largest identifier are kept, so
/// the root still commits the history length and identifiers never repeat.
#[test]
fn the_newest_position_is_never_pruned() {
    let _gate = funded_delegation_rehearsal::open();
    let _bound = funded_delegation_bound_rehearsal::open();
    let (mut state, first) = fixture();
    let base_fee = fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS;
    state.apply_funded_delegate(&first, base_fee, &AuthVerifier).unwrap();
    let mut state = withdraw_through_the_lifecycle(state, &first, 0);

    // The only position, withdrawn: it stays, whole, through boundaries.
    state = state.close_epoch();
    assert!(!state.delegations[0].is_pruned());
    assert!(state.funded_delegation_lifecycle[&0].1);
    assert_eq!(state.funded_delegation_owners.len(), 1);

    // A newer position takes its place as the newest; now it can go.
    let tx = provision_delegation(&mut state, 0x44, 1, delegation::MIN_DELEGATION_SAT);
    state.apply_funded_delegate(&tx, base_fee, &AuthVerifier).unwrap();
    assert_eq!(state.delegations[1].delegator, 1);
    state = state.close_epoch();
    assert!(state.delegations[0].is_pruned());
    assert!(!state.delegations[1].is_pruned());
    assert_eq!(state.funded_delegation_owners.keys().copied().collect::<Vec<_>>(), [1]);
    assert!(state.funded_delegation_lifecycle.is_empty());

    let tx = provision_delegation(&mut state, 0x45, 1, delegation::MIN_DELEGATION_SAT);
    state.apply_funded_delegate(&tx, base_fee, &AuthVerifier).unwrap();
    assert_eq!(state.delegations.len(), 3);
    assert_eq!(state.delegations[2].delegator, 2, "identifiers stay monotonic");
}

/// A withdrawn record that once stood ahead of a backlog which is still
/// open is kept until the backlog closes: pruning it earlier would hand the
/// stake behind it weight the chain never agreed on.
#[test]
fn pruning_waits_while_the_withdrawn_position_still_shapes_a_backlog() {
    let (mut state, _) = fixture();
    let blch = tokenomics_v4::SAT_PER_BLOCH;
    state.delegations = vec![
        Delegation {
            delegator: 0,
            validator: 0,
            amount_sat: 5_000_000 * blch,
            requested_epoch: 1,
            deactivate_epoch: Some(2),
            eligible: true,
        },
        Delegation {
            delegator: 1,
            validator: 1,
            amount_sat: 40_000_000 * blch,
            requested_epoch: 1,
            deactivate_epoch: None,
            eligible: true,
        },
    ];
    state.funded_delegation_owners.insert(0, [0x71; 32]);
    state.funded_delegation_owners.insert(1, [0x72; 32]);
    state.funded_delegation_lifecycle.insert(0, (34, true));

    let behind = state.delegations[1];
    let weight_at = |s: &CommittedState, epoch| {
        delegation::Registry::resolve(&s.delegations, epoch).activated_sat(&behind)
    };
    let mut early = state.clone();
    early.prune_withdrawn_funded_delegations(40);
    assert_eq!(early, state, "the backlog behind it is still warming up");
    assert!(weight_at(&state, 40) < behind.amount_sat);

    let mut late = state.clone();
    late.prune_withdrawn_funded_delegations(200);
    assert!(late.delegations[0].is_pruned());
    for epoch in [200, 201, 260, 5_000] {
        assert_eq!(weight_at(&late, epoch), weight_at(&state, epoch));
        assert_eq!(late.duty_roster_at(epoch), state.duty_roster_at(epoch));
    }
}

/// The count limits: inert today, and with the gate armed the next position
/// past a limit is refused without touching state.
#[test]
fn armed_bound_refuses_the_position_past_each_limit() {
    use funded_delegation::{
        CROWDED_FUNDED_POSITION_MIN_SAT as LARGE, MAX_FUNDED_POSITIONS as GLOBAL,
        MAX_FUNDED_POSITIONS_PER_VALIDATOR as PER_VALIDATOR,
    };
    let _gate = funded_delegation_rehearsal::open();
    let base_fee = fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS;
    let small = delegation::MIN_DELEGATION_SAT;
    let refused = |state: &mut CommittedState, tag: u8, validator: u32, amount: u128| {
        let tx = provision_delegation(state, tag, validator, amount);
        let before = state.clone();
        assert_eq!(
            state.apply_funded_delegate(&tx, base_fee, &AuthVerifier),
            Err(FundedDelegationReject::PositionLimit)
        );
        assert_eq!(*state, before, "a refusal must not touch state");
    };
    let accepted = |state: &mut CommittedState, tag: u8, validator: u32, amount: u128| {
        let tx = provision_delegation(state, tag, validator, amount);
        state.apply_funded_delegate(&tx, base_fee, &AuthVerifier).unwrap();
    };

    // Inert: no count is ever looked at.
    {
        let (mut state, _) = fixture();
        fill_positions(&mut state, 0, PER_VALIDATOR + 5);
        fill_positions(&mut state, 1, GLOBAL);
        accepted(&mut state, 0x51, 0, small);
        accepted(&mut state, 0x52, 2, small);
    }

    let _bound = funded_delegation_bound_rehearsal::open();

    // Per validator. The first half of the slots takes any position...
    let (mut state, _) = fixture();
    fill_positions(&mut state, 0, PER_VALIDATOR / 2 - 1);
    accepted(&mut state, 0x53, 0, small);
    // ...the second half only substantial ones...
    refused(&mut state, 0x54, 0, small);
    refused(&mut state, 0x55, 0, LARGE - 1);
    accepted(&mut state, 0x56, 0, LARGE);
    // ...and a full validator takes none, while its neighbour is untouched.
    fill_positions(&mut state, 0, PER_VALIDATOR / 2 - 1);
    assert_eq!(state.delegations.iter().filter(|d| d.validator == 0).count(), PER_VALIDATOR);
    refused(&mut state, 0x57, 0, LARGE);
    refused(&mut state, 0x58, 0, small);
    accepted(&mut state, 0x59, 1, small);

    // A pruned slot is not a position: it gives its place back.
    let last_of_validator_0 = state.delegations.iter().rposition(|d| d.validator == 0).unwrap();
    let freed = state.delegations[last_of_validator_0].delegator;
    state.delegations[last_of_validator_0] = Delegation::PRUNED;
    state.funded_delegation_owners.remove(&freed);
    accepted(&mut state, 0x5a, 0, LARGE);
    refused(&mut state, 0x5b, 0, LARGE);

    // Globally, the same two steps.
    let (mut state, _) = fixture();
    for validator in 1..8 {
        fill_positions(&mut state, validator, (GLOBAL / 2 - 1) / 7);
    }
    let short = GLOBAL / 2 - 1 - state.delegations.len();
    fill_positions(&mut state, 1, short);
    accepted(&mut state, 0x61, 0, small);
    assert_eq!(state.delegations.len(), GLOBAL / 2);
    refused(&mut state, 0x62, 0, small);
    accepted(&mut state, 0x63, 0, LARGE);
    let room = GLOBAL - state.delegations.len();
    fill_positions(&mut state, 2, room);
    refused(&mut state, 0x64, 0, LARGE);
    refused(&mut state, 0x65, 0, small);
}

/// A pruned state survives the local restart cache: the pruned slot comes
/// back in place and the restored state has the header's root. A history
/// that ends in a pruned slot is refused, because no committed leaf would
/// pin its length.
#[test]
#[cfg(feature = "local-state-cache")]
fn local_cache_round_trips_a_pruned_history_and_refuses_a_pruned_tail() {
    let _gate = funded_delegation_rehearsal::open();
    let (state, _) = state_with_a_withdrawn_position();
    let mut pruned = {
        let _bound = funded_delegation_bound_rehearsal::open();
        state.close_epoch()
    };
    assert!(pruned.delegations[0].is_pruned());
    // A restored state must sit at a slot of its own epoch.
    pruned.slot = pruned.epoch * SLOTS_PER_EPOCH;
    let header_for = |state: &CommittedState| BlockHeaderV4 {
        version: BLOCK_VERSION_V4, parent: [0; 32], state_root: state.compute_root(),
        body_root: [0; 32], slot: state.slot, proposer_index: 0,
        randao_reveal: [0; 32], randao_mix: state.randao_mix,
        justified_root: [0; 32], finalized_root: [0; 32],
        attestation_root: [0; 32], coherence_root: [0; 32],
    };
    let header = header_for(&pruned);
    pruned.head = header.id();
    let bytes = pruned.encode_local_cache().unwrap();
    assert_eq!(CommittedState::decode_local_cache(&bytes, &header).unwrap(), pruned);

    let mut longer = pruned.clone();
    longer.delegations.push(Delegation::PRUNED);
    assert_eq!(longer.compute_root(), pruned.compute_root(), "a pruned slot is not committed");
    let header = header_for(&longer);
    longer.head = header.id();
    let bytes = longer.encode_local_cache().unwrap();
    let refusal = CommittedState::decode_local_cache(&bytes, &header).unwrap_err();
    assert!(refusal.contains("pruned slot"), "{refusal}");
}

/// What one state root and one epoch boundary cost with many funded
/// positions in committed state (not asserted on time). This is the part of
/// the per-block cost the resolver rewrite does not touch and the position
/// limit exists to bound.
///
/// ```sh
/// cargo test --release -p bloch-pos-committee --lib \
///     measure_state_root_with_many_funded_positions -- --ignored --nocapture
/// ```
#[test]
#[ignore = "measurement: run in release with --nocapture"]
fn measure_state_root_with_many_funded_positions() {
    use std::time::Instant;
    let _gate = funded_delegation_rehearsal::open();
    println!("positions | state root | epoch boundary | roster");
    for n in [0usize, 1_000, 4_096, 10_000, 100_000] {
        let (_, mut state, _) = setup_with(140, AuthVerifier, &[]);
        state.admission_network_domain = Some([0x91; 32]);
        for k in 0..n {
            fill_positions(&mut state, (k % 139) as u32, 1);
            // Half of them deactivated: those carry a lifecycle leaf too.
            if k % 2 == 0 {
                state.delegations[k].deactivate_epoch = Some(0);
                state.funded_delegation_lifecycle.insert(k as u32, (0, false));
            }
        }
        let _ = state.state_root();
        let t = Instant::now();
        std::hint::black_box(state.state_root());
        let root = t.elapsed();
        let t = Instant::now();
        std::hint::black_box(state.close_epoch());
        let boundary = t.elapsed();
        let _ = state.duty_roster_at(state.epoch);
        let t = Instant::now();
        std::hint::black_box(state.duty_roster_at(state.epoch));
        let roster = t.elapsed();
        println!("{n:>9} | {root:>10.3?} | {boundary:>14.3?} | {roster:>10.3?}");
    }
}
