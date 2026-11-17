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
    fill_positions_with(state, validator, count, delegation::MIN_DELEGATION_SAT, 0);
}

/// [`fill_positions`] with the principal and the request epoch chosen. A
/// position created in epoch `c` requests `c + 1`; the bound gate counts a
/// position toward its global limit when it was requested after the gate
/// epoch.
fn fill_positions_with(
    state: &mut CommittedState,
    validator: u32,
    count: usize,
    amount_sat: u128,
    requested_epoch: u64,
) {
    for _ in 0..count {
        let id = state.delegations.len() as u32;
        state.delegations.push(Delegation {
            delegator: id,
            validator,
            amount_sat,
            requested_epoch,
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

fn delegate_refused(state: &mut CommittedState, tag: u8, validator: u32, amount: u128) {
    let tx = provision_delegation(state, tag, validator, amount);
    let before = state.clone();
    assert_eq!(
        state.apply_funded_delegate(&tx, fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS, &AuthVerifier),
        Err(FundedDelegationReject::PositionLimit)
    );
    assert_eq!(*state, before, "a refusal must not touch state");
}

fn delegate_accepted(state: &mut CommittedState, tag: u8, validator: u32, amount: u128) {
    let tx = provision_delegation(state, tag, validator, amount);
    state
        .apply_funded_delegate(&tx, fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS, &AuthVerifier)
        .unwrap();
}

fn live_behind(state: &CommittedState, validator: u32) -> usize {
    state
        .delegations
        .iter()
        .filter(|d| !d.is_pruned() && d.validator == validator && d.deactivate_epoch.is_none())
        .count()
}

/// With the gate inert no count is looked at, nothing is displaced and no
/// minimum beyond the ordinary one applies, however full the history is.
#[test]
fn inert_bound_gate_applies_no_position_limit_and_displaces_nothing() {
    use funded_delegation::{MAX_FUNDED_POSITIONS as GLOBAL, MAX_FUNDED_POSITIONS_PER_VALIDATOR as PER_VALIDATOR};
    let _gate = funded_delegation_rehearsal::open();
    let small = delegation::MIN_DELEGATION_SAT;
    let (mut state, _) = fixture();
    // Both ages of position, far past every limit.
    fill_positions_with(&mut state, 0, PER_VALIDATOR + 5, small, 0);
    fill_positions_with(&mut state, 1, GLOBAL, small, 1);
    let before = state.delegations.clone();
    delegate_accepted(&mut state, 0x51, 0, small);
    delegate_accepted(&mut state, 0x52, 2, small);
    delegate_accepted(&mut state, 0x53, 0, 1_000 * small);
    assert_eq!(state.delegations[..before.len()], before[..], "no existing position was touched");
    assert_eq!(state.delegations.len(), before.len() + 3);
    assert!(state.delegations.iter().all(|d| d.deactivate_epoch.is_none()));
    assert!(state.funded_delegation_lifecycle.is_empty());
}

/// The priced minimum, as a table.
#[test]
fn the_position_minimum_doubles_through_the_second_half_of_the_limit() {
    use funded_delegation::{
        funded_position_minimum_sat as minimum, FUNDED_POSITION_MINIMUM_STEP as STEP,
        MAX_FUNDED_POSITIONS as GLOBAL,
    };
    let blch = tokenomics_v4::SAT_PER_BLOCH;
    assert_eq!((GLOBAL, STEP), (4_096, 128));
    for held in [0, 1, GLOBAL / 2 - 1] {
        assert_eq!(minimum(held), delegation::MIN_DELEGATION_SAT);
    }
    assert_eq!(minimum(GLOBAL / 2), 20 * blch);
    assert_eq!(minimum(GLOBAL / 2 + STEP - 1), 20 * blch);
    assert_eq!(minimum(GLOBAL / 2 + STEP), 40 * blch);
    assert_eq!(minimum(GLOBAL / 2 + 9 * STEP), 10_240 * blch);
    assert_eq!(minimum(GLOBAL - 1), 655_360 * blch);
    // Monotonic, and always below the per-validator principal ceiling.
    let mut last = 0;
    for held in 0..GLOBAL {
        assert!(minimum(held) >= last);
        last = minimum(held);
    }
    assert!(last < funded_delegation::MAX_FUNDED_DELEGATION_PER_VALIDATOR_SAT);
    // What it costs to hold the whole second half: about 168M BLCH.
    let fill: u128 = (GLOBAL / 2..GLOBAL).map(minimum).sum();
    assert_eq!(fill, 167_769_600 * blch);
}

/// The global limit: positions created under the gate are counted, the
/// minimum follows the count, and the limit itself admits nothing.
#[test]
fn armed_bound_prices_the_global_limit_and_stops_at_it() {
    use funded_delegation::{FUNDED_POSITION_MINIMUM_STEP as STEP, MAX_FUNDED_POSITIONS as GLOBAL};
    let _gate = funded_delegation_rehearsal::open();
    let _bound = funded_delegation_bound_rehearsal::open();
    let small = delegation::MIN_DELEGATION_SAT;
    let held = |state: &CommittedState| {
        state.delegations.iter().filter(|d| !d.is_pruned() && d.requested_epoch > 0).count()
    };

    // The first half takes the ordinary minimum.
    let (mut state, _) = fixture();
    for validator in 1..8 {
        fill_positions_with(&mut state, validator, (GLOBAL / 2 - 1) / 7, small, 1);
    }
    let short = GLOBAL / 2 - 1 - state.delegations.len();
    fill_positions_with(&mut state, 1, short, small, 1);
    delegate_accepted(&mut state, 0x61, 0, small);
    assert_eq!(held(&state), GLOBAL / 2);
    // From there the minimum is 20 BLCH...
    delegate_refused(&mut state, 0x62, 0, small);
    delegate_refused(&mut state, 0x63, 0, 2 * small - 1);
    delegate_accepted(&mut state, 0x64, 0, 2 * small);
    // ...and 40 BLCH one step later.
    let to_next_step = GLOBAL / 2 + STEP - held(&state);
    fill_positions_with(&mut state, 2, to_next_step, small, 1);
    delegate_refused(&mut state, 0x65, 0, 2 * small);
    delegate_accepted(&mut state, 0x66, 0, 4 * small);

    // One slot left: only the top of the curve gets it.
    let room = GLOBAL - 1 - held(&state);
    fill_positions_with(&mut state, 3, room, small, 1);
    let top = funded_delegation::funded_position_minimum_sat(GLOBAL - 1);
    delegate_refused(&mut state, 0x67, 0, top - 1);
    delegate_accepted(&mut state, 0x68, 0, top);
    assert_eq!(held(&state), GLOBAL);
    // Full: no amount enters, behind any validator.
    delegate_refused(&mut state, 0x69, 0, 4 * top);
    delegate_refused(&mut state, 0x6a, 5, 4 * top);

    // A pruned slot is not a position: it gives its place back.
    let last_of_validator_3 = state.delegations.iter().rposition(|d| d.validator == 3).unwrap();
    let freed = state.delegations[last_of_validator_3].delegator;
    state.delegations[last_of_validator_3] = Delegation::PRUNED;
    state.funded_delegation_owners.remove(&freed);
    delegate_accepted(&mut state, 0x6b, 0, top);
    delegate_refused(&mut state, 0x6c, 0, 4 * top);

    // A deactivating position still counts here (it is still hashed and
    // resolved by every block) until it is pruned.
    let leaving = state.delegations.iter().rposition(|d| d.validator == 2).unwrap();
    state.delegations[leaving].deactivate_epoch = Some(state.epoch + 1);
    delegate_refused(&mut state, 0x6d, 0, 4 * top);
}

/// Security review round 2, DET-1: positions created before the gate cannot
/// be used to fill the limits in advance. The state is built below the gate
/// (where today's rules apply and nothing is limited), with a full validator
/// and the whole global limit taken at the 10 BLCH minimum, and then rolled
/// past the gate through real epoch boundaries.
#[test]
fn positions_created_before_the_bound_gate_do_not_exhaust_the_limits() {
    use funded_delegation::{MAX_FUNDED_POSITIONS as GLOBAL, MAX_FUNDED_POSITIONS_PER_VALIDATOR as PER_VALIDATOR};
    const GATE: u64 = 2;
    let _gate = funded_delegation_rehearsal::open();
    let _bound = funded_delegation_bound_rehearsal::open_at(GATE);
    let small = delegation::MIN_DELEGATION_SAT;
    let large = 10_000 * tokenomics_v4::SAT_PER_BLOCH;

    let (mut state, _) = fixture();
    assert!(state.epoch < GATE && !crate::params::funded_delegation_bound_active(state.epoch));
    // Requested at or before the gate epoch: created below the gate.
    fill_positions_with(&mut state, 0, PER_VALIDATOR, small, 1);
    fill_positions_with(&mut state, 1, GLOBAL - PER_VALIDATOR - 1, small, GATE);
    // Below the gate the real transaction is still unlimited.
    delegate_accepted(&mut state, 0x70, 1, small);
    assert_eq!(state.delegations.len(), GLOBAL);
    assert!(state.funded_delegation_lifecycle.is_empty());

    while state.epoch < GATE {
        state = state.close_epoch();
    }
    assert!(crate::params::funded_delegation_bound_active(state.epoch));
    assert_eq!(live_behind(&state, 0), PER_VALIDATOR);

    // Another validator: none of the 4,096 old positions count, so even the
    // ordinary minimum is accepted.
    delegate_accepted(&mut state, 0x71, 2, small);
    // The full validator: a substantial position displaces the smallest old
    // one instead of being refused...
    let pre_gate = state.delegations[..GLOBAL].to_vec();
    delegate_accepted(&mut state, 0x72, 0, large);
    let displaced: Vec<usize> = (0..GLOBAL)
        .filter(|i| state.delegations[*i] != pre_gate[*i])
        .collect();
    assert_eq!(displaced, [PER_VALIDATOR - 1], "the newest of the equally small positions");
    assert_eq!(state.delegations[PER_VALIDATOR - 1].deactivate_epoch, Some(state.epoch + 1));
    assert_eq!(live_behind(&state, 0), PER_VALIDATOR);
    // ...and a minimum position cannot take a slot from an equal.
    delegate_refused(&mut state, 0x73, 0, small);

    // Positions created under the gate are what the global limit counts,
    // and it still cannot be exceeded.
    let held = |state: &CommittedState| {
        state.delegations.iter().filter(|d| !d.is_pruned() && d.requested_epoch > GATE).count()
    };
    assert_eq!(held(&state), 2);
    let created = state.epoch + 1;
    fill_positions_with(&mut state, 3, GLOBAL - 2, large, created);
    assert_eq!(held(&state), GLOBAL);
    delegate_refused(&mut state, 0x74, 4, 100 * large);
}

/// The per-validator limit with the gate armed: a full validator admits a
/// position only by displacement, the displaced position is in exactly the
/// state its owner's own `FundedUndelegate` would have left it in, and its
/// owner withdraws the whole principal through the ordinary path.
#[test]
fn a_full_validator_admits_a_larger_position_by_displacing_the_smallest() {
    use funded_delegation::{FUNDED_DISPLACEMENT_FACTOR as FACTOR, MAX_FUNDED_POSITIONS_PER_VALIDATOR as PER_VALIDATOR};
    let _gate = funded_delegation_rehearsal::open();
    let _bound = funded_delegation_bound_rehearsal::open();
    let base_fee = fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS;
    let small = delegation::MIN_DELEGATION_SAT;
    let blch = tokenomics_v4::SAT_PER_BLOCH;

    // Position 0 is a real 10 BLCH position; 63 of 25 BLCH fill validator 0.
    let (mut state, first) = fixture();
    state.apply_funded_delegate(&first, base_fee, &AuthVerifier).unwrap();
    assert_eq!((state.delegations[0].validator, state.delegations[0].amount_sat), (0, small));
    let created = state.epoch + 1;
    fill_positions_with(&mut state, 0, PER_VALIDATOR - 2, 25 * blch, created);
    // One short of full: no displacement, the ordinary minimum.
    delegate_accepted(&mut state, 0x80, 0, 25 * blch);
    assert_eq!(live_behind(&state, 0), PER_VALIDATOR);
    assert!(state.funded_delegation_lifecycle.is_empty());

    // Full. Less than twice the smallest position is refused...
    delegate_refused(&mut state, 0x81, 0, small);
    delegate_refused(&mut state, 0x82, 0, FACTOR * small - 1);
    // ...while another validator is untouched.
    delegate_accepted(&mut state, 0x83, 1, small);

    // Twice the smallest enters, and the smallest starts deactivating
    // exactly as if its owner had asked.
    let mut by_owner = state.clone();
    let exit = signed_undelegate(&by_owner, &first, 0);
    by_owner.apply_funded_undelegate(&exit, &AuthVerifier).unwrap();
    let before = state.clone();
    delegate_accepted(&mut state, 0x84, 0, FACTOR * small);
    assert_eq!(state.delegations[0], by_owner.delegations[0]);
    assert_eq!(state.delegations[0].deactivate_epoch, Some(state.epoch + 1));
    assert_eq!(state.funded_delegation_lifecycle, by_owner.funded_delegation_lifecycle);
    assert_eq!(state.funded_delegation_lifecycle[&0], (u64::MAX, false));
    // Nothing else of the old history moved, and no stake did: the displaced
    // principal and every ledger are where they were.
    assert_eq!(state.delegations[1..before.delegations.len()], before.delegations[1..]);
    assert_eq!(state.delegations.len(), before.delegations.len() + 1);
    assert_eq!(state.funded_delegation_owners[&0], before.funded_delegation_owners[&0]);
    assert_eq!(state.delegator_slash_losses, before.delegator_slash_losses);
    assert_eq!(state.delegator_issuance_rewards, before.delegator_issuance_rewards);
    assert_eq!(live_behind(&state, 0), PER_VALIDATOR);
    // The owner cannot deactivate it a second time.
    let again = signed_undelegate(&state, &first, 0);
    assert_eq!(
        state.apply_funded_undelegate(&again, &AuthVerifier),
        Err(FundedDelegationReject::AlreadyDeactivating)
    );

    // The smallest live position is now the 20 BLCH newcomer: 39.99 BLCH
    // does not move it, 40 BLCH does.
    let newcomer = state.delegations.len() - 1;
    delegate_refused(&mut state, 0x85, 0, 2 * FACTOR * small - 1);
    delegate_accepted(&mut state, 0x86, 0, 2 * FACTOR * small);
    assert_eq!(state.delegations[newcomer].deactivate_epoch, Some(state.epoch + 1));
    // Now 63 positions of 25 BLCH and one of 40: among equals the newest goes.
    let newest_of_25 = state
        .delegations
        .iter()
        .rposition(|d| d.validator == 0 && d.deactivate_epoch.is_none() && d.amount_sat == 25 * blch)
        .unwrap();
    delegate_refused(&mut state, 0x87, 0, 50 * blch - 1);
    delegate_accepted(&mut state, 0x88, 0, 50 * blch);
    let leaving: Vec<usize> = (0..state.delegations.len())
        .filter(|i| state.delegations[*i].deactivate_epoch.is_some())
        .collect();
    assert_eq!(leaving, [0, newest_of_25, newcomer]);
    assert_eq!(live_behind(&state, 0), PER_VALIDATOR);

    // The displaced owner gets everything back through the ordinary
    // withdrawal. (The synthetic fillers are taken out first only to keep
    // two thousand epoch boundaries cheap; they have no owner key anyway.)
    for index in 1..state.delegations.len() - 1 {
        let id = state.delegations[index].delegator;
        state.delegations[index] = Delegation::PRUNED;
        state.funded_delegation_owners.remove(&id);
        state.funded_delegation_lifecycle.remove(&(index as u32));
    }
    while state.funded_delegation_lifecycle[&0].0 == u64::MAX {
        state = state.close_epoch();
    }
    let mature = state.funded_delegation_lifecycle[&0].0 + staking::WITHDRAWAL_DELAY_EPOCHS;
    while state.epoch < mature {
        state = state.close_epoch();
    }
    let withdrawal = signed_withdrawal(&state, &first, 0);
    let paid_before = state.balance_sat(&withdrawal.destination_script_hash);
    let charge = state
        .apply_funded_delegation_withdrawal(&withdrawal, base_fee, &AuthVerifier)
        .unwrap();
    let paid = state.balance_sat(&withdrawal.destination_script_hash) - paid_before;
    assert!(paid + charge.base_fee_sat >= small, "principal back, less only the fee");
    assert!(state.funded_delegation_lifecycle.get(&0).map_or(true, |entry| entry.1));
}

// ── Security review round 2, DET-3: one commission update per epoch ─────────
// (`params::COMMISSION_UPDATE_LIMIT_ACTIVATION_EPOCH`)

use crate::params::commission_update_limit_rehearsal;

#[test]
fn commission_update_limit_gate_is_inert() {
    assert_eq!(crate::params::COMMISSION_UPDATE_LIMIT_ACTIVATION_EPOCH, u64::MAX);
    for epoch in [0, 4_669, 7_400, u64::MAX - 1, u64::MAX] {
        assert!(!crate::params::commission_update_limit_active(epoch));
    }
    let _limit = commission_update_limit_rehearsal::open();
    assert!(crate::params::commission_update_limit_active(0));
}

/// Inert: the rule is what it was. Two signed values of one epoch can be
/// applied in turn any number of times, nothing is recorded, and the state
/// (root included) is what it is without this change.
#[test]
fn inert_commission_limit_records_nothing_and_keeps_todays_rule() {
    let _gate = funded_delegation_rehearsal::open();
    let (mut state, _) = fixture();
    state.validators.get_mut(&0).unwrap().commission_bps = 0;
    let to_500 = commission_update(&state, 500);
    let to_300 = commission_update(&state, 300);
    let leaves = state.state_tree().len();
    for _ in 0..3 {
        state.apply_validator_commission_update(&to_500, &AuthVerifier).unwrap();
        state.apply_validator_commission_update(&to_300, &AuthVerifier).unwrap();
    }
    assert_eq!(state.validators[&0].commission_bps, 300);
    assert!(state.commission_update_epochs.is_empty());
    assert_eq!(state.state_tree().len(), leaves, "no leaf was added");
    // The component is absent from the root while empty: recording an
    // update is the only thing that moves it.
    let mut recorded = state.clone();
    recorded.commission_update_epochs.insert(0, recorded.epoch);
    assert_ne!(recorded.state_root(), state.state_root());
    assert_eq!(recorded.state_tree().len(), leaves + 1);
    // A boundary leaves nothing behind either.
    assert!(state.close_epoch().commission_update_epochs.is_empty());
}

/// Armed: the second signed value of the epoch is refused whoever sends it,
/// in the same block or a later one, so neither message can be replayed;
/// the next epoch starts clean.
#[test]
fn armed_commission_limit_admits_one_update_per_validator_per_epoch() {
    let _gate = funded_delegation_rehearsal::open();
    let _limit = commission_update_limit_rehearsal::open();
    let (mut state, _) = fixture();
    for record in state.validators.values_mut() {
        record.commission_bps = 0;
    }
    let to_500 = commission_update(&state, 500);
    let to_300 = commission_update(&state, 300);
    let clean_root = state.state_root();
    state.apply_validator_commission_update(&to_500, &AuthVerifier).unwrap();
    assert_eq!(state.commission_update_epochs, BTreeMap::from([(0, state.epoch)]));

    let before = state.clone();
    for replayed in [&to_300, &to_500, &to_300] {
        let refusal = state.apply_validator_commission_update(replayed, &AuthVerifier).unwrap_err();
        assert!(matches!(
            refusal,
            FundedDelegationReject::CommissionAlreadyUpdated | FundedDelegationReject::Commission
        ));
        assert_eq!(state, before, "a refusal must not touch state");
    }
    assert_eq!(
        state.apply_validator_commission_update(&to_300, &AuthVerifier),
        Err(FundedDelegationReject::CommissionAlreadyUpdated)
    );
    assert_eq!(state.validators[&0].commission_bps, 500);

    // Another validator still has its own update this epoch.
    let mut other = commission_update(&state, 700);
    other.validator = 1;
    other.signature = auth_sign(&state.validators[&1].pubkey, &other.signing_root());
    state.apply_validator_commission_update(&other, &AuthVerifier).unwrap();
    assert_eq!(state.commission_update_epochs.len(), 2);

    // The record is committed: a state that forgot it has another root.
    let mut forgetful = state.clone();
    forgetful.commission_update_epochs.clear();
    assert_ne!(forgetful.state_root(), state.state_root());
    assert_eq!(state.state_tree().len(), forgetful.state_tree().len() + 2);
    assert_ne!(state.state_root(), clean_root);

    // The boundary empties it, and the new epoch admits one update again.
    let mut next = state.close_epoch();
    assert!(next.commission_update_epochs.is_empty());
    assert_eq!(next.state_tree().len(), forgetful.close_epoch().state_tree().len());
    assert_eq!(next.state_root(), forgetful.close_epoch().state_root());
    let later = commission_update(&next, 300);
    next.apply_validator_commission_update(&later, &AuthVerifier).unwrap();
    assert_eq!(next.validators[&0].commission_bps, 300);
    let back = commission_update(&next, 500);
    assert_eq!(
        next.apply_validator_commission_update(&back, &AuthVerifier),
        Err(FundedDelegationReject::CommissionAlreadyUpdated)
    );
}

/// The record survives the local restart cache (a node restored in the
/// middle of an epoch must refuse what the others refuse), and a state
/// without it keeps exactly the cache bytes it had.
#[test]
#[cfg(feature = "local-state-cache")]
fn local_cache_round_trips_the_commission_update_record() {
    let _gate = funded_delegation_rehearsal::open();
    let (mut state, _) = fixture();
    state.validators.get_mut(&0).unwrap().commission_bps = 0;
    state.slot = state.epoch * SLOTS_PER_EPOCH;
    let header_for = |state: &CommittedState| BlockHeaderV4 {
        version: BLOCK_VERSION_V4, parent: [0; 32], state_root: state.compute_root(),
        body_root: [0; 32], slot: state.slot, proposer_index: 0,
        randao_reveal: [0; 32], randao_mix: state.randao_mix,
        justified_root: [0; 32], finalized_root: [0; 32],
        attestation_root: [0; 32], coherence_root: [0; 32],
    };
    let plain = state.encode_local_cache().unwrap();
    assert_eq!(plain, state.encode_local_cache_owned_reference().unwrap(), "no section while empty");

    let _limit = commission_update_limit_rehearsal::open();
    let update = commission_update(&state, 500);
    state.apply_validator_commission_update(&update, &AuthVerifier).unwrap();
    let header = header_for(&state);
    state.head = header.id();
    let bytes = state.encode_local_cache().unwrap();
    assert!(bytes.len() > plain.len());
    let restored = CommittedState::decode_local_cache(&bytes, &header).unwrap();
    assert_eq!(restored, state);
    assert_eq!(restored.commission_update_epochs, BTreeMap::from([(0, state.epoch)]));
    // Dropping the section yields a state the header does not commit to.
    let section = crate::wire_alloc::local_cache::COMMISSION_UPDATES;
    let cut = bytes.windows(section.len()).rposition(|w| w == section).unwrap();
    assert!(CommittedState::decode_local_cache(&bytes[..cut], &header).is_err());
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

// GIP-0002, WT-04: the signed commission cap (`FundedDelegateV2`, tag 0x1C)
// behind `params::DELEGATION_COMMISSION_CAP_ACCEPT_EPOCH` and
// `params::DELEGATION_COMMISSION_CAP_ENFORCE_EPOCH`.

use crate::params::wallet_consensus_rehearsal;

const CAP_ACCEPT: u64 = 10;
const CAP_ENFORCE: u64 = 20;
const BASE_FEE: u128 = fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS;

/// The capped form of `v1`'s fields spending `input`, signed.
fn capped_delegate(v1: &FundedDelegate, input: FundingInput, max_commission_bps: u128) -> FundedDelegateV2 {
    let mut tx = FundedDelegateV2 { request: v1.clone(), max_commission_bps };
    tx.request.inputs = vec![input];
    tx.request.funding_signature = Vec::new();
    tx.request.tx_bytes = tx.reserved_tx_bytes();
    tx.request.funding_signature = auth_sign(&tx.request.funding_pubkey, &tx.signing_root());
    tx
}

/// A state at `epoch` holding one coin for a capless request and one for
/// its capped twin (same owner, same validator, cap `max_commission_bps`).
fn cap_fixture(epoch: u64, max_commission_bps: u128) -> (CommittedState, FundedDelegate, FundedDelegateV2) {
    let v1 = funded_delegate(FundingInput { txid: [0x31; 32], vout: 0 });
    let v2 = capped_delegate(&v1, FundingInput { txid: [0x32; 32], vout: 0 }, max_commission_bps);
    let owner: [u8; 32] = Sha3_256::digest(&v1.funding_pubkey).into();
    let coin = |input: &FundingInput, value: u128| crate::state_root::EutxoEntry {
        txid: input.txid,
        vout: input.vout,
        value: value.try_into().unwrap(),
        script_hash: owner,
    };
    let opening = [
        coin(&v1.inputs[0], v1.required_funding_sat().unwrap()),
        coin(&v2.request.inputs[0], v2.required_funding_sat().unwrap()),
    ];
    let (_, mut state, _) = setup_with(8, AuthVerifier, &opening);
    state.admission_network_domain = Some(v1.network_domain);
    state.epoch = epoch;
    (state, v1, v2)
}

fn apply_v1(state: &CommittedState, tx: &FundedDelegate) -> Result<CommittedState, FundedDelegationReject> {
    let mut next = state.clone();
    next.apply_funded_delegate(tx, BASE_FEE, &AuthVerifier).map(|_| next)
}

fn apply_v2(state: &CommittedState, tx: &FundedDelegateV2) -> Result<CommittedState, FundedDelegationReject> {
    let mut next = state.clone();
    next.apply_funded_delegate_v2(tx, BASE_FEE, &AuthVerifier).map(|_| next)
}

/// TRIPWIRE. Both ends of the window ship `u64::MAX`; arming is an owner
/// decision (GIP-0002).
#[cfg(not(feature = "wallet-consensus-rehearsal"))]
#[test]
fn delegation_commission_cap_window_is_inert() {
    use crate::params::DualAcceptanceGate;
    assert_eq!(crate::params::DELEGATION_COMMISSION_CAP_ACCEPT_EPOCH, u64::MAX);
    assert_eq!(crate::params::DELEGATION_COMMISSION_CAP_ENFORCE_EPOCH, u64::MAX);
    assert_eq!(crate::params::DELEGATION_COMMISSION_CAP_GATE, DualAcceptanceGate::INERT);
    assert_eq!(crate::params::delegation_commission_cap_gate(), DualAcceptanceGate::INERT);
}

/// With the window unset the capped tag is refused at every epoch without
/// touching state, and the capless request is admitted exactly as it is
/// with the window armed but not yet reached: same post-state root.
#[test]
fn with_the_cap_window_unset_only_the_capless_request_is_valid() {
    let _gate = funded_delegation_rehearsal::open();
    for epoch in [0, 5, CAP_ENFORCE + 5] {
        let (state, v1, v2) = cap_fixture(epoch, 10_000);
        assert_eq!(apply_v2(&state, &v2).unwrap_err(), FundedDelegationReject::CommissionCapNotActive);
        let unset = apply_v1(&state, &v1).unwrap();
        let _armed_later = wallet_consensus_rehearsal::arm_commission_cap(epoch + 1, epoch + 91);
        let before_window = apply_v1(&state, &v1).unwrap();
        assert_eq!(unset.state_root(), before_window.state_root());
        assert_eq!(unset, before_window);
    }
}

/// The capless wire form is frozen: tag 0x0E, the V1 domain, and exactly
/// the field sequence below, re-encoded here independently of the encoder.
#[test]
fn the_capless_request_keeps_its_bytes_and_its_signing_root() {
    let tx = funded_delegate(FundingInput { txid: [0x31; 32], vout: 7 });
    let mut intent = vec![0x0e];
    intent.extend_from_slice(&tx.network_domain);
    intent.extend_from_slice(&tx.valid_until_epoch.to_le_bytes());
    intent.extend_from_slice(&(tx.funding_pubkey.len() as u32).to_le_bytes());
    intent.extend_from_slice(&tx.funding_pubkey);
    intent.extend_from_slice(&1u32.to_le_bytes());
    intent.extend_from_slice(&[0x31; 32]);
    intent.extend_from_slice(&7u32.to_le_bytes());
    intent.extend_from_slice(&tx.validator_pubkey_hash);
    intent.extend_from_slice(&tx.amount_sat.to_le_bytes());
    intent.extend_from_slice(&tx.change.value.to_le_bytes());
    intent.extend_from_slice(&tx.change.script_hash);
    intent.extend_from_slice(&tx.max_base_fee_millisat_per_gas.to_le_bytes());
    intent.extend_from_slice(&tx.tip_millisat_per_gas.to_le_bytes());
    intent.extend_from_slice(&tx.tx_bytes.to_le_bytes());
    let mut root = Sha3_256::new();
    root.update(b"BLOCH:DELEGATION:FUND:V1");
    root.update(&intent);
    let root: [u8; 32] = root.finalize().into();
    assert_eq!(tx.signing_root(), root);
    assert_eq!(tx.reserved_tx_bytes(), intent.len() as u64 + 4 + ADMISSION_PQ_SIGNATURE_MAX as u64);
    let mut wire = intent.clone();
    wire.extend_from_slice(&(tx.funding_signature.len() as u32).to_le_bytes());
    wire.extend_from_slice(&tx.funding_signature);
    assert_eq!(PosTransaction::FundedDelegate(tx.clone()).canonical_bytes(), wire);
    assert_eq!(PosTransaction::from_canonical_bytes(&wire).unwrap(), PosTransaction::FundedDelegate(tx.clone()));

    // The capped form: tag 0x1C, the same fields, the cap, the V2 domain.
    let v2 = capped_delegate(&tx, FundingInput { txid: [0x31; 32], vout: 7 }, 750);
    let mut intent_v2 = intent.clone();
    intent_v2[0] = 0x1c;
    let tail = intent_v2.len() - 8;
    intent_v2[tail..].copy_from_slice(&v2.request.tx_bytes.to_le_bytes());
    intent_v2.extend_from_slice(&750u128.to_le_bytes());
    assert_eq!(v2.request.tx_bytes, tx.tx_bytes + 16);
    let mut root_v2 = Sha3_256::new();
    root_v2.update(b"BLOCH:DELEGATION:FUND:V2");
    root_v2.update(&intent_v2);
    let root_v2: [u8; 32] = root_v2.finalize().into();
    assert_eq!(v2.signing_root(), root_v2);
    let mut wire_v2 = intent_v2;
    wire_v2.extend_from_slice(&(v2.request.funding_signature.len() as u32).to_le_bytes());
    wire_v2.extend_from_slice(&v2.request.funding_signature);
    let encoded = PosTransaction::FundedDelegateV2(v2.clone());
    assert_eq!(encoded.canonical_bytes(), wire_v2);
    assert_eq!(PosTransaction::from_canonical_bytes(&wire_v2).unwrap(), encoded);
    assert_ne!(encoded.txid(), PosTransaction::FundedDelegate(tx).txid());
    // Every strict prefix is refused, never mis-decoded.
    for cut in [1, 33, wire_v2.len() - v2.request.funding_signature.len() - 5, wire_v2.len() - 1] {
        assert!(PosTransaction::from_canonical_bytes(&wire_v2[..cut]).is_err(), "prefix {cut}");
    }
}

/// The window, epoch by epoch: one before acceptance, at it, the last
/// before enforcement, at it, after.
#[test]
fn each_delegation_form_is_valid_exactly_inside_its_side_of_the_window() {
    let _gate = funded_delegation_rehearsal::open();
    let _armed = wallet_consensus_rehearsal::arm_commission_cap(CAP_ACCEPT, CAP_ENFORCE);
    for (epoch, v1_verdict, v2_verdict) in [
        (CAP_ACCEPT - 1, None, Some(FundedDelegationReject::CommissionCapNotActive)),
        (CAP_ACCEPT, None, None),
        (CAP_ENFORCE - 1, None, None),
        (CAP_ENFORCE, Some(FundedDelegationReject::CommissionCapRequired), None),
        (CAP_ENFORCE + 1, Some(FundedDelegationReject::CommissionCapRequired), None),
    ] {
        let (state, v1, v2) = cap_fixture(epoch, 500);
        assert_eq!(apply_v1(&state, &v1).err(), v1_verdict, "capless at epoch {epoch}");
        assert_eq!(apply_v2(&state, &v2).err(), v2_verdict, "capped at epoch {epoch}");
        // Through the dispatcher too, with the same verdicts.
        let total = state.total_active_stake_sat();
        for (tx, verdict) in [
            (PosTransaction::FundedDelegate(v1.clone()), v1_verdict),
            (PosTransaction::FundedDelegateV2(v2.clone()), v2_verdict),
        ] {
            let got = state.clone().apply_transaction(&tx, total, BASE_FEE, &AuthVerifier).err();
            assert_eq!(got, verdict.map(TxReject::FundedDelegation), "{tx:?} at epoch {epoch}");
        }
        // A refusal leaves the state as it was.
        let mut untouched = state.clone();
        let _ = untouched.apply_funded_delegate(&v1, BASE_FEE, &AuthVerifier);
        if v1_verdict.is_some() {
            assert_eq!(untouched, state);
        }
    }
}

/// Both forms create the same position: the cap is checked at admission and
/// leaves nothing in state, so the state root has no new component.
#[test]
fn a_capped_request_creates_the_position_a_capless_one_creates() {
    let _gate = funded_delegation_rehearsal::open();
    let _armed = wallet_consensus_rehearsal::arm_commission_cap(CAP_ACCEPT, CAP_ENFORCE);
    let (state, v1, v2) = cap_fixture(CAP_ACCEPT, 500);
    let with_v1 = apply_v1(&state, &v1).unwrap();
    let with_v2 = apply_v2(&state, &v2).unwrap();
    assert_eq!(with_v1.delegations, with_v2.delegations);
    assert_eq!(with_v1.funded_delegation_owners, with_v2.funded_delegation_owners);
    let position = with_v2.delegations.last().unwrap();
    assert_eq!(position.amount_sat, v2.request.amount_sat);
    assert_eq!(position.requested_epoch, CAP_ACCEPT + 1);
    // The funding coin is spent and the change exists under the V2 txid.
    assert!(with_v2.utxo(&v2.request.inputs[0].txid, 0).is_none());
    let change = with_v2.utxo(&PosTransaction::FundedDelegateV2(v2.clone()).txid(), 0).unwrap();
    assert_eq!(change.script_hash, v2.request.change.script_hash);
}

/// **WT-04, the griefing.** The delegator reads a 5% commission and signs.
/// The validator, with nothing delegated to it yet, raises its commission
/// to 100% before the request lands.
#[test]
fn a_commission_raised_before_admission_does_not_bind_a_capped_request() {
    let _gate = funded_delegation_rehearsal::open();
    let _armed = wallet_consensus_rehearsal::arm_commission_cap(CAP_ACCEPT, CAP_ENFORCE);
    let (mut state, v1, v2) = cap_fixture(CAP_ACCEPT, 500);
    assert_eq!(state.validators[&0].commission_bps, 500);

    // The raise is valid: no delegation targets the validator.
    let raise = commission_update(&state, 10_000);
    state.apply_validator_commission_update(&raise, &AuthVerifier).unwrap();
    assert_eq!(state.validators[&0].commission_bps, 10_000);

    // The capless request is admitted at 100%: the defect, still reachable
    // until enforcement.
    let trapped = apply_v1(&state, &v1).unwrap();
    assert_eq!(trapped.delegations.len(), 1);
    assert_eq!(trapped.validators[&0].commission_bps, 10_000);

    // The capped request is refused, and nothing was spent: the coin is
    // there and no position exists.
    assert_eq!(apply_v2(&state, &v2).unwrap_err(), FundedDelegationReject::CommissionAboveCap);
    let mut refused = state.clone();
    let _ = refused.apply_funded_delegate_v2(&v2, BASE_FEE, &AuthVerifier);
    assert_eq!(refused, state);
    assert!(state.utxo(&v2.request.inputs[0].txid, 0).is_some());

    // The cap is inclusive, and one basis point above it is refused.
    for (commission, admitted) in [(500, true), (501, false), (0, true), (10_000, false)] {
        let mut at = state.clone();
        at.validators.get_mut(&0).unwrap().commission_bps = commission;
        assert_eq!(apply_v2(&at, &v2).is_ok(), admitted, "commission {commission} against a cap of 500");
    }
}

/// Once the capped request is admitted the commission cannot rise: in the
/// same epoch, while the position is still queued, and afterwards. So the
/// signed value bounds the rate for the life of the position.
#[test]
fn after_admission_the_commission_cannot_rise_above_the_signed_cap() {
    let _gate = funded_delegation_rehearsal::open();
    let _armed = wallet_consensus_rehearsal::arm_commission_cap(CAP_ACCEPT, CAP_ENFORCE);
    let (state, _v1, v2) = cap_fixture(CAP_ACCEPT, 500);
    let mut state = apply_v2(&state, &v2).unwrap();
    for epoch in [CAP_ACCEPT, CAP_ACCEPT + 1, CAP_ACCEPT + 40] {
        state.epoch = epoch;
        let before = state.clone();
        for commission in [501, 10_000] {
            let raise = commission_update(&state, commission);
            assert_eq!(
                state.apply_validator_commission_update(&raise, &AuthVerifier),
                Err(FundedDelegationReject::CommissionIncreaseWithDelegations),
                "raise to {commission} at epoch {epoch}"
            );
        }
        assert_eq!(state, before);
    }
    // Lowering stays possible.
    let lower = commission_update(&state, 400);
    state.apply_validator_commission_update(&lower, &AuthVerifier).unwrap();
    assert_eq!(state.validators[&0].commission_bps, 400);
}

/// Negative cases: the cap is inside the signature, the two forms do not
/// authorise each other, and a malformed capped request is refused before
/// anything is read from state.
#[test]
fn a_capped_request_cannot_be_altered_downgraded_or_malformed() {
    let _gate = funded_delegation_rehearsal::open();
    let _armed = wallet_consensus_rehearsal::arm_commission_cap(CAP_ACCEPT, CAP_ENFORCE);
    let (state, v1, v2) = cap_fixture(CAP_ACCEPT, 500);
    use FundedDelegationReject as R;

    // Raising the cap after signing (what a validator would want).
    let mut raised = v2.clone();
    raised.max_commission_bps = 10_000;
    assert_eq!(apply_v2(&state, &raised).unwrap_err(), R::Signature);

    // A cap above 100% is not a cap.
    let mut absurd = capped_delegate(&v1, v2.request.inputs[0].clone(), 10_001);
    assert_eq!(absurd.validate_shape(), Err(R::Shape));
    assert_eq!(apply_v2(&state, &absurd).unwrap_err(), R::Shape);
    absurd.max_commission_bps = u128::MAX;
    assert_eq!(apply_v2(&state, &absurd).unwrap_err(), R::Shape);

    // Stripping the cap: the capped signature under the capless form, with
    // the capless form's own byte reservation so only the signature decides.
    let mut stripped = v2.request.clone();
    stripped.tx_bytes = stripped.reserved_tx_bytes();
    assert_ne!(stripped.signing_root(), v2.signing_root());
    assert!(matches!(apply_v1(&state, &stripped).unwrap_err(), R::Signature | R::Conservation));
    stripped.funding_signature = v2.request.funding_signature.clone();
    assert_ne!(
        PosTransaction::FundedDelegate(stripped.clone()).spend_signing_root(),
        PosTransaction::FundedDelegateV2(v2.clone()).spend_signing_root()
    );
    // Adding a cap to a capless signature.
    let mut grafted = FundedDelegateV2 { request: v1.clone(), max_commission_bps: 500 };
    assert_eq!(apply_v2(&state, &grafted).unwrap_err(), R::Shape, "capless byte reservation");
    grafted.request.tx_bytes = grafted.reserved_tx_bytes();
    assert!(matches!(apply_v2(&state, &grafted).unwrap_err(), R::Signature | R::Conservation));

    // The capless reservation under the capped tag is a shape error.
    let mut short = v2.clone();
    short.request.tx_bytes -= 16;
    assert_eq!(short.validate_shape(), Err(R::Shape));

    // Another network, an expired request, an unknown validator.
    let mut elsewhere = state.clone();
    elsewhere.admission_network_domain = Some([0x92; 32]);
    assert_eq!(apply_v2(&elsewhere, &v2).unwrap_err(), R::Network);
    let mut late = state.clone();
    late.epoch = v2.request.valid_until_epoch + 1;
    assert_eq!(apply_v2(&late, &v2).unwrap_err(), R::Expired);
    let mut nobody = v2.clone();
    nobody.request.validator_pubkey_hash = [0x77; 32];
    nobody.request.funding_signature = auth_sign(&nobody.request.funding_pubkey, &nobody.signing_root());
    assert_eq!(apply_v2(&state, &nobody).unwrap_err(), R::Validator);

    // Funded delegation itself not active: refused before the cap gate.
    drop(_gate);
    assert_eq!(apply_v2(&state, &v2).unwrap_err(), R::NotActive);
}
