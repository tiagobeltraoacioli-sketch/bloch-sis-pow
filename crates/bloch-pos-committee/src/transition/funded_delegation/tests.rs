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
