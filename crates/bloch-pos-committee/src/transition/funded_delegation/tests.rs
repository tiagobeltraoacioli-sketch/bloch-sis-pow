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
