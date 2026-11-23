// AUDIT-L1L2-20261123 L1S-01. A funded position that is past its nominal
// cool-down (deactivate + 32 epochs) but has not finished draining still
// carries consensus weight and still earns, and the slashing exposure view
// masked it ineligible. Behind `SLASH_DRAINING_STAKE_ACTIVATION_EPOCH` it is
// charged on its activated amount. Inert as shipped.

/// Drives a 20M BLCH funded position through the real transactions
/// (FundedDelegate, full warm-up, FundedUndelegate) and on to the first
/// epoch past the nominal cool-down, where it is `Inactive` and still
/// draining. Returns the state, the delegator id and the activated amount.
fn fix_l1s01_draining_past_the_cooldown() -> (CommittedState, u32, u128) {
    let (mut state, _first) = fixture();
    let base_fee = fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS;
    let amount = 20_000_000u128 * tokenomics_v4::SAT_PER_BLOCH;
    let tx = provision_delegation(&mut state, 0x61, 0, amount);
    state.apply_funded_delegate(&tx, base_fee, &AuthVerifier).unwrap();
    let delegator = state.delegations[0].delegator;
    while delegation::Registry::resolve(&state.delegations, state.epoch).activated_sat(&state.delegations[0]) < amount {
        state = state.close_epoch();
    }
    let mut exit = FundedUndelegate {
        network_domain: tx.network_domain,
        epoch: state.epoch,
        delegator_id: delegator,
        position: 0,
        funding_pubkey: tx.funding_pubkey.clone(),
        signature: Vec::new(),
    };
    exit.signature = auth_sign(&exit.funding_pubkey, &exit.signing_root());
    state.apply_funded_undelegate(&exit, &AuthVerifier).unwrap();
    let deactivate = state.delegations[0].deactivate_epoch.unwrap();
    while state.epoch < deactivate + delegation::COOLDOWN_EPOCHS {
        state = state.close_epoch();
    }
    let registry = delegation::Registry::resolve(&state.delegations, state.epoch);
    assert_eq!(registry.state_of(&state.delegations[0]), delegation::StakeState::Inactive);
    let still_active = registry.activated_sat(&state.delegations[0]);
    assert!(still_active > 0, "the churn budget has not finished draining the position");
    (state, delegator, still_active)
}

fn fix_l1s01_slash(state: &CommittedState) -> CommittedState {
    let mut slashed = state.clone();
    let roster = slashed.consensus_roster_at(slashed.epoch);
    slashed.apply_slashing_evidence(&double_vote_evidence(0), 1, &roster, &OkVerifier).unwrap();
    assert!(slashed.validators[&0].slashed);
    slashed
}

#[test]
fn l1s01_fix_draining_stake_stays_slashable_until_it_has_drained() {
    assert_eq!(crate::params::SLASH_DRAINING_STAKE_ACTIVATION_EPOCH, u64::MAX);
    assert!(!crate::params::slash_draining_stake_active(u64::MAX - 1));
    let _gate = funded_delegation_rehearsal::open();
    let (mut state, delegator, still_active) = fix_l1s01_draining_past_the_cooldown();
    // The stake under test really carries the validator's weight.
    let weight = state.consensus_roster_at(state.epoch).iter().find(|v| v.index == 0).unwrap().effective_stake as u128;
    assert_eq!(weight, state.validators[&0].staked_sat + still_active);

    // Inert (as shipped): the finding, the delegator loses nothing.
    let inert = fix_l1s01_slash(&state);
    assert_eq!(inert.delegator_slash_loss_sat(delegator), 0);
    {
        // Armed: charged on the activated amount, and the operator's own
        // loss is what it was.
        let _fix = crate::params::slash_draining_stake_rehearsal::open();
        let armed = fix_l1s01_slash(&state);
        let loss = armed.delegator_slash_loss_sat(delegator);
        assert!(loss > 0 && loss <= still_active, "priced on the activated amount");
        assert_eq!(armed.validators[&0].staked_sat, inert.validators[&0].staked_sat);
    }
    // Fully drained: no weight, no loss, with or without the gate.
    while delegation::Registry::resolve(&state.delegations, state.epoch).activated_sat(&state.delegations[0]) > 0 {
        state = state.close_epoch();
    }
    assert_eq!(fix_l1s01_slash(&state).delegator_slash_loss_sat(delegator), 0);
    let _fix = crate::params::slash_draining_stake_rehearsal::open();
    assert_eq!(fix_l1s01_slash(&state).delegator_slash_loss_sat(delegator), 0);
}
