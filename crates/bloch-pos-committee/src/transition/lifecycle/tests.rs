// SPDX-License-Identifier: AGPL-3.0-or-later

fn mature(state: &mut CommittedState, funded: bool, principal: u128, accrual: u128) {
    let rec = state.validators.get_mut(&0).unwrap();
    rec.staked_sat = principal + accrual;
    rec.exit_epoch = 1;
    rec.withdrawable_epoch = 20;
    rec.withdrawal_credentials = vec![0x55; 32];
    state.genesis_principal_sat.insert(0, principal);
    if funded {
        state.funded_validators.insert(0);
    }
    state.epoch = 20;
}

fn crank(state: &mut CommittedState) -> Result<fee_market::TxCharge, TxReject> {
    let _gate = crate::params::rehearsal::withdrawal_gate_open_guard();
    {
        let tx = PosTransaction::Withdraw { validator: 0 };
        state.apply_transaction(&tx, 1_000_000, 0, &OkVerifier)
    }
}

#[test]
fn withdrawal_pays_funded_bonds_and_only_genesis_accrual() {
    for funded in [false, true] {
        let (_, mut state, _) = setup(8);
        mature(&mut state, funded, 100_000, 500);
        let before = state.total_unspent_sat();
        let issued = state.issued_sat();
        let charge = crank(&mut state).unwrap();
        let payout = if funded { 100_500 } else { 500 };
        assert_eq!(state.total_unspent_sat() - before, payout);
        assert_eq!(state.written_off_sat(), 100_500 - payout);
        assert_eq!(state.issued_sat(), issued);
        assert_eq!(state.validators[&0].staked_sat, 0);
        assert!(charge.gas > 0);
        assert_eq!(charge.tx_bytes, 5);
        assert_eq!(charge.base_fee_sat, 0);
        let root = state.compute_root();
        assert!(crank(&mut state).is_err());
        assert_eq!(state.compute_root(), root);
    }
}

#[test]
fn withdrawal_failure_is_atomic_at_each_boundary() {
    let (_, mut base, _) = setup(8);
    mature(&mut base, false, 100_000, 500);
    let mutations: &[fn(&mut CommittedState)] = &[
        |s| s.epoch = 19,
        |s| s.validators.get_mut(&0).unwrap().exit_epoch = u64::MAX,
        |s| s.validators.get_mut(&0).unwrap().withdrawable_epoch = u64::MAX,
        |s| {
            s.validators
                .get_mut(&0)
                .unwrap()
                .withdrawal_credentials
                .pop()
                .map(|_| ())
                .unwrap()
        },
        |s| s.validators.get_mut(&0).unwrap().slashed = true,
        |s| s.written_off_sat = u128::MAX,
        |s| {
            s.funded_validators.insert(0);
            s.validators.get_mut(&0).unwrap().staked_sat = u128::from(u64::MAX) + 1;
        },
        |s| {
            s.eutxos.insert(crate::state_root::EutxoEntry {
                txid: PosTransaction::Withdraw { validator: 0 }.txid(),
                vout: 0,
                value: 1,
                script_hash: [7; 32],
            });
        },
    ];
    for mutate in mutations {
        let mut state = base.clone();
        mutate(&mut state);
        let root = state.compute_root();
        assert!(crank(&mut state).is_err());
        assert_eq!(root, state.compute_root());
    }
    assert!(base
        .apply_transaction(
            &PosTransaction::Withdraw { validator: 0 },
            0,
            0,
            &OkVerifier
        )
        .is_err());
}

#[test]
fn withdrawal_remembers_slashes_without_confiscating_later_rewards() {
    let (_, mut state, _) = setup(8);
    mature(&mut state, false, 100_000, 500);
    state.validators.get_mut(&0).unwrap().slashed = true;
    state.stake_low_water.insert(0, 60_000);
    // A post-penalty reward is backed; the original principal must not be
    // subtracted a second time after the penalty already destroyed it.
    state.validators.get_mut(&0).unwrap().staked_sat = 60_700;
    let before = state.total_unspent_sat();
    crank(&mut state).unwrap();
    assert_eq!(state.total_unspent_sat() - before, 700);
    assert_eq!(state.written_off_sat(), 60_000);
}

#[test]
fn pure_writeoff_does_not_create_a_zero_utxo() {
    let (_, mut state, _) = setup(8);
    mature(&mut state, false, 100_000, 0);
    crank(&mut state).unwrap();
    assert!(state
        .utxo(&PosTransaction::Withdraw { validator: 0 }.txid(), 0)
        .is_none());
    assert_eq!(state.written_off_sat(), 100_000);
    assert!(crank(&mut state).is_err(), "a zero-payout withdrawal is one-shot too");
}

#[test]
fn lifecycle_metadata_is_committed_and_empty_at_genesis() {
    let (_, base, _) = setup(8);
    assert_eq!(base.written_off_sat, 0);
    assert!(base.stake_low_water.is_empty());
    assert!(base.randao_generations.is_empty());
    assert!(base.funded_validators.is_empty());
    let root = base.compute_root();
    for field in 0..4 {
        let mut state = base.clone();
        match field {
            0 => state.written_off_sat = 1,
            1 => {
                state.stake_low_water.insert(0, 0);
            }
            2 => {
                state.randao_generations.insert(0, 1);
            }
            _ => {
                state.funded_validators.insert(0);
            }
        }
        assert_ne!(root, state.compute_root());
    }
}

#[test]
fn slashing_records_floor_caps_reward_and_extends_withdrawal_lock() {
    let _slash = crate::params::rehearsal::slashing_gate_open_guard();
    let _withdraw = crate::params::rehearsal::withdrawal_gate_open_guard();
    for funded in [false, true] {
        let (_, mut state, _) = setup(8);
        let principal = state.validators[&0].staked_sat;
        state.validators.get_mut(&0).unwrap().withdrawal_credentials = vec![0x55; 32];
        if funded {
            state.funded_validators.insert(0);
        }
        state.epoch = 5;
        state.validators.get_mut(&0).unwrap().withdrawable_epoch = 7;
        state
            .apply_slashing_evidence(&double_vote_evidence(0), 1, principal * 8, &OkVerifier)
            .unwrap();
        let rec = state.validator_record(0).unwrap();
        assert!(rec.staked_sat < principal);
        assert_eq!(state.stake_low_water[&0], rec.staked_sat);
        assert_eq!(rec.withdrawable_epoch, 5 + staking::WITHDRAWAL_DELAY_EPOCHS);
        let reward = state.pending_fee_rewards.get(&1).copied().unwrap_or(0);
        if funded {
            assert!(reward > 0);
        } else {
            assert_eq!(reward, 0, "unissued stake cannot fund a reward");
        }
        state.epoch = rec.withdrawable_epoch - 1;
        assert!(crank(&mut state).is_err());
        state.epoch += 1;
        let before = state.total_unspent_sat();
        crank(&mut state).unwrap();
        assert_eq!(
            state.total_unspent_sat() - before,
            if funded { rec.staked_sat } else { 0 }
        );
    }
}

#[test]
fn genesis_principal_is_per_validator_and_zero_floor_is_not_absence() {
    let (_, mut state, _) = setup(8);
    mature(&mut state, false, 70_000, 9);
    assert_eq!(state.withdrawable_sat(0), 9);
    state.validators.get_mut(&0).unwrap().slashed = true;
    assert!(state.is_write_off_indeterminate(0));
    state.stake_low_water.insert(0, 0);
    assert!(!state.is_write_off_indeterminate(0));
    state.validators.get_mut(&0).unwrap().staked_sat = 23;
    assert_eq!(state.withdrawable_sat(0), 23);
}
