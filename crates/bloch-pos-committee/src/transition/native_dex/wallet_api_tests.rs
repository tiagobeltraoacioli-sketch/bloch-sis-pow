use super::*;
use super::{
    consensus_pool,
    tests::{BoundVerifier, DOMAIN},
};
use crate::transition::native_wallet::WalletOperation;
use sha3::{Digest, Sha3_256};

fn populated() -> CommittedState {
    consensus_pool::tests::fixtures(crate::fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS)
        .pop()
        .unwrap()
        .0
}
#[test]
fn official_wallet_requires_committed_activation_domain_and_native_component() {
    let mut state = populated();
    assert!(state
        .authorize_native_wallet(DOMAIN, WalletOperation::View)
        .is_err());
    crate::params::native_state_rehearsal::run(0, || {
        assert!(state
            .authorize_native_wallet(DOMAIN, WalletOperation::View)
            .is_ok());
        assert!(state
            .authorize_native_wallet([0; 32], WalletOperation::View)
            .is_err());
        assert!(state
            .authorize_native_wallet([99; 32], WalletOperation::View)
            .is_err());
        assert!(state
            .authorize_native_wallet(DOMAIN, WalletOperation::Pool)
            .is_err());
        assert!(state
            .authorize_native_wallet(DOMAIN, WalletOperation::Withdrawal)
            .is_err());
        crate::params::native_pool_rehearsal::run(state.epoch + 1, || {
            assert!(state
                .authorize_native_wallet(DOMAIN, WalletOperation::Pool)
                .is_err());
        });
        crate::params::native_pool_rehearsal::run(0, || {
            assert!(state
                .authorize_native_wallet(DOMAIN, WalletOperation::Pool)
                .is_ok());
            assert!(state
                .authorize_native_wallet(DOMAIN, WalletOperation::Withdrawal)
                .is_err());
        });
        crate::params::native_withdrawal_rehearsal::run(0, || {
            assert!(state
                .authorize_native_wallet(DOMAIN, WalletOperation::Withdrawal)
                .is_ok());
        });
        let original = state.native_state.take();
        assert!(state
            .authorize_native_wallet(DOMAIN, WalletOperation::View)
            .is_err());
        state.native_state = Some(super::NativeState::empty([99; 32]).unwrap());
        assert!(state
            .authorize_native_wallet(DOMAIN, WalletOperation::View)
            .is_err());
        state.native_state = original;
    });
    assert!(state
        .authorize_native_wallet(DOMAIN, WalletOperation::View)
        .is_err());
}

#[test]
fn owner_projection_ignores_large_unrelated_ledger_preserves_custody_and_refuses_truncation() {
    let mut state = populated();
    for index in 0..5000u32 {
        let mut txid = [88; 32];
        txid[..4].copy_from_slice(&index.to_le_bytes());
        state.eutxos.insert(crate::state_root::EutxoEntry {
            txid,
            vout: 0,
            value: 1,
            script_hash: [87; 32],
        });
    }
    assert!(state.native_wallet_view().is_err());
    let owner = b"projection-owner";
    let view = state.native_wallet_view_for_owner(owner).unwrap();
    assert!(view.utxos.len() < 4096);
    assert!(view.utxos.iter().all(|u| u.script_hash != [87; 32]));
    let base = super::wallet_projection::base(
        DOMAIN,
        &view.utxos,
        view.base_fee,
        view.block_gas_used,
        view.block_tx_bytes,
        view.epoch,
    )
    .unwrap();
    let restored = super::NativeState::restore_snapshot(
        &view.snapshot,
        &base,
        view.commitment,
        &BoundVerifier,
    )
    .unwrap();
    assert_eq!(
        restored.commitment(),
        state.native_state.as_ref().unwrap().commitment()
    );
    let owner_hash: [u8; 32] = Sha3_256::digest(owner).into();
    for index in 0..4097u32 {
        let mut txid = [86; 32];
        txid[..4].copy_from_slice(&index.to_le_bytes());
        state.eutxos.insert(crate::state_root::EutxoEntry {
            txid,
            vout: 0,
            value: 1,
            script_hash: owner_hash,
        });
    }
    assert!(state.native_wallet_view_for_owner(owner).is_err());
}

#[test]
fn official_native_admission_dry_runs_authorized_pool_without_mutating_parent() {
    struct Strict;
    impl crate::SignatureVerifier for Strict {
        fn verify_with_key(&self, key: &[u8], root: &[u8; 32], signature: &[u8]) -> bool {
            crate::SignatureVerifier::verify_with_key(&BoundVerifier, key, root, signature)
        }
        fn valid_native_key(&self, key: &[u8]) -> bool {
            bloch_euvm::ustav::Verifier::valid_pq_key(&BoundVerifier, key)
        }
        fn verify_native_signature(&self, key: &[u8], root: &[u8; 32], signature: &[u8]) -> bool {
            bloch_euvm::ustav::Verifier::verify_pq(&BoundVerifier, root, key, signature)
        }
    }
    let (state, bytes, expected) =
        consensus_pool::tests::fixtures(crate::fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS)
            .pop()
            .unwrap();
    let tx =
        PosTransaction::NativePool(crate::transition::NativeTransferPayload::new(bytes).unwrap());
    let tr = crate::transition::Transition::new(Strict);
    let root = state.compute_root();
    assert!(tr.validate_native_transaction(&state, &tx, 1).is_err());
    crate::params::native_state_rehearsal::run(0, || {
        assert!(tr.validate_native_transaction(&state, &tx, 1).is_err());
        crate::params::native_pool_rehearsal::run(0, || {
            assert_eq!(
                tr.validate_native_transaction(&state, &tx, 1).unwrap(),
                expected
            );
            assert!(tr.validate_native_transaction(&state, &tx, 0).is_err());
            let malformed = PosTransaction::NativePool(
                crate::transition::NativeTransferPayload::new(vec![0]).unwrap(),
            );
            assert!(tr
                .validate_native_transaction(&state, &malformed, 1)
                .is_err());
        });
    });
    assert_eq!(state.compute_root(), root);
}
