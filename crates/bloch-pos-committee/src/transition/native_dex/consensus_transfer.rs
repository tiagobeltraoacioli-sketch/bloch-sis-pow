//! Internal staging adapter for a gated canonical native transfer.
//! Expiry uses the candidate block's slot, inclusively: slot == valid_until is
//! valid. The block transition owns gate selection, admission, fee settlement
//! and publication; this module neither initializes nor imports native state.
use super::{wire, CommittedState, NativeState, State};
use crate::{fee_market::TxCharge, SignatureVerifier};
use bloch_euvm::ustav::Verifier;

/// Outer PosTransaction tag (one byte) and payload length (four bytes).
const OUTER_BYTES: u64 = crate::transition::NATIVE_TRANSFER_FRAME_BYTES as u64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::transition) enum Error {
    InvalidState,
    Wire(wire::Error),
    Execution(super::Error),
}

/// Stage both ledgers and publish them together only after successful execution.
/// `base_fee` is the candidate block's selected price, not the next-block quote.
/// Returned fees must enter the host's normal block fee accounting exactly once.
pub(in crate::transition) fn apply_transfer(
    base: &mut CommittedState,
    payload: &[u8],
    slot: u64,
    base_fee: u128,
    base_verifier: &dyn SignatureVerifier,
    native_verifier: &dyn Verifier,
) -> Result<TxCharge, Error> {
    let native = base.native_state.as_ref().ok_or(Error::InvalidState)?;
    if native.domain == [0; 32]
        || base.admission_network_domain != Some(native.domain)
        || native.native.gateway().native().domain() != &native.domain
        || native.base_fees != 0
        || native.priority_fees != 0
    {
        return Err(Error::InvalidState);
    }
    let request = wire::decode(payload, &native.domain).map_err(Error::Wire)?;
    let mut staged = base.clone();
    let native = staged.native_state.take().ok_or(Error::InvalidState)?;
    // Only an already-owned canonical component reaches this private adapter.
    // The temporary rehearsal executor sees a base with no embedded component.
    let mut state = State {
        base: staged,
        native: native.native,
        domain: native.domain,
        base_fees: 0,
        priority_fees: 0,
        base_reserves: native.base_reserves,
        base_locks: native.base_locks,
        paired_reserves: native.paired_reserves,
        paired_locks: native.paired_locks,
        initial_pools: native.initial_pools,
        reserve_pools: native.reserve_pools,
    };
    let execution = state
        .execute_with_context(
            &request,
            slot,
            base_fee,
            OUTER_BYTES,
            base_verifier,
            native_verifier,
        )
        .map_err(Error::Execution)?;
    // Consensus settles the returned charge in its existing burn/reward path.
    // Never carry rehearsal escrow into canonical native state or double-charge it.
    let native = NativeState {
        native: state.native,
        domain: state.domain,
        base_fees: 0,
        priority_fees: 0,
        base_reserves: state.base_reserves,
        base_locks: state.base_locks,
        paired_reserves: state.paired_reserves,
        paired_locks: state.paired_locks,
        initial_pools: state.initial_pools,
        reserve_pools: state.reserve_pools,
    };
    state.base.native_state = Some(native);
    *base = state.base;
    Ok(execution.charge)
}

#[cfg(test)]
pub(in crate::transition) mod tests {
    use super::*;
    use crate::transition::native_dex::{tests as fixtures, PosTransaction, Request};
    use fixtures::{key, signature, COIN, DOMAIN};
    pub(in crate::transition) struct BoundVerifier;
    impl SignatureVerifier for BoundVerifier {
        fn verify_with_key(&self, key: &[u8], root: &[u8; 32], signature: &[u8]) -> bool {
            SignatureVerifier::verify_with_key(&fixtures::BoundVerifier, key, root, signature)
        }
    }
    impl Verifier for BoundVerifier {
        fn valid_pq_key(&self, key: &[u8]) -> bool {
            Verifier::valid_pq_key(&fixtures::BoundVerifier, key)
        }
        fn verify_pq(&self, message: &[u8], key: &[u8], signature: &[u8]) -> bool {
            Verifier::verify_pq(&fixtures::BoundVerifier, message, key, signature)
        }
    }

    pub(in crate::transition) fn funded(base_fee: u128) -> (CommittedState, Request, TxCharge) {
        let (state, mut request) = fixtures::fixture();
        let bytes = request.canonical_bytes(&DOMAIN).unwrap().len() as u64 + OUTER_BYTES;
        if let PosTransaction::TransferV2 { tx_bytes, .. } = &mut request.blch {
            *tx_bytes = bytes;
        }
        let charge = state
            .quote_with_context(&request, base_fee, OUTER_BYTES)
            .unwrap();
        if let PosTransaction::TransferV2 { outputs, .. } = &mut request.blch {
            outputs[0].value = COIN - (charge.base_fee_sat + charge.priority_fee_sat) as u64;
        }
        sign(&mut request);
        let (mut base, pinned) = state.into_parts();
        base.native_state = Some(pinned.state);
        (base, request, charge)
    }
    /// Test-only funded state transplant, preserving committee/RANDAO bookkeeping.
    /// The caller must select the same fixture domain before constructing blocks.
    pub(in crate::transition) fn install_funded(
        base: &mut CommittedState,
        price: u128,
    ) -> (Request, TxCharge) {
        assert_eq!(base.admission_network_domain, Some(DOMAIN));
        assert!(base.native_state.is_none());
        let (funded, request, charge) = funded(price);
        for entry in funded.utxos() {
            assert!(base.utxo(&entry.txid, entry.vout).is_none());
            base.eutxos.insert(entry.clone());
        }
        base.native_state = funded.native_state;
        (request, charge)
    }

    fn sign(request: &mut Request) {
        let authorization = request.authorization(&DOMAIN).unwrap();
        if let PosTransaction::TransferV2 { keys, .. } = &mut request.blch {
            keys[0].signature = signature(&authorization, &key(1));
        }
        request.native.witnesses.owners[0] = signature(&authorization, &key(3));
    }
    fn apply(
        base: &mut CommittedState,
        request: &Request,
        slot: u64,
        fee: u128,
    ) -> Result<TxCharge, Error> {
        apply_transfer(
            base,
            &request.canonical_bytes(&DOMAIN).unwrap(),
            slot,
            fee,
            &BoundVerifier,
            &BoundVerifier,
        )
    }

    #[test]
    fn explicit_block_price_and_outer_bytes_settle_without_native_escrow() {
        let price = 200;
        let (mut base, request, expected) = funded(price);
        assert_ne!(base.next_base_fee(), price);
        let before = base.clone();
        let charge = apply(&mut base, &request, request.valid_until, price).unwrap();
        assert_eq!(charge, expected);
        assert_eq!(
            charge.tx_bytes,
            request.canonical_bytes(&DOMAIN).unwrap().len() as u64 + OUTER_BYTES
        );
        let native = base.native_state.as_ref().unwrap();
        assert_eq!((native.base_fees, native.priority_fees), (0, 0));
        assert!(base.utxo(&[8; 32], 0).is_none());
        assert!(base
            .utxo(&request.output_txid(&DOMAIN).unwrap(), 0)
            .is_some());
        assert_ne!(base.compute_root(), before.compute_root());
        let after = base.clone();
        assert!(apply(&mut base, &request, request.valid_until, price).is_err());
        assert_eq!(base, after);
    }

    #[test]
    fn malformed_expired_forged_and_late_base_failure_preserve_both_ledgers() {
        let price = 200;
        let (base, request, _) = funded(price);
        let mut staged = base.clone();
        assert!(apply_transfer(
            &mut staged,
            &[0; 8],
            1,
            price,
            &BoundVerifier,
            &BoundVerifier
        )
        .is_err());
        assert_eq!(staged, base);
        assert!(apply(&mut staged, &request, request.valid_until + 1, price).is_err());
        assert_eq!(staged, base);
        let mut forged = request.clone();
        forged.native.witnesses.owners[0][0] ^= 1;
        assert!(apply(&mut staged, &forged, 1, price).is_err());
        assert_eq!(staged, base);
        // Native plan is valid, but base conservation fails after it is staged.
        let mut bad_base = request.clone();
        if let PosTransaction::TransferV2 { outputs, .. } = &mut bad_base.blch {
            outputs[0].value += 1;
        }
        sign(&mut bad_base);
        assert!(apply(&mut staged, &bad_base, 1, price).is_err());
        assert_eq!(staged, base);
    }

    #[test]
    fn ordinary_joint_transfer_cannot_spend_canonical_custody_locks() {
        let price = 200;
        let (base, request, _) = funded(price);
        for native_side in [false, true] {
            let mut locked = base.clone();
            let component = locked.native_state.as_mut().unwrap();
            if native_side {
                component
                    .paired_locks
                    .insert(request.native.transaction.inputs[0].clone(), [9; 32]);
            } else {
                component.base_locks.insert(([8; 32], 0), [9; 32]);
            }
            let before = locked.clone();
            assert!(matches!(
                apply(&mut locked, &request, 1, price),
                Err(Error::Execution(super::super::Error::LockedReserve))
            ));
            assert_eq!(locked, before);
        }
    }

    #[test]
    fn rejects_underdeclared_outer_bytes_wrong_domain_and_nonzero_escrow() {
        let price = 200;
        let (base, mut request, _) = funded(price);
        if let PosTransaction::TransferV2 { tx_bytes, .. } = &mut request.blch {
            *tx_bytes -= OUTER_BYTES;
        }
        sign(&mut request);
        let mut staged = base.clone();
        assert!(matches!(
            apply(&mut staged, &request, 1, price),
            Err(Error::Execution(super::super::Error::Base(
                crate::transition::TransferReject::UnderdeclaredSize
            )))
        ));
        assert_eq!(staged, base);
        for priority in [false, true] {
            let mut dirty = base.clone();
            let native = dirty.native_state.as_mut().unwrap();
            if priority {
                native.priority_fees = 1;
            } else {
                native.base_fees = 1;
            }
            let before = dirty.clone();
            assert!(matches!(
                apply(&mut dirty, &request, 1, price),
                Err(Error::InvalidState)
            ));
            assert_eq!(dirty, before);
        }
        let mut wrong = base.clone();
        wrong.admission_network_domain = Some([99; 32]);
        let before = wrong.clone();
        assert!(matches!(
            apply(&mut wrong, &request, 1, price),
            Err(Error::InvalidState)
        ));
        assert_eq!(wrong, before);
    }
}
