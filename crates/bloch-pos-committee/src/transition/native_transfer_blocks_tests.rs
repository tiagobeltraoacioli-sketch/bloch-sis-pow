use super::*;
use native_dex::consensus_transfer::tests::{install_funded, BoundVerifier};

struct BlockVerifier;
impl SignatureVerifier for BlockVerifier {
    fn verify_with_key(&self, key: &[u8], root: &[u8; 32], sig: &[u8]) -> bool {
        ToyVerifier.verify_with_key(key, root, sig) || BoundVerifier.verify_with_key(key, root, sig)
    }
    fn valid_native_key(&self, key: &[u8]) -> bool {
        bloch_euvm::ustav::Verifier::valid_pq_key(&BoundVerifier, key)
    }
    fn verify_native_signature(&self, key: &[u8], root: &[u8; 32], sig: &[u8]) -> bool {
        bloch_euvm::ustav::Verifier::verify_pq(&BoundVerifier, root, key, sig)
    }
}

struct ProposalProbe;
impl SignatureVerifier for ProposalProbe {
    fn verify_with_key(&self, _: &[u8], _: &[u8; 32], _: &[u8]) -> bool {
        true
    }
    fn valid_native_key(&self, key: &[u8]) -> bool {
        BlockVerifier.valid_native_key(key)
    }
    fn verify_native_signature(&self, key: &[u8], root: &[u8; 32], sig: &[u8]) -> bool {
        BlockVerifier.verify_native_signature(key, root, sig)
    }
}

fn active<T>(f: impl FnOnce() -> T) -> T {
    crate::params::native_state_rehearsal::run(0, || {
        crate::params::native_transfer_rehearsal::run(0, f)
    })
}

fn replace_body(
    pre: &CommittedState,
    block: &ProposalEnvelope,
    txs: &[PosTransaction],
) -> ProposalEnvelope {
    let mut block = block.clone();
    block.header.body_root = crate::derive::body_root(
        &txs.iter()
            .map(PosTransaction::canonical_bytes)
            .collect::<Vec<_>>(),
    );
    let key = crate::attestation::KeyLookup::pubkey(pre, block.header.proposer_index).unwrap();
    block.proposer_sig = toy_sign(key, &block.header.proposal_signing_root());
    block
}

#[test]
fn native_block_dispatch_settles_fees_once_and_replays() {
    active(|| {
        for slot in [1, crate::SLOTS_PER_EPOCH, 2 * crate::SLOTS_PER_EPOCH] {
            let (_, mut pre, mut chains) = setup(4);
            pre.admission_network_domain = Some([42; 32]);
            pre.base_fee_millisat_per_gas = 3 * fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS;
            pre.block_gas_used = fee_market::BLOCK_GAS_LIMIT;
            let fee = pre.next_base_fee_at(crate::epoch_of(slot));
            let (request, charge) = install_funded(&mut pre, fee);
            let tx = PosTransaction::NativeTransfer(
                NativeTransferPayload::new(request.canonical_bytes(&[42; 32]).unwrap()).unwrap(),
            );
            let t = Transition::new(BlockVerifier);
            let block = build_block(&t, &pre, slot, &[], std::slice::from_ref(&tx), &mut chains);
            let post = t
                .apply_block(&pre, &block, &[], std::slice::from_ref(&tx))
                .unwrap();
            assert_eq!(post.block_gas_used, charge.gas);
            assert_eq!(post.block_tx_bytes, charge.tx_bytes);
            assert!(charge.tx_bytes >= tx.canonical_bytes().len() as u64);
            let split = rewards::split_fees_at(charge.base_fee_sat, charge.priority_fee_sat, slot);
            assert_eq!(
                pre.accounted_supply_sat() - post.accounted_supply_sat(),
                charge.base_fee_sat + charge.priority_fee_sat - split.to_producer
            );
            assert_ne!(pre.native_state, post.native_state);
            assert_eq!(
                t.apply_block(&pre.clone(), &block, &[], &[tx.clone()])
                    .unwrap(),
                post
            );
            let empty = build_block(&t, &post, slot + 1, &[], &[], &mut chains);
            let next = t.apply_block(&post, &empty, &[], &[]).unwrap();
            assert_eq!(next.native_state, post.native_state);
            let replay_body = replace_body(&post, &empty, &[tx.clone()]);
            assert_eq!(
                t.apply_block(&post, &replay_body, &[], &[tx.clone()]),
                Err(TransitionError::Transaction(0))
            );
            let duplicate = replace_body(&pre, &block, &[tx.clone(), tx.clone()]);
            assert_eq!(
                t.apply_block(&pre, &duplicate, &[], &[tx.clone(), tx]),
                Err(TransitionError::Transaction(1))
            );
        }
    });
}

#[test]
fn native_block_gate_crypto_and_mixed_spends_fail_without_parent_mutation() {
    assert!(!crate::params::native_transfer_active(u64::MAX));
    let (_, mut pre, mut chains) = setup(4);
    pre.admission_network_domain = Some([42; 32]);
    let fee = pre.next_base_fee();
    let (request, _) = install_funded(&mut pre, fee);
    let tx = PosTransaction::NativeTransfer(
        NativeTransferPayload::new(request.canonical_bytes(&[42; 32]).unwrap()).unwrap(),
    );
    let t = Transition::new(BlockVerifier);
    let block = active(|| build_block(&t, &pre, 1, &[], &[tx.clone()], &mut chains));
    let original = pre.clone();
    crate::params::native_state_rehearsal::run(0, || {
        assert_eq!(
            t.apply_block(&pre, &block, &[], &[tx.clone()]),
            Err(TransitionError::Transaction(0))
        );
    });
    active(|| {
        // A consensus verifier without explicit native capabilities rejects.
        assert_eq!(
            Transition::new(ToyVerifier).apply_block(&pre, &block, &[], &[tx.clone()]),
            Err(TransitionError::Transaction(0))
        );
        let coin = pre.utxo(&[8; 32], 0).unwrap().clone();
        let ordinary =
            transfer_spending(&[coin], &vec![1; 32], script_of(&owner_key(9)), 256, 0, fee);
        for body in [
            vec![tx.clone(), ordinary.clone()],
            vec![ordinary, tx.clone()],
        ] {
            let candidate = replace_body(&pre, &block, &body);
            assert!(matches!(
                t.apply_block(&pre, &candidate, &[], &body),
                Err(TransitionError::Transaction(1)) | Err(TransitionError::Transfer(1, _))
            ));
            assert_eq!(pre, original);
        }
        let mut bad_request = request.clone();
        bad_request.native.witnesses.owners[0][0] ^= 1;
        let bad = PosTransaction::NativeTransfer(
            NativeTransferPayload::new(bad_request.canonical_bytes(&[42; 32]).unwrap()).unwrap(),
        );
        let candidate = replace_body(&pre, &block, &[bad.clone()]);
        assert_eq!(
            t.apply_block(&pre, &candidate, &[], &[bad]),
            Err(TransitionError::Transaction(0))
        );
        assert_eq!(pre, original);
        // A producer may bypass its future proposal signature, never the
        // sponsor witness of an already signed native operation.
        let mut bad_sponsor = request.clone();
        if let PosTransaction::TransferV2 { keys, .. } = &mut bad_sponsor.blch {
            keys[0].signature[0] ^= 1;
        }
        let bad = PosTransaction::NativeTransfer(
            NativeTransferPayload::new(bad_sponsor.canonical_bytes(&[42; 32]).unwrap()).unwrap(),
        );
        let candidate = replace_body(&pre, &block, &[bad.clone()]);
        assert_eq!(
            Transition::new(ProposalProbe).apply_block(&pre, &candidate, &[], &[bad]),
            Err(TransitionError::Transaction(0))
        );
    });
}
