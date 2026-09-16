#[test]
fn native_gateway_canonical_import_replay_and_disabled_gate() {
    let (parent, block, tx) = active(|| {
        crate::params::native_import_rehearsal::run(0, || {
            let (_, mut pre, mut chains) = setup(4);
            pre.admission_network_domain = Some([42; 32]);
            let (funded, request) =
                native_dex::consensus_gateway::tests::funded_import(pre.next_base_fee_at(0));
            for entry in funded.utxos() {
                pre.eutxos.insert(entry.clone());
            }
            pre.native_state = funded.native_state;
            let tx = PosTransaction::NativeImport(
                NativeTransferPayload::new(request.canonical_bytes(&[42; 32]).unwrap()).unwrap(),
            );
            let t = Transition::new(BlockVerifier);
            let block = build_block(&t, &pre, 1, &[], std::slice::from_ref(&tx), &mut chains);
            let post = t
                .apply_block(&pre, &block, &[], std::slice::from_ref(&tx))
                .unwrap();
            let replay = PosTransaction::from_canonical_bytes(&tx.canonical_bytes()).unwrap();
            assert_eq!(t.apply_block(&pre, &block, &[], &[replay]).unwrap(), post);
            assert_ne!(pre.native_state, post.native_state);
            let bytes = post.native_component_snapshot_bytes().unwrap().unwrap();
            assert_eq!(
                post.with_restored_native_component(&bytes, &BlockVerifier)
                    .unwrap(),
                post
            );
            let mut corrupted = block.clone();
            corrupted.header.body_root = [0; 32];
            assert!(t
                .apply_block(&pre, &corrupted, &[], std::slice::from_ref(&tx))
                .is_err());
            (pre, block, tx)
        })
    });
    active(|| {
        assert!(Transition::new(BlockVerifier)
            .apply_block(&parent, &block, &[], &[tx])
            .is_err());
    });
    assert_eq!(crate::params::NATIVE_IMPORT_ACTIVATION_EPOCH, u64::MAX);
    assert_eq!(crate::params::NATIVE_WITHDRAWAL_ACTIVATION_EPOCH, u64::MAX);
}

#[test]
fn native_gateway_withdrawal_real_block_and_gate() {
    let (parent, block, tx) = active(|| {
        crate::params::native_import_rehearsal::run(0, || {
            crate::params::native_withdrawal_rehearsal::run(0, || {
                let (_, mut pre, mut chains) = setup(4);
                pre.admission_network_domain = Some([42; 32]);
                let (funded, request) =
                    native_dex::consensus_gateway::tests::funded_import(pre.next_base_fee_at(0));
                for entry in funded.utxos() {
                    pre.eutxos.insert(entry.clone());
                }
                pre.native_state = funded.native_state;
                let tx = PosTransaction::NativeImport(
                    NativeTransferPayload::new(request.canonical_bytes(&[42; 32]).unwrap())
                        .unwrap(),
                );
                let t = Transition::new(BlockVerifier);
                let first = build_block(&t, &pre, 1, &[], &[tx.clone()], &mut chains);
                let parent = t.apply_block(&pre, &first, &[], &[tx]).unwrap();
                let withdrawal = native_dex::consensus_gateway::tests::withdrawal_for(
                    &parent,
                    request,
                    parent.next_base_fee_at(0),
                );
                let tx = PosTransaction::NativeWithdrawal(
                    NativeTransferPayload::new(withdrawal.canonical_bytes(&[42; 32]).unwrap())
                        .unwrap(),
                );
                let block = build_block(&t, &parent, 2, &[], &[tx.clone()], &mut chains);
                let post = t.apply_block(&parent, &block, &[], &[tx.clone()]).unwrap();
                let decoded = PosTransaction::from_canonical_bytes(&tx.canonical_bytes()).unwrap();
                assert_eq!(
                    t.apply_block(&parent, &block, &[], &[decoded]).unwrap(),
                    post
                );
                assert_ne!(parent.native_state, post.native_state);
                (parent, block, tx)
            })
        })
    });
    active(|| {
        assert!(Transition::new(BlockVerifier)
            .apply_block(&parent, &block, &[], &[tx])
            .is_err())
    });
}

#[cfg(feature = "native-lab")]
#[test]
fn native_lab_instance_is_domain_bound_and_replay_deterministic() {
    let (_, mut pre, mut chains) = setup(4);
    pre.admission_network_domain = Some([42; 32]);
    let (funded, request) =
        native_dex::consensus_gateway::tests::funded_import(pre.next_base_fee_at(0));
    for entry in funded.utxos() {
        pre.eutxos.insert(entry.clone());
    }
    pre.native_state = funded.native_state;
    let tx = PosTransaction::NativeImport(
        NativeTransferPayload::new(request.canonical_bytes(&[42; 32]).unwrap()).unwrap(),
    );
    let lab = Transition::native_laboratory(BlockVerifier, [42; 32]).unwrap();
    let before = pre.clone();
    assert!(lab.validate_native_lab_transaction(&pre, &tx, 1).is_ok());
    assert_eq!(pre, before);
    let block = build_block(&lab, &pre, 1, &[], &[tx.clone()], &mut chains);
    let post = lab.apply_block(&pre, &block, &[], &[tx.clone()]).unwrap();
    assert_eq!(
        lab.apply_block(&pre, &block, &[], &[tx.clone()]).unwrap(),
        post
    );
    assert!(Transition::new(BlockVerifier)
        .apply_block(&pre, &block, &[], &[tx.clone()])
        .is_err());
    let wrong = Transition::native_laboratory(BlockVerifier, [43; 32]).unwrap();
    assert!(wrong.validate_native_lab_transaction(&pre, &tx, 1).is_err());
    assert!(wrong.apply_block(&pre, &block, &[], &[tx]).is_err());
    assert_eq!(pre, before);
}
