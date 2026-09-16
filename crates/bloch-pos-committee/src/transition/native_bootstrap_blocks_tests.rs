#[test]
fn native_bootstrap_canonical_block_and_disabled_gate() {
    let (parent, block, tx, expected) = active(|| {
        crate::params::native_bootstrap_rehearsal::run(0, || {
            let (_, mut pre, mut chains) = setup(4);
            pre.admission_network_domain = Some([42; 32]);
            let fee = pre.next_base_fee_at(0);
            let (funded, request) = native_dex::bootstrap::tests::fixture(fee);
            for entry in funded.utxos() {
                pre.eutxos.insert(entry.clone());
            }
            assert!(pre.native_state.is_none());
            let tx = PosTransaction::NativeBootstrap(
                NativeTransferPayload::new(request.canonical_bytes().unwrap()).unwrap(),
            );
            let transition = Transition::new(BlockVerifier);
            let block = build_block(
                &transition,
                &pre,
                1,
                &[],
                std::slice::from_ref(&tx),
                &mut chains,
            );
            let post = transition
                .apply_block(&pre, &block, &[], std::slice::from_ref(&tx))
                .unwrap();
            native_dex::bootstrap::tests::assert_registered(&post, &request);
            let decoded = PosTransaction::from_canonical_bytes(&tx.canonical_bytes()).unwrap();
            assert_eq!(
                transition
                    .apply_block(&pre, &block, &[], &[decoded])
                    .unwrap()
                    .state_root(),
                post.state_root()
            );
            assert_eq!(post.block_gas_used, request.quote(fee).unwrap().gas);
            (pre, block, tx, post.state_root())
        })
    });
    active(|| {
        assert!(Transition::new(BlockVerifier)
            .apply_block(&parent, &block, &[], &[tx])
            .is_err());
    });
    assert_ne!(parent.state_root(), expected);
    assert_eq!(crate::params::NATIVE_BOOTSTRAP_ACTIVATION_EPOCH, u64::MAX);
    assert!(!crate::params::native_bootstrap_active(u64::MAX));
}
