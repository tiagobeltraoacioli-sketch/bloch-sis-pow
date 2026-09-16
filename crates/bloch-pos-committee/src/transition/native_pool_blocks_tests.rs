#[test]
fn native_pool_complete_blocks_all_operations_and_disabled_gate() {
    for operation in 0..6 {
        let (parent, block, tx) = active(|| {
            crate::params::native_pool_rehearsal::run(0, || {
                let (_, mut pre, mut chains) = setup(4);
                pre.admission_network_domain = Some([42; 32]);
                pre.base_fee_millisat_per_gas = 3 * fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS;
                pre.block_gas_used = fee_market::BLOCK_GAS_LIMIT;
                let fee = pre.next_base_fee_at(0);
                let (funded, bytes, charge) =
                    native_dex::consensus_pool::tests::fixtures(fee).remove(operation);
                for entry in funded.utxos() {
                    pre.eutxos.insert(entry.clone());
                }
                pre.native_state = funded.native_state;
                let tx = PosTransaction::NativePool(NativeTransferPayload::new(bytes).unwrap());
                let t = Transition::new(BlockVerifier);
                let block = build_block(&t, &pre, 1, &[], std::slice::from_ref(&tx), &mut chains);
                let post = t
                    .apply_block(&pre, &block, &[], std::slice::from_ref(&tx))
                    .unwrap();
                assert_eq!(post.block_gas_used, charge.gas);
                assert_eq!(post.block_tx_bytes, charge.tx_bytes);
                let split = rewards::split_fees_at(charge.base_fee_sat, charge.priority_fee_sat, 1);
                assert_eq!(
                    pre.accounted_supply_sat() - post.accounted_supply_sat(),
                    charge.base_fee_sat + charge.priority_fee_sat - split.to_producer
                );
                let decoded = PosTransaction::from_canonical_bytes(&tx.canonical_bytes()).unwrap();
                assert_eq!(t.apply_block(&pre, &block, &[], &[decoded]).unwrap(), post);
                let snapshot = post.native_component_snapshot_bytes().unwrap().unwrap();
                assert_eq!(
                    post.with_restored_native_component(&snapshot, &BlockVerifier)
                        .unwrap(),
                    post
                );
                // A valid lifecycle prefix cannot publish if a malformed suffix follows it.
                let invalid =
                    PosTransaction::NativePool(NativeTransferPayload::new(vec![0]).unwrap());
                let txs = vec![tx.clone(), invalid];
                let bad = replace_body(&pre, &block, &txs);
                let before = pre.clone();
                assert!(t.apply_block(&pre, &bad, &[], &txs).is_err());
                assert_eq!(pre, before);
                (pre, block, tx)
            })
        });
        active(|| {
            assert!(Transition::new(BlockVerifier)
                .apply_block(&parent, &block, &[], &[tx])
                .is_err());
        });
    }
    assert_eq!(crate::params::NATIVE_POOL_ACTIVATION_EPOCH, u64::MAX);
    assert!(!crate::params::native_pool_active(u64::MAX));
}

#[test]
fn native_pool_import_pair_initialize_swap_canonical_chain() {
    active(|| {
        crate::params::native_import_rehearsal::run(0, || {
            crate::params::native_pool_rehearsal::run(0, || {
                let (_, mut pre, mut chains) = setup(4);
                pre.admission_network_domain = Some([42; 32]);
                let (funded, import) =
                    native_dex::consensus_pool::tests::imported_pool_start(pre.next_base_fee_at(0));
                for entry in funded.utxos() {
                    pre.eutxos.insert(entry.clone());
                }
                pre.native_state = funded.native_state;
                let t = Transition::new(BlockVerifier);
                let mut previous = pre;
                for step in 0..4 {
                    let tx = if step == 0 {
                        import.clone()
                    } else {
                        native_dex::consensus_pool::tests::imported_pool_step(
                            &previous,
                            step - 1,
                            previous.next_base_fee_at(0),
                        )
                    };
                    let block = build_block(
                        &t,
                        &previous,
                        step as u64 + 1,
                        &[],
                        std::slice::from_ref(&tx),
                        &mut chains,
                    );
                    let post = t
                        .apply_block(&previous, &block, &[], std::slice::from_ref(&tx))
                        .unwrap();
                    let replay =
                        PosTransaction::from_canonical_bytes(&tx.canonical_bytes()).unwrap();
                    assert_eq!(
                        t.apply_block(&previous, &block, &[], &[replay]).unwrap(),
                        post
                    );
                    let snapshot = post.native_component_snapshot_bytes().unwrap().unwrap();
                    if step == 2 {
                        native_dex::consensus_pool::tests::assert_imported_pool(&post, false);
                    }
                    previous = post
                        .with_restored_native_component(&snapshot, &BlockVerifier)
                        .unwrap();
                }
                native_dex::consensus_pool::tests::assert_imported_pool(&previous, true);
            })
        })
    });
}
