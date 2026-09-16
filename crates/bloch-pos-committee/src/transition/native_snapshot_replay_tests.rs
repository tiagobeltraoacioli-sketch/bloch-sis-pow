// These tests use the canonical proposer/RANDAO/header/body transition. Native
// funding is a cfg(test) fixture; no production bootstrap or gate is enabled.
fn replay_native_blocks(
    start: &CommittedState,
    blocks: &[(ProposalEnvelope, Vec<PosTransaction>)],
) -> CommittedState {
    let transition = Transition::new(BlockVerifier);
    blocks.iter().fold(start.clone(), |state, (block, body)| {
        // Restart recovery decodes the stored wire body, not an executor handle.
        let decoded: Vec<_> = body
            .iter()
            .map(|tx| PosTransaction::from_canonical_bytes(&tx.canonical_bytes()).unwrap())
            .collect();
        transition
            .apply_block(&state, block, &[], &decoded)
            .unwrap()
    })
}

#[test]
fn native_populated_canonical_replay_from_ancestor_survives_competing_branches() {
    active(|| {
        let (_, mut ancestor, mut a_chains) = setup(4);
        ancestor.admission_network_domain = Some([42; 32]);
        let price = ancestor.next_base_fee();
        let (request, _) = install_funded(&mut ancestor, price);
        let original = ancestor.clone();
        let tx = PosTransaction::NativeTransfer(
            NativeTransferPayload::new(request.canonical_bytes(&[42; 32]).unwrap()).unwrap(),
        );
        let t = Transition::new(BlockVerifier);
        let a1 = build_block(&t, &ancestor, 1, &[], &[tx.clone()], &mut a_chains);
        let a_state = t.apply_block(&ancestor, &a1, &[], &[tx.clone()]).unwrap();
        assert_ne!(a_state.native_state, ancestor.native_state);

        // A competing branch delays the same valid operation by one block.
        // Restoring the ancestor must recover its unspent native/base inputs.
        let (_, _, mut b_chains) = setup(4);
        let b1 = build_block(&t, &ancestor, 1, &[], &[], &mut b_chains);
        let b_parent = t.apply_block(&ancestor, &b1, &[], &[]).unwrap();
        assert_eq!(b_parent.native_state, ancestor.native_state);
        let b2 = build_block(&t, &b_parent, 2, &[], &[tx.clone()], &mut b_chains);
        let mut b_state = t.apply_block(&b_parent, &b2, &[], &[tx.clone()]).unwrap();
        let mut branch = vec![(b1, vec![]), (b2, vec![tx.clone()])];
        assert_eq!(b_state.native_state, a_state.native_state);
        assert_ne!(b_state.head, a_state.head);
        for slot in [
            3,
            crate::SLOTS_PER_EPOCH,
            crate::SLOTS_PER_EPOCH + 1,
            2 * crate::SLOTS_PER_EPOCH,
            2 * crate::SLOTS_PER_EPOCH + 1,
        ] {
            let block = build_block(&t, &b_state, slot, &[], &[], &mut b_chains);
            b_state = t.apply_block(&b_state, &block, &[], &[]).unwrap();
            branch.push((block, vec![]));
        }
        assert_eq!(replay_native_blocks(&ancestor, &branch), b_state);
        assert_eq!(replay_native_blocks(&original, &branch), b_state);
        assert_eq!(
            ancestor, original,
            "fork execution must not mutate its ancestor"
        );
        assert_eq!(b_state.native_state, a_state.native_state);
        // A branch cannot reuse inputs consumed on that branch, even though
        // another branch accepted the identical canonical transaction.
        let last = branch.last().unwrap().0.clone();
        let next = build_block(&t, &b_state, last.header.slot + 1, &[], &[], &mut b_chains);
        let replay = replace_body(&b_state, &next, &[tx.clone()]);
        assert_eq!(
            t.apply_block(&b_state, &replay, &[], &[tx]),
            Err(TransitionError::Transaction(0))
        );
    });
}

#[test]
fn native_populated_rejected_suffix_preserves_ancestor_and_valid_branch() {
    active(|| {
        let (_, mut pre, mut chains) = setup(4);
        pre.admission_network_domain = Some([42; 32]);
        let price = pre.next_base_fee();
        let (request, _) = install_funded(&mut pre, price);
        let tx = PosTransaction::NativeTransfer(
            NativeTransferPayload::new(request.canonical_bytes(&[42; 32]).unwrap()).unwrap(),
        );
        let original = pre.clone();
        let t = Transition::new(BlockVerifier);
        let valid = build_block(&t, &pre, 1, &[], &[tx.clone()], &mut chains);
        let expected = t.apply_block(&pre, &valid, &[], &[tx.clone()]).unwrap();
        let malformed =
            PosTransaction::NativeTransfer(NativeTransferPayload::new(vec![1]).unwrap());
        let rejected = replace_body(&pre, &valid, &[tx.clone(), malformed.clone()]);
        assert_eq!(
            t.apply_block(&pre, &rejected, &[], &[tx.clone(), malformed]),
            Err(TransitionError::Transaction(1))
        );
        assert_eq!(pre, original);
        assert_eq!(pre.compute_root(), original.compute_root());
        assert_eq!(t.apply_block(&pre, &valid, &[], &[tx]).unwrap(), expected);
    });
}

#[test]
fn native_populated_header_corruption_cannot_publish_staged_state() {
    active(|| {
        let (_, mut pre, mut chains) = setup(4);
        pre.admission_network_domain = Some([42; 32]);
        let price = pre.next_base_fee();
        let (request, _) = install_funded(&mut pre, price);
        let tx = PosTransaction::NativeTransfer(
            NativeTransferPayload::new(request.canonical_bytes(&[42; 32]).unwrap()).unwrap(),
        );
        let t = Transition::new(BlockVerifier);
        let block = build_block(&t, &pre, 1, &[], &[tx.clone()], &mut chains);
        let original = pre.clone();
        for field in 0..5 {
            let mut corrupt = block.clone();
            match field {
                0 => corrupt.header.state_root[0] ^= 1,
                1 => corrupt.header.body_root[0] ^= 1,
                2 => corrupt.header.randao_reveal[0] ^= 1,
                3 => corrupt.header.attestation_root[0] ^= 1,
                _ => corrupt.header.parent[0] ^= 1,
            }
            // Re-sign so each failure exercises its consensus field check,
            // instead of every test stopping at a stale proposer signature.
            let key =
                crate::attestation::KeyLookup::pubkey(&pre, corrupt.header.proposer_index).unwrap();
            corrupt.proposer_sig = toy_sign(key, &corrupt.header.proposal_signing_root());
            assert!(t.apply_block(&pre, &corrupt, &[], &[tx.clone()]).is_err());
            assert_eq!(pre, original);
        }
        let mut signature = block.clone();
        signature.proposer_sig[0] ^= 1;
        assert!(t.apply_block(&pre, &signature, &[], &[tx]).is_err());
        assert_eq!(pre, original);
    });
}

#[test]
fn native_future_activation_preserves_historical_block_ids_and_roots() {
    assert!(!crate::params::native_state_active(u64::MAX));
    assert!(!crate::params::native_transfer_active(u64::MAX));
    let (t, genesis, mut chains) = setup(4);
    let mut state = genesis.clone();
    let mut history = vec![];
    for slot in [1, 2, crate::SLOTS_PER_EPOCH, crate::SLOTS_PER_EPOCH + 1] {
        let block = build_block(&t, &state, slot, &[], &[], &mut chains);
        state = t.apply_block(&state, &block, &[], &[]).unwrap();
        history.push((block, state.clone()));
    }
    crate::params::native_state_rehearsal::run(3, || {
        crate::params::native_transfer_rehearsal::run(3, || {
            let mut replay = genesis.clone();
            for (block, expected) in &history {
                replay = t.apply_block(&replay, block, &[], &[]).unwrap();
                assert_eq!(replay.native_state, None);
                assert_eq!(replay.compute_root(), expected.compute_root());
                assert_eq!(replay.head, expected.head);
                assert_eq!(replay, *expected);
            }
        })
    });
    assert!(!crate::params::native_state_active(u64::MAX));
    assert!(!crate::params::native_transfer_active(u64::MAX));
}

fn restore_native_component(state: &CommittedState) -> CommittedState {
    let native = state.native_state.as_ref().unwrap();
    let bytes = native.encode_snapshot().unwrap();
    let mut restored = state.clone();
    restored.native_state = None;
    let component = native_dex::NativeState::restore_snapshot(
        &bytes,
        &restored,
        native.commitment(),
        &BoundVerifier,
    )
    .unwrap();
    assert_eq!(component.encode_snapshot().unwrap(), bytes);
    restored.native_state = Some(component);
    assert_eq!(restored.compute_root(), state.compute_root());
    assert_eq!(restored, *state);
    restored
}

#[test]
fn native_snapshot_populated_restore_then_real_block_replay_matches_uninterrupted_execution() {
    active(|| {
        let (_, mut pre, mut chains) = setup(4);
        pre.admission_network_domain = Some([42; 32]);
        let price = pre.next_base_fee();
        let (request, _) = install_funded(&mut pre, price);
        let tx = PosTransaction::NativeTransfer(
            NativeTransferPayload::new(request.canonical_bytes(&[42; 32]).unwrap()).unwrap(),
        );
        let t = Transition::new(BlockVerifier);
        let restored_pre = restore_native_component(&pre);
        let first = build_block(&t, &pre, 1, &[], &[tx.clone()], &mut chains);
        let post = t.apply_block(&pre, &first, &[], &[tx.clone()]).unwrap();
        assert_eq!(
            t.apply_block(&restored_pre, &first, &[], &[tx]).unwrap(),
            post
        );
        let mut uninterrupted = post.clone();
        let mut restarted = restore_native_component(&post);
        for slot in [2, 3, crate::SLOTS_PER_EPOCH, crate::SLOTS_PER_EPOCH + 1] {
            let block = build_block(&t, &uninterrupted, slot, &[], &[], &mut chains);
            uninterrupted = t.apply_block(&uninterrupted, &block, &[], &[]).unwrap();
            restarted = t.apply_block(&restarted, &block, &[], &[]).unwrap();
            assert_eq!(restarted, uninterrupted);
            restarted = restore_native_component(&restarted);
        }
        // The consumed native input and sponsor UTXO remain consumed across
        // restore; snapshot decoding cannot reset replay/nullifier protection.
        let next = build_block(
            &t,
            &restarted,
            crate::SLOTS_PER_EPOCH + 2,
            &[],
            &[],
            &mut chains,
        );
        let replay_tx = PosTransaction::NativeTransfer(
            NativeTransferPayload::new(request.canonical_bytes(&[42; 32]).unwrap()).unwrap(),
        );
        let invalid = replace_body(&restarted, &next, &[replay_tx.clone()]);
        assert_eq!(
            t.apply_block(&restarted, &invalid, &[], &[replay_tx]),
            Err(TransitionError::Transaction(0))
        );
        assert_eq!(restarted, uninterrupted);
    });
}

#[test]
fn native_snapshot_corruption_and_wrong_trust_context_cannot_modify_canonical_parent() {
    active(|| {
        let (_, mut pre, _) = setup(4);
        pre.admission_network_domain = Some([42; 32]);
        let price = pre.next_base_fee();
        install_funded(&mut pre, price);
        let original = pre.clone();
        let native = pre.native_state.as_ref().unwrap();
        let encoded = native.encode_snapshot().unwrap();
        let expected = native.commitment();
        let mut projection = pre.clone();
        projection.native_state = None;
        let mut corrupt = encoded.clone();
        let middle = corrupt.len() / 2;
        corrupt[middle] ^= 1;
        assert!(native_dex::NativeState::restore_snapshot(
            &corrupt,
            &projection,
            expected,
            &BoundVerifier
        )
        .is_err());
        assert!(native_dex::NativeState::restore_snapshot(
            &encoded,
            &projection,
            [7; 32],
            &BoundVerifier
        )
        .is_err());
        projection.admission_network_domain = Some([43; 32]);
        assert!(native_dex::NativeState::restore_snapshot(
            &encoded,
            &projection,
            expected,
            &BoundVerifier
        )
        .is_err());
        assert_eq!(pre, original);
        assert_eq!(pre.compute_root(), original.compute_root());
    });
}
