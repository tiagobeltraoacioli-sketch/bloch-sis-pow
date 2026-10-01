// SPDX-License-Identifier: AGPL-3.0-or-later
mod l2_tests {
    use super::*;
    use crate::l2_settlement::{Policy, Reject, Transaction, STATEMENT_TAG, TRANSACTION_BYTES};
    const TEMPLATE: &[u8; 590] =
        include_bytes!("../../../bloch-l2-proof/tests/fixtures/empty.values");
    const S: usize = STATEMENT_TAG.len();
    fn hash_at(s: &[u8], offset: usize) -> [u8; 32] {
        s[offset..offset + 32].try_into().unwrap()
    }
    struct ProofDouble;
    impl SignatureVerifier for ProofDouble {
        fn verify_with_key(&self, pk: &[u8], root: &[u8; 32], sig: &[u8]) -> bool {
            ToyVerifier.verify_with_key(pk, root, sig)
        }
        fn verify_l2_settlement(&self, _: &[u8; 32], _: &[u8; 32], _: &[u8], proof: &[u8]) -> bool {
            proof == [1; 356]
        }
    }
    struct RealProof;
    impl SignatureVerifier for RealProof {
        fn verify_with_key(&self, pk: &[u8], root: &[u8; 32], sig: &[u8]) -> bool {
            ToyVerifier.verify_with_key(pk, root, sig)
        }
        fn verify_l2_settlement(
            &self,
            policy: &[u8; 32],
            key: &[u8; 32],
            values: &[u8],
            proof: &[u8],
        ) -> bool {
            bloch_l2_proof::verify(policy, key, values, proof)
        }
    }
    fn fixture() -> (CommittedState, Vec<RandaoChain>) {
        let (_, mut genesis, mut chains) = setup(4);
        let identities = std::array::from_fn(|i| hash_at(TEMPLATE, S + i * 32));
        let mut policy = Policy {
            identities,
            proof_policy: bloch_l2_proof::policy_commitment(),
            chain_id: 700771,
            initial_l2_parent: hash_at(TEMPLATE, S + 272),
            initial_l2_state: hash_at(TEMPLATE, S + 304),
        };
        policy.identities[0] = [0x91; 32];
        policy.identities[1] = *genesis.head.as_bytes();
        genesis.admission_network_domain = Some(policy.identities[0]);
        genesis = genesis.configure_l2_genesis(policy).unwrap();
        let t = Transition::new(ToyVerifier);
        let first = build_block(&t, &genesis, 1, &[], &[], &mut chains);
        let pre = t.apply_block(&genesis, &first, &[], &[]).unwrap();
        assert_eq!(pre.l2_settlement().unwrap().height(), 1);
        (pre, chains)
    }
    fn transaction(pre: &CommittedState) -> Transaction {
        let state = pre.l2_settlement().unwrap();
        let source = state.source(*pre.head.as_bytes(), pre.slot);
        let mut statement = *TEMPLATE;
        for (i, id) in state.policy().identities.iter().enumerate() {
            statement[S + i * 32..S + (i + 1) * 32].copy_from_slice(id);
        }
        for (offset, value) in [
            (400, source.block),
            (448, source.commitment),
            (480, source.inbox_root),
        ] {
            statement[S + offset..S + offset + 32].copy_from_slice(&value);
        }
        statement[S + 432..S + 440].copy_from_slice(&source.slot.to_be_bytes());
        statement[S + 440..S + 448].copy_from_slice(&source.height.to_be_bytes());
        Transaction {
            proof_policy: state.policy().proof_policy,
            statement,
            proof: [1; 356],
        }
    }
    #[test]
    fn native_l2_prepare_and_replay_atomic_state_root() {
        let (pre, mut chains) = fixture();
        let tx = PosTransaction::L2Settlement(Box::new(transaction(&pre)));
        let bytes = tx.canonical_bytes();
        assert_eq!(bytes.len(), TRANSACTION_BYTES);
        assert_eq!(PosTransaction::from_canonical_bytes(&bytes).unwrap(), tx);
        let t = Transition::new(ProofDouble);
        let block = build_block(&t, &pre, 2, &[], std::slice::from_ref(&tx), &mut chains);
        let before = pre.state_root();
        let first = t
            .apply_block(&pre, &block, &[], std::slice::from_ref(&tx))
            .unwrap();
        let second = t
            .apply_block(&pre, &block, &[], std::slice::from_ref(&tx))
            .unwrap();
        assert_eq!(first, second);
        assert_eq!(pre.state_root(), before);
        assert_ne!(first.state_root(), before);
        assert!(first.l2_settlement().unwrap().head().is_some());
        assert_eq!(first.accounted_supply_sat(), pre.accounted_supply_sat());
        assert!(Transition::new(ToyVerifier)
            .apply_block(&pre, &block, &[], std::slice::from_ref(&tx))
            .is_err());
        assert!(t
            .apply_block(&first, &block, &[], std::slice::from_ref(&tx))
            .is_err());
        // Export only public deterministic fixture context for a real prover run.
        if let Some(path) = std::env::var_os("BLOCH_NATIVE_L2_REQUEST_OUT") {
            let state = pre.l2_settlement().unwrap();
            let src = state.source(*pre.head.as_bytes(), pre.slot);
            let text = format!(
                "{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
                hex::encode(state.policy().identities[0]),
                hex::encode(state.policy().identities[1]),
                hex::encode(src.block),
                src.slot,
                src.height,
                hex::encode(src.commitment),
                hex::encode(src.inbox_root)
            );
            use std::io::Write;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .unwrap()
                .write_all(text.as_bytes())
                .unwrap();
        }
    }
    #[test]
    fn native_l2_parent_source_policy_and_bounds_fail_closed() {
        let (pre, _) = fixture();
        let original = transaction(&pre);
        for offset in [
            S,
            S + 32,
            S + 224,
            S + 256,
            S + 264,
            S + 272,
            S + 304,
            S + 400,
            S + 432,
            S + 440,
            S + 448,
            S + 480,
            S + 512,
            S + 520,
            S + 528,
        ] {
            let mut tx = original.clone();
            tx.statement[offset] ^= 1;
            let mut state = pre.clone();
            assert!(
                state
                    .apply_transaction(
                        &PosTransaction::L2Settlement(Box::new(tx)),
                        0,
                        1,
                        &ProofDouble
                    )
                    .is_err(),
                "offset {offset}"
            );
            assert_eq!(state, pre);
        }
        let mut off = pre.clone();
        off.l2_settlement = None;
        assert_eq!(
            off.apply_transaction(
                &PosTransaction::L2Settlement(Box::new(original.clone())),
                0,
                1,
                &ProofDouble
            ),
            Err(TxReject::L2Settlement(Reject::NotActive))
        );
        for len in 0..TRANSACTION_BYTES {
            assert!(PosTransaction::from_canonical_bytes(&original.encode()[..len]).is_err());
        }
        assert!(
            PosTransaction::from_canonical_bytes(&[original.encode(), vec![0]].concat()).is_err()
        );
        assert!(pre
            .clone()
            .configure_l2_genesis(pre.l2_settlement().unwrap().policy().clone())
            .is_err());
    }
    #[test]
    fn native_l2_valid_foreign_groth16_never_authenticates_native_source() {
        let (pre, _) = fixture();
        let values =
            include_bytes!("../../../bloch-l2-proof/tests/fixtures/source-contract.values");
        let proof = include_bytes!("../../../bloch-l2-proof/tests/fixtures/source-contract.proof");
        let key = hash_at(values, S + 6 * 32);
        assert!(bloch_l2_proof::verify(
            &bloch_l2_proof::policy_commitment(),
            &key,
            values,
            proof
        ));
        let mut state = pre.clone();
        let tx = Transaction {
            proof_policy: bloch_l2_proof::policy_commitment(),
            statement: *values,
            proof: *proof,
        };
        assert_eq!(
            state.apply_transaction(
                &PosTransaction::L2Settlement(Box::new(tx)),
                0,
                1,
                &RealProof
            ),
            Err(TxReject::L2Settlement(Reject::Policy))
        );
        assert_eq!(state, pre);
    }
    #[test]
    fn native_l2_real_groth16_applies_in_the_actual_transition_and_replays() {
        let (pre, mut chains) = fixture();
        let statement =
            *include_bytes!("../../../bloch-l2-proof/tests/fixtures/native-empty.values");
        let proof = *include_bytes!("../../../bloch-l2-proof/tests/fixtures/native-empty.proof");
        let settlement = Transaction {
            proof_policy: pre.l2_settlement().unwrap().policy().proof_policy,
            statement,
            proof,
        };
        let tx = PosTransaction::L2Settlement(Box::new(settlement.clone()));
        assert_eq!(
            PosTransaction::from_canonical_bytes(&tx.canonical_bytes()).unwrap(),
            tx
        );
        let transition = Transition::new(RealProof);
        let block = build_block(
            &transition,
            &pre,
            2,
            &[],
            std::slice::from_ref(&tx),
            &mut chains,
        );
        let child = transition
            .apply_block(&pre, &block, &[], std::slice::from_ref(&tx))
            .unwrap();
        assert_eq!(
            child,
            transition
                .apply_block(&pre, &block, &[], std::slice::from_ref(&tx))
                .unwrap()
        );
        assert_eq!(
            child.l2_settlement().unwrap().head(),
            Some((settlement.commitment(), statement))
        );
        assert_eq!(child.l2_settlement().unwrap().height(), 2);
        assert_eq!(child.accounted_supply_sat(), pre.accounted_supply_sat());
        assert_ne!(child.state_root(), pre.state_root());
        // The complete encoded proof is covered by the block body. Corrupting it
        // fails block validation; a correctly rebound body still fails pairing.
        let mut corrupted = settlement.clone();
        corrupted.proof[12] ^= 1;
        let bad = PosTransaction::L2Settlement(Box::new(corrupted));
        assert!(transition
            .apply_block(&pre, &block, &[], std::slice::from_ref(&bad))
            .is_err());
        let mut bad_block = block.clone();
        bad_block.header.body_root = crate::derive::body_root(&[bad.canonical_bytes()]);
        let pk =
            crate::attestation::KeyLookup::pubkey(&pre, bad_block.header.proposer_index).unwrap();
        bad_block.proposer_sig = toy_sign(pk, &bad_block.header.proposal_signing_root());
        assert_eq!(
            transition.apply_block(&pre, &bad_block, &[], &[bad]),
            Err(TransitionError::Transaction(0))
        );
        let mut wrong_source = settlement;
        wrong_source.statement[S + 448] ^= 1;
        let mut unchanged = pre.clone();
        assert_eq!(
            unchanged.apply_transaction(
                &PosTransaction::L2Settlement(Box::new(wrong_source)),
                0,
                1,
                &RealProof
            ),
            Err(TxReject::L2Settlement(Reject::Source))
        );
        assert_eq!(unchanged, pre);
        assert!(transition.apply_block(&child, &block, &[], &[tx]).is_err());
    }
    #[test]
    fn native_l2_height_counts_committed_blocks_across_skipped_slots() {
        let (pre, mut chains) = fixture();
        let transition = Transition::new(ToyVerifier);
        let block = build_block(&transition, &pre, 5, &[], &[], &mut chains);
        let child = transition.apply_block(&pre, &block, &[], &[]).unwrap();
        assert_eq!(child.slot, 5);
        assert_eq!(child.l2_settlement().unwrap().height(), 2);
        let source = child
            .l2_settlement()
            .unwrap()
            .source(*child.head.as_bytes(), child.slot);
        assert_eq!(source.height, 2);
        assert_eq!(source.slot, 5);
    }
    #[test]
    fn native_l2_duplicate_proof_budget_is_enforced_before_verification() {
        let (pre, mut chains) = fixture();
        let tx = PosTransaction::L2Settlement(Box::new(transaction(&pre)));
        let t = Transition::new(ProofDouble);
        let mut block = build_block(&t, &pre, 2, &[], &[], &mut chains);
        let txs = vec![tx.clone(), tx];
        block.header.body_root = crate::derive::body_root(
            &txs.iter()
                .map(PosTransaction::canonical_bytes)
                .collect::<Vec<_>>(),
        );
        let pk = crate::attestation::KeyLookup::pubkey(&pre, block.header.proposer_index).unwrap();
        block.proposer_sig = toy_sign(pk, &block.header.proposal_signing_root());
        // ToyVerifier refuses every proof. Reaching the dedicated cap error
        // therefore proves the cap precedes proof verification.
        assert_eq!(
            Transition::new(ToyVerifier).compute_post_state(&pre, &block, &[], &txs),
            Err(TransitionError::BlockGasLimitExceeded)
        );
    }
    #[test]
    fn native_l2_policy_and_height_are_committed() {
        let (pre, _) = fixture();
        let original = pre.l2_settlement().unwrap();
        let base = pre.state_root();
        for i in 0..11 {
            let mut policy = original.policy().clone();
            match i {
                0..=6 => policy.identities[i][0] ^= 1,
                7 => policy.proof_policy[0] ^= 1,
                8 => policy.chain_id += 1,
                9 => policy.initial_l2_parent[0] ^= 1,
                10 => policy.initial_l2_state[0] ^= 1,
                _ => unreachable!(),
            }
            let mut state = crate::l2_settlement::State::genesis(policy).unwrap();
            state.advance_height().unwrap();
            let mut changed = pre.clone();
            changed.l2_settlement = Some(state);
            assert_ne!(changed.state_root(), base, "policy field {i}");
        }
        let mut changed = pre.clone();
        changed
            .l2_settlement
            .as_mut()
            .unwrap()
            .advance_height()
            .unwrap();
        assert_ne!(changed.state_root(), base);
    }
}
