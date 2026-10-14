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
    fn fixture() -> (CommittedState, Vec<RandaoChain>) { fixture_mode(false) }
    fn fixture_mode(asynchronous: bool) -> (CommittedState, Vec<RandaoChain>) {
        let (_, mut genesis, mut chains) = setup(4);
        let identities = std::array::from_fn(|i| hash_at(TEMPLATE, S + i * 32));
        let mut policy = Policy {
            identities,
            proof_policy: bloch_l2_proof::policy_commitment(),
            chain_id: 700771,
            initial_l2_parent: hash_at(TEMPLATE, S + 272),
            initial_l2_state: hash_at(TEMPLATE, S + 304),
            attestor_set: [0; 32],
        };
        policy.identities[0] = [0x91; 32];
        policy.identities[1] = *genesis.head.as_bytes();
        genesis.admission_network_domain = Some(policy.identities[0]);
        genesis = if asynchronous { genesis.configure_l2_genesis_async(policy) } else { genesis.configure_l2_genesis(policy) }.unwrap();
        let t = Transition::new(ToyVerifier);
        let first = build_block(&t, &genesis, 1, &[], &[], &mut chains);
        let pre = t.apply_block(&genesis, &first, &[], &[]).unwrap();
        assert_eq!(pre.l2_settlement().unwrap().height(), 1);
        (pre, chains)
    }
    fn transaction(pre: &CommittedState) -> Transaction {
        let state = pre.l2_settlement().unwrap();
        let source = state.source(*pre.head.as_bytes(), pre.slot);
        let mut statement = TEMPLATE.to_vec();
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
            statement: values.to_vec(),
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
    // The real proof binds the native source block id of the test chain built
    // on the pre-port tree (8d83d3a6…). The Genesis-4 port (M8) changes that
    // chain (cbe3051c…), so the source check refuses it before the pairing.
    // Regenerate native-empty.{values,proof} with the SP1 prover before M9.
    #[ignore = "native-empty fixture predates the Genesis-4 port; regenerate with the SP1 prover"]
    fn native_l2_real_groth16_applies_in_the_actual_transition_and_replays() {
        let (pre, mut chains) = fixture();
        let statement =
            include_bytes!("../../../bloch-l2-proof/tests/fixtures/native-empty.values").to_vec();
        let proof = *include_bytes!("../../../bloch-l2-proof/tests/fixtures/native-empty.proof");
        let settlement = Transaction {
            proof_policy: pre.l2_settlement().unwrap().policy().proof_policy,
            statement: statement.clone(),
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
        // Public fixture export for cross-repository recovery/PQ qualification.
        // These are actual accepted header/body bytes; no signing keys are saved.
        if let Some(path) = std::env::var_os("BLOCH_NATIVE_RECOVERY_EXPORT") {
            let path = std::path::PathBuf::from(path);
            std::fs::create_dir(&path).unwrap();
            for (name, bytes) in [
                ("header.bin", block.header.canonical_serialize().to_vec()),
                ("transaction.bin", tx.canonical_bytes()),
                ("state-root.bin", child.state_root().to_vec()),
            ] {
                use std::io::Write;
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(path.join(name))
                    .unwrap()
                    .write_all(&bytes)
                    .unwrap();
            }
        }
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

    #[test]
    fn async_source_survives_skipped_slots_and_rotates_only_after_acceptance() {
        let (mut pre, mut chains) = fixture_mode(true);
        assert!(pre.l2_settlement().unwrap().frozen_source().is_none());
        let anchor = *pre.head().as_bytes();
        let t = Transition::new(ProofDouble);
        for slot in [2, 7, 12] {
            let block = build_block(&t, &pre, slot, &[], &[], &mut chains);
            pre = t.apply_block(&pre, &block, &[], &[]).unwrap();
            let source = pre.l2_settlement().unwrap().frozen_source().unwrap();
            assert_eq!((source.block, source.slot, source.height), (anchor, 1, 1));
        }
        let old_source = pre.l2_settlement().unwrap().frozen_source().unwrap();
        let tx = PosTransaction::L2SettlementAsync(Box::new(transaction(&pre)));
        assert_eq!(tx.canonical_bytes()[0], crate::l2_settlement::ASYNC_WIRE_TAG);
        assert_eq!(crate::l2_settlement::ASYNC_WIRE_TAG, 0x13);
        assert_eq!(PosTransaction::from_canonical_bytes(&tx.canonical_bytes()).unwrap(), tx);
        let before = pre.state_root();
        let block = build_block(&t, &pre, 15, &[], std::slice::from_ref(&tx), &mut chains);
        let post = t.apply_block(&pre, &block, &[], std::slice::from_ref(&tx)).unwrap();
        assert_eq!(pre.state_root(), before);
        assert!(post.l2_settlement().unwrap().frozen_source().is_none());
        assert!(post.clone().apply_transaction(&tx, 0, 1, &ProofDouble).is_err());
        let next = build_block(&t, &post, 16, &[], &[], &mut chains);
        let next_state = t.apply_block(&post, &next, &[], &[]).unwrap();
        let source = next_state.l2_settlement().unwrap().frozen_source().unwrap();
        assert_eq!(source.block, *post.head().as_bytes());
        assert_eq!(source.height, post.l2_settlement().unwrap().height());
        assert_ne!(source.commitment, old_source.commitment);
        assert_eq!(post.accounted_supply_sat(), pre.accounted_supply_sat());
        assert_eq!(t.apply_block(&pre, &block, &[], &[tx]).unwrap(), post);
    }
    #[test]
    fn async_mode_source_and_proof_fail_closed_without_state_mutation() {
        let (pre, _) = fixture();
        let tx = transaction(&pre);
        assert!(pre.clone().apply_transaction(&PosTransaction::L2SettlementAsync(Box::new(tx)), 0, 1, &ProofDouble).is_err());
        let (pre, mut chains) = fixture_mode(true);
        let t = Transition::new(ProofDouble);
        let block = build_block(&t, &pre, 2, &[], &[], &mut chains);
        let pre = t.apply_block(&pre, &block, &[], &[]).unwrap();
        let original = transaction(&pre);
        assert!(pre.clone().apply_transaction(&PosTransaction::L2Settlement(Box::new(original.clone())), 0, 1, &ProofDouble).is_err());
        for offset in [S, S+32, S+224, S+264, S+400, S+432, S+440, S+448, S+512] {
            let mut changed = original.clone(); changed.statement[offset] ^= 1;
            let mut state = pre.clone();
            assert!(state.apply_transaction(&PosTransaction::L2SettlementAsync(Box::new(changed)), 0, 1, &ProofDouble).is_err());
            assert_eq!(state, pre);
        }
        let mut state = pre.clone();
        assert!(state.apply_transaction(&PosTransaction::L2SettlementAsync(Box::new(original)), 0, 1, &RealProof).is_err());
        assert_eq!(state, pre);
    }

    // ── Native L2 deposits (devnet-l2-deposits) ─────────────────────────────

    fn depositor() -> Vec<u8> {
        // Hybrid key geometry; ToyVerifier only needs it to be one fixed key.
        vec![0x5a; crate::transition::funded::ADMISSION_PQ_KEY_BYTES]
    }
    const FUNDED: u64 = 50_000_000_000;

    fn funded_async_fixture() -> (CommittedState, Vec<RandaoChain>) {
        let key = depositor();
        let coin = crate::state_root::EutxoEntry { txid: [0x33; 32], vout: 0, value: FUNDED, script_hash: script_of(&key) };
        let (_, mut genesis, mut chains) = setup_with(4, ToyVerifier, &[coin]);
        let identities = std::array::from_fn(|i| hash_at(TEMPLATE, S + i * 32));
        let mut policy = Policy {
            identities,
            proof_policy: bloch_l2_proof::policy_commitment(),
            chain_id: 700771,
            initial_l2_parent: hash_at(TEMPLATE, S + 272),
            initial_l2_state: hash_at(TEMPLATE, S + 304),
            attestor_set: [0; 32],
        };
        policy.identities[0] = [0x91; 32];
        policy.identities[1] = *genesis.head.as_bytes();
        genesis.admission_network_domain = Some(policy.identities[0]);
        genesis = genesis.configure_l2_genesis_async(policy).unwrap();
        let t = Transition::new(ToyVerifier);
        let first = build_block(&t, &genesis, 1, &[], &[], &mut chains);
        (t.apply_block(&genesis, &first, &[], &[]).unwrap(), chains)
    }

    fn deposit_tx(pre: &CommittedState, amount: u64) -> crate::transition::L2Deposit {
        let key = depositor();
        let mut tx = crate::transition::L2Deposit {
            network_domain: [0x91; 32],
            funding_pubkey: key.clone(),
            inputs: vec![crate::transition::FundingInput { txid: [0x33; 32], vout: 0 }],
            amount_sat: amount,
            recipient: [0x42; 20],
            change: TransferOutput { value: 0, script_hash: script_of(&key) },
            tx_bytes: 0,
            tip_millisat_per_gas: 0,
            signature: vec![0; 32],
        };
        tx.tx_bytes = tx.canonical_bytes().len() as u64;
        let charge = fee_market::charge(fee_market::TxClass::Eutxo { inputs: 1 }, tx.tx_bytes, pre.next_base_fee(), 0);
        tx.change.value = (u128::from(FUNDED) - u128::from(amount) - charge.base_fee_sat - charge.priority_fee_sat) as u64;
        tx.signature = toy_sign(&key, &tx.intent_root());
        tx
    }

    /// An async settlement for the frozen source, chaining from the current head.
    fn settlement(pre: &CommittedState, body: [u8; 32]) -> Transaction {
        let state = pre.l2_settlement().unwrap();
        let mut tx = transaction(pre);
        let source = state.source(*pre.head.as_bytes(), pre.slot);
        let s = &mut tx.statement;
        let end = source.inbox_count.min(state.consumed() + crate::l2_settlement::MAX_INBOX_PER_SETTLEMENT);
        s[S + 512..S + 520].copy_from_slice(&source.inbox_count.to_be_bytes());
        s[S + 520..S + 528].copy_from_slice(&state.consumed().to_be_bytes());
        s[S + 528..S + 536].copy_from_slice(&end.to_be_bytes());
        s[S + 536..S + 568].copy_from_slice(&body);
        if let Some((digest, old)) = state.head() {
            s[S + 224..S + 256].copy_from_slice(&digest);
            let number = u64::from_be_bytes(old[S + 264..S + 272].try_into().unwrap()) + 1;
            s[S + 264..S + 272].copy_from_slice(&number.to_be_bytes());
            s[S + 272..S + 304].copy_from_slice(&old[S + 336..S + 368]);
            s[S + 304..S + 336].copy_from_slice(&old[S + 368..S + 400]);
            s[S + 336] ^= number as u8; // a distinct successor header
        }
        tx
    }

    fn apply(pre: &CommittedState, slot: u64, txs: &[PosTransaction], chains: &mut [RandaoChain]) -> Result<CommittedState, TransitionError> {
        let t = Transition::new(ProofDouble);
        let block = build_block(&t, pre, slot, &[], txs, chains);
        t.apply_block(pre, &block, &[], txs)
    }

    #[test]
    #[cfg(feature = "devnet-l2-deposits")]
    fn l2_deposit_escrows_and_the_next_settlement_must_mint_it_exactly() {
        let (pre, mut chains) = funded_async_fixture();
        let amount = 7_000_000_000;
        let tx = deposit_tx(&pre, amount);
        let wire = PosTransaction::L2Deposit(tx.clone());
        assert_eq!(PosTransaction::from_canonical_bytes(&wire.canonical_bytes()).unwrap(), wire);
        let supply = pre.accounted_supply_sat();
        let s2 = apply(&pre, 2, std::slice::from_ref(&wire), &mut chains).expect("deposit applies");
        let l2 = s2.l2_settlement().unwrap();
        assert_eq!(l2.inbox().len(), 1);
        let record = l2.inbox()[0];
        assert_eq!((record.sats, record.recipient, record.vout, record.tx_index), (amount, [0x42; 20], 1, 0));
        assert_eq!(record.txid, wire.txid());
        assert_eq!(record.height, pre.l2_settlement().unwrap().height() + 1);
        assert_eq!(l2.escrow_sat(), u128::from(amount));
        assert!(s2.eutxos.get(&([0x33; 32], 0)).is_none(), "input spent");
        assert_eq!(s2.eutxos.get(&(wire.txid(), 0)).unwrap().value, tx.change.value);
        // Escrow leaves the spendable set but stays in the accounted supply
        // (M5: claims move it back out); only the fee leaves.
        assert!(s2.eutxos.total_sat() + u128::from(amount) < pre.eutxos.total_sat() + 1);
        assert!(s2.accounted_supply_sat() <= supply && supply - s2.accounted_supply_sat() < u128::from(amount));
        assert!(s2.l2_settlement().unwrap().escrow_conserved());
        // Replaying the same deposit fails (input already spent).
        let mut replay = s2.clone();
        assert!(replay.apply_transaction(&wire, 0, s2.next_base_fee(), &ToyVerifier).is_err());
        assert_eq!(replay, s2);

        // Block 3: the anchor predates the deposit, so it consumes nothing.
        let empty = crate::l2_settlement::expected_body_commitment(&[]);
        let first = PosTransaction::L2SettlementAsync(Box::new(settlement(&s2, empty)));
        let s3 = apply(&s2, 3, std::slice::from_ref(&first), &mut chains).expect("empty settlement");
        assert_eq!(s3.l2_settlement().unwrap().consumed(), 0);

        // Block 4: anchored after the deposit; it must mint exactly that record.
        let s3b = apply(&s3, 4, &[], &mut chains).unwrap();
        for wrong in [empty, crate::l2_settlement::expected_body_commitment(&[crate::l2_settlement::InboxRecord { sats: amount + 1, ..record }])] {
            let bad = settlement(&s3b, wrong);
            let mut l2 = s3b.l2_settlement().unwrap().clone();
            let r = l2.apply(&bad, *s3b.head.as_bytes(), s3b.slot, true, &ProofDouble);
            assert_eq!(r, Err(Reject::Deposits), "wrong body must be refused");
        }
        let exact = crate::l2_settlement::expected_body_commitment(&[record]);
        let good = PosTransaction::L2SettlementAsync(Box::new(settlement(&s3b, exact)));
        let s5 = apply(&s3b, 5, std::slice::from_ref(&good), &mut chains).expect("exact body settles the deposit");
        assert_eq!(s5.l2_settlement().unwrap().consumed(), 1);
        assert_ne!(s5.state_root(), s3b.state_root());
    }

    #[test]
    #[cfg(feature = "devnet-l2-deposits")]
    fn invalid_l2_deposits_are_refused_without_mutation() {
        let (pre, _) = funded_async_fixture();
        let base = deposit_tx(&pre, 7_000_000_000);
        let fee = pre.next_base_fee();
        let mut cases = Vec::new();
        let mut t = base.clone();
        t.network_domain = [0x92; 32];
        t.signature = toy_sign(&t.funding_pubkey, &t.intent_root());
        cases.push(("network", t));
        let mut t = base.clone();
        t.signature[0] ^= 1;
        cases.push(("signature", t));
        let mut t = base.clone();
        t.change.value += 1;
        t.signature = toy_sign(&t.funding_pubkey, &t.intent_root());
        cases.push(("conservation", t));
        let mut t = base.clone();
        t.amount_sat = crate::transition::l2_deposit::MIN_L2_DEPOSIT_SAT - 1;
        t.signature = toy_sign(&t.funding_pubkey, &t.intent_root());
        cases.push(("minimum", t));
        let mut t = base.clone();
        t.funding_pubkey[0] ^= 1; // not the coin's owner
        t.signature = toy_sign(&t.funding_pubkey, &t.intent_root());
        cases.push(("ownership", t));
        let mut t = base.clone();
        t.recipient = [0; 20];
        t.signature = toy_sign(&t.funding_pubkey, &t.intent_root());
        cases.push(("recipient", t));
        for (name, tx) in cases {
            let mut state = pre.clone();
            assert!(state.apply_transaction(&PosTransaction::L2Deposit(tx), 0, fee, &ToyVerifier).is_err(), "{name}");
            assert_eq!(state, pre, "{name} mutated state");
        }
    }

    #[test]
    #[cfg(not(feature = "devnet-l2-deposits"))]
    fn l2_deposits_are_inert_without_the_development_feature() {
        let (pre, _) = funded_async_fixture();
        let mut state = pre.clone();
        let tx = PosTransaction::L2Deposit(deposit_tx(&pre, 7_000_000_000));
        assert!(state.apply_transaction(&tx, 0, pre.next_base_fee(), &ToyVerifier).is_err());
        assert_eq!(state, pre);
    }

    // ── Settlement V3: user transactions, deposits bound by deposits_hash ──

    use crate::l2_settlement::{v3, STATEMENT_V3_BYTES, STATEMENT_V3_TAG, TRANSACTION_V3_BYTES};

    /// Promote a V2 statement to V3: V3 tag, V2 fields unchanged, then the
    /// V3 commitments for a body with `user_txs` transactions minting
    /// `deposits` and no withdrawals (the empty withdrawal tree).
    fn to_v3(mut tx: Transaction, deposits: [u8; 32], user_txs: u64) -> Transaction {
        let s = &mut tx.statement;
        s[..S].copy_from_slice(STATEMENT_V3_TAG);
        s.resize(STATEMENT_V3_BYTES, 0);
        s[S + v3::DEPOSITS_HASH..S + v3::DEPOSITS_HASH + 32].copy_from_slice(&deposits);
        s[S + v3::TRANSACTIONS_ROOT..S + v3::TRANSACTIONS_ROOT + 32].copy_from_slice(&[0x7a; 32]);
        s[S + v3::RECEIPTS_ROOT..S + v3::RECEIPTS_ROOT + 32].copy_from_slice(&[0x7b; 32]);
        s[S + v3::USER_TX_COUNT..S + v3::USER_TX_COUNT + 8].copy_from_slice(&user_txs.to_be_bytes());
        s[S + v3::WITHDRAWAL_ROOT..S + v3::WITHDRAWAL_ROOT + 32]
            .copy_from_slice(&crate::l2_settlement::withdrawal::empty_root());
        // M3: user transactions name their L1 batch; none means zero.
        if user_txs != 0 {
            s[S + v3::DA_COMMITMENT..S + v3::DA_COMMITMENT + 32].copy_from_slice(&TEST_DA);
        }
        // A body with user transactions has a body commitment the native
        // chain cannot recompute; V3 must not try.
        s[S + 536..S + 568].copy_from_slice(&[0x5c; 32]);
        tx
    }
    const TEST_DA: [u8; 32] = [0xd7; 32];
    /// `state` plus an L1 DA record for `tx`'s block and commitment, included
    /// at the state's current native height (an earlier block than the one
    /// that will apply `tx`). Unchanged when `tx` has no user transactions.
    fn ready(state: &CommittedState, tx: &Transaction) -> CommittedState {
        let s = &tx.statement;
        let users = u64::from_be_bytes(s[S + v3::USER_TX_COUNT..S + v3::USER_TX_COUNT + 8].try_into().unwrap());
        let mut out = state.clone();
        if users != 0 {
            let l2 = out.l2_settlement.as_mut().unwrap();
            let height = l2.height();
            l2.insert_da_record(crate::l2_settlement::da::Record {
                l2_number: u64::from_be_bytes(s[S + 264..S + 272].try_into().unwrap()),
                commitment: s[S + v3::DA_COMMITMENT..S + v3::DA_COMMITMENT + 32].try_into().unwrap(),
                height,
            });
        }
        out
    }
    fn no_deposits() -> [u8; 32] {
        crate::l2_settlement::deposits_hash(&[])
    }
    /// User transaction count for tests that must pass on every build: real
    /// user transactions only where the devnet feature admits them (M2.6).
    fn user_txs(n: u64) -> u64 {
        if crate::l2_settlement::USER_TRANSACTIONS_ENABLED { n } else { 0 }
    }

    #[test]
    fn v3_settlement_with_user_transactions_is_accepted_and_replays() {
        let (pre, mut chains) = fixture();
        let settlement = to_v3(transaction(&pre), no_deposits(), user_txs(3));
        let pre = ready(&pre, &settlement);
        let tx = PosTransaction::L2Settlement(Box::new(settlement.clone()));
        let bytes = tx.canonical_bytes();
        assert_eq!(bytes.len(), TRANSACTION_V3_BYTES);
        assert_eq!(bytes[0], crate::l2_settlement::WIRE_TAG);
        assert_eq!(PosTransaction::from_canonical_bytes(&bytes).unwrap(), tx);
        let t = Transition::new(ProofDouble);
        let block = build_block(&t, &pre, 2, &[], std::slice::from_ref(&tx), &mut chains);
        let post = t.apply_block(&pre, &block, &[], std::slice::from_ref(&tx)).unwrap();
        assert_eq!(post, t.apply_block(&pre, &block, &[], std::slice::from_ref(&tx)).unwrap());
        let (commitment, head) = post.l2_settlement().unwrap().head().unwrap();
        assert_eq!((commitment, head.len()), (settlement.commitment(), STATEMENT_V3_BYTES));
        assert_ne!(post.state_root(), pre.state_root());
        assert_eq!(post.accounted_supply_sat(), pre.accounted_supply_sat());
        // Replay: the same settlement cannot be applied on top of itself.
        let mut again = post.clone();
        assert_eq!(
            again.apply_transaction(&tx, 0, 1, &ProofDouble),
            Err(TxReject::L2Settlement(Reject::Source))
        );
        assert_eq!(again, post);
        // The real verifier still decides: ToyVerifier refuses the proof.
        let mut refused = pre.clone();
        assert_eq!(
            refused.apply_transaction(&tx, 0, 1, &ToyVerifier),
            Err(TxReject::L2Settlement(Reject::Proof))
        );
    }

    /// M2.6 production guard: until L1 data availability (M3) exists, only a
    /// `devnet-l2-user-txs` build admits a V3 settlement with user transactions.
    /// The check runs before deposits and the proof, and never mutates state.
    #[test]
    fn v3_user_transactions_require_the_devnet_feature() {
        let (pre, _) = fixture();
        assert_eq!(crate::l2_settlement::USER_TRANSACTIONS_ENABLED, cfg!(feature = "devnet-l2-user-txs"));
        for count in [1u64, 2, u64::MAX] {
            let settlement = to_v3(transaction(&pre), no_deposits(), count);
            let mut state = ready(&pre, &settlement);
            let before = state.clone();
            let tx = PosTransaction::L2Settlement(Box::new(settlement));
            let result = state.apply_transaction(&tx, 0, 1, &ProofDouble);
            if cfg!(feature = "devnet-l2-user-txs") {
                assert!(result.is_ok(), "count {count}: {result:?}");
            } else {
                assert_eq!(result, Err(TxReject::L2Settlement(Reject::UserTransactions)), "count {count}");
                assert_eq!(state, before, "count {count} mutated state");
            }
        }
        // A deposit-only V3 settlement (user_tx_count = 0) is accepted on every build.
        let tx = PosTransaction::L2Settlement(Box::new(to_v3(transaction(&pre), no_deposits(), 0)));
        let mut state = pre.clone();
        assert!(state.apply_transaction(&tx, 0, 1, &ProofDouble).is_ok());
        // The guard does not apply to V2 statements, which cannot carry user
        // transactions at all (their body is recomputed as deposit-only).
        assert!(pre.clone().apply_transaction(&PosTransaction::L2Settlement(Box::new(transaction(&pre))), 0, 1, &ProofDouble).is_ok());
    }

    #[test]
    fn v3_rejects_wrong_length_tag_deposits_and_reserved_fields() {
        let (pre, _) = fixture();
        let good = to_v3(transaction(&pre), no_deposits(), user_txs(1));
        let pre = ready(&pre, &good);
        let encoded = good.encode();
        // Wrong length: every truncation, and a suffix.
        for len in 0..TRANSACTION_V3_BYTES {
            assert!(PosTransaction::from_canonical_bytes(&encoded[..len]).is_err(), "len {len}");
        }
        assert!(PosTransaction::from_canonical_bytes(&[encoded.clone(), vec![0]].concat()).is_err());
        // Wrong tag: a V2 tag on V3 length, a V3 tag on V2 length, a mangled tag.
        let mut v2_tag = encoded.clone();
        v2_tag[33..33 + S].copy_from_slice(STATEMENT_TAG);
        assert!(PosTransaction::from_canonical_bytes(&v2_tag).is_err());
        let mut v3_on_v2 = transaction(&pre).encode();
        v3_on_v2[33..33 + S].copy_from_slice(STATEMENT_V3_TAG);
        assert!(PosTransaction::from_canonical_bytes(&v3_on_v2).is_err());
        let mut mangled = encoded.clone();
        mangled[33 + S - 1] ^= 1;
        assert!(PosTransaction::from_canonical_bytes(&mangled).is_err());
        // An in-memory statement of neither shape is refused by apply.
        let mut odd = good.clone();
        odd.statement.push(0);
        let mut state = pre.clone();
        assert_eq!(
            state.apply_transaction(&PosTransaction::L2Settlement(Box::new(odd)), 0, 1, &ProofDouble),
            Err(TxReject::L2Settlement(Reject::Policy))
        );
        // Field-level rejections leave state untouched.
        let cases: Vec<(&str, usize, Reject)> = vec![
            ("deposits_hash", S + v3::DEPOSITS_HASH, Reject::Deposits),
            // M4: without new withdrawals the root must stay the empty tree,
            // and a new leaf must move the root.
            ("withdrawal_root", S + v3::WITHDRAWAL_ROOT, Reject::Withdrawals),
            ("withdrawal_count", S + v3::WITHDRAWAL_COUNT + 7, Reject::Withdrawals),
            // Zero is the only value without user transactions; with them,
            // any other commitment has no L1 record.
            (
                "da_commitment",
                S + v3::DA_COMMITMENT,
                if crate::l2_settlement::USER_TRANSACTIONS_ENABLED { Reject::DataUnavailable } else { Reject::Reserved },
            ),
        ];
        for (name, offset, reject) in cases {
            let mut bad = good.clone();
            bad.statement[offset] ^= 1;
            let mut state = pre.clone();
            assert_eq!(
                state.apply_transaction(&PosTransaction::L2Settlement(Box::new(bad)), 0, 1, &ProofDouble),
                Err(TxReject::L2Settlement(reject)),
                "{name}"
            );
            assert_eq!(state, pre, "{name} mutated state");
        }
        for zeroed in [v3::TRANSACTIONS_ROOT, v3::RECEIPTS_ROOT] {
            let mut bad = good.clone();
            bad.statement[S + zeroed..S + zeroed + 32].fill(0);
            let mut state = pre.clone();
            assert_eq!(
                state.apply_transaction(&PosTransaction::L2Settlement(Box::new(bad)), 0, 1, &ProofDouble),
                Err(TxReject::L2Settlement(Reject::Reserved))
            );
        }
        // Every V2-prefix field still binds policy, source and successor.
        for offset in [S, S + 224, S + 256, S + 264, S + 272, S + 304, S + 400, S + 432, S + 448, S + 480, S + 512, S + 528] {
            let mut bad = good.clone();
            bad.statement[offset] ^= 1;
            let mut state = pre.clone();
            assert!(
                state.apply_transaction(&PosTransaction::L2Settlement(Box::new(bad)), 0, 1, &ProofDouble).is_err(),
                "offset {offset}"
            );
            assert_eq!(state, pre);
        }
    }

    #[test]
    fn v3_out_of_order_settlement_is_refused() {
        let (pre, mut chains) = fixture();
        let t = Transition::new(ProofDouble);
        let first = to_v3(transaction(&pre), no_deposits(), user_txs(1));
        let pre = ready(&pre, &first);
        let first = PosTransaction::L2Settlement(Box::new(first));
        let block = build_block(&t, &pre, 2, &[], std::slice::from_ref(&first), &mut chains);
        let s2 = t.apply_block(&pre, &block, &[], std::slice::from_ref(&first)).unwrap();
        // Skips a number / does not chain from the accepted head.
        let state = s2.l2_settlement().unwrap();
        let (digest, old) = state.head().unwrap();
        let mut next = to_v3(transaction(&s2), no_deposits(), user_txs(2));
        next.statement[S + 224..S + 256].copy_from_slice(&digest);
        next.statement[S + 272..S + 304].copy_from_slice(&old[S + 336..S + 368]);
        next.statement[S + 304..S + 336].copy_from_slice(&old[S + 368..S + 400]);
        for (name, number, previous) in [("skipped", 3u64, digest), ("unchained", 2, [0xee; 32])] {
            let mut bad = next.clone();
            bad.statement[S + 264..S + 272].copy_from_slice(&number.to_be_bytes());
            bad.statement[S + 224..S + 256].copy_from_slice(&previous);
            let mut st = s2.clone();
            assert_eq!(
                st.apply_transaction(&PosTransaction::L2Settlement(Box::new(bad)), 0, 1, &ProofDouble),
                Err(TxReject::L2Settlement(Reject::Successor)),
                "{name}"
            );
        }
        // The correctly chained successor is accepted (state built in a block).
        next.statement[S + 264..S + 272].copy_from_slice(&2u64.to_be_bytes());
        let s2 = ready(&s2, &next);
        let tx = PosTransaction::L2Settlement(Box::new(next));
        let block = build_block(&t, &s2, 3, &[], std::slice::from_ref(&tx), &mut chains);
        let s3 = t.apply_block(&s2, &block, &[], std::slice::from_ref(&tx)).unwrap();
        assert_eq!(s3.l2_settlement().unwrap().head().unwrap().1[S + 271], 2);
    }

    #[test]
    #[cfg(feature = "devnet-l2-deposits")]
    fn v3_deposits_must_match_the_inbox_while_user_transactions_settle() {
        let (pre, mut chains) = funded_async_fixture();
        let amount = 7_000_000_000;
        let wire = PosTransaction::L2Deposit(deposit_tx(&pre, amount));
        let s2 = apply(&pre, 2, std::slice::from_ref(&wire), &mut chains).unwrap();
        let record = s2.l2_settlement().unwrap().inbox()[0];
        // Anchor predates the deposit: consumes nothing, user txs only.
        let empty = crate::l2_settlement::expected_body_commitment(&[]);
        let first = to_v3(settlement(&s2, empty), no_deposits(), user_txs(4));
        let s2 = ready(&s2, &first);
        let first = PosTransaction::L2SettlementAsync(Box::new(first));
        let s3 = apply(&s2, 3, std::slice::from_ref(&first), &mut chains).expect("V3 with user txs, no deposits");
        assert_eq!(s3.l2_settlement().unwrap().consumed(), 0);
        let s3b = apply(&s3, 4, &[], &mut chains).unwrap();
        // Now the deposit must be minted: deposits_hash binds it exactly.
        let exact = crate::l2_settlement::deposits_hash(&[record]);
        for wrong in [
            no_deposits(),
            crate::l2_settlement::deposits_hash(&[crate::l2_settlement::InboxRecord { sats: amount + 1, ..record }]),
            crate::l2_settlement::deposits_hash(&[crate::l2_settlement::InboxRecord { recipient: [0x43; 20], ..record }]),
            crate::l2_settlement::deposits_hash(&[record, record]),
        ] {
            let bad = to_v3(settlement(&s3b, empty), wrong, user_txs(2));
            let mut l2 = s3b.l2_settlement().unwrap().clone();
            assert_eq!(l2.apply(&bad, *s3b.head.as_bytes(), s3b.slot, true, &ProofDouble), Err(Reject::Deposits));
        }
        // A wrong consumed range is refused before deposits are compared.
        let mut range = to_v3(settlement(&s3b, empty), exact, user_txs(2));
        range.statement[S + 528..S + 536].copy_from_slice(&0u64.to_be_bytes());
        let mut l2 = s3b.l2_settlement().unwrap().clone();
        assert_eq!(l2.apply(&range, *s3b.head.as_bytes(), s3b.slot, true, &ProofDouble), Err(Reject::Source));
        // The V3 body commitment is NOT recomputed: any body (here with two
        // user txs) settles as long as deposits_hash matches the inbox.
        let good = to_v3(settlement(&s3b, empty), exact, user_txs(2));
        let s3b = ready(&s3b, &good);
        let good = PosTransaction::L2SettlementAsync(Box::new(good));
        let s5 = apply(&s3b, 5, std::slice::from_ref(&good), &mut chains).expect("V3 mints the deposit");
        assert_eq!(s5.l2_settlement().unwrap().consumed(), 1);
        assert_eq!(s5.l2_settlement().unwrap().escrow_sat(), u128::from(amount));
        // Replaying the accepted settlement fails.
        let mut replay = s5.clone();
        assert!(replay.apply_transaction(&good, 0, 1, &ProofDouble).is_err());
        assert_eq!(replay, s5);
    }

    #[test]
    #[cfg(feature = "devnet-l2-deposits")]
    fn v2_history_still_requires_the_empty_transaction_body() {
        // V2 keeps its exact rule: a V2 statement whose body commitment is not
        // the deposit-only body is refused even when deposits are empty.
        let (pre, mut chains) = funded_async_fixture();
        let s2 = apply(&pre, 2, &[], &mut chains).unwrap();
        let with_user_txs = settlement(&s2, [0x5c; 32]);
        let mut l2 = s2.l2_settlement().unwrap().clone();
        assert_eq!(l2.apply(&with_user_txs, *s2.head.as_bytes(), s2.slot, true, &ProofDouble), Err(Reject::Deposits));
        let empty = crate::l2_settlement::expected_body_commitment(&[]);
        let ok = PosTransaction::L2SettlementAsync(Box::new(settlement(&s2, empty)));
        assert!(apply(&s2, 3, std::slice::from_ref(&ok), &mut chains).is_ok());
    }

    // ── M3: L1 data availability (0x15, devnet-l2-user-txs) ─────────────────

    use crate::l2_settlement::da;
    use crate::transition::l2_da::{L2DataAvailability, L2DataAvailabilityReject as DaReject};

    /// Canonical batch of `txs` (see `l2_settlement::da`).
    fn batch(txs: &[&[u8]]) -> Vec<u8> {
        let mut out = (txs.len() as u32).to_be_bytes().to_vec();
        for tx in txs {
            out.extend_from_slice(&(tx.len() as u32).to_be_bytes());
            out.extend_from_slice(tx);
        }
        out
    }

    /// A signed DA transaction spending `coin` (value, at `outpoint`) with
    /// all remaining value back as change.
    fn da_tx(pre: &CommittedState, outpoint: ([u8; 32], u32), value: u64, number: u64, payload: Vec<u8>) -> L2DataAvailability {
        let key = depositor();
        let mut tx = L2DataAvailability {
            network_domain: [0x91; 32],
            funding_pubkey: key.clone(),
            inputs: vec![crate::transition::FundingInput { txid: outpoint.0, vout: outpoint.1 }],
            l2_chain_id: 700771,
            l2_block_number: number,
            payload,
            change: TransferOutput { value: 0, script_hash: script_of(&key) },
            tx_bytes: 0,
            tip_millisat_per_gas: 0,
            signature: vec![0; 32],
        };
        tx.tx_bytes = tx.canonical_bytes().len() as u64;
        let charge = fee_market::charge(fee_market::TxClass::Eutxo { inputs: 1 }, tx.tx_bytes, pre.next_base_fee(), 0);
        tx.change.value = (u128::from(value) - charge.base_fee_sat - charge.priority_fee_sat) as u64;
        tx.signature = toy_sign(&key, &tx.intent_root());
        tx
    }
    fn resign(mut tx: L2DataAvailability) -> L2DataAvailability {
        tx.signature = toy_sign(&tx.funding_pubkey, &tx.intent_root());
        tx
    }

    /// V3 user-transaction settlement of the next L2 block naming `commitment`.
    fn v3_with_da(pre: &CommittedState, commitment: [u8; 32]) -> Transaction {
        let empty = crate::l2_settlement::expected_body_commitment(&[]);
        let mut tx = to_v3(settlement(pre, empty), no_deposits(), 2);
        tx.statement[S + v3::DA_COMMITMENT..S + v3::DA_COMMITMENT + 32].copy_from_slice(&commitment);
        tx
    }

    /// Shared with bloch-l2-evm `da_batch_cross_repository_vector`: the same
    /// payload bytes must produce the same commitment in both codecs.
    #[test]
    fn da_batch_matches_the_shared_vector() {
        let text = include_str!("../../tests/fixtures/l2-da-v1/batch.hex");
        let payload = hex::decode(text.trim()).unwrap();
        let tx2: Vec<u8> = (0u8..100).collect();
        assert_eq!(payload, batch(&[&[0x02, 0xc0], &tx2]));
        assert_eq!(da::batch_count(&payload), Some(2));
        let digest = hex::encode(da::commitment(700771, 7, &payload));
        assert_eq!(digest, include_str!("../../tests/fixtures/l2-da-v1/commitment-700771-7.hex").trim());
        // Chain and block number are bound.
        assert_ne!(da::commitment(700772, 7, &payload), da::commitment(700771, 7, &payload));
        assert_ne!(da::commitment(700771, 8, &payload), da::commitment(700771, 7, &payload));
    }

    /// The exact 0x15 wire frame carrying the shared batch, pinned for the
    /// settler's independent parser (bloch-l2-evm `deployment/devnet`).
    #[test]
    fn l2_da_wire_frame_matches_the_shared_vector() {
        let payload = hex::decode(include_str!("../../tests/fixtures/l2-da-v1/batch.hex").trim()).unwrap();
        let tx = L2DataAvailability {
            network_domain: [0x91; 32],
            funding_pubkey: vec![0x5a; crate::transition::funded::ADMISSION_PQ_KEY_BYTES],
            inputs: vec![crate::transition::FundingInput { txid: [0x33; 32], vout: 0 }],
            l2_chain_id: 700771,
            l2_block_number: 7,
            payload,
            change: TransferOutput { value: 12_345, script_hash: [0x44; 32] },
            tx_bytes: 9_000,
            tip_millisat_per_gas: 0,
            signature: vec![0x66; 64],
        };
        let wire = PosTransaction::L2DataAvailability(tx.clone());
        let bytes = wire.canonical_bytes();
        assert_eq!(hex::encode(&bytes), include_str!("../../tests/fixtures/l2-da-v1/tx-0x15.hex").trim());
        assert_eq!(PosTransaction::from_canonical_bytes(&bytes).unwrap(), wire);
        assert_eq!(
            hex::encode(tx.commitment()),
            include_str!("../../tests/fixtures/l2-da-v1/commitment-700771-7.hex").trim()
        );
    }

    #[test]
    fn da_batch_codec_is_exact_and_size_capped() {
        assert_eq!(da::batch_count(&batch(&[b"a"])), Some(1));
        for bad in [
            vec![],
            vec![0, 0, 0],
            batch(&[]),                                  // zero transactions
            batch(&[b""]),                               // empty envelope
            [batch(&[b"a"]), vec![0]].concat(),          // trailing byte
            batch(&[b"ab"])[..batch(&[b"ab"]).len() - 1].to_vec(), // truncated
            vec![0, 0, 0, 2, 0, 0, 0, 1, 7],             // count too high
            vec![0xff, 0xff, 0xff, 0xff],                // huge count, no data
        ] {
            assert_eq!(da::batch_count(&bad), None, "{bad:?}");
        }
        // Exactly at the cap is accepted, one byte more is refused.
        let fill = da::MAX_PAYLOAD_BYTES - 8;
        let at_cap = batch(&[&vec![1u8; fill]]);
        assert_eq!(at_cap.len(), da::MAX_PAYLOAD_BYTES);
        assert_eq!(da::batch_count(&at_cap), Some(1));
        assert_eq!(da::batch_count(&batch(&[&vec![1u8; fill + 1]])), None);
    }

    #[test]
    #[cfg(feature = "devnet-l2-user-txs")]
    fn l2_da_publishes_a_batch_and_unlocks_exactly_that_settlement() {
        let (genesis, mut chains) = funded_async_fixture();
        // One empty block anchors the asynchronous source.
        let pre = apply(&genesis, 2, &[], &mut chains).unwrap();
        let payload = batch(&[&[0x02, 0xc0], b"second"]);
        let tx = da_tx(&pre, ([0x33; 32], 0), FUNDED, 1, payload.clone());
        let commitment = da::commitment(700771, 1, &payload);
        assert_eq!(tx.commitment(), commitment);
        let wire = PosTransaction::L2DataAvailability(tx.clone());
        let bytes = wire.canonical_bytes();
        assert_eq!(bytes[0], 0x15);
        assert_eq!(PosTransaction::from_canonical_bytes(&bytes).unwrap(), wire);
        assert!(bytes.len() <= crate::transition::l2_da::MAX_L2_DATA_AVAILABILITY_BYTES);

        // Missing DA: the user-transaction settlement is refused.
        let settle = v3_with_da(&pre, commitment);
        let mut l2 = pre.l2_settlement().unwrap().clone();
        assert_eq!(l2.apply(&settle, *pre.head.as_bytes(), pre.slot, true, &ProofDouble), Err(Reject::DataUnavailable));

        // Same block: DA then settlement. The record is not yet from an
        // earlier native block, so the settlement is still refused.
        let mut same = pre.clone();
        same.apply_transaction(&wire, 0, pre.next_base_fee(), &ToyVerifier).expect("DA applies");
        assert_eq!(
            same.apply_transaction(&PosTransaction::L2SettlementAsync(Box::new(settle.clone())), 0, 1, &ProofDouble),
            Err(TxReject::L2Settlement(Reject::DataUnavailable))
        );

        // Block 2 includes the DA; only the commitment is stored.
        let s2 = apply(&pre, 3, std::slice::from_ref(&wire), &mut chains).expect("DA block");
        let records = s2.l2_settlement().unwrap().data_availability().to_vec();
        assert_eq!(records, vec![da::Record { l2_number: 1, commitment, height: 3 }]);
        assert!(s2.eutxos.get(&([0x33; 32], 0)).is_none(), "fee input spent");
        assert_eq!(s2.eutxos.get(&(wire.txid(), 0)).unwrap().value, tx.change.value);
        assert_ne!(s2.state_root(), pre.state_root());
        // Replay of the same DA transaction: its input is gone.
        let mut replay = s2.clone();
        assert_eq!(
            replay.apply_transaction(&wire, 0, s2.next_base_fee(), &ToyVerifier),
            Err(TxReject::L2DataAvailability(DaReject::MissingInput))
        );
        assert_eq!(replay, s2);

        // Wrong commitment: refused. The matching one settles in block 3.
        let mut l2 = s2.l2_settlement().unwrap().clone();
        let wrong = v3_with_da(&s2, da::commitment(700771, 1, &batch(&[b"other"])));
        assert_eq!(l2.apply(&wrong, *s2.head.as_bytes(), s2.slot, true, &ProofDouble), Err(Reject::DataUnavailable));
        // A user-transaction settlement with a zero commitment never matches.
        let zero = v3_with_da(&s2, [0; 32]);
        assert_eq!(l2.apply(&zero, *s2.head.as_bytes(), s2.slot, true, &ProofDouble), Err(Reject::DataUnavailable));
        let good = PosTransaction::L2SettlementAsync(Box::new(v3_with_da(&s2, commitment)));
        let s3 = apply(&s2, 4, std::slice::from_ref(&good), &mut chains).expect("settles with DA");
        assert_eq!(s3.l2_settlement().unwrap().settled_number(), 1);
        // The record is consumed with its block; a DA for block 1 is now stale.
        assert!(s3.l2_settlement().unwrap().data_availability().is_empty());
        let late = da_tx(&s3, (wire.txid(), 0), tx.change.value, 1, payload.clone());
        let mut st = s3.clone();
        assert_eq!(
            st.apply_transaction(&PosTransaction::L2DataAvailability(late), 0, s3.next_base_fee(), &ToyVerifier),
            Err(TxReject::L2DataAvailability(DaReject::Number))
        );
        assert_eq!(st, s3);
    }

    #[test]
    #[cfg(feature = "devnet-l2-user-txs")]
    fn invalid_l2_da_transactions_are_refused_without_mutation() {
        let (pre, _) = funded_async_fixture();
        let payload = batch(&[b"tx"]);
        let base = da_tx(&pre, ([0x33; 32], 0), FUNDED, 1, payload.clone());
        let fee = pre.next_base_fee();
        let mut cases: Vec<(&str, L2DataAvailability, DaReject)> = Vec::new();
        cases.push(("chain", resign(L2DataAvailability { l2_chain_id: 700772, ..base.clone() }), DaReject::Chain));
        cases.push(("settled number", resign(L2DataAvailability { l2_block_number: 0, ..base.clone() }), DaReject::Number));
        cases.push((
            "beyond window",
            resign(L2DataAvailability { l2_block_number: da::WINDOW + 1, ..base.clone() }),
            DaReject::Number,
        ));
        cases.push(("network", resign(L2DataAvailability { network_domain: [0x92; 32], ..base.clone() }), DaReject::Network));
        let mut t = base.clone();
        t.signature[0] ^= 1;
        cases.push(("signature", t, DaReject::Signature));
        let mut t = base.clone();
        t.change.value += 1;
        cases.push(("conservation", resign(t), DaReject::Conservation));
        let mut t = base.clone();
        t.funding_pubkey[0] ^= 1;
        cases.push(("ownership", resign(t), DaReject::Ownership));
        for payload in [batch(&[]), [payload.clone(), vec![0]].concat(), batch(&[&vec![1u8; da::MAX_PAYLOAD_BYTES]])] {
            let mut t = base.clone();
            t.payload = payload;
            t.tx_bytes = t.canonical_bytes().len() as u64 + 64;
            cases.push(("payload", resign(t), DaReject::Payload));
        }
        let mut t = base.clone();
        t.tx_bytes -= 1;
        cases.push(("underdeclared", resign(t), DaReject::UnderdeclaredSize));
        for (name, tx, reject) in cases {
            let mut state = pre.clone();
            assert_eq!(
                state.apply_transaction(&PosTransaction::L2DataAvailability(tx), 0, fee, &ToyVerifier),
                Err(TxReject::L2DataAvailability(reject)),
                "{name}"
            );
            assert_eq!(state, pre, "{name} mutated state");
        }
        // The same batch twice for one block is refused (a different batch is not).
        let mut state = pre.clone();
        let first = PosTransaction::L2DataAvailability(base.clone());
        state.apply_transaction(&first, 0, fee, &ToyVerifier).unwrap();
        let coin = (first.txid(), 0);
        let change = base.change.value;
        let again = da_tx(&state, coin, change, 1, payload.clone());
        let before = state.clone();
        assert_eq!(
            state.apply_transaction(&PosTransaction::L2DataAvailability(again), 0, fee, &ToyVerifier),
            Err(TxReject::L2DataAvailability(DaReject::Duplicate))
        );
        assert_eq!(state, before);
        let other = da_tx(&state, coin, change, 1, batch(&[b"competing"]));
        assert!(state.apply_transaction(&PosTransaction::L2DataAvailability(other), 0, fee, &ToyVerifier).is_ok());
        assert_eq!(state.l2_settlement().unwrap().data_availability().len(), 2);
    }

    #[test]
    #[cfg(feature = "devnet-l2-user-txs")]
    fn oversize_da_does_not_decode() {
        let (pre, _) = funded_async_fixture();
        let mut tx = da_tx(&pre, ([0x33; 32], 0), FUNDED, 1, batch(&[b"x"]));
        tx.payload = vec![0; da::MAX_PAYLOAD_BYTES + 1];
        let bytes = PosTransaction::L2DataAvailability(tx).canonical_bytes();
        assert_eq!(
            PosTransaction::from_canonical_bytes(&bytes),
            Err(TxDecodeError::NotCanonical(crate::transition::l2_da::L2_DATA_AVAILABILITY_TAG))
        );
    }

    #[test]
    #[cfg(feature = "devnet-l2-user-txs")]
    fn more_than_four_da_batches_in_one_block_are_refused() {
        let (pre, mut chains) = funded_async_fixture();
        let mut state = pre.clone();
        let mut coin = (([0x33; 32], 0), FUNDED);
        let mut txs = Vec::new();
        for i in 0..=da::MAX_PER_BLOCK {
            let tx = da_tx(&state, coin.0, coin.1, 1, batch(&[&[i as u8 + 1]]));
            let wire = PosTransaction::L2DataAvailability(tx.clone());
            state.apply_transaction(&wire, 0, pre.next_base_fee(), &ToyVerifier).unwrap();
            coin = ((wire.txid(), 0), tx.change.value);
            txs.push(wire);
        }
        let t = Transition::new(ToyVerifier);
        let mut block = build_block(&t, &pre, 2, &[], &[], &mut chains);
        block.header.body_root =
            crate::derive::body_root(&txs.iter().map(PosTransaction::canonical_bytes).collect::<Vec<_>>());
        let pk = crate::attestation::KeyLookup::pubkey(&pre, block.header.proposer_index).unwrap();
        block.proposer_sig = toy_sign(pk, &block.header.proposal_signing_root());
        assert_eq!(t.compute_post_state(&pre, &block, &[], &txs), Err(TransitionError::BlockGasLimitExceeded));
        assert!(apply(&pre, 3, &txs[..da::MAX_PER_BLOCK], &mut chains).is_ok());
    }

    #[test]
    #[cfg(not(feature = "devnet-l2-user-txs"))]
    fn l2_da_is_inert_without_the_user_transaction_feature() {
        let (pre, _) = funded_async_fixture();
        let mut state = pre.clone();
        let tx = PosTransaction::L2DataAvailability(da_tx(&pre, ([0x33; 32], 0), FUNDED, 1, batch(&[b"tx"])));
        assert_eq!(
            state.apply_transaction(&tx, 0, pre.next_base_fee(), &ToyVerifier),
            Err(TxReject::L2DataAvailability(DaReject::NotActive))
        );
        assert_eq!(state, pre);
    }

    /// Records expire after `RETENTION_BLOCKS`; the retained set never
    /// exceeds `MAX_RECORDS` even with every block full of DA batches.
    #[test]
    #[cfg(feature = "devnet-l2-user-txs")]
    fn da_records_expire_and_stay_bounded() {
        let (pre, _) = funded_async_fixture();
        let mut l2 = pre.l2_settlement().unwrap().clone();
        l2.record_data_availability(700771, 1, [1; 32]).unwrap();
        l2.advance_height().unwrap();
        assert!(l2.data_availability().iter().any(|r| r.commitment == [1; 32]));
        for _ in 1..da::RETENTION_BLOCKS {
            l2.advance_height().unwrap();
        }
        assert_eq!(l2.data_availability().len(), 1, "usable for RETENTION_BLOCKS blocks");
        l2.advance_height().unwrap();
        assert!(l2.data_availability().is_empty(), "expired");

        // Worst case: MAX_PER_BLOCK new records in every block, forever.
        let mut l2 = pre.l2_settlement().unwrap().clone();
        let mut peak = 0;
        for block in 0..(da::RETENTION_BLOCKS + 64) {
            for k in 0..da::MAX_PER_BLOCK {
                let number = 1 + (block % da::WINDOW);
                let mut c = [0u8; 32];
                c[..8].copy_from_slice(&block.to_be_bytes());
                c[8] = k as u8;
                l2.record_data_availability(700771, number, c).unwrap();
            }
            peak = peak.max(l2.data_availability().len());
            l2.advance_height().unwrap();
        }
        assert_eq!(peak, da::MAX_RECORDS);
        assert!(l2.data_availability().len() < da::MAX_RECORDS);
        assert!(l2.committed_bytes().len() <= pre.l2_settlement().unwrap().committed_bytes().len() + 26 + 8 + 48 * da::MAX_RECORDS);
    }

    // ── M4: withdrawal root and count ──

    /// A V3 successor of the accepted head of `l2` (or the first settlement),
    /// for a body without deposits or user transactions, publishing the
    /// withdrawal tree `(root, count)`.
    fn next_v3(
        l2: &crate::l2_settlement::State,
        parent: [u8; 32],
        slot: u64,
        withdrawals: ([u8; 32], u64),
    ) -> Transaction {
        let source = l2.source(parent, slot);
        let mut tx = to_v3(
            Transaction { proof_policy: l2.policy().proof_policy, statement: TEMPLATE.to_vec(), proof: [1; 356] },
            no_deposits(),
            0,
        );
        let s = &mut tx.statement;
        for (i, id) in l2.policy().identities.iter().enumerate() {
            s[S + i * 32..S + (i + 1) * 32].copy_from_slice(id);
        }
        let mut put = |offset: usize, value: &[u8]| s[S + offset..S + offset + value.len()].copy_from_slice(value);
        put(400, &source.block);
        put(432, &source.slot.to_be_bytes());
        put(440, &source.height.to_be_bytes());
        put(448, &source.commitment);
        put(480, &source.inbox_root);
        if let Some((digest, head)) = l2.head() {
            let number = u64::from_be_bytes(head[S + 264..S + 272].try_into().unwrap()) + 1;
            put(224, &digest);
            put(264, &number.to_be_bytes());
            put(272, &hash_at(&head, S + 336));
            put(304, &hash_at(&head, S + 368));
            put(336, &[number as u8 + 0x30; 32]);
            put(368, &[number as u8 + 0x50; 32]);
        }
        put(v3::WITHDRAWAL_ROOT, &withdrawals.0);
        put(v3::WITHDRAWAL_COUNT, &withdrawals.1.to_be_bytes());
        tx
    }

    #[test]
    fn v3_withdrawal_tree_must_grow_and_its_roots_are_retained() {
        use crate::l2_settlement::withdrawal::{self, Record};
        let (pre, _) = fixture();
        let (parent, slot) = (*pre.head.as_bytes(), pre.slot);
        let mut l2 = pre.l2_settlement().unwrap().clone();
        let empty = withdrawal::empty_root();
        assert_eq!(l2.withdrawal_head(), (empty, 0));
        let bytes_before = l2.committed_bytes();
        // Settle, then close the native block.
        let settle = |l2: &mut crate::l2_settlement::State, w: ([u8; 32], u64)| -> Result<(), Reject> {
            // One native block per settlement: the slot never trails the height.
            let slot = slot.max(l2.height());
            let tx = next_v3(l2, parent, slot, w);
            let before = l2.clone();
            let result = l2.apply(&tx, parent, slot, false, &ProofDouble);
            if result.is_err() {
                assert_eq!(*l2, before, "a refused settlement mutated state");
            } else {
                l2.advance_height().unwrap();
            }
            result
        };
        // Block 1: no withdrawal. Nothing is recorded; committed bytes keep
        // the pre-M4 layout apart from the head.
        settle(&mut l2, (empty, 0)).unwrap();
        assert!(l2.withdrawal_roots().is_empty());
        assert!(!l2.committed_bytes().windows(9).any(|w| w == b"WITHDRAWA"));
        assert_ne!(l2.committed_bytes(), bytes_before);
        // Block 2: two withdrawals.
        let r2 = [0x21; 32];
        settle(&mut l2, (r2, 2)).unwrap();
        assert_eq!(l2.withdrawal_head(), (r2, 2));
        let height = l2.height();
        assert_eq!(l2.withdrawal_roots(), &[Record { l2_number: 2, root: r2, count: 2, height }]);
        assert!(l2.committed_bytes().windows(34).any(|w| w == b"BLOCH:NATIVE:L2:WITHDRAWAL-STATE:1"));
        // Refused: fewer leaves, a moved root without leaves, new leaves
        // without a new root, a zero root.
        assert_eq!(settle(&mut l2, ([0x22; 32], 1)), Err(Reject::Withdrawals));
        assert_eq!(settle(&mut l2, ([0x22; 32], 2)), Err(Reject::Withdrawals));
        assert_eq!(settle(&mut l2, (r2, 3)), Err(Reject::Withdrawals));
        assert_eq!(settle(&mut l2, (empty, 0)), Err(Reject::Withdrawals));
        // Block 3: unchanged tree, no new record. Block 4: one more leaf.
        settle(&mut l2, (r2, 2)).unwrap();
        assert_eq!(l2.withdrawal_roots().len(), 1);
        settle(&mut l2, ([0x23; 32], 3)).unwrap();
        assert_eq!(l2.withdrawal_roots().len(), 2);
        assert_eq!(l2.withdrawal_roots()[1].l2_number, 4);
        // A V2 head counts as the empty tree for the next V3 statement.
        let v2_head = crate::l2_settlement::State::genesis(l2.policy().clone()).unwrap();
        assert_eq!(v2_head.withdrawal_head(), (empty, 0));

        // Retention: every record younger than RETENTION_BLOCKS and the
        // newest older one (so a mature root always remains).
        for _ in 0..withdrawal::RETENTION_BLOCKS {
            l2.advance_height().unwrap();
        }
        assert_eq!(l2.withdrawal_roots().len(), 1);
        assert_eq!(l2.withdrawal_roots()[0].root, [0x23; 32]);
        settle(&mut l2, ([0x24; 32], 4)).unwrap();
        for _ in 0..3 * withdrawal::RETENTION_BLOCKS {
            l2.advance_height().unwrap();
        }
        assert_eq!(l2.withdrawal_roots().len(), 1);
        assert_eq!(l2.withdrawal_roots()[0].root, [0x24; 32]);
    }

    /// Shared vectors with bloch-l2-evm (`tests/fixtures/l2-withdrawal-v1`,
    /// identical copy), rebuilt from THIS crate's leaf and tree code.
    #[test]
    fn withdrawal_leaf_and_tree_match_the_shared_l2_vectors() {
        use crate::l2_settlement::withdrawal;
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/fixtures/l2-withdrawal-v1/vectors.json")).unwrap();
        let hex32 = |v: &serde_json::Value| -> [u8; 32] {
            hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap().try_into().unwrap()
        };
        let int = |v: &serde_json::Value| v.as_u64().unwrap();
        assert_eq!(hex32(&fixture["empty_root"]), withdrawal::empty_root());
        let leaves = fixture["leaves"].as_array().unwrap();
        assert_eq!(leaves.len(), 3);
        for leaf in leaves {
            let computed =
                withdrawal::leaf(int(&leaf["chain_id"]), int(&leaf["nonce"]), &hex32(&leaf["l1_recipient"]), int(&leaf["sats"]));
            assert_eq!(computed, hex32(&leaf["leaf"]));
        }
        let chain = int(&fixture["chain_id"]);
        let vector_leaf = |i: u64| withdrawal::leaf(chain, i, &[(i % 255) as u8 + 1; 32], 1_000_000 + i);
        let trees = fixture["trees"].as_array().unwrap();
        assert_eq!(trees.iter().map(|t| int(&t["count"])).collect::<Vec<_>>(), vec![1, 2, 3, 1000]);
        for tree in trees {
            let leaves: Vec<[u8; 32]> = (0..int(&tree["count"])).map(vector_leaf).collect();
            let root = hex32(&tree["root"]);
            assert_eq!(withdrawal::root(&leaves), root, "{} leaves", leaves.len());
            for proof in tree["proofs"].as_array().unwrap() {
                let index = int(&proof["index"]);
                let siblings: Vec<[u8; 32]> = proof["siblings"].as_array().unwrap().iter().map(hex32).collect();
                let siblings: [[u8; 32]; 32] = siblings.try_into().unwrap();
                assert_eq!(withdrawal::root_from_proof(&vector_leaf(index), index, &siblings), Some(root));
                assert_ne!(withdrawal::root_from_proof(&vector_leaf(index), index ^ 1, &siblings), Some(root));
            }
        }
        assert_eq!(withdrawal::root_from_proof(&[0; 32], 1 << 32, &[[0; 32]; 32]), None);
    }

    // ── M5: L2WithdrawClaim (0x16) ──

    use crate::l2_settlement::withdrawal::{self as wd, WITHDRAW_DELAY_BLOCKS};
    use crate::transition::l2_claim::{L2WithdrawClaim, L2WithdrawClaimReject as ClaimReject, CHANGE_VOUT, RELEASE_VOUT};

    /// Leaf `i` of the shared l2-withdrawal-v1 vector trees.
    fn wleaf(i: u64) -> ([u8; 32], u64) {
        ([(i % 255) as u8 + 1; 32], 1_000_000 + i)
    }
    fn wleaves(n: u64) -> Vec<[u8; 32]> {
        (0..n).map(|i| { let (r, sats) = wleaf(i); wd::leaf(700771, i, &r, sats) }).collect()
    }

    /// A signed claim of leaf `index` of the `n`-leaf vector tree, funded by
    /// the depositor key's coin `outpoint` worth `value`, all of it but the
    /// fee back as change.
    fn claim_tx(pre: &CommittedState, outpoint: ([u8; 32], u32), value: u64, n: u64, index: u64) -> L2WithdrawClaim {
        let key = depositor();
        let (l1_recipient, sats) = wleaf(index);
        let mut tx = L2WithdrawClaim {
            network_domain: [0x91; 32],
            funding_pubkey: key.clone(),
            inputs: vec![crate::transition::FundingInput { txid: outpoint.0, vout: outpoint.1 }],
            l2_chain_id: 700771,
            index,
            l1_recipient,
            sats,
            siblings: wd::proof(&wleaves(n), index).unwrap(),
            release: TransferOutput { value: sats, script_hash: l1_recipient },
            change: TransferOutput { value: 0, script_hash: script_of(&key) },
            tx_bytes: 0,
            tip_millisat_per_gas: 0,
            attestation: None,
            signature: vec![0; 32],
        };
        tx.tx_bytes = tx.canonical_bytes().len() as u64;
        let charge = fee_market::charge(tx.class(), tx.tx_bytes, pre.next_base_fee(), 0);
        tx.change.value = (u128::from(value) - charge.base_fee_sat - charge.priority_fee_sat) as u64;
        tx.signature = toy_sign(&key, &tx.intent_root());
        tx
    }
    fn resign_claim(mut tx: L2WithdrawClaim) -> L2WithdrawClaim {
        tx.signature = toy_sign(&tx.funding_pubkey, &tx.intent_root());
        tx
    }
    fn claim(tx: &L2WithdrawClaim) -> PosTransaction {
        PosTransaction::L2WithdrawClaim(tx.clone())
    }

    /// The block at `slot` carrying `txs` instead of `valid.1` is invalid
    /// because of transaction `index`, and `valid` is then applied. One block
    /// per slot: building a block spends its proposer's RANDAO reveal, so the
    /// invalid body is grafted onto the valid block and re-signed.
    fn refuse_then_apply(
        pre: &CommittedState,
        slot: u64,
        txs: &[PosTransaction],
        index: u32,
        valid: &[PosTransaction],
        chains: &mut [RandaoChain],
    ) -> CommittedState {
        let t = Transition::new(ProofDouble);
        let block = build_block(&t, pre, slot, &[], valid, chains);
        let mut graft = block.clone();
        graft.header.body_root = crate::derive::body_root(&txs.iter().map(PosTransaction::canonical_bytes).collect::<Vec<_>>());
        let pk = crate::attestation::KeyLookup::pubkey(pre, graft.header.proposer_index).unwrap();
        graft.proposer_sig = toy_sign(pk, &graft.header.proposal_signing_root());
        assert_eq!(t.compute_post_state(pre, &graft, &[], txs), Err(TransitionError::Transaction(index)));
        t.apply_block(pre, &block, &[], valid).expect("valid block")
    }

    /// Async fixture with `escrow` sats escrowed (one deposit record) and a
    /// matured withdrawal record for the `n`-leaf vector tree; the funding
    /// coin is untouched.
    fn matured_claim_fixture(n: u64, escrow: u64) -> CommittedState {
        let (mut pre, _) = funded_async_fixture();
        let l2 = pre.l2_settlement.as_mut().unwrap();
        l2.append_deposit(crate::l2_settlement::InboxRecord {
            height: 1, tx_index: 0, txid: [0x77; 32], vout: 1, sats: escrow, recipient: [0x42; 20],
        })
        .unwrap();
        let height = l2.height();
        l2.insert_withdrawal_record(wd::Record { l2_number: 1, root: wd::root(&wleaves(n)), count: n, height: 1 });
        for _ in height..1 + WITHDRAW_DELAY_BLOCKS {
            l2.advance_height().unwrap();
        }
        assert_eq!(l2.matured_count(), n);
        finalize_all(&mut pre);
        pre
    }

    /// Mark the chain up to `state`'s head FFG-finalized: claims prove only
    /// against finalized settlements (`wd::record_finalized`), and these
    /// fixtures carry no attestations.
    fn finalize_all(state: &mut CommittedState) {
        state.finality_engine = crate::finality::FinalityState::relaunch(crate::finality::Checkpoint {
            epoch: crate::epoch_of(state.slot) + 1,
            root: *state.head.as_bytes(),
        });
    }

    /// Shared with bloch-l2-evm (`tests/fixtures/l2-claim-v1`, identical
    /// copy): the exact 0x16 frame, its intent root, txid and nullifier.
    #[test]
    fn l2_claim_wire_frame_matches_the_shared_vector() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/fixtures/l2-claim-v1/vectors.json")).unwrap();
        let hex32 = |v: &serde_json::Value| -> [u8; 32] { hex::decode(v.as_str().unwrap()).unwrap().try_into().unwrap() };
        let leaves = wleaves(3);
        let (l1_recipient, sats) = wleaf(1);
        let tx = L2WithdrawClaim {
            network_domain: [0x91; 32],
            funding_pubkey: vec![0x5a; crate::transition::funded::ADMISSION_PQ_KEY_BYTES],
            inputs: vec![crate::transition::FundingInput { txid: [0x33; 32], vout: 0 }],
            l2_chain_id: 700771,
            index: 1,
            l1_recipient,
            sats,
            siblings: wd::proof(&leaves, 1).unwrap(),
            release: TransferOutput { value: sats, script_hash: l1_recipient },
            change: TransferOutput { value: 12_345, script_hash: [0x44; 32] },
            tx_bytes: 4_000,
            tip_millisat_per_gas: 7,
            attestation: None,
            signature: vec![0x66; 64],
        };
        let wire = claim(&tx);
        let bytes = wire.canonical_bytes();
        assert_eq!(hex::encode(&bytes), fixture["tx_hex"].as_str().unwrap());
        assert_eq!(PosTransaction::from_canonical_bytes(&bytes).unwrap(), wire);
        assert_eq!(tx.intent_root(), hex32(&fixture["intent_root"]));
        assert_eq!(wire.txid(), hex32(&fixture["txid"]));
        assert_eq!(tx.nullifier(), hex32(&fixture["nullifier"]));
        assert_eq!(wd::nullifier(700771, 1), hex32(&fixture["nullifier"]));
        assert_eq!(tx.leaf(), hex32(&fixture["leaf"]));
        assert_eq!(wd::root(&leaves), hex32(&fixture["root"]));
        assert_eq!(fixture["count"].as_u64(), Some(3));
        // The root is the l2-withdrawal-v1 3-leaf tree root.
        let shared: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/fixtures/l2-withdrawal-v1/vectors.json")).unwrap();
        let three = shared["trees"].as_array().unwrap().iter().find(|t| t["count"] == 3).unwrap();
        assert_eq!(three["root"].as_str().unwrap().trim_start_matches("0x"), fixture["root"].as_str().unwrap());
        // Versions other than 1 do not decode (M6 adds version 2).
        for version in [0u8, 2, 0xff] {
            let mut other = bytes.clone();
            other[1] = version;
            assert_eq!(
                PosTransaction::from_canonical_bytes(&other),
                Err(TxDecodeError::NotCanonical(crate::transition::l2_claim::L2_WITHDRAW_CLAIM_TAG))
            );
        }
        // Truncation never decodes.
        assert!(PosTransaction::from_canonical_bytes(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn withdrawal_proofs_and_nullifier_bitmap() {
        let leaves = wleaves(5);
        let root = wd::root(&leaves);
        for i in 0..5 {
            assert_eq!(wd::root_from_proof(&leaves[i as usize], i, &wd::proof(&leaves, i).unwrap()), Some(root));
        }
        assert_eq!(wd::proof(&leaves, 5), None);
        assert_ne!(wd::nullifier(700771, 1), wd::nullifier(700772, 1));
        assert_ne!(wd::nullifier(700771, 1), wd::nullifier(700771, 2));
        // Bitmap: set/contains, floor compaction after a full word.
        let mut b = wd::ClaimBitmap::default();
        assert!(!b.contains(3));
        assert!(b.insert(3));
        assert!(!b.insert(3));
        assert!(b.contains(3) && !b.contains(2) && !b.contains(259));
        for i in 0..256 {
            b.insert(i);
        }
        assert_eq!((b.floor(), b.stored_words(), b.claims()), (1, 0, 256));
        assert!(b.contains(0) && b.contains(255) && !b.contains(256));
        b.insert(600);
        assert_eq!((b.floor(), b.stored_words()), (1, 1));
        for i in 256..512 {
            b.insert(i);
        }
        assert_eq!((b.floor(), b.stored_words(), b.claims()), (2, 1, 513));
        for i in 512..768 {
            b.insert(i);
        }
        assert_eq!((b.floor(), b.stored_words(), b.claims()), (3, 0, 768));
    }

    #[test]
    #[cfg(feature = "devnet-l2-user-txs")]
    fn invalid_l2_claims_are_refused_without_mutation() {
        let pre = matured_claim_fixture(3, 50_000_000);
        let fee = pre.next_base_fee();
        let base = claim_tx(&pre, ([0x33; 32], 0), FUNDED, 3, 1);
        let mut cases: Vec<(&str, L2WithdrawClaim, ClaimReject)> = Vec::new();
        let mut t = base.clone();
        t.siblings[0][0] ^= 1;
        cases.push(("bad proof", resign_claim(t), ClaimReject::Proof));
        let mut t = base.clone();
        t.siblings[5] = [0x99; 32];
        cases.push(("bad upper sibling", resign_claim(t), ClaimReject::Proof));
        cases.push(("proof for another index", resign_claim(L2WithdrawClaim { index: 0, ..base.clone() }), ClaimReject::Proof));
        cases.push(("chain", resign_claim(L2WithdrawClaim { l2_chain_id: 700772, ..base.clone() }), ClaimReject::Chain));
        // Wrong amount or recipient: the release output must match, and a
        // consistent but different (recipient, sats) is not the settled leaf.
        let mut t = base.clone();
        t.release.value += 1;
        cases.push(("release amount", resign_claim(t), ClaimReject::ReleaseOutput));
        let mut t = base.clone();
        t.release.script_hash = [0x55; 32];
        cases.push(("release recipient", resign_claim(t), ClaimReject::ReleaseOutput));
        let mut t = base.clone();
        t.sats += 1;
        t.release.value += 1;
        cases.push(("amount", resign_claim(t), ClaimReject::Proof));
        let mut t = base.clone();
        t.l1_recipient = [0x55; 32];
        t.release.script_hash = [0x55; 32];
        cases.push(("recipient", resign_claim(t), ClaimReject::Proof));
        let mut t = base.clone();
        t.sats = crate::transition::l2_deposit::MIN_L2_DEPOSIT_SAT - 1;
        t.release.value = t.sats;
        cases.push(("dust", resign_claim(t), ClaimReject::Amount));
        cases.push(("network", resign_claim(L2WithdrawClaim { network_domain: [0x92; 32], ..base.clone() }), ClaimReject::Network));
        let mut t = base.clone();
        t.signature[0] ^= 1;
        cases.push(("signature", t, ClaimReject::Signature));
        let mut t = base.clone();
        t.change.value += 1;
        cases.push(("conservation", resign_claim(t), ClaimReject::Conservation));
        let mut t = base.clone();
        t.funding_pubkey[0] ^= 1;
        cases.push(("ownership", resign_claim(t), ClaimReject::Ownership));
        let mut t = base.clone();
        t.inputs[0].vout = 9;
        cases.push(("missing input", resign_claim(t), ClaimReject::MissingInput));
        let mut t = base.clone();
        t.tx_bytes -= 1;
        cases.push(("underdeclared", resign_claim(t), ClaimReject::UnderdeclaredSize));
        let mut t = base.clone();
        t.index = 1 << 32;
        cases.push(("index outside the tree", resign_claim(t), ClaimReject::Shape));
        for (name, tx, reject) in cases {
            let mut state = pre.clone();
            assert_eq!(state.apply_transaction(&claim(&tx), 0, fee, &ToyVerifier), Err(TxReject::L2WithdrawClaim(reject)), "{name}");
            assert_eq!(state, pre, "{name} mutated state");
        }

        // Index at or above the count of the root it proves against: a record
        // whose count stops before a leaf the tree holds.
        let mut short = pre.clone();
        let l2 = short.l2_settlement.as_mut().unwrap();
        l2.insert_withdrawal_record(wd::Record { l2_number: 2, root: wd::root(&wleaves(4)), count: 3, height: 1 });
        let t = claim_tx(&short, ([0x33; 32], 0), FUNDED, 4, 3);
        let before = short.clone();
        assert_eq!(short.apply_transaction(&claim(&t), 0, fee, &ToyVerifier), Err(TxReject::L2WithdrawClaim(ClaimReject::Index)));
        assert_eq!(short, before);

        // Not yet matured: the same tree accepted one block too recently.
        let (mut young, _) = funded_async_fixture();
        let l2 = young.l2_settlement.as_mut().unwrap();
        l2.append_deposit(crate::l2_settlement::InboxRecord {
            height: 1, tx_index: 0, txid: [0x77; 32], vout: 1, sats: 50_000_000, recipient: [0x42; 20],
        })
        .unwrap();
        let accepted = l2.height() + 1;
        l2.insert_withdrawal_record(wd::Record { l2_number: 1, root: wd::root(&wleaves(3)), count: 3, height: accepted });
        l2.advance_height().unwrap();
        for _ in 1..WITHDRAW_DELAY_BLOCKS {
            assert_eq!(young.l2_settlement().unwrap().matured_count(), 0);
            let t = claim_tx(&young, ([0x33; 32], 0), FUNDED, 3, 1);
            let before = young.clone();
            assert_eq!(
                young.apply_transaction(&claim(&t), 0, fee, &ToyVerifier),
                Err(TxReject::L2WithdrawClaim(ClaimReject::NotMatured))
            );
            assert_eq!(young, before);
            young.l2_settlement.as_mut().unwrap().advance_height().unwrap();
        }
        // Exactly WITHDRAW_DELAY_BLOCKS after acceptance it is claimable.
        assert_eq!(young.l2_settlement().unwrap().height() + 1, accepted + WITHDRAW_DELAY_BLOCKS);
        assert_eq!(young.l2_settlement().unwrap().matured_count(), 3);
        let t = claim_tx(&young, ([0x33; 32], 0), FUNDED, 3, 1);
        // Matured but not finalized: refused until the settlement is final.
        assert_eq!(young.l2_withdraw_claim_refusal(&t), Some(ClaimReject::NotFinalized));
        finalize_all(&mut young);
        young.apply_transaction(&claim(&t), 0, fee, &ToyVerifier).expect("matured claim");

        // Escrow insufficient (unreachable with proven settlements).
        let poor = matured_claim_fixture(3, 1_000_000);
        let mut state = poor.clone();
        let t = claim_tx(&poor, ([0x33; 32], 0), FUNDED, 3, 1);
        assert_eq!(state.apply_transaction(&claim(&t), 0, fee, &ToyVerifier), Err(TxReject::L2WithdrawClaim(ClaimReject::Escrow)));
        assert_eq!(state, poor);
        // ... while the 1_000_000-sat leaf 0 exactly empties it.
        let t = claim_tx(&poor, ([0x33; 32], 0), FUNDED, 3, 0);
        state.apply_transaction(&claim(&t), 0, fee, &ToyVerifier).unwrap();
        let l2 = state.l2_settlement().unwrap();
        assert_eq!((l2.escrow_sat(), l2.released_sat()), (0, 1_000_000));
        assert!(l2.escrow_conserved());
    }

    #[test]
    #[cfg(feature = "devnet-l2-user-txs")]
    fn a_leaf_is_claimed_once_in_a_block_across_blocks_and_never_again() {
        let (genesis, mut chains) = funded_async_fixture();
        let mut pre = genesis.clone();
        {
            let l2 = pre.l2_settlement.as_mut().unwrap();
            l2.append_deposit(crate::l2_settlement::InboxRecord {
                height: 1, tx_index: 0, txid: [0x77; 32], vout: 1, sats: 50_000_000, recipient: [0x42; 20],
            })
            .unwrap();
            l2.insert_withdrawal_record(wd::Record { l2_number: 1, root: wd::root(&wleaves(3)), count: 3, height: 1 });
        }
        let mut slot = 2;
        while pre.l2_settlement().unwrap().matured_count() == 0 {
            pre = apply(&pre, slot, &[], &mut chains).unwrap();
            slot += 1;
        }
        finalize_all(&mut pre);
        let fee = pre.next_base_fee();
        let first = claim_tx(&pre, ([0x33; 32], 0), FUNDED, 3, 1);
        let mut state = pre.clone();
        state.apply_transaction(&claim(&first), 0, fee, &ToyVerifier).unwrap();
        // A second claim of the same leaf funded by the first claim's change.
        let again = claim_tx(&state, (claim(&first).txid(), CHANGE_VOUT), first.change.value, 3, 1);
        let before = state.clone();
        assert_eq!(
            state.apply_transaction(&claim(&again), 0, fee, &ToyVerifier),
            Err(TxReject::L2WithdrawClaim(ClaimReject::AlreadyClaimed))
        );
        assert_eq!(state, before);
        // In one block: the block is invalid.
        let both = [claim(&first), claim(&again)];
        // Across blocks: the first lands, the second is refused next block.
        let s1 = refuse_then_apply(&pre, slot, &both, 1, std::slice::from_ref(&both[0]), &mut chains);
        assert!(s1.l2_settlement().unwrap().claimed().contains(1));
        // Another leaf still claims in the block that refuses the replay.
        let other = claim_tx(&s1, (claim(&first).txid(), CHANGE_VOUT), first.change.value, 3, 2);
        let s2 = refuse_then_apply(&s1, slot + 1, std::slice::from_ref(&both[1]), 0, &[claim(&other)], &mut chains);
        let l2 = s2.l2_settlement().unwrap();
        assert_eq!(l2.claimed().claims(), 2);
        assert_eq!(l2.released_sat(), u128::from(wleaf(1).1 + wleaf(2).1));
        assert!(l2.escrow_conserved());
        assert!(s2.l2_settlement().unwrap().committed_bytes().windows(29).any(|w| w == b"BLOCH:NATIVE:L2:CLAIM-STATE:1"));
    }

    #[test]
    #[cfg(not(feature = "devnet-l2-user-txs"))]
    fn l2_claims_are_inert_without_the_user_transaction_feature() {
        let pre = matured_claim_fixture(3, 50_000_000);
        let mut state = pre.clone();
        let tx = claim_tx(&pre, ([0x33; 32], 0), FUNDED, 3, 1);
        assert_eq!(
            state.apply_transaction(&claim(&tx), 0, pre.next_base_fee(), &ToyVerifier),
            Err(TxReject::L2WithdrawClaim(ClaimReject::NotActive))
        );
        assert_eq!(state, pre);
        assert_eq!(
            pre.l2_settlement().unwrap().check_claim(700771, 1, &wleaf(1).0, wleaf(1).1, &tx.siblings, false),
            Err(wd::ClaimRefusal::NotActive)
        );
    }

    /// Conservation over random deposit / settle / claim sequences at the L2
    /// state: escrow always equals deposits minus claims, never underflows,
    /// a leaf releases at most once, and only matured, in-tree leaves pay.
    #[test]
    #[cfg(feature = "devnet-l2-user-txs")]
    fn escrow_is_conserved_over_random_deposit_settle_claim_sequences() {
        let (pre, _) = funded_async_fixture();
        // Refusals by the M6 rules alone, summed over seeds: both must bind.
        let (mut limited, mut large_waits) = (0u32, 0u32);
        for seed in 1..=24u64 {
            let mut rng = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15);
            let mut next = move |m: u64| {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                rng % m
            };
            let mut l2 = pre.l2_settlement().unwrap().clone();
            // The L2 side: withdrawals appended to the outbox (leaf, recipient, sats).
            let mut outbox: Vec<([u8; 32], [u8; 32], u64)> = Vec::new();
            let mut settled = 0usize; // leaves covered by the newest record
            let mut paid = std::collections::BTreeSet::new();
            let (mut deposited, mut released) = (0u128, 0u128);
            // Odd seeds use BLCH-scale amounts, so the large-claim delay and
            // the release window bind; even seeds stay below both.
            let scale = if seed % 2 == 1 { 10_000 } else { 1 };
            // Independent model of the release window: (window, released, cap).
            let mut window = (u64::MAX, 0u128, 0u128);
            for step in 0..400u64 {
                match next(6) {
                    0 => {
                        let sats = (1_000_000 + next(5_000_000)) * scale;
                        l2.append_deposit(crate::l2_settlement::InboxRecord {
                            height: l2.height() + 1, tx_index: 0, txid: [step as u8; 32], vout: 1, sats, recipient: [1; 20],
                        })
                        .unwrap();
                        deposited += u128::from(sats);
                    }
                    1 => {
                        // L2 withdraws (possibly more than escrowed: the
                        // escrow check must hold the line).
                        let i = outbox.len() as u64;
                        let recipient = [(next(250) + 1) as u8; 32];
                        let sats = (1_000_000 + next(3_000_000)) * scale;
                        outbox.push((wd::leaf(700771, i, &recipient, sats), recipient, sats));
                    }
                    2 if outbox.len() > settled => {
                        let leaves: Vec<[u8; 32]> = outbox.iter().map(|o| o.0).collect();
                        let height = l2.height() + 1;
                        l2.insert_withdrawal_record(wd::Record {
                            l2_number: step, root: wd::root(&leaves), count: leaves.len() as u64, height,
                        });
                        settled = leaves.len();
                        l2.advance_height().unwrap();
                    }
                    3 => {
                        for _ in 0..next(wd::LARGE_WITHDRAW_DELAY_BLOCKS / 2 + 8) {
                            l2.advance_height().unwrap();
                        }
                    }
                    _ if !outbox.is_empty() => {
                        let index = next(outbox.len() as u64 + 1); // sometimes out of range
                        let (leaf, recipient, sats) = outbox.get(index as usize).copied().unwrap_or(([9; 32], [9; 32], 1_000_000));
                        let leaves: Vec<[u8; 32]> = outbox.iter().map(|o| o.0).collect();
                        // Prove against the tree as of a random retained record.
                        let records = l2.withdrawal_roots().to_vec();
                        let Some(record) = records.get(next(records.len() as u64 + 1) as usize) else { continue };
                        let siblings = wd::proof(&leaves[..record.count as usize], index).unwrap_or([[7; 32]; 32]);
                        let at = l2.height() + 1;
                        let delay = if sats >= wd::LARGE_CLAIM_SAT { wd::LARGE_WITHDRAW_DELAY_BLOCKS } else { WITHDRAW_DELAY_BLOCKS };
                        let matured = record.height + delay <= at;
                        let in_tree = index < record.count && leaf == leaves[index as usize];
                        let w = at / wd::RELEASE_WINDOW_BLOCKS;
                        let current = if window.0 == w && window.1 != 0 {
                            window
                        } else {
                            (w, 0, (l2.escrow_sat() / 10).max(1_000_000_000))
                        };
                        let fits = current.1 == 0 || current.1 + u128::from(sats) <= current.2;
                        let expected_ok =
                            matured && in_tree && !paid.contains(&index) && l2.escrow_sat() >= u128::from(sats) && fits;
                        let before = l2.clone();
                        let result = l2.release_withdrawal(700771, index, &recipient, sats, &siblings, false);
                        assert_eq!(result.is_ok(), expected_ok, "seed {seed} step {step}: {result:?}");
                        if result.is_ok() {
                            paid.insert(index);
                            released += u128::from(sats);
                            window = (current.0, current.1 + u128::from(sats), current.2);
                        } else {
                            assert_eq!(l2, before);
                            limited += u32::from(matured && in_tree && !paid.contains(&index) && l2.escrow_sat() >= u128::from(sats) && !fits);
                            large_waits += u32::from(
                                in_tree && sats >= wd::LARGE_CLAIM_SAT && record.height + WITHDRAW_DELAY_BLOCKS <= at && !matured,
                            );
                        }
                    }
                    _ => {}
                }
                assert!(l2.escrow_conserved(), "seed {seed} step {step}");
                assert_eq!(l2.escrow_sat(), deposited - released);
                assert_eq!(l2.released_sat(), released);
                assert_eq!(l2.claimed().claims(), paid.len() as u64);
            }
        }
        assert!(limited > 0 && large_waits > 0, "M6 rules never bound: limited {limited}, large waits {large_waits}");
    }

    // ── M6: post-quantum co-signature of large claims (claim version 2) ──

    use crate::transition::l2_claim::Attestation;

    fn attestor(i: u8) -> Vec<u8> {
        vec![0xa0 + i; crate::transition::funded::ADMISSION_PQ_KEY_BYTES]
    }
    fn attestors() -> Vec<Vec<u8>> {
        (0..3).map(attestor).collect()
    }

    /// Committed state with attestors 2-of-3 (unless `configured` is false),
    /// 1 000 BLCH escrowed and one record over `leaves`, matured for large
    /// claims; the relayer's funding coin is untouched.
    fn attested_fixture(leaves: &[([u8; 32], u64)], configured: bool) -> CommittedState {
        let (mut pre, _) = funded_async_fixture();
        let l2 = pre.l2_settlement.as_mut().unwrap();
        l2.append_deposit(crate::l2_settlement::InboxRecord {
            height: 1, tx_index: 0, txid: [0x77; 32], vout: 1, sats: 1_000 * BLCH, recipient: [0x42; 20],
        })
        .unwrap();
        if configured {
            l2.set_attestor_set(wd::attestor_set_hash(2, &attestors()));
        }
        let tree: Vec<[u8; 32]> =
            leaves.iter().enumerate().map(|(i, (r, sats))| wd::leaf(700771, i as u64, r, *sats)).collect();
        l2.insert_withdrawal_record(wd::Record { l2_number: 1, root: wd::root(&tree), count: tree.len() as u64, height: 1 });
        while l2.height() + 1 < 1 + wd::LARGE_WITHDRAW_DELAY_BLOCKS {
            l2.advance_height().unwrap();
        }
        finalize_all(&mut pre);
        pre
    }

    /// A signed claim of `leaves[index]`, attested by `signers` when given.
    fn claim_of(pre: &CommittedState, leaves: &[([u8; 32], u64)], index: u64, attestation: Option<Attestation>) -> L2WithdrawClaim {
        let key = depositor();
        let (l1_recipient, sats) = leaves[index as usize];
        let tree: Vec<[u8; 32]> =
            leaves.iter().enumerate().map(|(i, (r, s))| wd::leaf(700771, i as u64, r, *s)).collect();
        let mut tx = L2WithdrawClaim {
            network_domain: [0x91; 32],
            funding_pubkey: key.clone(),
            inputs: vec![crate::transition::FundingInput { txid: [0x33; 32], vout: 0 }],
            l2_chain_id: 700771,
            index,
            l1_recipient,
            sats,
            siblings: wd::proof(&tree, index).unwrap(),
            release: TransferOutput { value: sats, script_hash: l1_recipient },
            change: TransferOutput { value: 0, script_hash: script_of(&key) },
            tx_bytes: 0,
            tip_millisat_per_gas: 0,
            attestation,
            signature: vec![0; 32],
        };
        tx.tx_bytes = tx.canonical_bytes().len() as u64;
        let charge = fee_market::charge(tx.class(), tx.tx_bytes, pre.next_base_fee(), 0);
        tx.change.value = (u128::from(FUNDED) - charge.base_fee_sat - charge.priority_fee_sat) as u64;
        tx.signature = toy_sign(&key, &tx.intent_root());
        tx
    }

    /// Signatures of `signers` over the root `leaves` folds to.
    fn attest(leaves: &[([u8; 32], u64)], signers: &[u8]) -> Attestation {
        let tree: Vec<[u8; 32]> =
            leaves.iter().enumerate().map(|(i, (r, s))| wd::leaf(700771, i as u64, r, *s)).collect();
        let digest = wd::attestation_digest(&[0x91; 32], 700771, &wd::root(&tree));
        Attestation {
            threshold: 2,
            keys: attestors(),
            signatures: signers.iter().map(|&i| (i, toy_sign(&attestor(i), &digest))).collect(),
        }
    }

    fn try_claim(pre: &CommittedState, tx: &L2WithdrawClaim) -> Result<CommittedState, TxReject> {
        let mut state = pre.clone();
        state.apply_transaction(&claim(tx), 0, pre.next_base_fee(), &ToyVerifier).map(|_| state)
    }

    #[test]
    #[cfg(feature = "devnet-l2-user-txs")]
    fn a_large_claim_needs_the_attestors_k_of_n_signature() {
        let leaves = [([1; 32], 150 * BLCH), ([2; 32], 5 * BLCH)];
        let pre = attested_fixture(&leaves, true);
        let refuse = |tx: &L2WithdrawClaim, why| assert_eq!(try_claim(&pre, tx).map(|_| ()), Err(TxReject::L2WithdrawClaim(why)));
        // Version 1 above the threshold: refused.
        refuse(&claim_of(&pre, &leaves, 0, None), ClaimReject::AttestationRequired);
        // The node logs this reason (the block error is only `Transaction(i)`).
        assert_eq!(pre.l2_withdraw_claim_refusal(&claim_of(&pre, &leaves, 0, None)), Some(ClaimReject::AttestationRequired));
        // 2-of-3 over the proven root: applies, and round-trips on the wire.
        let good = claim_of(&pre, &leaves, 0, Some(attest(&leaves, &[0, 2])));
        let wire = claim(&good);
        assert_eq!(wire.canonical_bytes()[1], 2, "version 2");
        assert_eq!(PosTransaction::from_canonical_bytes(&wire.canonical_bytes()).unwrap(), wire);
        let post = try_claim(&pre, &good).expect("attested large claim");
        assert!(post.l2_settlement().unwrap().claimed().contains(0));
        assert_eq!(post.balance_sat(&[1; 32]), pre.balance_sat(&[1; 32]) + u128::from(150 * BLCH));
        // All three also pass.
        try_claim(&pre, &claim_of(&pre, &leaves, 0, Some(attest(&leaves, &[0, 1, 2])))).unwrap();
        // One signature is below k: a shape error.
        refuse(&claim_of(&pre, &leaves, 0, Some(attest(&leaves, &[1]))), ClaimReject::Shape);
        // A signature over another root.
        let mut other = attest(&[([9; 32], 150 * BLCH)], &[0, 1]);
        other.threshold = 2;
        refuse(&claim_of(&pre, &leaves, 0, Some(other)), ClaimReject::Attestation);
        // One forged signature among enough.
        let mut forged = attest(&leaves, &[0, 1]);
        forged.signatures[1].1[0] ^= 1;
        refuse(&claim_of(&pre, &leaves, 0, Some(forged)), ClaimReject::Attestation);
        // Another set (a key replaced), signed by its own keys.
        let mut foreign = attest(&leaves, &[0, 1]);
        foreign.keys[2] = attestor(9);
        refuse(&claim_of(&pre, &leaves, 0, Some(foreign)), ClaimReject::Attestation);
        // Same key twice to turn 2-of-3 into 1 holder: shape.
        let mut doubled = attest(&leaves, &[0, 1]);
        doubled.keys[1] = attestor(0);
        doubled.signatures[1].1 = doubled.signatures[0].1.clone();
        refuse(&claim_of(&pre, &leaves, 0, Some(doubled)), ClaimReject::Shape);
        // Re-signing the funding key cannot detach the attestation: a claim
        // whose attestation was swapped has another txid.
        let swapped = claim_of(&pre, &leaves, 0, Some(attest(&leaves, &[0, 1])));
        assert_ne!(claim(&swapped).txid(), wire.txid());
    }

    #[test]
    #[cfg(feature = "devnet-l2-user-txs")]
    fn small_claims_and_networks_without_attestors_keep_version_1() {
        let leaves = [([1; 32], 150 * BLCH), ([2; 32], wd::ATTESTED_CLAIM_SAT - 1)];
        let pre = attested_fixture(&leaves, true);
        // Below the threshold, version 1 suffices; version 2 is also accepted.
        try_claim(&pre, &claim_of(&pre, &leaves, 1, None)).expect("small claim, no attestation");
        try_claim(&pre, &claim_of(&pre, &leaves, 1, Some(attest(&leaves, &[1, 2])))).expect("optional attestation");
        // No attestors configured: large claims stay version 1, and a version 2
        // claim names a set the network does not have.
        let bare = attested_fixture(&leaves, false);
        try_claim(&bare, &claim_of(&bare, &leaves, 0, None)).expect("no attestors: version 1");
        assert_eq!(
            try_claim(&bare, &claim_of(&bare, &leaves, 0, Some(attest(&leaves, &[0, 1])))).map(|_| ()),
            Err(TxReject::L2WithdrawClaim(ClaimReject::Attestation))
        );
    }

    // ── M6: large-claim delay and release window ──

    const BLCH: u64 = 100_000_000;

    /// Async L2 state with `escrow` sats escrowed and one withdrawal record
    /// (accepted at native height 1) over `leaves` = (recipient, sats).
    fn window_fixture(escrow: u64, leaves: &[([u8; 32], u64)]) -> (crate::l2_settlement::State, Vec<[u8; 32]>) {
        let (pre, _) = funded_async_fixture();
        let mut l2 = pre.l2_settlement().unwrap().clone();
        l2.append_deposit(crate::l2_settlement::InboxRecord {
            height: 1, tx_index: 0, txid: [0x77; 32], vout: 1, sats: escrow, recipient: [0x42; 20],
        })
        .unwrap();
        let tree: Vec<[u8; 32]> =
            leaves.iter().enumerate().map(|(i, (r, sats))| wd::leaf(700771, i as u64, r, *sats)).collect();
        l2.insert_withdrawal_record(wd::Record { l2_number: 1, root: wd::root(&tree), count: tree.len() as u64, height: 1 });
        (l2, tree)
    }

    fn release(l2: &mut crate::l2_settlement::State, tree: &[[u8; 32]], leaves: &[([u8; 32], u64)], i: u64) -> Result<(), wd::ClaimRefusal> {
        let (r, sats) = leaves[i as usize];
        l2.release_withdrawal(700771, i, &r, sats, &wd::proof(tree, i).unwrap(), false)
    }

    #[test]
    #[cfg(feature = "devnet-l2-user-txs")]
    fn a_large_claim_waits_the_longer_delay() {
        let leaves = [([1; 32], wd::LARGE_CLAIM_SAT - 1), ([2; 32], wd::LARGE_CLAIM_SAT)];
        let (mut l2, tree) = window_fixture(1_000 * BLCH, &leaves);
        while l2.height() + 1 < 1 + WITHDRAW_DELAY_BLOCKS {
            l2.advance_height().unwrap();
        }
        assert_eq!(l2.matured_withdrawals().map(|r| r.count), Some(2));
        assert_eq!(l2.matured_large_withdrawals(), None);
        assert_eq!(release(&mut l2, &tree, &leaves, 1), Err(wd::ClaimRefusal::NotMatured));
        release(&mut l2, &tree, &leaves, 0).expect("just below the threshold: standard delay");
        while l2.height() + 1 < 1 + wd::LARGE_WITHDRAW_DELAY_BLOCKS {
            assert_eq!(release(&mut l2, &tree, &leaves, 1), Err(wd::ClaimRefusal::NotMatured));
            l2.advance_height().unwrap();
        }
        assert!(l2.matured_large_withdrawals().is_some());
        // Next window: the first claim of a window is always admitted.
        release(&mut l2, &tree, &leaves, 1).expect("large claim after the long delay");
        assert!(l2.escrow_conserved());
    }

    #[test]
    #[cfg(feature = "devnet-l2-user-txs")]
    fn claims_beyond_the_window_cap_wait_for_the_next_window() {
        // Escrow 1 000 BLCH: cap 100 BLCH per window.
        let leaves = [([1; 32], 60 * BLCH), ([2; 32], 50 * BLCH), ([3; 32], 40 * BLCH), ([4; 32], 99 * BLCH)];
        let (mut l2, tree) = window_fixture(1_000 * BLCH, &leaves);
        while (l2.height() + 1) % wd::RELEASE_WINDOW_BLOCKS != 0 || l2.height() + 1 < 1 + WITHDRAW_DELAY_BLOCKS {
            l2.advance_height().unwrap();
        }
        assert_eq!(l2.release_window().cap, 100 * BLCH as u128);
        release(&mut l2, &tree, &leaves, 0).unwrap();
        let state = l2.clone();
        assert_eq!(release(&mut l2, &tree, &leaves, 1), Err(wd::ClaimRefusal::RateLimited));
        assert_eq!(l2, state, "a refused claim changes nothing");
        release(&mut l2, &tree, &leaves, 2).expect("60 + 40 fits the cap exactly");
        assert_eq!(l2.release_window().remaining(), 0);
        assert_eq!(release(&mut l2, &tree, &leaves, 3), Err(wd::ClaimRefusal::RateLimited));
        // The cap stays fixed for the window although the escrow shrank.
        assert_eq!(l2.release_window().cap, 100 * BLCH as u128);
        for _ in 0..wd::RELEASE_WINDOW_BLOCKS {
            l2.advance_height().unwrap();
        }
        // New window: cap from the escrow now (900 BLCH → 90 BLCH), and the
        // window's first claim is admitted even above it.
        assert_eq!(l2.release_window().cap, 90 * BLCH as u128);
        release(&mut l2, &tree, &leaves, 3).expect("first claim of the window");
        assert_eq!(release(&mut l2, &tree, &leaves, 1), Err(wd::ClaimRefusal::RateLimited));
        assert!(l2.escrow_conserved());
    }

    #[test]
    fn a_record_is_finalized_once_its_slot_bound_precedes_the_checkpoint() {
        let e = crate::params::SLOTS_PER_EPOCH;
        // Tip at height 100, slot 3e+10: the record at height 90 has slot
        // at most 3e. Finalized epoch 3 covers slots < 3e: not yet.
        assert!(!wd::record_finalized(90, 100, 3 * e + 10, 3));
        assert!(wd::record_finalized(89, 100, 3 * e + 10, 3));
        assert!(wd::record_finalized(90, 100, 3 * e + 10, 4));
        // Nothing is finalized at epoch 0; a record above the tip never is.
        assert!(!wd::record_finalized(0, 100, 50, 0));
        assert!(!wd::record_finalized(101, 100, 1_000, 99));
        // Missed slots after the record only delay it (the bound is conservative).
        assert!(!wd::record_finalized(90, 91, 3 * e + 40, 3));
        assert_eq!(wd::FINALIZED_CLAIMS_FROM_HEIGHT, 0, "tests build without the devnet activation override");
    }

    #[test]
    #[cfg(feature = "devnet-l2-user-txs")]
    fn only_an_attested_first_claim_may_exceed_the_window_cap() {
        // Escrow 300 BLCH: cap 30 BLCH. 99 BLCH is below the attestation
        // threshold, so before 2026-10-12 it passed unattested as the
        // window's first claim and took a third of the escrow.
        let leaves = [([1; 32], 99 * BLCH), ([2; 32], 5 * BLCH)];
        let (mut l2, tree) = window_fixture(300 * BLCH, &leaves);
        l2.set_attestor_set(wd::attestor_set_hash(2, &attestors()));
        while (l2.height() + 1) % wd::RELEASE_WINDOW_BLOCKS != 0 || l2.height() + 1 < 1 + WITHDRAW_DELAY_BLOCKS {
            l2.advance_height().unwrap();
        }
        assert_eq!(l2.release_window().cap, 30 * BLCH as u128);
        let proof = wd::proof(&tree, 0).unwrap();
        let state = l2.clone();
        assert_eq!(l2.release_withdrawal(700771, 0, &[1; 32], 99 * BLCH, &proof, false), Err(wd::ClaimRefusal::RateLimited));
        assert_eq!(l2, state);
        // Within the cap, no attestation is needed; afterwards the window is
        // no longer empty, so even an attested 99 BLCH waits.
        release(&mut l2, &tree, &leaves, 1).unwrap();
        assert_eq!(l2.release_withdrawal(700771, 0, &[1; 32], 99 * BLCH, &proof, true), Err(wd::ClaimRefusal::RateLimited));
        for _ in 0..wd::RELEASE_WINDOW_BLOCKS {
            l2.advance_height().unwrap();
        }
        l2.release_withdrawal(700771, 0, &[1; 32], 99 * BLCH, &proof, true).expect("attested first claim of a window");
        assert!(l2.escrow_conserved());
        // Without attestors nobody can lift the cap, so the first claim stays
        // exempt (otherwise it would never pay).
        let (mut bare, tree) = window_fixture(300 * BLCH, &leaves);
        while (bare.height() + 1) % wd::RELEASE_WINDOW_BLOCKS != 0 || bare.height() + 1 < 1 + WITHDRAW_DELAY_BLOCKS {
            bare.advance_height().unwrap();
        }
        release(&mut bare, &tree, &leaves, 0).expect("no attestors: first claim exempt");
    }

    #[test]
    #[cfg(feature = "devnet-l2-user-txs")]
    fn a_small_escrow_releases_up_to_the_floor_per_window() {
        let leaves = [([1; 32], 6 * BLCH), ([2; 32], 4 * BLCH), ([3; 32], BLCH)];
        let (mut l2, tree) = window_fixture(20 * BLCH, &leaves);
        while (l2.height() + 1) % wd::RELEASE_WINDOW_BLOCKS != 0 || l2.height() + 1 < 1 + WITHDRAW_DELAY_BLOCKS {
            l2.advance_height().unwrap();
        }
        assert_eq!(l2.release_window().cap, wd::RELEASE_FLOOR_SAT);
        release(&mut l2, &tree, &leaves, 0).unwrap();
        release(&mut l2, &tree, &leaves, 1).unwrap();
        assert_eq!(release(&mut l2, &tree, &leaves, 2), Err(wd::ClaimRefusal::RateLimited));
    }

    /// Full transition, block by block: deposit (0x14) → V3 settlement
    /// publishing the withdrawal tree → the delay → claim (0x16). The escrow
    /// shrinks by exactly the claim, the recipient's output holds exactly the
    /// leaf amount, the relayer pays the fee, and supply is conserved (the
    /// transition's own check runs on every block).
    #[test]
    #[cfg(feature = "devnet-l2-user-txs")]
    fn deposit_settle_wait_claim_end_to_end() {
        let (pre, mut chains) = funded_async_fixture();
        let amount = 7_000_000_000;
        let deposit = deposit_tx(&pre, amount);
        let deposit_wire = PosTransaction::L2Deposit(deposit.clone());
        let s2 = apply(&pre, 2, std::slice::from_ref(&deposit_wire), &mut chains).unwrap();
        let empty = crate::l2_settlement::expected_body_commitment(&[]);
        let first = to_v3(settlement(&s2, empty), no_deposits(), 0);
        let s3 = apply(&s2, 3, &[PosTransaction::L2SettlementAsync(Box::new(first))], &mut chains).unwrap();
        let s4 = apply(&s3, 4, &[], &mut chains).unwrap();
        // L2 block 2 mints the deposit and withdraws three leaves.
        let record = s4.l2_settlement().unwrap().inbox()[0];
        let mut second = to_v3(settlement(&s4, empty), crate::l2_settlement::deposits_hash(&[record]), 0);
        let leaves = wleaves(3);
        second.statement[S + v3::WITHDRAWAL_ROOT..S + v3::WITHDRAWAL_ROOT + 32].copy_from_slice(&wd::root(&leaves));
        second.statement[S + v3::WITHDRAWAL_COUNT..S + v3::WITHDRAWAL_COUNT + 8].copy_from_slice(&3u64.to_be_bytes());
        let mut state = apply(&s4, 5, &[PosTransaction::L2SettlementAsync(Box::new(second))], &mut chains).unwrap();
        let accepted = state.l2_settlement().unwrap().withdrawal_roots()[0];
        assert_eq!((accepted.count, accepted.height), (3, state.l2_settlement().unwrap().height()));
        let funding = (deposit_wire.txid(), 0);
        let mut slot = 6;
        // Every block before maturity refuses the claim; empty blocks pass.
        while state.l2_settlement().unwrap().height() + 1 < accepted.height + WITHDRAW_DELAY_BLOCKS {
            let early = claim_tx(&state, funding, deposit.change.value, 3, 2);
            state = refuse_then_apply(&state, slot, &[claim(&early)], 0, &[], &mut chains);
            slot += 1;
        }
        assert_eq!(state.l2_settlement().unwrap().matured_count(), 3);
        let tx = claim_tx(&state, funding, deposit.change.value, 3, 2);
        // Matured, but the accepting block is not FFG-finalized yet: the
        // block refuses the claim (an Ethereum rollup waits for L1 finality).
        assert_eq!(state.l2_withdraw_claim_refusal(&tx), Some(ClaimReject::NotFinalized));
        state = refuse_then_apply(&state, slot, &[claim(&tx)], 0, &[], &mut chains);
        slot += 1;
        finalize_all(&mut state);
        let (recipient, sats) = wleaf(2);
        let supply = state.accounted_supply_sat();
        let balance = state.balance_sat(&recipient);
        let post = apply(&state, slot, &[claim(&tx)], &mut chains).expect("matured claim applies");
        let l2 = post.l2_settlement().unwrap();
        assert_eq!(l2.escrow_sat(), u128::from(amount - sats));
        assert_eq!(l2.released_sat(), u128::from(sats));
        assert!(l2.escrow_conserved());
        assert!(l2.claimed().contains(2) && !l2.claimed().contains(1));
        assert_eq!(post.balance_sat(&recipient), balance + u128::from(sats));
        let txid = claim(&tx).txid();
        let out = post.eutxos.get(&(txid, RELEASE_VOUT)).unwrap();
        assert_eq!((out.value, out.script_hash), (sats, recipient));
        assert_eq!(post.eutxos.get(&(txid, CHANGE_VOUT)).unwrap().value, tx.change.value);
        assert!(post.eutxos.get(&funding).is_none(), "relayer input spent");
        // Only the relayer's fee left the accounted supply.
        let fee = deposit.change.value - tx.change.value;
        assert!(supply - post.accounted_supply_sat() <= u128::from(fee));
        assert_ne!(post.state_root(), state.state_root());
        // Replay in the next block: refused.
        refuse_then_apply(&post, slot + 1, &[claim(&tx)], 0, &[], &mut chains);
    }

    // ── M8 part 2: activation of the L2 on a running network ──────────────

    use crate::l2_settlement::{Activation, Profile};

    /// A network that has run without L2: no policy at genesis, bound domain.
    fn running_without_l2() -> (CommittedState, Policy) {
        let (_, mut genesis, _) = setup(4);
        genesis.admission_network_domain = Some([0x91; 32]);
        let identities = std::array::from_fn(|i| hash_at(TEMPLATE, S + i * 32));
        let mut policy = Policy {
            identities,
            proof_policy: bloch_l2_proof::policy_commitment(),
            chain_id: 700771,
            initial_l2_parent: hash_at(TEMPLATE, S + 272),
            initial_l2_state: hash_at(TEMPLATE, S + 304),
            attestor_set: [0; 32],
        };
        policy.identities[0] = [0x91; 32];
        policy.identities[1] = *genesis.head.as_bytes();
        assert!(genesis.l2_settlement().is_none());
        (genesis, policy)
    }

    /// Limits of a rehearsal activation, deliberately unlike the development
    /// constants so that a test passing with them proves the pinned limits
    /// (not `withdrawal::Limits::DEVELOPMENT`) govern the activated L2.
    const PINNED: wd::Limits = wd::Limits {
        delay_blocks: 40,
        large_claim_sat: 50 * BLCH,
        large_delay_blocks: 90,
        retention_blocks: 120,
        release_window_blocks: 48,
        release_window_bps: 500,
        release_floor_sat: 5 * BLCH,
    };
    const _: () = assert!(PINNED.valid() && PINNED.delay_blocks > WITHDRAW_DELAY_BLOCKS);

    fn activation(policy: Policy, asynchronous: bool) -> Activation {
        Activation { policy, asynchronous, limits: PINNED }
    }

    #[test]
    fn l2_settlement_gate_is_inert() {
        assert_eq!(crate::params::L2_SETTLEMENT_ACTIVATION_EPOCH, u64::MAX);
        assert!(!crate::params::l2_settlement_active(u64::MAX - 1));
        assert!(crate::l2_settlement::activation_policy().is_none());
    }

    #[test]
    fn armed_l2_gate_has_a_policy() {
        if crate::params::L2_SETTLEMENT_ACTIVATION_EPOCH != u64::MAX {
            let pinned = crate::l2_settlement::activation_policy()
                .expect("an armed L2 gate needs a pinned activation policy");
            assert!(pinned.valid(), "pinned policy and limits must be valid");
            assert_eq!(pinned.policy.chain_id, crate::l2_settlement::MAINNET_CHAIN_ID);
            // The approved mainnet policy, with every set-once part filled.
            assert_eq!(Ok(pinned.clone()), crate::l2_settlement::mainnet::activation());
            assert_ne!(pinned.policy.attestor_set, [0; 32], "attestor keys must be set");
            let l2 = crate::l2_settlement::State::activated(pinned).expect("the pinned activation installs");
            assert!(l2.profile().is_activated() && l2.user_transactions());
        }
    }

    #[test]
    fn inert_boundary_keeps_the_state_root() {
        let (genesis, policy) = running_without_l2();
        let plain = genesis.close_epoch();
        // A pinned policy alone does nothing while the gate is the sentinel.
        let _policy = crate::l2_settlement::activation_rehearsal::set(activation(policy, true));
        let with_policy = genesis.close_epoch();
        assert!(with_policy.l2_settlement().is_none());
        assert_eq!(with_policy.state_root(), plain.state_root());
        assert_eq!(with_policy, plain);
    }

    #[test]
    fn activation_installs_the_policy_at_the_boundary() {
        for asynchronous in [false, true] {
            let (genesis, policy) = running_without_l2();
            let inert = genesis.close_epoch();
            let _gate = crate::params::l2_settlement_rehearsal::open();
            let _policy = crate::l2_settlement::activation_rehearsal::set(activation(policy.clone(), asynchronous));
            // Mid-epoch blocks are untouched: activation happens at the boundary.
            assert!(genesis.l2_settlement().is_none());
            let opened = genesis.close_epoch();
            let l2 = opened.l2_settlement().expect("installed at the boundary");
            assert_eq!(l2.policy(), &policy);
            assert_eq!(l2.height(), 0);
            assert_eq!(l2.asynchronous(), asynchronous);
            assert_eq!(l2.profile(), &Profile::activated(PINNED));
            assert_eq!(opened.epoch, genesis.epoch + 1);
            // The L2 component enters the state root only now.
            assert_ne!(opened.state_root(), inert.state_root());
            let mut without = opened.clone();
            without.l2_settlement = None;
            assert_eq!(without.state_root(), inert.state_root());
            // Installed once: the next boundary does not reset it.
            let next = opened.close_epoch();
            assert_eq!(next.l2_settlement().map(|s| s.policy()), Some(&policy));
        }
    }

    #[test]
    fn activation_ignores_other_networks() {
        let (genesis, mut policy) = running_without_l2();
        policy.identities[0] = [0x92; 32];
        let _gate = crate::params::l2_settlement_rehearsal::open();
        let _policy = crate::l2_settlement::activation_rehearsal::set(activation(policy, true));
        let opened = genesis.close_epoch();
        assert!(opened.l2_settlement().is_none());
        let mut unbound = genesis.clone();
        unbound.admission_network_domain = None;
        assert!(unbound.close_epoch().l2_settlement().is_none());
    }

    #[test]
    fn activation_with_invalid_limits_installs_nothing() {
        let (genesis, policy) = running_without_l2();
        let _gate = crate::params::l2_settlement_rehearsal::open();
        let broken = [
            wd::Limits { delay_blocks: 0, ..PINNED },
            wd::Limits { large_delay_blocks: PINNED.delay_blocks - 1, ..PINNED },
            wd::Limits { retention_blocks: PINNED.large_delay_blocks - 1, ..PINNED },
            wd::Limits { retention_blocks: wd::MAX_RETENTION_BLOCKS + 1, large_delay_blocks: wd::MAX_RETENTION_BLOCKS + 1, ..PINNED },
            wd::Limits { release_window_blocks: 0, ..PINNED },
            wd::Limits { release_window_bps: 0, ..PINNED },
            wd::Limits { release_window_bps: 10_001, ..PINNED },
            wd::Limits { release_floor_sat: 0, ..PINNED },
            wd::Limits { large_claim_sat: 0, ..PINNED },
        ];
        for limits in broken {
            let pinned = Activation { policy: policy.clone(), asynchronous: true, limits };
            assert!(!pinned.valid(), "{limits:?}");
            assert_eq!(crate::l2_settlement::State::activated(pinned.clone()), Err(Reject::Policy));
            let _policy = crate::l2_settlement::activation_rehearsal::set(pinned);
            assert!(genesis.close_epoch().l2_settlement().is_none(), "{limits:?}");
        }
    }

    #[test]
    fn activation_never_replaces_existing_l2_state() {
        let (pre, _) = fixture();
        let mut other = pre.l2_settlement().unwrap().policy().clone();
        other.chain_id = 1;
        other.identities[0] = pre.admission_network_domain.unwrap();
        let _gate = crate::params::l2_settlement_rehearsal::open();
        let _policy = crate::l2_settlement::activation_rehearsal::set(activation(other, true));
        let next = pre.close_epoch();
        assert_eq!(next.l2_settlement().unwrap().policy(), pre.l2_settlement().unwrap().policy());
        assert_eq!(next.l2_settlement().unwrap().policy().chain_id, 700771);
        // A development genesis keeps its development profile.
        assert_eq!(next.l2_settlement().unwrap().profile(), &Profile::development());
    }

    #[test]
    fn settlements_are_refused_before_and_admitted_after_activation() {
        let (_, mut genesis, mut chains) = setup(4);
        let (_, policy) = running_without_l2();
        genesis.admission_network_domain = Some(policy.identities[0]);
        let mut policy = policy;
        policy.identities[1] = *genesis.head.as_bytes();
        let t = Transition::new(ToyVerifier);

        // Epoch 0, before the flag day: a block applies, no L2 state, the
        // settlement wire is refused exactly as by a build without L2.
        let first = build_block(&t, &genesis, 1, &[], &[], &mut chains);
        let before = t.apply_block(&genesis, &first, &[], &[]).unwrap();
        assert!(before.l2_settlement().is_none());
        let (with_l2, _) = fixture();
        let foreign = transaction(&with_l2);
        assert_eq!(
            before.clone().apply_transaction(&PosTransaction::L2Settlement(Box::new(foreign)), 0, 1, &ProofDouble),
            Err(TxReject::L2Settlement(Reject::NotActive))
        );

        // The first block of epoch 1 crosses the boundary: the flag day
        // installs the policy, and the block itself is the L2's native height 1.
        let _gate = crate::params::l2_settlement_rehearsal::open();
        let _policy = crate::l2_settlement::activation_rehearsal::set(activation(policy.clone(), false));
        let boundary = build_block(&t, &before, crate::params::SLOTS_PER_EPOCH, &[], &[], &mut chains);
        let opened = t.apply_block(&before, &boundary, &[], &[]).unwrap();
        let l2 = opened.l2_settlement().expect("installed at the boundary");
        assert_eq!(l2.policy(), &policy);
        assert_eq!(l2.height(), 1);

        // A settlement built against the activated L2 is admitted in the next block.
        let tx = PosTransaction::L2Settlement(Box::new(transaction(&opened)));
        let mut admitted = opened.clone();
        admitted.apply_transaction(&tx, 0, 1, &ProofDouble)
            .expect("a settlement against the activated L2 is admitted");
        assert_ne!(admitted.state_root(), opened.state_root());
    }

    // ── M9: the activated L2 is fully capable on every build ──────────────

    /// The funded running network (the depositor's coin at `[0x33; 32]:0`)
    /// before the flag day, at slot 1, and its policy.
    fn funded_running_without_l2() -> (CommittedState, Policy, Vec<RandaoChain>) {
        let key = depositor();
        let coin = crate::state_root::EutxoEntry { txid: [0x33; 32], vout: 0, value: FUNDED, script_hash: script_of(&key) };
        let (_, mut genesis, mut chains) = setup_with(4, ToyVerifier, &[coin]);
        genesis.admission_network_domain = Some([0x91; 32]);
        let (_, mut policy) = running_without_l2();
        policy.identities[1] = *genesis.head.as_bytes();
        let pre = apply(&genesis, 1, &[], &mut chains).unwrap();
        assert!(pre.l2_settlement().is_none());
        (pre, policy, chains)
    }

    /// The funded network after its flag day: the first block of epoch 1
    /// installed the activation (native L2 height 1).
    fn activated_fixture(asynchronous: bool, attestor_set: [u8; 32]) -> (CommittedState, Vec<RandaoChain>) {
        let (pre, mut policy, mut chains) = funded_running_without_l2();
        policy.attestor_set = attestor_set;
        let _gate = crate::params::l2_settlement_rehearsal::open();
        let _policy = crate::l2_settlement::activation_rehearsal::set(activation(policy, asynchronous));
        let opened = apply(&pre, crate::params::SLOTS_PER_EPOCH, &[], &mut chains).unwrap();
        let l2 = opened.l2_settlement().expect("installed at the boundary");
        assert_eq!((l2.height(), l2.asynchronous()), (1, asynchronous));
        (opened, chains)
    }

    #[test]
    fn the_activated_profile_does_not_depend_on_build_features() {
        let (_, policy) = running_without_l2();
        let dev = crate::l2_settlement::State::genesis(policy.clone()).unwrap();
        // A development genesis follows the build (devnet replays unchanged).
        assert_eq!(dev.profile(), &Profile::development());
        assert_eq!(dev.profile().deposits, cfg!(feature = "devnet-l2-deposits"));
        assert_eq!(dev.user_transactions(), cfg!(feature = "devnet-l2-user-txs"));
        assert_eq!(dev.limits(), &wd::Limits::DEVELOPMENT);
        assert!(!dev.profile().is_activated());
        // The activated L2 admits everything on this build, whatever it is.
        let on = crate::l2_settlement::State::activated(activation(policy.clone(), true)).unwrap();
        assert!(on.profile().is_activated() && on.deposits_enabled() && on.user_transactions());
        assert_eq!(on.profile().finalized_claims_from_height, 0);
        assert_eq!(on.limits(), &PINNED);
        // Synchronous settlement has no inbox: no deposits (and no claims).
        let sync = crate::l2_settlement::State::activated(activation(policy, false)).unwrap();
        assert!(!sync.deposits_enabled() && sync.user_transactions());
        // The development state bytes carry no profile (devnet roots are
        // unchanged); the activated state commits its profile and limits.
        let tag: &[u8] = b"BLOCH:NATIVE:L2:ACTIVATED-PROFILE:1";
        assert!(!dev.committed_bytes().windows(tag.len()).any(|w| w == tag));
        let bytes = on.committed_bytes();
        assert!(bytes.windows(tag.len()).any(|w| w == tag));
        let other = crate::l2_settlement::State::activated(Activation {
            limits: wd::Limits { release_window_bps: 400, ..PINNED },
            ..activation(on.policy().clone(), true)
        })
        .unwrap();
        assert_ne!(other.committed_bytes(), bytes, "the limits are committed");
    }

    #[test]
    fn l2_transactions_are_refused_and_roots_unchanged_while_inert() {
        let (pre, policy, mut chains) = funded_running_without_l2();
        // Blocks across the first boundary, built and applied without any pinned policy.
        let mut plain = vec![pre.clone()];
        let mut blocks = Vec::new();
        let t = Transition::new(ProofDouble);
        for slot in [2, crate::params::SLOTS_PER_EPOCH - 1, crate::params::SLOTS_PER_EPOCH, crate::params::SLOTS_PER_EPOCH + 1] {
            let block = build_block(&t, plain.last().unwrap(), slot, &[], &[], &mut chains);
            plain.push(t.apply_block(plain.last().unwrap(), &block, &[], &[]).unwrap());
            blocks.push(block);
        }
        // The same blocks with an activation pinned but the gate the
        // sentinel: every post-state, and so every state root, is identical.
        let _policy = crate::l2_settlement::activation_rehearsal::set(activation(policy, true));
        let mut state = pre.clone();
        for (block, expected) in blocks.iter().zip(&plain[1..]) {
            state = t.apply_block(&state, block, &[], &[]).unwrap();
            assert_eq!(&state, expected);
            assert_eq!(state.state_root(), expected.state_root());
            assert!(state.l2_settlement().is_none());
        }
        // Every L2 transaction is refused without mutation, as by a build
        // without L2: deposit, DA, claim, settlement (sync and async).
        let leaves = [([1; 32], BLCH)];
        let refusals = [
            PosTransaction::L2Deposit(deposit_tx(&state, 7 * BLCH)),
            PosTransaction::L2DataAvailability(da_tx(&state, ([0x33; 32], 0), FUNDED, 1, batch(&[b"tx"]))),
            claim(&claim_of(&state, &leaves, 0, None)),
        ];
        for tx in refusals.iter() {
            let mut st = state.clone();
            assert!(st.apply_transaction(tx, 0, state.next_base_fee(), &ToyVerifier).is_err(), "{tx:?}");
            assert_eq!(st, state);
        }
        assert_eq!(state.l2_withdraw_claim_refusal(&claim_of(&state, &leaves, 0, None)), Some(ClaimReject::NotActive));
        let (with_l2, _) = fixture();
        for wire in [
            PosTransaction::L2Settlement(Box::new(transaction(&with_l2))),
            PosTransaction::L2SettlementAsync(Box::new(transaction(&with_l2))),
        ] {
            let mut st = state.clone();
            assert_eq!(st.apply_transaction(&wire, 0, 1, &ProofDouble), Err(TxReject::L2Settlement(Reject::NotActive)));
            assert_eq!(st, state);
        }
        // A block carrying one of them is invalid.
        let t = Transition::new(ProofDouble);
        let mut graft = build_block(&t, &state, crate::params::SLOTS_PER_EPOCH + 2, &[], &[], &mut chains);
        graft.header.body_root = crate::derive::body_root(&[refusals[0].canonical_bytes()]);
        let pk = crate::attestation::KeyLookup::pubkey(&state, graft.header.proposer_index).unwrap();
        graft.proposer_sig = toy_sign(pk, &graft.header.proposal_signing_root());
        assert_eq!(t.compute_post_state(&state, &graft, &[], &refusals[..1]), Err(TransitionError::Transaction(0)));
    }

    #[test]
    fn activated_l2_deposits_settles_user_transactions_and_pays_claims() {
        let (opened, mut chains) = activated_fixture(true, [0; 32]);
        let mut slot = crate::params::SLOTS_PER_EPOCH + 1;
        let mut next = |pre: &CommittedState, txs: &[PosTransaction], chains: &mut Vec<RandaoChain>| {
            let post = apply(pre, slot, txs, chains);
            slot += 1;
            post
        };
        // Deposit: escrowed into the inbox (no cargo feature needed).
        let amount = 70 * BLCH;
        let deposit = deposit_tx(&opened, amount);
        let deposit_wire = PosTransaction::L2Deposit(deposit.clone());
        let s2 = next(&opened, std::slice::from_ref(&deposit_wire), &mut chains).expect("deposit applies");
        assert_eq!(s2.l2_settlement().unwrap().escrow_sat(), u128::from(amount));
        let record = s2.l2_settlement().unwrap().inbox()[0];

        // DA for L2 block 1, then the user-transaction settlement that needs it.
        let payload = batch(&[&[0x02, 0xc0], b"second"]);
        let da = da_tx(&s2, (deposit_wire.txid(), 0), deposit.change.value, 1, payload.clone());
        let da_wire = PosTransaction::L2DataAvailability(da.clone());
        let commitment = da::commitment(700771, 1, &payload);
        // Without the batch on L1 the settlement is refused.
        let early = v3_with_da(&s2, commitment);
        assert_eq!(
            s2.l2_settlement().unwrap().clone().apply(&early, *s2.head.as_bytes(), s2.slot, true, &ProofDouble),
            Err(Reject::DataUnavailable)
        );
        let s3 = next(&s2, std::slice::from_ref(&da_wire), &mut chains).expect("DA applies");
        assert_eq!(s3.l2_settlement().unwrap().data_availability().len(), 1);
        let first = PosTransaction::L2SettlementAsync(Box::new(v3_with_da(&s3, commitment)));
        let s4 = next(&s3, std::slice::from_ref(&first), &mut chains).expect("user transactions settle with DA");
        assert_eq!(s4.l2_settlement().unwrap().settled_number(), 1);
        let s5 = next(&s4, &[], &mut chains).unwrap();

        // L2 block 2 mints the deposit and withdraws three leaves.
        let empty = crate::l2_settlement::expected_body_commitment(&[]);
        let mut second = to_v3(settlement(&s5, empty), crate::l2_settlement::deposits_hash(&[record]), 0);
        let leaves = wleaves(3);
        second.statement[S + v3::WITHDRAWAL_ROOT..S + v3::WITHDRAWAL_ROOT + 32].copy_from_slice(&wd::root(&leaves));
        second.statement[S + v3::WITHDRAWAL_COUNT..S + v3::WITHDRAWAL_COUNT + 8].copy_from_slice(&3u64.to_be_bytes());
        let mut state = next(&s5, &[PosTransaction::L2SettlementAsync(Box::new(second))], &mut chains).unwrap();
        let accepted = state.l2_settlement().unwrap().withdrawal_roots()[0];
        assert_eq!(state.l2_settlement().unwrap().consumed(), 1);

        // The pinned delay governs, not the development one.
        let funding = (da_wire.txid(), 0);
        while state.l2_settlement().unwrap().height() + 1 < accepted.height + PINNED.delay_blocks {
            let early = claim_tx(&state, funding, da.change.value, 3, 2);
            assert_eq!(state.l2_withdraw_claim_refusal(&early), Some(ClaimReject::NotMatured));
            state = next(&state, &[], &mut chains).unwrap();
        }
        assert!(state.l2_settlement().unwrap().height() + 1 > accepted.height + WITHDRAW_DELAY_BLOCKS);
        let tx = claim_tx(&state, funding, da.change.value, 3, 2);
        // Ethereum-rollup finality from the first activated block.
        assert_eq!(state.l2_withdraw_claim_refusal(&tx), Some(ClaimReject::NotFinalized));
        finalize_all(&mut state);
        assert_eq!(state.l2_withdraw_claim_refusal(&tx), None);
        let (recipient, sats) = wleaf(2);
        let balance = state.balance_sat(&recipient);
        let post = next(&state, &[claim(&tx)], &mut chains).expect("matured, finalized claim pays");
        let l2 = post.l2_settlement().unwrap();
        assert_eq!(l2.escrow_sat(), u128::from(amount - sats));
        assert!(l2.escrow_conserved() && l2.claimed().contains(2));
        assert_eq!(post.balance_sat(&recipient), balance + u128::from(sats));
        // Replay: refused.
        assert!(post.l2_withdraw_claim_refusal(&tx).is_some());
        // The restart cache restores all of it (inbox, DA, withdrawals,
        // claim bitmap, release window, activated profile).
        #[cfg(feature = "local-state-cache")]
        {
            assert!(l2.claimed().claims() == 1 && !l2.withdrawal_roots().is_empty());
            local_cache_round_trip(&post);
        }
    }

    #[test]
    fn activated_l2_enforces_attestors_and_the_pinned_release_window() {
        let set = wd::attestor_set_hash(2, &attestors());
        let (mut pre, _) = activated_fixture(true, set);
        // 1 000 BLCH escrowed; one finalized record over `leaves`, old
        // enough for large claims under the pinned limits.
        let leaves = [([1; 32], 60 * BLCH), ([2; 32], 30 * BLCH), ([3; 32], 25 * BLCH), ([4; 32], 4 * BLCH)];
        let tree: Vec<[u8; 32]> =
            leaves.iter().enumerate().map(|(i, (r, sats))| wd::leaf(700771, i as u64, r, *sats)).collect();
        let l2 = pre.l2_settlement.as_mut().unwrap();
        l2.append_deposit(crate::l2_settlement::InboxRecord {
            height: 1, tx_index: 0, txid: [0x77; 32], vout: 1, sats: 1_000 * BLCH, recipient: [0x42; 20],
        })
        .unwrap();
        l2.insert_withdrawal_record(wd::Record { l2_number: 1, root: wd::root(&tree), count: tree.len() as u64, height: 1 });
        // Matured for small claims but not yet for large ones (pinned delays).
        while l2.height() + 1 < 1 + PINNED.delay_blocks {
            l2.advance_height().unwrap();
        }
        finalize_all(&mut pre);
        let refuse = |pre: &CommittedState, tx: &L2WithdrawClaim, why| {
            assert_eq!(try_claim(pre, tx).map(|_| ()), Err(TxReject::L2WithdrawClaim(why)))
        };
        // 60 BLCH >= the pinned large threshold (50): it needs the attestors...
        refuse(&pre, &claim_of(&pre, &leaves, 0, None), ClaimReject::AttestationRequired);
        // ...and the pinned large delay (90), attested or not.
        refuse(&pre, &claim_of(&pre, &leaves, 0, Some(attest(&leaves, &[0, 1]))), ClaimReject::NotMatured);
        // 30 BLCH is small here (it would be small in development too) and pays.
        let small = try_claim(&pre, &claim_of(&pre, &leaves, 1, None)).expect("small claim");
        // Pinned window: 5% of 1 000 BLCH = 50 BLCH; 30 + 25 exceeds it.
        assert_eq!(small.l2_settlement().unwrap().release_window().cap, 50 * u128::from(BLCH));
        refuse(&small, &claim_of(&small, &leaves, 2, None), ClaimReject::RateLimited);

        let l2 = pre.l2_settlement.as_mut().unwrap();
        while l2.height() + 1 < 1 + PINNED.large_delay_blocks {
            l2.advance_height().unwrap();
        }
        refuse(&pre, &claim_of(&pre, &leaves, 0, None), ClaimReject::AttestationRequired);
        refuse(&pre, &claim_of(&pre, &leaves, 0, Some(attest(&leaves, &[2]))), ClaimReject::Shape);
        // k-of-n: the attested first claim of a window may exceed its cap.
        let post = try_claim(&pre, &claim_of(&pre, &leaves, 0, Some(attest(&leaves, &[0, 2])))).expect("attested large claim");
        assert!(post.l2_settlement().unwrap().claimed().contains(0));
        assert!(post.l2_settlement().unwrap().escrow_conserved());
        // The next claim of the same window is over the cap.
        refuse(&post, &claim_of(&post, &leaves, 3, None), ClaimReject::RateLimited);
    }

    // ── Mainnet L2 policy approved 2026-10-14 ─────────────────────────────

    use crate::l2_settlement::mainnet;

    fn mainnet_attestors() -> Vec<Vec<u8>> {
        (0..5).map(attestor).collect()
    }

    /// The text `l2-claim attestor-set` writes for `keys` at `threshold`.
    fn set_file(threshold: u8, keys: &[Vec<u8>]) -> String {
        let hex = |k: &Vec<u8>| k.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let mut text = format!("{threshold}\n");
        for key in keys {
            text.push_str(&hex(key));
            text.push('\n');
        }
        text
    }

    fn mainnet_program() -> mainnet::Program {
        let (_, policy) = running_without_l2();
        mainnet::Program {
            identities: policy.identities,
            proof_policy: policy.proof_policy,
            initial_l2_parent: policy.initial_l2_parent,
            initial_l2_state: policy.initial_l2_state,
        }
    }

    #[test]
    fn mainnet_policy_records_the_approved_values() {
        assert!(mainnet::ASYNCHRONOUS);
        assert_eq!((mainnet::ATTESTOR_THRESHOLD, mainnet::ATTESTOR_COUNT), (3, 5));
        assert_eq!(mainnet::BLCH, BLCH);
        assert_eq!(
            mainnet::LIMITS,
            wd::Limits {
                delay_blocks: 64,
                large_claim_sat: 100 * BLCH,
                large_delay_blocks: 2_880,
                retention_blocks: 2_880,
                release_window_blocks: 2_880,
                release_window_bps: 1_000,
                release_floor_sat: 10 * BLCH,
            }
        );
        assert!(mainnet::LIMITS.valid());
        // The epoch is not chosen and the set-once parts are unset.
        assert_eq!(crate::params::L2_SETTLEMENT_ACTIVATION_EPOCH, u64::MAX);
        assert_eq!(mainnet::ATTESTOR_SET, None);
        assert_eq!(mainnet::PROGRAM, None);
        assert_eq!(mainnet::activation(), Err(mainnet::Incomplete::AttestorKeysUnset));
        assert!(crate::l2_settlement::activation_policy().is_none());
        // Once filled, the activation is exactly the approved policy.
        let set = set_file(3, &mainnet_attestors());
        let a = mainnet::activation_from(Some(&mainnet_program()), Some(&set)).unwrap();
        assert!(a.valid());
        assert!(a.asynchronous);
        assert_eq!(a.limits, mainnet::LIMITS);
        assert_eq!(a.policy.chain_id, crate::l2_settlement::MAINNET_CHAIN_ID);
        assert_eq!(a.policy.attestor_set, wd::attestor_set_hash(3, &mainnet_attestors()));
        let l2 = crate::l2_settlement::State::activated(a).unwrap();
        assert!(l2.profile().is_activated() && l2.deposits_enabled() && l2.user_transactions());
    }

    #[test]
    fn mainnet_activation_is_refused_while_attestor_keys_are_unset() {
        use mainnet::Incomplete as I;
        let program = mainnet_program();
        let keys = mainnet_attestors();
        // The build refuses to produce an activation.
        assert_eq!(mainnet::activation_from(Some(&program), None), Err(I::AttestorKeysUnset));
        assert_eq!(mainnet::activation_from(None, None), Err(I::AttestorKeysUnset));
        assert_eq!(mainnet::activation_from(None, Some(&set_file(3, &keys))), Err(I::ProgramUnset));
        // Only 3-of-5 distinct enveloped hybrid keys are a mainnet set.
        let mut dup = keys.clone();
        dup[4] = dup[0].clone();
        let mut short = keys.clone();
        short[2].pop();
        for bad in [
            set_file(2, &keys),
            set_file(5, &keys),
            set_file(3, &keys[..4]),
            set_file(3, &[keys.clone(), vec![attestor(5)]].concat()),
            set_file(3, &dup),
            set_file(3, &short),
            String::new(),
            "3\nzz\n".to_string(),
        ] {
            assert_eq!(mainnet::activation_from(Some(&program), Some(&bad)), Err(I::AttestorSet));
        }
        // Consensus never installs a mainnet-chain activation without
        // attestors, synchronous, or with other limits, even when armed.
        let (genesis, mut policy) = running_without_l2();
        policy.chain_id = crate::l2_settlement::MAINNET_CHAIN_ID;
        let _gate = crate::params::l2_settlement_rehearsal::open();
        let unset = Activation { policy: policy.clone(), asynchronous: true, limits: mainnet::LIMITS };
        let mut set_policy = policy.clone();
        set_policy.attestor_set = wd::attestor_set_hash(3, &keys);
        let broken = [
            unset,
            Activation { policy: set_policy.clone(), asynchronous: false, limits: mainnet::LIMITS },
            Activation { policy: set_policy.clone(), asynchronous: true, limits: PINNED },
        ];
        for pinned in broken {
            assert!(!pinned.valid());
            assert_eq!(crate::l2_settlement::State::activated(pinned.clone()), Err(Reject::Policy));
            let _policy = crate::l2_settlement::activation_rehearsal::set(pinned);
            assert!(genesis.close_epoch().l2_settlement().is_none());
        }
        // With the keys set, the same boundary installs it.
        let good = Activation { policy: set_policy, asynchronous: true, limits: mainnet::LIMITS };
        assert!(good.valid());
        let _policy = crate::l2_settlement::activation_rehearsal::set(good);
        let opened = genesis.close_epoch();
        let l2 = opened.l2_settlement().expect("installed with the keys set");
        assert_eq!(l2.limits(), &mainnet::LIMITS);
    }

    #[test]
    fn mainnet_large_threshold_is_exactly_100_blch() {
        let limits = mainnet::LIMITS;
        assert_eq!(limits.delay_for(100 * BLCH - 1), 64);
        assert_eq!(limits.delay_for(100 * BLCH), 2_880);
        assert_eq!(limits.delay_for(100 * BLCH + 1), 2_880);
        assert_eq!(limits.delay_for(1), 64);
        let (_, mut policy) = running_without_l2();
        policy.attestor_set = wd::attestor_set_hash(3, &mainnet_attestors());
        let l2 = crate::l2_settlement::State::activated(Activation { policy, asynchronous: true, limits }).unwrap();
        assert!(!l2.attestation_required(100 * BLCH - 1));
        assert!(l2.attestation_required(100 * BLCH));
        assert!(l2.attestation_required(u64::MAX));
    }

    #[test]
    fn mainnet_release_window_is_10_percent_with_a_10_blch_floor() {
        let limits = mainnet::LIMITS;
        let cap = |escrow: u64| wd::ReleaseWindow::default().at(&limits, 2_880, u128::from(escrow)).cap;
        let sat = |blch: u64| u128::from(blch * BLCH);
        // The floor governs below 100 BLCH of escrow.
        assert_eq!(cap(0), sat(10));
        assert_eq!(cap(50 * BLCH), sat(10));
        assert_eq!(cap(100 * BLCH), sat(10));
        // 10% above it.
        assert_eq!(cap(101 * BLCH), sat(10) + u128::from(BLCH / 10));
        assert_eq!(cap(1_000 * BLCH), sat(100));
        assert_eq!(cap(25_000 * BLCH), sat(2_500));
        // Windows are 2 880 native blocks.
        let used = wd::ReleaseWindow { window: 0, released: sat(100), cap: sat(100) };
        assert_eq!(used.at(&limits, 2_879, sat(900)), used);
        let next = used.at(&limits, 2_880, sat(900));
        assert_eq!((next.window, next.released, next.cap), (1, 0, sat(90)));
        // The cap is inclusive; only an exempt (attested) first claim exceeds it.
        let fresh = wd::ReleaseWindow::default().at(&limits, 0, sat(1_000));
        assert!(fresh.admits(100 * BLCH, false));
        assert!(!fresh.admits(100 * BLCH + 1, false));
        assert!(fresh.admits(100 * BLCH + 1, true));
        let after = wd::ReleaseWindow { released: 1, ..fresh };
        assert!(!after.admits(100 * BLCH, true));
    }

    /// Signatures of `signers` (indices into `keys`, signed with `signing`
    /// keys) over the root `leaves` folds to, as a 3-of-n attestation.
    fn attest_with(leaves: &[([u8; 32], u64)], keys: Vec<Vec<u8>>, signers: &[(u8, Vec<u8>)]) -> Attestation {
        let tree: Vec<[u8; 32]> =
            leaves.iter().enumerate().map(|(i, (r, s))| wd::leaf(700771, i as u64, r, *s)).collect();
        let digest = wd::attestation_digest(&[0x91; 32], 700771, &wd::root(&tree));
        Attestation {
            threshold: mainnet::ATTESTOR_THRESHOLD,
            keys,
            signatures: signers.iter().map(|(i, key)| (*i, toy_sign(key, &digest))).collect(),
        }
    }
    fn attest5(leaves: &[([u8; 32], u64)], signers: &[u8]) -> Attestation {
        let signers: Vec<(u8, Vec<u8>)> = signers.iter().map(|&i| (i, attestor(i))).collect();
        attest_with(leaves, mainnet_attestors(), &signers)
    }

    #[test]
    fn mainnet_policy_end_to_end_3_of_5_delays_and_window() {
        // The approved limits and a 3-of-5 set, installed at the boundary of
        // the funded test network (chain 700771, so the mainnet-chain shape
        // rule is not what is under test here).
        let (base, mut policy, mut chains) = funded_running_without_l2();
        policy.attestor_set = wd::attestor_set_hash(3, &mainnet_attestors());
        let mut pre = {
            let _gate = crate::params::l2_settlement_rehearsal::open();
            let _policy = crate::l2_settlement::activation_rehearsal::set(Activation {
                policy,
                asynchronous: mainnet::ASYNCHRONOUS,
                limits: mainnet::LIMITS,
            });
            apply(&base, crate::params::SLOTS_PER_EPOCH, &[], &mut chains).unwrap()
        };
        assert_eq!(pre.l2_settlement().unwrap().limits(), &mainnet::LIMITS);
        // 1 000 BLCH escrowed (window cap 100 BLCH); one record at height 1.
        let leaves = [([1; 32], 100 * BLCH), ([2; 32], 100 * BLCH - 1), ([3; 32], 50 * BLCH), ([4; 32], BLCH)];
        let tree: Vec<[u8; 32]> =
            leaves.iter().enumerate().map(|(i, (r, sats))| wd::leaf(700771, i as u64, r, *sats)).collect();
        let l2 = pre.l2_settlement.as_mut().unwrap();
        l2.append_deposit(crate::l2_settlement::InboxRecord {
            height: 1, tx_index: 0, txid: [0x77; 32], vout: 1, sats: 1_000 * BLCH, recipient: [0x42; 20],
        })
        .unwrap();
        l2.insert_withdrawal_record(wd::Record { l2_number: 1, root: wd::root(&tree), count: tree.len() as u64, height: 1 });
        while l2.height() + 1 < 64 {
            l2.advance_height().unwrap();
        }
        finalize_all(&mut pre);
        let refuse = |pre: &CommittedState, tx: &L2WithdrawClaim, why| {
            assert_eq!(try_claim(pre, tx).map(|_| ()), Err(TxReject::L2WithdrawClaim(why)))
        };
        // Small (just under 100 BLCH): 63 blocks are not enough, 64 are.
        refuse(&pre, &claim_of(&pre, &leaves, 1, None), ClaimReject::NotMatured);
        pre.l2_settlement.as_mut().unwrap().advance_height().unwrap();
        let small = try_claim(&pre, &claim_of(&pre, &leaves, 1, None)).expect("small claim after 64 blocks");
        assert_eq!(small.l2_settlement().unwrap().release_window().cap, 100 * u128::from(BLCH));
        // Window: 99.99999999 + 50 BLCH exceeds the 100 BLCH cap.
        refuse(&small, &claim_of(&small, &leaves, 2, None), ClaimReject::RateLimited);
        // Exactly 100 BLCH is large: attestation required, then the large delay.
        refuse(&pre, &claim_of(&pre, &leaves, 0, None), ClaimReject::AttestationRequired);
        refuse(&pre, &claim_of(&pre, &leaves, 0, Some(attest5(&leaves, &[0, 1, 2]))), ClaimReject::NotMatured);

        let l2 = pre.l2_settlement.as_mut().unwrap();
        while l2.height() + 1 < 1 + 2_880 {
            l2.advance_height().unwrap();
        }
        refuse(&pre, &claim_of(&pre, &leaves, 0, None), ClaimReject::AttestationRequired);
        // Two signatures: refused.
        refuse(&pre, &claim_of(&pre, &leaves, 0, Some(attest5(&leaves, &[0, 3]))), ClaimReject::Shape);
        // The same signer twice to make up three: refused.
        refuse(&pre, &claim_of(&pre, &leaves, 0, Some(attest5(&leaves, &[0, 0, 3]))), ClaimReject::Shape);
        let mut doubled = attest5(&leaves, &[0, 1, 3]);
        doubled.keys[1] = attestor(0);
        doubled.signatures[1].1 = doubled.signatures[0].1.clone();
        refuse(&pre, &claim_of(&pre, &leaves, 0, Some(doubled)), ClaimReject::Shape);
        // A non-member: a set with an outside key, signed by it...
        let mut foreign_keys = mainnet_attestors();
        foreign_keys[4] = attestor(9);
        let foreign = attest_with(&leaves, foreign_keys, &[(0, attestor(0)), (1, attestor(1)), (4, attestor(9))]);
        refuse(&pre, &claim_of(&pre, &leaves, 0, Some(foreign)), ClaimReject::Attestation);
        // ...or signing in a member's slot.
        let impostor = attest_with(&leaves, mainnet_attestors(), &[(0, attestor(0)), (1, attestor(1)), (4, attestor(9))]);
        refuse(&pre, &claim_of(&pre, &leaves, 0, Some(impostor)), ClaimReject::Attestation);
        // The right set at another threshold is another set.
        let mut two_of_five = attest5(&leaves, &[0, 1, 2]);
        two_of_five.threshold = 2;
        refuse(&pre, &claim_of(&pre, &leaves, 0, Some(two_of_five)), ClaimReject::Attestation);
        // Three distinct members: accepted (any three, and all five).
        for signers in [&[0u8, 1, 2][..], &[0, 2, 4], &[1, 3, 4], &[0, 1, 2, 3, 4]] {
            let post = try_claim(&pre, &claim_of(&pre, &leaves, 0, Some(attest5(&leaves, signers)))).expect("3-of-5");
            let l2 = post.l2_settlement().unwrap();
            assert!(l2.claimed().contains(0) && l2.escrow_conserved());
            assert_eq!(post.balance_sat(&[1; 32]), pre.balance_sat(&[1; 32]) + u128::from(100 * BLCH));
        }
    }

    #[test]
    fn a_synchronous_activation_settles_but_refuses_deposits_and_claims() {
        let (opened, _) = activated_fixture(false, [0; 32]);
        let fee = opened.next_base_fee();
        let mut st = opened.clone();
        assert!(st.apply_transaction(&PosTransaction::L2Deposit(deposit_tx(&opened, 7 * BLCH)), 0, fee, &ToyVerifier).is_err());
        assert_eq!(st, opened);
        let leaves = [([1; 32], BLCH)];
        assert_eq!(
            try_claim(&opened, &claim_of(&opened, &leaves, 0, None)).map(|_| ()),
            Err(TxReject::L2WithdrawClaim(ClaimReject::NotActive))
        );
        // V3 settlements with user transactions are admitted (with DA).
        let settlement = to_v3(transaction(&opened), no_deposits(), 2);
        let ready_state = ready(&opened, &settlement);
        let mut admitted = ready_state.clone();
        admitted
            .apply_transaction(&PosTransaction::L2Settlement(Box::new(settlement)), 0, 1, &ProofDouble)
            .expect("user transactions settle on the activated L2 on every build");
    }

    /// Bind `state` to a header carrying its root, cache it and restore it.
    #[cfg(feature = "local-state-cache")]
    fn local_cache_round_trip(state: &CommittedState) -> (CommittedState, Vec<u8>, crate::header::BlockHeaderV4) {
        let mut state = state.clone();
        let header = crate::header::BlockHeaderV4 {
            version: BLOCK_VERSION_V4, parent: [0; 32], state_root: state.compute_root(),
            body_root: [0; 32], slot: state.slot, proposer_index: 0,
            randao_reveal: [0; 32], randao_mix: state.randao_mix,
            justified_root: [0; 32], finalized_root: [0; 32],
            attestation_root: [0; 32], coherence_root: [0; 32],
        };
        state.head = header.id();
        let bytes = state.encode_local_cache().unwrap();
        let restored = CommittedState::decode_local_cache(&bytes, &header).expect("cached state restores");
        assert_eq!(restored, state);
        assert_eq!(restored.state_root(), state.state_root());
        (state, bytes, header)
    }

    /// The restart cache carries the L2 settlement component as an optional
    /// trailing section: states without L2 (every network before the
    /// activation epoch) keep their exact bytes, and a node holding L2 (after
    /// activation, or on a devnet) restores it instead of replaying.
    #[test]
    #[cfg(feature = "local-state-cache")]
    fn local_cache_carries_l2_state_and_keeps_pre_activation_bytes() {
        // Before activation: the pre-L2 encoding, byte for byte.
        let (pre, _, _) = funded_running_without_l2();
        let (pre, bytes, header) = local_cache_round_trip(&pre);
        assert_eq!(bytes, pre.encode_local_cache_owned_reference().unwrap(), "pre-activation cache bytes are unchanged");
        let marker: &[u8] = b"BPOSST01:L2:v1";
        assert!(!bytes.windows(marker.len()).any(|w| w == marker));
        let mut trailing = bytes.clone(); trailing.push(0);
        assert!(CommittedState::decode_local_cache(&trailing, &header).is_err());

        // The flag-day state, then a state with an inbox, DA, a settled head,
        // retained withdrawals, a claim and a release window.
        let (opened, mut chains) = activated_fixture(true, [0; 32]);
        let (opened, opened_bytes, opened_header) = local_cache_round_trip(&opened);
        assert_eq!(&opened_bytes[..], {
            let mut base = opened.clone();
            base.l2_settlement = None;
            let mut expected = base.encode_local_cache().unwrap();
            assert_eq!(expected, base.encode_local_cache_owned_reference().unwrap());
            expected.extend_from_slice(&opened_bytes[expected.len()..]);
            expected
        }.as_slice(), "the L2 section only appends");
        assert!(opened_bytes.windows(marker.len()).any(|w| w == marker));
        let restored = CommittedState::decode_local_cache(&opened_bytes, &opened_header).unwrap();
        assert!(restored.l2_settlement().unwrap().profile().is_activated());
        // A cache without its L2 section, or with garbage after it, is refused.
        let mut without = opened.clone();
        without.l2_settlement = None;
        assert!(CommittedState::decode_local_cache(&without.encode_local_cache().unwrap(), &opened_header).is_err());
        let mut garbage = opened_bytes.clone(); garbage.push(0);
        assert!(CommittedState::decode_local_cache(&garbage, &opened_header).is_err());
        let mut bad_marker = opened_bytes.clone();
        let at = bad_marker.windows(marker.len()).position(|w| w == marker).unwrap();
        bad_marker[at] ^= 1;
        assert!(CommittedState::decode_local_cache(&bad_marker, &opened_header).is_err());
        assert!(CommittedState::decode_local_cache(&opened_bytes[..opened_bytes.len() - 1], &opened_header).is_err());

        let deposit = deposit_tx(&opened, 70 * BLCH);
        let deposit_wire = PosTransaction::L2Deposit(deposit.clone());
        let mut slot = opened.slot + 1;
        let s2 = apply(&opened, slot, std::slice::from_ref(&deposit_wire), &mut chains).unwrap();
        slot += 1;
        let payload = batch(&[&[0x02, 0xc0], b"second"]);
        let da = da_tx(&s2, (deposit_wire.txid(), 0), deposit.change.value, 1, payload.clone());
        let s3 = apply(&s2, slot, &[PosTransaction::L2DataAvailability(da)], &mut chains).unwrap();
        slot += 1;
        let first = PosTransaction::L2SettlementAsync(Box::new(v3_with_da(&s3, da::commitment(700771, 1, &payload))));
        let s4 = apply(&s3, slot, &[first], &mut chains).unwrap();
        assert!(!s3.l2_settlement().unwrap().data_availability().is_empty());
        let l2 = s4.l2_settlement().unwrap();
        assert!(!l2.inbox().is_empty() && l2.settled_number() == 1);
        let (_, s4_bytes, s4_header) = local_cache_round_trip(&s4);
        // A cache of another L2 state under this header fails the root check.
        let (_, s3_bytes, _) = local_cache_round_trip(&s3);
        assert!(CommittedState::decode_local_cache(&s3_bytes, &s4_header).is_err());
        assert_ne!(s3_bytes, s4_bytes);

        // Withdrawals, a paid claim and a release window: see the end of
        // `activated_l2_deposits_settles_user_transactions_and_pays_claims`.

        // A development (manifest genesis) L2 restores with this build's profile.
        let (devnet, _) = fixture_mode(true);
        let (devnet, _, _) = local_cache_round_trip(&devnet);
        assert_eq!(devnet.l2_settlement().unwrap().profile(), &Profile::development());
    }

    /// Qualification builds only: the gate is the compiled epoch, and the
    /// rehearsal policy binds whatever development network runs it.
    #[test]
    #[cfg(feature = "l2-activation-rehearsal")]
    fn rehearsal_build_arms_the_compiled_epoch_for_any_network() {
        let e = crate::params::L2_SETTLEMENT_ACTIVATION_EPOCH;
        assert!(e != u64::MAX && crate::params::l2_settlement_active(e) && !crate::params::l2_settlement_active(e - 1));
        let a = crate::l2_settlement::activation_for(Some([0x93; 32])).unwrap();
        assert!(a.valid() && a.asynchronous && a.policy.identities[0] == [0x93; 32]);
        assert!(crate::l2_settlement::activation_for(None).is_none());
    }
}
