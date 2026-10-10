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
        assert!(s2.accounted_supply_sat() < supply - u128::from(amount) + 1, "escrow leaves spendable supply");
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
}
