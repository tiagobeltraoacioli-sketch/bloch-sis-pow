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
        assert_eq!(tx.canonical_bytes()[0], 0x0f);
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
}
