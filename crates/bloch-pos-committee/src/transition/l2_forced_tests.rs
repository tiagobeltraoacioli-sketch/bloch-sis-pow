    // ── L1 forced inclusion of L2 transactions (candidate, inert) ─────────
    //
    // Included from `l2_settlement_tests.rs`, inside `mod l2_tests`, so it uses
    // that module's fixtures (`activated_fixture`, `settlement`, `to_v3`, ...).

    use crate::l2_settlement::{forced, MAINNET_CHAIN_ID};
    use sha3::Keccak256;
    use crate::transition::l2_forced::{L2ForcedTransaction, L2ForcedTransactionReject as ForcedReject};

    /// A minimal legacy-looking L2 envelope; L1 never parses it.
    fn envelope(tag: u8) -> Vec<u8> {
        vec![0xf8, 0x6c, tag, 0x01, 0x02, 0x03]
    }

    /// A signed forced transaction spending `coin` (value, at `outpoint`) with
    /// all remaining value back as change, at the surcharge `pre` asks for.
    fn forced_tx(pre: &CommittedState, outpoint: ([u8; 32], u32), value: u64, env: Vec<u8>, gas: u64) -> L2ForcedTransaction {
        let key = depositor();
        let mut tx = L2ForcedTransaction {
            network_domain: [0x91; 32],
            funding_pubkey: key.clone(),
            inputs: vec![crate::transition::FundingInput { txid: outpoint.0, vout: outpoint.1 }],
            l2_chain_id: 700771,
            gas_limit: gas,
            envelope: env,
            change: TransferOutput { value: 0, script_hash: script_of(&key) },
            tx_bytes: 0,
            tip_millisat_per_gas: 0,
            signature: vec![0; 32],
        };
        tx.tx_bytes = tx.canonical_bytes().len() as u64;
        let pending = pre
            .l2_settlement()
            .and_then(|l2| l2.forced_queue())
            .map_or(0, |q| q.pending().len() as u64);
        let surcharge = forced::surcharge_sat(pending).unwrap_or(0);
        let charge = fee_market::charge(fee_market::TxClass::Eutxo { inputs: 1 }, tx.tx_bytes, pre.next_base_fee(), 0);
        tx.change.value =
            (u128::from(value) - charge.base_fee_sat - charge.priority_fee_sat - u128::from(surcharge)) as u64;
        tx.signature = toy_sign(&key, &tx.intent_root());
        tx
    }

    fn enabled(mut state: CommittedState) -> CommittedState {
        assert!(state.l2_settlement.as_mut().unwrap().enable_forced_inclusion_for_test());
        state
    }

    fn statement_with_inbox(pre: &CommittedState, inbox: [u8; 32]) -> Transaction {
        let empty = crate::l2_settlement::expected_body_commitment(&[]);
        to_v3(settlement(pre, empty), inbox, 0)
    }

    #[test]
    fn forced_inclusion_gate_ships_inert_and_no_program_implements_it() {
        assert_eq!(crate::params::L2_FORCED_INCLUSION_EPOCH, u64::MAX);
        assert!(!crate::params::l2_forced_inclusion_active(u64::MAX - 1));
        assert!(mainnet::FORCED_INCLUSION_CONFIGURATIONS.is_empty());
        // The mainnet L2, before and after the program swap: never enabled.
        let mut l2 = mainnet_l2_state();
        assert!(!l2.forced_inclusion_program());
        assert!(!l2.enable_forced_inclusion());
        l2.replace_program_for_test(&mainnet::PROGRAM_NEXT);
        assert!(!l2.enable_forced_inclusion());
        assert!(l2.forced_queue().is_none());
    }

    #[test]
    fn while_inert_the_wire_is_refused_and_the_boundary_keeps_the_root() {
        let (opened, mut chains) = activated_fixture(true, [0; 32]);
        assert!(opened.l2_settlement().unwrap().forced_queue().is_none());
        let tx = forced_tx(&opened, ([0x33; 32], 0), FUNDED, envelope(1), 21_000);
        let wire = PosTransaction::L2ForcedTransaction(tx);
        let bytes = wire.canonical_bytes();
        assert_eq!(bytes[0], 0x1C);
        assert_eq!(PosTransaction::from_canonical_bytes(&bytes).unwrap(), wire);
        let mut st = opened.clone();
        assert_eq!(
            st.apply_transaction(&wire, 0, opened.next_base_fee(), &ToyVerifier),
            Err(TxReject::L2ForcedTransaction(ForcedReject::NotActive))
        );
        assert_eq!(st, opened);

        // An epoch boundary with the gate open but no listed configuration
        // installs nothing: the root equals the one with the gate closed.
        // RANDAO chains are spent by use, so the second run takes an identical fixture.
        let at = 2 * crate::params::SLOTS_PER_EPOCH;
        let closed = apply(&opened, at, &[], &mut chains).unwrap();
        let (twin, mut twin_chains) = activated_fixture(true, [0; 32]);
        assert_eq!(twin, opened);
        let open = {
            let _gate = crate::params::l2_forced_inclusion_test::open();
            apply(&twin, at, &[], &mut twin_chains).unwrap()
        };
        assert!(open.l2_settlement().unwrap().forced_queue().is_none());
        assert_eq!(open.state_root(), closed.state_root());
    }

    #[test]
    fn a_forced_transaction_is_queued_and_every_later_settlement_must_consume_it() {
        let (opened, mut chains) = activated_fixture(true, [0; 32]);
        let opened = enabled(opened);
        assert_ne!(opened.state_root(), activated_fixture(true, [0; 32]).0.state_root(), "the queue is committed");
        let mut slot = crate::params::SLOTS_PER_EPOCH + 1;
        let mut next = |pre: &CommittedState, txs: &[PosTransaction], chains: &mut Vec<RandaoChain>| {
            let post = apply(pre, slot, txs, chains);
            slot += 1;
            post
        };

        // Block 2: the anchor freezes before the forced transaction lands.
        let tx = forced_tx(&opened, ([0x33; 32], 0), FUNDED, envelope(7), 60_000);
        let wire = PosTransaction::L2ForcedTransaction(tx.clone());
        let s2 = next(&opened, std::slice::from_ref(&wire), &mut chains).expect("forced transaction applies");
        let queue = s2.l2_settlement().unwrap().forced_queue().unwrap().clone();
        assert_eq!((queue.queued(), queue.consumed(), queue.pending().len()), (1, 0, 1));
        let record = queue.pending()[0];
        assert_eq!(record.height, s2.l2_settlement().unwrap().height());
        assert_eq!(record.l1_txid, wire.txid());
        assert_eq!(record.envelope_hash, <[u8; 32]>::from(Keccak256::digest(envelope(7))));
        assert_eq!(record.gas_limit, 60_000);
        assert!(queue.due().is_empty(), "frozen before it landed");
        // Fees: inputs = change + base fee + tip + the burned surcharge.
        assert!(s2.eutxos.get(&([0x33; 32], 0)).is_none());
        let charge = fee_market::charge(fee_market::TxClass::Eutxo { inputs: 1 }, tx.tx_bytes, opened.next_base_fee(), 0);
        assert_eq!(
            u128::from(s2.eutxos.get(&(wire.txid(), 0)).unwrap().value),
            u128::from(FUNDED) - charge.base_fee_sat - u128::from(forced::BASE_SURCHARGE_SAT)
        );
        // Replay: the input is gone.
        let mut replay = s2.clone();
        assert_eq!(
            replay.apply_transaction(&wire, 0, s2.next_base_fee(), &ToyVerifier),
            Err(TxReject::L2ForcedTransaction(ForcedReject::MissingInput))
        );

        // Block 3: the settlement in flight on the earlier anchor owes nothing.
        let plain = statement_with_inbox(&s2, no_deposits());
        let s3 = next(&s2, &[PosTransaction::L2SettlementAsync(Box::new(plain))], &mut chains).expect("settles");
        assert_eq!(s3.l2_settlement().unwrap().forced_queue().unwrap().pending().len(), 1);

        // Block 4 freezes a new anchor: the record is now due.
        let s4 = next(&s3, &[], &mut chains).unwrap();
        let due = s4.l2_settlement().unwrap().forced_queue().unwrap().due().to_vec();
        assert_eq!(due, vec![record]);
        let expected = forced::inbox_hash(no_deposits(), &due);
        assert_ne!(expected, no_deposits());

        // Any settler that leaves it out is refused, before the proof.
        for omitted in [statement_with_inbox(&s4, no_deposits()), statement_with_inbox(&s4, [0x66; 32])] {
            let mut l2 = s4.l2_settlement().unwrap().clone();
            assert_eq!(l2.apply(&omitted, *s4.head.as_bytes(), s4.slot, true, &ProofDouble), Err(Reject::Forced));
            assert_eq!(&l2, s4.l2_settlement().unwrap());
            assert_eq!(
                l2.apply(&omitted, *s4.head.as_bytes(), s4.slot, true, &ToyVerifier),
                Err(Reject::Forced),
                "checked before the proof"
            );
        }
        // The statement that consumes it settles, and the queue drains.
        let good = statement_with_inbox(&s4, expected);
        let s5 = next(&s4, &[PosTransaction::L2SettlementAsync(Box::new(good))], &mut chains).expect("consumes the queue");
        let queue = s5.l2_settlement().unwrap().forced_queue().unwrap();
        assert_eq!((queue.queued(), queue.consumed(), queue.pending().len()), (1, 1, 0));
        assert_eq!(s5.l2_settlement().unwrap().settled_number(), 2);
        // With nothing due the slot is the plain deposits hash again.
        let s6 = next(&s5, &[], &mut chains).unwrap();
        let after = statement_with_inbox(&s6, no_deposits());
        let s7 = next(&s6, &[PosTransaction::L2SettlementAsync(Box::new(after))], &mut chains).expect("plain again");
        assert_eq!(s7.l2_settlement().unwrap().settled_number(), 3);
        // The restart cache carries the queue in its own section, and only once enabled.
        #[cfg(feature = "local-state-cache")]
        {
            let marker = crate::wire_alloc::local_cache::L2_FORCED;
            for state in [&s2, &s4, &s7] {
                let (_, bytes, _) = local_cache_round_trip(state);
                assert!(bytes.windows(16).any(|w| w == marker));
            }
            let (_, bytes, _) = local_cache_round_trip(&activated_fixture(true, [0; 32]).0);
            assert!(!bytes.windows(16).any(|w| w == marker), "absent while not enabled");
        }
    }

    #[test]
    fn deposits_and_forced_records_are_bound_together() {
        let (opened, mut chains) = activated_fixture(true, [0; 32]);
        let opened = enabled(opened);
        let mut slot = crate::params::SLOTS_PER_EPOCH + 1;
        let mut next = |pre: &CommittedState, txs: &[PosTransaction], chains: &mut Vec<RandaoChain>| {
            let post = apply(pre, slot, txs, chains);
            slot += 1;
            post
        };
        // A deposit, then a forced transaction, both after the anchor froze.
        let deposit = deposit_tx(&opened, 5 * BLCH);
        let deposit_wire = PosTransaction::L2Deposit(deposit.clone());
        let s2 = next(&opened, std::slice::from_ref(&deposit_wire), &mut chains).unwrap();
        let tx = forced_tx(&s2, (deposit_wire.txid(), 0), deposit.change.value, envelope(9), 21_000);
        let s3 = next(&s2, &[PosTransaction::L2ForcedTransaction(tx)], &mut chains).unwrap();
        // The settlement in flight owes neither.
        let first = statement_with_inbox(&s3, no_deposits());
        let s4 = next(&s3, &[PosTransaction::L2SettlementAsync(Box::new(first))], &mut chains).expect("settles");
        // The next anchor owes both: the deposit and the forced record.
        let s5 = next(&s4, &[], &mut chains).unwrap();
        let record = s5.l2_settlement().unwrap().inbox()[0];
        let due = s5.l2_settlement().unwrap().forced_queue().unwrap().due().to_vec();
        assert_eq!(due.len(), 1);
        let deposits = crate::l2_settlement::deposits_hash(&[record]);
        let mut l2 = s5.l2_settlement().unwrap().clone();
        for (name, wrong) in [
            ("deposits only", deposits),
            ("forced without the deposit", forced::inbox_hash(no_deposits(), &due)),
            ("forced hash alone", forced::hash(&due)),
        ] {
            let tx = statement_with_inbox(&s5, wrong);
            assert_eq!(l2.apply(&tx, *s5.head.as_bytes(), s5.slot, true, &ProofDouble), Err(Reject::Forced), "{name}");
        }
        let good = statement_with_inbox(&s5, forced::inbox_hash(deposits, &due));
        assert_eq!(l2.apply(&good, *s5.head.as_bytes(), s5.slot, true, &ProofDouble), Ok(()));
        assert_eq!((l2.consumed(), l2.forced_queue().unwrap().consumed()), (1, 1));
    }

    #[test]
    fn the_queue_is_bounded_priced_by_depth_and_capped_per_settlement() {
        let mut l2 = mainnet_l2_state();
        assert!(l2.enable_forced_inclusion_for_test());
        let start = l2.committed_bytes();
        // Shape and chain refusals never queue.
        use forced::Refusal as R;
        assert_eq!(l2.queue_forced(1, [1; 32], &envelope(1), 21_000), Err(R::Chain));
        for gas in [0, forced::MIN_GAS - 1, forced::MAX_GAS + 1, u64::MAX] {
            assert_eq!(l2.queue_forced(MAINNET_CHAIN_ID, [1; 32], &envelope(1), gas), Err(R::Shape), "{gas}");
        }
        assert_eq!(l2.queue_forced(MAINNET_CHAIN_ID, [1; 32], &[], 21_000), Err(R::Shape));
        let big = vec![0u8; forced::MAX_ENVELOPE_BYTES + 1];
        assert_eq!(l2.queue_forced(MAINNET_CHAIN_ID, [1; 32], &big, 21_000), Err(R::Shape));
        assert_eq!(l2.committed_bytes(), start);

        // The surcharge doubles every 32 pending records; the queue holds 256.
        assert_eq!(forced::surcharge_sat(0), Some(1_000));
        assert_eq!(forced::surcharge_sat(31), Some(1_000));
        assert_eq!(forced::surcharge_sat(32), Some(2_000));
        assert_eq!(forced::surcharge_sat(255), Some(1_000 << 7));
        assert_eq!(forced::surcharge_sat(256), None);
        let mut roots = std::collections::BTreeSet::new();
        for i in 0..forced::MAX_PENDING {
            let txid = [i as u8; 32];
            l2.queue_forced(MAINNET_CHAIN_ID, txid, &envelope(i as u8), forced::MAX_GAS).unwrap();
            assert!(roots.insert(l2.forced_queue().unwrap().root()));
        }
        assert_eq!(l2.queue_forced(MAINNET_CHAIN_ID, [0xee; 32], &envelope(0), 21_000), Err(R::Full));
        let queue = l2.forced_queue().unwrap();
        assert_eq!(queue.pending().len() as u64, forced::MAX_PENDING);
        // One settlement owes at most 16, from the front, in order.
        assert_eq!(queue.due().len() as u64, forced::MAX_PER_SETTLEMENT);
        assert_eq!(queue.due()[0].l1_txid, [0; 32]);
        assert_eq!(queue.due()[15].l1_txid, [15; 32]);
        // Proving work one settlement can be forced to do is bounded.
        assert!(forced::MAX_PER_SETTLEMENT * forced::MAX_GAS <= 8_000_000);
        assert_ne!(l2.committed_bytes(), start);
    }

    #[test]
    fn forced_hash_matches_the_l2_golden_vector() {
        let record = forced::Record {
            height: 7,
            l1_txid: [0x11; 32],
            envelope_hash: [0x22; 32],
            gas_limit: 21_000,
        };
        let hex = |b: [u8; 32]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let empty: [u8; 32] = Keccak256::digest([]).into();
        assert_eq!(forced::hash(&[]), empty);
        assert_eq!(forced::inbox_hash([0x33; 32], &[]), [0x33; 32]);
        assert_eq!(hex(forced::hash(&[record])), FORCED_HASH_VECTOR);
        assert_eq!(hex(forced::inbox_hash(empty, &[record])), INBOX_HASH_VECTOR);
    }
    /// Shared with bloch-l2-evm `forced_inclusion_golden_vector`.
    const FORCED_HASH_VECTOR: &str = "3209df24b99a7f67b3f05d26d89b51fc199a2c2cb2ed89b9677fba958f52e099";
    const INBOX_HASH_VECTOR: &str = "364cbe02ac69f9eb79d5b5e2dd5dd0fde2f3d80b7ed81ae0e587cef4d785fea3";

    #[test]
    fn more_than_four_forced_transactions_in_one_block_are_refused() {
        let (opened, mut chains) = activated_fixture(true, [0; 32]);
        let pre = enabled(opened);
        let mut state = pre.clone();
        let mut txs = Vec::new();
        let mut coin = (([0x33; 32], 0), FUNDED);
        for i in 0..=forced::MAX_PER_BLOCK as u8 {
            // Each one's surcharge follows the queue it finds.
            let tx = forced_tx(&state, coin.0, coin.1, envelope(i), 21_000);
            let wire = PosTransaction::L2ForcedTransaction(tx.clone());
            state.apply_transaction(&wire, 0, pre.next_base_fee(), &ToyVerifier).expect("applies alone");
            coin = ((wire.txid(), 0), tx.change.value);
            txs.push(wire);
        }
        let slot = crate::params::SLOTS_PER_EPOCH + 1;
        let t = Transition::new(ToyVerifier);
        let mut block = build_block(&t, &pre, slot, &[], &[], &mut chains);
        block.header.body_root =
            crate::derive::body_root(&txs.iter().map(PosTransaction::canonical_bytes).collect::<Vec<_>>());
        let pk = crate::attestation::KeyLookup::pubkey(&pre, block.header.proposer_index).unwrap();
        block.proposer_sig = toy_sign(pk, &block.header.proposal_signing_root());
        assert_eq!(t.compute_post_state(&pre, &block, &[], &txs), Err(TransitionError::BlockGasLimitExceeded));
        // RANDAO chains are spent by use: the accepted block runs on an identical fixture.
        let (twin, mut twin_chains) = activated_fixture(true, [0; 32]);
        let twin = enabled(twin);
        assert_eq!(twin, pre);
        let four = apply(&twin, slot, &txs[..forced::MAX_PER_BLOCK], &mut twin_chains).expect("four fit");
        assert_eq!(four.l2_settlement().unwrap().forced_queue().unwrap().pending().len(), forced::MAX_PER_BLOCK);
    }

    #[test]
    fn invalid_forced_transactions_are_refused_without_mutation() {
        let (opened, _) = activated_fixture(true, [0; 32]);
        let pre = enabled(opened);
        let base = forced_tx(&pre, ([0x33; 32], 0), FUNDED, envelope(1), 21_000);
        let resign = |mut tx: L2ForcedTransaction| {
            tx.signature = toy_sign(&tx.funding_pubkey, &tx.intent_root());
            tx
        };
        let mut cases: Vec<(&str, L2ForcedTransaction, ForcedReject)> = Vec::new();
        cases.push(("chain", resign(L2ForcedTransaction { l2_chain_id: 700772, ..base.clone() }), ForcedReject::Chain));
        cases.push(("network", resign(L2ForcedTransaction { network_domain: [0x92; 32], ..base.clone() }), ForcedReject::Network));
        cases.push(("gas low", resign(L2ForcedTransaction { gas_limit: 20_999, ..base.clone() }), ForcedReject::Shape));
        cases.push(("gas high", resign(L2ForcedTransaction { gas_limit: 500_001, ..base.clone() }), ForcedReject::Shape));
        cases.push(("empty", resign(L2ForcedTransaction { envelope: vec![], ..base.clone() }), ForcedReject::Shape));
        let mut short = base.clone();
        short.tx_bytes -= 1;
        cases.push(("size", resign(short), ForcedReject::UnderdeclaredSize));
        // Paying the fee without the surcharge breaks conservation.
        let mut cheap = base.clone();
        cheap.change.value += forced::BASE_SURCHARGE_SAT;
        cases.push(("surcharge", resign(cheap), ForcedReject::Conservation));
        let mut unsigned = base.clone();
        unsigned.signature = vec![1; 32];
        cases.push(("signature", unsigned, ForcedReject::Signature));
        for (name, tx, want) in cases {
            let mut st = pre.clone();
            assert_eq!(
                st.apply_transaction(&PosTransaction::L2ForcedTransaction(tx), 0, pre.next_base_fee(), &ToyVerifier),
                Err(TxReject::L2ForcedTransaction(want)),
                "{name}"
            );
            assert_eq!(st, pre, "{name} mutated state");
        }
        // An oversized envelope does not even decode.
        let mut big = base.clone();
        big.envelope = vec![0; forced::MAX_ENVELOPE_BYTES + 1];
        assert!(PosTransaction::from_canonical_bytes(&PosTransaction::L2ForcedTransaction(big).canonical_bytes()).is_err());
        let mut st = pre.clone();
        assert!(st.apply_transaction(&PosTransaction::L2ForcedTransaction(base), 0, pre.next_base_fee(), &ToyVerifier).is_ok());
    }
