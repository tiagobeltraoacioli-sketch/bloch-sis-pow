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
    /// all remaining value back as change, signing as its maximum surcharge the
    /// ceiling one price tier deeper than the queue `pre` shows (a wallet's
    /// default headroom); the unused part comes back as the refund output.
    fn forced_tx(pre: &CommittedState, outpoint: ([u8; 32], u32), value: u64, env: Vec<u8>, gas: u64) -> L2ForcedTransaction {
        let key = depositor();
        let mut tx = L2ForcedTransaction {
            network_domain: [0x91; 32],
            funding_pubkey: key.clone(),
            inputs: vec![crate::transition::FundingInput { txid: outpoint.0, vout: outpoint.1 }],
            l2_chain_id: 700771,
            gas_limit: gas,
            max_surcharge_sat: 0,
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
            .map_or(0, |q| q.pending_weight());
        tx.max_surcharge_sat = forced::surcharge_ceiling_sat(pending + forced::SURCHARGE_DOUBLING, gas).unwrap_or(0);
        let charge = fee_market::charge(fee_market::TxClass::Eutxo { inputs: 1 }, tx.tx_bytes, pre.next_base_fee(), 0);
        tx.change.value = (u128::from(value)
            - charge.base_fee_sat
            - charge.priority_fee_sat
            - u128::from(tx.max_surcharge_sat)) as u64;
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
        // Only the next program's configuration may be listed.
        assert!(mainnet::FORCED_INCLUSION_CONFIGURATIONS.iter().all(|c| *c == mainnet::PROGRAM_NEXT.identities[0]));
        let listed = !mainnet::FORCED_INCLUSION_CONFIGURATIONS.is_empty();
        // The mainnet L2 before the swap never runs it; after the swap it does
        // exactly when the next configuration is listed (the gate is inert, so
        // no compiled boundary calls this today).
        let mut l2 = mainnet_l2_state();
        assert!(!l2.forced_inclusion_program());
        assert!(!l2.enable_forced_inclusion());
        assert!(l2.forced_queue().is_none());
        l2.replace_program_for_test(&mainnet::PROGRAM_NEXT);
        assert_eq!(l2.forced_inclusion_program(), listed);
        assert_eq!(l2.enable_forced_inclusion(), listed && l2.user_transactions() && l2.asynchronous());
        // The fallback keeps the next rules; it implements forced inclusion only
        // if its configuration is listed (it is since agent 216's guest, so a
        // rollback may be armed with forced inclusion).
        l2.replace_program_for_test(&mainnet::PROGRAM_FALLBACK);
        assert!(l2.next_program_active());
        assert_eq!(
            l2.forced_inclusion_program(),
            mainnet::FORCED_INCLUSION_CONFIGURATIONS.contains(&mainnet::PROGRAM_FALLBACK.identities[0])
        );
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
        // Fees: inputs = change + base fee + tip + the signed maximum surcharge.
        // The charged surcharge goes to the treasury, the rest back to the payer.
        assert!(s2.eutxos.get(&([0x33; 32], 0)).is_none());
        let charge = fee_market::charge(fee_market::TxClass::Eutxo { inputs: 1 }, tx.tx_bytes, opened.next_base_fee(), 0);
        let change = s2.eutxos.get(&(wire.txid(), 0)).unwrap();
        assert_eq!(
            u128::from(change.value),
            u128::from(FUNDED) - charge.base_fee_sat - u128::from(tx.max_surcharge_sat)
        );
        // 60k declared gas is 3 weight units: 3 * 1000 sat on an empty queue.
        let charged = 3 * forced::BASE_SURCHARGE_SAT;
        let treasury = s2.eutxos.get(&(wire.txid(), crate::transition::l2_forced::TREASURY_VOUT)).unwrap();
        assert_eq!((treasury.value, treasury.script_hash), (charged, forced::treasury_test::TREASURY));
        let refund = s2.eutxos.get(&(wire.txid(), crate::transition::l2_forced::REFUND_VOUT)).unwrap();
        assert_eq!((refund.value, refund.script_hash), (tx.max_surcharge_sat - charged, script_of(&depositor())));
        assert!(tx.max_surcharge_sat > charged);
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

        // Weight: a record's share of a settlement, ceil(gas * 14 / 300k).
        assert_eq!((forced::weight(21_000), forced::weight(21_001), forced::weight(forced::MAX_GAS)), (1, 1, 14));
        assert_eq!((forced::weight(21_429), forced::weight(150_001), forced::weight(100_001)), (2, 8, 5));
        // The unit price doubles every 24 positions; the queue holds 256 units.
        assert_eq!(forced::surcharge_sat(0, 1), Some(1_000));
        assert_eq!(forced::surcharge_sat(23, 1), Some(1_000));
        assert_eq!(forced::surcharge_sat(24, 1), Some(2_000));
        assert_eq!(forced::surcharge_sat(24, 14), Some(28_000));
        // Each unit at its own position: 23 at 1_000, then 13 at 2_000.
        assert_eq!(forced::surcharge_sat(23, 14), Some(1_000 + 13 * 2_000));
        assert_eq!(forced::surcharge_sat(255, 1), Some(1_000 << 10));
        assert_eq!(forced::surcharge_sat(256, 1), None);
        assert_eq!(forced::surcharge_sat(243, 14), None, "a large record must fit whole");
        assert_eq!(forced::surcharge_sat(0, 0), None);
        let mut roots = std::collections::BTreeSet::new();
        for i in 0..forced::MAX_PENDING_WEIGHT {
            let txid = [i as u8; 32];
            l2.queue_forced(MAINNET_CHAIN_ID, txid, &envelope(i as u8), forced::MIN_GAS).unwrap();
            assert!(roots.insert(l2.forced_queue().unwrap().root()));
        }
        assert_eq!(l2.queue_forced(MAINNET_CHAIN_ID, [0xee; 32], &envelope(0), 21_000), Err(R::Full));
        let queue = l2.forced_queue().unwrap();
        assert_eq!(queue.pending_weight(), forced::MAX_PENDING_WEIGHT);
        assert_ne!(l2.committed_bytes(), start);
        // Large records fill it in settlement-sized steps: 18 of 300k are
        // 252 units, four transfers fit, then it is full.
        let mut large = mainnet_l2_state();
        assert!(large.enable_forced_inclusion_for_test());
        for i in 0..18u8 {
            large.queue_forced(MAINNET_CHAIN_ID, [i; 32], &envelope(i), forced::MAX_GAS).unwrap();
        }
        assert_eq!(large.forced_queue().unwrap().pending_weight(), 252);
        assert_eq!(large.queue_forced(MAINNET_CHAIN_ID, [18; 32], &envelope(18), forced::MAX_GAS), Err(R::Full));
        for i in 19..23u8 {
            large.queue_forced(MAINNET_CHAIN_ID, [i; 32], &envelope(i), forced::MIN_GAS).unwrap();
        }
        assert_eq!(large.queue_forced(MAINNET_CHAIN_ID, [23; 32], &envelope(23), forced::MIN_GAS), Err(R::Full));
        // At the gas cap: one 300k record per settlement, from the front.
        assert_eq!(large.forced_queue().unwrap().due().len(), 1);
        assert_eq!(large.forced_queue().unwrap().due()[0].l1_txid, [0; 32]);
        // Small records: the record cap binds first; mixed: the gas cap does.
        let mut small = mainnet_l2_state();
        assert!(small.enable_forced_inclusion_for_test());
        for i in 0..20u8 {
            small.queue_forced(MAINNET_CHAIN_ID, [i; 32], &envelope(i), 21_000).unwrap();
        }
        // 14 * 21k = 294k fits, a 15th would cross 300k.
        assert_eq!(small.forced_queue().unwrap().due().len(), 14);
        let mut mixed = mainnet_l2_state();
        assert!(mixed.enable_forced_inclusion_for_test());
        for (i, gas) in [100_000u64, 150_000, 60_000, 21_000].into_iter().enumerate() {
            mixed.queue_forced(MAINNET_CHAIN_ID, [i as u8; 32], &envelope(i as u8), gas).unwrap();
        }
        // 100k + 150k fit; 60k would cross; the 21k behind it waits too (order is kept).
        assert_eq!(mixed.forced_queue().unwrap().due().len(), 2);
        // Proving work one settlement can be forced to do is bounded by the gas cap.
        assert!(forced::MAX_GAS <= forced::MAX_GAS_PER_SETTLEMENT);
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
        cases.push(("gas high", resign(L2ForcedTransaction { gas_limit: forced::MAX_GAS + 1, ..base.clone() }), ForcedReject::Shape));
        cases.push(("empty", resign(L2ForcedTransaction { envelope: vec![], ..base.clone() }), ForcedReject::Shape));
        let mut short = base.clone();
        short.tx_bytes -= 1;
        cases.push(("size", resign(short), ForcedReject::UnderdeclaredSize));
        // Paying the fee without funding the signed maximum breaks conservation.
        let mut cheap = base.clone();
        cheap.change.value += forced::BASE_SURCHARGE_SAT;
        cases.push(("surcharge", resign(cheap), ForcedReject::Conservation));
        // A signed maximum below what the queue charges is refused (the payer
        // re-signs; nothing is taken).
        let mut low = base.clone();
        let charged = pre.l2_settlement().unwrap().forced_queue().unwrap().surcharge_for(low.gas_limit).unwrap();
        low.change.value += low.max_surcharge_sat - (charged - 1);
        low.max_surcharge_sat = charged - 1;
        cases.push(("maximum", resign(low), ForcedReject::SurchargeAboveMax));
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
        // Without a treasury nothing is charged and nothing is queued.
        {
            let _unset = forced::treasury_test::unset();
            let mut st = pre.clone();
            assert_eq!(
                st.apply_transaction(&PosTransaction::L2ForcedTransaction(base.clone()), 0, pre.next_base_fee(), &ToyVerifier),
                Err(TxReject::L2ForcedTransaction(ForcedReject::NotActive))
            );
            assert_eq!(st, pre);
            let (fresh, _) = activated_fixture(true, [0; 32]);
            assert!(!fresh.l2_settlement().unwrap().clone().enable_forced_inclusion_for_test(), "never enabled");
        }
        // An exact maximum leaves no refund output.
        let mut exact = base.clone();
        let charged = pre.l2_settlement().unwrap().forced_queue().unwrap().surcharge_for(exact.gas_limit).unwrap();
        exact.change.value += exact.max_surcharge_sat - charged;
        exact.max_surcharge_sat = charged;
        let exact = resign(exact);
        let mut st = pre.clone();
        let wire = PosTransaction::L2ForcedTransaction(exact);
        st.apply_transaction(&wire, 0, pre.next_base_fee(), &ToyVerifier).expect("exact maximum");
        assert!(st.eutxos.get(&(wire.txid(), crate::transition::l2_forced::REFUND_VOUT)).is_none());
        assert_eq!(st.eutxos.get(&(wire.txid(), crate::transition::l2_forced::TREASURY_VOUT)).unwrap().value, charged);
        // An oversized envelope does not even decode.
        let mut big = base.clone();
        big.envelope = vec![0; forced::MAX_ENVELOPE_BYTES + 1];
        assert!(PosTransaction::from_canonical_bytes(&PosTransaction::L2ForcedTransaction(big).canonical_bytes()).is_err());
        let mut st = pre.clone();
        assert!(st.apply_transaction(&PosTransaction::L2ForcedTransaction(base), 0, pre.next_base_fee(), &ToyVerifier).is_ok());
    }

    /// A V3 statement for `l2`'s frozen source and head, built from the
    /// state alone (the `transaction` + `settlement` + `to_v3` fixtures).
    fn statement_on(l2: &crate::l2_settlement::State, inbox: [u8; 32], salt: u8) -> Transaction {
        let source = l2.frozen_source().expect("anchored");
        let mut s = TEMPLATE.to_vec();
        for (i, id) in l2.policy().identities.iter().enumerate() {
            s[S + i * 32..S + (i + 1) * 32].copy_from_slice(id);
        }
        s[S + 256..S + 264].copy_from_slice(&l2.policy().chain_id.to_be_bytes());
        for (offset, value) in [(400, source.block), (448, source.commitment), (480, source.inbox_root)] {
            s[S + offset..S + offset + 32].copy_from_slice(&value);
        }
        s[S + 432..S + 440].copy_from_slice(&source.slot.to_be_bytes());
        s[S + 440..S + 448].copy_from_slice(&source.height.to_be_bytes());
        let end = source.inbox_count.min(l2.consumed() + crate::l2_settlement::MAX_INBOX_PER_SETTLEMENT);
        s[S + 512..S + 520].copy_from_slice(&source.inbox_count.to_be_bytes());
        s[S + 520..S + 528].copy_from_slice(&l2.consumed().to_be_bytes());
        s[S + 528..S + 536].copy_from_slice(&end.to_be_bytes());
        if let Some((digest, old)) = l2.head() {
            s[S + 224..S + 256].copy_from_slice(&digest);
            let number = u64::from_be_bytes(old[S + 264..S + 272].try_into().unwrap()) + 1;
            s[S + 264..S + 272].copy_from_slice(&number.to_be_bytes());
            s[S + 272..S + 304].copy_from_slice(&old[S + 336..S + 368]);
            s[S + 304..S + 336].copy_from_slice(&old[S + 368..S + 400]);
        }
        s[S + 336] ^= salt; // a distinct header per settlement
        let tx = Transaction { proof_policy: l2.policy().proof_policy, statement: s, proof: [1; 356] };
        to_v3(tx, inbox, 0)
    }

    /// Agent 66's griefing, at the transition: a third party lands one block
    /// every `window` native blocks (one finality window on mainnet) and the
    /// sequencer lands none. A forced transaction, submitted at any offset in
    /// the window, is consumed by the second settlement after it, never later:
    /// latency in `window..2*window` blocks. The griefer that tries to leave it
    /// out is refused every time. Twenty at once drain 16 + 4.
    #[test]
    fn under_griefing_a_forced_transaction_lands_within_two_settlement_intervals() {
        let (_, policy) = running_without_l2();
        let window = 8u64;
        let mut worst = 0;
        for submit in window + 1..=3 * window {
            for burst in [1u64, 20] {
                let mut l2 = crate::l2_settlement::State::activated(activation(policy.clone(), true)).unwrap();
                assert!(l2.enable_forced_inclusion_for_test());
                let mut landed: Vec<(u64, u64)> = Vec::new();
                let mut settlements = 0u8;
                for h in 1..=8 * window {
                    l2.advance_height().unwrap();
                    l2.prepare_source(Keccak256::digest(h.to_be_bytes()).into(), h);
                    if h == submit {
                        for i in 0..burst {
                            l2.queue_forced(700771, [i as u8; 32], &envelope(i as u8), 21_000).unwrap();
                        }
                    }
                    if h % window != 0 {
                        continue;
                    }
                    let due = l2.forced_queue().unwrap().due().to_vec();
                    let consumed_before = l2.forced_queue().unwrap().consumed();
                    settlements += 1;
                    if !due.is_empty() {
                        let omit = statement_on(&l2, no_deposits(), settlements);
                        assert_eq!(l2.clone().apply(&omit, [0; 32], 0, true, &ProofDouble), Err(Reject::Forced));
                    }
                    let good = statement_on(&l2, forced::inbox_hash(no_deposits(), &due), settlements);
                    l2.apply(&good, [0; 32], 0, true, &ProofDouble).expect("the griefer's block settles");
                    let consumed = l2.forced_queue().unwrap().consumed();
                    for index in consumed_before..consumed {
                        landed.push((index, h));
                    }
                }
                assert_eq!(landed.len() as u64, burst, "submit {submit} burst {burst}");
                let first = landed[0].1 - submit;
                assert!((window..2 * window).contains(&first), "submit {submit}: {first} blocks");
                let last = landed.last().unwrap().1 - submit;
                // 20 transfers are 420k declared gas: 14 in the first due settlement, 6 in the next.
                let bound = if burst > 1 { 3 * window } else { 2 * window };
                assert!(last < bound, "submit {submit} burst {burst}: {last} blocks");
                worst = worst.max(last);
            }
        }
        assert_eq!(worst, 3 * window - 1);
    }

    #[test]
    fn a_head_reset_queues_again_what_later_settlements_consumed() {
        let (opened, mut chains) = activated_fixture(true, [0; 32]);
        let opened = enabled(opened);
        let mut slot = crate::params::SLOTS_PER_EPOCH + 1;
        let mut next = |pre: &CommittedState, txs: &[PosTransaction], chains: &mut Vec<RandaoChain>| {
            let post = apply(pre, slot, txs, chains);
            slot += 1;
            post
        };
        let tx = forced_tx(&opened, ([0x33; 32], 0), FUNDED, envelope(7), 60_000);
        let s2 = next(&opened, &[PosTransaction::L2ForcedTransaction(tx)], &mut chains).unwrap();
        let record = s2.l2_settlement().unwrap().forced_queue().unwrap().pending()[0];
        // Block 1 settles on the earlier anchor; block 2 consumes the record.
        let s3 = next(&s2, &[PosTransaction::L2SettlementAsync(Box::new(statement_with_inbox(&s2, no_deposits())))], &mut chains)
            .unwrap();
        let (kept_commitment, kept_statement) = s3.l2_settlement().unwrap().head().unwrap();
        let s4 = next(&s3, &[], &mut chains).unwrap();
        let good = statement_with_inbox(&s4, forced::inbox_hash(no_deposits(), &[record]));
        let s5 = next(&s4, &[PosTransaction::L2SettlementAsync(Box::new(good))], &mut chains).unwrap();
        let queue = s5.l2_settlement().unwrap().forced_queue().unwrap();
        assert_eq!((queue.consumed(), queue.pending().len()), (1, 0));
        assert_eq!(queue.consumed_log(), &[(2, record)]);

        // A head reset back to block 1 puts the record back, as the inbox cursor goes back.
        let reset = mainnet::HeadReset { number: 1, commitment: kept_commitment, statement: Some(leaked_hex(&kept_statement)) };
        let mut reset_state = s5.clone();
        let root = reset_state.l2_settlement().unwrap().forced_queue().unwrap().root();
        assert!(reset_state.l2_settlement.as_mut().unwrap().reset_head(&reset));
        let queue = reset_state.l2_settlement().unwrap().forced_queue().unwrap();
        assert_eq!(reset_state.l2_settlement().unwrap().settled_number(), 1);
        assert_eq!((queue.queued(), queue.consumed(), queue.pending()), (1, 0, &[record][..]));
        assert!(queue.consumed_log().is_empty());
        assert_eq!(queue.root(), root, "nothing new was queued");
        assert_ne!(reset_state.state_root(), s5.state_root());

        // The next block 2 must consume it again: omission is refused, inclusion settles.
        let s6 = next(&reset_state, &[], &mut chains).unwrap();
        assert_eq!(s6.l2_settlement().unwrap().forced_queue().unwrap().due(), &[record]);
        let mut l2 = s6.l2_settlement().unwrap().clone();
        assert_eq!(
            l2.apply(&statement_with_inbox(&s6, no_deposits()), *s6.head.as_bytes(), s6.slot, true, &ProofDouble),
            Err(Reject::Forced)
        );
        let again = statement_with_inbox(&s6, forced::inbox_hash(no_deposits(), &[record]));
        let s7 = next(&s6, &[PosTransaction::L2SettlementAsync(Box::new(again))], &mut chains).expect("consumed again");
        let queue = s7.l2_settlement().unwrap().forced_queue().unwrap();
        assert_eq!(s7.l2_settlement().unwrap().settled_number(), 2);
        assert_eq!((queue.queued(), queue.consumed(), queue.pending().len()), (1, 1, 0));
        #[cfg(feature = "local-state-cache")]
        for state in [&reset_state, &s6, &s7] {
            let (restored, _, _) = local_cache_round_trip(state);
            assert_eq!(restored.l2_settlement().unwrap().forced_queue(), state.l2_settlement().unwrap().forced_queue());
        }
    }

    #[test]
    fn a_head_reset_deeper_than_the_consumed_log_is_refused() {
        let record = |i: u64| forced::Record { height: i, l1_txid: [i as u8; 32], envelope_hash: [0x5a; 32], gas_limit: 21_000 };
        // Unit level: the log keeps the newest CONSUMED_LOG records.
        let mut queue = forced::Queue::new();
        let mut number = 0u64;
        let mut i = 0u64;
        while queue.covers_reset_to(0) {
            number += 1;
            for _ in 0..14 {
                i += 1;
                queue.push(record(i)).unwrap();
            }
            queue.consume_due(number);
            assert!(queue.consumed_log().len() <= forced::CONSUMED_LOG);
            assert!(number < 200);
        }
        let floor = queue.log_floor;
        assert!(floor >= 1 && queue.consumed_log()[0].0 >= floor);
        assert!(queue.covers_reset_to(floor) && !queue.covers_reset_to(floor - 1));
        let mut copy = queue.clone();
        assert_eq!(copy.requeue_after(floor - 1), None);
        assert_eq!(copy, queue, "a refused re-queue changes nothing");
        let back = copy.requeue_after(number - 1).unwrap();
        assert_eq!(back, 14);
        assert_eq!(copy.pending().len(), 14);
        assert_eq!(copy.consumed(), queue.consumed() - 14);
        assert_eq!(copy.pending()[0], record(i - 13), "original order");

        // State level: a reset below the log floor keeps the head.
        let mut l2 = state_with_bad_tail();
        assert!(l2.enable_forced_inclusion_for_test());
        let q = l2.forced_queue_mut_for_test().unwrap();
        for n in 1..=7u64 {
            for _ in 0..14 {
                i += 1;
                q.push(record(i)).unwrap();
            }
            q.consume_due(n);
        }
        // Drop the old entries as a long history would.
        let keep = q.consumed_log().iter().filter(|(n, _)| *n >= 5).count();
        while q.consumed_log().len() > keep {
            let (n, _) = q.log.remove(0);
            q.log_floor = q.log_floor.max(n);
        }
        let deep = statement_at(&l2, 3, [0xaa; 32], 2);
        let refused = mainnet::HeadReset { number: 3, commitment: [3; 32], statement: Some(leaked_hex(&deep)) };
        let before = l2.clone();
        assert!(!l2.reset_head(&refused));
        assert_eq!(l2, before);
        let shallow = statement_at(&l2, 6, [0xbb; 32], 5);
        let applied = mainnet::HeadReset { number: 6, commitment: [6; 32], statement: Some(leaked_hex(&shallow)) };
        assert!(l2.reset_head(&applied));
        assert_eq!(l2.settled_number(), 6);
        let q = l2.forced_queue().unwrap();
        assert_eq!(q.pending().len(), 14, "the records block 7 consumed are due again");
        assert!(q.consumed_log().iter().all(|(n, _)| *n <= 6));
    }

    // ── Agent 215 (round 11): decided changes R3-R6 of review 164 ─────────

    fn record_n(i: u64, gas: u64) -> forced::Record {
        forced::Record { height: i, l1_txid: Keccak256::digest(i.to_be_bytes()).into(), envelope_hash: [0x5a; 32], gas_limit: gas }
    }

    /// A small deterministic generator for adversarial gas sequences.
    fn lcg(seed: &mut u64) -> u64 {
        *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        *seed >> 33
    }

    /// R3: every record is consumed by the `ceil(p / 14)`-th settlement after
    /// it, where `p` is the queue position its record ends at, whatever the
    /// sizes and the mix, and with a filler topping the queue up between
    /// settlements. So a full queue drains in at most 19 settlements.
    #[test]
    fn every_record_lands_within_its_position_bound_whatever_the_mix() {
        let patterns: Vec<(&str, Vec<u64>)> = vec![
            ("transfers", vec![forced::MIN_GAS]),
            ("150_001", vec![150_001]),
            ("100_001", vec![100_001]),
            ("300k", vec![forced::MAX_GAS]),
            ("small then large", vec![forced::MIN_GAS, 290_000]),
            ("odd shares", vec![21_429, 280_000, 42_858]),
            ("half and a transfer", vec![150_001, forced::MIN_GAS, 150_001]),
        ];
        let mut seeds: Vec<(String, Vec<u64>)> = patterns.into_iter().map(|(n, p)| (n.to_string(), p)).collect();
        for seed in 0..24u64 {
            let mut s = seed;
            let gas = (0..64).map(|_| forced::MIN_GAS + lcg(&mut s) % (forced::MAX_GAS - forced::MIN_GAS + 1)).collect();
            seeds.push((format!("random {seed}"), gas));
        }
        let mut worst_drain = 0u64;
        for (name, pattern) in &seeds {
            for refill in [false, true] {
                let mut queue = forced::Queue::new();
                let mut next = 0usize;
                let mut i = 0u64;
                // (record, the settlement index it must land by)
                let mut bounds: Vec<(forced::Record, u64)> = Vec::new();
                let mut push_all = |queue: &mut forced::Queue, settled: u64, bounds: &mut Vec<(forced::Record, u64)>| {
                    loop {
                        let gas = pattern[next % pattern.len()];
                        let record = record_n(i, gas);
                        if queue.push(record).is_err() {
                            break;
                        }
                        next += 1;
                        i += 1;
                        let end = queue.pending_weight();
                        bounds.push((record, settled + end.div_ceil(forced::UNITS_PER_SETTLEMENT)));
                    }
                };
                push_all(&mut queue, 0, &mut bounds);
                assert!(queue.pending_weight() <= forced::MAX_PENDING_WEIGHT);
                let initial = bounds.len();
                let mut settled = 0u64;
                while !queue.pending().is_empty() {
                    settled += 1;
                    let due: Vec<forced::Record> = queue.due().to_vec();
                    assert!(!due.is_empty(), "{name}: progress");
                    queue.consume_due(settled);
                    for r in &due {
                        let (_, bound) = bounds.iter().find(|(b, _)| b == r).unwrap();
                        assert!(settled <= *bound, "{name} refill {refill}: record {} landed in {settled}, bound {bound}", r.height);
                    }
                    if refill && settled < 60 {
                        push_all(&mut queue, settled, &mut bounds);
                    }
                    if !refill {
                        assert!(settled <= forced::MAX_DRAIN_SETTLEMENTS, "{name}: {settled} settlements");
                    }
                    assert!(settled < 200);
                }
                if !refill {
                    worst_drain = worst_drain.max(settled);
                    assert!(initial > 0);
                }
            }
        }
        assert!(worst_drain <= forced::MAX_DRAIN_SETTLEMENTS);
        assert_eq!(worst_drain, forced::MAX_DRAIN_SETTLEMENTS, "transfers reach the bound");
    }

    /// R6 arithmetic: what keeping the queue full costs per settlement, for
    /// the filler's best pattern, against 1_024_000 sat before (review 164:
    /// 8 units x 128_000 with 150_001-gas records). The surcharge is paid to
    /// the treasury.
    #[test]
    fn keeping_the_queue_full_costs_about_ten_times_more_than_before() {
        let hold = |pattern: &[u64]| -> (u64, u64) {
            let mut queue = forced::Queue::new();
            let mut i = 0u64;
            let mut fill = |queue: &mut forced::Queue| -> u64 {
                let mut paid = 0;
                loop {
                    let gas = pattern[i as usize % pattern.len()];
                    let Some(s) = queue.surcharge_for(gas) else { break };
                    queue.push(record_n(i, gas)).unwrap();
                    paid += s;
                    i += 1;
                }
                paid
            };
            let first = fill(&mut queue);
            // Steady state: the cheapest of the later rounds, summed over two
            // settlements (a mixed pattern alternates group sizes).
            let mut rounds = Vec::new();
            for n in 1..=12 {
                queue.consume_due(n);
                rounds.push(fill(&mut queue));
            }
            let per_two = rounds.windows(2).skip(4).map(|w| w[0] + w[1]).min().unwrap();
            (first, per_two / 2)
        };
        let (fill_transfers, transfers) = hold(&[forced::MIN_GAS]);
        assert_eq!(fill_transfers, 24_000 * ((1 << 10) - 1) + 16 * 1_024_000, "40_936_000 sat from empty");
        assert_eq!(transfers, 14 * 1_024_000);
        let (_, half) = hold(&[150_001]);
        assert_eq!(half, 8 * 512_000 + 6 * 1_024_000);
        let before = 8 * 128_000u64;
        let mut cheapest = u64::MAX;
        for pattern in [&[forced::MIN_GAS][..], &[150_001], &[100_001], &[forced::MAX_GAS], &[60_001], &[forced::MIN_GAS, 290_000], &[21_429, 280_000]] {
            let (_, per) = hold(pattern);
            cheapest = cheapest.min(per);
        }
        assert_eq!(cheapest, 10_240_000, "the filler's cheapest full hold");
        assert_eq!(cheapest / before, 10);
    }

    /// R5 and R4: each unit is priced at its own position, a record pays for
    /// the room it leaves in the group it closes, and the signed ceiling covers
    /// every charge up to the depth it was computed for.
    #[test]
    fn records_pay_for_their_own_positions_and_the_ceiling_covers_them() {
        // A record that closes a group pays for the room it leaves.
        let mut queue = forced::Queue::new();
        queue.push(record_n(0, forced::MIN_GAS)).unwrap();
        assert_eq!(queue.pending_weight(), 1);
        assert_eq!(queue.charged_weight(290_000), (1, 13 + 14), "13 units of room plus its own 14");
        assert_eq!(queue.charged_weight(forced::MIN_GAS), (1, 1));
        assert_eq!(forced::MAX_CHARGED_WEIGHT, 27);
        // Each unit at its own position, never the entry tier only.
        for p in 0..forced::MAX_PENDING_WEIGHT {
            for w in 1..=forced::MAX_CHARGED_WEIGHT {
                let one_by_one: Option<u64> = (p..p + w).map(|u| forced::surcharge_sat(u, 1)).sum();
                assert_eq!(forced::surcharge_sat(p, w), one_by_one, "{p} {w}");
            }
        }
        // The ceiling at depth d covers any record of that gas at any queue
        // whose position is at most d.
        let mut seed = 7u64;
        for _ in 0..400 {
            let mut queue = forced::Queue::new();
            let mut i = 0;
            let target = lcg(&mut seed) % forced::MAX_PENDING_WEIGHT;
            while queue.pending_weight() < target {
                let gas = forced::MIN_GAS + lcg(&mut seed) % (forced::MAX_GAS - forced::MIN_GAS + 1);
                if queue.push(record_n(i, gas)).is_err() {
                    break;
                }
                i += 1;
            }
            let depth = queue.pending_weight();
            for gas in [forced::MIN_GAS, 21_429, 60_001, 150_001, forced::MAX_GAS] {
                if let Some(charged) = queue.surcharge_for(gas) {
                    for headroom in [0, forced::SURCHARGE_DOUBLING] {
                        assert!(charged <= forced::surcharge_ceiling_sat(depth + headroom, gas).unwrap(), "{depth} {gas}");
                    }
                }
            }
        }
        assert_eq!(forced::surcharge_ceiling_sat(0, 20_999), None);
        assert_eq!(forced::surcharge_ceiling_sat(0, forced::MIN_GAS), Some(14 * 1_000));
        assert_eq!(forced::surcharge_ceiling_sat(u64::MAX, forced::MAX_GAS), forced::surcharge_sat(229, 27));
    }

    /// Pricing golden vector, mirrored by bloch-l2-evm
    /// `deployment/mainnet/test_l2_monitor.py` (`FORCED_PRICING_VECTOR`).
    #[test]
    fn forced_pricing_matches_the_golden_vector() {
        let got: Vec<(u64, u64, u64)> = FORCED_PRICING_VECTOR
            .iter()
            .map(|&(p, w, _)| (p, w, forced::surcharge_sat(p, w).unwrap()))
            .collect();
        assert_eq!(got, FORCED_PRICING_VECTOR);
        let weights: Vec<u64> = [21_000, 21_429, 60_000, 100_001, 150_001, 300_000].iter().map(|g| forced::weight(*g)).collect();
        assert_eq!(weights, [1, 2, 3, 5, 8, 14]);
        assert_eq!(
            (forced::UNITS_PER_SETTLEMENT, forced::MAX_PENDING_WEIGHT, forced::SURCHARGE_DOUBLING, forced::MAX_DRAIN_SETTLEMENTS),
            (14, 256, 24, 19)
        );
    }
    const FORCED_PRICING_VECTOR: &[(u64, u64, u64)] = &[
        (0, 1, 1_000),
        (0, 14, 14_000),
        (23, 14, 27_000),
        (100, 3, 48_000),
        (232, 14, 10_240_000),
        (242, 14, 14_336_000),
        (229, 27, 22_016_000),
        (255, 1, 1_024_000),
    ];

    /// R1 closed (agent 216): the fallback guest implements forced inclusion,
    /// so its configuration is the listed next one and a rollback keeps the
    /// queue working: records queued before the rollback stay due and new ones
    /// are taken. The run-time refusal for an unlisted fallback stays in place
    /// for any later pin that would drop the rule (the compile-time assert
    /// in `mainnet` now forbids such a pin).
    #[test]
    fn the_listed_fallback_keeps_taking_forced_records() {
        let mut l2 = mainnet_l2_state();
        l2.replace_program_for_test(&mainnet::PROGRAM_NEXT);
        assert!(l2.enable_forced_inclusion_for_test());
        l2.queue_forced(MAINNET_CHAIN_ID, [1; 32], &envelope(1), forced::MIN_GAS).unwrap();
        l2.replace_program_for_test(&mainnet::PROGRAM_FALLBACK);
        assert_eq!(mainnet::PROGRAM_FALLBACK.identities[0], mainnet::PROGRAM_NEXT.identities[0]);
        assert!(l2.forced_inclusion_program());
        assert!(l2.next_program_active());
        let before = l2.clone();
        l2.queue_forced(MAINNET_CHAIN_ID, [2; 32], &envelope(2), forced::MIN_GAS).unwrap();
        assert_ne!(l2, before);
    }
