    // ── Independent review of forced inclusion (agent 164, round 10) ──────
    //
    // Included from `l2_settlement_tests.rs` after `l2_forced_tests.rs`, so it
    // reuses that file's fixtures (`envelope`, `forced_tx`, `enabled`,
    // `statement_on`). Each `review_*` test states a property the design claims
    // or needs; the ones that fail on 3533cd56 are the findings in
    // agents/164-forced-review.md.

    /// R1 (rollback). The rollback swaps the program to `PROGRAM_FALLBACK`.
    /// Forced inclusion stays enabled, so the fallback must be a guest that
    /// publishes `inbox_hash`, or one forced submission halts settlement for
    /// the price of one L1 transaction. Agent 216's fallback guest implements
    /// the rule and carries the listed next configuration, so after the
    /// rollback the queue keeps working and every due record stays provable.
    /// (Originally agent 164's test asserted the refusal for an unlisted
    /// fallback; that run-time guard stays in `queue_forced` for any later pin.)
    #[test]
    fn review_after_a_rollback_the_fallback_still_implements_forced_inclusion() {
        let mut l2 = mainnet_l2_state();
        l2.replace_program_for_test(&mainnet::PROGRAM_NEXT);
        assert!(l2.enable_forced_inclusion_for_test());
        // Rollback; the reset is refused (nothing settled) but the program moves.
        let reset = mainnet::HeadReset { number: 5, commitment: [5; 32], statement: None };
        l2.install_fallback_with_for_test(&reset);
        assert_eq!(program_of(&l2), mainnet::PROGRAM_FALLBACK.identities);
        assert!(l2.forced_inclusion_program(), "the fallback is listed: it executes forced records");
        assert_eq!(mainnet::PROGRAM_FALLBACK.identities[0], mainnet::PROGRAM_NEXT.identities[0]);
        assert_eq!(l2.queue_forced(MAINNET_CHAIN_ID, [7; 32], &envelope(7), forced::MIN_GAS), Ok(()));
    }

    /// R1, at the arming rule: an armed rollback under armed forced inclusion
    /// must require the fallback's configuration to be listed as well. The rule
    /// on 3533cd56 only looks at the swap, so this combination compiles.
    #[test]
    fn review_the_arming_rule_considers_the_rollback() {
        let fallback_listed =
            mainnet::FORCED_INCLUSION_CONFIGURATIONS.contains(&mainnet::PROGRAM_FALLBACK.identities[0]);
        // forced = next = 10_060 with a listed next program, rollback armed at
        // 10_100 and an unlisted fallback: the current rule says yes.
        let allowed = crate::hard_forks::l2_forced_inclusion_may_arm(10_060, 10_060, true);
        assert!(
            !allowed || fallback_listed,
            "l2_forced_inclusion_may_arm ignores L2_PROGRAM_ROLLBACK_EPOCH and the fallback's listing"
        );
    }

    /// R2 (head reset). `reset_head` moves the inbox cursor back so discarded
    /// deposits mint again, but forced records consumed by the discarded blocks
    /// were drained from the queue and are never owed again: the user paid the
    /// L1 fee and the surcharge and the transaction is silently dropped.
    #[test]
    fn review_a_head_reset_owes_again_the_forced_records_of_discarded_blocks() {
        let (_, policy) = running_without_l2();
        let mut l2 = crate::l2_settlement::State::activated(activation(policy, true)).unwrap();
        assert!(l2.enable_forced_inclusion_for_test());
        l2.advance_height().unwrap();
        l2.queue_forced(700771, [9; 32], &envelope(9), forced::MIN_GAS).unwrap();
        l2.prepare_source(Keccak256::digest(b"h1").into(), 1);
        let due = l2.forced_queue().unwrap().due().to_vec();
        assert_eq!(due.len(), 1);
        let good = statement_on(&l2, forced::inbox_hash(no_deposits(), &due), 1);
        l2.apply(&good, [0; 32], 0, true, &ProofDouble).expect("block 1 consumes the record");
        assert_eq!(l2.settled_number(), 1);
        assert!(l2.forced_queue().unwrap().pending().is_empty());
        // Discard block 1: back to the L2 genesis.
        let reset = mainnet::HeadReset { number: 0, commitment: [0; 32], statement: None };
        assert!(l2.reset_head(&reset), "the reset applies");
        assert_eq!(l2.settled_number(), 0);
        let queue = l2.forced_queue().unwrap();
        assert_eq!(
            queue.pending().to_vec(),
            due,
            "the record consumed only by the discarded block is lost: queued {}, consumed {}, pending {}",
            queue.queued(),
            queue.consumed(),
            queue.pending().len()
        );
    }

    /// R3 (drain rate). The design note says weighting by gas "makes the drain
    /// rate, at most MAX_GAS_PER_SETTLEMENT per settlement, the same whatever
    /// record sizes a filler picks". It is not: the due prefix stops before the
    /// record that crosses 300k, so records of 150_001 gas (8 units each) drain
    /// one per settlement, 8 units, against 14 for transfers. A queue filled
    /// with them takes 32 settlements to drain, not ceil(256 / 14) = 19, and a
    /// keeper refills it at 8 top-tier units per settlement.
    #[test]
    fn review_a_full_queue_drains_at_the_transfer_rate_whatever_the_record_sizes() {
        let transfers_per_settlement = forced::MAX_GAS_PER_SETTLEMENT / forced::MIN_GAS; // 14
        let bound = forced::MAX_PENDING_WEIGHT.div_ceil(transfers_per_settlement); // 19
        let mut worst = (0u64, 0u64);
        for gas in [forced::MIN_GAS, 21_001, 100_001, 150_001, forced::MAX_GAS] {
            let mut l2 = mainnet_l2_state();
            assert!(l2.enable_forced_inclusion_for_test());
            let mut i = 0u32;
            while l2.queue_forced(MAINNET_CHAIN_ID, Keccak256::digest(i.to_be_bytes()).into(), &envelope(i as u8), gas).is_ok() {
                i += 1;
            }
            let mut settlements = 0u64;
            while !l2.forced_queue().unwrap().pending().is_empty() {
                l2.forced_consume_due_for_review();
                settlements += 1;
            }
            if settlements > worst.1 {
                worst = (gas, settlements);
            }
        }
        assert!(
            worst.1 <= bound,
            "a full queue of {}-gas records takes {} settlements to drain (bound {bound})",
            worst.0,
            worst.1
        );
    }

    /// R4 (exact conservation x depth price). A forced transaction pays the
    /// surcharge of the depth it finds, with exact conservation, so it is valid
    /// at one price tier only. One weight unit queued ahead of it (1_000 sat)
    /// at a tier boundary, or a settlement that drains the queue across one,
    /// invalidates every signed forced transaction in flight.
    #[test]
    fn review_a_signed_forced_transaction_survives_one_record_queued_ahead_of_it() {
        let (opened, _) = activated_fixture(true, [0; 32]);
        let mut pre = enabled(opened);
        let chain = pre.l2_settlement().unwrap().policy().chain_id;
        for i in 0..forced::SURCHARGE_DOUBLING - 1 {
            let l2 = pre.l2_settlement.as_mut().unwrap();
            l2.queue_forced(chain, [i as u8; 32], &envelope(i as u8), forced::MIN_GAS).unwrap();
        }
        // Adapted (agent 215): the tier boundary is SURCHARGE_DOUBLING (24 after R6), not 32.
        assert_eq!(pre.l2_settlement().unwrap().forced_queue().unwrap().pending_weight(), forced::SURCHARGE_DOUBLING - 1);
        let honest = forced_tx(&pre, ([0x33; 32], 0), FUNDED, envelope(0xaa), forced::MIN_GAS);
        // A griefer's single transfer-size record lands first in the same block.
        let mut st = pre.clone();
        st.l2_settlement.as_mut().unwrap().queue_forced(chain, [0xee; 32], &envelope(0xee), forced::MIN_GAS).unwrap();
        let result = st.apply_transaction(&PosTransaction::L2ForcedTransaction(honest), 0, pre.next_base_fee(), &ToyVerifier);
        assert!(result.is_ok(), "the honest forced transaction is invalidated by one record ahead of it: {result:?}");
    }

    /// R5 (pricing by entry depth). A record of `w` units pays `w` times the
    /// unit price at the depth it finds, so one 15-unit record entered at depth
    /// 31 pays 15_000 sat for units that, queued one by one, cost 29_000.
    /// Filling the queue with large records at tier boundaries is cheaper than
    /// the ladder suggests.
    #[test]
    fn review_the_surcharge_prices_every_unit_at_its_own_depth() {
        // Adapted (agent 215): the tier boundary moved from 32 to 24 (R6), so the
        // window starts at SURCHARGE_DOUBLING - 1 instead of 31; same literal.
        let at = forced::SURCHARGE_DOUBLING - 1;
        let one_by_one: u64 = (at..at + 15).map(|p| forced::surcharge_sat(p, 1).unwrap()).sum();
        assert_eq!(one_by_one, 1_000 + 14 * 2_000);
        assert_eq!(
            forced::surcharge_sat(at, 15),
            Some(one_by_one),
            "a large record skips the tier it crosses"
        );
    }

    /// Positive checks that hold on 3533cd56 (kept as regression tests).
    #[test]
    fn review_positive_properties_hold() {
        // Inert gate: the sentinel never activates, at any epoch.
        for epoch in [0, 1, 7_360, 8_620, 10_060, u64::MAX - 1, u64::MAX] {
            assert!(!crate::params::epoch_gate_active(epoch, crate::params::L2_FORCED_INCLUSION_EPOCH));
        }
        // Surcharge never overflows and the full queue is refused.
        for p in 0..=forced::MAX_PENDING_WEIGHT {
            for w in 1..=forced::weight(forced::MAX_GAS) {
                if let Some(s) = forced::surcharge_sat(p, w) {
                    assert!(p + w <= forced::MAX_PENDING_WEIGHT);
                    // Adapted (agent 215): the top tier is 2^10 after R6 and a record
                    // can be charged up to MAX_CHARGED_WEIGHT units (room it closes).
                    assert!(s <= forced::unit_price_sat(forced::MAX_PENDING_WEIGHT - 1) * forced::MAX_CHARGED_WEIGHT);
                }
            }
        }
        // Progress: whatever is pending at the anchor, at least one record is due.
        let mut l2 = mainnet_l2_state();
        assert!(l2.enable_forced_inclusion_for_test());
        l2.queue_forced(MAINNET_CHAIN_ID, [1; 32], &envelope(1), forced::MAX_GAS).unwrap();
        assert_eq!(l2.forced_queue().unwrap().due().len(), 1);
        // The record cap never binds before the gas cap (16 * 21k > 300k).
        assert!(forced::MAX_PER_SETTLEMENT * forced::MIN_GAS > forced::MAX_GAS_PER_SETTLEMENT);
        // The largest wire encoding fits a block.
        assert!(
            crate::transition::l2_forced::MAX_L2_FORCED_TRANSACTION_BYTES as u64
                <= fee_market::BLOCK_TX_BYTES_TARGET
        );
    }
