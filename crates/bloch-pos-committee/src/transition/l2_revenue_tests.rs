    // ── L2 protocol fee on deposits and claims (candidate, inert) ─────────
    //
    // Included from `l2_settlement_tests.rs`, inside `mod l2_tests`, so it uses
    // that module's fixtures (`activated_fixture`, `claim_tx`, ...). The
    // activated profile admits deposits and claims on every build, so these
    // run without development features.

    use crate::l2_revenue::{self, TREASURY_VOUT};

    const TREASURY: [u8; 32] = [0x7e; 32];

    /// A signed deposit of `amount` from the funded coin, paying `protocol_fee`
    /// on top of the amount and the eUTXO fee; the rest is change.
    fn deposit_paying(pre: &CommittedState, amount: u64, protocol_fee: u64) -> crate::transition::L2Deposit {
        let mut tx = deposit_tx(pre, amount);
        tx.change.value -= protocol_fee;
        tx.signature = toy_sign(&tx.funding_pubkey, &tx.intent_root());
        tx
    }

    /// The activated fixture with `escrow` escrowed and the `n`-leaf vector
    /// tree matured and finalized; the funding coin is untouched.
    fn activated_matured(n: u64, escrow: u64) -> CommittedState {
        let (mut pre, _) = activated_fixture(true, [0; 32]);
        let l2 = pre.l2_settlement.as_mut().unwrap();
        l2.append_deposit(crate::l2_settlement::InboxRecord {
            height: l2.height(), tx_index: 0, txid: [0x77; 32], vout: 1, sats: escrow, recipient: [0x42; 20],
        })
        .unwrap();
        let height = l2.height();
        l2.insert_withdrawal_record(wd::Record { l2_number: 1, root: wd::root(&wleaves(n)), count: n, height });
        let mut steps = 0;
        while l2.matured_count() < n {
            l2.advance_height().unwrap();
            steps += 1;
            assert!(steps < 10_000, "the record never matured");
        }
        finalize_all(&mut pre);
        pre
    }

    #[test]
    fn an_inert_gate_leaves_deposits_and_claims_as_they_were() {
        let (pre, _) = activated_fixture(true, [0; 32]);
        assert_eq!(pre.l2_deposit_protocol_fee(BLCH), None);
        // A stand-in treasury alone changes nothing while the gate is inert.
        let _treasury = l2_revenue::test_treasury::set(TREASURY);
        assert_eq!(pre.l2_deposit_protocol_fee(BLCH), None);
        let tx = PosTransaction::L2Deposit(deposit_tx(&pre, 7_000_000_000));
        let mut post = pre.clone();
        post.apply_transaction(&tx, 0, pre.next_base_fee(), &ToyVerifier).expect("unchanged deposit applies");
        assert!(post.eutxos.get(&(tx.txid(), TREASURY_VOUT)).is_none());
        // A deposit paying a fee nobody asks for breaks conservation.
        let mut state = pre.clone();
        let paying = PosTransaction::L2Deposit(deposit_paying(&pre, 7_000_000_000, l2_revenue::deposit_fee_sat(7_000_000_000)));
        assert!(state.apply_transaction(&paying, 0, pre.next_base_fee(), &ToyVerifier).is_err());
        assert_eq!(state, pre);

        let pre = activated_matured(3, 50_000_000);
        assert_eq!(pre.l2_claim_release_sat(1_000_001), 1_000_001);
        let whole = claim_tx(&pre, ([0x33; 32], 0), FUNDED, 3, 1);
        let mut post = pre.clone();
        post.apply_transaction(&claim(&whole), 0, pre.next_base_fee(), &ToyVerifier).expect("whole release applies");
        assert!(post.eutxos.get(&(claim(&whole).txid(), TREASURY_VOUT)).is_none());
        // The net release passes the state-free door but not the state.
        let mut net = whole.clone();
        net.release.value = l2_revenue::claim_net_sat(net.sats);
        let net = resign_claim(net);
        assert!(net.validate_shape().is_ok());
        assert_eq!(pre.l2_withdraw_claim_refusal(&net), Some(ClaimReject::ReleaseOutput));
    }

    #[test]
    fn an_active_gate_charges_the_deposit_from_the_inputs_and_mints_the_whole_amount() {
        let (pre, mut chains) = activated_fixture(true, [0; 32]);
        let _gate = crate::params::l2_revenue_test::open();
        let _treasury = l2_revenue::test_treasury::set(TREASURY);
        let amount = 7_000_000_000; // 70 BLCH: 5 bps = 0.035 BLCH
        let fee = l2_revenue::deposit_fee_sat(amount);
        assert_eq!(fee, 3_500_000);
        assert_eq!(pre.l2_deposit_protocol_fee(amount), Some((fee, TREASURY)));
        // The pre-fork transaction (no fee) is refused without mutation.
        let mut state = pre.clone();
        let old = PosTransaction::L2Deposit(deposit_tx(&pre, amount));
        assert_eq!(
            state.apply_transaction(&old, 0, pre.next_base_fee(), &ToyVerifier),
            Err(TxReject::L2Deposit(crate::transition::L2DepositReject::Conservation))
        );
        assert_eq!(state, pre);
        // Off by one satoshi either way: refused.
        for wrong in [fee - 1, fee + 1] {
            let mut state = pre.clone();
            let tx = PosTransaction::L2Deposit(deposit_paying(&pre, amount, wrong));
            assert!(state.apply_transaction(&tx, 0, pre.next_base_fee(), &ToyVerifier).is_err(), "{wrong}");
            assert_eq!(state, pre);
        }
        // The fee-paying deposit, in a real block (the transition checks supply).
        let tx = deposit_paying(&pre, amount, fee);
        let wire = PosTransaction::L2Deposit(tx.clone());
        let supply = pre.accounted_supply_sat();
        let post = apply(&pre, crate::params::SLOTS_PER_EPOCH + 1, std::slice::from_ref(&wire), &mut chains)
            .expect("fee-paying deposit applies");
        let l2 = post.l2_settlement().unwrap();
        let record = *l2.inbox().last().unwrap();
        assert_eq!((record.sats, record.recipient), (amount, [0x42; 20]), "the L2 mints the whole amount");
        assert_eq!(l2.escrow_sat(), u128::from(amount));
        let out = post.eutxos.get(&(wire.txid(), TREASURY_VOUT)).expect("treasury output");
        assert_eq!((out.value, out.script_hash), (fee, TREASURY));
        assert_eq!(post.eutxos.get(&(wire.txid(), 0)).unwrap().value, tx.change.value);
        // The fee stays in the supply: only the eUTXO fee left it.
        let charge = fee_market::charge(fee_market::TxClass::Eutxo { inputs: 1 }, tx.tx_bytes, pre.next_base_fee(), 0);
        assert!(supply - post.accounted_supply_sat() <= charge.base_fee_sat + charge.priority_fee_sat);
        assert_eq!(FUNDED as u128, u128::from(amount) + u128::from(fee) + u128::from(tx.change.value) + charge.base_fee_sat + charge.priority_fee_sat);
        assert!(l2.escrow_conserved());
    }

    #[test]
    fn the_smallest_deposit_pays_the_floor() {
        let (pre, _) = activated_fixture(true, [0; 32]);
        let _gate = crate::params::l2_revenue_test::open();
        let _treasury = l2_revenue::test_treasury::set(TREASURY);
        let amount = crate::transition::l2_deposit::MIN_L2_DEPOSIT_SAT;
        let fee = l2_revenue::FEE_FLOOR_SAT;
        let wire = PosTransaction::L2Deposit(deposit_paying(&pre, amount, fee));
        let mut post = pre.clone();
        post.apply_transaction(&wire, 0, pre.next_base_fee(), &ToyVerifier).expect("floor deposit applies");
        assert_eq!(post.eutxos.get(&(wire.txid(), TREASURY_VOUT)).unwrap().value, fee);
        assert_eq!(post.l2_settlement().unwrap().inbox().last().unwrap().sats, amount);
    }

    #[test]
    fn an_active_gate_takes_the_claim_fee_from_the_release_and_frees_the_whole_leaf() {
        let pre = activated_matured(3, 50_000_000);
        let _gate = crate::params::l2_revenue_test::open();
        let _treasury = l2_revenue::test_treasury::set(TREASURY);
        let (recipient, sats) = wleaf(1);
        let fee = l2_revenue::claim_fee_sat(sats);
        assert_eq!(fee, l2_revenue::FEE_FLOOR_SAT);
        assert_eq!(pre.l2_claim_release_sat(sats), sats - fee);
        // The whole release (a pre-fork claim) is refused without mutation.
        let whole = claim_tx(&pre, ([0x33; 32], 0), FUNDED, 3, 1);
        assert_eq!(pre.l2_withdraw_claim_refusal(&whole), Some(ClaimReject::ReleaseOutput));
        let mut state = pre.clone();
        assert!(state.apply_transaction(&claim(&whole), 0, pre.next_base_fee(), &ToyVerifier).is_err());
        assert_eq!(state, pre);
        // Any other value: refused at the state-free door already.
        let mut odd = whole.clone();
        odd.release.value = sats - fee - 1;
        assert_eq!(resign_claim(odd).validate_shape(), Err(ClaimReject::ReleaseOutput));
        // The net release applies.
        let mut net = whole.clone();
        net.release.value = sats - fee;
        let net = resign_claim(net);
        assert_eq!(pre.l2_withdraw_claim_refusal(&net), None);
        let supply = pre.accounted_supply_sat();
        let escrow = pre.l2_settlement().unwrap().escrow_sat();
        let mut post = pre.clone();
        post.apply_transaction(&claim(&net), 0, pre.next_base_fee(), &ToyVerifier).expect("net claim applies");
        let txid = claim(&net).txid();
        let release = post.eutxos.get(&(txid, RELEASE_VOUT)).unwrap();
        assert_eq!((release.value, release.script_hash), (sats - fee, recipient));
        let out = post.eutxos.get(&(txid, TREASURY_VOUT)).expect("treasury output");
        assert_eq!((out.value, out.script_hash), (fee, TREASURY));
        assert_eq!(post.eutxos.get(&(txid, CHANGE_VOUT)).unwrap().value, net.change.value);
        let l2 = post.l2_settlement().unwrap();
        assert_eq!(l2.escrow_sat(), escrow - u128::from(sats), "the escrow frees the whole leaf");
        assert!(l2.claimed().contains(1) && l2.escrow_conserved());
        // Release + fee = the leaf; only the relayer's eUTXO fee left the supply.
        let relayer_fee = u128::from(FUNDED - net.change.value);
        assert_eq!(supply - post.accounted_supply_sat(), relayer_fee);
        // Replay: refused (claimed once).
        let mut replay = post.clone();
        assert!(replay.apply_transaction(&claim(&net), 0, post.next_base_fee(), &ToyVerifier).is_err());
        assert_eq!(replay, post);
    }

    #[test]
    fn a_large_claim_pays_the_cap() {
        assert_eq!(l2_revenue::claim_fee_sat(5_000 * BLCH), l2_revenue::FEE_CAP_SAT);
        assert_eq!(l2_revenue::claim_net_sat(5_000 * BLCH), 5_000 * BLCH - BLCH);
    }

    // ── Review r17 (agent 335): a spend FROM a treasury output ────────────
    //
    // `params::PROTOCOL_TREASURY_SCRIPT_HASH` is a key hash in the carried form
    // (20 bytes of `SHA3-256(pubkey)`, twelve zero bytes). Nothing in the tree
    // spent an output the fee rules create at such a script. This does, with a
    // stand-in key in the same form: the fee output of a deposit is an ordinary
    // eUTXO that the holder of the key moves with a plain transfer, and that
    // nobody else moves.

    fn r335_carried(pubkey: &[u8]) -> [u8; 32] {
        let full = script_of(pubkey);
        let mut out = [0u8; 32];
        out[..20].copy_from_slice(&full[..20]);
        out
    }

    #[test]
    fn r335_a_treasury_output_in_the_carried_form_is_spent_by_its_key_and_by_no_other() {
        let (pre, _) = activated_fixture(true, [0; 32]);
        let _gate = crate::params::l2_revenue_test::open();
        let key = vec![0x7e; crate::transition::funded::ADMISSION_PQ_KEY_BYTES];
        let treasury = r335_carried(&key);
        // The compiled treasury has exactly this shape.
        let compiled = crate::params::PROTOCOL_TREASURY_SCRIPT_HASH.expect("named");
        assert_eq!(compiled[20..], [0u8; 12]);
        assert_eq!(treasury[20..], [0u8; 12]);
        assert_ne!(treasury[..20], [0u8; 20]);
        let _treasury = l2_revenue::test_treasury::set(treasury);

        let amount = 7_000_000_000;
        let fee = l2_revenue::deposit_fee_sat(amount);
        let wire = PosTransaction::L2Deposit(deposit_paying(&pre, amount, fee));
        let mut post = pre.clone();
        post.apply_transaction(&wire, 0, pre.next_base_fee(), &ToyVerifier).expect("fee-paying deposit applies");
        let out = post.eutxos.get(&(wire.txid(), TREASURY_VOUT)).expect("treasury output").clone();
        assert_eq!((out.value, out.script_hash), (fee, treasury));
        let price = post.next_base_fee();

        // Another key: refused before any signature is looked at, state untouched.
        let thief = vec![0x7f; crate::transition::funded::ADMISSION_PQ_KEY_BYTES];
        let steal = transfer_spending(std::slice::from_ref(&out), &thief, script_of(&thief), 0, 0, price);
        let mut state = post.clone();
        assert_eq!(
            state.apply_transaction(&steal, 0, price, &ToyVerifier).map(|_| ()),
            Err(TxReject::Transfer(TransferReject::ScriptMismatch))
        );
        assert_eq!(state, post);

        // The right key with somebody else's signature: refused.
        let mut forged = transfer_spending(std::slice::from_ref(&out), &key, script_of(&thief), 0, 0, price);
        let root = forged.spend_signing_root();
        if let PosTransaction::Transfer { inputs, .. } = &mut forged {
            inputs[0].signature = toy_sign(&thief, &root);
        }
        let mut state = post.clone();
        assert_eq!(
            state.apply_transaction(&forged, 0, price, &ToyVerifier).map(|_| ()),
            Err(TxReject::Transfer(TransferReject::BadSignature))
        );
        assert_eq!(state, post);

        // The holder of the key moves it to a native (32-byte) script of its choice.
        let destination = script_of(b"the treasury's next address");
        let spend = transfer_spending(std::slice::from_ref(&out), &key, destination, 0, 0, price);
        let supply = post.accounted_supply_sat();
        let mut state = post.clone();
        state.apply_transaction(&spend, 0, price, &ToyVerifier).expect("the treasury key spends the treasury output");
        assert!(state.eutxos.get(&(wire.txid(), TREASURY_VOUT)).is_none());
        let moved = state.eutxos.get(&(spend.txid(), 0)).expect("the moved output");
        assert_eq!(moved.script_hash, destination);
        // Only the transfer's own fee left the supply.
        assert_eq!(supply - state.accounted_supply_sat(), u128::from(fee - moved.value));
        assert!(moved.value > fee / 2, "a 0.035 BLCH fee output is worth moving: {} of {fee}", moved.value);
        // A second spend of the same output: gone.
        assert!(state.apply_transaction(&spend, 0, state.next_base_fee(), &ToyVerifier).is_err());
    }

    /// The smallest outputs the two rules create (the crossing-fee floor, 5,000 sat, and the forced-inclusion
    /// surcharge of a plain transfer, 1,000 sat at an empty queue) against the fee of moving ONE output alone
    /// with a real hybrid key and signature at the minimum base fee, and the marginal fee of one more input
    /// under the same key (TransferV2 shares the witness): a measurement for the documents, printed.
    #[test]
    fn r335_what_it_costs_to_move_the_smallest_treasury_outputs() {
        let key_bytes = crate::transition::funded::ADMISSION_PQ_KEY_BYTES as u64;
        let bytes_one = key_bytes + fee_market::HYBRID_SIG_BYTES + 36 + 40 + 40;
        let floor = fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS;
        let one = fee_market::charge(fee_market::TxClass::Eutxo { inputs: 1 }, bytes_one, floor, 0);
        let more = fee_market::charge(fee_market::TxClass::Eutxo { inputs: 1 }, bytes_one + 40, floor, 0);
        let alone = one.base_fee_sat + one.priority_fee_sat;
        let marginal = more.base_fee_sat + more.priority_fee_sat - alone;
        eprintln!(
            "r335: one treasury output alone costs {alone} sat to move at the minimum base fee; one more input under \
             the same key about {marginal} sat; crossing-fee floor {} sat; smallest forced surcharge 1000 sat",
            l2_revenue::FEE_FLOOR_SAT
        );
        assert!(alone > 0 && marginal < alone);
    }
