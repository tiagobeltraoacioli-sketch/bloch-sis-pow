//! Cross-component rehearsal: an independent trader buys the bridge asset and
//! burns only the received output. All source events and funds are test fixtures.
use super::*;
use bloch_euvm::ustav::transfer_wire;
use bloch_pos_committee::transition::native_dex::{
    base_reserves::{reserve_script, RESERVE_KEY_INDEX},
    initial_liquidity, paired_custody, swap, swap_quote,
};

pub(super) fn complete_market_roundtrip(
    anchor: State,
    mut state: State,
    import: joint::Request,
    pair: paired_custody::Request,
    created: paired_custody::Receipt,
) {
    let mut init = initial_liquidity::Request {
        reserve: created.reserve.id,
        creation_authorization: created.authorization,
        fee_bps: 30,
        minimum_lp: 1,
        valid_until: 100,
        blch: sponsor(),
    };
    if let PosTransaction::TransferV2 { inputs, .. } = &mut init.blch {
        inputs[0].txid = created.blch_txid;
        inputs[0].vout = 1;
    }
    let size = init.canonical_bytes(&DOMAIN).unwrap().len() as u64;
    if let PosTransaction::TransferV2 { tx_bytes, .. } = &mut init.blch {
        *tx_bytes = size + 256;
    }
    let fee = state.quote_initial_liquidity(&init).unwrap();
    if let PosTransaction::TransferV2 { outputs, .. } = &mut init.blch {
        outputs[0].value = state.base().utxo(&created.blch_txid, 1).unwrap().value
            - (fee.base_fee_sat + fee.priority_fee_sat) as u64;
    }
    let message = init.authorization(&DOMAIN).unwrap();
    if let PosTransaction::TransferV2 { keys, .. } = &mut init.blch {
        keys[0].signature = sign(0, &message);
    }
    let initialized = state
        .execute_initial_liquidity(&init, 4, &BaseVerifier, &BlochVerifier)
        .unwrap();
    let lp = state.blch_lp_position(&initialized.pool, &keys()[0].0);
    let base = state.base_reserve(&created.reserve.id).unwrap().clone();
    let native = state.paired_custody(&created.reserve.id).unwrap().clone();
    let quote_request = swap_quote::Request {
        domain: DOMAIN,
        pool: initialized.pool,
        revision: state.blch_pool(&initialized.pool).unwrap().revision(),
        input_asset: bloch_euvm::BLCH,
        amount: 100_000,
        minimum_out: 1,
        valid_until: 100,
    };
    let quote = state.quote_blch_swap(&quote_request, 4).unwrap();
    let trader_hash = Sha3_256::digest(&keys()[2].0).into();
    let mut trade = swap::Request {
        quote: quote_request,
        pool_state_root: quote.pool_state_root,
        native_gas: 100_000,
        blch: PosTransaction::TransferV2 {
            keys: vec![WitnessKey {
                pubkey: keys()[2].0.clone(),
                signature: vec![0; 5500],
            }],
            inputs: vec![
                TransferInputV2 {
                    txid: base.outpoint.0,
                    vout: base.outpoint.1,
                    key_index: RESERVE_KEY_INDEX,
                },
                TransferInputV2 {
                    txid: [19; 32],
                    vout: 0,
                    key_index: 0,
                },
            ],
            outputs: vec![
                TransferOutput {
                    value: base.amount + 100_000,
                    script_hash: reserve_script(&DOMAIN, &created.reserve.id),
                },
                TransferOutput {
                    value: 1,
                    script_hash: trader_hash,
                },
            ],
            tx_bytes: 0,
            tip_millisat_per_gas: 2,
        },
        native: transfer_wire::Envelope {
            domain: DOMAIN,
            transaction: Transaction {
                asset: native.asset,
                inputs: vec![native.outpoint],
                outputs: vec![
                    Output {
                        owner: keys()[0].0.clone(),
                        amount: native.amount - quote.amount_out,
                    },
                    Output {
                        owner: keys()[2].0.clone(),
                        amount: quote.amount_out,
                    },
                ],
                delta: 0,
                mint_nonce: 0,
                policy_revision: 0,
                valid_until: 100,
            },
            witnesses: Witnesses {
                owners: vec![vec![]],
                modules: vec![vec![]],
                ..Witnesses::default()
            },
        },
    };
    let size = trade.canonical_bytes(&DOMAIN).unwrap().len() as u64;
    if let PosTransaction::TransferV2 { tx_bytes, .. } = &mut trade.blch {
        *tx_bytes = size + 256;
    }
    let fee = state.quote_blch_swap_fee(&trade).unwrap();
    if let PosTransaction::TransferV2 { outputs, .. } = &mut trade.blch {
        outputs[1].value = COIN - 100_000 - (fee.base_fee_sat + fee.priority_fee_sat) as u64;
    }
    let message = trade.authorization(&DOMAIN).unwrap();
    if let PosTransaction::TransferV2 { keys, .. } = &mut trade.blch {
        keys[0].signature = sign(2, &message);
    }
    let swapped = state
        .execute_blch_swap(&trade, 4, &BaseVerifier, &BlochVerifier)
        .unwrap();
    assert_eq!(swapped.quote.amount_out, quote.amount_out);
    assert_eq!(state.blch_lp_position(&initialized.pool, &keys()[0].0), lp);
    assert_eq!(
        state.native().gateway().native().supply(&native.asset),
        Some(AMOUNT)
    );

    let Operation::Import(original) = &import.gateway.operation else {
        unreachable!()
    };
    let mut burn = joint::Request {
        blch: sponsor(),
        gateway: Envelope {
            domain: DOMAIN,
            operation: Operation::Withdraw(gateway::WithdrawalRequest {
                route: original.deposit.route,
                nonce: 0,
                recipient: [20; 20],
                transaction: Transaction {
                    inputs: vec![swapped.native.outputs[1]],
                    outputs: vec![],
                    delta: -(quote.amount_out as i128),
                    ..original.transaction.clone()
                },
            }),
            witnesses: Witnesses {
                owners: vec![vec![0; 5500]],
                modules: vec![vec![Val::Bytes(vec![0; 5500])]],
                ..Witnesses::default()
            },
            approvals: vec![vec![0; 5500]; 2],
        },
        valid_until: 100,
        native_gas: 100_000,
    };
    if let PosTransaction::TransferV2 {
        keys: witnesses,
        inputs,
        outputs,
        ..
    } = &mut burn.blch
    {
        witnesses[0].pubkey = keys()[2].0.clone();
        inputs[0].txid = swapped.blch_txid;
        inputs[0].vout = 1;
        outputs[0].script_hash = trader_hash;
    }
    let funds = state.base().utxo(&swapped.blch_txid, 1).unwrap().value;
    fund_and_sign_with(&state, &mut burn, funds, 2);
    let before_burn = state.clone();
    let burned = state
        .execute_gateway(&burn, 4, &BaseVerifier, &BlochVerifier)
        .unwrap();
    let release = burned.gateway.release.unwrap();
    assert_eq!(release.amount, quote.amount_out);
    assert_eq!(release.recipient, [20; 20]);
    assert_eq!(
        state.native().gateway().native().supply(&native.asset),
        Some(AMOUNT - quote.amount_out)
    );
    assert_eq!(
        state.paired_custody(&created.reserve.id),
        before_burn.paired_custody(&created.reserve.id)
    );
    assert_eq!(
        state.base_reserve(&created.reserve.id),
        before_burn.base_reserve(&created.reserve.id)
    );
    assert_eq!(state.blch_lp_position(&initialized.pool, &keys()[0].0), lp);
    let route = state
        .native()
        .gateway()
        .route(&original.deposit.route)
        .unwrap();
    assert_eq!(route.imported, AMOUNT as u128);
    assert_eq!(route.burned, quote.amount_out as u128);
    assert_eq!(route.next_release_nonce, 1);
    // Count each live base output once, including the reserve and prepaid fees.
    let fees = state.fee_escrow();
    let remaining_blch = state.base().utxo(&initialized.blch_txid, 0).unwrap().value as u128
        + state.base_reserve(&created.reserve.id).unwrap().amount as u128
        + state.base().utxo(&burned.blch_txid, 0).unwrap().value as u128;
    assert_eq!(remaining_blch + fees.0 + fees.1, 2 * COIN as u128);
    assert_eq!(
        state.paired_custody(&created.reserve.id).unwrap().amount,
        AMOUNT - quote.amount_out
    );
    let frames = vec![
        import.canonical_bytes(&DOMAIN).unwrap(),
        pair.canonical_bytes(&DOMAIN).unwrap(),
        init.canonical_bytes(&DOMAIN).unwrap(),
        trade.canonical_bytes(&DOMAIN).unwrap(),
        burn.canonical_bytes(&DOMAIN).unwrap(),
    ];
    let refs: Vec<_> = frames.iter().map(Vec::as_slice).collect();
    let candidate =
        pool_candidate::build(&anchor, 4, &refs, &BaseVerifier, &BlochVerifier).unwrap();
    let mut receiver = anchor.clone();
    pool_candidate::apply(&mut receiver, &candidate, 4, &BaseVerifier, &BlochVerifier).unwrap();
    assert_eq!(receiver.state_root(), state.state_root());
    assert_eq!(receiver.fee_escrow(), state.fee_escrow());
    // A forged final withdrawal must roll back import, liquidity and swap as well.
    let mut bad = burn.clone();
    bad.gateway.approvals[0][crypto::SUITE_HEADER_LEN] ^= 1;
    let bad_frame = bad.canonical_bytes(&DOMAIN).unwrap();
    let mut bad_refs = refs.clone();
    bad_refs[4] = &bad_frame;
    let mut rejected = anchor.clone();
    assert!(pool_batch::apply(
        &mut rejected,
        &anchor.state_root(),
        4,
        &bad_refs,
        &BaseVerifier,
        &BlochVerifier
    )
    .is_err());
    assert_eq!(rejected.state_root(), anchor.state_root());
    #[cfg(feature = "native-dex-host")]
    restart_each_stage(anchor, frames, state, release);
}

#[cfg(feature = "native-dex-host")]
fn restart_each_stage(
    anchor: State,
    frames: Vec<Vec<u8>>,
    expected: State,
    release: gateway::Release,
) {
    use bloch_ustav::{
        dex_admission::PendingBatch,
        dex_journal::{Journal, TailRecovery},
    };
    let path = std::env::temp_dir().join(format!(
        "bloch-market-{}-{}.log",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut journal = Journal::create(&path, anchor.clone(), 3).unwrap();
    for (index, frame) in frames.iter().enumerate() {
        let height = 4 + index as u64;
        let previous = journal.checkpoint();
        let mut pending = PendingBatch::new(&journal, height).unwrap();
        pending.admit(&journal, frame, height).unwrap();
        assert!(journal
            .release_page(previous, &release.route, None, 1)
            .unwrap()
            .records()
            .is_empty());
        pending.commit(&mut journal, height).unwrap();
        let checkpoint = journal.checkpoint();
        drop(journal);
        journal =
            Journal::open(&path, anchor.clone(), 3, checkpoint, TailRecovery::Reject).unwrap();
        let page = journal
            .release_page(checkpoint, &release.route, None, 1)
            .unwrap();
        if index < 4 {
            assert!(page.records().is_empty());
        } else {
            assert_eq!(page.records(), &[&release]);
        }
        let mut replay = PendingBatch::new(&journal, height + 1).unwrap();
        assert!(replay.admit(&journal, frame, height + 1).is_err());
        assert_eq!(journal.checkpoint(), checkpoint);
    }
    assert_eq!(journal.state().state_root(), expected.state_root());
    assert_eq!(journal.state().fee_escrow(), expected.fee_escrow());
    drop(journal);
    std::fs::remove_file(path).unwrap();
}
