use super::*;
use base_reserves::RESERVE_KEY_INDEX;
use bloch_pos_committee::transition::native_dex::{
    add_liquidity, initial_liquidity, remove_liquidity, swap, swap_quote,
};
type Point = ([u8; 32], u32);
pub(super) fn key() -> Vec<u8> {
    crypto::generate_keypair_from_seed(&SEED).unwrap().0
}
fn owner_hash() -> [u8; 32] {
    Sha3_256::digest(key()).into()
}
fn payer(state: &State) -> Point {
    let out = state
        .base()
        .utxos()
        .filter(|u| {
            u.script_hash == owner_hash()
                && state.spendable_base_output(&(u.txid, u.vout)).is_some()
        })
        .max_by_key(|u| u.value)
        .unwrap();
    (out.txid, out.vout)
}
fn base(point: Point, reserve: Option<Point>, outputs: Vec<TransferOutput>) -> PosTransaction {
    let mut inputs = vec![];
    if let Some(p) = reserve {
        inputs.push(TransferInputV2 {
            txid: p.0,
            vout: p.1,
            key_index: RESERVE_KEY_INDEX,
        });
    }
    inputs.push(TransferInputV2 {
        txid: point.0,
        vout: point.1,
        key_index: 0,
    });
    PosTransaction::TransferV2 {
        keys: vec![WitnessKey {
            pubkey: key(),
            signature: vec![0; 4593],
        }],
        inputs,
        outputs,
        tx_bytes: 0,
        tip_millisat_per_gas: 0,
    }
}
fn base_mut(r: &mut pool_wire::Request) -> &mut PosTransaction {
    match r {
        pool_wire::Request::CreatePair(r) => &mut r.blch,
        pool_wire::Request::Initialize(r) => &mut r.blch,
        pool_wire::Request::Add(r) => &mut r.blch,
        pool_wire::Request::Swap(r) => &mut r.blch,
        pool_wire::Request::Remove(r) => &mut r.blch,
        pool_wire::Request::ClosePair(r) => &mut r.blch,
        pool_wire::Request::Gateway(r) => &mut r.blch,
    }
}
fn price(state: &State, r: &mut pool_wire::Request) {
    let size = pool_wire::encode(r, &DOMAIN).unwrap().len() as u64 + 5;
    if let PosTransaction::TransferV2 { tx_bytes, .. } = base_mut(r) {
        *tx_bytes = size;
    }
    let charge = pool_wire::quote_encoded(state, &pool_wire::encode(r, &DOMAIN).unwrap()).unwrap();
    if let PosTransaction::TransferV2 {
        inputs, outputs, ..
    } = base_mut(r)
    {
        let funded: u128 = inputs
            .iter()
            .map(|p| u128::from(state.base().utxo(&p.txid, p.vout).unwrap().value))
            .sum();
        let reserved: u128 = outputs[..outputs.len() - 1]
            .iter()
            .map(|o| u128::from(o.value))
            .sum();
        outputs.last_mut().unwrap().value =
            u64::try_from(funded - reserved - charge.base_fee_sat - charge.priority_fee_sat)
                .unwrap();
    }
}
fn context(state: &State) -> serde_json::Value {
    let (snapshot, commitment) = state.wallet_review_snapshot().unwrap();
    let rows:Vec<_>=state.base().utxos().map(|u|json!({"txid":hex::encode(u.txid),"vout":u.vout.to_string(),"value":u.value.to_string(),"scriptHash":hex::encode(u.script_hash)})).collect();
    json!({"nativeSnapshotHex":hex::encode(snapshot),"nativeCommitmentHex":hex::encode(commitment),"utxos":rows,"baseFeeMillisatPerGas":"1","blockGasUsed":"0","blockTxBytes":"0","epoch":"0"})
}
fn packet(request: &pool_wire::Request) -> Vec<u8> {
    let payload = NativeTransferPayload::new(pool_wire::encode(request, &DOMAIN).unwrap()).unwrap();
    if matches!(request, pool_wire::Request::Gateway(_)) {
        PosTransaction::NativeWithdrawal(payload).canonical_bytes()
    } else {
        PosTransaction::NativePool(payload).canonical_bytes()
    }
}
fn run(
    name: &str,
    state: &mut State,
    request: pool_wire::Request,
    vectors: &mut Vec<serde_json::Value>,
) -> pool_wire::Receipt {
    let mut request = request;
    if !matches!(request, pool_wire::Request::Gateway(_)) {
        price(state, &mut request);
    }
    let bytes = packet(&request);
    let pre = state.clone();
    let mut session = Session::open(&SEED, DOMAIN).unwrap();
    let review = session.prepare(state, &bytes, 1).unwrap();
    let signed = session
        .sign(review.id, state, &bytes, 1, true)
        .unwrap_or_else(|e| panic!("{name} sign: {e}"));
    let signed = if let Ok(path) = std::env::var("NATIVE_WASM_SIGNED_VECTORS_PATH") {
        let external: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let row = external["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["operation"] == name)
            .unwrap();
        hex::decode(row["signedTransactionHex"].as_str().unwrap()).unwrap()
    } else {
        signed
    };
    let signed_tx = PosTransaction::from_canonical_bytes(&signed).unwrap();
    let payload = match signed_tx {
        PosTransaction::NativePool(p) | PosTransaction::NativeWithdrawal(p) => p,
        _ => panic!(),
    };
    let receipt = pool_wire::apply_encoded(state, payload.as_bytes(), 1, &Hybrid, &Hybrid)
        .unwrap_or_else(|e| panic!("{name}: {e:?}"));
    let after = state.state_root();
    assert_ne!(after, pre.state_root());
    assert!(pool_wire::apply_encoded(state, payload.as_bytes(), 1, &Hybrid, &Hybrid).is_err());
    assert_eq!(state.state_root(), after);
    vectors.push(json!({"operation":name,"publicTestSeedHex":hex::encode(SEED),"domainHex":hex::encode(DOMAIN),"transactionHex":hex::encode(bytes),"height":"1","context":context(&pre),"signedTransactionHex":hex::encode(signed),"feeSat":review.fee_sat.to_string()}));
    *state = state.clone().fixture_review_projection();
    receipt
}
fn initialize(state: &State, reserve: [u8; 32], authorization: [u8; 32]) -> pool_wire::Request {
    pool_wire::Request::Initialize(initial_liquidity::Request {
        reserve,
        creation_authorization: authorization,
        fee_bps: 30,
        minimum_lp: 1,
        valid_until: 100,
        blch: base(
            payer(state),
            None,
            vec![TransferOutput {
                value: 1,
                script_hash: owner_hash(),
            }],
        ),
    })
}
fn envelope(
    asset: bloch_euvm::AssetId,
    inputs: Vec<n::OutPoint>,
    outputs: Vec<n::Output>,
    locked: n::OutPoint,
) -> n::transfer_wire::Envelope {
    let witnesses = n::Witnesses {
        owners: inputs
            .iter()
            .map(|p| if *p == locked { vec![] } else { vec![0; 4593] })
            .collect(),
        modules: vec![vec![]],
        eligibility: vec![],
    };
    n::transfer_wire::Envelope {
        domain: DOMAIN,
        transaction: n::Transaction {
            asset,
            inputs,
            outputs,
            delta: 0,
            mint_nonce: 0,
            policy_revision: 0,
            valid_until: 100,
        },
        witnesses,
    }
}
fn add(state: &State, reserve: [u8; 32], pool: [u8; 32]) -> pool_wire::Request {
    let b = state.base_reserve(&reserve).unwrap();
    let n = state.paired_custody(&reserve).unwrap();
    let query = add_liquidity::QuoteRequest {
        domain: DOMAIN,
        pool,
        revision: state.blch_pool(&pool).unwrap().revision(),
        maximum: [1_000_000, 30],
        minimum_lp: 1,
        valid_until: 100,
    };
    let q = state.quote_blch_add(&query, 1).unwrap();
    let change = n::OutPoint {
        transaction: n.outpoint.transaction,
        index: 1,
    };
    let available = state
        .native()
        .spendable_output(&change)
        .unwrap()
        .output
        .amount;
    pool_wire::Request::Add(add_liquidity::Request {
        quote: query,
        pool_state_root: q.pool_state_root,
        blch: base(
            payer(state),
            Some(b.outpoint),
            vec![
                TransferOutput {
                    value: q.reserves_after[0],
                    script_hash: base_reserves::reserve_script(&DOMAIN, &reserve),
                },
                TransferOutput {
                    value: 1,
                    script_hash: owner_hash(),
                },
            ],
        ),
        native: envelope(
            n.asset,
            vec![n.outpoint, change],
            vec![
                n::Output {
                    owner: key(),
                    amount: q.reserves_after[1],
                },
                n::Output {
                    owner: key(),
                    amount: available - q.amounts_in[1],
                },
            ],
            n.outpoint,
        ),
        native_gas: 100_000,
    })
}
fn swap(state: &State, reserve: [u8; 32], pool: [u8; 32]) -> pool_wire::Request {
    let b = state.base_reserve(&reserve).unwrap();
    let n = state.paired_custody(&reserve).unwrap();
    let query = swap_quote::Request {
        domain: DOMAIN,
        pool,
        revision: state.blch_pool(&pool).unwrap().revision(),
        input_asset: bloch_euvm::BLCH,
        amount: 100_000,
        minimum_out: 1,
        valid_until: 100,
    };
    let q = state.quote_blch_swap(&query, 1).unwrap();
    pool_wire::Request::Swap(swap::Request {
        quote: query,
        pool_state_root: q.pool_state_root,
        blch: base(
            payer(state),
            Some(b.outpoint),
            vec![
                TransferOutput {
                    value: q.reserves_after[0],
                    script_hash: base_reserves::reserve_script(&DOMAIN, &reserve),
                },
                TransferOutput {
                    value: 1,
                    script_hash: owner_hash(),
                },
            ],
        ),
        native: envelope(
            n.asset,
            vec![n.outpoint],
            vec![
                n::Output {
                    owner: key(),
                    amount: q.reserves_after[1],
                },
                n::Output {
                    owner: key(),
                    amount: q.amount_out,
                },
            ],
            n.outpoint,
        ),
        native_gas: 100_000,
    })
}
fn remove(state: &State, reserve: [u8; 32], pool: [u8; 32]) -> pool_wire::Request {
    let b = state.base_reserve(&reserve).unwrap();
    let n = state.paired_custody(&reserve).unwrap();
    let query = remove_liquidity::QuoteRequest {
        owner: key(),
        domain: DOMAIN,
        pool,
        revision: state.blch_pool(&pool).unwrap().revision(),
        lp: 3000,
        minimum: [1, 1],
        valid_until: 100,
    };
    let q = state.quote_blch_remove(&query, 1).unwrap();
    pool_wire::Request::Remove(remove_liquidity::Request {
        quote: query,
        pool_state_root: q.pool_state_root,
        blch: base(
            payer(state),
            Some(b.outpoint),
            vec![
                TransferOutput {
                    value: q.reserves_after[0],
                    script_hash: base_reserves::reserve_script(&DOMAIN, &reserve),
                },
                TransferOutput {
                    value: q.amounts_out[0],
                    script_hash: owner_hash(),
                },
                TransferOutput {
                    value: 1,
                    script_hash: owner_hash(),
                },
            ],
        ),
        native: envelope(
            n.asset,
            vec![n.outpoint],
            vec![
                n::Output {
                    owner: key(),
                    amount: q.reserves_after[1],
                },
                n::Output {
                    owner: key(),
                    amount: q.amounts_out[1],
                },
            ],
            n::OutPoint {
                transaction: [0; 32],
                index: 0,
            },
        ),
        native_gas: 100_000,
    })
}
fn close(state: &State, reserve: [u8; 32], authorization: [u8; 32]) -> pool_wire::Request {
    let b = state.base_reserve(&reserve).unwrap();
    let n = state.paired_custody(&reserve).unwrap();
    pool_wire::Request::ClosePair(paired_custody::CloseRequest {
        reserve,
        creation_authorization: authorization,
        blch: base(
            payer(state),
            Some(b.outpoint),
            vec![
                TransferOutput {
                    value: b.amount,
                    script_hash: owner_hash(),
                },
                TransferOutput {
                    value: 1,
                    script_hash: owner_hash(),
                },
            ],
        ),
        native: envelope(
            n.asset,
            vec![n.outpoint],
            vec![n::Output {
                owner: key(),
                amount: n.amount,
            }],
            n::OutPoint {
                transaction: [0; 32],
                index: 0,
            },
        ),
        valid_until: 100,
        native_gas: 100_000,
    })
}
fn withdrawal() -> (State, pool_wire::Request, [u8; 32]) {
    use bloch_euvm::ustav::gateway as g;
    use bloch_pos_committee::transition::native_dex::gateway;
    let (issuer, issuer_secret) = crypto::generate_keypair_from_seed(&[8; 32]).unwrap();
    let mut committee = vec![
        crypto::generate_keypair_from_seed(&[9; 32]).unwrap(),
        crypto::generate_keypair_from_seed(&[10; 32]).unwrap(),
    ];
    committee.sort_by(|a, b| a.0.cmp(&b.0));
    let approvals = |message: &[u8; 32]| {
        committee
            .iter()
            .map(|(_, s)| crypto::sign(s, message).unwrap())
            .collect::<Vec<_>>()
    };
    let mut ledger = PoolLedger::new(DOMAIN);
    let registration = n::Registration {
        charter: TokenCharter {
            token_name: b"Gateway fixture".to_vec(),
            modules: vec![ModuleKind::Supply(SupplyConfig {
                cap: 1000,
                issuer_pubkey: issuer.clone(),
            })],
        },
        nonce: [1; 32],
        initial_kyc_root: None,
    };
    let signature =
        crypto::sign(&issuer_secret, &registration.signing_hash(&DOMAIN).unwrap()).unwrap();
    let asset = ledger
        .register(registration, &signature, &Hybrid, 1_000_000)
        .unwrap();
    let config = g::RouteConfig {
        route: g::Route {
            source_domain: [7; 32],
            native_domain: DOMAIN,
            native_asset: asset,
            token: [8; 20],
            vault: [9; 20],
            decimals: 6,
            cap: 1000,
            vault_code_hash: [10; 32],
        },
        committee: committee.iter().map(|(p, _)| p.clone()).collect(),
        threshold: 2,
    };
    let auth = config.signing_hash();
    ledger
        .enable(
            config.clone(),
            &crypto::sign(&issuer_secret, &auth).unwrap(),
            &approvals(&auth),
            &Hybrid,
            1_000_000,
        )
        .unwrap();
    let mint = n::Transaction {
        asset,
        inputs: vec![],
        outputs: vec![n::Output {
            owner: key(),
            amount: 100,
        }],
        delta: 100,
        mint_nonce: 0,
        policy_revision: 0,
        valid_until: 100,
    };
    let import = g::ImportRequest {
        deposit: g::Deposit {
            route: config.route.id(),
            nonce: 1,
            sender: [11; 20],
            amount: 100,
            pq_recipient_hash: g::recipient_hash(&key()),
        },
        source_transaction: [13; 32],
        source_block: [14; 32],
        event_index: 0,
        valid_until: 100,
        transaction: mint.clone(),
    };
    let witnesses = n::Witnesses {
        modules: vec![vec![Val::Bytes(
            crypto::sign(&issuer_secret, &import.signing_hash(&DOMAIN).unwrap()).unwrap(),
        )]],
        ..Default::default()
    };
    let minted = ledger
        .import(
            &import,
            &witnesses,
            &approvals(&import.signing_hash(&DOMAIN).unwrap()),
            1,
            &Hybrid,
            1_000_000,
        )
        .unwrap();
    let base_state = wallet_projection::base(
        DOMAIN,
        &[EutxoEntry {
            txid: [8; 32],
            vout: 0,
            value: COIN,
            script_hash: owner_hash(),
        }],
        1,
        0,
        0,
        0,
    )
    .unwrap();
    let root = ledger.state_root();
    let state =
        State::from_parts(base_state.clone(), ledger, base_state.state_root(), root).unwrap();
    let request = gateway::Request {
        blch: base(
            (([8; 32]), 0),
            None,
            vec![TransferOutput {
                value: 1,
                script_hash: owner_hash(),
            }],
        ),
        gateway: g::wire::Envelope {
            domain: DOMAIN,
            operation: g::wire::Operation::Withdraw(g::WithdrawalRequest {
                route: config.route.id(),
                nonce: 0,
                recipient: [15; 20],
                transaction: n::Transaction {
                    inputs: minted.outputs,
                    outputs: vec![],
                    delta: -100,
                    ..mint
                },
            }),
            witnesses: n::Witnesses {
                owners: vec![vec![0; 4593]],
                modules: vec![vec![Val::Bytes(vec![0; 4593])]],
                eligibility: vec![],
            },
            approvals: vec![vec![0; 4593]; 2],
        },
        valid_until: 100,
        native_gas: 100_000,
    };
    let mut request = pool_wire::Request::Gateway(request);
    price(&state, &mut request);
    let pool_wire::Request::Gateway(r) = &mut request else {
        unreachable!()
    };
    let auth = r.authorization(&DOMAIN).unwrap();
    r.gateway.witnesses.modules[0] = vec![Val::Bytes(crypto::sign(&issuer_secret, &auth).unwrap())];
    r.gateway.approvals = approvals(&auth);
    (state, request, config.route.id())
}
#[test]
fn full_pool_lifecycle_real_hybrid_signatures_and_wasm_vectors() {
    let (mut state, create, _) = fixture();
    let PosTransaction::NativePool(payload) =
        PosTransaction::from_canonical_bytes(&create).unwrap()
    else {
        panic!()
    };
    let request = pool_wire::decode(payload.as_bytes(), &DOMAIN).unwrap();
    let mut vectors = vec![];
    let pool_wire::Receipt::CreatePair(receipt) =
        run("create-pair", &mut state, request, &mut vectors)
    else {
        panic!()
    };
    let reserve = receipt.reserve.id;
    let authorization = receipt.authorization;
    let mut close_state = state.clone();
    let request = close(&close_state, reserve, authorization);
    run("close-pair", &mut close_state, request, &mut vectors);
    assert!(close_state.base_reserve(&reserve).is_none());
    let request = initialize(&state, reserve, authorization);
    run("initialize", &mut state, request, &mut vectors);
    let pool = state.blch_pool_for_reserve(&reserve).unwrap().id();
    assert_eq!(state.blch_pool(&pool).unwrap().reserves(), [1_000_000, 60]);
    assert_eq!(state.blch_lp_position(&pool, &key()), 6745);
    let request = add(&state, reserve, pool);
    run("add", &mut state, request, &mut vectors);
    assert_eq!(state.blch_pool(&pool).unwrap().reserves(), [1_499_936, 90]);
    assert_eq!(state.blch_lp_position(&pool, &key()), 6745 + 3872);
    // LP mint floor(30*7745/60)=3872; BLCH debit ceil(3872*1m/7745)=499936.
    let request = swap(&state, reserve, pool);
    run("swap", &mut state, request, &mut vectors);
    assert_eq!(state.blch_pool(&pool).unwrap().reserves(), [1_599_936, 85]);
    let before_lp = state.blch_lp_position(&pool, &key());
    let request = remove(&state, reserve, pool);
    run("remove", &mut state, request, &mut vectors);
    assert_eq!(state.blch_lp_position(&pool, &key()), before_lp - 3000);
    let (mut withdrawal_state, request, route) = withdrawal();
    run("withdrawal", &mut withdrawal_state, request, &mut vectors);
    assert_eq!(
        withdrawal_state
            .native()
            .gateway()
            .route(&route)
            .unwrap()
            .burned,
        100
    );
    assert_eq!(
        withdrawal_state
            .native()
            .gateway()
            .release_record(&route, 0)
            .unwrap()
            .recipient,
        [15; 20]
    );
    if let Ok(path) = std::env::var("NATIVE_WASM_VECTORS_PATH") {
        std::fs::write(
            path,
            serde_json::to_vec_pretty(
                &json!({"schema":"postern.native-wasm-vectors.v1","vectors":vectors}),
            )
            .unwrap(),
        )
        .unwrap();
    }
}
fn refuse(state: &State, mut request: pool_wire::Request) {
    if !matches!(request, pool_wire::Request::Gateway(_)) {
        price(state, &mut request)
    }
    let bytes = packet(&request);
    let mut signer = Session::open(&SEED, DOMAIN).unwrap();
    let before = state.state_root();
    if let Ok(review) = signer.prepare(state, &bytes, 1) {
        assert!(signer.sign(review.id, state, &bytes, 1, true).is_err());
        assert!(signer.sign(review.id, state, &bytes, 1, true).is_err());
    }
    assert_eq!(state.state_root(), before);
}
#[test]
fn typed_signing_refuses_slippage_reserve_owner_and_authority_changes() {
    let (mut state, create, _) = fixture();
    let PosTransaction::NativePool(p) = PosTransaction::from_canonical_bytes(&create).unwrap()
    else {
        panic!()
    };
    let mut vectors = vec![];
    let pool_wire::Receipt::CreatePair(created) = run(
        "create-pair",
        &mut state,
        pool_wire::decode(p.as_bytes(), &DOMAIN).unwrap(),
        &mut vectors,
    ) else {
        panic!()
    };
    let reserve = created.reserve.id;
    let mut bad = close(&state, reserve, created.authorization);
    if let pool_wire::Request::ClosePair(r) = &mut bad {
        r.creation_authorization[0] ^= 1;
    }
    refuse(&state, bad);
    let mut bad = close(&state, reserve, created.authorization);
    if let pool_wire::Request::ClosePair(r) = &mut bad {
        r.native.transaction.outputs[0].owner =
            crypto::generate_keypair_from_seed(&[20; 32]).unwrap().0;
    }
    refuse(&state, bad);
    let initialize = initialize(&state, reserve, created.authorization);
    run("initialize", &mut state, initialize, &mut vectors);
    let pool = state.blch_pool_for_reserve(&reserve).unwrap().id();
    refuse(&state, close(&state, reserve, created.authorization));
    for case in 0..4 {
        let mut request = swap(&state, reserve, pool);
        if let pool_wire::Request::Swap(r) = &mut request {
            match case {
                0 => r.pool_state_root[0] ^= 1,
                1 => r.quote.minimum_out = u64::MAX,
                2 => r.quote.revision += 1,
                _ => {
                    r.native.transaction.outputs[1].owner =
                        crypto::generate_keypair_from_seed(&[20; 32]).unwrap().0
                }
            }
        }
        refuse(&state, request);
    }
    for case in 0..2 {
        let mut request = remove(&state, reserve, pool);
        if let pool_wire::Request::Remove(r) = &mut request {
            if case == 0 {
                r.quote.owner = crypto::generate_keypair_from_seed(&[20; 32]).unwrap().0
            } else {
                r.quote.lp = u64::MAX
            }
        }
        refuse(&state, request);
    }
    let mut request = swap(&state, reserve, pool);
    price(&state, &mut request);
    let bytes = packet(&request);
    let mut signer = Session::open(&SEED, DOMAIN).unwrap();
    let review = signer.prepare(&state, &bytes, 1).unwrap();
    let mut changed = state.clone();
    run("swap", &mut changed, request, &mut vectors);
    assert!(signer.sign(review.id, &changed, &bytes, 1, true).is_err());
    let (state, mut request, _) = withdrawal();
    if let pool_wire::Request::Gateway(r) = &mut request {
        r.gateway.approvals[1][0] ^= 1;
    }
    refuse(&state, request);
}
