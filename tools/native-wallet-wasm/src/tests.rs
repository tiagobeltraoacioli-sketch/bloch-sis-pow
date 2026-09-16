use super::*;
use bloch_euvm::{
    modules::{ModuleKind, SupplyConfig, TokenCharter},
    ustav::{self as n, gateway::pools::PoolLedger},
    Val,
};
use bloch_pos_committee::interfaces::StateReader;
use bloch_pos_committee::{
    state_root::EutxoEntry,
    transition::{
        native_dex::{base_reserves, paired_custody, pool_wire, wallet_projection},
        TransferInputV2, TransferOutput, WitnessKey,
    },
};
use serde_json::json;
const DOMAIN: [u8; 32] = [42; 32];
const SEED: [u8; 32] = [7; 32];
const COIN: u64 = 100_000_000;
mod lab_builder;
mod lifecycle;
#[test]
fn unsigned_frame_must_reserve_outer_bytes_before_consent() {
    let (state, bytes, _) = fixture();
    let PosTransaction::NativePool(payload) = PosTransaction::from_canonical_bytes(&bytes).unwrap()
    else {
        panic!()
    };
    let pool_wire::Request::CreatePair(mut r) =
        pool_wire::decode(payload.as_bytes(), &DOMAIN).unwrap()
    else {
        panic!()
    };
    let inner = r.canonical_bytes(&DOMAIN).unwrap().len() as u64;
    if let PosTransaction::TransferV2 { tx_bytes, .. } = &mut r.blch {
        *tx_bytes = inner;
    }
    let charge = state.quote_paired_custody(&r).unwrap();
    if let PosTransaction::TransferV2 { outputs, .. } = &mut r.blch {
        outputs[1].value = COIN
            - r.blch_amount
            - u64::try_from(charge.base_fee_sat + charge.priority_fee_sat).unwrap();
    }
    let bytes = PosTransaction::NativePool(
        NativeTransferPayload::new(r.canonical_bytes(&DOMAIN).unwrap()).unwrap(),
    )
    .canonical_bytes();
    assert_eq!(
        Session::open(&SEED, DOMAIN)
            .unwrap()
            .prepare(&state, &bytes, 1)
            .unwrap_err(),
        "outer frame size is underdeclared"
    );
}
fn fixture() -> (State, Vec<u8>, serde_json::Value) {
    let (key, secret) = crypto::generate_keypair_from_seed(&SEED).unwrap();
    fixture_keypair(key, secret)
}
fn fixture_keypair(key: Vec<u8>, secret: Vec<u8>) -> (State, Vec<u8>, serde_json::Value) {
    // Falcon compressed signatures vary in length. Reserve the maximum hybrid
    // witness size before consent; declaration/fee never changes during signing.
    let placeholder = vec![0; 4593];
    let script = Sha3_256::digest(&key).into();
    let utxo = EutxoEntry {
        txid: [8; 32],
        vout: 0,
        value: COIN,
        script_hash: script,
    };
    let base = wallet_projection::base(DOMAIN, &[utxo], 1, 0, 0, 0).unwrap();
    let mut ledger = PoolLedger::new(DOMAIN);
    let registration = n::Registration {
        charter: TokenCharter {
            token_name: b"Fixture".to_vec(),
            modules: vec![ModuleKind::Supply(SupplyConfig {
                cap: 1000,
                issuer_pubkey: key.clone(),
            })],
        },
        nonce: [1; 32],
        initial_kyc_root: None,
    };
    let signature = crypto::sign(&secret, &registration.signing_hash(&DOMAIN).unwrap()).unwrap();
    let asset = ledger
        .register(registration, &signature, &Hybrid, 1_000_000)
        .unwrap();
    let mint = n::Transaction {
        asset,
        inputs: vec![],
        outputs: vec![n::Output {
            owner: key.clone(),
            amount: 100,
        }],
        delta: 100,
        mint_nonce: 0,
        policy_revision: 0,
        valid_until: 100,
    };
    let witnesses = n::Witnesses {
        modules: vec![vec![Val::Bytes(
            crypto::sign(&secret, &mint.signing_hash(&DOMAIN).unwrap()).unwrap(),
        )]],
        ..Default::default()
    };
    let minted = ledger
        .apply(&mint, &witnesses, 1, &Hybrid, 1_000_000)
        .unwrap();
    let state = State::from_parts(
        base.clone(),
        ledger.clone(),
        base.state_root(),
        ledger.state_root(),
    )
    .unwrap();
    let seed = [44; 32];
    let reserve = base_reserves::reserve_id(&DOMAIN, &seed, &key).unwrap();
    let mut request = paired_custody::Request {
        blch: PosTransaction::TransferV2 {
            keys: vec![WitnessKey {
                pubkey: key.clone(),
                signature: placeholder.clone(),
            }],
            inputs: vec![TransferInputV2 {
                txid: [8; 32],
                vout: 0,
                key_index: 0,
            }],
            outputs: vec![
                TransferOutput {
                    value: 1_000_000,
                    script_hash: base_reserves::reserve_script(&DOMAIN, &reserve),
                },
                TransferOutput {
                    value: 1,
                    script_hash: script,
                },
            ],
            tx_bytes: 0,
            tip_millisat_per_gas: 0,
        },
        native: n::transfer_wire::Envelope {
            domain: DOMAIN,
            transaction: n::Transaction {
                inputs: minted.outputs,
                outputs: vec![
                    n::Output {
                        owner: key.clone(),
                        amount: 60,
                    },
                    n::Output {
                        owner: key,
                        amount: 40,
                    },
                ],
                delta: 0,
                ..mint
            },
            witnesses: n::Witnesses {
                owners: vec![placeholder],
                modules: vec![vec![]],
                eligibility: vec![],
            },
        },
        seed,
        blch_amount: 1_000_000,
        native_amount: 60,
        valid_until: 100,
        native_gas: 100_000,
    };
    let length = request.canonical_bytes(&DOMAIN).unwrap().len() as u64 + 5;
    if let PosTransaction::TransferV2 { tx_bytes, .. } = &mut request.blch {
        *tx_bytes = length;
    }
    let charge = state.quote_paired_custody(&request).unwrap();
    if let PosTransaction::TransferV2 { outputs, .. } = &mut request.blch {
        outputs[1].value = COIN
            - 1_000_000
            - u64::try_from(charge.base_fee_sat + charge.priority_fee_sat).unwrap();
    }
    let packet = PosTransaction::NativePool(
        NativeTransferPayload::new(request.canonical_bytes(&DOMAIN).unwrap()).unwrap(),
    )
    .canonical_bytes();
    let (snapshot, commitment) = state.wallet_review_snapshot().unwrap();
    let context = json!({"nativeSnapshotHex":hex::encode(snapshot),"nativeCommitmentHex":hex::encode(commitment),"utxos":[{"txid":hex::encode([8;32]),"vout":"0","value":COIN.to_string(),"scriptHash":hex::encode(script)}],"baseFeeMillisatPerGas":"1","blockGasUsed":"0","blockTxBytes":"0","epoch":"0"});
    (state, packet, context)
}
#[test]
fn real_hybrid_typed_review_sign_execute_and_one_shot() {
    let (mut state, packet, context) = fixture();
    let mut session = Session::open(&SEED, DOMAIN).unwrap();
    let review = session.prepare(&state, &packet, 1).unwrap();
    assert_eq!(review.funding_sats, COIN as u128);
    let signed = session.sign(review.id, &state, &packet, 1, true).unwrap();
    let signed = if let Ok(path) = std::env::var("NATIVE_WASM_SIGNED_PATH") {
        hex::decode(std::fs::read_to_string(path).unwrap().trim()).unwrap()
    } else {
        signed
    };
    assert!(session.sign(review.id, &state, &packet, 1, true).is_err());
    let PosTransaction::NativePool(payload) =
        PosTransaction::from_canonical_bytes(&signed).unwrap()
    else {
        panic!()
    };
    let pool_wire::Request::CreatePair(request) =
        pool_wire::decode(payload.as_bytes(), &DOMAIN).unwrap()
    else {
        panic!()
    };
    let receipt = state
        .execute_paired_custody(&request, 1, &Hybrid, &Hybrid)
        .unwrap();
    assert_eq!(state.fee_escrow().0, receipt.charge.base_fee_sat);
    let artifact = json!({"schema":"postern.native-wasm-fixture.v1","publicTestSeedHex":hex::encode(SEED),"domainHex":hex::encode(DOMAIN),"transactionHex":hex::encode(packet),"height":"1","context":context,"signedTransactionHex":hex::encode(signed)});
    if let Ok(path) = std::env::var("NATIVE_WASM_FIXTURE_PATH") {
        std::fs::write(path, serde_json::to_vec_pretty(&artifact).unwrap()).unwrap();
    }
}
#[test]
fn cancellation_mutation_expiry_domain_and_foreign_owner_refuse() {
    let (state, packet, _) = fixture();
    let mut session = Session::open(&SEED, DOMAIN).unwrap();
    let first = session.prepare(&state, &packet, 1).unwrap();
    let replaced = session.prepare(&state, &packet, 2).unwrap();
    assert_ne!(first.id, replaced.id);
    assert!(session.sign(first.id, &state, &packet, 2, true).is_err());
    let r = session.prepare(&state, &packet, 1).unwrap();
    session.cancel();
    assert!(session.sign(r.id, &state, &packet, 1, true).is_err());
    let r = session.prepare(&state, &packet, 1).unwrap();
    assert!(session.sign(r.id, &state, &packet, 1, false).is_err());
    assert!(session.sign(r.id, &state, &packet, 1, true).is_err());
    let r = session.prepare(&state, &packet, 1).unwrap();
    assert!(session.sign(r.id, &state, &packet, 101, true).is_err());
    let r = session.prepare(&state, &packet, 1).unwrap();
    let mut changed = packet.clone();
    changed[8] ^= 1;
    assert!(session.sign(r.id, &state, &changed, 1, true).is_err());
    assert!(Session::open(&[8; 32], DOMAIN)
        .unwrap()
        .prepare(&state, &packet, 1)
        .is_err());
    assert!(Session::open(&SEED, [43; 32])
        .unwrap()
        .prepare(&state, &packet, 1)
        .is_err());
}
#[test]
fn abi_revalidates_snapshot_context_and_consumes_malformed_confirmation() {
    let (_, packet, context) = fixture();
    let open = || {
        abi::dispatch(json!({"method":"open","args":{"seedHex":hex::encode(SEED),"domainHex":hex::encode(DOMAIN)}})).unwrap()
    };
    open();
    let args = json!({"transactionHex":hex::encode(&packet),"context":context,"height":"1"});
    let review = abi::dispatch(json!({"method":"review","args":args})).unwrap();
    assert_eq!(review["packetHex"], args["transactionHex"]);
    assert!(abi::dispatch(json!({"method":"sign","args":null})).is_err());
    let mut confirm = args.clone();
    confirm["reviewId"] = review["id"].clone();
    confirm["confirmed"] = json!(true);
    assert!(abi::dispatch(json!({"method":"sign","args":confirm})).is_err());
    let review = abi::dispatch(json!({"method":"review","args":args})).unwrap();
    confirm["reviewId"] = review["id"].clone();
    confirm["context"]["epoch"] = json!("1");
    assert!(abi::dispatch(json!({"method":"sign","args":confirm})).is_err());
    let mut broken = args.clone();
    broken["context"]["nativeCommitmentHex"] = json!(hex::encode([0; 32]));
    assert!(abi::dispatch(json!({"method":"review","args":broken})).is_err());
    let review = abi::dispatch(json!({"method":"review","args":args})).unwrap();
    let mut valid = args.clone();
    valid["reviewId"] = review["id"].clone();
    valid["confirmed"] = json!(true);
    let signed = abi::dispatch(json!({"method":"sign","args":valid})).unwrap();
    let bytes = hex::decode(signed["transactionHex"].as_str().unwrap()).unwrap();
    let txid = PosTransaction::from_canonical_bytes(&bytes).unwrap().txid();
    assert_eq!(signed["txid"], hex::encode(txid));
    broken = args.clone();
    broken["context"]["baseFeeMillisatPerGas"] = json!(u128::MAX.to_string());
    assert!(abi::dispatch(json!({"method":"review","args":broken})).is_err());
    broken = args.clone();
    broken["height"] = json!(1);
    assert!(abi::dispatch(json!({"method":"review","args":broken})).is_err());
    abi::dispatch(json!({"method":"lock","args":{}})).unwrap();
    assert!(abi::dispatch(json!({"method":"review","args":args})).is_err());
}

#[test]
fn existing_account_import_matches_pinned_legacy_core_and_rejects_other_keys() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("tests/existing-account-vectors.json")).unwrap();
    for row in vectors.as_array().unwrap() {
        let public = hex::decode(row["public_key_hex"].as_str().unwrap()).unwrap();
        let session =
            Session::open_mnemonic(row["mnemonic"].as_str().unwrap(), &public, [42; 32]).unwrap();
        assert_eq!(session.public_key(), public);
    }
    let (public, secret) = crypto::generate_keypair_from_seed(&[7; 32]).unwrap();
    assert!(Session::open_keypair(public.clone(), secret.clone(), [42; 32]).is_ok());
    assert!(Session::open_keypair(public.clone(), secret.clone(), [0; 32]).is_err());
    let (_, foreign) = crypto::generate_keypair_from_seed(&[8; 32]).unwrap();
    assert!(Session::open_keypair(public.clone(), foreign, [42; 32]).is_err());
    assert!(Session::open_keypair(public.clone(), secret[4..].to_vec(), [42; 32]).is_err());
    assert!(
        Session::open_mnemonic(vectors[0]["mnemonic"].as_str().unwrap(), &public, [42; 32])
            .is_err()
    );
}

#[test]
fn existing_encrypted_account_typed_signature_executes_without_changing_identity() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("tests/existing-account-vectors.json")).unwrap();
    let row = &vectors[0];
    let public = hex::decode(row["public_key_hex"].as_str().unwrap()).unwrap();
    let mut session =
        Session::open_mnemonic(row["mnemonic"].as_str().unwrap(), &public, DOMAIN).unwrap();
    let (mut state, packet, context) = fixture_keypair(public, session.secret.to_vec());
    let review = session.prepare(&state, &packet, 1).unwrap();
    let signed = session.sign(review.id, &state, &packet, 1, true).unwrap();
    let signed = if let Ok(path) = std::env::var("NATIVE_ACCOUNT_SIGNED_PATH") {
        let r: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let bytes = hex::decode(r["transactionHex"].as_str().unwrap()).unwrap();
        assert_eq!(
            r["txid"],
            hex::encode(PosTransaction::from_canonical_bytes(&bytes).unwrap().txid())
        );
        bytes
    } else {
        signed
    };
    let PosTransaction::NativePool(payload) =
        PosTransaction::from_canonical_bytes(&signed).unwrap()
    else {
        panic!()
    };
    pool_wire::apply_encoded(&mut state, payload.as_bytes(), 1, &Hybrid, &Hybrid).unwrap();
    if let Ok(path) = std::env::var("NATIVE_ACCOUNT_VECTOR_PATH") {
        let artifact = json!({"publicFixtureMnemonic":row["mnemonic"],"publicKeyHex":row["public_key_hex"],"address":row["address"],"domainHex":hex::encode(DOMAIN),"transactionHex":hex::encode(packet),"context":context,"height":"1"});
        std::fs::write(path, serde_json::to_vec_pretty(&artifact).unwrap()).unwrap();
    }
}

#[test]
fn export_public_existing_hd_account_fixture_when_requested() {
    if let Ok(path) = std::env::var("NATIVE_ACCOUNT_HD_FIXTURE_PATH") {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("tests/existing-account-vectors.json")).unwrap();
        let wallet = bloch_crypto::hd_wallet::HdWallet::recover(
            vectors[0]["mnemonic"].as_str().unwrap(),
            Some("public-passphrase"),
            "Public-fixture-password-only",
            false,
            2,
        )
        .unwrap();
        wallet.save(std::path::Path::new(&path)).unwrap();
    }
}
