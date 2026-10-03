use super::*;
use bloch_pos_committee::SignatureVerifier;
const PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
struct Verifier;
impl SignatureVerifier for Verifier {
    fn verify_with_key(&self, key: &[u8], message: &[u8; 32], signature: &[u8]) -> bool {
        crypto::verify(key, message, signature)
    }
}
fn fixture() -> (Session, Value) {
    use bloch_crypto::wallet::seed::{SeedPhrase, SeedVersion};
    let parsed = SeedPhrase::parse(PHRASE).unwrap();
    let seed = Zeroizing::new(
        parsed
            .to_seed_bytes_versioned(SeedVersion::V1LegacyPbkdf2Sha256, "")
            .unwrap(),
    );
    let (public, secret) = crypto::generate_keypair_from_seed(&seed[..32]).unwrap();
    let owner = hex::encode(digest(&public));
    let s = Session::open(public, secret).unwrap();
    let args = json!({"operation":"delegate","amountSat":"1000000000","context":{
        "domain":DOMAIN,"ownerHash":owner,"epoch":"7000","finalizedEpoch":"6998","active":true,"activationEpoch":"4669",
        "cooldownEpochs":"32","withdrawalDelayEpochs":"2048","baseFee":"10",
        "validator":{"index":"7","keyHash":"12".repeat(32),"status":"active","commissionBps":"500","reservedSat":"0"},
        "utxos":[{"txid":"34".repeat(32),"vout":"0","value":"10000000000","scriptHash":owner}],
        "position":{"position":"0","delegator":"5","ownerHash":owner,"principalSat":"1000000000","activatedSat":"0",
            "feeRewardsSat":"5000","issuanceRewardsSat":"7000","slashLossesSat":"10000","deactivateEpoch":null,"inactiveSince":null,"withdrawableEpoch":null,"withdrawn":false,"mature":false}
    }});
    (s, args)
}
fn verify_signed(value: &Value) {
    let tx = PosTransaction::from_canonical_bytes(
        &hex::decode(value["transactionHex"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(hex::encode(tx.txid()), value["txid"]);
    match tx {
        PosTransaction::FundedDelegate(t) => t.verify_authorization(&Verifier),
        PosTransaction::FundedUndelegate(t) => t.verify_authorization(&Verifier),
        PosTransaction::FundedDelegationWithdraw(t) => t.verify_authorization(&Verifier),
        _ => panic!(),
    }
    .unwrap();
}
#[test]
fn all_three_real_hybrid_signatures_use_canonical_protocol_intents() {
    let (mut s, base) = fixture();
    let mut vectors = Vec::new();
    for op in ["delegate", "undelegate", "withdraw"] {
        let mut args = base.clone();
        args["operation"] = op.into();
        if op != "delegate" {
            args["position"] = "0".into();
        }
        if op == "withdraw" {
            let p = &mut args["context"]["position"];
            p["deactivateEpoch"] = "4900".into();
            p["inactiveSince"] = "4950".into();
            p["withdrawableEpoch"] = "6998".into();
            p["mature"] = true.into();
        }
        let review = s.review(&args).unwrap();
        let mut signing = args.clone();
        signing["confirmed"] = true.into();
        signing["reviewId"] = review["id"].clone();
        let signed = s.sign(&signing).unwrap();
        verify_signed(&signed);
        assert!(s.sign(&signing).is_err());
        vectors.push(json!({"args":args,"review":review,"signed":signed}));
    }
    if let Ok(path) = std::env::var("DELEGATION_WALLET_FIXTURE") {
        std::fs::write(path,serde_json::to_vec_pretty(&json!({"publicFixtureMnemonic":PHRASE,"publicKeyHex":hex::encode(s.public),"domain":DOMAIN,"vectors":vectors})).unwrap()).unwrap();
    }
    if let Ok(path) = std::env::var("DELEGATION_BROWSER_SIGNATURES") {
        let signed: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(signed.as_array().unwrap().len(), 3);
        for value in signed.as_array().unwrap() {
            verify_signed(value);
        }
    }
}
#[test]
fn review_is_single_use_and_bound_to_amount_epoch_fee_commission_and_owner() {
    let (mut s, args) = fixture();
    for (path, value) in [
        ("amountSat", json!("2000000000")),
        ("context.epoch", json!("7001")),
        ("context.baseFee", json!("11")),
        ("context.validator.commissionBps", json!("600")),
        ("context.ownerHash", json!("00".repeat(32))),
    ] {
        let r = s.review(&args).unwrap();
        let mut changed = args.clone();
        let keys: Vec<_> = path.split('.').collect();
        let mut target = &mut changed;
        for key in &keys[..keys.len() - 1] {
            target = &mut target[*key];
        }
        target[keys[keys.len() - 1]] = value;
        changed["confirmed"] = true.into();
        changed["reviewId"] = r["id"].clone();
        assert!(s.sign(&changed).is_err());
        let mut original = args.clone();
        original["confirmed"] = true.into();
        original["reviewId"] = r["id"].clone();
        assert!(s.sign(&original).is_err());
    }
}
#[test]
fn exit_and_withdrawal_fail_closed_for_wrong_owner_cooldown_early_or_unfinalized_maturity() {
    let (mut s, mut args) = fixture();
    args["operation"] = "withdraw".into();
    args["position"] = "0".into();
    let p = &mut args["context"]["position"];
    p["deactivateEpoch"] = "4900".into();
    p["inactiveSince"] = "4950".into();
    p["withdrawableEpoch"] = "6998".into();
    p["mature"] = true.into();
    assert!(s.review(&args).is_ok());
    for (key, value) in [
        ("deactivateEpoch", json!("4940")),
        ("inactiveSince", Value::Null),
        ("withdrawableEpoch", json!("6997")),
        ("activatedSat", json!("1")),
        ("ownerHash", json!("ab".repeat(32))),
        ("withdrawn", json!(true)),
        ("mature", json!(false)),
        ("slashLossesSat", json!("1000000001")),
    ] {
        let mut bad = args.clone();
        bad["context"]["position"][key] = value;
        assert!(s.review(&bad).is_err(), "{key}");
    }
    for key in ["epoch", "finalizedEpoch"] {
        let mut bad = args.clone();
        bad["context"][key] = "6997".into();
        assert!(s.review(&bad).is_err());
    }
}
#[test]
fn funding_requires_native_ownership_strict_outpoints_capacity_and_live_gate() {
    let (mut s, args) = fixture();
    let mut bad = args.clone();
    bad["context"]["active"] = false.into();
    assert!(s.review(&bad).is_err());
    let mut bad = args.clone();
    bad["context"]["epoch"] = "4668".into();
    assert!(s.review(&bad).is_err());
    let mut bad = args.clone();
    bad["context"]["utxos"][0]["scriptHash"] = "00".repeat(32).into();
    assert!(s.review(&bad).is_err());
    let mut bad = args.clone();
    bad["context"]["utxos"]
        .as_array_mut()
        .unwrap()
        .push(args["context"]["utxos"][0].clone());
    assert!(s.review(&bad).is_err());
    let mut bad = args.clone();
    bad["context"]["validator"]["reservedSat"] = "50000000000000000".into();
    assert!(s.review(&bad).is_err());
    let mut bad = args.clone();
    bad["amountSat"] = json!(1000000000);
    assert!(s.review(&bad).is_err());
}
