// SPDX-License-Identifier: AGPL-3.0-or-later
//! Every test drives the signer through `dispatch`, the function behind
//! `nw_call`, with the published disposable BIP39 test mnemonic. Nothing here
//! connects to a network or opens an existing wallet.
use super::*;
use bloch_crypto::wallet::seed::{SeedPhrase, SeedVersion};
use std::sync::OnceLock;

/// Published BIP39 test vector; never fund it.
const PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const FIXTURE: &str = include_str!("../fixtures/l2-deposit-fixture.json");

fn derive(version: SeedVersion) -> (Vec<u8>, Vec<u8>) {
    let seed = Zeroizing::new(
        SeedPhrase::parse(PHRASE).unwrap().to_seed_bytes_versioned(version, "").unwrap(),
    );
    crypto::generate_keypair_from_seed(&seed[..32]).unwrap()
}
/// The production web wallet's account (V1 legacy PBKDF2 seed).
fn v1() -> &'static (Vec<u8>, Vec<u8>) {
    static KEY: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
    KEY.get_or_init(|| derive(SeedVersion::V1LegacyPbkdf2Sha256))
}
fn v2() -> &'static (Vec<u8>, Vec<u8>) {
    static KEY: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
    KEY.get_or_init(|| derive(SeedVersion::V2Bip39Sha512))
}
fn call(method: &str, args: Value) -> Result<Value> {
    dispatch(json!({"method": method, "args": args}))
}
fn open_args() -> Value {
    json!({"domainHex": DOMAIN, "publicKeyHex": hex::encode(&v1().0), "mnemonic": PHRASE})
}
fn open() {
    call("open_mnemonic", open_args()).unwrap();
}
/// 10 BLCH to an L2 address from two outputs, at the mainnet floor price.
fn deposit_args() -> Value {
    json!({
        "recipientHex": "42".repeat(20),
        "amountSat": "1000000000",
        "inputs": [
            {"txidHex": "34".repeat(32), "vout": 1, "valueSat": "900000000"},
            {"txidHex": "12".repeat(32), "vout": 0, "valueSat": "600000000"},
        ],
        "baseFeeMillisatPerGas": "10",
        "tipMillisatPerGas": "0",
    })
}
fn with_review(args: &Value, review: &Value) -> Value {
    let mut signing = args.clone();
    signing["reviewId"] = review["reviewId"].clone();
    signing
}
fn review_and_sign(args: &Value) -> (Value, Value) {
    let review = call("review", args.clone()).unwrap();
    let signed = call("sign", with_review(args, &review)).unwrap();
    (review, signed)
}
fn decode(signed: &Value) -> L2Deposit {
    let wire = hex::decode(signed["transactionHex"].as_str().unwrap()).unwrap();
    match PosTransaction::from_canonical_bytes(&wire).unwrap() {
        PosTransaction::L2Deposit(tx) => tx,
        _ => panic!("not an L2 deposit"),
    }
}
fn set(args: &Value, path: &str, value: Value) -> Value {
    let mut changed = args.clone();
    let mut target = &mut changed;
    let keys: Vec<&str> = path.split('.').collect();
    for key in &keys[..keys.len() - 1] {
        target = match key.parse::<usize>() {
            Ok(i) => &mut target[i],
            Err(_) => &mut target[*key],
        };
    }
    target[keys[keys.len() - 1]] = value;
    changed
}

/// What `bloch-pos l2-deposit prepare` builds for the same request, written
/// out independently of `Session::build` (the CLI's own lines).
fn cli_prepare(public: &[u8], inputs: &[([u8; 32], u32, u64)], amount_sat: u64, recipient: [u8; 20], base_fee: u128, tip: u128) -> L2Deposit {
    let mut funding: Vec<FundingInput> =
        inputs.iter().map(|(txid, vout, _)| FundingInput { txid: *txid, vout: *vout }).collect();
    let total: u128 = inputs.iter().map(|(_, _, sats)| u128::from(*sats)).sum();
    funding.sort();
    let owner: [u8; 32] = Sha3_256::digest(public).into();
    let mut tx = L2Deposit {
        network_domain: hex::decode(DOMAIN).unwrap().try_into().unwrap(),
        funding_pubkey: public.to_vec(),
        inputs: funding,
        amount_sat,
        recipient,
        change: TransferOutput { value: 0, script_hash: owner },
        tx_bytes: 0,
        tip_millisat_per_gas: tip,
        signature: Vec::new(),
    };
    tx.tx_bytes = (tx.canonical_bytes().len() + ADMISSION_PQ_SIGNATURE_MAX) as u64;
    let charge = fee_market::charge(fee_market::TxClass::Eutxo { inputs: tx.inputs.len() as u32 }, tx.tx_bytes, base_fee, tip);
    let change = total
        .checked_sub(u128::from(amount_sat) + charge.base_fee_sat + charge.priority_fee_sat)
        .expect("inputs do not cover the amount plus fees");
    tx.change.value = u64::try_from(change).unwrap();
    tx
}

// ── Known answer ────────────────────────────────────────────────────────────

#[test]
fn review_and_sign_produce_the_transaction_the_node_cli_prepares() {
    open();
    let args = deposit_args();
    let (review, signed) = review_and_sign(&args);
    let hex_tx = signed["transactionHex"].as_str().unwrap();
    assert!(hex_tx.starts_with("14"), "wire tag 0x14");
    let tx = decode(&signed);
    let wire = PosTransaction::L2Deposit(tx.clone());
    // Canonical: the node's decoder and encoder agree on these bytes.
    assert_eq!(hex::encode(wire.canonical_bytes()), hex_tx);

    // The node's own txid, and the one the review already announced.
    assert_eq!(signed["txid"], hex::encode(wire.txid()));
    assert_eq!(review["txid"], signed["txid"]);
    // The txid is witness-free: DS_TXID over the signed intent root, so no
    // re-signing or re-encoding of the signature can move it.
    let mut h = Sha3_256::new();
    h.update(bloch_pos_committee::params::DS_TXID);
    h.update(tx.intent_root());
    assert_eq!(wire.txid(), <[u8; 32]>::from(h.finalize()));
    let mut resigned = tx.clone();
    resigned.signature = vec![1; 64];
    assert_eq!(PosTransaction::L2Deposit(resigned).txid(), wire.txid());

    // The signature is a real hybrid signature over the node's signing root.
    assert!(crypto::verify(&tx.funding_pubkey, &tx.intent_root(), &tx.signature));
    // Mainnet judges transaction witnesses with the pinned FIPS 204 ML-DSA
    // verifier since MLDSA_PIN_ACTIVATION_EPOCH (`SignaturePolicy::transaction`
    // -> CompatiblePinned -> `verify_pinned`).
    assert!(crypto::verify_pinned(&tx.funding_pubkey, &tx.intent_root(), &tx.signature));
    assert!(!tx.signature.is_empty() && tx.signature.len() <= ADMISSION_PQ_SIGNATURE_MAX);
    let mut other = tx.clone();
    other.amount_sat += 1;
    assert!(!crypto::verify(&tx.funding_pubkey, &other.intent_root(), &tx.signature));

    // Field by field against the CLI's construction.
    let expected = cli_prepare(
        &v1().0,
        &[([0x34; 32], 1, 900_000_000), ([0x12; 32], 0, 600_000_000)],
        1_000_000_000,
        [0x42; 20],
        10,
        0,
    );
    let mut unsigned = tx.clone();
    unsigned.signature = Vec::new();
    assert_eq!(unsigned, expected);
    assert_eq!(tx.inputs[0].txid, [0x12; 32], "inputs are sorted");
    assert_eq!(tx.change.script_hash, digest(&v1().0), "change returns to the owner");
    assert!(tx.tx_bytes >= wire.canonical_bytes().len() as u64, "declared size covers the encoding");
    assert!(
        tx.tx_bytes <= wire.canonical_bytes().len() as u64 + fee_market::TX_BYTES_DECLARE_SLACK,
        "and stays inside the mempool's over-declaration slack",
    );

    // The review's numbers are the transaction's.
    let charge = fee_market::charge(fee_market::TxClass::Eutxo { inputs: 2 }, tx.tx_bytes, 10, 0);
    let fee = charge.base_fee_sat + charge.priority_fee_sat;
    assert_eq!(review["feeSat"], fee.to_string());
    assert_eq!(signed["feeSat"], review["feeSat"]);
    assert_eq!(review["changeSat"], tx.change.value.to_string());
    assert_eq!(signed["changeSat"], review["changeSat"]);
    assert_eq!(u128::from(tx.change.value) + fee + 1_000_000_000, 1_500_000_000, "exact conservation");
    assert_eq!(review["recipientHex"], "42".repeat(20));
    assert_eq!(review["amountSat"], "1000000000");
    assert_eq!(review["txBytes"], tx.tx_bytes.to_string());
    assert_eq!(review["inputCount"], 2);
    assert_eq!(review["domainHex"], DOMAIN);
    assert_eq!(review["changeScriptHashHex"], hex::encode(digest(&v1().0)));
}

#[test]
fn the_tip_is_priced_and_signed() {
    open();
    let args = set(&deposit_args(), "tipMillisatPerGas", json!("25"));
    let (review, signed) = review_and_sign(&args);
    let tx = decode(&signed);
    assert_eq!(tx.tip_millisat_per_gas, 25);
    let charge = fee_market::charge(fee_market::TxClass::Eutxo { inputs: 2 }, tx.tx_bytes, 10, 25);
    assert!(charge.priority_fee_sat > 0);
    assert_eq!(review["priorityFeeSat"], charge.priority_fee_sat.to_string());
    assert_eq!(review["baseFeeSat"], charge.base_fee_sat.to_string());
    assert_eq!(review["feeSat"], (charge.base_fee_sat + charge.priority_fee_sat).to_string());
    assert!(crypto::verify(&tx.funding_pubkey, &tx.intent_root(), &tx.signature));
}

#[test]
fn input_rows_accept_integers_or_decimal_strings_with_one_fingerprint() {
    open();
    let args = deposit_args();
    let a = call("review", args.clone()).unwrap();
    let mut b = set(&args, "inputs.0.vout", json!("1"));
    b = set(&b, "inputs.0.valueSat", json!(900_000_000u64));
    let mut c = args.clone();
    c["inputs"].as_array_mut().unwrap().reverse();
    assert_eq!(call("review", b).unwrap(), a);
    assert_eq!(call("review", c).unwrap(), a, "input order given by the page does not matter");
}

#[test]
fn the_pinned_domain_is_the_mainnet_manifest_digest() {
    // `l2_deposit_cli::domain` is SHA3-256 of the manifest's canonical
    // encoding; `genesis/mainnet.manifest` is that encoding.
    let manifest = include_bytes!("../../../genesis/mainnet.manifest");
    assert_eq!(hex::encode(Sha3_256::digest(manifest)), DOMAIN);
}

// ── Account opening ─────────────────────────────────────────────────────────

#[test]
fn a_mnemonic_opens_the_expected_account_under_v1_then_v2_and_nothing_else() {
    let (legacy, standard) = (&v1().0, &v2().0);
    assert_ne!(legacy, standard);
    for public in [legacy, standard] {
        let reply = call("open_mnemonic", json!({"domainHex": DOMAIN, "publicKeyHex": hex::encode(public), "mnemonic": PHRASE})).unwrap();
        assert_eq!(reply["publicKeyHex"], hex::encode(public));
        assert_eq!(reply["ownerHashHex"], hex::encode(digest(public)));
        assert_eq!(reply["domainHex"], DOMAIN);
        let (_, signed) = review_and_sign(&deposit_args());
        assert_eq!(&decode(&signed).funding_pubkey, public);
    }
    // A public key the phrase does not derive: refused, and no session stays.
    let mut wrong = legacy.clone();
    wrong[100] ^= 1;
    assert_eq!(
        call("open_mnemonic", json!({"domainHex": DOMAIN, "publicKeyHex": hex::encode(&wrong), "mnemonic": PHRASE})),
        Err("phrase account mismatch")
    );
    assert_eq!(call("review", deposit_args()), Err("locked"));
    assert_eq!(
        call("open_mnemonic", json!({"domainHex": DOMAIN, "publicKeyHex": hex::encode(legacy), "mnemonic": "abandon abandon"})),
        Err("invalid phrase")
    );
}

#[test]
fn a_keypair_opens_only_with_its_own_secret() {
    let (public, secret) = v1();
    let args = json!({"domainHex": DOMAIN, "publicKeyHex": hex::encode(public), "secretKeyHex": hex::encode(secret)});
    call("open_keypair", args.clone()).unwrap();
    let (_, signed) = review_and_sign(&deposit_args());
    assert!(crypto::verify(public, &decode(&signed).intent_root(), &decode(&signed).signature));
    // Another account's secret under this public key.
    let mismatched = set(&args, "secretKeyHex", hex::encode(&v2().1).into());
    assert_eq!(call("open_keypair", mismatched), Err("account mismatch"));
    assert_eq!(call("review", deposit_args()), Err("locked"), "a failed open leaves no session");
    // Not a hybrid suite-0x0001 key.
    let short = set(&args, "publicKeyHex", hex::encode(&public[..100]).into());
    assert_eq!(call("open_keypair", short), Err("invalid account"));
}

#[test]
fn a_wrong_network_domain_is_refused_at_open() {
    let mut other = DOMAIN.to_owned();
    other.replace_range(0..2, "00");
    for method in ["open_mnemonic", "open_keypair"] {
        let mut args = open_args();
        args["secretKeyHex"] = hex::encode(&v1().1).into();
        args["domainHex"] = other.clone().into();
        assert_eq!(call(method, args.clone()), Err("wrong network"), "{method}");
        args.as_object_mut().unwrap().remove("domainHex");
        assert!(call(method, args).is_err(), "{method} without a domain");
        assert_eq!(call("review", deposit_args()), Err("locked"));
    }
}

#[test]
fn the_signed_domain_is_the_pinned_one_and_no_argument_can_change_it() {
    open();
    for field in ["domainHex", "networkDomainHex", "changeScriptHashHex", "publicKeyHex", "fundingPubkeyHex", "digestHex"] {
        let args = set(&deposit_args(), field, "00".repeat(32).into());
        assert_eq!(call("review", args), Err("unsupported field"), "{field}");
    }
    let (_, signed) = review_and_sign(&deposit_args());
    assert_eq!(hex::encode(decode(&signed).network_domain), DOMAIN);
}

// ── Refusals ────────────────────────────────────────────────────────────────

fn refused(path: &str, value: Value, why: &str) {
    assert_eq!(call("review", set(&deposit_args(), path, value)), Err(why), "{path}");
}

#[test]
fn a_zero_or_malformed_recipient_is_refused() {
    open();
    refused("recipientHex", "00".repeat(20).into(), "zero recipient");
    refused("recipientHex", "42".repeat(19).into(), "invalid recipient");
    refused("recipientHex", "42".repeat(21).into(), "invalid recipient");
    refused("recipientHex", format!("0x{}", "42".repeat(19)).into(), "invalid recipient");
    refused("recipientHex", "zz".repeat(20).into(), "invalid recipient");
    refused("recipientHex", json!(null), "missing string");
    // Either hex case is one recipient.
    let upper = set(&deposit_args(), "recipientHex", "aB".repeat(20).into());
    assert_eq!(call("review", upper).unwrap()["recipientHex"], "ab".repeat(20));
}

#[test]
fn an_amount_outside_the_protocol_range_is_refused() {
    open();
    refused("amountSat", (MIN_L2_DEPOSIT_SAT - 1).to_string().into(), "amount out of range");
    refused("amountSat", "0".into(), "amount out of range");
    refused("amountSat", (MAX_L2_DEPOSIT_SAT + 1).to_string().into(), "amount out of range");
    refused("amountSat", "18446744073709551616".into(), "integer overflow");
    refused("amountSat", "01000000".into(), "noncanonical integer");
    refused("amountSat", "-1000000".into(), "noncanonical integer");
    refused("amountSat", "1e9".into(), "noncanonical integer");
    refused("amountSat", json!(1_000_000_000u64), "missing string");
    // The minimum itself is a deposit.
    let minimum = set(&deposit_args(), "amountSat", MIN_L2_DEPOSIT_SAT.to_string().into());
    assert_eq!(call("review", minimum).unwrap()["amountSat"], MIN_L2_DEPOSIT_SAT.to_string());
}

#[test]
fn more_than_128_inputs_none_or_a_duplicate_are_refused() {
    open();
    let rows = |n: usize| -> Vec<Value> {
        (0..n).map(|i| json!({"txidHex": "34".repeat(32), "vout": i, "valueSat": "20000000"})).collect()
    };
    refused("inputs", rows(MAX_DEPOSIT_INPUTS + 1).into(), "funding bound");
    refused("inputs", json!([]), "funding bound");
    refused("inputs", json!(null), "missing funding");
    let mut twice = rows(2);
    twice[1] = twice[0].clone();
    refused("inputs", twice.into(), "duplicate input");
    refused("inputs.0.valueSat", "0".into(), "empty input");
    refused("inputs.0.txidHex", "34".repeat(31).into(), "invalid hash");
    refused("inputs.0.vout", json!(4294967296u64), "integer overflow");
    refused("inputs.0.vout", json!(-1), "noncanonical integer");
    refused("inputs.0.vout", json!(1.5), "noncanonical integer");
    refused("inputs.0.extra", json!(1), "unsupported field");
    // Exactly 128 is the protocol's bound and is accepted, sorted.
    let full = set(&deposit_args(), "inputs", rows(MAX_DEPOSIT_INPUTS).into());
    let (review, signed) = review_and_sign(&full);
    assert_eq!(review["inputCount"], MAX_DEPOSIT_INPUTS);
    let tx = decode(&signed);
    assert_eq!(tx.inputs.len(), MAX_DEPOSIT_INPUTS);
    assert!(tx.inputs.windows(2).all(|w| w[0] < w[1]));
    assert!(crypto::verify(&tx.funding_pubkey, &tx.intent_root(), &tx.signature));
    // The largest deposit still passes the node's relay bounds: inside the
    // block byte budget, the gas ceiling and the over-declaration slack.
    let encoded = PosTransaction::L2Deposit(tx.clone()).canonical_bytes().len() as u64;
    assert!(encoded.max(tx.tx_bytes) <= fee_market::max_block_tx_bytes(0).min(fee_market::max_block_tx_bytes(u64::MAX)));
    assert!(tx.tx_bytes <= encoded + fee_market::TX_BYTES_DECLARE_SLACK);
    let class = fee_market::TxClass::Eutxo { inputs: MAX_DEPOSIT_INPUTS as u32 };
    assert!(fee_market::intrinsic_gas(class, tx.tx_bytes) <= fee_market::MAX_TX_GAS);
}

#[test]
fn a_tip_above_the_protocol_ceiling_or_a_base_fee_out_of_range_is_refused() {
    open();
    refused("tipMillisatPerGas", (fee_market::MAX_TIP_MILLISAT_PER_GAS + 1).to_string().into(), "tip above ceiling");
    refused("tipMillisatPerGas", u128::MAX.to_string().into(), "tip above ceiling");
    refused("baseFeeMillisatPerGas", (fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS - 1).to_string().into(), "invalid fee");
    refused("baseFeeMillisatPerGas", (fee_market::MAX_BASE_FEE_MILLISAT_PER_GAS + 1).to_string().into(), "invalid fee");
    refused("baseFeeMillisatPerGas", json!(10), "missing string");
    // The ceiling itself is a valid tip; these inputs cannot pay it.
    refused("tipMillisatPerGas", fee_market::MAX_TIP_MILLISAT_PER_GAS.to_string().into(), "inputs do not cover the amount plus fee");
}

#[test]
fn inputs_that_do_not_cover_amount_plus_fee_are_refused() {
    open();
    // 15 BLCH of inputs: the amount alone fits, the fee does not.
    refused("amountSat", "1500000000".into(), "inputs do not cover the amount plus fee");
    refused("amountSat", "1500000001".into(), "inputs do not cover the amount plus fee");
    let fee: u64 = call("review", deposit_args()).unwrap()["feeSat"].as_str().unwrap().parse().unwrap();
    // One satoshi short of amount + fee, then exactly amount + fee (no change).
    refused("amountSat", (1_500_000_000 - fee + 1).to_string().into(), "inputs do not cover the amount plus fee");
    let exact = set(&deposit_args(), "amountSat", (1_500_000_000 - fee).to_string().into());
    let (review, signed) = review_and_sign(&exact);
    assert_eq!(review["changeSat"], "0");
    assert_eq!(decode(&signed).change.value, 0);
}

#[test]
fn funding_that_names_another_owner_is_refused() {
    open();
    let owner = digest(&v1().0);
    let mut carried = [0u8; 32];
    carried[..20].copy_from_slice(&owner[..20]);
    for mine in [owner, carried] {
        let args = set(&deposit_args(), "inputs.0.scriptHashHex", hex::encode(mine).into());
        assert!(call("review", args).is_ok(), "the node's ownership rule: full or carried key hash");
    }
    refused("inputs.0.scriptHashHex", hex::encode(digest(&v2().0)).into(), "funding owner mismatch");
    let mut almost = carried;
    almost[31] = 1;
    refused("inputs.0.scriptHashHex", hex::encode(almost).into(), "funding owner mismatch");
}

#[test]
fn sign_refuses_any_difference_from_the_review() {
    open();
    let args = deposit_args();
    for (path, value) in [
        ("amountSat", json!("1000000001")),
        ("recipientHex", json!("43".repeat(20))),
        // Altered input between review and sign: outpoint, then value (which
        // moves only the change).
        ("inputs.0.txidHex", json!("35".repeat(32))),
        ("inputs.0.vout", json!(2)),
        ("inputs.0.valueSat", json!("900000001")),
        ("inputs.1.valueSat", json!("599999999")),
        ("baseFeeMillisatPerGas", json!("11")),
        ("tipMillisatPerGas", json!("1")),
    ] {
        let review = call("review", args.clone()).unwrap();
        let changed = with_review(&set(&args, path, value), &review);
        assert_eq!(call("sign", changed), Err("review changed"), "{path}");
        // The refused attempt consumed the review: the original no longer signs.
        assert_eq!(call("sign", with_review(&args, &review)), Err("review required"), "{path}");
    }
    // An added or removed input.
    let review = call("review", args.clone()).unwrap();
    let mut more = args.clone();
    more["inputs"].as_array_mut().unwrap().push(json!({"txidHex": "56".repeat(32), "vout": 0, "valueSat": "1"}));
    assert_eq!(call("sign", with_review(&more, &review)), Err("review changed"));
    let review = call("review", args.clone()).unwrap();
    let mut fewer = set(&args, "amountSat", "100000000".into());
    fewer["inputs"].as_array_mut().unwrap().pop();
    assert_eq!(call("sign", with_review(&fewer, &review)), Err("review changed"));
}

#[test]
fn a_change_or_fee_that_differs_from_the_review_is_refused() {
    open();
    let args = deposit_args();
    let review = call("review", args.clone()).unwrap();
    let change: u64 = review["changeSat"].as_str().unwrap().parse().unwrap();
    let fee: u64 = review["feeSat"].as_str().unwrap().parse().unwrap();
    for (field, value) in [("changeSat", change + 1), ("changeSat", change - 1), ("feeSat", fee + 1), ("feeSat", 0)] {
        let review = call("review", args.clone()).unwrap();
        let mut signing = with_review(&args, &review);
        signing[field] = value.to_string().into();
        assert_eq!(call("sign", signing), Err("review changed"), "{field} {value}");
        assert_eq!(call("sign", with_review(&args, &review)), Err("review required"));
    }
    // Echoing the reviewed values signs.
    let review = call("review", args.clone()).unwrap();
    let mut signing = with_review(&args, &review);
    signing["changeSat"] = review["changeSat"].clone();
    signing["feeSat"] = review["feeSat"].clone();
    let signed = call("sign", signing).unwrap();
    assert_eq!(decode(&signed).change.value, change);
}

#[test]
fn a_review_id_signs_once_and_only_its_own_review() {
    open();
    let args = deposit_args();
    // No review at all.
    let mut blind = args.clone();
    blind["reviewId"] = "00".repeat(32).into();
    assert_eq!(call("sign", blind), Err("review required"));
    // Reused.
    let (review, _) = review_and_sign(&args);
    assert_eq!(call("sign", with_review(&args, &review)), Err("review required"));
    // A newer review replaces the older one.
    let first = call("review", args.clone()).unwrap();
    let other = set(&args, "amountSat", "1100000000".into());
    let second = call("review", other.clone()).unwrap();
    assert_ne!(first["reviewId"], second["reviewId"]);
    assert_eq!(call("sign", with_review(&args, &first)), Err("review changed"));
    assert_eq!(call("sign", with_review(&other, &second)), Err("review required"));
    // A wrong, missing or malformed fingerprint consumes the review too.
    for bad in [json!("11".repeat(32)), json!(null), json!("11")] {
        let review = call("review", args.clone()).unwrap();
        let mut signing = args.clone();
        signing["reviewId"] = bad;
        assert!(call("sign", signing).is_err());
        assert_eq!(call("sign", with_review(&args, &review)), Err("review required"));
    }
    // `review` itself does not accept sign-only fields.
    assert_eq!(call("review", with_review(&args, &first)), Err("unsupported field"));
}

#[test]
fn cancel_and_any_failed_call_invalidate_the_pending_review() {
    open();
    let args = deposit_args();
    let review = call("review", args.clone()).unwrap();
    assert_eq!(call("cancel", json!({})).unwrap(), json!({"cancelled": true}));
    assert_eq!(call("sign", with_review(&args, &review)), Err("review required"));
    // A refused review clears the earlier consent.
    let review = call("review", args.clone()).unwrap();
    assert!(call("review", set(&args, "amountSat", "1".into())).is_err());
    assert_eq!(call("sign", with_review(&args, &review)), Err("review required"));
    // So does an unknown method.
    let review = call("review", args.clone()).unwrap();
    assert_eq!(call("sign_digest", json!({"digestHex": "00".repeat(32)})), Err("unsupported method"));
    assert_eq!(call("sign", with_review(&args, &review)), Err("review required"));
}

#[test]
fn a_locked_session_refuses_everything() {
    let args = deposit_args();
    // Never opened.
    for method in ["review", "sign", "cancel"] {
        assert_eq!(call(method, args.clone()), Err("locked"), "{method}");
    }
    open();
    let review = call("review", args.clone()).unwrap();
    assert_eq!(call("lock", json!({})).unwrap(), json!({"locked": true}));
    assert_eq!(call("sign", with_review(&args, &review)), Err("locked"));
    assert_eq!(call("review", args.clone()), Err("locked"));
    assert_eq!(call("cancel", json!({})), Err("locked"));
    assert_eq!(call("lock", json!({})).unwrap(), json!({"locked": true}), "lock is idempotent");
    // Reopening does not revive the old consent.
    open();
    assert_eq!(call("sign", with_review(&args, &review)), Err("review required"));
}

#[test]
fn there_is_no_digest_signing_and_no_key_export() {
    open();
    for method in ["sign_digest", "sign_message", "export", "export_secret", "get_secret", "open", "debug"] {
        assert_eq!(call(method, json!({})), Err("unsupported method"), "{method}");
    }
    // No reply of the whole flow contains secret key material or the phrase.
    let secret = hex::encode(&v1().1);
    let needle = &secret[secret.len() - 64..];
    let (review, signed) = review_and_sign(&deposit_args());
    for reply in [call("open_mnemonic", open_args()).unwrap(), review, signed, call("lock", json!({})).unwrap()] {
        let text = reply.to_string();
        assert!(!text.contains(needle) && !text.contains("abandon"));
    }
}

#[test]
fn the_exported_abi_round_trips_through_bounded_buffers() {
    let abi = |request: Value| -> Value {
        let bytes = serde_json::to_vec(&request).unwrap();
        let ptr = nw_alloc(bytes.len() as u32);
        assert_ne!(ptr, 0);
        BUFFERS.with(|b| b.borrow_mut().get_mut(&ptr).unwrap().copy_from_slice(&bytes));
        let packed = nw_call(ptr, bytes.len() as u32);
        nw_free(ptr, bytes.len() as u32);
        // The packed pointer is 32 bits (the ABI is wasm32); on a 64-bit
        // test host the reply is found as the one buffer still allocated.
        let len = packed as u32;
        let (out, reply) = BUFFERS.with(|b| {
            let map = b.borrow();
            assert_eq!(map.len(), 1);
            let (out, bytes) = map.iter().next().unwrap();
            assert_eq!(bytes.len(), len as usize);
            assert_eq!(*out as u32, (packed >> 32) as u32);
            (*out, serde_json::from_slice(bytes).unwrap())
        });
        nw_free(out, len);
        assert!(BUFFERS.with(|b| b.borrow().is_empty()));
        reply
    };
    assert_eq!(abi(json!({"method": "review", "args": deposit_args()})), json!({"ok": false, "error": "locked"}));
    assert_eq!(abi(json!({"method": "open_mnemonic", "args": open_args()}))["ok"], true);
    let review = abi(json!({"method": "review", "args": deposit_args()}));
    assert_eq!(review["ok"], true);
    let signed = abi(json!({"method": "sign", "args": with_review(&deposit_args(), &review["result"])}));
    assert_eq!(signed["ok"], true);
    assert!(signed["result"]["transactionHex"].as_str().unwrap().starts_with("14"));
    assert_eq!(nw_alloc(0), 0);
    assert_eq!(nw_alloc(MAX as u32 + 1), 0);
    assert_eq!(nw_call(12345, 7) as u32 as usize, br#"{"error":"invalid buffer","ok":false}"#.len());
}

// ── State level: the node's own admission and transition checks ─────────────

#[cfg(feature = "state-acceptance")]
mod state {
    use super::*;
    use bloch_pos_committee::{
        l2_settlement::Policy,
        state_root::{EutxoEntry, EvmCommitment},
        transition::L2DepositReject,
        BlockHeaderV4, BlockId, CommittedState, GenesisValidator, VERSION_G4,
    };

    /// A committed state bound to `domain`, with an asynchronous L2 whose
    /// profile admits deposits, opening with `coins`.
    fn committed(domain: [u8; 32], coins: &[EutxoEntry]) -> CommittedState {
        let block = BlockId::of(&BlockHeaderV4 {
            version: VERSION_G4,
            parent: [0; 32],
            state_root: [0; 32],
            body_root: [0; 32],
            slot: 0,
            proposer_index: 0,
            randao_reveal: [0; 32],
            randao_mix: [0; 32],
            justified_root: [0; 32],
            finalized_root: [0; 32],
            attestation_root: [0; 32],
            coherence_root: [0; 32],
        });
        let validators: Vec<GenesisValidator> = (0..4u32)
            .map(|i| GenesisValidator {
                index: i,
                pubkey: vec![i as u8; 8],
                staked_sat: 200_000 * 100_000_000,
                randao_commitment: [i as u8 + 1; 32],
                withdrawal_credentials: vec![i as u8; 4],
                commission_bps: 500,
            })
            .collect();
        let state = CommittedState::genesis_with_network_domain(
            domain,
            block,
            [0x07; 32],
            &validators,
            &[],
            [0x11; 32],
            [0x22; 32],
            [0x33; 32],
            EvmCommitment { account_root: [0x44; 32], receipts_root: [0x55; 32], gas_used: 0, base_fee_per_gas: 1 },
            coins,
        );
        let mut identities = [[0x61; 32]; 7];
        identities[0] = domain;
        identities[1] = *state.head().as_bytes();
        let state = state
            .configure_l2_genesis_async(Policy {
                identities,
                proof_policy: [0x77; 32],
                chain_id: 700770,
                initial_l2_parent: [0x78; 32],
                initial_l2_state: [0x79; 32],
                attestor_set: [0; 32],
            })
            .unwrap();
        assert!(state.l2_settlement().unwrap().deposits_enabled());
        state
    }
    fn mainnet() -> [u8; 32] {
        hex::decode(DOMAIN).unwrap().try_into().unwrap()
    }
    fn coins(owner: [u8; 32]) -> Vec<EutxoEntry> {
        vec![
            EutxoEntry { txid: [0x34; 32], vout: 1, value: 900_000_000, script_hash: owner },
            EutxoEntry { txid: [0x12; 32], vout: 0, value: 600_000_000, script_hash: owner },
        ]
    }

    /// `l2_deposit_refusal_at` is the node's mempool door for 0x14
    /// (`engine/admission.rs`) and runs `check_l2_deposit`, the function
    /// `apply_l2_deposit` runs before the signature: activation, shape
    /// (`validate_shape`), network, tip and gas ceilings, input existence and
    /// ownership, exact conservation, output collision, inbox capacity. With
    /// the real hybrid signature verified as well, nothing in the transition
    /// can refuse this deposit in this state.
    #[test]
    fn the_committed_state_admits_the_signed_deposit() {
        open();
        let (_, signed) = review_and_sign(&deposit_args());
        let tx = decode(&signed);
        let owner = digest(&v1().0);
        let state = committed(mainnet(), &coins(owner));
        let base_fee = state.next_base_fee();
        assert_eq!(base_fee, 10, "the request was priced at this state's next base fee");
        assert_eq!(state.l2_deposit_refusal_at(&tx, base_fee), None);
        assert!(crypto::verify(&tx.funding_pubkey, &tx.intent_root(), &tx.signature));

        // Carried outputs (20-byte key hash, twelve zero bytes) are spendable too.
        let mut carried = [0u8; 32];
        carried[..20].copy_from_slice(&owner[..20]);
        assert_eq!(committed(mainnet(), &coins(carried)).l2_deposit_refusal_at(&tx, base_fee), None);

        // The same check is not vacuous: each wrong context is refused by name.
        use L2DepositReject as R;
        assert_eq!(committed([0x91; 32], &coins(owner)).l2_deposit_refusal_at(&tx, base_fee), Some(R::Network));
        assert_eq!(committed(mainnet(), &coins(digest(&v2().0))).l2_deposit_refusal_at(&tx, base_fee), Some(R::Ownership));
        assert_eq!(committed(mainnet(), &coins(owner)[..1]).l2_deposit_refusal_at(&tx, base_fee), Some(R::MissingInput));
        assert_eq!(state.l2_deposit_refusal_at(&tx, base_fee + 1), Some(R::Conservation), "priced at another base fee");
        let mut richer = coins(owner);
        richer[0].value += 1;
        assert_eq!(committed(mainnet(), &richer).l2_deposit_refusal_at(&tx, base_fee), Some(R::Conservation), "a wrong input value");
        let mut altered = tx.clone();
        altered.change.value += 1;
        assert_eq!(state.l2_deposit_refusal_at(&altered, base_fee), Some(R::Conservation));
        let mut unsigned = tx.clone();
        unsigned.signature.clear();
        assert_eq!(state.l2_deposit_refusal_at(&unsigned, base_fee), Some(R::Shape));
    }

    /// What the December line does once `params::L2_REVENUE_EPOCH` is armed:
    /// it adds `l2_revenue::deposit_fee_sat(amount)` to the required inputs,
    /// so a deposit built by this signer is short by exactly that fee and is
    /// refused with `Conservation`. Here the same shortfall is produced with
    /// an input one protocol fee poorer (5 bps, floor 5,000 sat, cap 1 BLCH).
    #[test]
    fn a_deposit_without_the_future_protocol_fee_would_fail_conservation() {
        open();
        let (_, signed) = review_and_sign(&deposit_args());
        let tx = decode(&signed);
        let protocol_fee = (tx.amount_sat / 10_000 * 5).clamp(5_000, 100_000_000);
        assert_eq!(protocol_fee, 500_000);
        let mut poorer = coins(digest(&v1().0));
        poorer[0].value -= protocol_fee;
        let state = committed(mainnet(), &poorer);
        assert_eq!(state.l2_deposit_refusal_at(&tx, state.next_base_fee()), Some(L2DepositReject::Conservation));
    }
}

// ── Public fixture ──────────────────────────────────────────────────────────

/// With `L2_DEPOSIT_WALLET_FIXTURE=<path>` this writes one complete
/// `open_mnemonic -> review -> sign` run (requests and replies) for the
/// wallet's browser tests. The committed copy is checked by the next test.
#[test]
fn export_the_public_fixture_when_asked() {
    let Ok(path) = std::env::var("L2_DEPOSIT_WALLET_FIXTURE") else { return };
    let request = |method: &str, args: Value| json!({"method": method, "args": args});
    let reply = |r: Result<Value>| match r {
        Ok(v) => json!({"ok": true, "result": v}),
        Err(e) => json!({"ok": false, "error": e}),
    };
    let args = deposit_args();
    let opened = call("open_mnemonic", open_args());
    let review = call("review", args.clone());
    let signing = with_review(&args, review.as_ref().unwrap());
    let signed = call("sign", signing.clone());
    let replay = call("sign", signing.clone());
    let locked = call("lock", json!({}));
    let unsigned_hex = {
        let mut unsigned = decode(signed.as_ref().unwrap());
        unsigned.signature = Vec::new();
        let bytes = PosTransaction::L2Deposit(unsigned).canonical_bytes();
        hex::encode(&bytes[..bytes.len() - 4])
    };
    let steps = vec![
        json!({"request": request("open_mnemonic", open_args()), "response": reply(opened)}),
        json!({"request": request("review", args), "response": reply(review)}),
        json!({"request": request("sign", signing.clone()), "response": reply(signed)}),
        json!({"request": request("sign", signing), "response": reply(replay), "note": "the review is single-use"}),
        json!({"request": request("lock", json!({})), "response": reply(locked)}),
    ];
    let fixture = json!({
        "description": "Bloch L1 -> L2 deposit signer (wire 0x14): one full open_mnemonic -> review -> sign run. PUBLIC TEST DATA: the mnemonic is the published BIP39 test vector; the inputs do not exist on any network. Never fund this account.",
        "wasm": "bloch_l2_deposit_wallet_wasm.wasm",
        "publicFixtureMnemonic": PHRASE,
        "seedVersion": "v1-pbkdf2-sha256",
        "domainHex": DOMAIN,
        "publicKeyHex": hex::encode(&v1().0),
        "ownerHashHex": hex::encode(digest(&v1().0)),
        "deterministic": "Every reply is deterministic except sign.result.transactionHex: the hybrid signature is randomized, so only its unsigned prefix (unsignedTransactionHex, then a 4-byte little-endian signature length) and its txid are fixed. Verify a fresh signature with the node's verifier, not by comparing bytes.",
        "unsignedTransactionHex": unsigned_hex,
        "steps": steps,
    });
    std::fs::write(path, serde_json::to_vec_pretty(&fixture).unwrap()).unwrap();
}

/// The committed fixture is still what this signer and the node agree on.
/// `L2_DEPOSIT_BROWSER_SIGNATURES=<path>` additionally checks an array of
/// `sign` results produced by the WASM in a browser or under Node.
#[test]
fn the_committed_fixture_is_what_the_signer_and_the_node_agree_on() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    assert_eq!(fixture["domainHex"], DOMAIN);
    assert_eq!(fixture["publicFixtureMnemonic"], PHRASE);
    assert_eq!(fixture["publicKeyHex"], hex::encode(&v1().0));
    let steps = fixture["steps"].as_array().unwrap();
    let run = |i: usize| -> Value {
        match dispatch(steps[i]["request"].clone()) {
            Ok(v) => json!({"ok": true, "result": v}),
            Err(e) => json!({"ok": false, "error": e}),
        }
    };
    // Replayed in order: every deterministic reply is reproduced exactly.
    assert_eq!(run(0), steps[0]["response"]);
    assert_eq!(run(1), steps[1]["response"]);
    let fresh = run(2);
    let recorded = &steps[2]["response"]["result"];
    for field in ["txid", "feeSat", "changeSat"] {
        assert_eq!(fresh["result"][field], recorded[field], "{field}");
    }
    assert_eq!(run(3), steps[3]["response"]);
    assert_eq!(run(4), steps[4]["response"]);

    let check = |signed: &Value| {
        let tx = decode(signed);
        let wire = PosTransaction::L2Deposit(tx.clone());
        assert_eq!(signed["txid"], hex::encode(wire.txid()));
        assert_eq!(signed["txid"], recorded["txid"]);
        assert!(crypto::verify(&tx.funding_pubkey, &tx.intent_root(), &tx.signature));
        assert!(crypto::verify_pinned(&tx.funding_pubkey, &tx.intent_root(), &tx.signature));
        let unsigned = fixture["unsignedTransactionHex"].as_str().unwrap();
        let text = signed["transactionHex"].as_str().unwrap();
        assert!(text.starts_with(unsigned));
        assert_eq!(text.len(), unsigned.len() + 8 + tx.signature.len() * 2);
    };
    check(recorded);
    check(&fresh["result"]);
    if let Ok(path) = std::env::var("L2_DEPOSIT_BROWSER_SIGNATURES") {
        let signed: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert!(!signed.as_array().unwrap().is_empty());
        for value in signed.as_array().unwrap() {
            check(value);
        }
    }
}
