// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tests for the partner-send core. The properties that matter are the
//! refusals — this is a tool whose value is what it will NOT do — plus exact
//! agreement with the consensus crate on fees, roots and encodings.

use super::*;
use bloch_pos_committee::fee_market;

fn addr(byte: u8) -> Address {
    Address::from_hash([byte; 20], Network::Mainnet)
}

fn taddr(byte: u8) -> Address {
    Address::from_hash([byte; 20], Network::Testnet)
}

fn coin(seed: u8, value_sat: u64) -> Coin {
    Coin { txid: [seed; 32], vout: 0, value_sat }
}

const BASE: u128 = 10; // the live floor base fee
const TIP: u128 = DEFAULT_TIP_MILLISAT_PER_GAS;

// ── Amount parsing ──────────────────────────────────────────────────────────

#[test]
fn parse_blch_accepts_exact_decimals() {
    assert_eq!(parse_blch("25"), Ok(25 * SAT_PER_BLCH));
    assert_eq!(parse_blch("0.5"), Ok(50_000_000));
    assert_eq!(parse_blch("1.00000001"), Ok(100_000_001));
    assert_eq!(parse_blch("0.00000546"), Ok(546));
    assert_eq!(parse_blch(".5"), Ok(50_000_000));
    assert_eq!(parse_blch("10000"), Ok(MAX_PARTNER_SEND_SAT));
}

#[test]
fn parse_blch_refuses_everything_else() {
    for bad in [
        "", " ", ".", "-1", "+1", "1e3", "1,5", "1.000000001", "0", "0.0", "1.2.3", "abc",
        "1 BLCH", "0x10",
    ] {
        assert!(parse_blch(bad).is_err(), "`{bad}` must be refused");
    }
}

#[test]
fn blch_roundtrip() {
    for sat in [1u64, 546, 50_000_000, 100_000_001, MAX_PARTNER_SEND_SAT] {
        assert_eq!(parse_blch(&format_blch(sat)), Ok(sat), "roundtrip {sat}");
    }
}

// ── script_hash derivation ──────────────────────────────────────────────────

#[test]
fn script_hash_is_the_20_byte_hash_zero_padded() {
    let a = addr(0xAB);
    let sh = script_hash32(&a);
    assert_eq!(&sh[..20], &[0xAB; 20]);
    assert_eq!(&sh[20..], &[0u8; 12]);
}

/// The exact padding consensus accepts: `owns()` in the committee crate takes
/// key_hash[..20] == script_hash[..20] with a zero tail. A pubkey whose
/// SHA3-256 starts with the address hash must own the padded script.
#[test]
fn script_hash_padding_matches_consensus_owns_rule() {
    use sha3::{Digest, Sha3_256};
    let pubkey = b"any bytes stand in for a hybrid key here";
    let digest: [u8; 32] = Sha3_256::digest(pubkey).into();
    let mut h20 = [0u8; 20];
    h20.copy_from_slice(&digest[..20]);
    let a = Address::from_hash(h20, Network::Mainnet);
    let sh = script_hash32(&a);
    // Reproduce owns() (it is private): zero tail + 20-byte prefix match.
    assert_eq!(&sh[20..], &[0u8; 12]);
    assert_eq!(&digest[..20], &sh[..20]);
    // And from_pubkey agrees end-to-end.
    assert_eq!(Address::from_pubkey(pubkey, Network::Mainnet), a);
}

// ── Refusals ────────────────────────────────────────────────────────────────

#[test]
fn refuses_cross_network_and_self_send() {
    let coins = [coin(1, 10 * SAT_PER_BLCH)];
    assert!(matches!(
        build_plan(&addr(1), &taddr(2), SAT_PER_BLCH, &coins, BASE, TIP),
        Err(PlanError::NetworkMismatch { .. })
    ));
    assert_eq!(
        build_plan(&addr(1), &addr(1), SAT_PER_BLCH, &coins, BASE, TIP),
        Err(PlanError::SelfSend)
    );
}

#[test]
fn refuses_sub_dust_amount_and_the_hard_cap() {
    let coins = [coin(1, MAX_PARTNER_SEND_SAT * 2)];
    assert_eq!(
        build_plan(&addr(1), &addr(2), DUST_THRESHOLD_SAT - 1, &coins, BASE, TIP),
        Err(PlanError::AmountBelowDust { amount_sat: DUST_THRESHOLD_SAT - 1 })
    );
    assert_eq!(
        build_plan(&addr(1), &addr(2), MAX_PARTNER_SEND_SAT + 1, &coins, BASE, TIP),
        Err(PlanError::AmountAboveCap { amount_sat: MAX_PARTNER_SEND_SAT + 1 })
    );
    // The cap itself is sendable — the boundary is inclusive.
    assert!(build_plan(&addr(1), &addr(2), MAX_PARTNER_SEND_SAT, &coins, BASE, TIP).is_ok());
}

#[test]
fn refuses_insufficient_funds_with_the_real_need() {
    let coins = [coin(1, SAT_PER_BLCH)];
    let err = build_plan(&addr(1), &addr(2), SAT_PER_BLCH, &coins, BASE, TIP).unwrap_err();
    match err {
        PlanError::InsufficientFunds { need_sat, have_sat } => {
            assert_eq!(have_sat, SAT_PER_BLCH as u128);
            // need = amount + the one-input fee, exactly as the fee market prices it
            let c = fee_market::charge(
                fee_market::TxClass::Eutxo { inputs: 1 },
                planned_tx_bytes(1),
                BASE,
                TIP,
            );
            assert_eq!(need_sat, SAT_PER_BLCH as u128 + c.base_fee_sat + c.priority_fee_sat);
        }
        other => panic!("expected InsufficientFunds, got {other:?}"),
    }
}

/// THE dust rule: a selection that would leave 1..546 sat of change is
/// refused, and both suggested amounts actually plan cleanly.
#[test]
fn refuses_sub_dust_change_and_its_suggestions_work() {
    let fee = {
        let c = fee_market::charge(
            fee_market::TxClass::Eutxo { inputs: 1 },
            planned_tx_bytes(1),
            BASE,
            TIP,
        );
        (c.base_fee_sat + c.priority_fee_sat) as u64
    };
    let amount = SAT_PER_BLCH;
    // One coin engineered to leave exactly 100 sat of change.
    let coins = [coin(1, amount + fee + 100)];
    let err = build_plan(&addr(1), &addr(2), amount, &coins, BASE, TIP).unwrap_err();
    let PlanError::DustChange { change_sat, send_less_sat, send_more_sat } = err else {
        panic!("expected DustChange, got {err:?}");
    };
    assert_eq!(change_sat, 100);
    assert_eq!(send_less_sat, amount - 446); // change lands exactly on 546
    assert_eq!(send_more_sat, amount + 100); // change becomes exactly 0

    let less = build_plan(&addr(1), &addr(2), send_less_sat, &coins, BASE, TIP).unwrap();
    assert_eq!(less.change_sat, DUST_THRESHOLD_SAT);
    let more = build_plan(&addr(1), &addr(2), send_more_sat, &coins, BASE, TIP).unwrap();
    assert_eq!(more.change_sat, 0);
}

/// A dust trap on one coin is escaped by taking a second coin when one
/// exists — refusal is the last resort, not the first.
#[test]
fn dust_trap_is_escaped_by_adding_an_input() {
    let fee1 = {
        let c = fee_market::charge(
            fee_market::TxClass::Eutxo { inputs: 1 },
            planned_tx_bytes(1),
            BASE,
            TIP,
        );
        (c.base_fee_sat + c.priority_fee_sat) as u64
    };
    let amount = SAT_PER_BLCH;
    let coins = [coin(1, amount + fee1 + 100), coin(2, SAT_PER_BLCH)];
    let plan = build_plan(&addr(1), &addr(2), amount, &coins, BASE, TIP).unwrap();
    assert_eq!(plan.inputs.len(), 2);
    assert!(plan.change_sat >= DUST_THRESHOLD_SAT);
}

#[test]
fn refuses_a_fee_above_the_sanity_cap() {
    // An absurd base fee (price spike / misread node) must stop the tool.
    let coins = [coin(1, MAX_PARTNER_SEND_SAT * 3)];
    let err = build_plan(&addr(1), &addr(2), SAT_PER_BLCH, &coins, 1_000_000_000, TIP);
    assert!(
        matches!(err, Err(PlanError::FeeAboveSanityCap { .. })),
        "a 1e9-millisat/gas base fee must be refused, got {err:?}"
    );
}

#[test]
fn refuses_fragmentation_beyond_max_inputs() {
    // 200 small coins: the 32 largest cover 32M sat (< 1 BLCH + fee), the
    // full 200 cover 200M — the balance exists, one send cannot reach it.
    let coins: Vec<Coin> =
        (0..200).map(|i| Coin { txid: [i as u8; 32], vout: i, value_sat: 1_000_000 }).collect();
    let err = build_plan(&addr(1), &addr(2), SAT_PER_BLCH, &coins, BASE, TIP).unwrap_err();
    assert_eq!(err, PlanError::TooManyInputs { needed_more_than: MAX_INPUTS });
}

// ── Agreement with consensus ────────────────────────────────────────────────

fn good_plan() -> Plan {
    let coins = [coin(7, 10 * SAT_PER_BLCH), coin(9, SAT_PER_BLCH)];
    build_plan(&addr(1), &addr(2), SAT_PER_BLCH, &coins, BASE, TIP).unwrap()
}

/// Exact conservation — the chain's own equality, `spent == created + fee`.
#[test]
fn plan_conserves_value_exactly() {
    let plan = good_plan();
    let spent: u128 = plan.inputs.iter().map(|i| i.value_sat as u128).sum();
    assert_eq!(
        spent,
        plan.amount_sat as u128
            + plan.change_sat as u128
            + plan.base_fee_sat
            + plan.tip_fee_sat
    );
    check_plan_integrity(&plan).unwrap();
}

/// The fee in the plan IS the consensus fee for its terms — computed by the
/// same crate, asserted term by term.
#[test]
fn plan_fee_is_the_fee_market_fee() {
    let plan = good_plan();
    let c = fee_market::charge(
        fee_market::TxClass::Eutxo { inputs: plan.inputs.len() as u32 },
        plan.tx_bytes,
        plan.base_fee_millisat_per_gas,
        plan.tip_millisat_per_gas,
    );
    assert_eq!(plan.gas, c.gas);
    assert_eq!(plan.base_fee_sat, c.base_fee_sat);
    assert_eq!(plan.tip_fee_sat, c.priority_fee_sat);
}

/// The signing root is witness-free: filling in a pubkey and signature does
/// not move it, which is what lets the preview show the root before the key
/// is touched.
#[test]
fn signing_root_is_witness_free_and_matches_the_plan() {
    let plan = good_plan();
    let unsigned = transfer_from_plan(&plan, &[], &[]).unwrap();
    let witnessed = transfer_from_plan(&plan, b"key bytes", b"sig bytes").unwrap();
    assert_eq!(unsigned.spend_signing_root(), witnessed.spend_signing_root());
    assert_eq!(hex::encode(unsigned.spend_signing_root()), plan.signing_root);
    assert_eq!(hex::encode(unsigned.txid()), plan.txid);
}

/// Tampering with any field after planning is caught: the integrity check
/// recomputes the root from the fields, so the file is data, not authority.
#[test]
fn integrity_check_catches_a_tampered_plan() {
    let mut p = good_plan();
    p.amount_sat += 1;
    assert!(check_plan_integrity(&p).is_err());

    let mut p = good_plan();
    p.to_address = addr(3).to_string();
    assert!(check_plan_integrity(&p).is_err());

    let mut p = good_plan();
    p.change_sat = 100; // sub-dust smuggled into the file
    assert!(check_plan_integrity(&p).is_err());

    let mut p = good_plan();
    p.base_fee_sat += 1; // breaks conservation AND the fee-market match
    assert!(check_plan_integrity(&p).is_err());
}

// ── Real hybrid keys, end to end ────────────────────────────────────────────

/// One real keygen + sign, shared by the expensive tests (hybrid keygen is
/// slow enough to do once).
fn real_key() -> &'static (Vec<u8>, Vec<u8>) {
    use std::sync::OnceLock;
    static KEY: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
    KEY.get_or_init(bloch_crypto::crypto::generate_keypair)
}

/// The tx_bytes budgets hold for a real enveloped hybrid witness — the
/// property that keeps `UnderdeclaredSize` unreachable from this tool.
#[test]
fn budget_fits_a_real_hybrid_witness() {
    let (pk, sk) = real_key();
    let sig = bloch_crypto::crypto::sign(sk, &[7u8; 32]).unwrap();
    assert!(pk.len() as u64 <= 3_800, "pubkey {} bytes exceeds budget", pk.len());
    assert!(sig.len() as u64 <= 4_700, "signature {} bytes exceeds budget", sig.len());
}

/// Full path: plan → sign → checked broadcastable bytes → decode roundtrip.
/// The decoded transaction must be the planned one, bit for bit.
#[test]
fn sign_plan_produces_broadcastable_bytes_that_decode_back() {
    use bloch_pos_committee::transition::PosTransaction;
    let (pk, sk) = real_key();
    let from = Address::from_pubkey(pk, Network::Mainnet);
    let coins = [coin(7, 10 * SAT_PER_BLCH)];
    let plan = build_plan(&from, &addr(2), SAT_PER_BLCH, &coins, BASE, TIP).unwrap();

    let signed = sign_plan(&plan, pk, sk).unwrap();
    let raw = check_signed_plan(&signed).unwrap();
    assert!((raw.len() as u64) <= plan.tx_bytes, "encoding must fit the declared size");

    let decoded = PosTransaction::from_canonical_bytes(&raw).unwrap();
    assert_eq!(hex::encode(decoded.txid()), plan.txid);
}

/// The wrong key is refused BEFORE signing: ownership is checked against the
/// source address, so a mixed-up keystore cannot produce a doomed (or worse,
/// wrong-source) transaction.
#[test]
fn sign_plan_refuses_a_key_that_does_not_own_the_source() {
    let (pk, sk) = real_key();
    let plan = good_plan(); // source addr(1), which this key does not own
    let err = sign_plan(&plan, pk, sk).unwrap_err();
    assert!(err.contains("does not own the source address"), "{err}");
}

/// A tampered SignedPlan is refused at broadcast: raw bytes that differ from
/// the plan, or a signature that does not verify, never leave the machine.
#[test]
fn check_signed_plan_catches_tampering() {
    let (pk, sk) = real_key();
    let from = Address::from_pubkey(pk, Network::Mainnet);
    let coins = [coin(7, 10 * SAT_PER_BLCH)];
    let plan = build_plan(&from, &addr(2), SAT_PER_BLCH, &coins, BASE, TIP).unwrap();
    let signed = sign_plan(&plan, pk, sk).unwrap();

    // Signature swapped for garbage of a plausible shape.
    let mut bad = signed.clone();
    bad.signature = hex::encode(vec![0u8; 4_600]);
    let err = check_signed_plan(&bad).unwrap_err();
    assert!(err.contains("does not match the plan"), "{err}");

    // Amount inflated after signing: integrity check rejects first.
    let mut bad = signed.clone();
    bad.plan.amount_sat += 1;
    assert!(check_signed_plan(&bad).is_err());

    // The genuine article still passes.
    check_signed_plan(&signed).unwrap();
}

/// Pin the seed-phrase derivation to the reference wallet's: same phrase,
/// same keypair, same address. If `Wallet::from_seed` ever changes its
/// derivation, this fails rather than this tool silently deriving a
/// different (empty) address.
#[test]
fn seed_derivation_matches_the_reference_wallet() {
    use bloch_crypto::wallet::{SeedPhrase, Wallet};
    let (wallet, phrase) = Wallet::generate(Network::Mainnet).unwrap();
    let phrase_str = phrase.words().join(" ");
    // Sanity: the phrase reparses.
    SeedPhrase::parse(&phrase_str).unwrap();
    let (pk, _sk) = keypair_from_seed_phrase(&phrase_str).unwrap();
    assert_eq!(pk.as_slice(), wallet.public_key());
    assert_eq!(Address::from_pubkey(&pk, Network::Mainnet), *wallet.address());
}

// ── Keystore parsing ────────────────────────────────────────────────────────

#[test]
fn node_keystore_roundtrip_and_refusals() {
    // Assemble the BPOSKEY1 layout by hand, as keys.rs writes it.
    let pk = vec![0xAA; 100];
    let sk = vec![0xBB; 200];
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"BPOSKEY1");
    bytes.extend_from_slice(&7u32.to_le_bytes());
    bytes.extend_from_slice(&(pk.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&pk);
    bytes.extend_from_slice(&(sk.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&sk);
    bytes.extend_from_slice(&[0x11; 32]);

    let (got_pk, got_sk) = parse_node_keystore(&bytes).unwrap();
    assert_eq!(got_pk, pk);
    assert_eq!(got_sk, sk);

    assert!(parse_node_keystore(b"NOTAKEY!").is_err());
    assert!(parse_node_keystore(&bytes[..bytes.len() - 1]).is_err(), "truncated tail");
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(parse_node_keystore(&extra).is_err(), "trailing bytes");
}

// ── Preview & confirmation ──────────────────────────────────────────────────

/// The preview must state every consequential number: amount, destination,
/// change, fee, signing root, txid. This is the operator's whole view.
#[test]
fn preview_states_everything_that_moves() {
    let plan = good_plan();
    let p = preview(&plan);
    for needle in [
        plan.to_address.as_str(),
        plan.from_address.as_str(),
        "1 BLCH",
        plan.signing_root.as_str(),
        plan.txid.as_str(),
        "change",
        "fee",
    ] {
        assert!(p.contains(needle), "preview must contain `{needle}`:\n{p}");
    }
}

#[test]
fn confirmation_phrase_restates_amount_and_destination_tail() {
    let plan = good_plan();
    let phrase = confirmation_phrase(&plan);
    let tail = &plan.to_address[plan.to_address.len() - 8..];
    assert_eq!(phrase, format!("SEND 1 BLCH TO {tail}"));
}

// ── RPC plumbing against a stub node ────────────────────────────────────────

/// One-shot HTTP stub that answers a single request with a canned JSON-RPC
/// body, exactly as the node frames it (200 + Content-Length).
fn stub_node(response_body: &'static str) -> String {
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        if let Ok((mut sock, _)) = listener.accept() {
            let mut buf = [0u8; 4096];
            let _ = std::io::Read::read(&mut sock, &mut buf); // one read is enough for these tests
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            let _ = std::io::Write::write_all(&mut sock, resp.as_bytes());
        }
    });
    format!("http://{addr}")
}

#[test]
fn rpc_client_reads_string_sats_and_unwraps_results() {
    let url = stub_node(
        r#"{"jsonrpc":"2.0","id":1,"result":{"script_hash":"aa","balance_sat":"12345678901234567890","utxo_count":3}}"#,
    );
    let client = rpc::Client::new(&url).unwrap();
    let (bal, count) = rpc::get_balance(&client, &[0u8; 32]).unwrap();
    assert_eq!(bal, 12345678901234567890u128);
    assert_eq!(count, 3);
}

#[test]
fn rpc_client_surfaces_node_errors_as_errors() {
    let url = stub_node(
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32002,"message":"not a canonical Genesis-4 transaction"}}"#,
    );
    let client = rpc::Client::new(&url).unwrap();
    let err = client.call("sendrawtransaction", serde_json::json!(["00"])).unwrap_err();
    assert!(err.contains("-32002"), "{err}");
    assert!(err.contains("canonical"), "{err}");
}

#[test]
fn rpc_client_refuses_non_http_urls() {
    assert!(rpc::Client::new("https://node.example:16400").is_err());
    assert!(rpc::Client::new("node.example:16400").is_err());
}

#[test]
fn get_coins_parses_the_getutxos_shape_and_refuses_truncation() {
    let url = stub_node(
        r#"{"jsonrpc":"2.0","id":1,"result":{"total":1,"returned":1,"truncated":false,"utxos":[{"txid":"0707070707070707070707070707070707070707070707070707070707070707","vout":2,"value_sat":"4000000000000","at_slot":9}]}}"#,
    );
    let client = rpc::Client::new(&url).unwrap();
    let coins = rpc::get_coins(&client, &[0u8; 32]).unwrap();
    assert_eq!(coins, vec![Coin { txid: [7u8; 32], vout: 2, value_sat: 4_000_000_000_000 }]);

    let url = stub_node(
        r#"{"jsonrpc":"2.0","id":1,"result":{"total":2000,"returned":1000,"truncated":true,"utxos":[]}}"#,
    );
    let client = rpc::Client::new(&url).unwrap();
    assert!(rpc::get_coins(&client, &[0u8; 32]).unwrap_err().contains("truncated"));
}
