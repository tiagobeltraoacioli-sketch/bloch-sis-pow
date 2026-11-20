// SPDX-License-Identifier: AGPL-3.0-or-later
//! Independent review 503 (2026-11-20). These tests judge transactions that
//! the BUILT WASM produced under `review/adversarial-503.mjs` (the real
//! `nw_alloc` / `nw_call` / `nw_free` ABI), with the node's own decoder,
//! verifiers and committed-state preflight. They are skipped unless the
//! environment names the files, so the ordinary test run is unchanged.
//!
//!   R503_EXPORT_KEYS=<out.json>   write the public test accounts (V1 and V2
//!                                 of the published BIP39 test mnemonic)
//!   R503_SIGNED=<signed.json>     judge the array written by the script
use bloch_crypto::{
    crypto,
    wallet::seed::{SeedPhrase, SeedVersion},
};
use bloch_pos_committee::{
    fee_market,
    transition::{funded::ADMISSION_PQ_SIGNATURE_MAX, L2Deposit, PosTransaction},
};
use serde_json::{json, Value};
use sha3::{Digest, Sha3_256};

/// Published BIP39 test vector; never fund it.
const PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const MAINNET_DOMAIN: &str = "f47d3e498ff978e34471dafff5f94fe139fc3ff489b1a00f469c030258311966";

fn seed(version: SeedVersion) -> Vec<u8> {
    SeedPhrase::parse(PHRASE).unwrap().to_seed_bytes_versioned(version, "").unwrap().to_vec()
}
fn derive(version: SeedVersion) -> (Vec<u8>, Vec<u8>) {
    crypto::generate_keypair_from_seed(&seed(version)[..32]).unwrap()
}

#[test]
fn r503_export_public_test_accounts() {
    let Ok(path) = std::env::var("R503_EXPORT_KEYS") else { return };
    let (p1, s1) = derive(SeedVersion::V1LegacyPbkdf2Sha256);
    let (p2, s2) = derive(SeedVersion::V2Bip39Sha512);
    let out = json!({
        "note": "PUBLIC TEST DATA: published BIP39 test mnemonic. Never fund.",
        "mnemonic": PHRASE,
        "domainHex": MAINNET_DOMAIN,
        "v1": {"publicKeyHex": hex::encode(&p1), "secretKeyHex": hex::encode(&s1), "seedHex": hex::encode(seed(SeedVersion::V1LegacyPbkdf2Sha256))},
        "v2": {"publicKeyHex": hex::encode(&p2), "secretKeyHex": hex::encode(&s2), "seedHex": hex::encode(seed(SeedVersion::V2Bip39Sha512))},
    });
    std::fs::write(path, serde_json::to_vec(&out).unwrap()).unwrap();
}

fn text(v: &Value) -> &str {
    v.as_str().expect("string")
}

/// Every transaction the WASM released: the node decodes it, re-encodes the
/// same bytes, both verifiers accept the signature over the node's root, and
/// every field equals what `review` told the page.
#[test]
fn r503_wasm_signed_transactions_are_what_the_node_accepts() {
    let Ok(path) = std::env::var("R503_SIGNED") else { return };
    let cases: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let cases = cases.as_array().unwrap();
    assert!(!cases.is_empty());
    let mut judged = 0usize;
    for case in cases {
        let label = text(&case["label"]);
        let review = &case["review"];
        let signed = &case["signed"];
        let bytes = hex::decode(text(&signed["transactionHex"])).unwrap();
        let wire = PosTransaction::from_canonical_bytes(&bytes).unwrap_or_else(|e| panic!("{label}: {e}"));
        assert_eq!(wire.canonical_bytes(), bytes, "{label}: canonical");
        let PosTransaction::L2Deposit(tx) = wire.clone() else { panic!("{label}: not 0x14") };
        assert_eq!(hex::encode(wire.txid()), text(&signed["txid"]), "{label}");
        assert_eq!(text(&review["txid"]), text(&signed["txid"]), "{label}");
        assert_eq!(hex::encode(tx.network_domain), MAINNET_DOMAIN, "{label}");
        assert_eq!(hex::encode(&tx.funding_pubkey), text(&case["publicKeyHex"]), "{label}");
        let owner: [u8; 32] = Sha3_256::digest(&tx.funding_pubkey).into();
        // Second pass: change goes to the owner's ADDRESS form (hash160 and
        // twelve zero bytes), the form the web wallet indexes by.
        let mut address_form = [0u8; 32];
        address_form[..20].copy_from_slice(&owner[..20]);
        assert_eq!(tx.change.script_hash, address_form, "{label}: change to the owner's address form only");
        assert_eq!(hex::encode(address_form), text(&review["changeScriptHashHex"]), "{label}");
        assert_eq!(hex::encode(address_form), text(&signed["changeScriptHashHex"]), "{label}");
        assert_eq!(hex::encode(tx.recipient), text(&review["recipientHex"]), "{label}");
        assert_eq!(tx.amount_sat.to_string(), text(&review["amountSat"]), "{label}");
        assert_eq!(tx.change.value.to_string(), text(&review["changeSat"]), "{label}");
        assert_eq!(tx.tx_bytes.to_string(), text(&review["txBytes"]), "{label}");
        assert_eq!(tx.tip_millisat_per_gas.to_string(), text(&review["tipMillisatPerGas"]), "{label}");
        assert_eq!(tx.inputs.len() as u64, review["inputCount"].as_u64().unwrap(), "{label}");
        assert!(tx.inputs.windows(2).all(|w| w[0] < w[1]), "{label}: strict order");
        // The inputs are exactly the rows the page named.
        let mut named: Vec<([u8; 32], u32)> = case["inputs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| (hex::decode(text(&r["txidHex"])).unwrap().try_into().unwrap(), r["vout"].as_u64().unwrap() as u32))
            .collect();
        named.sort();
        let got: Vec<([u8; 32], u32)> = tx.inputs.iter().map(|i| (i.txid, i.vout)).collect();
        assert_eq!(got, named, "{label}");
        // Size rules: consensus (declared >= encoded) and relay slack.
        assert!(!tx.signature.is_empty() && tx.signature.len() <= ADMISSION_PQ_SIGNATURE_MAX, "{label}");
        assert!(tx.tx_bytes >= bytes.len() as u64, "{label}");
        assert!(tx.tx_bytes <= bytes.len() as u64 + fee_market::TX_BYTES_DECLARE_SLACK, "{label}");
        // Fee and exact conservation as the node computes them.
        let base: u128 = text(&review["baseFeeMillisatPerGas"]).parse().unwrap();
        let charge = fee_market::charge(
            fee_market::TxClass::Eutxo { inputs: tx.inputs.len() as u32 },
            tx.tx_bytes,
            base,
            tx.tip_millisat_per_gas,
        );
        let fee = charge.base_fee_sat + charge.priority_fee_sat;
        assert_eq!(fee.to_string(), text(&review["feeSat"]), "{label}");
        let total: u128 = case["inputs"].as_array().unwrap().iter().map(|r| r["valueSat"].as_u64().unwrap() as u128).sum();
        assert_eq!(total, u128::from(tx.amount_sat) + u128::from(tx.change.value) + fee, "{label}: conservation");
        // The signature, under the compatible and the pinned (mainnet) rule.
        let root = tx.intent_root();
        assert!(crypto::verify(&tx.funding_pubkey, &root, &tx.signature), "{label}: verify");
        assert!(crypto::verify_pinned(&tx.funding_pubkey, &root, &tx.signature), "{label}: verify_pinned");
        #[cfg(feature = "state-acceptance")]
        state::judge(label, &tx, case, base);
        judged += 1;
    }
    println!("r503: judged {judged} WASM-signed transactions");
}

/// Two instances whose `random_get` returned only zero bytes: the scheme is
/// then deterministic; the signatures must still verify (and be equal).
#[test]
fn r503_zero_entropy_signatures() {
    let Ok(path) = std::env::var("R503_ZERO_RNG") else { return };
    let v: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let pair = v.as_array().unwrap();
    let decode = |s: &Value| -> L2Deposit {
        match PosTransaction::from_canonical_bytes(&hex::decode(text(s)).unwrap()).unwrap() {
            PosTransaction::L2Deposit(tx) => tx,
            _ => panic!(),
        }
    };
    for s in pair {
        let tx = decode(s);
        assert!(crypto::verify_pinned(&tx.funding_pubkey, &tx.intent_root(), &tx.signature));
    }
    println!("r503: zero-entropy signatures equal = {}", pair[0] == pair[1]);
}

#[cfg(feature = "state-acceptance")]
mod state {
    use super::*;
    use bloch_pos_committee::{
        l2_settlement::Policy,
        state_root::{EutxoEntry, EvmCommitment},
        transition::L2DepositReject,
        BlockHeaderV4, BlockId, CommittedState, GenesisValidator, VERSION_G4,
    };

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
        state
            .configure_l2_genesis_async(Policy {
                identities,
                proof_policy: [0x77; 32],
                chain_id: 700770,
                initial_l2_parent: [0x78; 32],
                initial_l2_state: [0x79; 32],
                attestor_set: [0; 32],
            })
            .unwrap()
    }

    /// The node's mempool door / pre-signature transition checks on a state
    /// holding exactly the named outputs. Only cases priced at this state's
    /// base fee can be admitted; the others must fail by Conservation only.
    pub fn judge(label: &str, tx: &L2Deposit, case: &Value, base: u128) {
        let owner: [u8; 32] = Sha3_256::digest(&tx.funding_pubkey).into();
        let coins: Vec<EutxoEntry> = case["inputs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| EutxoEntry {
                txid: hex::decode(text(&r["txidHex"])).unwrap().try_into().unwrap(),
                vout: r["vout"].as_u64().unwrap() as u32,
                value: r["valueSat"].as_u64().unwrap(),
                script_hash: owner,
            })
            .collect();
        let domain: [u8; 32] = hex::decode(MAINNET_DOMAIN).unwrap().try_into().unwrap();
        let state = committed(domain, &coins);
        let verdict = state.l2_deposit_refusal_at(tx, base);
        assert_eq!(verdict, None, "{label}: node preflight at the reviewed base fee");
        // Base fee moved by one unit either way: a clean Conservation refusal.
        assert_eq!(state.l2_deposit_refusal_at(tx, base + 1), Some(L2DepositReject::Conservation), "{label}");
        if base > fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS {
            assert_eq!(state.l2_deposit_refusal_at(tx, base - 1), Some(L2DepositReject::Conservation), "{label}");
        }
    }
}
