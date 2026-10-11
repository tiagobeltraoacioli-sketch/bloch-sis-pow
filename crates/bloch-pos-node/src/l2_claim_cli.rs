// SPDX-License-Identifier: AGPL-3.0-or-later
//! Offline L2 withdrawal-claim workflow (development networks). Builds and
//! signs the `L2WithdrawClaim` (0x16) transaction that releases one settled,
//! matured L2 withdrawal from escrow to its L1 recipient; broadcasting
//! remains an explicit sendrawtransaction. The relayer's funding key pays the
//! fee; the recipient receives exactly the withdrawn amount.

use crate::{
    codec,
    keys::Keystore,
    l2_deposit_cli::{domain, get, options, read_text},
    rpc::{parse_json, Json},
};
use bloch_pos_committee::{
    fee_market,
    l2_settlement::withdrawal::{self, TREE_DEPTH},
    transition::{
        funded::ADMISSION_PQ_SIGNATURE_MAX,
        l2_claim::MAX_CLAIM_INPUTS,
        FundingInput, L2WithdrawClaim, PosTransaction, TransferOutput,
    },
};
use sha3::{Digest, Sha3_256};
use std::{fs::OpenOptions, io::Write, path::Path};

const HELP: &str = "Native L2 withdrawal claim: release one settled L2 withdrawal to its L1 recipient (offline; does not broadcast)

prepare --genesis FILE --funding-pubkey HEX_FILE --input TXID:VOUT:SAT [--input ...]
        --proof JSON_FILE --base-fee MILLISAT_PER_GAS --tip MILLISAT_PER_GAS --out FILE
inspect --tx FILE
sign --genesis TRUSTED_FILE --tx FILE --dir KEYSTORE_DIR --out NEW_FILE

--proof is the output of bloch-l2-produce-dev withdrawal-proof. Its root must be
a withdrawal root the L1 retains (getl2settlement withdrawals.roots) and at
least withdrawals.delay_blocks native blocks old when the claim is included;
proving against the newest matured root (withdrawals.matured) always works.
The funding inputs pay the fee and the rest returns as change to the funding
key; the recipient output is exactly the withdrawn sats. Consensus requires
exact conservation at the including block's base fee (getchaininfo
next_base_fee_millisat_per_gas). Development networks only: a build without
devnet-l2-user-txs refuses the transaction.";

fn read_tx(path: &str) -> Result<L2WithdrawClaim, String> {
    match PosTransaction::from_canonical_bytes(&codec::unhex(read_text(path)?.trim())?).map_err(|e| e.to_string())? {
        PosTransaction::L2WithdrawClaim(tx) => Ok(tx),
        _ => Err("expected an L2 withdrawal claim (wire 0x16)".into()),
    }
}

fn write_tx(path: &str, tx: &L2WithdrawClaim) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|e| e.to_string())?;
    writeln!(file, "{}", codec::hex(&PosTransaction::L2WithdrawClaim(tx.clone()).canonical_bytes())).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())
}

fn h32(v: Option<&Json>, what: &str) -> Result<[u8; 32], String> {
    let text = v.and_then(Json::as_str).ok_or_else(|| format!("proof lacks {what}"))?;
    codec::unhex(text.trim_start_matches("0x"))?.try_into().map_err(|_| format!("{what} needs 32 bytes"))
}

fn u(v: Option<&Json>, what: &str) -> Result<u64, String> {
    v.and_then(Json::as_u64).ok_or_else(|| format!("proof lacks {what}"))
}

/// The claim fields of a `withdrawal-proof` document, checked with the
/// native leaf and proof code: `(chain_id, index, l1_recipient, sats,
/// siblings, root)`.
pub(crate) struct Proof {
    pub chain_id: u64,
    pub index: u64,
    pub l1_recipient: [u8; 32],
    pub sats: u64,
    pub siblings: [[u8; 32]; TREE_DEPTH],
    pub root: [u8; 32],
}

pub(crate) fn parse_proof(text: &str) -> Result<Proof, String> {
    let doc = parse_json(text).map_err(|e| format!("proof: {e}"))?;
    let w = doc.get("withdrawal").ok_or("proof lacks withdrawal")?;
    let chain_id = u(doc.get("chain_id"), "chain_id")?;
    let index = u(doc.get("index"), "index")?;
    if u(w.get("nonce"), "withdrawal.nonce")? != index {
        return Err("withdrawal nonce differs from the proof index".into());
    }
    let l1_recipient = h32(w.get("l1_recipient"), "withdrawal.l1_recipient")?;
    let sats = u(w.get("sats"), "withdrawal.sats")?;
    let Some(Json::Arr(list)) = doc.get("siblings") else { return Err("proof lacks siblings".into()) };
    if list.len() != TREE_DEPTH {
        return Err(format!("proof needs {TREE_DEPTH} siblings"));
    }
    let mut siblings = [[0u8; 32]; TREE_DEPTH];
    for (slot, v) in siblings.iter_mut().zip(list) {
        *slot = h32(Some(v), "sibling")?;
    }
    let leaf = withdrawal::leaf(chain_id, index, &l1_recipient, sats);
    if h32(w.get("leaf"), "withdrawal.leaf")? != leaf {
        return Err("the proof's leaf differs from the native leaf of its fields".into());
    }
    let root = h32(doc.get("withdrawal_root"), "withdrawal_root")?;
    if withdrawal::root_from_proof(&leaf, index, &siblings) != Some(root) {
        return Err("the siblings do not prove the leaf against withdrawal_root".into());
    }
    if index >= u(doc.get("withdrawal_count"), "withdrawal_count")? {
        return Err("index is not below withdrawal_count".into());
    }
    Ok(Proof { chain_id, index, l1_recipient, sats, siblings, root })
}

fn prepare(args: &[String]) -> Result<(), String> {
    let o = options(args, &["--genesis", "--funding-pubkey", "--input", "--proof", "--base-fee", "--tip", "--out"])?;
    let funding_pubkey = codec::unhex(read_text(get(&o, "--funding-pubkey")?)?.trim())?;
    let mut inputs = Vec::new();
    let mut total: u128 = 0;
    for (_, value) in o.iter().filter(|(f, _)| f == "--input") {
        let parts: Vec<&str> = value.split(':').collect();
        let [txid, vout, sats] = parts[..] else { return Err("--input needs TXID:VOUT:SAT".into()) };
        let txid: [u8; 32] = codec::unhex(txid)?.try_into().map_err(|_| "input txid needs 32 bytes")?;
        inputs.push(FundingInput { txid, vout: vout.parse().map_err(|_| "bad vout")? });
        total += u128::from(sats.parse::<u64>().map_err(|_| "bad input sats")?);
    }
    inputs.sort();
    if inputs.is_empty() || inputs.len() > MAX_CLAIM_INPUTS {
        return Err(format!("between 1 and {MAX_CLAIM_INPUTS} inputs are required"));
    }
    let proof = parse_proof(&read_text(get(&o, "--proof")?)?)?;
    let base_fee: u128 = get(&o, "--base-fee")?.parse().map_err(|_| "bad --base-fee")?;
    let tip: u128 = get(&o, "--tip")?.parse().map_err(|_| "bad --tip")?;
    let owner: [u8; 32] = Sha3_256::digest(&funding_pubkey).into();
    let mut tx = L2WithdrawClaim {
        network_domain: domain(get(&o, "--genesis")?)?,
        funding_pubkey,
        inputs,
        l2_chain_id: proof.chain_id,
        index: proof.index,
        l1_recipient: proof.l1_recipient,
        sats: proof.sats,
        siblings: proof.siblings,
        release: TransferOutput { value: proof.sats, script_hash: proof.l1_recipient },
        change: TransferOutput { value: 0, script_hash: owner },
        tx_bytes: 0,
        tip_millisat_per_gas: tip,
        signature: Vec::new(),
    };
    // Reserve the worst-case signature so the declared size never under-runs.
    tx.tx_bytes = (tx.canonical_bytes().len() + ADMISSION_PQ_SIGNATURE_MAX) as u64;
    let charge = fee_market::charge(tx.class(), tx.tx_bytes, base_fee, tip);
    let change = total.checked_sub(charge.base_fee_sat + charge.priority_fee_sat).ok_or("inputs do not cover the fee")?;
    tx.change.value = u64::try_from(change).map_err(|_| "change exceeds u64")?;
    println!("  proven root    : {}", codec::hex32(&proof.root));
    inspect(&tx);
    write_tx(get(&o, "--out")?, &tx)
}

fn inspect(tx: &L2WithdrawClaim) {
    println!("L2 withdrawal claim (wire 0x16)");
    println!("  network domain : {}", codec::hex32(&tx.network_domain));
    println!("  funding key    : sha3 {}", codec::hex32(&Sha3_256::digest(&tx.funding_pubkey).into()));
    for input in &tx.inputs {
        println!("  input          : {}:{}", codec::hex32(&input.txid), input.vout);
    }
    println!("  l2 chain/index : {} / {}", tx.l2_chain_id, tx.index);
    println!("  recipient      : {}", codec::hex32(&tx.l1_recipient));
    println!("  sats           : {}", tx.sats);
    println!("  leaf           : {}", codec::hex32(&tx.leaf()));
    let root = withdrawal::root_from_proof(&tx.leaf(), tx.index, &tx.siblings);
    println!("  proves root    : {}", root.map_or("none".to_string(), |r| codec::hex32(&r)));
    println!("  nullifier      : {}", codec::hex32(&tx.nullifier()));
    println!("  change         : {} sat", tx.change.value);
    println!("  tx_bytes       : {}  tip: {} millisat/gas", tx.tx_bytes, tx.tip_millisat_per_gas);
    println!("  txid           : {}", codec::hex32(&PosTransaction::L2WithdrawClaim(tx.clone()).txid()));
    println!("  shape          : {}", tx.validate_shape().map_or_else(|e| format!("{e:?}"), |_| "ok".into()));
    println!("  signed         : {}", !tx.signature.is_empty());
}

fn sign(args: &[String]) -> Result<(), String> {
    let o = options(args, &["--genesis", "--tx", "--dir", "--out"])?;
    let mut tx = read_tx(get(&o, "--tx")?)?;
    if tx.network_domain != domain(get(&o, "--genesis")?)? {
        return Err("transaction does not match the signer's trusted genesis manifest".into());
    }
    let keys = Keystore::load(Path::new(get(&o, "--dir")?)).map_err(|e| e.to_string())?;
    if keys.pubkey != tx.funding_pubkey {
        return Err("keystore does not own the funding key".into());
    }
    inspect(&tx);
    tx.signature = keys.sign(&tx.intent_root());
    if !bloch_crypto::crypto::verify(&tx.funding_pubkey, &tx.intent_root(), &tx.signature) {
        return Err("produced signature does not verify".into());
    }
    tx.validate_shape().map_err(|e| format!("signed claim has an invalid shape: {e:?}"))?;
    write_tx(get(&o, "--out")?, &tx)
}

pub fn run(args: &[String]) -> Result<(), String> {
    let Some((command, rest)) = args.split_first() else {
        println!("{HELP}");
        return Ok(());
    };
    match command.as_str() {
        "--help" | "help" => {
            println!("{HELP}");
            Ok(())
        }
        "prepare" => prepare(rest),
        "sign" => sign(rest),
        "inspect" => {
            let o = options(rest, &["--tx"])?;
            inspect(&read_tx(get(&o, "--tx")?)?);
            Ok(())
        }
        _ => Err("expected prepare, inspect, sign or --help".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A two-leaf `withdrawal-proof` document for leaf 1.
    fn doc(tamper_leaf: bool) -> String {
        let chain_id = 700771u64;
        let leaves: Vec<[u8; 32]> =
            (0..2u64).map(|i| withdrawal::leaf(chain_id, i, &[i as u8 + 1; 32], 1_000_000 + i)).collect();
        let siblings = withdrawal::proof(&leaves, 1).unwrap();
        let mut leaf = leaves[1];
        if tamper_leaf {
            leaf[0] ^= 1;
        }
        format!(
            r#"{{"chain_id":{chain_id},"number":2,"withdrawal_root":"{}","withdrawal_count":2,"index":1,
               "withdrawal":{{"nonce":1,"l1_recipient":"{}","sats":1000001,"sender":"00","l2_block":2,"leaf":"{}"}},
               "siblings":[{}]}}"#,
            codec::hex32(&withdrawal::root(&leaves)),
            codec::hex32(&[2; 32]),
            codec::hex32(&leaf),
            siblings.iter().map(|s| format!("\"{}\"", codec::hex32(s))).collect::<Vec<_>>().join(",")
        )
    }

    #[test]
    fn a_withdrawal_proof_document_parses_and_checks_against_the_native_tree() {
        let p = parse_proof(&doc(false)).unwrap();
        assert_eq!((p.chain_id, p.index, p.l1_recipient, p.sats), (700771, 1, [2; 32], 1_000_001));
        assert!(parse_proof(&doc(true)).is_err(), "leaf mismatch refused");
    }
}
