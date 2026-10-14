// SPDX-License-Identifier: AGPL-3.0-or-later
//! Offline native L2 deposit workflow (development networks). The signer opens
//! only its own keystore; broadcasting remains an explicit sendrawtransaction.

use crate::{codec, genesis::Manifest, keys::Keystore};
use bloch_pos_committee::{
    fee_market,
    transition::{
        funded::ADMISSION_PQ_SIGNATURE_MAX, FundingInput, L2Deposit, PosTransaction, TransferOutput,
    },
};
use sha3::{Digest, Sha3_256};
use std::{fs::OpenOptions, io::{Read, Write}, path::Path};

const HELP: &str = "Native L2 deposit: escrow BLCH for an EVM recipient on the L2 (offline; does not broadcast)

prepare --genesis FILE --funding-pubkey HEX_FILE --input TXID:VOUT:SAT [--input ...]
        --amount SAT --recipient HEX20 --base-fee MILLISAT_PER_GAS --tip MILLISAT_PER_GAS --out FILE
inspect --tx FILE
sign --genesis TRUSTED_FILE --tx FILE --dir KEYSTORE_DIR --out NEW_FILE

Change returns to the funding key. Consensus requires exact conservation at the
including block's base fee (query getchaininfo next_base_fee_millisat_per_gas).
Development networks only: a build without devnet-l2-deposits refuses the deposit.";

pub(crate) fn read_text(path: &str) -> Result<String, String> {
    let mut text = String::new();
    std::fs::File::open(path).map_err(|e| e.to_string())?.take(100_001).read_to_string(&mut text).map_err(|e| e.to_string())?;
    if text.len() > 100_000 {
        return Err("file exceeds the offline input limit".into());
    }
    Ok(text)
}

fn read_tx(path: &str) -> Result<L2Deposit, String> {
    match PosTransaction::from_canonical_bytes(&codec::unhex(read_text(path)?.trim())?).map_err(|e| e.to_string())? {
        PosTransaction::L2Deposit(tx) => Ok(tx),
        _ => Err("expected an L2 deposit (wire 0x14)".into()),
    }
}

fn write_tx(path: &str, tx: &L2Deposit) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|e| e.to_string())?;
    writeln!(file, "{}", codec::hex(&PosTransaction::L2Deposit(tx.clone()).canonical_bytes())).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())
}

/// Flags that may be given more than once (in order).
const REPEATABLE: &[&str] = &["--input", "--attestation", "--pubkey"];

pub(crate) fn options(args: &[String], allowed: &[&str]) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    let mut iter = args.iter();
    while let Some(flag) = iter.next() {
        if !allowed.contains(&flag.as_str()) {
            return Err(format!("unknown option {flag}"));
        }
        let value = iter.next().ok_or_else(|| format!("missing value for {flag}"))?;
        if !REPEATABLE.contains(&flag.as_str()) && out.iter().any(|(f, _)| f == flag) {
            return Err(format!("duplicate option {flag}"));
        }
        out.push((flag.clone(), value.clone()));
    }
    Ok(out)
}

pub(crate) fn get<'a>(opts: &'a [(String, String)], flag: &str) -> Result<&'a str, String> {
    opts.iter().find(|(f, _)| f == flag).map(|(_, v)| v.as_str()).ok_or_else(|| format!("missing {flag}"))
}

pub(crate) fn domain(genesis: &str) -> Result<[u8; 32], String> {
    let (manifest, _) = Manifest::load(Path::new(genesis)).map_err(|e| e.to_string())?;
    Ok(Sha3_256::digest(manifest.encode()).into())
}

fn prepare(args: &[String]) -> Result<(), String> {
    let o = options(args, &["--genesis", "--funding-pubkey", "--input", "--amount", "--recipient", "--base-fee", "--tip", "--out"])?;
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
    let recipient_text = get(&o, "--recipient")?.trim_start_matches("0x");
    let recipient: [u8; 20] = codec::unhex(recipient_text)?.try_into().map_err(|_| "--recipient needs 20 bytes")?;
    let amount_sat: u64 = get(&o, "--amount")?.parse().map_err(|_| "bad --amount")?;
    let base_fee: u128 = get(&o, "--base-fee")?.parse().map_err(|_| "bad --base-fee")?;
    let tip: u128 = get(&o, "--tip")?.parse().map_err(|_| "bad --tip")?;
    let owner: [u8; 32] = Sha3_256::digest(&funding_pubkey).into();
    let mut tx = L2Deposit {
        network_domain: domain(get(&o, "--genesis")?)?,
        funding_pubkey,
        inputs,
        amount_sat,
        recipient,
        change: TransferOutput { value: 0, script_hash: owner },
        tx_bytes: 0,
        tip_millisat_per_gas: tip,
        signature: Vec::new(),
    };
    // Reserve the worst-case signature so the declared size never under-runs.
    tx.tx_bytes = (tx.canonical_bytes().len() + ADMISSION_PQ_SIGNATURE_MAX) as u64;
    let charge = fee_market::charge(fee_market::TxClass::Eutxo { inputs: tx.inputs.len() as u32 }, tx.tx_bytes, base_fee, tip);
    let change = total
        .checked_sub(u128::from(amount_sat) + charge.base_fee_sat + charge.priority_fee_sat)
        .ok_or("inputs do not cover the amount plus fees")?;
    tx.change.value = u64::try_from(change).map_err(|_| "change exceeds u64")?;
    inspect(&tx);
    write_tx(get(&o, "--out")?, &tx)
}

fn inspect(tx: &L2Deposit) {
    println!("L2 deposit (wire 0x14)");
    println!("  network domain : {}", codec::hex32(&tx.network_domain));
    println!("  funding key    : sha3 {}", codec::hex32(&Sha3_256::digest(&tx.funding_pubkey).into()));
    for input in &tx.inputs {
        println!("  input          : {}:{}", codec::hex32(&input.txid), input.vout);
    }
    println!("  amount         : {} sat ({} BLCH) -> L2 recipient 0x{}", tx.amount_sat, tx.amount_sat as f64 / 1e8, codec::hex(&tx.recipient));
    println!("  change         : {} sat", tx.change.value);
    println!("  tx_bytes       : {}  tip: {} millisat/gas", tx.tx_bytes, tx.tip_millisat_per_gas);
    println!("  txid           : {}", codec::hex32(&PosTransaction::L2Deposit(tx.clone()).txid()));
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
