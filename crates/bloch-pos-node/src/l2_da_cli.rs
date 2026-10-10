// SPDX-License-Identifier: AGPL-3.0-or-later
//! Offline L2 data-availability workflow (development networks). Builds and
//! signs the `L2DataAvailability` (0x15) transaction that publishes one L2
//! block's user-transaction batch; broadcasting remains an explicit
//! sendrawtransaction.

use crate::{
    codec,
    keys::Keystore,
    l2_deposit_cli::{domain, get, options, read_text},
};
use bloch_pos_committee::{
    fee_market,
    l2_settlement::da,
    transition::{
        funded::ADMISSION_PQ_SIGNATURE_MAX, FundingInput, L2DataAvailability, PosTransaction,
        TransferOutput,
    },
};
use sha3::{Digest, Sha3_256};
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    path::Path,
};

const HELP: &str = "Native L2 data availability: publish one L2 block's user-transaction batch (offline; does not broadcast)

prepare --genesis FILE --funding-pubkey HEX_FILE --input TXID:VOUT:SAT [--input ...]
        --chain-id N --number L2_BLOCK --payload HEX_FILE
        --base-fee MILLISAT_PER_GAS --tip MILLISAT_PER_GAS --out FILE
inspect --tx FILE
sign --genesis TRUSTED_FILE --tx FILE --dir KEYSTORE_DIR --out NEW_FILE

The payload is the canonical batch (bloch-l2-produce-dev da). The whole input
value minus the fee returns as change to the funding key. Consensus requires
exact conservation at the including block's base fee (getchaininfo
next_base_fee_millisat_per_gas). Development networks only: a build without
devnet-l2-user-txs refuses the transaction.";

fn read_payload(path: &str) -> Result<Vec<u8>, String> {
    let limit = 2 * da::MAX_PAYLOAD_BYTES + 16;
    let mut text = String::new();
    std::fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(limit as u64 + 1)
        .read_to_string(&mut text)
        .map_err(|e| e.to_string())?;
    if text.len() > limit {
        return Err("payload exceeds the DA size cap".into());
    }
    let payload = codec::unhex(text.trim())?;
    da::batch_count(&payload).ok_or("payload is not one canonical batch within the DA size cap")?;
    Ok(payload)
}

fn read_tx(path: &str) -> Result<L2DataAvailability, String> {
    let limit = 2 * (da::MAX_PAYLOAD_BYTES + 16_384);
    let mut text = String::new();
    std::fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(limit as u64 + 1)
        .read_to_string(&mut text)
        .map_err(|e| e.to_string())?;
    if text.len() > limit {
        return Err("file exceeds the offline input limit".into());
    }
    match PosTransaction::from_canonical_bytes(&codec::unhex(text.trim())?)
        .map_err(|e| e.to_string())?
    {
        PosTransaction::L2DataAvailability(tx) => Ok(tx),
        _ => Err("expected an L2 data availability transaction (wire 0x15)".into()),
    }
}

fn write_tx(path: &str, tx: &L2DataAvailability) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|e| e.to_string())?;
    writeln!(
        file,
        "{}",
        codec::hex(&PosTransaction::L2DataAvailability(tx.clone()).canonical_bytes())
    )
    .map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())
}

fn prepare(args: &[String]) -> Result<(), String> {
    let o = options(
        args,
        &[
            "--genesis",
            "--funding-pubkey",
            "--input",
            "--chain-id",
            "--number",
            "--payload",
            "--base-fee",
            "--tip",
            "--out",
        ],
    )?;
    let funding_pubkey = codec::unhex(read_text(get(&o, "--funding-pubkey")?)?.trim())?;
    let mut inputs = Vec::new();
    let mut total: u128 = 0;
    for (_, value) in o.iter().filter(|(f, _)| f == "--input") {
        let parts: Vec<&str> = value.split(':').collect();
        let [txid, vout, sats] = parts[..] else {
            return Err("--input needs TXID:VOUT:SAT".into());
        };
        let txid: [u8; 32] = codec::unhex(txid)?
            .try_into()
            .map_err(|_| "input txid needs 32 bytes")?;
        inputs.push(FundingInput {
            txid,
            vout: vout.parse().map_err(|_| "bad vout")?,
        });
        total += u128::from(sats.parse::<u64>().map_err(|_| "bad input sats")?);
    }
    inputs.sort();
    if inputs.is_empty() || inputs.len() > da::MAX_INPUTS {
        return Err(format!(
            "between 1 and {} inputs are required",
            da::MAX_INPUTS
        ));
    }
    let base_fee: u128 = get(&o, "--base-fee")?
        .parse()
        .map_err(|_| "bad --base-fee")?;
    let tip: u128 = get(&o, "--tip")?.parse().map_err(|_| "bad --tip")?;
    let owner: [u8; 32] = Sha3_256::digest(&funding_pubkey).into();
    let mut tx = L2DataAvailability {
        network_domain: domain(get(&o, "--genesis")?)?,
        funding_pubkey,
        inputs,
        l2_chain_id: get(&o, "--chain-id")?
            .parse()
            .map_err(|_| "bad --chain-id")?,
        l2_block_number: get(&o, "--number")?.parse().map_err(|_| "bad --number")?,
        payload: read_payload(get(&o, "--payload")?)?,
        change: TransferOutput {
            value: 0,
            script_hash: owner,
        },
        tx_bytes: 0,
        tip_millisat_per_gas: tip,
        signature: Vec::new(),
    };
    // Reserve the worst-case signature so the declared size never under-runs.
    tx.tx_bytes = (tx.canonical_bytes().len() + ADMISSION_PQ_SIGNATURE_MAX) as u64;
    let charge = fee_market::charge(
        fee_market::TxClass::Eutxo {
            inputs: tx.inputs.len() as u32,
        },
        tx.tx_bytes,
        base_fee,
        tip,
    );
    let change = total
        .checked_sub(charge.base_fee_sat + charge.priority_fee_sat)
        .ok_or("inputs do not cover the fee")?;
    tx.change.value = u64::try_from(change).map_err(|_| "change exceeds u64")?;
    inspect(&tx);
    write_tx(get(&o, "--out")?, &tx)
}

fn inspect(tx: &L2DataAvailability) {
    println!("L2 data availability (wire 0x15)");
    println!("  network domain : {}", codec::hex32(&tx.network_domain));
    println!(
        "  funding key    : sha3 {}",
        codec::hex32(&Sha3_256::digest(&tx.funding_pubkey).into())
    );
    for input in &tx.inputs {
        println!(
            "  input          : {}:{}",
            codec::hex32(&input.txid),
            input.vout
        );
    }
    println!(
        "  l2 chain/block : {} / {}",
        tx.l2_chain_id, tx.l2_block_number
    );
    println!(
        "  payload        : {} bytes, {} transactions",
        tx.payload.len(),
        da::batch_count(&tx.payload).map_or("invalid".to_string(), |n| n.to_string())
    );
    println!("  da_commitment  : {}", codec::hex32(&tx.commitment()));
    println!("  change         : {} sat", tx.change.value);
    println!(
        "  tx_bytes       : {}  tip: {} millisat/gas",
        tx.tx_bytes, tx.tip_millisat_per_gas
    );
    println!(
        "  txid           : {}",
        codec::hex32(&PosTransaction::L2DataAvailability(tx.clone()).txid())
    );
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
