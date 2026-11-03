// SPDX-License-Identifier: AGPL-3.0-or-later
//! Offline L1 forced inclusion of one L2 transaction (wire 0x1C, CANDIDATE).
//! The signer opens only its own keystore; broadcasting remains an explicit
//! sendrawtransaction. Modelled on `l2-deposit`.

use crate::{
    codec,
    keys::Keystore,
    l2_deposit_cli::{domain, get, options, read_text},
};
use bloch_pos_committee::{
    fee_market,
    l2_settlement::{forced, MAINNET_CHAIN_ID},
    transition::{funded::ADMISSION_PQ_SIGNATURE_MAX, FundingInput, L2ForcedTransaction, PosTransaction, TransferOutput},
};
use sha3::{Digest, Keccak256, Sha3_256};
use std::{fs::OpenOptions, io::Write};

const HELP: &str = "L2 forced transaction: queue one signed L2 envelope on L1, so that every later settlement must run it (offline; does not broadcast)

prepare --genesis FILE --funding-pubkey HEX_FILE --input TXID:VOUT:SAT [--input ...]
        --envelope HEX_FILE --gas DECLARED_GAS
        (--pending-weight UNITS [--headroom-units UNITS] | --max-surcharge-sat SAT)
        --base-fee MILLISAT_PER_GAS --tip MILLISAT_PER_GAS [--l2-chain-id ID] --out FILE
inspect --tx FILE
sign --genesis TRUSTED_FILE --tx FILE --dir KEYSTORE_DIR --out NEW_FILE

--envelope holds the signed L2 transaction in hex (as `bloch-l2-produce-dev sign-tx --out`
writes it). --gas is the declared gas limit (21000..=300000); the L2 skips an envelope whose
own gas limit is above it.

The inputs pay the ordinary fee plus a signed maximum surcharge. Consensus charges the
surcharge of the queue depth the transaction finds (each weight unit at its own position),
pays it to the protocol treasury, and refunds the rest of the maximum to the funding key
(output 1). --pending-weight is getl2settlement.forced.pending_weight; the maximum is then
the most a record of this gas can be charged at that depth plus --headroom-units (default
one price tier, 24 units), so the transaction stays valid while the queue grows that much
in front of it. --max-surcharge-sat sets the maximum directly. The ordinary fee still needs
exact conservation at the including block's base fee. --l2-chain-id defaults to the mainnet
L2 (700770). Change returns to the funding key.";

/// The signed maximum surcharge for `gas` declared, valid while the queue's
/// position is at most `pending_weight + headroom` (`forced::surcharge_ceiling_sat`).
pub(crate) fn max_surcharge_for(pending_weight: u64, headroom: u64, gas: u64) -> Result<u64, String> {
    forced::surcharge_ceiling_sat(pending_weight.saturating_add(headroom), gas)
        .ok_or_else(|| format!("--gas must be in {}..={}", forced::MIN_GAS, forced::MAX_GAS))
}

/// The envelope bytes of a hex file (an optional 0x prefix and whitespace are ignored).
pub(crate) fn read_envelope(path: &str) -> Result<Vec<u8>, String> {
    let text = read_text(path)?;
    let bytes = codec::unhex(text.trim().trim_start_matches("0x"))?;
    if bytes.is_empty() || bytes.len() > forced::MAX_ENVELOPE_BYTES {
        return Err(format!("the envelope must be 1..={} bytes", forced::MAX_ENVELOPE_BYTES));
    }
    Ok(bytes)
}

fn read_tx(path: &str) -> Result<L2ForcedTransaction, String> {
    match PosTransaction::from_canonical_bytes(&codec::unhex(read_text(path)?.trim())?).map_err(|e| e.to_string())? {
        PosTransaction::L2ForcedTransaction(tx) => Ok(tx),
        _ => Err("expected an L2 forced transaction (wire 0x1C)".into()),
    }
}

fn write_tx(path: &str, tx: &L2ForcedTransaction) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|e| e.to_string())?;
    writeln!(file, "{}", codec::hex(&PosTransaction::L2ForcedTransaction(tx.clone()).canonical_bytes())).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())
}

/// Build the unsigned transaction with exact conservation: inputs = change +
/// base fee + tip + the signed maximum surcharge, as `apply_l2_forced_transaction`
/// checks (it refunds what it does not charge).
#[allow(clippy::too_many_arguments)]
pub(crate) fn build(
    network_domain: [u8; 32],
    funding_pubkey: Vec<u8>,
    mut inputs: Vec<(FundingInput, u64)>,
    l2_chain_id: u64,
    gas_limit: u64,
    envelope: Vec<u8>,
    max_surcharge_sat: u64,
    base_fee: u128,
    tip: u128,
) -> Result<L2ForcedTransaction, String> {
    inputs.sort_by(|a, b| a.0.cmp(&b.0));
    let total: u128 = inputs.iter().map(|(_, sats)| u128::from(*sats)).sum();
    if !(forced::MIN_GAS..=forced::MAX_GAS).contains(&gas_limit) {
        return Err(format!("--gas must be in {}..={}", forced::MIN_GAS, forced::MAX_GAS));
    }
    let owner: [u8; 32] = Sha3_256::digest(&funding_pubkey).into();
    let mut tx = L2ForcedTransaction {
        network_domain,
        funding_pubkey,
        inputs: inputs.into_iter().map(|(input, _)| input).collect(),
        l2_chain_id,
        gas_limit,
        max_surcharge_sat,
        envelope,
        change: TransferOutput { value: 0, script_hash: owner },
        tx_bytes: 0,
        tip_millisat_per_gas: tip,
        signature: Vec::new(),
    };
    // Reserve the worst-case signature so the declared size never under-runs.
    tx.tx_bytes = (tx.canonical_bytes().len() + ADMISSION_PQ_SIGNATURE_MAX) as u64;
    let charge = fee_market::charge(fee_market::TxClass::Eutxo { inputs: tx.inputs.len() as u32 }, tx.tx_bytes, base_fee, tip);
    let change = total
        .checked_sub(charge.base_fee_sat + charge.priority_fee_sat + u128::from(max_surcharge_sat))
        .ok_or("inputs do not cover the fee plus the maximum surcharge")?;
    tx.change.value = u64::try_from(change).map_err(|_| "change exceeds u64")?;
    Ok(tx)
}

fn prepare(args: &[String]) -> Result<(), String> {
    let o = options(
        args,
        &[
            "--genesis", "--funding-pubkey", "--input", "--envelope", "--gas", "--pending-weight", "--headroom-units",
            "--max-surcharge-sat", "--base-fee", "--tip", "--l2-chain-id", "--out",
        ],
    )?;
    let funding_pubkey = codec::unhex(read_text(get(&o, "--funding-pubkey")?)?.trim())?;
    let mut inputs = Vec::new();
    for (_, value) in o.iter().filter(|(f, _)| f == "--input") {
        let parts: Vec<&str> = value.split(':').collect();
        let [txid, vout, sats] = parts[..] else { return Err("--input needs TXID:VOUT:SAT".into()) };
        let txid: [u8; 32] = codec::unhex(txid)?.try_into().map_err(|_| "input txid needs 32 bytes")?;
        inputs.push((
            FundingInput { txid, vout: vout.parse().map_err(|_| "bad vout")? },
            sats.parse::<u64>().map_err(|_| "bad input sats")?,
        ));
    }
    let l2_chain_id = match get(&o, "--l2-chain-id") {
        Ok(text) => text.parse().map_err(|_| "bad --l2-chain-id")?,
        Err(_) => MAINNET_CHAIN_ID,
    };
    let gas: u64 = get(&o, "--gas")?.parse().map_err(|_| "bad --gas")?;
    let max_surcharge = match (get(&o, "--max-surcharge-sat"), get(&o, "--pending-weight")) {
        (Ok(text), Err(_)) => text.parse().map_err(|_| "bad --max-surcharge-sat")?,
        (Err(_), Ok(text)) => {
            let headroom = match get(&o, "--headroom-units") {
                Ok(text) => text.parse().map_err(|_| "bad --headroom-units")?,
                Err(_) => forced::SURCHARGE_DOUBLING,
            };
            max_surcharge_for(text.parse().map_err(|_| "bad --pending-weight")?, headroom, gas)?
        }
        _ => return Err("give exactly one of --pending-weight and --max-surcharge-sat".into()),
    };
    let tx = build(
        domain(get(&o, "--genesis")?)?,
        funding_pubkey,
        inputs,
        l2_chain_id,
        gas,
        read_envelope(get(&o, "--envelope")?)?,
        max_surcharge,
        get(&o, "--base-fee")?.parse().map_err(|_| "bad --base-fee")?,
        get(&o, "--tip")?.parse().map_err(|_| "bad --tip")?,
    )?;
    inspect(&tx);
    write_tx(get(&o, "--out")?, &tx)
}

fn inspect(tx: &L2ForcedTransaction) {
    println!("L2 forced transaction (wire 0x1C)");
    println!("  network domain : {}", codec::hex32(&tx.network_domain));
    println!("  funding key    : sha3 {}", codec::hex32(&Sha3_256::digest(&tx.funding_pubkey).into()));
    for input in &tx.inputs {
        println!("  input          : {}:{}", codec::hex32(&input.txid), input.vout);
    }
    println!("  l2 chain       : {}", tx.l2_chain_id);
    println!("  declared gas   : {} ({} weight units)", tx.gas_limit, forced::weight(tx.gas_limit));
    println!("  max surcharge  : {} sat (charged at inclusion to the treasury; the rest refunded as output 1)", tx.max_surcharge_sat);
    println!("  envelope       : {} bytes, L2 hash 0x{}", tx.envelope.len(), codec::hex32(&Keccak256::digest(&tx.envelope).into()));
    println!("  change         : {} sat", tx.change.value);
    println!("  tx_bytes       : {}  tip: {} millisat/gas", tx.tx_bytes, tx.tip_millisat_per_gas);
    println!("  txid           : {}", codec::hex32(&PosTransaction::L2ForcedTransaction(tx.clone()).txid()));
    println!("  signed         : {}", !tx.signature.is_empty());
}

fn sign(args: &[String]) -> Result<(), String> {
    let o = options(args, &["--genesis", "--tx", "--dir", "--out"])?;
    let mut tx = read_tx(get(&o, "--tx")?)?;
    if tx.network_domain != domain(get(&o, "--genesis")?)? {
        return Err("transaction does not match the signer's trusted genesis manifest".into());
    }
    let keys = Keystore::load(std::path::Path::new(get(&o, "--dir")?)).map_err(|e| e.to_string())?;
    if keys.pubkey != tx.funding_pubkey {
        return Err("keystore does not own the funding key".into());
    }
    inspect(&tx);
    tx.signature = keys.sign_fitting(&tx.intent_root(), ADMISSION_PQ_SIGNATURE_MAX)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_maximum_surcharge_is_the_ceiling_at_the_depth_plus_headroom() {
        for (pending, gas) in [(0, 21_000), (0, 60_000), (31, 21_001), (32, 300_000), (200, 42_000), (250, 300_000)] {
            assert_eq!(
                Some(max_surcharge_for(pending, forced::SURCHARGE_DOUBLING, gas).unwrap()),
                forced::surcharge_ceiling_sat(pending + forced::SURCHARGE_DOUBLING, gas)
            );
        }
        // An empty queue with no headroom: a transfer may close no group, so at most 14 units of the base.
        assert_eq!(max_surcharge_for(0, 0, 21_000).unwrap(), 14 * forced::BASE_SURCHARGE_SAT);
        assert!(max_surcharge_for(0, 0, 20_999).is_err() && max_surcharge_for(0, 0, 300_001).is_err());
    }

    #[test]
    fn a_prepared_forced_transaction_conserves_value_and_round_trips() {
        let key = vec![0x42; bloch_pos_committee::transition::funded::ADMISSION_PQ_KEY_BYTES];
        let inputs = vec![
            (FundingInput { txid: [9; 32], vout: 1 }, 2_000_000),
            (FundingInput { txid: [3; 32], vout: 0 }, 1_000_000),
        ];
        let base_fee = 5_000u128;
        let tx = build([7; 32], key, inputs, MAINNET_CHAIN_ID, 60_000, vec![0x02, 0xf8, 0x01], 3_000, base_fee, 0).unwrap();
        assert_eq!(tx.max_surcharge_sat, 3_000);
        assert!(tx.inputs.windows(2).all(|w| w[0] < w[1]), "inputs in canonical order");
        let charge = fee_market::charge(fee_market::TxClass::Eutxo { inputs: 2 }, tx.tx_bytes, base_fee, 0);
        assert_eq!(
            u128::from(tx.change.value) + charge.base_fee_sat + charge.priority_fee_sat + 3 * 1_000,
            3_000_000,
            "inputs = change + fee + the maximum surcharge"
        );
        assert!(tx.tx_bytes >= tx.canonical_bytes().len() as u64 + ADMISSION_PQ_SIGNATURE_MAX as u64 - 1);
        let wire = PosTransaction::L2ForcedTransaction(tx);
        assert_eq!(PosTransaction::from_canonical_bytes(&wire.canonical_bytes()).unwrap(), wire);
        // Too little to fund the maximum surcharge, or a gas outside the bounds.
        assert!(build([7; 32], vec![0x42; 4], vec![(FundingInput { txid: [1; 32], vout: 0 }, 10)], 1, 21_000, vec![1], 1_000, 0, 0).is_err());
        assert!(build([7; 32], vec![0x42; 4], vec![(FundingInput { txid: [1; 32], vout: 0 }, 1 << 40)], 1, 20_999, vec![1], 0, 0, 0).is_err());
    }
}
