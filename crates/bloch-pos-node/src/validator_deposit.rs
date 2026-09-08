// SPDX-License-Identifier: AGPL-3.0-or-later
//! Offline funded-deposit workflow. Each signer opens only its own keystore;
//! broadcasting remains an explicit sendrawtransaction RPC operation.

use crate::{codec, genesis::Manifest, keys::Keystore};
use bloch_pos_committee::{
    beacon::RandaoChain,
    transition::{FundedDeposit, FundingInput, PosTransaction, TransferOutput},
};
use sha3::{Digest, Sha3_256};
use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    io::{Read, Write},
    path::Path,
};

const HELP: &str = "Funded PQ validator admission (offline; does not broadcast)

prepare --genesis FILE --funding-pubkey HEX_FILE --validator-pubkey HEX_FILE
        --randao HEX32 --withdrawal HEX32 --change HEX32 --stake SAT
        --input TXID:VOUT:SAT [--input ...] --max-base-fee MILLISAT_PER_GAS
        --tip MILLISAT_PER_GAS --expiry EPOCH --commission BPS --out FILE
inspect --tx FILE
sign --tx FILE --role funding|validator --dir KEYSTORE_DIR --out NEW_FILE

The prepare input values are estimates; consensus resolves the actual UTXOs.
Inspect the complete intent on each signing machine before signing. Key files
contain the hex of suite-enveloped public keys. Transaction files contain hex.
Use separate sealed keystores; each sign invocation unlocks only the selected
role. Never pass a secret or passphrase as a command-line argument.
The validator's index is assigned by consensus. Joining keystores use index
auto (4294967295); the running node resolves the public key after registration.
Query getvalidatoradmission before submission: an unarmed activation is null.";

fn error(message: impl ToString) -> String {
    message.to_string()
}

fn read_text(path: &str) -> Result<String, String> {
    let mut text = String::new();
    std::fs::File::open(path)
        .map_err(error)?
        .take(100_001)
        .read_to_string(&mut text)
        .map_err(error)?;
    if text.len() > 100_000 {
        return Err("file exceeds the offline input limit".into());
    }
    Ok(text)
}

fn read_hex(path: &str) -> Result<Vec<u8>, String> {
    codec::unhex(read_text(path)?.trim())
}

fn read_tx(path: &str) -> Result<FundedDeposit, String> {
    match PosTransaction::from_canonical_bytes(&read_hex(path)?).map_err(error)? {
        PosTransaction::FundedDeposit(tx) => Ok(tx),
        _ => Err("expected a funded deposit (wire 0x0b)".into()),
    }
}

fn write_tx(path: &str, tx: &FundedDeposit) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(error)?;
    writeln!(file, "{}", codec::hex(&tx.canonical_bytes())).map_err(error)?;
    file.sync_all().map_err(error)
}

struct Args(BTreeMap<String, Vec<String>>);
impl Args {
    fn parse(args: &[String], allowed: &[&str]) -> Result<Self, String> {
        let mut map = BTreeMap::<String, Vec<String>>::new();
        let mut iter = args.iter();
        while let Some(flag) = iter.next() {
            if !allowed.contains(&flag.as_str()) {
                return Err(format!("unknown option {flag}"));
            }
            let value = iter
                .next()
                .ok_or_else(|| format!("missing value for {flag}"))?;
            let values = map.entry(flag.clone()).or_default();
            if flag != "--input" && !values.is_empty() {
                return Err(format!("duplicate option {flag}"));
            }
            values.push(value.clone());
        }
        Ok(Self(map))
    }
    fn get(&self, flag: &str) -> Result<&str, String> {
        self.0
            .get(flag)
            .and_then(|v| v.first())
            .map(String::as_str)
            .ok_or_else(|| format!("missing {flag}"))
    }
    fn number<T: std::str::FromStr>(&self, flag: &str) -> Result<T, String> {
        self.get(flag)?
            .parse()
            .map_err(|_| format!("invalid integer for {flag}"))
    }
    fn hash(&self, flag: &str) -> Result<[u8; 32], String> {
        codec::unhex(self.get(flag)?)?
            .try_into()
            .map_err(|_| format!("{flag} needs 32 bytes"))
    }
}

fn prepare(args: &[String]) -> Result<(), String> {
    let a = Args::parse(
        args,
        &[
            "--genesis",
            "--funding-pubkey",
            "--validator-pubkey",
            "--randao",
            "--withdrawal",
            "--change",
            "--stake",
            "--input",
            "--max-base-fee",
            "--tip",
            "--expiry",
            "--commission",
            "--out",
        ],
    )?;
    let (manifest, _) = Manifest::load(Path::new(a.get("--genesis")?)).map_err(error)?;
    let mut total = 0u128;
    let mut inputs = Vec::new();
    for text in
        a.0.get("--input")
            .ok_or("at least one --input is required")?
    {
        let mut fields = text.split(':');
        let txid = codec::unhex(fields.next().ok_or("input needs TXID:VOUT:SAT")?)?
            .try_into()
            .map_err(|_| "input TXID needs 32 bytes")?;
        let vout = fields
            .next()
            .ok_or("input needs VOUT")?
            .parse()
            .map_err(|_| "invalid VOUT")?;
        let value: u64 = fields
            .next()
            .ok_or("input needs SAT")?
            .parse()
            .map_err(|_| "invalid SAT")?;
        if fields.next().is_some() {
            return Err("input needs exactly TXID:VOUT:SAT".into());
        }
        total = total
            .checked_add(u128::from(value))
            .ok_or("input sum overflow")?;
        inputs.push(FundingInput { txid, vout });
    }
    inputs.sort();
    let mut tx = FundedDeposit {
        network_domain: Sha3_256::digest(manifest.encode()).into(),
        valid_until_epoch: a.number("--expiry")?,
        funding_pubkey: read_hex(a.get("--funding-pubkey")?)?,
        inputs,
        validator_pubkey: read_hex(a.get("--validator-pubkey")?)?,
        amount_sat: a.number("--stake")?,
        randao_commitment: a.hash("--randao")?,
        withdrawal_credentials: a.hash("--withdrawal")?,
        commission_bps: a.number("--commission")?,
        change: TransferOutput {
            value: 1_000,
            script_hash: a.hash("--change")?,
        },
        max_base_fee_millisat_per_gas: a.number("--max-base-fee")?,
        tip_millisat_per_gas: a.number("--tip")?,
        tx_bytes: 0,
        funding_signature: Vec::new(),
        proof_of_possession: Vec::new(),
    };
    tx.tx_bytes = tx.reserved_tx_bytes();
    tx.validate_shape()
        .map_err(|e| format!("invalid deposit: {e:?}"))?;
    let fees = tx.charge(tx.max_base_fee_millisat_per_gas);
    let change = total
        .checked_sub(tx.amount_sat)
        .and_then(|v| v.checked_sub(fees.base_fee_sat))
        .and_then(|v| v.checked_sub(fees.priority_fee_sat))
        .ok_or("insufficient funding for stake and fee budget")?;
    tx.change.value = u64::try_from(change).map_err(|_| "change exceeds a u64 UTXO")?;
    tx.validate_shape()
        .map_err(|e| format!("invalid change or deposit: {e:?}"))?;
    inspect(&tx);
    write_tx(a.get("--out")?, &tx)
}

fn inspect(tx: &FundedDeposit) {
    let pk_hash = |key: &[u8]| codec::hex(&Sha3_256::digest(key));
    println!("Network domain: {}", codec::hex(&tx.network_domain));
    println!("Funding authority: {}", pk_hash(&tx.funding_pubkey));
    println!(
        "Validator public-key hash: {}",
        pk_hash(&tx.validator_pubkey)
    );
    println!(
        "Stake (sat): {}\nCommission (bps): {}\nExpiry (inclusive epoch): {}",
        tx.amount_sat, tx.commission_bps, tx.valid_until_epoch
    );
    println!(
        "RANDAO commitment: {}\nWithdrawal script: {}",
        codec::hex(&tx.randao_commitment),
        codec::hex(&tx.withdrawal_credentials)
    );
    for input in &tx.inputs {
        println!("Input: {}:{}", codec::hex(&input.txid), input.vout);
    }
    println!(
        "Minimum change (sat): {}\nChange/refund script: {}",
        tx.change.value,
        codec::hex(&tx.change.script_hash)
    );
    println!(
        "Maximum base fee (millisat/gas): {}\nTip (millisat/gas): {}\nReserved bytes: {}",
        tx.max_base_fee_millisat_per_gas, tx.tip_millisat_per_gas, tx.tx_bytes
    );
    let budget = tx.charge(tx.max_base_fee_millisat_per_gas);
    println!(
        "Base-fee budget (sat): {}\nPriority fee (sat): {}\nRequired inputs (sat): {:?}",
        budget.base_fee_sat,
        budget.priority_fee_sat,
        tx.required_funding_sat()
    );
    println!(
        "Funding signing root: {}\nPossession signing root: {}",
        codec::hex(&tx.funding_root()),
        codec::hex(&tx.possession_root())
    );
    println!(
        "Transaction id: {}",
        codec::hex(&PosTransaction::FundedDeposit(tx.clone()).txid())
    );
    println!(
        "Funding signature present: {}\nPossession signature present: {}",
        !tx.funding_signature.is_empty(),
        !tx.proof_of_possession.is_empty()
    );
}

fn sign(args: &[String]) -> Result<(), String> {
    let a = Args::parse(args, &["--tx", "--role", "--dir", "--out"])?;
    let mut tx = read_tx(a.get("--tx")?)?;
    let role = a.get("--role")?;
    if role != "funding" && role != "validator" {
        return Err("role must be funding or validator".into());
    }
    // Verify any existing signatures before opening a secret. An invalid
    // counterparty signature must not be laundered into a signed artifact.
    for (pk, root, sig) in [
        (&tx.funding_pubkey, tx.funding_root(), &tx.funding_signature),
        (
            &tx.validator_pubkey,
            tx.possession_root(),
            &tx.proof_of_possession,
        ),
    ] {
        if !sig.is_empty() && !bloch_crypto::crypto::verify(pk, &root, sig) {
            return Err("existing authorization does not match the intent".into());
        }
    }
    let keys = Keystore::load(Path::new(a.get("--dir")?)).map_err(error)?;
    let expected = if role == "funding" {
        &tx.funding_pubkey
    } else {
        &tx.validator_pubkey
    };
    if &keys.pubkey != expected {
        return Err("keystore does not own the selected role".into());
    }
    if role == "validator"
        && RandaoChain::generate(keys.randao_seed).commitment() != tx.randao_commitment
    {
        return Err("validator keystore does not open the signed RANDAO commitment".into());
    }
    inspect(&tx);
    if role == "funding" {
        tx.funding_signature = keys.sign(&tx.funding_root());
    } else {
        tx.proof_of_possession = keys.sign(&tx.possession_root());
    }
    if !tx.funding_signature.is_empty() && !tx.proof_of_possession.is_empty() {
        tx.verify_authorizations(&crate::keys::HybridVerifier::new())
            .map_err(|e| format!("authorization failed: {e:?}"))?;
    }
    write_tx(a.get("--out")?, &tx)
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
            let a = Args::parse(rest, &["--tx"])?;
            inspect(&read_tx(a.get("--tx")?)?);
            Ok(())
        }
        _ => Err("expected prepare, inspect, sign or --help".into()),
    }
}
