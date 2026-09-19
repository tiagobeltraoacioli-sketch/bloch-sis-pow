// SPDX-License-Identifier: AGPL-3.0-or-later
//! Offline single-withdrawal payout spending. No RPC, broadcast or key generation.

use crate::{
    codec,
    keys::{Keystore, Unlock},
};
use bloch_pos_committee::{
    fee_market::{self, TxClass},
    transition::{
        funded::{ADMISSION_PQ_KEY_BYTES, ADMISSION_PQ_SIGNATURE_MAX},
        PosTransaction, TransferInputV2, TransferOutput, WitnessKey,
    },
};
use sha3::{Digest, Sha3_256};
use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    io::{Read, Write},
    path::Path,
};

const HELP: &str = "Validator withdrawal payout (offline; does not broadcast)

prepare --pubkey HEX_FILE --out NEW_FILE COMMON_OPTIONS
inspect --tx HEX_FILE COMMON_OPTIONS
sign --tx HEX_FILE --dir KEYSTORE_DIR --expected-root HEX32 --out NEW_FILE COMMON_OPTIONS

COMMON_OPTIONS:
  --validator INDEX --input-value SAT --withdrawal-script HEX32
  --destination HEX32 --base-fee MILLISAT_PER_GAS --epoch INCLUSION_EPOCH
  --max-fee SAT
prepare also requires --tip MILLISAT_PER_GAS.

Spends exactly the selected validator's Withdraw output 0 into one destination,
less the exact fee. Obtain the payout value and withdrawal credential from your
own synchronized node and verify finality before using these options. Offline
checks cannot prove that an input exists, is mature, or remains unspent.
Inspect on the signing machine and independently approve the expected root,
destination and fee cap before signing with the withdrawal owner's sealed key.
Input values, base fee and inclusion epoch are operator observations, not proofs.
If the base fee changes, prepare and sign again: TransferV2 has exact conservation,
not a fee-budget refund. The epoch selects the signing rules; it is NOT an expiry.
The current network-binding gate is unarmed: use distinct keys across networks.
This command creates no keys, changes no consensus parameters and sends nothing.";

const COMMON: &[&str] = &[
    "--validator",
    "--input-value",
    "--withdrawal-script",
    "--destination",
    "--base-fee",
    "--epoch",
    "--max-fee",
];
const MAX_TEXT_BYTES: u64 = 32_768;

struct Args(BTreeMap<String, String>);
impl Args {
    fn parse(args: &[String], extra: &[&str]) -> Result<Self, String> {
        let mut values = BTreeMap::new();
        let mut iter = args.iter();
        while let Some(flag) = iter.next() {
            if !COMMON.contains(&flag.as_str()) && !extra.contains(&flag.as_str()) {
                return Err(format!("unknown option {flag}"));
            }
            let value = iter
                .next()
                .ok_or_else(|| format!("missing value for {flag}"))?;
            if values.insert(flag.clone(), value.clone()).is_some() {
                return Err(format!("duplicate option {flag}"));
            }
        }
        Ok(Self(values))
    }
    fn get(&self, flag: &str) -> Result<&str, String> {
        self.0
            .get(flag)
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

struct Observation {
    validator: u32,
    value: u64,
    withdrawal: [u8; 32],
    destination: [u8; 32],
    base_fee: u128,
    epoch: u64,
    max_fee: u64,
}
impl Observation {
    fn read(a: &Args) -> Result<Self, String> {
        let observation = Self {
            validator: a.number("--validator")?,
            value: a.number("--input-value")?,
            withdrawal: a.hash("--withdrawal-script")?,
            destination: a.hash("--destination")?,
            base_fee: a.number("--base-fee")?,
            epoch: a.number("--epoch")?,
            max_fee: a.number("--max-fee")?,
        };
        if observation.value == 0
            || observation.validator == u32::MAX
            || observation.epoch == u64::MAX
        {
            return Err("invalid payout value, validator index or inclusion epoch".into());
        }
        if !(fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS..=fee_market::MAX_BASE_FEE_MILLISAT_PER_GAS)
            .contains(&observation.base_fee)
        {
            return Err("base fee is outside the consensus range".into());
        }
        if observation.epoch < bloch_pos_committee::params::WITHDRAWAL_ACTIVATION_EPOCH
            || observation.epoch
                < bloch_pos_committee::params::TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH
        {
            return Err("withdrawal and TransferV2 must be active at the inclusion epoch".into());
        }
        Ok(observation)
    }
    fn outpoint(&self) -> [u8; 32] {
        PosTransaction::Withdraw {
            validator: self.validator,
        }
        .txid()
    }
}

fn read_hex(path: &str) -> Result<Vec<u8>, String> {
    let mut text = String::new();
    std::fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(MAX_TEXT_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|e| e.to_string())?;
    if text.len() as u64 > MAX_TEXT_BYTES {
        return Err("offline file exceeds 32768 bytes".into());
    }
    codec::unhex(text.trim())
}
fn read_tx(path: &str) -> Result<PosTransaction, String> {
    PosTransaction::from_canonical_bytes(&read_hex(path)?)
        .map_err(|e| format!("invalid transaction: {e:?}"))
}
fn ensure_new(path: &str) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.to_string()),
        Ok(_) => Err("output already exists; refusing to overwrite".into()),
    }
}
fn write_tx(path: &str, tx: &PosTransaction) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|e| e.to_string())?;
    writeln!(file, "{}", codec::hex(&tx.canonical_bytes())).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())
}
fn check_pubkey(pubkey: &[u8], withdrawal: &[u8; 32]) -> Result<(), String> {
    if pubkey.len() != ADMISSION_PQ_KEY_BYTES || !pubkey.starts_with(&[0xb1, 0x0c, 1, 0]) {
        return Err("expected a suite-1 hybrid public key".into());
    }
    let hash: [u8; 32] = Sha3_256::digest(pubkey).into();
    if &hash != withdrawal {
        return Err("public key does not own the observed withdrawal credential".into());
    }
    Ok(())
}
fn verify_payout_signature(public_key: &[u8], root: &[u8], signature: &[u8]) -> bool {
    if bloch_crypto::crypto::verify_enveloped(public_key, root, signature) {
        return true;
    }
    if public_key.len() == ADMISSION_PQ_KEY_BYTES
        && public_key.starts_with(&[0xb1, 0x0c, 1, 0])
        && bloch_crypto::crypto::verify_legacy_hybrid_raw(
            &public_key[bloch_crypto::crypto::SUITE_HEADER_LEN..],
            root,
            signature,
        )
    {
        return true;
    }
    bloch_crypto::crypto::verify(public_key, root, signature)
}
fn fee(bytes: u64, tip: u128, o: &Observation) -> Result<u64, String> {
    if tip > fee_market::MAX_TIP_MILLISAT_PER_GAS {
        return Err("tip exceeds consensus maximum".into());
    }
    let charge = fee_market::charge(TxClass::Eutxo { inputs: 1 }, bytes, o.base_fee, tip);
    let total = charge
        .base_fee_sat
        .checked_add(charge.priority_fee_sat)
        .ok_or("fee overflow")?;
    let total = u64::try_from(total).map_err(|_| "fee exceeds a u64 payout")?;
    if total > o.max_fee {
        return Err("fee exceeds the operator's --max-fee".into());
    }
    if total >= o.value {
        return Err("payout cannot cover fee and a positive output".into());
    }
    if o.value
        .checked_sub(total)
        .is_none_or(|value| value < bloch_pos_committee::params::MIN_TRANSFER_OUTPUT_SAT)
    {
        return Err("payout output is below the node minimum of 1000 satoshis".into());
    }
    Ok(total)
}
fn reserved_size(tx: &PosTransaction) -> Result<u64, String> {
    let mut unsigned = tx.clone();
    if let PosTransaction::TransferV2 { keys, .. } = &mut unsigned {
        keys.first_mut()
            .ok_or("missing payout key")?
            .signature
            .clear();
    }
    (unsigned.canonical_bytes().len() as u64)
        .checked_add(ADMISSION_PQ_SIGNATURE_MAX as u64)
        .ok_or_else(|| "signature reservation overflow".into())
}

/// Every check here runs before unlocking a keystore, including existing signatures.
fn inspect(tx: &PosTransaction, o: &Observation) -> Result<(), String> {
    let PosTransaction::TransferV2 {
        keys,
        inputs,
        outputs,
        tx_bytes,
        tip_millisat_per_gas,
    } = tx
    else {
        return Err("expected a TransferV2 payout (wire 0x06)".into());
    };
    if keys.len() != 1 || inputs.len() != 1 || outputs.len() != 1 || inputs[0].key_index != 0 {
        return Err("payout requires one key, one input and one output".into());
    }
    check_pubkey(&keys[0].pubkey, &o.withdrawal)?;
    if inputs[0].txid != o.outpoint() || inputs[0].vout != 0 {
        return Err("input is not the selected validator's withdrawal output 0".into());
    }
    if outputs[0].script_hash != o.destination {
        return Err("destination does not match the operator's intent".into());
    }
    if *tx_bytes != reserved_size(tx)? {
        return Err("unexpected signature byte reservation".into());
    }
    let total_fee = fee(*tx_bytes, *tip_millisat_per_gas, o)?;
    if Some(outputs[0].value) != o.value.checked_sub(total_fee) {
        return Err("observed payout value, output and exact fee do not conserve".into());
    }
    let root = tx.checked_signing_root(o.epoch);
    let signature = &keys[0].signature;
    if !signature.is_empty()
        && (signature.len() > ADMISSION_PQ_SIGNATURE_MAX
            || !verify_payout_signature(&keys[0].pubkey, &root, signature))
    {
        return Err("invalid existing payout signature".into());
    }
    println!(
        "Validator: {}\nPayout input: {}:0\nObserved input value (sat): {}",
        o.validator,
        codec::hex(&o.outpoint()),
        o.value
    );
    println!(
        "Withdrawal credential: {}\nDestination: {}\nOutput value (sat): {}",
        codec::hex(&o.withdrawal),
        codec::hex(&o.destination),
        outputs[0].value
    );
    println!("Base fee (millisat/gas): {}\nTip (millisat/gas): {}\nExact fee (sat): {}\nOperator fee cap (sat): {}\nReserved bytes: {}", o.base_fee, tip_millisat_per_gas, total_fee, o.max_fee, tx_bytes);
    println!("Signing epoch (not expiry): {}\nSigning root: {}\nTransaction id: {}\nSignature present: {}", o.epoch, codec::hex(&root), codec::hex(&tx.txid()), !signature.is_empty());
    println!("Offline observations are not UTXO/finality proofs. Nothing was broadcast.");
    Ok(())
}
fn prepare(args: &[String]) -> Result<(), String> {
    let a = Args::parse(args, &["--pubkey", "--tip", "--out"])?;
    let o = Observation::read(&a)?;
    let out = a.get("--out")?;
    ensure_new(out)?;
    let pubkey = read_hex(a.get("--pubkey")?)?;
    check_pubkey(&pubkey, &o.withdrawal)?;
    let tip = a.number("--tip")?;
    let mut tx = PosTransaction::TransferV2 {
        keys: vec![WitnessKey {
            pubkey,
            signature: Vec::new(),
        }],
        inputs: vec![TransferInputV2 {
            txid: o.outpoint(),
            vout: 0,
            key_index: 0,
        }],
        outputs: vec![TransferOutput {
            value: 1,
            script_hash: o.destination,
        }],
        tx_bytes: 0,
        tip_millisat_per_gas: tip,
    };
    let reserved = reserved_size(&tx)?;
    let total_fee = fee(reserved, tip, &o)?;
    if let PosTransaction::TransferV2 {
        tx_bytes, outputs, ..
    } = &mut tx
    {
        *tx_bytes = reserved;
        outputs[0].value = o.value.checked_sub(total_fee).ok_or("fee exceeds payout")?;
    }
    inspect(&tx, &o)?;
    write_tx(out, &tx)
}
fn sign(args: &[String]) -> Result<(), String> {
    let a = Args::parse(args, &["--tx", "--dir", "--expected-root", "--out"])?;
    let o = Observation::read(&a)?;
    let out = a.get("--out")?;
    let dir = a.get("--dir")?;
    ensure_new(out)?;
    let expected = a.hash("--expected-root")?;
    let mut tx = read_tx(a.get("--tx")?)?;
    inspect(&tx, &o)?;
    let root = tx.checked_signing_root(o.epoch);
    if root != expected {
        return Err("signing root does not match the independently approved intent".into());
    }
    let PosTransaction::TransferV2 { keys, .. } = &tx else {
        return Err("expected a TransferV2 payout".into());
    };
    if !keys[0].signature.is_empty() {
        return Err("payout is already signed".into());
    }
    let unlock = Unlock::from_env().map_err(|e| e.to_string())?;
    if matches!(unlock, Unlock::PlaintextOptIn) {
        return Err("payout signing requires a sealed keystore and passphrase".into());
    }
    let signer = Keystore::load_with(Path::new(dir), &unlock).map_err(|e| e.to_string())?;
    if signer.pubkey != keys[0].pubkey {
        return Err("keystore does not own this payout".into());
    }
    if let PosTransaction::TransferV2 { keys, .. } = &mut tx {
        keys[0].signature = signer.sign(&root);
    }
    inspect(&tx, &o)?;
    write_tx(out, &tx)
}
pub fn run(args: &[String]) -> Result<(), String> {
    let Some((command, rest)) = args.split_first() else {
        println!("{HELP}");
        return Ok(());
    };
    match command.as_str() {
        "help" | "--help" => {
            println!("{HELP}");
            Ok(())
        }
        "prepare" => prepare(rest),
        "sign" => sign(rest),
        "inspect" => {
            let a = Args::parse(rest, &["--tx"])?;
            inspect(&read_tx(a.get("--tx")?)?, &Observation::read(&a)?)
        }
        _ => Err("expected prepare, inspect, sign or --help".into()),
    }
}

#[cfg(test)]
mod audit_signature_policy_tests {
    use super::*;

    #[test]
    fn explicit_policy_accepts_genuine_magic_prefixed_raw_payout_signature() {
        const SEARCH_COUNTER: u64 = 19_830;
        const SIGNING_SEED_HEX: &str =
            "669adde213cc9d27054989bc755943b83364b48aa4b146f492421402b7b997ea";
        const ROOT_HEX: &str =
            "14dd03330118a6495e0880801a40438e67a880adfa80e78b5adbf8807b5fcdb4";

        let (pubkey, secret_key) =
            bloch_crypto::crypto::generate_keypair_from_seed(&[0x69; 32]).unwrap();
        let o = Observation {
            validator: 71,
            value: 2_500_000_000_000,
            withdrawal: Sha3_256::digest(&pubkey).into(),
            destination: [0x82; 32],
            base_fee: 10,
            epoch: 5000,
            max_fee: 1_000_000,
        };
        let mut tx = PosTransaction::TransferV2 {
            keys: vec![WitnessKey { pubkey: pubkey.clone(), signature: vec![] }],
            inputs: vec![TransferInputV2 { txid: o.outpoint(), vout: 0, key_index: 0 }],
            outputs: vec![TransferOutput { value: 1, script_hash: o.destination }],
            tx_bytes: 0,
            tip_millisat_per_gas: 5,
        };
        let reserved = reserved_size(&tx).unwrap();
        let total_fee = fee(reserved, 5, &o).unwrap();
        if let PosTransaction::TransferV2 { tx_bytes, outputs, .. } = &mut tx {
            *tx_bytes = reserved;
            outputs[0].value = o.value - total_fee;
        }
        let root = tx.checked_signing_root(o.epoch);
        assert_eq!(codec::hex(&root), ROOT_HEX);

        let mut h = Sha3_256::new();
        h.update(b"bloch/validator-payout/cr10/signing-rng/v1");
        h.update(SEARCH_COUNTER.to_le_bytes());
        let signing_seed: [u8; 32] = h.finalize().into();
        assert_eq!(codec::hex(&signing_seed), SIGNING_SEED_HEX);
        let enveloped_signature =
            pqcrypto_internals::with_seeded_rng_scope(&signing_seed, || {
                bloch_crypto::crypto::sign(&secret_key, &root).unwrap()
            });
        assert!(verify_payout_signature(&pubkey, &root, &enveloped_signature));
        assert!(bloch_crypto::crypto::verify_enveloped_canonical(
            &pubkey,
            &root,
            &enveloped_signature,
        ));

        let raw_signature =
            enveloped_signature[bloch_crypto::crypto::SUITE_HEADER_LEN..].to_vec();
        assert_eq!(&raw_signature[..2], &[0xb1, 0x0c]);
        assert!(
            !bloch_crypto::crypto::verify(&pubkey, &root, &raw_signature),
            "generic autodetection must misclassify this genuine raw signature"
        );
        assert!(verify_payout_signature(&pubkey, &root, &raw_signature));

        let PosTransaction::TransferV2 { keys, .. } = &mut tx else {
            unreachable!()
        };
        keys[0].signature = raw_signature;
        assert!(inspect(&tx, &o).is_ok());
    }
}
