// SPDX-License-Identifier: AGPL-3.0-or-later
//! Offline unsigned self-conversion of one legacy hybrid UTXO to suite-1 funding.
//! No keys are unlocked and no network request or transaction is submitted.
use bloch_pos_committee::{
    fee_market::{self, TxClass},
    params,
    transition::{
        funded::ADMISSION_PQ_SIGNATURE_MAX, PosTransaction, TransferInputV2, TransferOutput,
        WitnessKey,
    },
};
use sha3::{Digest, Sha3_256};
use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    io::{Read, Write},
};
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn unhex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 || !s.is_ascii() {
        return Err("Invalid hex".into());
    }
    s.as_bytes()
        .chunks_exact(2)
        .map(|b| {
            u8::from_str_radix(std::str::from_utf8(b).map_err(|_| "Invalid hex")?, 16)
                .map_err(|_| "Invalid hex".into())
        })
        .collect()
}
fn hash(b: &[u8]) -> [u8; 32] {
    Sha3_256::digest(b).into()
}
struct Plan {
    tx: PosTransaction,
    native_key: Vec<u8>,
    legacy: [u8; 32],
    native: [u8; 32],
    fee: u64,
}
fn plan(
    pubkey: Vec<u8>,
    txid: [u8; 32],
    vout: u32,
    value: u64,
    amount: u64,
    base: u128,
    tip: u128,
    cap: u64,
) -> Result<Plan, String> {
    if pubkey.len() != 3745 {
        return Err("Expected a raw legacy hybrid public key of 3745 bytes".into());
    }
    if !(fee_market::MIN_BASE_FEE_MILLISAT_PER_GAS..=fee_market::MAX_BASE_FEE_MILLISAT_PER_GAS)
        .contains(&base)
        || tip > fee_market::MAX_TIP_MILLISAT_PER_GAS
    {
        return Err("Fee rate outside consensus bounds".into());
    }
    if amount < params::MIN_TRANSFER_OUTPUT_SAT {
        return Err("Native output below relay minimum".into());
    }
    let mut native_key = vec![0xb1, 0x0c, 1, 0];
    native_key.extend_from_slice(&pubkey);
    let native = hash(&native_key);
    let mut legacy = hash(&pubkey);
    legacy[20..].fill(0);
    let mut tx = PosTransaction::TransferV2 {
        keys: vec![WitnessKey {
            pubkey,
            signature: vec![],
        }],
        inputs: vec![TransferInputV2 {
            txid,
            vout,
            key_index: 0,
        }],
        outputs: vec![
            TransferOutput {
                value: amount,
                script_hash: native,
            },
            TransferOutput {
                value: 0,
                script_hash: legacy,
            },
        ],
        tx_bytes: 0,
        tip_millisat_per_gas: tip,
    };
    let reserved = (tx.canonical_bytes().len() as u64)
        .checked_add(ADMISSION_PQ_SIGNATURE_MAX as u64)
        .ok_or("Size overflow")?;
    let charge = fee_market::charge(TxClass::Eutxo { inputs: 1 }, reserved, base, tip);
    let fee = u64::try_from(
        charge
            .base_fee_sat
            .checked_add(charge.priority_fee_sat)
            .ok_or("Fee overflow")?,
    )
    .map_err(|_| "Fee overflow")?;
    if fee > cap {
        return Err("Fee exceeds approved cap".into());
    }
    let change = value
        .checked_sub(amount)
        .and_then(|v| v.checked_sub(fee))
        .ok_or("Insufficient input")?;
    if change < params::MIN_TRANSFER_OUTPUT_SAT {
        return Err(
            "Change below relay minimum; choose a larger input or a separate exact-spend plan"
                .into(),
        );
    }
    if let PosTransaction::TransferV2 {
        outputs, tx_bytes, ..
    } = &mut tx
    {
        outputs[1].value = change;
        *tx_bytes = reserved;
    }
    Ok(Plan {
        tx,
        native_key,
        legacy,
        native,
        fee,
    })
}
fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args == ["--help"] {
        println!("Offline unsigned legacy-to-native self-conversion\n--pubkey FILE --txid HEX32 --vout N --input-value SAT --amount SAT --base-fee MILLISAT --tip MILLISAT --max-fee SAT --epoch N --out NEW_FILE\nOne input; output 0 is the same key with suite-1 envelope, output 1 returns legacy change. No signing or broadcast. Input observations are not proofs.");
        return Ok(());
    }
    let allowed = [
        "--pubkey",
        "--txid",
        "--vout",
        "--input-value",
        "--amount",
        "--base-fee",
        "--tip",
        "--max-fee",
        "--epoch",
        "--out",
    ];
    if args.len() != allowed.len() * 2 {
        return Err("Use --help for required options".into());
    }
    let mut a = BTreeMap::new();
    for pair in args.chunks_exact(2) {
        if !allowed.contains(&pair[0].as_str())
            || a.insert(pair[0].as_str(), pair[1].as_str()).is_some()
        {
            return Err("Unknown or duplicate option".into());
        }
    }
    let get = |k| a.get(k).copied().ok_or_else(|| format!("Missing {k}"));
    let number =
        |k| -> Result<u128, String> { get(k)?.parse().map_err(|_| format!("Invalid {k}")) };
    let u64n = |k| -> Result<u64, String> {
        u64::try_from(number(k)?).map_err(|_| format!("Overflow {k}"))
    };
    let epoch = u64n("--epoch")?;
    if epoch < params::TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH || epoch == u64::MAX {
        return Err("Invalid TransferV2 epoch".into());
    }
    let mut text = String::new();
    std::fs::File::open(get("--pubkey")?)
        .map_err(|e| e.to_string())?
        .take(10001)
        .read_to_string(&mut text)
        .map_err(|e| e.to_string())?;
    if text.len() > 10000 {
        return Err("Public key file too large".into());
    }
    let txid: [u8; 32] = unhex(get("--txid")?)?
        .try_into()
        .map_err(|_| "Expected hex32 txid")?;
    let p = plan(
        unhex(text.trim())?,
        txid,
        u32::try_from(number("--vout")?).map_err(|_| "Invalid vout")?,
        u64n("--input-value")?,
        u64n("--amount")?,
        number("--base-fee")?,
        number("--tip")?,
        u64n("--max-fee")?,
    )?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut f = options.open(get("--out")?).map_err(|e| e.to_string())?;
    writeln!(f, "{}", hex(&p.tx.canonical_bytes())).map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())?;
    println!("Input outpoint: {}:{}\nObserved input value (sat): {}\nNative amount (sat): {}\nLegacy change (sat): {}",hex(&txid),number("--vout")?,u64n("--input-value")?,u64n("--amount")?,u64n("--input-value")?-u64n("--amount")?-p.fee);
    println!("Legacy input/change script: {}\nNative funding script: {}\nNative public key: {}\nExact fee (sat): {}\nSigning root: {}\nTransaction id: {}\nUnsigned only; nothing sent. Input value and ownership require independent verification.",hex(&p.legacy),hex(&p.native),hex(&p.native_key),p.fee,hex(&p.tx.checked_signing_root(epoch)),hex(&p.tx.txid()));
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("Plan refused: {e}");
        std::process::exit(1);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preserves_key_authority_and_conserves_value() {
        let p = plan(
            vec![1; 3745],
            [2; 32],
            1,
            4_000_000_000_000,
            2_500_001_000_000,
            10,
            5,
            1_000_000,
        )
        .unwrap();
        assert_eq!(&p.native_key[4..], &vec![1; 3745]);
        assert_eq!(&p.legacy[20..], &[0; 12]);
        assert_eq!(p.native, hash(&p.native_key));
        let decoded = PosTransaction::from_canonical_bytes(&p.tx.canonical_bytes()).unwrap();
        assert_eq!(decoded.txid(), p.tx.txid());
        if let PosTransaction::TransferV2 { outputs, keys, .. } = decoded {
            assert_eq!(
                outputs[0].value + outputs[1].value + p.fee,
                4_000_000_000_000
            );
            assert!(keys[0].signature.is_empty());
            assert_eq!(outputs[1].script_hash, p.legacy);
        } else {
            panic!("wrong wire");
        }
    }
    #[test]
    fn same_real_key_verifies_legacy_and_native_signatures() {
        let (public, secret) = bloch_crypto::crypto::generate_keypair();
        let raw = public[4..].to_vec();
        let mut p = plan(
            raw.clone(),
            [2; 32],
            1,
            4_000_000_000_000,
            2_500_001_000_000,
            10,
            5,
            1_000_000,
        )
        .unwrap();
        assert_eq!(p.native_key, public);
        let root = p.tx.checked_signing_root(5000);
        let signature = bloch_crypto::crypto::sign(&secret, &root).unwrap();
        assert!(bloch_crypto::crypto::verify(&raw, &root, &signature));
        assert!(bloch_crypto::crypto::verify(
            &p.native_key,
            &root,
            &signature
        ));
        if let PosTransaction::TransferV2 { keys, .. } = &mut p.tx {
            keys[0].signature = signature;
        }
        let length = p.tx.canonical_bytes().len() as u64;
        if let PosTransaction::TransferV2 { tx_bytes, .. } = p.tx {
            assert!(tx_bytes >= length);
            assert!(tx_bytes <= length + fee_market::TX_BYTES_DECLARE_SLACK);
        }
    }
    #[test]
    fn rejects_wrong_keys_caps_rates_and_insufficient_change() {
        assert!(plan(vec![1; 3749], [2; 32], 0, 10000, 1000, 10, 5, 1000).is_err());
        assert!(plan(vec![1; 3745], [2; 32], 0, 10000, 1000, 0, 5, 1000).is_err());
        assert!(plan(vec![1; 3745], [2; 32], 0, 10000, 1000, 10, 5, 0).is_err());
        assert!(plan(vec![1; 3745], [2; 32], 0, 1000, 1000, 10, 5, 1000).is_err());
    }
}
