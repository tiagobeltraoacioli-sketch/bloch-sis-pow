// SPDX-License-Identifier: AGPL-3.0-or-later
//! REHEARSAL TOOLING ONLY (scripts/hf-rehearsal/crossing.py). Throwaway keys
//! on a throwaway loopback network; never point it at a funded network.
//!
//! The release CLI has no suite-0x0003 key generator, no suite-0x0003 spend
//! builder (`transfer-v2` reserves a lattice-sized witness) and no builder for
//! the HF3 withdrawal-credential rotation (wire 0x18). This example fills
//! those three gaps with the same consensus types and signing functions the
//! node uses, so a gate-crossing rehearsal can include them after HF3:
//!
//!   slh-keystore  --dir D --index N
//!       Writes D/validator.key, a plaintext (BPOSKEY1) keystore holding a
//!       fresh suite-0x0003 (SLH-DSA-128s + Falcon-1024) key. Prints the
//!       enveloped public key and its SHA3-256 script hash.
//!   slh-transfer  --dir D --input TXID:VOUT:SAT --to HASH --base-fee F --tip T --epoch E --out FILE
//!       A one-owner TransferV2 spending outputs owned by the suite-0x0003 key
//!       in D, priced per suite (`eutxo_class_for_keys`) at epoch E.
//!   rotate        --genesis G --auth-dir A --new-dir N --validator V --epoch E --out FILE
//!       WithdrawalCredentialRotation (0x18): the key in A (which opens the
//!       validator's current credential) moves it to SHA3-256 of the
//!       suite-0x0003 key in N. Both keys sign the rotation root.
use bloch_pos_committee::{
    fee_market,
    params::{MIN_TRANSFER_OUTPUT_SAT, SLHDSA_FALCON_MAX_ENVELOPED_SIG_LEN},
    transition::{PosTransaction, TransferInputV2, TransferOutput, WitnessKey, WithdrawalCredentialRotation},
};
use bloch_pos_node::{codec, genesis::Manifest};
use sha3::{Digest, Sha3_256};
use std::{collections::BTreeMap, path::Path, process::exit};

const MAGIC_V1: &[u8; 8] = b"BPOSKEY1";

fn die(msg: impl std::fmt::Display) -> ! {
    eprintln!("hf3_rehearsal_tool: {msg}");
    exit(2)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        die(format!("odd-length hex {s:?}"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap_or_else(|_| die(format!("bad hex {s:?}"))))
        .collect()
}

fn h32(s: &str) -> [u8; 32] {
    unhex(s).try_into().unwrap_or_else(|_| die(format!("{s:?} is not 32 bytes")))
}

struct Key {
    pubkey: Vec<u8>,
    secret: Vec<u8>,
}

fn put_bytes(out: &mut Vec<u8>, v: &[u8]) {
    out.extend_from_slice(&(v.len() as u32).to_le_bytes());
    out.extend_from_slice(v);
}

fn load_plaintext(dir: &str) -> Key {
    let bytes = std::fs::read(Path::new(dir).join("validator.key")).unwrap_or_else(|e| die(format!("{dir}: {e}")));
    if bytes.len() < 12 || &bytes[..8] != MAGIC_V1 {
        die(format!("{dir}/validator.key is not a plaintext BPOSKEY1 keystore"));
    }
    let mut at = 12;
    let mut field = || {
        let n = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
        let v = bytes[at + 4..at + 4 + n].to_vec();
        at += 4 + n;
        v
    };
    let pubkey = field();
    let secret = field();
    Key { pubkey, secret }
}

fn sign(key: &Key, root: &[u8; 32]) -> Vec<u8> {
    for _ in 0..16 {
        if let Ok(sig) = bloch_crypto::crypto::sign(&key.secret, root) {
            if sig.len() <= SLHDSA_FALCON_MAX_ENVELOPED_SIG_LEN {
                return sig;
            }
        }
    }
    die("could not produce a signature within the suite bound")
}

fn flags(args: &[String]) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    for pair in args.chunks(2) {
        if pair.len() != 2 || !pair[0].starts_with("--") {
            die("options are --name value pairs");
        }
        m.insert(pair[0].clone(), pair[1].clone());
    }
    m
}

fn get<'a>(m: &'a BTreeMap<String, String>, k: &str) -> &'a str {
    m.get(k).map(String::as_str).unwrap_or_else(|| die(format!("missing {k}")))
}

fn num<T: std::str::FromStr>(m: &BTreeMap<String, String>, k: &str) -> T {
    get(m, k).parse().unwrap_or_else(|_| die(format!("{k} must be a number")))
}

fn write_hex(path: &str, bytes: &[u8]) {
    std::fs::write(path, hex(bytes) + "\n").unwrap_or_else(|e| die(format!("{path}: {e}")));
}

fn slh_keystore(m: &BTreeMap<String, String>) {
    let dir = Path::new(get(m, "--dir"));
    let index: u32 = num(m, "--index");
    std::fs::create_dir_all(dir).unwrap_or_else(|e| die(e));
    let path = dir.join("validator.key");
    if path.exists() {
        die(format!("{} exists", path.display()));
    }
    let (pk, sk) = bloch_crypto::crypto::slhdsa_suite::generate_keypair();
    let mut randao = [0u8; 32];
    getrandom::getrandom(&mut randao).unwrap_or_else(|e| die(e));
    let mut out = MAGIC_V1.to_vec();
    out.extend_from_slice(&index.to_le_bytes());
    put_bytes(&mut out, &pk);
    put_bytes(&mut out, &sk);
    out.extend_from_slice(&randao);
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .and_then(|mut f| f.write_all(&out))
        .unwrap_or_else(|e| die(e));
    let script: [u8; 32] = Sha3_256::digest(&pk).into();
    println!("suite 0x{:02x}{:02x}", pk[3], pk[2]);
    println!("pubkey {}", hex(&pk));
    println!("script {}", hex(&script));
}

fn slh_transfer(m: &BTreeMap<String, String>) {
    let key = load_plaintext(get(m, "--dir"));
    if !bloch_pos_committee::transition::pq_migration::is_hash_based_key(&key.pubkey) {
        die("the key in --dir is not suite 0x0003");
    }
    let input = get(m, "--input");
    let parts: Vec<&str> = input.split(':').collect();
    let [txid, vout, sat] = parts[..] else { die("--input needs TXID:VOUT:SAT") };
    let (txid, vout, value_sat): ([u8; 32], u32, u64) =
        (h32(txid), vout.parse().unwrap_or_else(|_| die("vout")), sat.parse().unwrap_or_else(|_| die("sat")));
    let to = h32(get(m, "--to"));
    let base_fee: u128 = num(m, "--base-fee");
    let tip: u128 = num(m, "--tip");
    let epoch: u64 = num(m, "--epoch");
    let mut tx = PosTransaction::TransferV2 {
        keys: vec![WitnessKey { pubkey: key.pubkey.clone(), signature: vec![0u8; SLHDSA_FALCON_MAX_ENVELOPED_SIG_LEN] }],
        inputs: vec![TransferInputV2 { txid, vout, key_index: 0 }],
        outputs: vec![TransferOutput { value: 0, script_hash: to }],
        tx_bytes: 0,
        tip_millisat_per_gas: tip,
    };
    let reserved = tx.canonical_bytes().len() as u64;
    let class = fee_market::eutxo_class_for_keys(epoch, [key.pubkey.as_slice()]);
    let charge = fee_market::charge(class, reserved, base_fee, tip);
    let fee = charge.base_fee_sat + charge.priority_fee_sat;
    let paid = u128::from(value_sat).checked_sub(fee).unwrap_or_else(|| die(format!("fee {fee} above input")));
    let paid = u64::try_from(paid).unwrap_or_else(|_| die("output overflow"));
    if paid < MIN_TRANSFER_OUTPUT_SAT {
        die("output below the minimum");
    }
    if let PosTransaction::TransferV2 { tx_bytes, outputs, .. } = &mut tx {
        *tx_bytes = reserved;
        outputs[0].value = paid;
    }
    let root = tx.checked_signing_root(epoch);
    let sig = sign(&key, &root);
    if let PosTransaction::TransferV2 { keys, .. } = &mut tx {
        keys[0].signature = sig;
    }
    let encoded = tx.canonical_bytes().len() as u64;
    if encoded > reserved || reserved - encoded > fee_market::TX_BYTES_DECLARE_SLACK {
        die(format!("encoding {encoded} vs reserved {reserved} outside the slack"));
    }
    write_hex(get(m, "--out"), &tx.canonical_bytes());
    println!("gas {} fee_sat {fee} paid_sat {paid} class {class:?}", charge.gas);
    println!("Transaction id: {}", hex(&tx.txid()));
}

fn rotate(m: &BTreeMap<String, String>) {
    let (manifest, _) = Manifest::load(Path::new(get(m, "--genesis"))).unwrap_or_else(|e| die(e));
    let domain: [u8; 32] = Sha3_256::digest(manifest.encode()).into();
    let auth = load_plaintext(get(m, "--auth-dir"));
    let new = load_plaintext(get(m, "--new-dir"));
    let mut tx = WithdrawalCredentialRotation {
        network_domain: domain,
        epoch: num(m, "--epoch"),
        validator: num(m, "--validator"),
        authorizing_pubkey: auth.pubkey.clone(),
        new_pubkey: new.pubkey.clone(),
        authorizing_signature: Vec::new(),
        new_key_signature: Vec::new(),
    };
    let root = tx.signing_root();
    tx.authorizing_signature = sign(&auth, &root);
    tx.new_key_signature = sign(&new, &root);
    let wire = PosTransaction::WithdrawalCredentialRotation(tx.clone());
    let bytes = wire.canonical_bytes();
    if PosTransaction::from_canonical_bytes(&bytes).ok() != Some(wire.clone()) {
        die("rotation does not round-trip through the wire encoding");
    }
    write_hex(get(m, "--out"), &bytes);
    println!("network_domain {}", codec::hex32(&domain));
    println!("new_credential {}", hex(&tx.new_credential()));
    println!("Transaction id: {}", hex(&wire.txid()));
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first() else { die("usage: slh-keystore | slh-transfer | rotate (see the source header)") };
    let m = flags(&args[1..]);
    match cmd.as_str() {
        "slh-keystore" => slh_keystore(&m),
        "slh-transfer" => slh_transfer(&m),
        "rotate" => rotate(&m),
        other => die(format!("unknown command {other}")),
    }
}
