// SPDX-License-Identifier: AGPL-3.0-or-later
//! Read-only verification of a signed TransferV2 against an approved unsigned file.
use bloch_pos_committee::transition::PosTransaction;
use std::io::Read;
fn read(path: &str) -> Result<Vec<u8>, String> {
    let mut text = String::new();
    std::fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(32769)
        .read_to_string(&mut text)
        .map_err(|e| e.to_string())?;
    if text.len() > 32768 {
        return Err("File too large".into());
    }
    let s = text.trim();
    if !s.is_ascii() || s.len() % 2 != 0 {
        return Err("Invalid hex".into());
    }
    s.as_bytes()
        .chunks_exact(2)
        .map(|p| {
            u8::from_str_radix(std::str::from_utf8(p).map_err(|_| "Invalid hex")?, 16)
                .map_err(|_| "Invalid hex".into())
        })
        .collect()
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 4 {
        return Err("Usage: verify-funding-signature SIGNED UNSIGNED EPOCH EXPECTED_ROOT".into());
    }
    let bytes = read(&args[0])?;
    let approved = read(&args[1])?;
    let mut signed = PosTransaction::from_canonical_bytes(&bytes)
        .map_err(|e| format!("Invalid transaction: {e:?}"))?;
    let epoch = args[2].parse().map_err(|_| "Invalid epoch")?;
    let root = signed.checked_signing_root(epoch);
    if hex(&root) != args[3] {
        return Err("Signing root mismatch".into());
    }
    let txid = signed.txid();
    if let PosTransaction::TransferV2 {
        keys,
        inputs,
        outputs,
        ..
    } = &mut signed
    {
        if keys.len() != 1 || inputs.len() != 1 || outputs.len() != 2 || inputs[0].key_index != 0 {
            return Err("Unexpected conversion shape".into());
        }
        if keys[0].signature.is_empty()
            || !bloch_crypto::crypto::verify(&keys[0].pubkey, &root, &keys[0].signature)
        {
            return Err("Invalid signature".into());
        }
        keys[0].signature.clear();
    } else {
        return Err("Expected TransferV2".into());
    }
    if signed.canonical_bytes() != approved {
        return Err("Signed intent differs from approved draft".into());
    }
    println!(
        "Signature verified; approved unsigned bytes match; txid {}",
        hex(&txid)
    );
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("Verification refused: {e}");
        std::process::exit(1);
    }
}
