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
fn verify_conversion_signature(public_key: &[u8], root: &[u8], signature: &[u8]) -> bool {
    const LEGACY_HYBRID_PUBLIC_KEY_LEN: usize = 3745;
    let expected_mixed_format = if public_key.len() == LEGACY_HYBRID_PUBLIC_KEY_LEN {
        let mut enveloped_public_key = vec![0xb1, 0x0c, 1, 0];
        enveloped_public_key.extend_from_slice(public_key);
        bloch_crypto::crypto::verify_enveloped(&enveloped_public_key, root, signature)
    } else {
        false
    };
    expected_mixed_format
        || bloch_crypto::crypto::verify_enveloped(public_key, root, signature)
        || bloch_crypto::crypto::verify_legacy_hybrid_raw(public_key, root, signature)
        || bloch_crypto::crypto::verify(public_key, root, signature)
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
            || !verify_conversion_signature(&keys[0].pubkey, &root, &keys[0].signature)
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

#[cfg(test)]
mod tests {
    use super::*;
    use bloch_pos_committee::transition::{TransferInputV2, TransferOutput, WitnessKey};
    use sha3::{Digest, Sha3_256};

    #[test]
    fn explicit_policy_handles_expected_mixed_and_magic_prefixed_raw_formats() {
        const SEARCH_COUNTER: u64 = 22_059;
        const SIGNING_SEED_HEX: &str =
            "734f85162b4137e79ac48f14791dbf61a8802295ef8c65bd87d9e68a3aa41a7e";
        const ROOT_HEX: &str =
            "6c690b661375f5a344d69bffc8a07dd982c4b918d46ff4a217bac549ca0f9ea7";

        let (public_key, secret_key) =
            bloch_crypto::crypto::generate_keypair_from_seed(&[0x68; 32]).unwrap();
        let raw_public_key = public_key[4..].to_vec();
        let tx = PosTransaction::TransferV2 {
            keys: vec![WitnessKey {
                pubkey: raw_public_key.clone(),
                signature: vec![],
            }],
            inputs: vec![TransferInputV2 { txid: [2; 32], vout: 1, key_index: 0 }],
            outputs: vec![
                TransferOutput { value: 2_500_001_000_000, script_hash: [3; 32] },
                TransferOutput { value: 1_499_998_000_000, script_hash: [4; 32] },
            ],
            tx_bytes: 9000,
            tip_millisat_per_gas: 5,
        };
        let root = tx.checked_signing_root(5000);
        assert_eq!(hex(&root), ROOT_HEX);

        let mut h = Sha3_256::new();
        h.update(b"bloch/verify-funding/cr10/signing-rng/v1");
        h.update(SEARCH_COUNTER.to_le_bytes());
        let signing_seed: [u8; 32] = h.finalize().into();
        assert_eq!(hex(&signing_seed), SIGNING_SEED_HEX);
        let enveloped_signature =
            pqcrypto_internals::with_seeded_rng_scope(&signing_seed, || {
                bloch_crypto::crypto::sign(&secret_key, &root).unwrap()
            });

        assert!(verify_conversion_signature(
            &raw_public_key,
            &root,
            &enveloped_signature,
        ));
        assert!(bloch_crypto::crypto::verify_enveloped_canonical(
            &public_key,
            &root,
            &enveloped_signature,
        ));

        let raw_signature = &enveloped_signature[bloch_crypto::crypto::SUITE_HEADER_LEN..];
        assert_eq!(&raw_signature[..2], &[0xb1, 0x0c]);
        assert!(
            !bloch_crypto::crypto::verify(&raw_public_key, &root, raw_signature),
            "generic autodetection must misclassify this genuine raw signature"
        );
        assert!(
            verify_conversion_signature(&raw_public_key, &root, raw_signature),
            "explicit raw fallback must accept the genuine legacy layout"
        );
    }
}
