// SPDX-License-Identifier: AGPL-3.0-or-later
//! The offline L2 signers emit signatures within `ADMISSION_PQ_SIGNATURE_MAX`.
//!
//! Falcon-1024 signatures are variable length, so a valid hybrid signature
//! can exceed the 4593-byte admission bound. `l2-deposit sign`, `l2-da sign`,
//! `l2-claim attest` and `l2-claim sign` re-sign until the encoding fits.
//! Each class is exercised repeatedly through the real binary with
//! disposable keys, and every produced artifact is decoded by the consensus
//! decoder (which refuses an oversized signature) and verified.
use bloch_pos_committee::{
    l2_settlement::withdrawal,
    transition::{funded::ADMISSION_PQ_SIGNATURE_MAX, PosTransaction},
};
use std::{
    path::{Path, PathBuf},
    process::Command,
};

const ROUNDS: usize = 6;

fn ok(args: &[&str]) -> String {
    let result = Command::new(env!("CARGO_BIN_EXE_bloch-pos"))
        .args(args)
        .env_remove("BLOCH_KEYSTORE_PASSPHRASE_FILE")
        .env_remove("BLOCH_KEYSTORE_ALLOW_PLAINTEXT")
        .env("BLOCH_KEYSTORE_PASSPHRASE", "disposable sign-fitting test")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8(result.stdout).unwrap()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn unhex(s: &str) -> Vec<u8> {
    s.trim()
        .as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
fn decode(p: &Path) -> PosTransaction {
    PosTransaction::from_canonical_bytes(&unhex(&std::fs::read_to_string(p).unwrap()))
        .expect("the consensus decoder accepts the signed artifact")
}
fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}
struct Temp(PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn temp(tag: &str) -> Temp {
    let dir = std::env::temp_dir().join(format!("bloch-sign-fitting-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    Temp(dir)
}

/// A keystore, its public key file and a devnet genesis it signs under.
fn owner(dir: &Path) -> (PathBuf, PathBuf, PathBuf, Vec<u8>) {
    let key = dir.join("owner");
    ok(&["keygen", "--dir", s(&key), "--index", "0"]);
    let pk = ok(&["keygen-public", "--dir", s(&key)]).trim().split('\t').nth(1).unwrap().to_owned();
    let pubfile = dir.join("owner.pub");
    std::fs::write(&pubfile, &pk).unwrap();
    let genesis = dir.join("genesis");
    ok(&["genesis", "--keys", s(&key), "--out", s(&genesis)]);
    (key, pubfile, genesis, unhex(&pk))
}

fn assert_fits(sig: &[u8], pk: &[u8], root: &[u8; 32]) {
    assert!(!sig.is_empty());
    assert!(sig.len() <= ADMISSION_PQ_SIGNATURE_MAX, "{} bytes", sig.len());
    assert!(bloch_crypto::crypto::verify(pk, root, sig));
}

#[test]
fn l2_deposit_and_da_signers_fit_the_admission_bound() {
    let dir = temp("deposit-da");
    let (key, pubfile, genesis, pk) = owner(&dir.0);
    let input = format!("{}:0:50000000", hex(&[71; 32]));
    let payload = dir.0.join("payload");
    // One canonical batch: count 1, then one 3-byte transaction.
    std::fs::write(&payload, hex(&[0, 0, 0, 1, 0, 0, 0, 3, 1, 2, 3])).unwrap();
    for round in 0..ROUNDS {
        let draft = dir.0.join(format!("deposit-{round}.draft"));
        let signed = dir.0.join(format!("deposit-{round}.signed"));
        let recipient = hex(&[round as u8 + 1; 20]);
        ok(&[
            "l2-deposit", "prepare", "--genesis", s(&genesis), "--funding-pubkey", s(&pubfile),
            "--input", &input, "--amount", "1000000", "--recipient", &recipient,
            "--base-fee", "100", "--tip", "0", "--out", s(&draft),
        ]);
        ok(&["l2-deposit", "sign", "--genesis", s(&genesis), "--tx", s(&draft), "--dir", s(&key), "--out", s(&signed)]);
        let PosTransaction::L2Deposit(tx) = decode(&signed) else { panic!("expected L2 deposit") };
        assert_fits(&tx.signature, &pk, &tx.intent_root());
        assert!(tx.tx_bytes >= PosTransaction::L2Deposit(tx.clone()).canonical_bytes().len() as u64);

        let draft = dir.0.join(format!("da-{round}.draft"));
        let signed = dir.0.join(format!("da-{round}.signed"));
        let number = (round + 1).to_string();
        ok(&[
            "l2-da", "prepare", "--genesis", s(&genesis), "--funding-pubkey", s(&pubfile),
            "--input", &input, "--chain-id", "700771", "--number", &number,
            "--payload", s(&payload), "--base-fee", "100", "--tip", "0", "--out", s(&draft),
        ]);
        ok(&["l2-da", "sign", "--genesis", s(&genesis), "--tx", s(&draft), "--dir", s(&key), "--out", s(&signed)]);
        let PosTransaction::L2DataAvailability(tx) = decode(&signed) else { panic!("expected L2 DA") };
        assert_fits(&tx.signature, &pk, &tx.intent_root());
        assert!(tx.tx_bytes >= PosTransaction::L2DataAvailability(tx.clone()).canonical_bytes().len() as u64);
    }
}

#[test]
fn l2_claim_attestor_and_claim_signers_fit_the_admission_bound() {
    let dir = temp("claim");
    let (key, pubfile, genesis, pk) = owner(&dir.0);
    let chain_id = 700771u64;
    let leaves: Vec<[u8; 32]> = (0..2u64)
        .map(|i| withdrawal::leaf(chain_id, i, &[i as u8 + 1; 32], 1_000_000 + i))
        .collect();
    let siblings = withdrawal::proof(&leaves, 1).unwrap();
    let root = withdrawal::root(&leaves);
    let proof = dir.0.join("proof.json");
    std::fs::write(
        &proof,
        format!(
            r#"{{"chain_id":{chain_id},"number":2,"withdrawal_root":"{}","withdrawal_count":2,"index":1,
               "withdrawal":{{"nonce":1,"l1_recipient":"{}","sats":1000001,"sender":"00","l2_block":2,"leaf":"{}"}},
               "siblings":[{}]}}"#,
            hex(&root),
            hex(&[2; 32]),
            hex(&leaves[1]),
            siblings.iter().map(|x| format!("\"{}\"", hex(x))).collect::<Vec<_>>().join(",")
        ),
    )
    .unwrap();
    let mut pubkeys = Vec::new();
    for i in 0..2 {
        let prefix = dir.0.join(format!("attestor-{i}"));
        ok(&["ws-keygen", "--out", s(&prefix)]);
        pubkeys.push(prefix);
    }
    let set = dir.0.join("set");
    let pk_files: Vec<String> = pubkeys.iter().map(|p| format!("{}.pk", s(p))).collect();
    ok(&[
        "l2-claim", "attestor-set", "--threshold", "2", "--pubkey", &pk_files[0], "--pubkey", &pk_files[1],
        "--out", s(&set),
    ]);
    let attestor_pks: Vec<Vec<u8>> =
        pk_files.iter().map(|f| unhex(&std::fs::read_to_string(f).unwrap())).collect();
    let input = format!("{}:0:50000000", hex(&[72; 32]));
    for round in 0..ROUNDS {
        let mut partials = Vec::new();
        for (i, prefix) in pubkeys.iter().enumerate() {
            let partial = dir.0.join(format!("partial-{round}-{i}"));
            let sk = format!("{}.sk", s(prefix));
            let index = i.to_string();
            ok(&[
                "l2-claim", "attest", "--genesis", s(&genesis), "--proof", s(&proof), "--attestors", s(&set),
                "--signer-index", &index, "--key", &sk, "--out", s(&partial),
            ]);
            let text = std::fs::read_to_string(&partial).unwrap();
            let lines: Vec<&str> = text.lines().collect();
            let digest: [u8; 32] = unhex(lines[1]).try_into().unwrap();
            assert_fits(&unhex(lines[2]), &attestor_pks[i], &digest);
            partials.push(partial);
        }
        let draft = dir.0.join(format!("claim-{round}.draft"));
        let signed = dir.0.join(format!("claim-{round}.signed"));
        ok(&[
            "l2-claim", "prepare", "--genesis", s(&genesis), "--funding-pubkey", s(&pubfile), "--input", &input,
            "--proof", s(&proof), "--base-fee", "100", "--tip", "0", "--attestors", s(&set),
            "--attestation", s(&partials[0]), "--attestation", s(&partials[1]), "--out", s(&draft),
        ]);
        ok(&["l2-claim", "sign", "--genesis", s(&genesis), "--tx", s(&draft), "--dir", s(&key), "--out", s(&signed)]);
        let PosTransaction::L2WithdrawClaim(tx) = decode(&signed) else { panic!("expected L2 claim") };
        assert_fits(&tx.signature, &pk, &tx.intent_root());
        let attestation = tx.attestation.as_ref().expect("attested claim");
        assert!(attestation.validate_shape());
        assert!(tx.tx_bytes >= PosTransaction::L2WithdrawClaim(tx.clone()).canonical_bytes().len() as u64);
    }
}

/// Signers changed; consensus did not. A valid but oversized hybrid draw is
/// still refused by the consensus decoder exactly as before, while the same
/// key's `sign_fitting` output over the same intent decodes and verifies.
/// The key and the signing randomness are seeded, so the oversized draw is
/// reproducible; `FIRST_OVERSIZED_SEED` only skips the search prefix.
#[test]
fn consensus_acceptance_is_unchanged_for_oversized_and_fitting_signatures() {
    use bloch_pos_committee::transition::{FundingInput, L2Deposit, TransferOutput};
    const FIRST_OVERSIZED_SEED: u32 = 565;
    let (pk, sk) = bloch_crypto::crypto::generate_keypair_from_seed(&[0x5F; 32]).unwrap();
    let mut tx = L2Deposit {
        network_domain: [0x11; 32],
        funding_pubkey: pk.clone(),
        inputs: vec![FundingInput { txid: [0x22; 32], vout: 0 }],
        amount_sat: 1_000_000,
        recipient: [0x33; 20],
        change: TransferOutput { value: 0, script_hash: [0x44; 32] },
        tx_bytes: 0,
        tip_millisat_per_gas: 0,
        signature: Vec::new(),
    };
    tx.tx_bytes = (PosTransaction::L2Deposit(tx.clone()).canonical_bytes().len()
        + ADMISSION_PQ_SIGNATURE_MAX) as u64;
    let root = tx.intent_root();
    let seed_of = |s: u32| {
        let mut seed = [0u8; 32];
        seed[..4].copy_from_slice(&s.to_le_bytes());
        seed
    };
    let (seed, oversized) = (FIRST_OVERSIZED_SEED..FIRST_OVERSIZED_SEED + 4096)
        .find_map(|s| {
            let sig = pqcrypto_internals::with_seeded_rng_scope(&seed_of(s), || {
                bloch_crypto::crypto::sign(&sk, &root).unwrap()
            });
            (sig.len() > ADMISSION_PQ_SIGNATURE_MAX).then(|| {
                eprintln!("first oversized seed: {s}");
                (seed_of(s), sig)
            })
        })
        .expect("an oversized Falcon draw");
    // Cryptographically valid, refused by the unchanged consensus bound.
    assert!(bloch_crypto::crypto::verify(&pk, &root, &oversized));
    let mut refused = tx.clone();
    refused.signature = oversized.clone();
    assert!(PosTransaction::from_canonical_bytes(
        &PosTransaction::L2Deposit(refused).canonical_bytes()
    )
    .is_err());
    // Same seed: the helper discards that draw and returns a fitting one.
    let fitted = pqcrypto_internals::with_seeded_rng_scope(&seed, || {
        bloch_crypto::crypto::sign_fitting(&sk, &root, ADMISSION_PQ_SIGNATURE_MAX).unwrap()
    });
    assert_ne!(fitted, oversized);
    assert_fits(&fitted, &pk, &root);
    tx.signature = fitted;
    let encoded = PosTransaction::L2Deposit(tx.clone()).canonical_bytes();
    assert!(tx.tx_bytes >= encoded.len() as u64);
    assert_eq!(PosTransaction::from_canonical_bytes(&encoded), Ok(PosTransaction::L2Deposit(tx)));
}
