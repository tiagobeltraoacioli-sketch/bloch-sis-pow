// SPDX-License-Identifier: MIT OR Apache-2.0
//
// PoS proving-cost spike — Gate 1: can the chain's EXISTING signatures be
// verified by a PURE-RUST verifier?
//
// Why this is the first question. In-circuit verification (§6.5.1 of the PoS
// migration design) needs the verifier compiled to riscv32im. The chain's
// current stack (pqcrypto-mldsa / pqcrypto-falcon) is PQClean *C* reference
// code behind FFI, so it needs a RISC-V C cross-compiler. If a pure-Rust
// verifier accepts the exact same signature bytes, the in-circuit path is open
// WITHOUT changing the consensus signature format. If it does not, the cost
// question is moot until a byte-compatible pure-Rust verifier exists.

use pqcrypto_mldsa::mldsa65;
use pqcrypto_falcon::falcon1024;
use pqcrypto_traits::sign::{
    DetachedSignature as _, PublicKey as _, SecretKey as _, SignedMessage as _,
};

const MSG: &[u8] = b"bloch pos spike: attestation payload";

fn main() {
    println!("== Gate 1 — verificacao pura-Rust das assinaturas atuais ==\n");
    mldsa_cross_verify();
    falcon_shape();
    if std::env::args().any(|a| a == "--dump-kat") {
        dump_kat();
    }
    println!("\n== fim ==");
}

/// Emit fixed vectors so the bare-metal RISC-V build verifies a real,
/// host-checked signature rather than synthetic bytes.
fn dump_kat() {
    use std::io::Write;
    let (pk, sk) = mldsa65::keypair();
    let sig = mldsa65::detached_sign(MSG, &sk);
    assert!(mldsa65::verify_detached_signature(&sig, MSG, &pk).is_ok());
    std::fs::create_dir_all("kat").unwrap();
    // Four DISTINCT hybrid keypairs/signatures, so the multi-signature
    // measurement reflects real per-signature work (and its variance), not the
    // same code path re-run on identical bytes.
    for i in 0..4u8 {
        let (mpk, msk) = mldsa65::keypair();
        let msig = mldsa65::detached_sign(MSG, &msk);
        assert!(mldsa65::verify_detached_signature(&msig, MSG, &mpk).is_ok());
        let (fpk, fsk) = falcon1024::keypair();
        let fsig = falcon1024::detached_sign(MSG, &fsk);
        assert!(falcon1024::verify_detached_signature(&fsig, MSG, &fpk).is_ok());
        for (name, bytes) in [
            (format!("kat/h{i}_mldsa_pk.bin"),  mpk.as_bytes()),
            (format!("kat/h{i}_mldsa_sig.bin"), msig.as_bytes()),
            (format!("kat/h{i}_falcon_pk.bin"),  fpk.as_bytes()),
            (format!("kat/h{i}_falcon_sig.bin"), fsig.as_bytes()),
        ] {
            std::fs::File::create(&name).unwrap().write_all(bytes).unwrap();
        }
        println!("  par hibrido {i}: falcon sig = {} B", fsig.as_bytes().len());
    }
    let (fpk, fsk) = falcon1024::keypair();
    let fsig = falcon1024::detached_sign(MSG, &fsk);
    assert!(falcon1024::verify_detached_signature(&fsig, MSG, &fpk).is_ok());
    for (name, bytes) in [
        ("kat/mldsa65_pk.bin",  pk.as_bytes()),
        ("kat/mldsa65_sig.bin", sig.as_bytes()),
        ("kat/msg.bin",         MSG),
        ("kat/falcon1024_pk.bin",  fpk.as_bytes()),
        ("kat/falcon1024_sig.bin", fsig.as_bytes()),
    ] {
        println!("  gravado {name} ({} B)", bytes.len());
    }
}

/// Sign with the C stack the chain uses today, verify with the pure-Rust
/// `fips204` crate, using the identical public-key and signature bytes.
fn mldsa_cross_verify() {
    use fips204::ml_dsa_65;
    use fips204::traits::{SerDes, Verifier};

    let (pk, sk) = mldsa65::keypair();
    let sig = mldsa65::detached_sign(MSG, &sk);

    let pk_bytes = pk.as_bytes();
    let sig_bytes = sig.as_bytes();
    println!("ML-DSA-65   pk={} B  sig={} B", pk_bytes.len(), sig_bytes.len());

    // Sanity: the C stack verifies its own signature.
    let c_ok = mldsa65::verify_detached_signature(&sig, MSG, &pk).is_ok();
    println!("  C  (PQClean) verifica:      {}", yn(c_ok));

    // The real question: same bytes, pure-Rust verifier.
    let pk_arr: [u8; 1952] = match pk_bytes.try_into() {
        Ok(a) => a,
        Err(_) => { println!("  pk com tamanho inesperado"); return; }
    };
    let sig_arr: [u8; 3309] = match sig_bytes.try_into() {
        Ok(a) => a,
        Err(_) => { println!("  sig com tamanho inesperado"); return; }
    };

    match ml_dsa_65::PublicKey::try_from_bytes(pk_arr) {
        Ok(rust_pk) => {
            let ok_empty = rust_pk.verify(MSG, &sig_arr, &[]);
            println!("  Rust (fips204) verifica:    {}   [ctx vazio]", yn(ok_empty));
            if !ok_empty {
                println!("  -> bytes incompativeis: provavel divergencia de");
                println!("     domain separation / variante FIPS 204 entre as duas.");
            }
        }
        Err(e) => println!("  Rust (fips204) rejeitou a pk: {e:?}"),
    }
}

/// Falcon-1024: report the PQClean wire shape. `fn-dsa`/`falcon-rs` implement
/// FN-DSA (FIPS 206 draft), whose encoding and domain separation differ from
/// the original Falcon that PQClean — and therefore this chain — implements.
fn falcon_shape() {
    println!();
    let (pk, sk) = falcon1024::keypair();
    let sig = falcon1024::detached_sign(MSG, &sk);
    let sm = falcon1024::sign(MSG, &sk);

    let sig_bytes = sig.as_bytes();
    println!("Falcon-1024 pk={} B  sig destacada={} B (variavel)", pk.as_bytes().len(), sig_bytes.len());
    println!("  mensagem assinada = {} B (msg {} B + envelope {} B)",
             sm.as_bytes().len(), MSG.len(), sm.as_bytes().len() - MSG.len());
    println!("  C  (PQClean) verifica:      {}",
             yn(falcon1024::verify_detached_signature(&sig, MSG, &pk).is_ok()));
    println!("  primeiro byte da sig = 0x{:02x} (header PQClean: 0x3_ + logn)", sig_bytes[0]);

    // Pure-Rust verifier with the explicit PQClean profile.
    use tide_fn_dsa_vrfy::{FalconProfile, VerifyingKey1024, VerifyingKey};
    match VerifyingKey1024::decode(pk.as_bytes()) {
        Some(vk) => {
            let ok = vk.verify_falcon(FalconProfile::PqClean, sig_bytes, MSG);
            println!("  Rust (tide-fn-dsa-vrfy, perfil PqClean): {}", yn(ok));
            // Negative control: a verifier that returns true unconditionally
            // would also "pass" above. Flip one byte; it must reject.
            let mut bad = sig_bytes.to_vec();
            bad[80] ^= 0x01;
            let rej = !vk.verify_falcon(FalconProfile::PqClean, &bad, MSG);
            println!("  rejeita sig adulterada (controle negativo): {}", yn(rej));
        }
        None => println!("  Rust: falhou ao decodificar a pk PQClean"),
    }
}

fn yn(b: bool) -> &'static str { if b { "SIM" } else { "NAO" } }
