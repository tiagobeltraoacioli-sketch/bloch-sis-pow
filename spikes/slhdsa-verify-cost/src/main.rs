// SPDX-License-Identifier: AGPL-3.0-or-later
//! P9f spike: native verify cost of the SLH-DSA suite candidates against the
//! production suite 0x0001 halves, on the host it runs on.
//!
//! `cargo run --release -- [iters] [--dump-kat]`
//!
//! Prints per-verify microseconds (single core, median of 5 batches) for:
//! ML-DSA-65 and Falcon-1024 through the PQClean C stack the node links
//! today, and SLH-DSA-SHAKE-128s/128f through `fips205` 0.4.1 (p9a's pin),
//! for both a VALID signature and an INVALID one (last byte flipped) —
//! the second number is what a mempool attacker buys per rejected spend.

use fips205::traits::{SerDes, Signer, Verifier};
use pqcrypto_traits::sign::{DetachedSignature, PublicKey as _};
use std::time::Instant;

const MSG: [u8; 32] = [0x42; 32];
const CTX: &[u8] = b"BLOCH/SUITE/0x0003/SLH-DSA-SHAKE-128s+Falcon-1024/v1";

fn median_us(iters: u32, mut f: impl FnMut() -> bool, expect: bool) -> f64 {
    let mut runs = Vec::new();
    for _ in 0..5 {
        let t = Instant::now();
        for _ in 0..iters {
            assert_eq!(std::hint::black_box(f()), expect);
        }
        runs.push(t.elapsed().as_secs_f64() * 1e6 / iters as f64);
    }
    runs.sort_by(|a, b| a.partial_cmp(b).unwrap());
    runs[2]
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let iters: u32 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(400);
    let dump = args.iter().any(|a| a == "--dump-kat");

    // Production halves (PQClean, as linked by bloch-crypto).
    use pqcrypto_falcon::falcon1024 as fal;
    use pqcrypto_mldsa::mldsa65 as mld;
    let (mpk, msk) = mld::keypair();
    let msig = mld::detached_sign(&MSG, &msk);
    let mut msig_bad = msig.as_bytes().to_vec();
    *msig_bad.last_mut().unwrap() ^= 1;
    let msig_bad = mld::DetachedSignature::from_bytes(&msig_bad).unwrap();
    let (fpk, fsk) = fal::keypair();
    let fsig = fal::detached_sign(&MSG, &fsk);
    let mut fsig_bad = fsig.as_bytes().to_vec();
    let n = fsig_bad.len();
    fsig_bad[n / 2] ^= 1;
    let fsig_bad = fal::DetachedSignature::from_bytes(&fsig_bad).unwrap();

    let mut rng = rand_core::OsRng;
    use fips205::slh_dsa_shake_128f as f128;
    use fips205::slh_dsa_shake_128s as s128;
    let (spk, ssk) = s128::try_keygen_with_rng(&mut rng).unwrap();
    let t = Instant::now();
    let ssig = ssk.try_sign_with_rng(&mut rng, &MSG, CTX, true).unwrap();
    let sign_s_ms = t.elapsed().as_secs_f64() * 1e3;
    let mut ssig_bad = ssig;
    ssig_bad[s128::SIG_LEN - 1] ^= 1;
    let (fpk2, fsk2) = f128::try_keygen_with_rng(&mut rng).unwrap();
    let fsig2 = fsk2.try_sign_with_rng(&mut rng, &MSG, CTX, true).unwrap();
    let mut fsig2_bad = fsig2;
    fsig2_bad[f128::SIG_LEN - 1] ^= 1;

    let rows = [
        ("ml-dsa-65 (pqclean)", median_us(iters, || mld::verify_detached_signature(&msig, &MSG, &mpk).is_ok(), true),
         median_us(iters, || mld::verify_detached_signature(&msig_bad, &MSG, &mpk).is_ok(), false), msig.as_bytes().len()),
        ("falcon-1024 (pqclean)", median_us(iters, || fal::verify_detached_signature(&fsig, &MSG, &fpk).is_ok(), true),
         median_us(iters, || fal::verify_detached_signature(&fsig_bad, &MSG, &fpk).is_ok(), false), fsig.as_bytes().len()),
        ("slh-dsa-shake-128s (fips205)", median_us(iters / 4 + 1, || spk.verify(&MSG, &ssig, CTX), true),
         median_us(iters / 4 + 1, || spk.verify(&MSG, &ssig_bad, CTX), false), s128::SIG_LEN),
        ("slh-dsa-shake-128f (fips205)", median_us(iters / 8 + 1, || fpk2.verify(&MSG, &fsig2, CTX), true),
         median_us(iters / 8 + 1, || fpk2.verify(&MSG, &fsig2_bad, CTX), false), f128::SIG_LEN),
    ];
    println!("{:<30} {:>12} {:>14} {:>9}", "verifier", "valid_us", "invalid_us", "sig_B");
    for (name, ok, bad, len) in rows {
        println!("{name:<30} {ok:>12.1} {bad:>14.1} {len:>9}");
    }
    println!("slh-dsa-shake-128s sign (one, hedged): {sign_s_ms:.1} ms");
    let _ = (mpk.as_bytes().len(), fpk.as_bytes().len());

    if dump {
        std::fs::create_dir_all("kat").unwrap();
        std::fs::write("kat/slh128s_pk.bin", spk.into_bytes()).unwrap();
        std::fs::write("kat/slh128s_sig.bin", ssig).unwrap();
        std::fs::write("kat/msg.bin", MSG).unwrap();
        println!("wrote kat/slh128s_{{pk,sig}}.bin, kat/msg.bin");
    }
}
