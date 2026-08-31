// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tempo NATIVO de uma verificacao hibrida ML-DSA-65 ‖ Falcon-1024, na mesma
//! maquina que mede o verify SP1 (../host). E o denominador da derivacao de
//! `SHIELDED_VERIFY_GAS` (fee_market.rs): la o gas sai de
//!
//!   t_shielded / t_hybrid * HYBRID_VERIFY_INSTRUCTIONS / INSTRUCTIONS_PER_GAS
//!
//! entao este binario usa EXATAMENTE o verificador que o no roda em consenso —
//! `bloch_crypto::crypto::verify` (PQClean clean, sem avx2/neon) — e nao uma
//! reimplementacao.

use std::time::Instant;

const ITERS: usize = 200;

fn main() {
    let (pk, sk) = bloch_crypto::crypto::generate_keypair();
    let msg = [0x42u8; 32]; // um sighash: e isso que o no verifica
    let sig = bloch_crypto::crypto::sign(&sk, &msg).expect("sign");
    println!("pk {} B, sig {} B", pk.len(), sig.len());

    // Aquecimento (paginas de codigo, tabelas), depois ITERS medidas.
    assert!(bloch_crypto::crypto::verify(&pk, &msg, &sig));
    let mut ms: Vec<f64> = (0..ITERS)
        .map(|_| {
            let t = Instant::now();
            assert!(bloch_crypto::crypto::verify(&pk, &msg, &sig));
            t.elapsed().as_secs_f64() * 1_000.0
        })
        .collect();
    ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    println!(
        "HYBRID VERIFY: mediana {:.4} ms  (min {:.4}, max {:.4}, {} iters)",
        ms[ms.len() / 2],
        ms[0],
        ms[ms.len() - 1],
        ITERS
    );
}
