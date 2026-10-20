#![no_main]
//! Arbitrary (attacker-controlled) bytes into every public verify / parse entry
//! point of bloch-crypto: must never panic, hang or over-allocate, and the
//! policy lattice must hold (canonical => enveloped => generic verify;
//! legacy-canonical => legacy). Half the inputs reuse a genuine fixture public
//! key so the fuzzed signature bytes reach the ML-DSA / Falcon decoders instead
//! of failing the key parse. Fills gaps left by ../../../fuzz sig_verify.rs
//! (which only covers `verify`, through the legacy Genesis-3 crate).
mod common;
use bloch_crypto::crypto as c;
use common::*;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let f = fixture();
    let mut cur = Cur(data);
    let mode = cur.u8();
    let pk: Vec<u8> = match mode % 4 {
        0 => { let n = cur.u16() as usize; cur.take(n).to_vec() }
        1 => f.keys[(mode as usize >> 2) % f.keys.len()].pk_env.clone(),
        2 => f.keys[(mode as usize >> 2) % 2].pk_body.clone(),
        _ => { let mut p = f.keys[(mode as usize >> 2) % 2].pk_env.clone(); let n = cur.u8() as usize; p.extend_from_slice(cur.take(n)); p }
    };
    let msg_n = cur.u8() as usize;
    let msg = cur.take(msg_n).to_vec();
    let sig = cur.0;

    let v = c::verify(&pk, &msg, sig);
    let ve = c::verify_enveloped(&pk, &msg, sig);
    let vc = c::verify_enveloped_canonical(&pk, &msg, sig);
    let lr = c::verify_legacy_hybrid_raw(&pk, &msg, sig);
    let lc = c::verify_legacy_hybrid_raw_canonical(&pk, &msg, sig);
    assert!(!vc || ve);
    assert!(!ve || v);
    assert!(!lc || lr);
    // Raw-half primitives used by the PoS weak-subjectivity verifier.
    let _ = c::verify_mldsa65_raw(&pk, &msg, sig);
    let _ = c::falcon::verify(&pk, &msg, sig);
    let fc = c::falcon::verify_canonical(&pk, &msg, sig);
    assert!(!fc || c::falcon::verify(&pk, &msg, sig));
    let _ = c::is_hybrid_public_key(&pk);
    let _ = c::split_envelope(sig);
    let _ = c::address_from_pubkey(&pk, false);
    // Raw random bytes can never verify against a genuine key.
    if mode % 4 != 0 {
        assert!(!v && !lr, "random signature bytes verified under a genuine key");
    }
});
