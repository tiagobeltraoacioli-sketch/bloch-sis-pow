#![no_main]
//! Forgery / malleability ORACLE for every public hybrid verify entry point.
//!
//! Starts from genuine fixture keys and signatures (suite 0x0001 hybrid and
//! suite 0x0002 ML-DSA-only), applies structured mutations aimed at the
//! envelope header, the fixed ML-DSA/Falcon split point (byte 3309 of the
//! body), Falcon's variable length/padding, half-swapping between signatures
//! and keys, and suite-id rewriting. Whenever an entry point ACCEPTS, the
//! oracle checks the triple is one of the documented-acceptable encodings of
//! a genuine signature by the same key over the same message:
//!
//!   * ML-DSA half byte-identical to a genuine ML-DSA half for (key, msg);
//!   * Falcon half byte-identical to a genuine compact Falcon half for
//!     (key, msg), or (non-canonical entry points only) that half zero-padded
//!     to PQClean's 1280-byte padded length;
//!   * header present for the `*_enveloped*` entry points; header optional
//!     (legacy fallback) for `verify`; absent for `verify_legacy_hybrid_raw*`.
//!
//! Anything else accepted (a wrong-part split that verifies, a cross-suite
//! confusion, a cross-key or cross-message acceptance) aborts the run.
mod common;
use bloch_crypto::crypto as c;
use common::*;
use libfuzzer_sys::fuzz_target;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Entry { Verify, Enveloped, EnvelopedCanonical, LegacyRaw, LegacyRawCanonical }

fn falcon_ok(fh: &[u8], genuine: &[&[u8]], canonical: bool) -> bool {
    genuine.iter().any(|g| {
        fh == *g
            || (!canonical
                && fh.len() == FALCON_PADDED_SIG // whole padded Falcon signature
                && fh.starts_with(g)
                && fh[g.len()..].iter().all(|&b| b == 0))
    })
}

fn check(f: &Fixture, entry: Entry, pk: &[u8], msg: &[u8], sig: &[u8]) {
    let Some(m) = f.msgs.iter().position(|x| x == msg) else {
        panic!("{entry:?} accepted a signature over a message never signed");
    };
    // Which key does this pk encode, and was it enveloped?
    let mut who = None;
    for (k, key) in f.keys.iter().enumerate() {
        if pk == key.pk_env.as_slice() { who = Some((k, true)); }
        if key.suite == 1 && pk == key.pk_body.as_slice() { who = Some((k, false)); }
    }
    let Some((k, pk_enveloped)) = who else {
        panic!("{entry:?} accepted under a public key that is not a genuine key encoding (len {})", pk.len());
    };
    let key = &f.keys[k];
    let genuine = &f.sigs[k][m];
    let has_hdr = sig.len() >= HDR && sig[..2] == MAGIC;
    let (sig_suite, body) = match entry {
        Entry::LegacyRaw | Entry::LegacyRawCanonical => (1u16, sig),
        _ if has_hdr => (u16::from_le_bytes([sig[2], sig[3]]), &sig[HDR..]),
        Entry::Verify => (1u16, sig),
        _ => panic!("{entry:?} accepted a signature without an envelope"),
    };
    match entry {
        Entry::Enveloped | Entry::EnvelopedCanonical => assert!(pk_enveloped && has_hdr, "{entry:?} accepted non-enveloped object"),
        Entry::LegacyRaw | Entry::LegacyRawCanonical => assert!(!pk_enveloped, "{entry:?} accepted enveloped pk"),
        Entry::Verify => {}
    }
    assert_eq!(sig_suite, key.suite, "{entry:?}: suite confusion (sig suite {sig_suite:#06x}, key suite {:#06x})", key.suite);
    if key.suite == 2 {
        assert!(genuine.iter().any(|g| &g[HDR..] == body), "{entry:?}: non-genuine 0x0002 body accepted");
        return;
    }
    assert!(body.len() > MLDSA_SIG, "{entry:?}: short hybrid body accepted");
    let (mh, fh) = body.split_at(MLDSA_SIG);
    assert!(genuine.iter().any(|g| mldsa_half(g) == mh),
        "{entry:?}: ML-DSA half is not a genuine half for (key {k}, msg {m}) — split/forgery");
    let canonical = matches!(entry, Entry::EnvelopedCanonical | Entry::LegacyRawCanonical);
    let fg: Vec<&[u8]> = genuine.iter().map(|g| falcon_half(g)).collect();
    assert!(falcon_ok(fh, &fg, canonical),
        "{entry:?}: Falcon half (len {}) is not a genuine/allowed encoding for (key {k}, msg {m})", fh.len());
}

fn all_sigs(f: &Fixture) -> Vec<&Vec<u8>> {
    f.sigs.iter().flatten().flatten().collect()
}

fn mutate(f: &Fixture, cur: &mut Cur, v: &mut Vec<u8>) {
    let pool = all_sigs(f);
    let op = cur.u8();
    let raw_pos = cur.u16() as usize;
    let val = cur.u8();
    let len = (cur.u8() as usize) % 64 + 1;
    // Half of the time, aim at the ML-DSA/Falcon boundary (header-adjusted).
    let pos = if op & 0x80 != 0 {
        (HDR + MLDSA_SIG).saturating_add(raw_pos % 129).saturating_sub(64)
    } else {
        raw_pos
    } % (v.len() + 1);
    match op % 11 {
        0 => if pos < v.len() { v[pos] ^= 1 << (val % 8) },
        1 => if pos < v.len() { v[pos] = val },
        2 => { for _ in 0..len { v.insert(pos, val) } }
        3 => { let end = (pos + len).min(v.len()); v.drain(pos..end); }
        4 => v.truncate(pos),
        5 => v.extend(std::iter::repeat(0u8).take(len * 8)),
        6 => {
            // Splice a window from another genuine signature at the same offset.
            let other = pool[val as usize % pool.len()];
            let end = (pos + len).min(v.len()).min(other.len());
            if pos < end { v[pos..end].copy_from_slice(&other[pos..end]); }
        }
        7 => {
            // Replace everything after the boundary with another sig's Falcon half.
            let other = pool[val as usize % pool.len()];
            if v.len() >= HDR + MLDSA_SIG && other.len() > HDR + MLDSA_SIG {
                v.truncate(HDR + MLDSA_SIG);
                v.extend_from_slice(falcon_half(other));
            }
        }
        8 => if v.len() >= HDR { v[2] = val; v[3] = len as u8 % 4 },
        9 => {
            if v.len() >= HDR && v[..2] == MAGIC { v.drain(..HDR); } else { let mut e = envelope(1, v); std::mem::swap(v, &mut e); }
        }
        _ => {
            // Pad the Falcon half to the PQClean padded length.
            if v.len() > HDR + MLDSA_SIG {
                let fl = v.len() - (HDR + MLDSA_SIG);
                if fl < FALCON_PADDED_SIG { v.extend(std::iter::repeat(val & 1).take(FALCON_PADDED_SIG - fl)); }
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let f = fixture();
    let mut cur = Cur(data);
    let k = cur.u8() as usize % f.keys.len();
    let m = cur.u8() as usize % f.msgs.len();
    let j = cur.u8() as usize % 2;
    let pk_k = cur.u8() as usize % f.keys.len();
    let msg_sel = cur.u8();
    let forms = cur.u8();
    let mut sig = f.sigs[k][m][j].clone();
    let mut pk = if forms & 1 == 0 { f.keys[pk_k].pk_env.clone() } else { f.keys[pk_k].pk_body.clone() };
    if forms & 2 != 0 { sig.drain(..HDR); }
    let msg: Vec<u8> = match msg_sel % 4 {
        0 => f.msgs[0].clone(),
        1 => f.msgs[1].clone(),
        2 => { let mut x = f.msgs[(msg_sel as usize >> 2) % 2].clone(); x.push(0); x }
        _ => cur.take(40).to_vec(),
    };
    let nops = cur.u8() % 6;
    for _ in 0..nops {
        if cur.is_empty() { break; }
        let target_pk = cur.u8() & 0x0F == 0;
        if target_pk { mutate(f, &mut cur, &mut pk) } else { mutate(f, &mut cur, &mut sig) }
    }
    let entries: [(Entry, fn(&[u8], &[u8], &[u8]) -> bool); 5] = [
        (Entry::Verify, c::verify),
        (Entry::Enveloped, c::verify_enveloped),
        (Entry::EnvelopedCanonical, c::verify_enveloped_canonical),
        (Entry::LegacyRaw, c::verify_legacy_hybrid_raw),
        (Entry::LegacyRawCanonical, c::verify_legacy_hybrid_raw_canonical),
    ];
    let mut res = [false; 5];
    for (i, (e, func)) in entries.iter().enumerate() {
        res[i] = func(&pk, &msg, &sig);
        if res[i] { check(f, *e, &pk, &msg, &sig); }
    }
    // Policy lattice: canonical => non-canonical for the same framing;
    // enveloped => generic verify.
    assert!(!res[2] || res[1], "canonical accepted but enveloped rejected");
    assert!(!res[1] || res[0], "enveloped accepted but generic verify rejected");
    assert!(!res[4] || res[3], "legacy canonical accepted but legacy rejected");
});
