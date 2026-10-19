#![no_main]
//! Falcon-1024 compact-encoding differential + canonicality oracle.
//!
//! (a) Bloch's `verify_canonical` decides "compact" with a Rust mirror of
//!     PQClean's `comp_decode` framing (crypto/mod.rs `compact_encoding_len`).
//!     A divergence between the mirror and the real decoder is either a
//!     canonical-signature rejection (liveness) or a non-canonical acceptance
//!     (malleability). The mirror is private, so it is copied VERBATIM below
//!     (keep in sync) and compared with the C decoder linked into this binary.
//! (b) Mutating genuine Falcon signatures: `verify_canonical => verify`, and a
//!     signature accepted by `verify` but not by `verify_canonical` must be the
//!     1280-byte zero-padded form of a genuine compact signature.
mod common;
use bloch_crypto::crypto::falcon;
use common::*;
use libfuzzer_sys::fuzz_target;

extern "C" {
    fn PQCLEAN_FALCON1024_CLEAN_comp_decode(x: *mut i16, logn: u32, input: *const u8, max_in_len: usize) -> usize;
}

// ---- verbatim copy of bloch-crypto crypto::falcon::compact_encoding_len ----
const FALCON1024_COEFFICIENTS: usize = 1024;
fn compact_encoding_len(encoded: &[u8]) -> Option<usize> {
    let mut accumulator = 0u32;
    let mut remaining_bits = 0u32;
    let mut consumed = 0usize;
    for _ in 0..FALCON1024_COEFFICIENTS {
        let next = *encoded.get(consumed)?;
        consumed += 1;
        accumulator = (accumulator << 8) | u32::from(next);
        let first = accumulator >> remaining_bits;
        let sign = first & 128;
        let mut magnitude = first & 127;
        loop {
            if remaining_bits == 0 {
                let next = *encoded.get(consumed)?;
                consumed += 1;
                accumulator = (accumulator << 8) | u32::from(next);
                remaining_bits = 8;
            }
            remaining_bits -= 1;
            if ((accumulator >> remaining_bits) & 1) != 0 {
                break;
            }
            magnitude += 128;
            if magnitude > 2047 {
                return None;
            }
        }
        if sign != 0 && magnitude == 0 {
            return None;
        }
    }
    let unused_mask = (1u32 << remaining_bits).wrapping_sub(1);
    if accumulator & unused_mask != 0 {
        return None;
    }
    Some(consumed)
}
// ---------------------------------------------------------------------------

fn c_decode(enc: &[u8]) -> usize {
    let mut x = [0i16; 1024];
    unsafe { PQCLEAN_FALCON1024_CLEAN_comp_decode(x.as_mut_ptr(), 10, enc.as_ptr(), enc.len()) }
}

fuzz_target!(|data: &[u8]| {
    let fx = fixture();
    let mut cur = Cur(data);
    let mode = cur.u8();
    if mode & 1 == 0 {
        // (a) raw encoded polynomial bytes: exact-length agreement.
        let enc = cur.0;
        let v = c_decode(enc);
        let c_exact = v != 0 && v == enc.len();
        let r_exact = compact_encoding_len(enc) == Some(enc.len());
        assert_eq!(c_exact, r_exact, "mirror/C disagree: C consumed {v} of {}", enc.len());
        // Prefix agreement: whenever C decodes a prefix, the mirror reports the same length.
        if v != 0 { assert_eq!(compact_encoding_len(&enc[..v]), Some(v)); }
        return;
    }
    // (b) mutate a genuine compact Falcon signature.
    let k = (mode as usize >> 1) % 2;
    let m = (mode as usize >> 2) % 2;
    let j = (mode as usize >> 3) % 2;
    let pk = &fx.keys[k].pk_body[MLDSA_PK..];
    let genuine: Vec<&[u8]> = fx.sigs[k][m].iter().map(|s| falcon_half(s)).collect();
    let mut s = genuine[j].to_vec();
    let nops = cur.u8() % 5;
    for _ in 0..nops {
        let op = cur.u8();
        let pos = cur.u16() as usize % (s.len() + 1);
        let val = cur.u8();
        match op % 6 {
            0 => if pos < s.len() { s[pos] ^= 1 << (val % 8) },
            1 => s.insert(pos, val),
            2 => if pos < s.len() { s.remove(pos); },
            3 => s.truncate(pos.max(1)),
            4 => { while s.len() < FALCON_PADDED_SIG { s.push(0) } }
            _ => s.extend(std::iter::repeat(val).take(op as usize % 4 + 1)),
        }
    }
    let msg = &fx.msgs[m];
    let ok = falcon::verify(pk, msg, &s);
    let canon = falcon::verify_canonical(pk, msg, &s);
    assert!(!canon || ok);
    if canon { assert!(genuine.iter().any(|g| *g == s.as_slice()), "canonical verifier accepted a non-genuine encoding"); }
    if ok && !canon {
        assert!(s.len() == FALCON_PADDED_SIG
            && genuine.iter().any(|g| s.starts_with(g) && s[g.len()..].iter().all(|&b| b == 0)),
            "verify accepted an encoding that is neither genuine nor its zero-padded form (len {})", s.len());
    }
});
