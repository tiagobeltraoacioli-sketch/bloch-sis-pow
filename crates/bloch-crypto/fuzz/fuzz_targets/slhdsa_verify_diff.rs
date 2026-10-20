#![no_main]
//! SLH-DSA-SHAKE-128s candidate verifiers, differential + SUF oracle:
//! `fips205 =0.4.1` vs RustCrypto `slh-dsa =0.2.0-rc.5`, on mutated genuine
//! signatures, messages, contexts and public keys, plus arbitrary-length
//! signature/key bytes through each crate's parsing path. Any disagreement,
//! panic, or acceptance of anything but the exact genuine (pk, msg, ctx, sig)
//! aborts.
mod common;
use common::Cur;
use fips205::slh_dsa_shake_128s as f205;
use fips205::traits::{KeyGen, SerDes, Signer, Verifier};
use libfuzzer_sys::fuzz_target;
use slh_dsa::{Shake128s, Signature, VerifyingKey};
use std::sync::OnceLock;

const CTX: &[u8] = b"BLOCH/SUITE/0x0003/SLH-DSA-SHAKE-128s+Falcon-1024/v1";
const MSG: &[u8] = b"bloch p9e slh-dsa fuzz message";

struct Zero;
impl rand_core_06::RngCore for Zero {
    fn next_u32(&mut self) -> u32 { 0 }
    fn next_u64(&mut self) -> u64 { 0 }
    fn fill_bytes(&mut self, o: &mut [u8]) { o.fill(0) }
    fn try_fill_bytes(&mut self, o: &mut [u8]) -> Result<(), rand_core_06::Error> { o.fill(0); Ok(()) }
}
impl rand_core_06::CryptoRng for Zero {}

fn fx() -> &'static ([u8; 32], Vec<u8>) {
    static F: OnceLock<([u8; 32], Vec<u8>)> = OnceLock::new();
    F.get_or_init(|| {
        let (pk, sk) = f205::KG::keygen_with_seeds(&[7u8; 16], &[8u8; 16], &[9u8; 16]);
        let sig = sk.try_sign_with_rng(&mut Zero, MSG, CTX, false).unwrap();
        (pk.into_bytes(), sig.to_vec())
    })
}

fn v205(pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
    let Ok(pk) = <[u8; f205::PK_LEN]>::try_from(pk) else { return false };
    let Ok(pk) = f205::PublicKey::try_from_bytes(&pk) else { return false };
    let Ok(sig) = <[u8; f205::SIG_LEN]>::try_from(sig) else { return false };
    pk.verify(msg, &sig, ctx)
}
fn vrc(pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
    let Ok(pk) = VerifyingKey::<Shake128s>::try_from(pk) else { return false };
    let Ok(sig) = Signature::<Shake128s>::try_from(sig) else { return false };
    pk.try_verify_with_context(msg, ctx, &sig).is_ok()
}

fuzz_target!(|data: &[u8]| {
    let (gpk, gsig) = fx();
    let mut cur = Cur(data);
    let mode = cur.u8();
    let (mut pk, mut sig, mut msg, mut ctx) = (gpk.to_vec(), gsig.clone(), MSG.to_vec(), CTX.to_vec());
    if mode % 8 == 0 {
        // Arbitrary lengths/bytes for everything.
        let n = cur.u8() as usize; pk = cur.take(n % 40).to_vec();
        let n = cur.u8() as usize; ctx = cur.take(n).to_vec();
        sig = cur.0.to_vec();
    } else {
        let nops = cur.u8() % 6;
        for _ in 0..nops {
            let op = cur.u8();
            let off = cur.u16() as usize;
            let val = cur.u8();
            match op % 7 {
                0 => { let i = off % 16; sig[i] ^= val | 1; }                  // R
                1 => { let i = 16 + off % (14 * 13 * 16); sig[i] ^= val | 1; } // FORS
                2 => { let i = off % sig.len(); sig[i] ^= val | 1; }             // anywhere
                3 => { let i = off % pk.len(); pk[i] ^= val | 1; }
                4 => { ctx.push(val) }
                5 => { msg.push(val) }
                _ => { if off & 1 == 0 { sig.push(val) } else { sig.pop(); } }
            }
        }
    }
    let a = v205(&pk, &msg, &ctx, &sig);
    let b = vrc(&pk, &msg, &ctx, &sig);
    assert_eq!(a, b, "fips205 vs slh-dsa disagree");
    if a {
        assert!(pk == gpk.as_slice() && msg == MSG && ctx == CTX && sig == *gsig,
            "accepted a (pk,msg,ctx,sig) that is not the genuine one");
    }
});
