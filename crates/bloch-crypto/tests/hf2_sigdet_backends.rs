// SPDX-License-Identifier: AGPL-3.0-or-later
//! HF2 signature determinism: ML-DSA-65 pinned to the FIPS 204 reference
//! behaviour (PQClean `clean`) on every platform.
//!
//! These tests check, on every backend the test host can execute:
//!
//! * keygen is the same function of the seed (FIPS 204 Alg. 6: wallets and
//!   validator keys derived from a seed do not rotate when the backend does);
//! * signing with the same `rnd` stream produces byte-identical signatures,
//!   with and without a FIPS 204 context (the v2 suite-bound context
//!   included), i.e. every intermediate value of Alg. 7 agrees;
//! * verification verdicts agree on genuine signatures and on structured
//!   mutations of c~, z, the hint vector and the per-row hint counters, under
//!   the empty context and under both v2 contexts;
//! * the pinned verifier enforces FIPS 204 Alg. 8's bound on z.
//!
//! NIST ACVP agreement for each backend is in `acvp_fips204_full.rs`; the
//! open-ended differential is the `mldsa_backend_diff` cargo-fuzz target.
use pqcrypto_mldsa::ffi;

const PK: usize = 1952;
const SK: usize = 4032;
const SIG: usize = 3309;

type Keypair = unsafe extern "C" fn(*mut u8, *mut u8) -> core::ffi::c_int;
type SignCtx =
    unsafe extern "C" fn(*mut u8, *mut usize, *const u8, usize, *const u8, usize, *const u8) -> core::ffi::c_int;
type VerifyCtx =
    unsafe extern "C" fn(*const u8, usize, *const u8, usize, *const u8, usize, *const u8) -> core::ffi::c_int;

struct Backend {
    name: &'static str,
    keypair: Keypair,
    sign: SignCtx,
    verify: VerifyCtx,
}

fn backends() -> Vec<Backend> {
    let mut v = vec![Backend {
        name: "clean",
        keypair: ffi::PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair,
        sign: ffi::PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature_ctx,
        verify: ffi::PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify_ctx,
    }];
    #[cfg(target_arch = "x86_64")]
    if std::is_x86_feature_detected!("avx2") {
        v.push(Backend {
            name: "avx2",
            keypair: ffi::PQCLEAN_MLDSA65_AVX2_crypto_sign_keypair,
            sign: ffi::PQCLEAN_MLDSA65_AVX2_crypto_sign_signature_ctx,
            verify: ffi::PQCLEAN_MLDSA65_AVX2_crypto_sign_verify_ctx,
        });
    }
    #[cfg(target_arch = "aarch64")]
    v.push(Backend {
        name: "aarch64",
        keypair: ffi::PQCLEAN_MLDSA65_AARCH64_crypto_sign_keypair,
        sign: ffi::PQCLEAN_MLDSA65_AARCH64_crypto_sign_signature_ctx,
        verify: ffi::PQCLEAN_MLDSA65_AARCH64_crypto_sign_verify_ctx,
    });
    v
}

fn keypair_seeded(b: &Backend, seed: &[u8; 32]) -> ([u8; PK], [u8; SK]) {
    let (mut pk, mut sk) = ([0u8; PK], [0u8; SK]);
    // SAFETY: buffers have exactly the FIPS 204 ML-DSA-65 sizes.
    let rc = pqcrypto_internals::with_seeded_rng_scope(seed, || unsafe {
        (b.keypair)(pk.as_mut_ptr(), sk.as_mut_ptr())
    });
    assert_eq!(rc, 0, "{} keypair", b.name);
    (pk, sk)
}

fn sign_seeded(b: &Backend, sk: &[u8; SK], msg: &[u8], ctx: &[u8], rnd_seed: &[u8; 32]) -> Vec<u8> {
    let mut sig = vec![0u8; SIG];
    let mut len = 0usize;
    // SAFETY: sig has SIG capacity, every input pointer carries its length.
    let rc = pqcrypto_internals::with_seeded_rng_scope(rnd_seed, || unsafe {
        (b.sign)(sig.as_mut_ptr(), &mut len, msg.as_ptr(), msg.len(), ctx.as_ptr(), ctx.len(), sk.as_ptr())
    });
    assert_eq!((rc, len), (0, SIG), "{} sign", b.name);
    sig
}

fn verify(b: &Backend, pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
    assert_eq!(pk.len(), PK);
    // SAFETY: every pointer is passed with its length; pk length asserted.
    unsafe { (b.verify)(sig.as_ptr(), sig.len(), msg.as_ptr(), msg.len(), ctx.as_ptr(), ctx.len(), pk.as_ptr()) == 0 }
}

/// Splitmix64, so the mutation schedule is reproducible without a dev-dep.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn v2_ctx(suite: u16) -> Vec<u8> {
    let mut c = bloch_crypto::crypto::SIG_V2_MLDSA_CONTEXT_PREFIX.to_vec();
    c.extend_from_slice(&suite.to_le_bytes());
    c
}

#[test]
fn seeded_keygen_is_backend_independent() {
    let bs = backends();
    eprintln!("backends: {:?}", bs.iter().map(|b| b.name).collect::<Vec<_>>());
    for i in 0..16u8 {
        let seed = [i.wrapping_mul(37).wrapping_add(1); 32];
        let reference = keypair_seeded(&bs[0], &seed);
        for b in &bs[1..] {
            assert_eq!(keypair_seeded(b, &seed), reference, "{} keygen differs from clean (seed {i})", b.name);
        }
    }
    // The production seeded keygen (which runs the dispatched keypair in this
    // test binary and `clean` in a release binary) yields the clean key.
    let seed = [0x42u8; 32];
    let (pk, _) = bloch_crypto::crypto::generate_keypair_from_seed(&seed).unwrap();
    let (_, body) = bloch_crypto::crypto::split_envelope(&pk).unwrap();
    assert_eq!(&body[..PK], &keypair_seeded(&bs[0], &seed).0[..]);
}

#[test]
fn same_rnd_gives_byte_identical_signatures_on_every_backend() {
    let bs = backends();
    let ctxs: [Vec<u8>; 4] = [Vec::new(), v2_ctx(0x0001), v2_ctx(0x0002), vec![0xA5; 255]];
    for i in 0..8u8 {
        let (pk, sk) = keypair_seeded(&bs[0], &[i ^ 0x5C; 32]);
        for ctx in &ctxs {
            for m in 0..4u8 {
                let msg: Vec<u8> = (0..(m as usize * 41)).map(|j| j as u8 ^ i).collect();
                let rnd = [m.wrapping_add(i).wrapping_mul(13); 32];
                let reference = sign_seeded(&bs[0], &sk, &msg, ctx, &rnd);
                for b in &bs {
                    let s = sign_seeded(b, &sk, &msg, ctx, &rnd);
                    assert_eq!(s, reference, "{} signature bytes differ from clean", b.name);
                    for v in &bs {
                        assert!(verify(v, &pk, &msg, ctx, &s), "{} rejects {} signature", v.name, b.name);
                    }
                }
            }
        }
    }
}

#[test]
fn verify_verdicts_agree_on_structured_mutations() {
    let bs = backends();
    let mut rng = Rng(0x4846_325f_5349_4744); // "HF2_SIGD"
    let ctxs: [Vec<u8>; 3] = [Vec::new(), v2_ctx(0x0001), v2_ctx(0x0002)];
    let (mut checked, mut accepted) = (0usize, 0usize);
    for k in 0..4u8 {
        let (pk, sk) = keypair_seeded(&bs[0], &[k.wrapping_add(0x77); 32]);
        for (ci, ctx) in ctxs.iter().enumerate() {
            let msg = [b"hf2 sigdet ".as_slice(), &[k, ci as u8]].concat();
            let sig = sign_seeded(&bs[0], &sk, &msg, ctx, &[k ^ ci as u8; 32]);
            for _ in 0..300 {
                let mut s = sig.clone();
                let mut p = pk.to_vec();
                let mut m = msg.clone();
                let mut c = ctx.clone();
                for _ in 0..=rng.below(3) {
                    match rng.below(9) {
                        0 => s[rng.below(48)] ^= 1 << rng.below(8),               // c~
                        1 => s[48 + rng.below(3200)] ^= 1 << rng.below(8),        // z
                        2 => { let i = SIG - 61 + rng.below(55); s[i] = rng.next() as u8; } // hint indices
                        3 => { let i = SIG - 6 + rng.below(6); s[i] = rng.next() as u8; }   // row counters
                        4 => { let i = SIG - 6 + rng.below(6); s[i] = s[i].wrapping_add(1); }
                        5 => p[rng.below(PK)] ^= 1 << rng.below(8),
                        6 => m.push(rng.next() as u8),
                        7 => c = ctxs[rng.below(3)].clone(),                     // cross-suite context
                        _ => {} // genuine
                    }
                }
                let reference = verify(&bs[0], &p, &m, &c, &s);
                for b in &bs[1..] {
                    assert_eq!(verify(b, &p, &m, &c, &s), reference, "{} vs clean verdict", b.name);
                }
                // Consensus wrapper = clean, empty context.
                if c.is_empty() {
                    assert_eq!(bloch_crypto::crypto::verify_mldsa65_raw(&p, &m, &s), reference);
                }
                checked += 1;
                accepted += usize::from(reference);
            }
        }
    }
    eprintln!("hf2 sigdet: {checked} cases, {accepted} accepted, all backends agree");
    assert!(accepted > 0 && accepted < checked);
}

/// The v2 suite-bound signer and verifier also run `clean`, and the v2
/// ML-DSA half is accepted by every backend under its suite context only.
#[test]
fn v2_bound_signatures_verify_on_every_backend_under_their_suite_context_only() {
    use bloch_crypto::crypto::{sign_bound, split_envelope, verify_bound, generate_keypair_from_seed};
    let bs = backends();
    let (pk, sk) = generate_keypair_from_seed(&[0x31u8; 32]).unwrap();
    let msg = b"hf2 v2 bound";
    let sig = sign_bound(&sk, msg).unwrap();
    assert!(verify_bound(&pk, msg, &sig));
    let (suite, pk_body) = split_envelope(&pk).unwrap();
    let (_, sig_body) = split_envelope(&sig).unwrap();
    assert_eq!(suite, 0x0001);
    for b in &bs {
        assert!(verify(b, &pk_body[..PK], msg, &v2_ctx(0x0001), &sig_body[..SIG]), "{}", b.name);
        assert!(!verify(b, &pk_body[..PK], msg, &v2_ctx(0x0002), &sig_body[..SIG]), "{}", b.name);
        assert!(!verify(b, &pk_body[..PK], msg, b"", &sig_body[..SIG]), "{}", b.name);
    }
}

// ── FIPS 204 Alg. 8 z bound ──────────────────────────────────────────────
//
// FIPS 204 Alg. 8 line 13 requires ||z||_inf < GAMMA1 - BETA. The fixture
// below produces a signature that is well-formed in every other respect but
// whose z lies in [GAMMA1 - BETA, GAMMA1]: it is the reference signer
// (sign.c, Alg. 7) driven through PQClean's own internal routines with the z
// acceptance condition inverted. The pinned verifier must reject it on every
// platform.

const N: usize = 256;
const K: usize = 6;
const L: usize = 5;
const GAMMA1: i32 = 1 << 19;
const GAMMA2: i32 = (8_380_417 - 1) / 32;
const BETA: i32 = 196;
const OMEGA: u32 = 55;

#[repr(C)]
#[derive(Clone, Copy)]
struct Poly([i32; N]);
#[repr(C)]
#[derive(Clone, Copy)]
struct VecL([Poly; L]);
#[repr(C)]
#[derive(Clone, Copy)]
struct VecK([Poly; K]);

extern "C" {
    fn PQCLEAN_MLDSA65_CLEAN_unpack_sk(
        rho: *mut u8, tr: *mut u8, key: *mut u8, t0: *mut VecK, s1: *mut VecL, s2: *mut VecK, sk: *const u8,
    );
    fn PQCLEAN_MLDSA65_CLEAN_polyvec_matrix_expand(mat: *mut VecL, rho: *const u8);
    fn PQCLEAN_MLDSA65_CLEAN_polyvecl_ntt(v: *mut VecL);
    fn PQCLEAN_MLDSA65_CLEAN_polyveck_ntt(v: *mut VecK);
    fn PQCLEAN_MLDSA65_CLEAN_polyvecl_uniform_gamma1(v: *mut VecL, seed: *const u8, nonce: u16);
    fn PQCLEAN_MLDSA65_CLEAN_polyvec_matrix_pointwise_montgomery(t: *mut VecK, mat: *const VecL, v: *const VecL);
    fn PQCLEAN_MLDSA65_CLEAN_polyveck_reduce(v: *mut VecK);
    fn PQCLEAN_MLDSA65_CLEAN_polyveck_invntt_tomont(v: *mut VecK);
    fn PQCLEAN_MLDSA65_CLEAN_polyveck_caddq(v: *mut VecK);
    fn PQCLEAN_MLDSA65_CLEAN_polyveck_decompose(v1: *mut VecK, v0: *mut VecK, v: *const VecK);
    fn PQCLEAN_MLDSA65_CLEAN_polyveck_pack_w1(r: *mut u8, w1: *const VecK);
    fn PQCLEAN_MLDSA65_CLEAN_poly_challenge(c: *mut Poly, seed: *const u8);
    fn PQCLEAN_MLDSA65_CLEAN_poly_ntt(a: *mut Poly);
    fn PQCLEAN_MLDSA65_CLEAN_polyvecl_pointwise_poly_montgomery(r: *mut VecL, a: *const Poly, v: *const VecL);
    fn PQCLEAN_MLDSA65_CLEAN_polyvecl_invntt_tomont(v: *mut VecL);
    fn PQCLEAN_MLDSA65_CLEAN_polyvecl_add(w: *mut VecL, u: *const VecL, v: *const VecL);
    fn PQCLEAN_MLDSA65_CLEAN_polyvecl_reduce(v: *mut VecL);
    fn PQCLEAN_MLDSA65_CLEAN_polyvecl_chknorm(v: *const VecL, b: i32) -> core::ffi::c_int;
    fn PQCLEAN_MLDSA65_CLEAN_polyveck_pointwise_poly_montgomery(r: *mut VecK, a: *const Poly, v: *const VecK);
    fn PQCLEAN_MLDSA65_CLEAN_polyveck_sub(w: *mut VecK, u: *const VecK, v: *const VecK);
    fn PQCLEAN_MLDSA65_CLEAN_polyveck_add(w: *mut VecK, u: *const VecK, v: *const VecK);
    fn PQCLEAN_MLDSA65_CLEAN_polyveck_chknorm(v: *const VecK, b: i32) -> core::ffi::c_int;
    fn PQCLEAN_MLDSA65_CLEAN_polyveck_make_hint(h: *mut VecK, v0: *const VecK, v1: *const VecK) -> core::ffi::c_uint;
    fn PQCLEAN_MLDSA65_CLEAN_pack_sig(sig: *mut u8, c: *const u8, z: *const VecL, h: *const VecK);
}

fn shake256(parts: &[&[u8]], out: &mut [u8]) {
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    let mut h = sha3::Shake256::default();
    for p in parts {
        h.update(p);
    }
    h.finalize_xof().read(out);
}

/// A signature on `msg` (empty context) under `sk` that satisfies every
/// FIPS 204 condition except ||z||_inf < GAMMA1 - BETA. Returns the signature and the
/// largest |z_i| it carries.
fn z_bound_fixture(sk: &[u8; SK], msg: &[u8]) -> (Vec<u8>, i32) {
    let zero_poly = Poly([0; N]);
    let (mut t0, mut s2) = (VecK([zero_poly; K]), VecK([zero_poly; K]));
    let mut s1 = VecL([zero_poly; L]);
    let (mut rho, mut tr, mut key) = ([0u8; 32], [0u8; 64], [0u8; 32]);
    let mut mat = [VecL([zero_poly; L]); K];
    let mut mu = [0u8; 64];
    let mut rhoprime = [0u8; 64];
    // SAFETY: every buffer has the exact type/size the PQClean prototypes in
    // clean/{packing,polyvec,poly}.h declare for ML-DSA-65 (K = 6, L = 5,
    // N = 256, int32 coefficients); pqcrypto-mldsa is pinned =0.1.2.
    unsafe {
        PQCLEAN_MLDSA65_CLEAN_unpack_sk(
            rho.as_mut_ptr(), tr.as_mut_ptr(), key.as_mut_ptr(), &mut t0, &mut s1, &mut s2, sk.as_ptr(),
        );
        shake256(&[&tr, &[0u8, 0u8], msg], &mut mu);
        shake256(&[&key, &[0u8; 32], &mu], &mut rhoprime); // rnd = 0^32
        PQCLEAN_MLDSA65_CLEAN_polyvec_matrix_expand(mat.as_mut_ptr(), rho.as_ptr());
        PQCLEAN_MLDSA65_CLEAN_polyvecl_ntt(&mut s1);
        PQCLEAN_MLDSA65_CLEAN_polyveck_ntt(&mut s2);
        PQCLEAN_MLDSA65_CLEAN_polyveck_ntt(&mut t0);
        for nonce in 0..u16::MAX {
            let mut y = VecL([zero_poly; L]);
            PQCLEAN_MLDSA65_CLEAN_polyvecl_uniform_gamma1(&mut y, rhoprime.as_ptr(), nonce);
            let mut z = y;
            let (mut w1, mut w0, mut h) = (VecK([zero_poly; K]), VecK([zero_poly; K]), VecK([zero_poly; K]));
            PQCLEAN_MLDSA65_CLEAN_polyvecl_ntt(&mut z);
            PQCLEAN_MLDSA65_CLEAN_polyvec_matrix_pointwise_montgomery(&mut w1, mat.as_ptr(), &z);
            PQCLEAN_MLDSA65_CLEAN_polyveck_reduce(&mut w1);
            PQCLEAN_MLDSA65_CLEAN_polyveck_invntt_tomont(&mut w1);
            PQCLEAN_MLDSA65_CLEAN_polyveck_caddq(&mut w1);
            let w = w1;
            PQCLEAN_MLDSA65_CLEAN_polyveck_decompose(&mut w1, &mut w0, &w);
            let mut sig = vec![0u8; SIG];
            PQCLEAN_MLDSA65_CLEAN_polyveck_pack_w1(sig.as_mut_ptr(), &w1);
            let mut ctilde = [0u8; 48];
            shake256(&[&mu, &sig[..K * 128]], &mut ctilde);
            let mut cp = zero_poly;
            PQCLEAN_MLDSA65_CLEAN_poly_challenge(&mut cp, ctilde.as_ptr());
            PQCLEAN_MLDSA65_CLEAN_poly_ntt(&mut cp);

            PQCLEAN_MLDSA65_CLEAN_polyvecl_pointwise_poly_montgomery(&mut z, &cp, &s1);
            PQCLEAN_MLDSA65_CLEAN_polyvecl_invntt_tomont(&mut z);
            let zc = z;
            PQCLEAN_MLDSA65_CLEAN_polyvecl_add(&mut z, &zc, &y);
            PQCLEAN_MLDSA65_CLEAN_polyvecl_reduce(&mut z);
            // Inverted z condition: keep only z outside the bound that still encodes
            // (polyz_pack represents exactly [-(GAMMA1 - 1), GAMMA1]).
            let over = PQCLEAN_MLDSA65_CLEAN_polyvecl_chknorm(&z, GAMMA1 - BETA) != 0;
            let encodable = z.0.iter().all(|p| p.0.iter().all(|&c| (-(GAMMA1 - 1)..=GAMMA1).contains(&c)));
            if !(over && encodable) {
                continue;
            }
            // Every other signer check, unchanged.
            PQCLEAN_MLDSA65_CLEAN_polyveck_pointwise_poly_montgomery(&mut h, &cp, &s2);
            PQCLEAN_MLDSA65_CLEAN_polyveck_invntt_tomont(&mut h);
            let w0c = w0;
            PQCLEAN_MLDSA65_CLEAN_polyveck_sub(&mut w0, &w0c, &h);
            PQCLEAN_MLDSA65_CLEAN_polyveck_reduce(&mut w0);
            if PQCLEAN_MLDSA65_CLEAN_polyveck_chknorm(&w0, GAMMA2 - BETA) != 0 {
                continue;
            }
            PQCLEAN_MLDSA65_CLEAN_polyveck_pointwise_poly_montgomery(&mut h, &cp, &t0);
            PQCLEAN_MLDSA65_CLEAN_polyveck_invntt_tomont(&mut h);
            PQCLEAN_MLDSA65_CLEAN_polyveck_reduce(&mut h);
            if PQCLEAN_MLDSA65_CLEAN_polyveck_chknorm(&h, GAMMA2) != 0 {
                continue;
            }
            let w0c = w0;
            PQCLEAN_MLDSA65_CLEAN_polyveck_add(&mut w0, &w0c, &h);
            let hc = h;
            let n = PQCLEAN_MLDSA65_CLEAN_polyveck_make_hint(&mut h, &w0, &w1);
            let _ = hc;
            if n > OMEGA {
                continue;
            }
            PQCLEAN_MLDSA65_CLEAN_pack_sig(sig.as_mut_ptr(), ctilde.as_ptr(), &z, &h);
            let max = z.0.iter().flat_map(|p| p.0.iter()).map(|c| c.abs()).max().unwrap();
            return (sig, max);
        }
    }
    panic!("no z-bound fixture candidate found");
}

#[test]
fn pinned_verifier_enforces_the_fips204_z_bound() {
    let bs = backends();
    for i in 0..4u8 {
        let (pk, sk) = keypair_seeded(&bs[0], &[0xD0 ^ i; 32]);
        let msg = [b"hf2 z bound ".as_slice(), &[i]].concat();
        let (sig, max_z) = z_bound_fixture(&sk, &msg);
        assert!(max_z >= GAMMA1 - BETA && max_z <= GAMMA1, "fixture |z| = {max_z}");
        assert!(!verify(&bs[0], &pk, &msg, b"", &sig), "clean must enforce the z bound");
        assert!(!bloch_crypto::crypto::verify_mldsa65_raw_pinned(&pk, &msg, &sig));
        // Tamper control.
        let mut bad = sig.clone();
        bad[0] ^= 1;
        for b in &bs {
            assert!(!verify(b, &pk, &msg, b"", &bad), "{} accepts tampered c~", b.name);
        }
    }
}

/// The pinned policies enforce the same bound on hybrid (0x0001) signatures
/// whose ML-DSA half is the z-bound fixture, and still accept honest ones.
#[test]
fn pinned_policies_enforce_the_fips204_z_bound_on_hybrid_signatures() {
    use bloch_crypto::crypto::{
        falcon, generate_keypair_from_seed, sign, split_envelope, verify as verify_legacy, verify_pinned,
        verify_with_policy, SignaturePolicy, MLDSA_SECRET_LEN, SUITE_HEADER_LEN,
    };
    let (pk, sk) = generate_keypair_from_seed(&[0xE7u8; 32]).unwrap();
    let (_, sk_body) = split_envelope(&sk).unwrap();
    let msk: [u8; SK] = sk_body[..MLDSA_SECRET_LEN].try_into().unwrap();
    let msg = [0x5Au8; 32];
    let (msig, _) = z_bound_fixture(&msk, &msg);
    let honest = sign(&sk, &msg).unwrap();
    let mut candidate = honest[..SUITE_HEADER_LEN].to_vec();
    candidate.extend_from_slice(&msig);
    candidate.extend_from_slice(&falcon::sign(&sk_body[MLDSA_SECRET_LEN..], &msg).unwrap());
    for policy in [SignaturePolicy::CompatiblePinned, SignaturePolicy::CanonicalUnbound] {
        assert!(!verify_with_policy(policy, &pk, &msg, &candidate), "{policy:?}");
    }
    assert!(!verify_pinned(&pk, &msg, &candidate));
    assert_eq!(
        verify_with_policy(SignaturePolicy::Compatible, &pk, &msg, &candidate),
        verify_legacy(&pk, &msg, &candidate)
    );
    for policy in [SignaturePolicy::Compatible, SignaturePolicy::CompatiblePinned, SignaturePolicy::CanonicalUnbound] {
        assert!(verify_with_policy(policy, &pk, &msg, &honest), "{policy:?}");
    }
}
