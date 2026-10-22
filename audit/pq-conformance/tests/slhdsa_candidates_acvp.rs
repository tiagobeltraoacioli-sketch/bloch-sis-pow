//! P9e: FIPS 205 (final) ACVP conformance of the SLH-DSA candidate crates for
//! the optional hash-based suite, parameter set SLH-DSA-SHAKE-128s.
//!
//!  * `fips205 =0.4.1` (IntegrityChain; the crate P9a prototyped with). Its
//!    public API has no `*_internal` sign/verify, so only the external/pure
//!    groups and keyGen are reachable.
//!  * `slh-dsa =0.2.0-rc.5` (RustCrypto). Exposes `slh_keygen_internal`,
//!    `slh_sign_internal`, `slh_verify_internal` (doc-hidden, "for KAT").
//!
//! Round-3 SPHINCS+ differs from FIPS 205 (M' context framing, H_msg/PRF_msg
//! changes, address encoding in SHA2 sets), so byte-exact ACVP FIPS205 sigGen
//! reproduction is evidence the crate implements the final standard.
use serde_json::Value;

const FIXTURE: &[u8] = include_bytes!("../vectors/acvp-fips205-slhdsa-shake128s.json");
const FIXTURE_SHA256: &str = "03c3c86e668f540c71add101b8aa89ac60bcfa60683dc608e75872ea21081329";

fn fixture() -> Value {
    use sha2::Digest;
    assert_eq!(hex::encode(sha2::Sha256::digest(FIXTURE)), FIXTURE_SHA256, "fixture edited");
    let v: Value = serde_json::from_slice(FIXTURE).unwrap();
    assert_eq!(v["parameterSet"], "SLH-DSA-SHAKE-128s");
    v
}
fn b(case: &Value, field: &str) -> Vec<u8> {
    hex::decode(case[field].as_str().unwrap_or("")).unwrap()
}
fn arr<const N: usize>(v: &[u8]) -> [u8; N] {
    v.try_into().unwrap()
}
fn external(case: &Value) -> bool {
    case["signatureInterface"] == "external"
}

mod fips205_crate {
    use super::*;
    use fips205::slh_dsa_shake_128s as slh;
    use fips205::traits::{KeyGen, SerDes, Signer, Verifier};

    /// rand_core 0.6 RNG that returns one pre-chosen buffer (opt_rand).
    pub(super) struct Fixed(pub(super) Vec<u8>);
    impl rand_core_06::RngCore for Fixed {
        fn next_u32(&mut self) -> u32 { unimplemented!() }
        fn next_u64(&mut self) -> u64 { unimplemented!() }
        fn fill_bytes(&mut self, out: &mut [u8]) { self.try_fill_bytes(out).unwrap() }
        fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), rand_core_06::Error> {
            out.copy_from_slice(&self.0);
            Ok(())
        }
    }
    impl rand_core_06::CryptoRng for Fixed {}

    #[test]
    fn keygen_10_of_10() {
        let v = fixture();
        let cases = v["keyGen"].as_array().unwrap();
        assert_eq!(cases.len(), 10);
        for case in cases {
            let (pk, sk) = slh::KG::keygen_with_seeds(
                &arr::<16>(&b(case, "skSeed")), &arr(&b(case, "skPrf")), &arr(&b(case, "pkSeed")));
            assert_eq!(pk.into_bytes().to_vec(), b(case, "pk"), "tcId {}", case["tcId"]);
            assert_eq!(sk.into_bytes().to_vec(), b(case, "sk"), "tcId {}", case["tcId"]);
        }
    }

    #[test]
    fn siggen_external_pure_deterministic_and_hedged() {
        let v = fixture();
        let mut n = 0;
        for case in v["sigGen"].as_array().unwrap().iter().filter(|c| external(c)) {
            let sk = slh::PrivateKey::try_from_bytes(&arr(&b(case, "sk"))).unwrap();
            let det = case["deterministic"].as_bool().unwrap();
            let sig = if det {
                sk.try_sign_with_rng(&mut Fixed(vec![0u8; 16]), &b(case, "message"), &b(case, "context"), false).unwrap()
            } else {
                let mut rng = Fixed(b(case, "additionalRandomness"));
                sk.try_sign_with_rng(&mut rng, &b(case, "message"), &b(case, "context"), true).unwrap()
            };
            assert_eq!(sig.to_vec(), b(case, "signature"), "tcId {} det={det}", case["tcId"]);
            n += 1;
        }
        assert_eq!(n, 14);
    }

    #[test]
    fn sigver_external_pure_all_outcomes() {
        let v = fixture();
        let mut n = 0;
        for case in v["sigVer"].as_array().unwrap().iter().filter(|c| external(c)) {
            let want = case["testPassed"].as_bool().unwrap();
            let pk = slh::PublicKey::try_from_bytes(&arr(&b(case, "pk"))).unwrap();
            let sig = b(case, "signature");
            // fips205 takes a fixed-size array: wrong-length signatures are
            // rejected by the caller's length check (Bloch must do this too).
            let got = match <[u8; slh::SIG_LEN]>::try_from(sig.as_slice()) {
                Ok(s) => pk.verify(&b(case, "message"), &s, &b(case, "context")),
                Err(_) => false,
            };
            assert_eq!(got, want, "tcId {} ({})", case["tcId"], case["reason"]);
            n += 1;
        }
        assert_eq!(n, 14);
    }
}

mod rustcrypto_slh_dsa {
    use super::*;
    use slh_dsa::signature::Keypair;
    use slh_dsa::{Shake128s, Signature, SigningKey, VerifyingKey};

    #[test]
    fn keygen_10_of_10() {
        let v = fixture();
        for case in v["keyGen"].as_array().unwrap() {
            let sk = SigningKey::<Shake128s>::slh_keygen_internal(
                &b(case, "skSeed"), &b(case, "skPrf"), &b(case, "pkSeed"));
            assert_eq!(sk.to_vec(), b(case, "sk"), "tcId {}", case["tcId"]);
            assert_eq!(sk.verifying_key().to_vec(), b(case, "pk"), "tcId {}", case["tcId"]);
        }
    }

    #[test]
    fn siggen_all_28_internal_and_external() {
        let v = fixture();
        let mut n = 0;
        for case in v["sigGen"].as_array().unwrap() {
            let sk = SigningKey::<Shake128s>::try_from(b(case, "sk").as_slice()).unwrap();
            let det = case["deterministic"].as_bool().unwrap();
            let rnd = b(case, "additionalRandomness");
            let opt = if det { None } else { Some(rnd.as_slice()) };
            let msg = b(case, "message");
            let sig = if external(case) {
                sk.try_sign_with_context(&msg, &b(case, "context"), opt).unwrap()
            } else {
                sk.slh_sign_internal(&[&msg], opt)
            };
            assert_eq!(sig.to_vec(), b(case, "signature"), "tcId {}", case["tcId"]);
            n += 1;
        }
        assert_eq!(n, 28);
    }

    #[test]
    fn sigver_all_28_outcomes() {
        let v = fixture();
        for case in v["sigVer"].as_array().unwrap() {
            let want = case["testPassed"].as_bool().unwrap();
            let pk = VerifyingKey::<Shake128s>::try_from(b(case, "pk").as_slice()).unwrap();
            let got = match Signature::<Shake128s>::try_from(b(case, "signature").as_slice()) {
                Ok(sig) if external(case) =>
                    pk.try_verify_with_context(&b(case, "message"), &b(case, "context"), &sig).is_ok(),
                Ok(sig) => pk.slh_verify_internal(&[&b(case, "message")], &sig).is_ok(),
                Err(_) => false,
            };
            assert_eq!(got, want, "tcId {} ({})", case["tcId"], case["reason"]);
        }
    }

    /// Cross-implementation: the two candidates agree on signatures they emit.
    #[test]
    fn candidates_interoperate() {
        use fips205::slh_dsa_shake_128s as slh;
        use fips205::traits::{KeyGen, SerDes, Signer, Verifier};
        let (pk, sk) = slh::KG::keygen_with_seeds(&[1u8; 16], &[2u8; 16], &[3u8; 16]);
        let rc_sk = SigningKey::<Shake128s>::slh_keygen_internal(&[1u8; 16], &[2u8; 16], &[3u8; 16]);
        assert_eq!(rc_sk.to_vec(), sk.clone().into_bytes().to_vec());
        let ctx = b"BLOCH/SUITE/0x0003/test";
        let s1 = sk.try_sign_with_rng(&mut super::fips205_crate::Fixed(vec![0u8; 16]), b"m", ctx, false).unwrap();
        let s2 = rc_sk.try_sign_with_context(b"m", ctx, None).unwrap();
        assert_eq!(s1.to_vec(), s2.to_vec(), "deterministic signatures must be identical");
        assert!(pk.verify(b"m", &s1, ctx));
        let vk = VerifyingKey::<Shake128s>::try_from(pk.into_bytes().as_slice()).unwrap();
        assert!(vk.try_verify_with_context(b"m", ctx, &s2).is_ok());
    }
}
