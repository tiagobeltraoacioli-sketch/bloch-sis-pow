//! FIPS 205 known-answer tests: every NIST ACVP-Server SLH-DSA-SHAKE-128s
//! keyGen, sigGen and sigVer case for the pure external interface (the mode
//! suite 0x0003 uses) and the internal interface, run against the exact
//! vendored `fips205` build bloch-crypto links (crates/fips205). Expected
//! answers come from NIST, never from this implementation. Provenance:
//! vectors/ACVP-SLHDSA-PROVENANCE.md.
#![allow(deprecated)] // fips205 marks its internal-interface ACVP hooks deprecated.

use fips205::slh_dsa_shake_128s as p;
use fips205::traits::{KeyGen, SerDes, Signer, Verifier};
use serde_json::Value;
use sha2::{Digest, Sha256};

const FIXTURE: &[u8] = include_bytes!("vectors/acvp-slhdsa-shake128s.json");
const FIXTURE_SHA256: &str = "a0603e6c9bf79cdb210bd781ff335363cc0e2d1e7a1745baa790b74750f27531";

fn fixture() -> Value {
    assert_eq!(hex::encode(Sha256::digest(FIXTURE)), FIXTURE_SHA256, "fixture bytes changed");
    let v: Value = serde_json::from_slice(FIXTURE).unwrap();
    assert_eq!(v["source"]["commit"], "975de31eb83d87039ec88934fdc47d8c312b892d");
    v
}

fn b(v: &Value, f: &str) -> Vec<u8> { hex::decode(v[f].as_str().unwrap()).unwrap() }
fn cases<'a>(f: &'a Value, kind: &str) -> &'a Vec<Value> { f[kind].as_array().unwrap() }
fn external(t: &Value) -> bool {
    match t["signatureInterface"].as_str().unwrap() {
        "external" => true,
        "internal" => false,
        other => panic!("unexpected interface {other}"),
    }
}

/// rand_core 0.6 RNG returning one fixed opt_rand (ACVP additionalRandomness).
struct Fixed(Vec<u8>);
impl rand_core::RngCore for Fixed {
    fn next_u32(&mut self) -> u32 { unimplemented!() }
    fn next_u64(&mut self) -> u64 { unimplemented!() }
    fn fill_bytes(&mut self, d: &mut [u8]) { d.copy_from_slice(&self.0) }
    fn try_fill_bytes(&mut self, d: &mut [u8]) -> Result<(), rand_core::Error> { self.fill_bytes(d); Ok(()) }
}
impl rand_core::CryptoRng for Fixed {}

#[test]
fn acvp_slh_dsa_shake_128s_keygen() {
    let f = fixture();
    let kg = cases(&f, "keyGen");
    assert_eq!(kg.len(), 10);
    for t in kg {
        let s = |k| <[u8; p::N]>::try_from(b(t, k)).unwrap();
        let (pk, sk) = p::KG::keygen_with_seeds(&s("skSeed"), &s("skPrf"), &s("pkSeed"));
        assert_eq!(pk.into_bytes().to_vec(), b(t, "pk"), "keyGen tcId {}", t["tcId"]);
        assert_eq!(sk.into_bytes().to_vec(), b(t, "sk"), "keyGen tcId {}", t["tcId"]);
    }
}

#[test]
fn acvp_slh_dsa_shake_128s_siggen() {
    let f = fixture();
    let sg = cases(&f, "sigGen");
    assert_eq!(sg.len(), 28);
    let (mut ext, mut det) = (0, 0);
    for t in sg {
        let sk = p::PrivateKey::try_from_bytes(&b(t, "sk").try_into().unwrap()).unwrap();
        assert_eq!(sk.get_public_key().into_bytes().to_vec(), b(t, "pk"), "tcId {}", t["tcId"]);
        let deterministic = t["deterministic"].as_bool().unwrap();
        let mut rng = Fixed(if deterministic { Vec::new() } else { b(t, "additionalRandomness") });
        let sig = if external(t) {
            ext += 1;
            sk.try_sign_with_rng(&mut rng, &b(t, "message"), &b(t, "context"), !deterministic).unwrap()
        } else {
            sk._test_only_raw_sign(&mut rng, &b(t, "message"), !deterministic).unwrap()
        };
        det += usize::from(deterministic);
        assert_eq!(sig.to_vec(), b(t, "signature"), "sigGen tcId {}", t["tcId"]);
    }
    assert_eq!((ext, det), (14, 14), "external/pure and internal, deterministic and hedged");
}

#[test]
fn acvp_slh_dsa_shake_128s_sigver() {
    let f = fixture();
    let sv = cases(&f, "sigVer");
    assert_eq!(sv.len(), 28);
    let mut passed = 0;
    for t in sv {
        let pk = p::PublicKey::try_from_bytes(&b(t, "pk").try_into().unwrap()).unwrap();
        let sig = b(t, "signature");
        // Wrong-length signatures cannot be represented ⇒ rejected, exactly as
        // the suite-0x0003 body verifier does by its fixed-length split.
        let got = <[u8; p::SIG_LEN]>::try_from(sig.as_slice())
            .map(|s| {
                if external(t) {
                    pk.verify(&b(t, "message"), &s, &b(t, "context"))
                } else {
                    pk._test_only_raw_verify(&b(t, "message"), &s).unwrap()
                }
            })
            .unwrap_or(false);
        let want = t["testPassed"].as_bool().unwrap();
        passed += usize::from(want);
        assert_eq!(got, want, "sigVer tcId {} ({})", t["tcId"], t["reason"]);
    }
    assert_eq!(passed, 4, "2 valid + 12 negative cases per interface");
}

/// The suite-0x0003 SLH-DSA half is a plain FIPS 205 pure signature under the
/// suite context: the ACVP-validated primitive verifies it, and refuses it
/// under any other context.
#[test]
fn suite_0x0003_slh_half_interoperates_with_the_acvp_verified_primitive() {
    use bloch_crypto::crypto::slhdsa_suite::{generate_keypair_from_seed, SLHDSA_SUITE_CONTEXT, SLHDSA128S_SIG_LEN};
    let (pk, sk) = generate_keypair_from_seed(&[7u8; 32]).unwrap();
    let msg = b"interop";
    let sig = bloch_crypto::crypto::sign(&sk, msg).unwrap();
    let spk = p::PublicKey::try_from_bytes(&pk[4..36].try_into().unwrap()).unwrap();
    let ssig: [u8; p::SIG_LEN] = sig[4..4 + SLHDSA128S_SIG_LEN].try_into().unwrap();
    assert!(spk.verify(msg, &ssig, SLHDSA_SUITE_CONTEXT));
    assert!(!spk.verify(msg, &ssig, b""));
    assert!(!spk.verify(msg, &ssig, b"BLOCH/SUITE/0x0003/SLH-DSA-SHAKE-128s+Falcon-1024/v2"));
}
