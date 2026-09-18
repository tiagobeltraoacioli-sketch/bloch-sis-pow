//! Official NIST ACVP sample sigVer fixtures, not ACVP certification or keygen KATs.
//! See vectors/ACVP-MLDSA-PROVENANCE.md for exact source and scope.
use pqcrypto_mldsa::mldsa65;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};
use serde_json::Value;
use sha2::{Digest, Sha256};

const FIXTURE: &[u8] = include_bytes!("vectors/acvp-mldsa65-sigver.json");

fn cases() -> Vec<Value> {
    assert_eq!(hex::encode(Sha256::digest(FIXTURE)),
        "852fbdc10ebb41858ac3fa04d7cebda1240752ccb58ce24c6b1fe0db5a2dd7c1");
    let fixture: Value = serde_json::from_slice(FIXTURE).unwrap();
    assert_eq!(fixture["parameterSet"], "ML-DSA-65");
    assert_eq!(fixture["signatureInterface"], "external");
    assert_eq!(fixture["preHash"], "pure");
    fixture["tests"].as_array().unwrap().clone()
}

fn bytes(case: &Value, field: &str) -> Vec<u8> {
    hex::decode(case[field].as_str().unwrap()).unwrap()
}

#[test]
fn official_acvp_external_pure_context_verification_matches_all_group3_results() {
    let cases = cases();
    assert_eq!(cases.len(), 15);
    assert_eq!(cases.iter().filter(|case| case["testPassed"] == true).count(), 3);
    for case in cases {
        let public_key = mldsa65::PublicKey::from_bytes(&bytes(&case, "pk")).unwrap();
        let signature = mldsa65::DetachedSignature::from_bytes(&bytes(&case, "signature")).unwrap();
        let actual = mldsa65::verify_detached_signature_ctx(
            &signature, &bytes(&case, "message"), &bytes(&case, "context"), &public_key).is_ok();
        assert_eq!(actual, case["testPassed"].as_bool().unwrap(), "NIST ACVP tcId {}", case["tcId"]);
    }
}

#[test]
fn production_empty_context_wrapper_rejects_context_bound_positives_and_official_negative() {
    let selected: Vec<_> = cases().into_iter().filter(|case|
        case["testPassed"] == true || case["tcId"] == 39).collect();
    assert_eq!(selected.len(), 4);
    for case in selected {
        if case["testPassed"] == true { assert!(!bytes(&case, "context").is_empty()); }
        else { assert!(bytes(&case, "context").is_empty()); }
        assert!(!bloch_crypto::crypto::verify_mldsa65_raw(
            &bytes(&case, "pk"), &bytes(&case, "message"), &bytes(&case, "signature")),
            "empty-context wrapper must reject tcId {}", case["tcId"]);
    }
}
