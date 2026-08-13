use crate::stratum_v2::Sv2StaticKeypair;
use tempfile::TempDir;

#[test]
fn keypair_round_trip_through_disk() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("sv2_key.json");

    let kp1 = Sv2StaticKeypair::load_or_generate(&path).expect("first load");
    let fp1 = kp1.fingerprint_hex();
    assert!(path.exists());

    let kp2 = Sv2StaticKeypair::load_or_generate(&path).expect("second load");
    let fp2 = kp2.fingerprint_hex();

    assert_eq!(fp1, fp2, "loaded keypair must have same fingerprint");
    assert_eq!(kp1.public.serialize(), kp2.public.serialize());
}

#[test]
fn keypair_fingerprint_stable() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("sv2_key.json");
    let kp = Sv2StaticKeypair::load_or_generate(&path).expect("generate");

    assert_eq!(kp.fingerprint_hex(), kp.fingerprint_hex());
    assert_eq!(kp.fingerprint_hex().len(), 16);
}

#[test]
fn keypair_rejects_corrupt_file() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("sv2_key.json");
    std::fs::write(&path, b"not valid json").expect("write junk");

    let result = Sv2StaticKeypair::load_or_generate(&path);
    assert!(result.is_err());
}
