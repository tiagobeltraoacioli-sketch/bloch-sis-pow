//! Public fixture rows only: invalid new manifests must never be published.
use std::fs;
use std::process::Command;

#[test]
fn duplicate_validator_indices_and_public_keys_refuse_before_writing_manifest() {
    let directory = std::env::temp_dir().join(format!("bloch-new-genesis-identity-{}", std::process::id()));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir_all(&directory).unwrap();
    let cohort = directory.join("cohort.tsv");
    let output = directory.join("manifest.bin");
    let key = |byte: &str| format!("b10c0100{}", byte.repeat(1952 + 1793));
    let row = |index, public: String| format!("{index}\t{public}\t{}\t2500000000000\t{}\t0\n", "00".repeat(32), "00".repeat(32));
    for (second_index, second_key, message) in [
        (0, key("22"), "duplicate genesis validator index"),
        (1, key("11"), "duplicate genesis validator public key"),
    ] {
        fs::write(&cohort, format!("index\tpubkey\trandao\tstake\twithdrawal\tcommission\n{}{}", row(0, key("11")), row(second_index, second_key))).unwrap();
        let result = Command::new(env!("CARGO_BIN_EXE_bloch-pos"))
            .arg("genesis-mainnet").arg("--cohort").arg(&cohort).arg("--out").arg(&output).output().unwrap();
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains(message), "{}", String::from_utf8_lossy(&result.stderr));
        assert!(!output.exists());
    }
    fs::remove_dir_all(directory).unwrap();
}
