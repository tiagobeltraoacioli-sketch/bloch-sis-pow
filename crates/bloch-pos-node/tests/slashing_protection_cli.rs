// SPDX-License-Identifier: AGPL-3.0-or-later
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};
const BIN: &str = env!("CARGO_BIN_EXE_bloch-pos");
struct Temp(PathBuf);
impl Temp {
    fn new(name: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("bloch-signing-cli-{name}-{}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn run(
    dir: &Path,
    action: &str,
    option: &str,
    value: &str,
    identity: &str,
) -> std::process::Output {
    Command::new(BIN)
        .args([
            "slashing-protection",
            action,
            "--data-dir",
            dir.to_str().unwrap(),
            "--validator-pubkey-sha3",
            identity,
            "--genesis-digest",
            &"22".repeat(32),
            option,
            value,
        ])
        .output()
        .unwrap()
}
#[test]
fn recovery_cli_preserves_monotone_records_and_rejects_other_identities() {
    let root = Temp::new("monotone");
    let dir = root.0.join("node");
    let key = "11".repeat(32);
    let out = run(&dir, "set-floor", "--min-slot", "100", &key);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let backup = root.0.join("backup.bin");
    assert!(run(&dir, "export", "--out", backup.to_str().unwrap(), &key)
        .status
        .success());
    assert!(
        !run(&dir, "export", "--out", backup.to_str().unwrap(), &key)
            .status
            .success()
    );
    assert!(run(&dir, "set-floor", "--min-slot", "200", &key)
        .status
        .success());
    let record = dir.join("slashing_protection.bin");
    let before = fs::read(&record).unwrap();
    assert!(run(&dir, "import", "--in", backup.to_str().unwrap(), &key)
        .status
        .success());
    assert_eq!(fs::read(&record).unwrap(), before);
    assert!(!run(
        &dir,
        "import",
        "--in",
        backup.to_str().unwrap(),
        &"33".repeat(32)
    )
    .status
    .success());
    assert_eq!(fs::read(&record).unwrap(), before);
    let mut damaged = fs::read(&backup).unwrap();
    damaged.push(0);
    fs::write(&backup, damaged).unwrap();
    assert!(!run(&dir, "import", "--in", backup.to_str().unwrap(), &key)
        .status
        .success());
    assert_eq!(fs::read(&record).unwrap(), before);
}
#[test]
fn recovery_cli_refuses_invalid_floor_before_creating_state() {
    let root = Temp::new("invalid");
    let dir = root.0.join("node");
    assert!(!run(&dir, "set-floor", "--min-slot", "0", &"11".repeat(32))
        .status
        .success());
    assert!(!dir.exists());
    assert!(!run(
        &dir,
        "set-floor",
        "--min-slot",
        "18446744073709551615",
        &"11".repeat(32)
    )
    .status
    .success());
    assert!(!dir.exists());
}

#[test]
fn migration_export_merges_the_anchor_and_retire_blocks_the_old_host() {
    let root = Temp::new("retire");
    let dir = root.0.join("node");
    let anchors = root.0.join("anchors");
    let key = "11".repeat(32);
    let digest = "22".repeat(32);
    let cli = |args: &[&str]| {
        Command::new(BIN)
            .env("BLOCH_SIGNER_ANCHOR_DIR", &anchors)
            .args(["slashing-protection"])
            .args(args)
            .args(["--data-dir", dir.to_str().unwrap(), "--validator-pubkey-sha3", &key, "--genesis-digest", &digest])
            .output()
            .unwrap()
    };
    assert!(cli(&["set-floor", "--min-slot", "100"]).status.success());
    // The anchor is ahead of the data dir (as after a restored backup).
    let anchor_dir = anchors.join(format!("{key}-{digest}"));
    fs::create_dir_all(&anchor_dir).unwrap();
    let ahead = root.0.join("ahead");
    assert!(Command::new(BIN)
        .args(["slashing-protection", "set-floor", "--min-slot", "500", "--data-dir", ahead.to_str().unwrap(),
            "--validator-pubkey-sha3", &key, "--genesis-digest", &digest, "--signer-anchor-dir", root.0.join("unused").to_str().unwrap()])
        .status().unwrap().success());
    fs::copy(ahead.join("slashing_protection.bin"), anchor_dir.join("signing_record.bin")).unwrap();
    let out_file = root.0.join("export.bin");
    let out = cli(&["export", "--out", out_file.to_str().unwrap()]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(fs::read(&out_file).unwrap(), fs::read(ahead.join("slashing_protection.bin")).unwrap(),
        "export must carry the higher anchor record");
    let out = cli(&["retire", "--note", "moved to host-b"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(dir.join("SIGNER-RETIRED").exists());
    assert!(anchor_dir.join("SIGNER-RETIRED").exists());
}
