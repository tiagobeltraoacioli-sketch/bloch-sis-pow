//! The diagnostic command must never invoke Store::open or repair bytes.
use std::fs;
use std::process::Command;

#[test]
fn offline_diagnostic_reports_corruption_without_mutating_log_or_creating_store_files() {
    let directory = std::env::temp_dir().join(format!("bloch-log-inspect-cli-{}", std::process::id()));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir_all(&directory).unwrap();
    let log = directory.join("blocks.log");
    fs::write(&log, []).unwrap();
    let invoke = || Command::new(env!("CARGO_BIN_EXE_bloch-pos"))
        .arg("block-log-inspect").arg("--data-dir").arg(&directory).output().unwrap();
    let clean = invoke();
    assert!(clean.status.success(), "{}", String::from_utf8_lossy(&clean.stderr));
    assert!(String::from_utf8_lossy(&clean.stdout).contains("decoded_frames=0"));
    fs::write(&log, [0, 0, 0, 0]).unwrap();
    let damaged = invoke();
    assert_eq!(damaged.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&damaged.stderr).contains("invalid envelope"));
    assert_eq!(fs::read(&log).unwrap(), [0, 0, 0, 0]);
    assert_eq!(fs::read_dir(&directory).unwrap().count(), 1);
    let invalid = Command::new(env!("CARGO_BIN_EXE_bloch-pos"))
        .arg("block-log-inspect").arg("--repair").arg(&directory).output().unwrap();
    assert_eq!(invalid.status.code(), Some(2));
    assert_eq!(fs::read(&log).unwrap(), [0, 0, 0, 0]);
    fs::remove_dir_all(directory).unwrap();
}
