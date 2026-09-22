//! The diagnostic command must never invoke Store::open or repair bytes.
use std::fs;
use std::process::Command;

#[test]
fn help_prints_the_tail_repair_invocation_without_patch_artifacts() {
    let output = Command::new(env!("CARGO_BIN_EXE_bloch-pos"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("block-log-repair-tail --data-dir <stopped-node>"));
    assert!(help.contains("--truncate-to <inspected-offset> --backup <new-file>"));
    assert!(!help.contains("\n+               --truncate-to"));
}

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

#[test]
fn offline_repair_requires_the_inspected_offset_and_preserves_the_removed_tail() {
    let directory = std::env::temp_dir().join(format!(
        "bloch-log-repair-cli-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir_all(&directory).unwrap();
    let log = directory.join("blocks.log");
    let backup = directory.join("removed-tail.bin");
    let damaged = [0u8; 12];
    fs::write(&log, damaged).unwrap();

    let wrong = Command::new(env!("CARGO_BIN_EXE_bloch-pos"))
        .arg("block-log-repair-tail")
        .arg("--data-dir")
        .arg(&directory)
        .arg("--truncate-to")
        .arg("1")
        .arg("--backup")
        .arg(&backup)
        .output()
        .unwrap();
    assert_eq!(wrong.status.code(), Some(2));
    assert_eq!(fs::read(&log).unwrap(), damaged);
    assert!(!backup.exists());

    let repaired = Command::new(env!("CARGO_BIN_EXE_bloch-pos"))
        .arg("block-log-repair-tail")
        .arg("--data-dir")
        .arg(&directory)
        .arg("--truncate-to")
        .arg("0")
        .arg("--backup")
        .arg(&backup)
        .output()
        .unwrap();
    assert!(
        repaired.status.success(),
        "{}",
        String::from_utf8_lossy(&repaired.stderr)
    );
    assert!(fs::read(&log).unwrap().is_empty());
    assert_eq!(fs::read(&backup).unwrap(), damaged);
    fs::remove_dir_all(directory).unwrap();
}
