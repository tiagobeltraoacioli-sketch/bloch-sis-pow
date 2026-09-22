// SPDX-License-Identifier: AGPL-3.0-or-later
//! Real CLI PTYs: no production keys and no keystore writes.
#[cfg(unix)]
#[test]
fn native_passphrase_restores_terminal_and_preserves_signal_semantics() {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/test-native-passphrase-tty.py");
    let output = std::process::Command::new("python3")
        .arg(script)
        .arg(env!("CARGO_BIN_EXE_bloch-pos"))
        .output()
        .expect("run the Python PTY regression harness");
    assert!(output.status.success(), "{}\n{}",
        String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
}
