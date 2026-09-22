// SPDX-License-Identifier: AGPL-3.0-or-later

//! Identity for the native tools that cc-rs actually selects.

use sha3::{Digest, Sha3_256};
use std::path::Path;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Hash one selected executable without publishing its path.
pub(crate) fn tool_file_digest(path: &Path) -> Option<String> {
    let selected = if path.components().count() > 1 {
        path.to_path_buf()
    } else {
        let search = std::env::var_os("PATH")?;
        std::env::split_paths(&search)
            .map(|directory| directory.join(path))
            .find(|candidate| candidate.is_file())?
    };
    let body = std::fs::read(&selected).ok()?;
    println!("cargo:rerun-if-changed={}", selected.display());
    let mut hasher = Sha3_256::new();
    hasher.update(b"bloch-pos/build-tool-binary/v1\0");
    hasher.update((body.len() as u64).to_le_bytes());
    hasher.update(body);
    Some(hex(&hasher.finalize()))
}

/// Resolve the same default compiler family used by checked-in cc-rs native
/// builds, then bind the selected executable bytes. The PQ dependency needs a
/// working C compiler, so inability to identify this required input must stop
/// the node build rather than stamp a silently incomplete identity.
#[cfg(not(test))]
pub(crate) fn required_cc_compiler_digest(target: &str, host: &str) -> String {
    let compiler = cc::Build::new()
        .target(target)
        .host(host)
        .try_get_compiler()
        .unwrap_or_else(|error| panic!("cannot identify required cc-rs compiler: {error}"));
    tool_file_digest(compiler.path()).unwrap_or_else(|| {
        panic!(
            "cannot read required cc-rs compiler selected for the build: {}",
            compiler.path().display()
        )
    })
}

/// Resolve the archiver used to turn the checked-in PQ objects into static
/// libraries. cc-rs may select this tool without an explicit `AR`, just as it
/// may select the compiler without `CC`; both executables are build inputs.
#[cfg(not(test))]
pub(crate) fn required_cc_archiver_digest(target: &str, host: &str) -> String {
    let archiver = cc::Build::new()
        .target(target)
        .host(host)
        .try_get_archiver()
        .unwrap_or_else(|error| panic!("cannot identify required cc-rs archiver: {error}"));
    let program = Path::new(archiver.get_program());
    tool_file_digest(program).unwrap_or_else(|| {
        panic!(
            "cannot read required cc-rs archiver selected for the build: {}",
            program.display()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn selected_tool_identity_tracks_executable_bytes() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("bloch-native-tool-{}-{nonce}", std::process::id()));
        fs::write(&path, b"compiler-v1").expect("write fixture");
        let before = tool_file_digest(&path).expect("first digest");
        fs::write(&path, b"compiler-v2").expect("mutate fixture");
        let after = tool_file_digest(&path).expect("second digest");
        assert_ne!(before, after);
        fs::remove_file(path).expect("remove fixture");
    }

    #[test]
    fn missing_selected_tool_has_no_identity() {
        let path =
            std::env::temp_dir().join(format!("bloch-missing-native-tool-{}", std::process::id()));
        let _ = fs::remove_file(&path);
        assert!(tool_file_digest(&path).is_none());
    }
}
