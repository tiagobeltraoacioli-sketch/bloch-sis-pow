// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fail-closed source-tree inventory shared by the build script and tests.

use sha3::{Digest, Sha3_256};
use std::path::{Path, PathBuf};

/// Extensions that are build inputs for this binary.
const SOURCE_EXT: &[&str] = &["rs", "toml", "c", "h", "S", "s", "macros"];

/// Collect the hashed set, workspace-relative, sorted and deduplicated.
///
/// A partial traversal is not a source identity. Directory-entry, metadata,
/// path-encoding and symlink surprises therefore invalidate the whole digest
/// instead of silently shrinking its declared scope.
fn collect(root: &Path, dir: &Path, out: &mut Vec<(String, PathBuf)>) -> Option<()> {
    let entries = std::fs::read_dir(dir).ok()?;
    for entry in entries {
        let entry = entry.ok()?;
        let path = entry.path();
        let name = path.file_name()?.to_str()?;

        // Build outputs and VCS metadata are not source. `target/` in
        // particular is enormous and changes on every build.
        if name == ".git" || name == "target" {
            continue;
        }

        let file_type = entry.file_type().ok()?;
        if file_type.is_symlink() {
            return None;
        }
        if file_type.is_dir() {
            collect(root, &path, out)?;
        } else if file_type.is_file() {
            let extension = path
                .extension()
                .and_then(|value| value.to_str())
                .unwrap_or("");
            if SOURCE_EXT.contains(&extension) {
                let relative = path.strip_prefix(root).ok()?.to_str()?.replace('\\', "/");
                out.push((relative, path));
            }
        }
    }
    Some(())
}

/// Hash the tree. Returns `(hex digest, file count, total bytes)`.
pub(crate) fn source_digest(root: &Path) -> Option<(String, usize, u64)> {
    let mut files = Vec::new();
    collect(root, &root.join("crates"), &mut files)?;
    for extra in ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml"] {
        let path = root.join(extra);
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() => return None,
            Ok(metadata) if metadata.is_file() => files.push((extra.to_owned(), path)),
            Ok(_) => return None,
            Err(_) => return None,
        }
    }
    if files.is_empty() {
        return None;
    }
    files.sort();
    files.dedup();

    let mut hasher = Sha3_256::new();
    hasher.update(b"bloch-pos/source-digest/v1\0");
    let mut bytes_total = 0u64;
    for (relative, path) in &files {
        let body = std::fs::read(path).ok()?;
        bytes_total = bytes_total.saturating_add(body.len() as u64);
        hasher.update(relative.as_bytes());
        hasher.update([0u8]);
        hasher.update((body.len() as u64).to_le_bytes());
        hasher.update(&body);
        println!("cargo:rerun-if-changed={}", path.display());
    }
    let digest = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Some((digest, files.len(), bytes_total))
}

/// A detected workspace promises a complete source identity. Refuse its build
/// rather than producing a runnable binary whose identity is `unavailable`.
pub(crate) fn required_source_digest(root: &Path) -> (String, usize, u64) {
    source_digest(root).unwrap_or_else(|| {
        panic!("detected workspace source inventory is incomplete; refusing an unidentified build")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn fixture() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "bloch-source-digest-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(root.join("crates/.hidden")).expect("fixture dirs");
        fs::write(root.join("Cargo.toml"), b"[workspace]\n").expect("workspace manifest");
        fs::write(root.join("Cargo.lock"), b"version = 4\n").expect("lockfile");
        fs::write(
            root.join("rust-toolchain.toml"),
            b"[toolchain]\nchannel = \"stable\"\n",
        )
        .expect("toolchain file");
        fs::write(root.join("crates/.hidden/input.macros"), b"macro input\n")
            .expect("hidden source");
        root
    }

    #[test]
    fn hidden_macro_input_is_hashed() {
        let root = fixture();
        let before = source_digest(&root).expect("complete digest");
        assert_eq!(before.1, 4);
        fs::write(
            root.join("crates/.hidden/input.macros"),
            b"changed macro input\n",
        )
        .expect("mutate source");
        let after = source_digest(&root).expect("changed digest");
        assert_ne!(before.0, after.0);
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[cfg(unix)]
    #[test]
    fn source_symlink_invalidates_digest() {
        use std::os::unix::fs::symlink;

        let root = fixture();
        fs::write(root.join("outside.rs"), b"pub fn outside() {}\n").expect("target");
        symlink(root.join("outside.rs"), root.join("crates/linked.rs")).expect("symlink");
        assert!(source_digest(&root).is_none());
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn missing_required_workspace_input_invalidates_digest() {
        let root = fixture();
        fs::remove_file(root.join("rust-toolchain.toml")).expect("remove required input");
        assert!(source_digest(&root).is_none());
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[cfg(unix)]
    #[test]
    fn detected_workspace_refuses_to_build_from_an_incomplete_inventory() {
        use std::os::unix::fs::symlink;

        let root = fixture();
        fs::write(root.join("outside.rs"), b"pub fn outside() {}\n").expect("target");
        symlink(root.join("outside.rs"), root.join("crates/linked.rs")).expect("symlink");
        let refusal = std::panic::catch_unwind(|| required_source_digest(&root));
        assert!(refusal.is_err(), "an incomplete detected workspace must stop the build");
        fs::remove_dir_all(root).expect("remove fixture");
    }

    // Darwin filesystems may reject the fixture name before our inventory can
    // observe it. Linux accepts the raw byte name used by release builders.
    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn non_utf8_source_name_invalidates_digest() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let root = fixture();
        let mut name = b"source-".to_vec();
        name.push(0xff);
        name.extend_from_slice(b".rs");
        fs::write(
            root.join("crates").join(OsString::from_vec(name)),
            b"pub fn input() {}\n",
        )
        .expect("non-UTF-8 source");
        assert!(source_digest(&root).is_none());
        fs::remove_dir_all(root).expect("remove fixture");
    }
}
