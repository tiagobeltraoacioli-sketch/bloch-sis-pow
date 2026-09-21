// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fail-closed identity for externally selected native input trees.

use sha3::{Digest, Sha3_256};
use std::path::{Path, PathBuf};

fn collect(root: &Path, dir: &Path, files: &mut Vec<(String, PathBuf)>) -> Option<()> {
    println!("cargo:rerun-if-changed={}", dir.display());
    for entry in std::fs::read_dir(dir).ok()? {
        let entry = entry.ok()?;
        let path = entry.path();
        let file_type = entry.file_type().ok()?;
        if file_type.is_symlink() {
            return None;
        }
        if file_type.is_dir() {
            collect(root, &path, files)?;
        } else if file_type.is_file() {
            let relative = path.strip_prefix(root).ok()?.to_str()?.replace('\\', "/");
            files.push((relative, path));
        } else {
            return None;
        }
    }
    Some(())
}

/// Hash every regular file in a selected include tree. Directory watches catch
/// additions/removals while file watches catch in-place replacement.
pub(crate) fn native_input_tree_digest(root: &Path) -> Option<(String, usize, u64)> {
    if !std::fs::symlink_metadata(root).ok()?.is_dir() {
        return None;
    }
    let mut files = Vec::new();
    collect(root, root, &mut files)?;
    files.sort();
    files.dedup();

    let mut hasher = Sha3_256::new();
    hasher.update(b"bloch-pos/native-input-tree/v1\0");
    let mut bytes = 0u64;
    for (relative, path) in &files {
        let body = std::fs::read(path).ok()?;
        bytes = bytes.checked_add(body.len() as u64)?;
        hasher.update((relative.len() as u64).to_le_bytes());
        hasher.update(relative.as_bytes());
        hasher.update((body.len() as u64).to_le_bytes());
        hasher.update(body);
        println!("cargo:rerun-if-changed={}", path.display());
    }
    let digest = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Some((digest, files.len(), bytes))
}

fn native_inputs_for_target_os(target_os: &str) -> &'static [&'static str] {
    if target_os == "wasi" {
        &["WASI_SDK_DIR"]
    } else {
        &["DEP_WASM32_UNKNOWN_UNKNOWN_OPENBSD_LIBC_INCLUDE"]
    }
}

/// The checked-in PQ build selects either a WASI sysroot or the freestanding
/// libc include tree. Their selector values are already bound; bind the bytes
/// that the target-specific branch can consume as well.
#[cfg(not(test))]
pub(crate) fn required_native_input_digests(target_os: &str) -> Vec<(String, String)> {
    let mut digests = Vec::new();
    for key in native_inputs_for_target_os(target_os) {
        let Some(path) = std::env::var_os(key) else {
            continue;
        };
        let root = PathBuf::from(path);
        let (digest, _, _) = native_input_tree_digest(&root).unwrap_or_else(|| {
            panic!("native input tree selected by {key} is incomplete or unsafe")
        });
        digests.push(((*key).to_owned(), digest));
    }
    digests
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    fn fixture() -> PathBuf {
        let root = loop {
            let nonce = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let candidate = std::env::temp_dir()
                .join(format!("bloch-native-input-{}-{nonce}", std::process::id()));
            match fs::create_dir(&candidate) {
                Ok(()) => break candidate,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create fixture root: {error}"),
            }
        };
        fs::create_dir(root.join("sys")).expect("fixture dirs");
        fs::write(root.join("stddef.h"), b"typedef unsigned long size_t;\n").expect("header");
        fs::write(root.join("sys/types.h"), b"typedef long ssize_t;\n").expect("nested header");
        root
    }

    #[test]
    fn content_and_inventory_changes_change_native_identity() {
        let root = fixture();
        let initial = native_input_tree_digest(&root).expect("initial tree");
        assert_eq!(initial.1, 2);

        fs::write(root.join("stddef.h"), b"typedef unsigned int size_t;\n").expect("mutate");
        let mutated = native_input_tree_digest(&root).expect("mutated tree");
        assert_ne!(initial.0, mutated.0);

        fs::write(root.join("stdint.h"), b"typedef signed int int32_t;\n").expect("new header");
        let extended = native_input_tree_digest(&root).expect("extended tree");
        assert_ne!(mutated.0, extended.0);
        assert_eq!(extended.1, 3);
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn target_selects_only_the_native_tree_its_build_branch_consumes() {
        assert_eq!(native_inputs_for_target_os("wasi"), &["WASI_SDK_DIR"]);
        assert_eq!(
            native_inputs_for_target_os("linux"),
            &["DEP_WASM32_UNKNOWN_UNKNOWN_OPENBSD_LIBC_INCLUDE"],
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_invalidates_native_input_identity() {
        use std::os::unix::fs::symlink;

        let root = fixture();
        symlink(root.join("stddef.h"), root.join("alias.h")).expect("symlink fixture");
        assert!(native_input_tree_digest(&root).is_none());
        fs::remove_dir_all(root).expect("remove fixture");
    }
}
