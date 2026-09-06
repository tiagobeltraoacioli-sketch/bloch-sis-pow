//! G3: recompute SHA-256 over every vendored PQClean C file (`cfiles/`,
//! `include/`) and compare against the pins recorded in `VENDOR.toml`.
//!
//! This is a tripwire, not a provenance guarantee (see VENDOR.toml's header):
//! it catches an accidental or malicious edit to the vendored C between
//! commits, and catches VENDOR.toml itself drifting out of sync with the
//! files it claims to describe (missing pin, stale hash, or an untracked
//! file appearing under `cfiles/`/`include/`).

use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Walk `cfiles/` and `include/` under the crate root, returning every file
/// path relative to the crate root (forward-slash separated, matching how
/// VENDOR.toml records them), sorted for a deterministic comparison.
fn list_vendored_files() -> Vec<String> {
    let root = manifest_dir();
    let mut out = Vec::new();
    for top in ["cfiles", "include"] {
        walk(&root, &root.join(top), &mut out);
    }
    out.sort();
    out
}

fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return; };
    for entry in entries {
        let entry = entry.expect("readable dir entry");
        let path = entry.path();
        if path.is_dir() {
            walk(root, &path, out);
        } else {
            let rel = path.strip_prefix(root).expect("path under crate root");
            out.push(rel.to_string_lossy().replace('\\', "/"));
        }
    }
}

fn sha256_hex(path: &Path) -> String {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("reading {}: {}", path.display(), e));
    let digest = Sha256::digest(&bytes);
    hex_encode(&digest)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

#[derive(serde::Deserialize)]
struct VendorManifest {
    file: Vec<PinnedFile>,
}

#[derive(serde::Deserialize)]
struct PinnedFile {
    path: String,
    sha256: String,
}

fn load_manifest() -> VendorManifest {
    let path = manifest_dir().join("VENDOR.toml");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading {}: {}", path.display(), e));
    toml::from_str(&text).expect("VENDOR.toml must parse as valid TOML")
}

/// The hash-pin itself: every recorded file's LIVE hash must match the pin.
#[test]
fn vendored_c_sources_match_vendor_toml_pins() {
    let manifest = load_manifest();
    assert!(!manifest.file.is_empty(), "VENDOR.toml must pin at least one file");

    let root = manifest_dir();
    let mut mismatches = Vec::new();
    for pinned in &manifest.file {
        let full = root.join(&pinned.path);
        if !full.is_file() {
            mismatches.push(format!("{}: pinned in VENDOR.toml but missing on disk", pinned.path));
            continue;
        }
        let actual = sha256_hex(&full);
        if actual != pinned.sha256 {
            mismatches.push(format!(
                "{}: hash mismatch (pinned {}, actual {})",
                pinned.path, pinned.sha256, actual
            ));
        }
    }

    assert!(
        mismatches.is_empty(),
        "vendored C source(s) drifted from VENDOR.toml:\n{}",
        mismatches.join("\n")
    );
}

/// The file LIST must also match exactly — a new file dropped into
/// `cfiles/`/`include/` without a pin, or a pinned file that no longer
/// exists, must fail loudly instead of silently going unverified.
#[test]
fn vendor_toml_file_list_matches_disk_exactly() {
    let manifest = load_manifest();
    let pinned: BTreeSet<String> = manifest.file.iter().map(|f| f.path.clone()).collect();
    let on_disk: BTreeSet<String> = list_vendored_files().into_iter().collect();

    let unpinned: Vec<&String> = on_disk.difference(&pinned).collect();
    let missing: Vec<&String> = pinned.difference(&on_disk).collect();

    assert!(unpinned.is_empty(), "file(s) under cfiles//include/ with NO VENDOR.toml pin: {:?}", unpinned);
    assert!(missing.is_empty(), "VENDOR.toml pins file(s) that no longer exist: {:?}", missing);
}
