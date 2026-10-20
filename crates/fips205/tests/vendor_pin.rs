//! Recompute SHA-256 over every vendored fips205 0.4.1 file and compare it
//! with the pins in `VENDOR.toml` (same tripwire as
//! crates/pqcrypto-internals/tests/vendor_pin.rs).
//!
//! Fails on: a changed byte in any pinned file, a pinned file that vanished,
//! and a new file under `src/` that nobody pinned. The algorithm code behind
//! signature suite 0x0003 therefore cannot drift without a deliberate re-pin.

use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Top-level upstream files that are pinned besides everything under `src/`.
const PINNED_TOP_LEVEL: &[&str] =
    &["CHANGELOG.md", "LICENSE-APACHE", "LICENSE-MIT", "README.md", "SECURITY.md"];

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("reading {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("readable dir entry").path();
        if path.is_dir() {
            walk(root, &path, out);
        } else {
            let rel = path.strip_prefix(root).expect("path under crate root");
            out.push(rel.to_string_lossy().replace('\\', "/"));
        }
    }
}

fn expected_files() -> BTreeSet<String> {
    let root = manifest_dir();
    let mut out = Vec::new();
    walk(&root, &root.join("src"), &mut out);
    out.extend(PINNED_TOP_LEVEL.iter().map(|s| (*s).to_string()));
    out.into_iter().collect()
}

fn sha256_hex(path: &Path) -> String {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    Sha256::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(serde::Deserialize)]
struct VendorManifest {
    meta: Meta,
    file: Vec<PinnedFile>,
}

#[derive(serde::Deserialize)]
struct Meta {
    upstream_crate: String,
    upstream_version: String,
    upstream_crate_sha256: String,
}

#[derive(serde::Deserialize)]
struct PinnedFile {
    path: String,
    sha256: String,
}

fn load_manifest() -> VendorManifest {
    let path = manifest_dir().join("VENDOR.toml");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    toml::from_str(&text).expect("VENDOR.toml must parse")
}

#[test]
fn vendored_fips205_sources_match_vendor_toml_pins() {
    let manifest = load_manifest();
    assert_eq!(manifest.meta.upstream_crate, "fips205");
    assert_eq!(manifest.meta.upstream_version, env!("CARGO_PKG_VERSION"));
    assert_eq!(
        manifest.meta.upstream_crate_sha256,
        "2f5626bf5534df4ebdbd2536465d7eaa8a9dc2cdeb7e036e0ecf291dcc80ffb6"
    );
    let root = manifest_dir();
    let mut bad = Vec::new();
    for pinned in &manifest.file {
        let full = root.join(&pinned.path);
        if !full.is_file() {
            bad.push(format!("{}: pinned but missing", pinned.path));
        } else if sha256_hex(&full) != pinned.sha256 {
            bad.push(format!("{}: hash mismatch", pinned.path));
        }
    }
    assert!(bad.is_empty(), "vendored fips205 drifted from VENDOR.toml:\n{}", bad.join("\n"));
}

#[test]
fn vendor_toml_file_list_matches_disk_exactly() {
    let manifest = load_manifest();
    let pinned: BTreeSet<String> = manifest.file.iter().map(|f| f.path.clone()).collect();
    let on_disk = expected_files();
    let unpinned: Vec<_> = on_disk.difference(&pinned).collect();
    let missing: Vec<_> = pinned.difference(&on_disk).collect();
    assert!(unpinned.is_empty(), "files with no VENDOR.toml pin: {unpinned:?}");
    assert!(missing.is_empty(), "VENDOR.toml pins files that do not exist: {missing:?}");
}
