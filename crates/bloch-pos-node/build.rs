// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Stamps the git commit into the `bloch-pos` binary.
//
// Ported from the Genesis-3 node's root build.rs (commits 0f1766d + 6ec7378 on
// `deploy/g3-terminal-height`), which exists because of a documented failure:
// the 2026-08-11 fleet survey found three boxes running three different
// binaries, all reporting `bloch 0.3.0-genesis2`, with no way to tell what any
// of them was built from. Separately, the published Genesis-3 release WAS a
// broken abandoned branch (f819e87f) while the fleet ran unpublished fixes,
// and nobody noticed until nodes froze at block 10802. A version string
// without a commit is not a version string.
//
// This makes "what is this binary?" answerable with `bloch-pos --version`,
// forever, and is the anchor of the G8 release-integrity gate
// (docs/specs/BLOCH-POS-SHA3-LATTICE-MIGRATION.md §11): the published binary,
// the fleet binary and the source commit are compared THROUGH this stamp plus
// a sha256 — see deploy/RELEASE-INTEGRITY.md.
//
// Reproducibility contract: the stamp is a build INPUT like any other. Two
// builds of the same commit produce the same stamp and (with the pinned
// toolchain + --locked + path remapping, see scripts/pos-release-integrity.sh)
// the same binary. Container/CI builds have no .git, so the caller passes
// BLOCH_BUILD_COMMIT explicitly; the env var wins over the repo because the
// caller knows what it is building, and a build script guessing from a partial
// checkout is how stamps go stale.

// ── The source-tree digest ──────────────────────────────────────────────────
//
// The commit stamp above answers "which commit was checked out". That is NOT
// the same question as "which tree was compiled", and the gap between them is
// exactly where this repo has been burned before: a caller can assert
// BLOCH_BUILD_COMMIT and the stamp will repeat it, dirty or not, because the
// build script is told not to second-guess a caller who says what it is
// building. That is the right call for CI. It also means the commit alone
// cannot stop an operator from editing one file, rebuilding, and reporting a
// clean tag id.
//
// So the build script also hashes the files it is about to hand rustc, and
// stamps THAT. The digest is computed from bytes on disk. No environment
// variable can move it, and no assertion by the caller is involved.
//
// SCOPE, stated exactly, because a digest whose scope is vague is a digest
// nobody can compare against: every `.rs`, `.toml`, `.c`, `.h`, `.S` and `.s`
// file under the workspace `crates/` directory, plus the workspace root
// `Cargo.toml` and `Cargo.lock`. That covers this binary's whole path-
// dependency graph (bloch-pos-committee, bloch-crypto, bloch-sis-pow,
// coherence-core, pqcrypto-internals) and then some; `Cargo.lock` binds the
// registry dependencies by version and by the registry's own checksums.
//
// Paths enter the hash workspace-RELATIVE and forward-slashed, so the digest
// is the same on every machine and carries nothing about the box that built
// it. Entries are sorted, and each is fed as path, NUL, an 8-byte length, then
// the bytes — length-prefixed so no rearrangement of files can produce the
// same stream.
//
// WHAT THIS DOES NOT PROVE, and the limit belongs next to the code rather than
// only in a report: it is evidence against drift and accident, not against a
// motivated liar. Anyone who can edit the source can also edit this file to
// print a digest it did not compute. It does not cover `legacy/`, `tools/`,
// `apps/`, `scripts/`, the rustc build itself, or the compiled artifact. And
// there is a window between the build script reading a file and rustc reading
// it; nothing here closes that. What it does close is the accident: an edit
// anywhere in the hashed set changes the digest, whatever the operator asserts
// about the commit.

use sha3::{Digest, Sha3_256};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Extensions that are build inputs for this binary.
const SOURCE_EXT: &[&str] = &["rs", "toml", "c", "h", "S", "s"];

/// Walk from the crate directory to the workspace root: the first ancestor
/// holding both `Cargo.lock` and a `crates/` directory. Returns `None` when
/// this crate is being built out of a vendored copy or as a git dependency,
/// in which case the digest is honestly reported as unavailable rather than
/// computed over whatever happens to be nearby.
fn workspace_root() -> Option<PathBuf> {
    let start = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").ok()?);
    let mut dir: &Path = &start;
    loop {
        if dir.join("Cargo.lock").is_file() && dir.join("crates").is_dir() {
            return Some(dir.to_path_buf());
        }
        dir = dir.parent()?;
    }
}

/// Collect the hashed set, workspace-relative, sorted, deduplicated.
fn collect(root: &Path, dir: &Path, out: &mut Vec<(String, PathBuf)>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for e in entries.flatten() {
        let path = e.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else { continue };
        // Build outputs and VCS metadata are not source. `target/` in
        // particular is enormous and changes on every build, which would make
        // the digest a random number.
        if name.starts_with('.') || name == "target" {
            continue;
        }
        let Ok(ft) = e.file_type() else { continue };
        if ft.is_dir() {
            collect(root, &path, out);
        } else if ft.is_file() {
            let ext = path.extension().and_then(|x| x.to_str()).unwrap_or("");
            if SOURCE_EXT.contains(&ext) {
                if let Ok(rel) = path.strip_prefix(root) {
                    let rel = rel.to_string_lossy().replace('\\', "/");
                    out.push((rel, path));
                }
            }
        }
    }
}

/// Hash the tree. Returns `(hex digest, file count, total bytes)`.
fn source_digest(root: &Path) -> Option<(String, usize, u64)> {
    let mut files = Vec::new();
    collect(root, &root.join("crates"), &mut files);
    for extra in ["Cargo.toml", "Cargo.lock"] {
        let p = root.join(extra);
        if p.is_file() {
            files.push((extra.to_string(), p));
        }
    }
    if files.is_empty() {
        return None;
    }
    files.sort();
    files.dedup();

    let mut h = Sha3_256::new();
    // Domain separator: this digest is not a block hash and must never be
    // confused for one if it turns up in a log.
    h.update(b"bloch-pos/source-digest/v1\0");
    let mut bytes_total: u64 = 0;
    for (rel, path) in &files {
        let body = std::fs::read(path).ok()?;
        bytes_total += body.len() as u64;
        h.update(rel.as_bytes());
        h.update([0u8]);
        h.update((body.len() as u64).to_le_bytes());
        h.update(&body);
        // A stamp that goes stale in an incremental build is worse than no
        // stamp: it is a confident lie. Every hashed file is watched.
        println!("cargo:rerun-if-changed={}", path.display());
    }
    Some((hex(&h.finalize()), files.len(), bytes_total))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}



fn main() {
    let pkg = env!("CARGO_PKG_VERSION");

    let git = |args: &[&str]| -> Option<String> {
        let out = Command::new("git").args(args).output().ok()?;
        if !out.status.success() {
            return None;
        }
        let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    };

    let commit = std::env::var("BLOCH_BUILD_COMMIT")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| git(&["rev-parse", "--short=12", "HEAD"]))
        .unwrap_or_else(|| "unknown".into());

    // A dirty build is the thing that made the fleet unidentifiable in the
    // first place, so it is marked loudly rather than hidden.
    let dirty = if std::env::var("BLOCH_BUILD_COMMIT").is_ok() {
        // Caller-supplied commit: it asserted the tree state, do not second-guess.
        ""
    } else {
        match git(&["status", "--porcelain"]) {
            Some(s) if !s.is_empty() => "+dirty",
            Some(_) => "",
            None => "+nogit",
        }
    };

    println!("cargo:rustc-env=BLOCH_BUILD_VERSION={pkg} ({commit}{dirty})");

    // ── The machine-readable half, for `getbuildinfo` ──────────────────────
    //
    // Split into separate stamps rather than parsed back out of the display
    // string above, because a client that has to parse "0.1.0 (abc123+dirty)"
    // with a regex is a client that will eventually parse it wrong.
    println!("cargo:rustc-env=BLOCH_BUILD_COMMIT_ID={commit}");
    // Whether the commit is EVIDENCE or an ASSERTION. This is the field that
    // keeps the response honest: `asserted` means whoever ran the build typed
    // the id, and the build script did not check it against anything.
    let commit_source = if std::env::var("BLOCH_BUILD_COMMIT")
        .ok()
        .is_some_and(|s| !s.trim().is_empty())
    {
        "asserted"
    } else if commit == "unknown" {
        "none"
    } else {
        "git"
    };
    println!("cargo:rustc-env=BLOCH_BUILD_COMMIT_SOURCE={commit_source}");
    let tree_state = match dirty {
        "+dirty" => "modified",
        "+nogit" => "unknown",
        _ if commit_source == "asserted" => "unverified",
        _ => "clean",
    };
    println!("cargo:rustc-env=BLOCH_BUILD_TREE_STATE={tree_state}");

    match source_digest(&workspace_root().unwrap_or_else(|| PathBuf::from("."))) {
        Some((digest, files, bytes)) => {
            println!("cargo:rustc-env=BLOCH_SOURCE_DIGEST={digest}");
            println!("cargo:rustc-env=BLOCH_SOURCE_FILES={files}");
            println!("cargo:rustc-env=BLOCH_SOURCE_BYTES={bytes}");
        }
        None => {
            // Say so, rather than emit a digest of nothing. A client can tell
            // "I could not compute this" from "here is the tree".
            println!("cargo:rustc-env=BLOCH_SOURCE_DIGEST=unavailable");
            println!("cargo:rustc-env=BLOCH_SOURCE_FILES=0");
            println!("cargo:rustc-env=BLOCH_SOURCE_BYTES=0");
        }
    }

    // Build inputs that change behaviour and are not source: the compiler, the
    // profile and the target. All three are safe to publish — none of them
    // says anything about the box, its paths or its operator.
    let rustc_v = Command::new(std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into()))
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=BLOCH_BUILD_RUSTC={rustc_v}");
    println!(
        "cargo:rustc-env=BLOCH_BUILD_PROFILE={}",
        std::env::var("PROFILE").unwrap_or_else(|_| "unknown".into())
    );
    println!(
        "cargo:rustc-env=BLOCH_BUILD_TARGET={}",
        std::env::var("TARGET").unwrap_or_else(|_| "unknown".into())
    );

    // Rebuild when HEAD moves, so the stamp cannot go stale in an incremental
    // build — a stale stamp is worse than no stamp: it is a confident lie.
    //
    // Unlike the G3 original (which watched the literal ".git/HEAD" relative
    // to the crate — wrong for a crate in a subdirectory, and wrong for linked
    // worktrees where .git is a file), resolve the real git dir. In a linked
    // worktree --absolute-git-dir points at the per-worktree gitdir, which is
    // where its HEAD and index actually live.
    println!("cargo:rerun-if-env-changed=BLOCH_BUILD_COMMIT");
    if let Some(gitdir) = git(&["rev-parse", "--absolute-git-dir"]) {
        for f in ["HEAD", "index"] {
            let p = format!("{gitdir}/{f}");
            if std::path::Path::new(&p).exists() {
                println!("cargo:rerun-if-changed={p}");
            }
        }
    }
}
