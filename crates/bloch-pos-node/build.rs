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
// nobody can compare against: every `.rs`, `.toml`, `.c`, `.h`, `.S`, `.s`
// and `.macros` file under workspace `crates/`, including hidden directories
// except `.git` and build outputs, plus root `Cargo.toml`, `Cargo.lock` and
// `rust-toolchain.toml`. That covers this binary's whole path-
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
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

mod build_command;
use build_command::{
    configured_command_words, delegated_compiler, linker_from_printed_args, rustflags_linker,
};

/// Extensions that are build inputs for this binary.
const SOURCE_EXT: &[&str] = &["rs", "toml", "c", "h", "S", "s", "macros"];

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
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let path = e.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        // Build outputs and VCS metadata are not source. `target/` in
        // particular is enormous and changes on every build, which would make
        // the digest a random number.
        if name == ".git" || name == "target" {
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
    for extra in ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml"] {
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
        // `bytes_total` is a build-time diagnostic counter (printed into the
        // source-digest stamp), not a value that feeds consensus or a state
        // root: saturation is the intended semantics for a total this size
        // could never realistically reach (it would require exabytes of
        // source under `crates/`).
        bytes_total = bytes_total.saturating_add(body.len() as u64);
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

/// Build knobs whose values can change generated machine code without changing
/// the source tree. Values are hashed, never published verbatim. Prefixes cover
/// Cargo's target/profile-specific forms and the C toolchain used by PQClean.
const FIXED_BUILD_ENV: &[&str] = &[
    "AR",
    "BINDGEN_EXTRA_CLANG_ARGS",
    "CARGO",
    "CARGO_BUILD_RUSTC",
    "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
    "CARGO_BUILD_RUSTC_WRAPPER",
    "CARGO_BUILD_RUSTFLAGS",
    "CARGO_BUILD_TARGET",
    "CARGO_ENCODED_RUSTFLAGS",
    "CARGO_INCREMENTAL",
    "CC",
    "CFLAGS",
    "CPPFLAGS",
    "DEBUG",
    "HOST_AR",
    "HOST_CC",
    "HOST_CFLAGS",
    "HOST_CPPFLAGS",
    "HOST_CXX",
    "HOST_CXXFLAGS",
    "HOST_RANLIB",
    "MACOSX_DEPLOYMENT_TARGET",
    "OPT_LEVEL",
    "RANLIB",
    "RUSTC",
    "RUSTC_BOOTSTRAP",
    "RUSTC_LINKER",
    "RUSTC_WORKSPACE_WRAPPER",
    "RUSTC_WRAPPER",
    "RUSTFLAGS",
    "SDKROOT",
    "SOURCE_DATE_EPOCH",
    "TARGET_AR",
    "TARGET_CC",
    "TARGET_CFLAGS",
    "TARGET_CPPFLAGS",
    "TARGET_CXX",
    "TARGET_CXXFLAGS",
    "TARGET_RANLIB",
];

/// Hash the executable bytes selected for a build tool without publishing its
/// path. Cargo normally supplies absolute `RUSTC`/`CARGO` paths; resolving a
/// bare command through PATH preserves ordinary local builds. The selected
/// file itself is watched so an in-place tool replacement cannot leave an
/// incremental build stamped with the old fingerprint.
fn build_tool_digest_with_path(command: &str, search_path: Option<&str>) -> Option<String> {
    let direct = PathBuf::from(command);
    let path = if direct.components().count() > 1 {
        direct
    } else {
        let paths = search_path
            .map(OsStr::new)
            .map(ToOwned::to_owned)
            .or_else(|| std::env::var_os("PATH"))?;
        std::env::split_paths(&paths)
            .map(|dir| dir.join(command))
            .find(|path| path.is_file())?
    };
    let body = std::fs::read(&path).ok()?;
    println!("cargo:rerun-if-changed={}", path.display());
    let mut h = Sha3_256::new();
    h.update(b"bloch-pos/build-tool-binary/v1\0");
    h.update((body.len() as u64).to_le_bytes());
    h.update(body);
    Some(hex(&h.finalize()))
}

fn build_tool_digest(command: &str) -> Option<String> {
    build_tool_digest_with_path(command, None)
}

/// Build environment variables whose value begins with an executable. This
/// deliberately excludes flags and SDK directories. Target/host spellings are
/// already enumerated by `exact_build_env`; prefix forms cover the variants
/// that Cargo and cc-rs may actually export.
fn configured_tool_key(key: &str) -> bool {
    matches!(
        key,
        "AR" | "CARGO_BUILD_RUSTC"
            | "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER"
            | "CARGO_BUILD_RUSTC_WRAPPER"
            | "CC"
            | "CXX"
            | "HOST_AR"
            | "HOST_CC"
            | "HOST_CXX"
            | "HOST_RANLIB"
            | "RANLIB"
            | "RUSTC_LINKER"
            | "RUSTC_WORKSPACE_WRAPPER"
            | "RUSTC_WRAPPER"
            | "TARGET_AR"
            | "TARGET_CC"
            | "TARGET_CXX"
            | "TARGET_RANLIB"
    ) || key.starts_with("AR_")
        || key.starts_with("CC_")
        || key.starts_with("CXX_")
        || key.starts_with("RANLIB_")
        || (key.starts_with("CARGO_TARGET_") && key.ends_with("_LINKER"))
}

/// Fingerprint every explicitly configured compiler/linker/archive/wrapper
/// executable without disclosing its command or path. The environment value
/// itself is separately included in the canonical build-environment fields.
fn configured_tool_digests(target: &str, host: &str) -> Vec<(String, String)> {
    let mut keys = exact_build_env(target, host);
    keys.extend(
        std::env::vars()
            .map(|(key, _)| key)
            .filter(|key| relevant_build_env(key)),
    );
    keys.sort();
    keys.dedup();

    let mut digests = Vec::new();
    for key in keys.into_iter().filter(|key| configured_tool_key(key)) {
        let Ok(value) = std::env::var(&key) else {
            continue;
        };
        let Some(words) = configured_command_words(&value) else {
            continue;
        };
        if let Some(digest) = build_tool_digest(&words[0]) {
            digests.push((key.clone(), digest));
        }
        if let Some(delegate) = delegated_compiler(&words) {
            if let Some(digest) = build_tool_digest(delegate) {
                digests.push((format!("{key}:delegate"), digest));
            }
        }
    }
    let flags_linker = std::env::var("CARGO_ENCODED_RUSTFLAGS")
        .ok()
        .and_then(|flags| rustflags_linker(&flags, true))
        .or_else(|| {
            std::env::var("CARGO_BUILD_RUSTFLAGS")
                .ok()
                .and_then(|flags| rustflags_linker(&flags, false))
        })
        .or_else(|| {
            std::env::var("RUSTFLAGS")
                .ok()
                .and_then(|flags| rustflags_linker(&flags, false))
        });
    if let Some(linker) = flags_linker {
        if let Some(digest) = build_tool_digest(&linker) {
            digests.push(("rustflags-linker".to_owned(), digest));
        }
    }
    digests.sort();
    digests.dedup();
    digests
}

fn explicit_linker_selected(target: &str) -> bool {
    let cargo_target = target.to_ascii_uppercase().replace('-', "_");
    for key in [
        "RUSTC_LINKER".to_owned(),
        format!("CARGO_TARGET_{cargo_target}_LINKER"),
    ] {
        if std::env::var(key).is_ok_and(|value| !value.trim().is_empty()) {
            return true;
        }
    }
    std::env::var("CARGO_ENCODED_RUSTFLAGS")
        .ok()
        .and_then(|flags| rustflags_linker(&flags, true))
        .or_else(|| {
            std::env::var("CARGO_BUILD_RUSTFLAGS")
                .ok()
                .and_then(|flags| rustflags_linker(&flags, false))
        })
        .or_else(|| {
            std::env::var("RUSTFLAGS")
                .ok()
                .and_then(|flags| rustflags_linker(&flags, false))
        })
        .is_some()
}

/// Ask rustc to link a tiny target binary and report the command it actually
/// invoked. The exact probe files live in OUT_DIR and are removed immediately.
fn default_linker_digest(rustc: &str, target: &str) -> Option<String> {
    if target.is_empty() || target == "unknown" || explicit_linker_selected(target) {
        return None;
    }
    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR")?);
    let source = out_dir.join("bloch-linker-probe.rs");
    let binary = out_dir.join("bloch-linker-probe-bin");
    std::fs::write(&source, b"fn main() {}\n").ok()?;
    let output = Command::new(rustc)
        .arg(&source)
        .args([
            "--crate-name",
            "bloch_linker_probe",
            "--edition",
            "2024",
            "--target",
            target,
            "--print",
            "link-args",
            "-o",
        ])
        .arg(&binary)
        .output()
        .ok();
    let _ = std::fs::remove_file(&source);
    let _ = std::fs::remove_file(&binary);
    let _ = std::fs::remove_file(binary.with_extension("exe"));
    let output = output?;
    if !output.status.success() {
        return None;
    }
    let printed = String::from_utf8(output.stdout).ok()?;
    let (linker, search_path) = linker_from_printed_args(&printed)?;
    build_tool_digest_with_path(&linker, search_path.as_deref())
}

/// Fingerprint the compiler implementation and target standard library that
/// `rustc` selected from its sysroot. Hashing this small, load-bearing subset
/// avoids walking an entire toolchain while binding more than version text or
/// a rustup shim. The aggregate publishes neither paths nor component names.
fn rust_sysroot_digest(rustc: &str) -> (Option<String>, usize) {
    let query = |kind: &str| -> Option<PathBuf> {
        let out = Command::new(rustc).args(["--print", kind]).output().ok()?;
        if !out.status.success() {
            return None;
        }
        let value = String::from_utf8(out.stdout).ok()?;
        let value = value.trim();
        (!value.is_empty()).then(|| PathBuf::from(value))
    };
    let sysroot = match query("sysroot") {
        Some(path) => path,
        None => return (None, 0),
    };
    let target_libdir = match query("target-libdir") {
        Some(path) => path,
        None => return (None, 0),
    };
    let mut files =
        vec![
            sysroot
                .join("bin")
                .join(if cfg!(windows) { "rustc.exe" } else { "rustc" }),
        ];
    for dir in [sysroot.join("lib"), target_libdir] {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.contains("rustc_driver")
                || name.starts_with("libstd-")
                || name.starts_with("std-")
            {
                files.push(entry.path());
            }
        }
    }
    files.sort();
    files.dedup();

    let mut h = Sha3_256::new();
    h.update(b"bloch-pos/rust-sysroot-components/v1\0");
    let mut count = 0usize;
    for path in files {
        let Ok(body) = std::fs::read(&path) else {
            continue;
        };
        println!("cargo:rerun-if-changed={}", path.display());
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        h.update((name.len() as u64).to_le_bytes());
        h.update(name.as_bytes());
        h.update((body.len() as u64).to_le_bytes());
        h.update(body);
        count = count.saturating_add(1);
    }
    if count == 0 {
        (None, 0)
    } else {
        (Some(hex(&h.finalize())), count)
    }
}

fn relevant_build_env(key: &str) -> bool {
    FIXED_BUILD_ENV.contains(&key)
        || key.starts_with("AR_")
        || key.starts_with("BINDGEN_EXTRA_CLANG_ARGS_")
        || key.starts_with("CC_")
        || key.starts_with("CFLAGS_")
        || key.starts_with("CPPFLAGS_")
        || key.starts_with("CXX_")
        || key.starts_with("CXXFLAGS_")
        || key.starts_with("RANLIB_")
        || key.starts_with("CARGO_BUILD_")
        || key.starts_with("CARGO_CFG_")
        || key.starts_with("CARGO_FEATURE_")
        || key.starts_with("CARGO_PROFILE_")
        || key.starts_with("CARGO_TARGET_")
}

/// Exact target/host forms used by Cargo, cc-rs and bindgen. Watching these
/// while absent closes the incremental-build hole that wildcard-like prefix
/// discovery alone cannot close.
fn exact_build_env(target: &str, host: &str) -> Vec<String> {
    let mut keys: Vec<String> = FIXED_BUILD_ENV
        .iter()
        .map(|key| (*key).to_owned())
        .collect();
    for triple in [target, host] {
        let underscored = triple.replace('-', "_");
        for stem in [
            "AR",
            "BINDGEN_EXTRA_CLANG_ARGS",
            "CC",
            "CFLAGS",
            "CPPFLAGS",
            "CXX",
            "CXXFLAGS",
            "RANLIB",
        ] {
            keys.push(format!("{stem}_{triple}"));
            keys.push(format!("{stem}_{underscored}"));
        }
    }
    let cargo_target = target.to_ascii_uppercase().replace('-', "_");
    for suffix in ["LINKER", "RUNNER", "RUSTFLAGS"] {
        keys.push(format!("CARGO_TARGET_{cargo_target}_{suffix}"));
    }
    keys.sort();
    keys.dedup();
    keys
}

/// Hash the compiler/Cargo identities, effective target/profile and selected
/// code-generation environment. The canonical framing keeps the digest stable
/// without publishing machine paths that wrappers or SDK variables may carry.
fn build_environment_digest(
    rustc_verbose: &str,
    cargo_verbose: &str,
    rustc_binary_digest: Option<String>,
    cargo_binary_digest: Option<String>,
    rust_sysroot_digest: Option<String>,
    configured_tool_digests: &[(String, String)],
    default_linker_digest: Option<String>,
    profile: &str,
    target: &str,
    host: &str,
) -> (String, usize) {
    // An absent fixed variable is also watched: setting it after an incremental
    // build must rerun this script rather than leave a stale fingerprint.
    let watched = exact_build_env(target, host);
    for key in &watched {
        println!("cargo:rerun-if-env-changed={key}");
    }
    let mut fields = vec![
        ("cargo-version".to_owned(), Some(cargo_verbose.to_owned())),
        ("cargo-binary-sha3-256".to_owned(), cargo_binary_digest),
        ("host".to_owned(), Some(host.to_owned())),
        ("profile".to_owned(), Some(profile.to_owned())),
        ("rustc-binary-sha3-256".to_owned(), rustc_binary_digest),
        (
            "rust-sysroot-components-sha3-256".to_owned(),
            rust_sysroot_digest,
        ),
        (
            "probed-default-linker-sha3-256".to_owned(),
            default_linker_digest,
        ),
        ("rustc-version".to_owned(), Some(rustc_verbose.to_owned())),
        ("target".to_owned(), Some(target.to_owned())),
    ];
    fields.extend(configured_tool_digests.iter().map(|(key, digest)| {
        (
            format!("configured-tool-binary-sha3-256:{key}"),
            Some(digest.clone()),
        )
    }));
    for key in watched {
        let value = match std::env::var(&key) {
            Ok(value) => Some(value),
            Err(std::env::VarError::NotPresent) => None,
            Err(std::env::VarError::NotUnicode(_)) => {
                panic!("build environment variable {key} is not Unicode")
            }
        };
        fields.push((format!("env:{key}"), value));
    }
    for (key, value) in std::env::vars().filter(|(key, _)| relevant_build_env(key)) {
        println!("cargo:rerun-if-env-changed={key}");
        fields.push((format!("env:{key}"), Some(value)));
    }
    fields.sort();
    fields.dedup();

    let mut h = Sha3_256::new();
    h.update(b"bloch-pos/build-environment/v1\0");
    for (key, value) in &fields {
        h.update((key.len() as u64).to_le_bytes());
        h.update(key.as_bytes());
        match value {
            Some(value) => {
                h.update([1]);
                h.update((value.len() as u64).to_le_bytes());
                h.update(value.as_bytes());
            }
            None => h.update([0]),
        }
    }
    (hex(&h.finalize()), fields.len())
}

fn main() {
    let pkg = env!("CARGO_PKG_VERSION");

    // Ran and exited 0, whatever it printed. `None` means "git could not
    // answer" and NOTHING else.
    let git_raw = |args: &[&str]| -> Option<String> {
        let out = Command::new("git").args(args).output().ok()?;
        if !out.status.success() {
            return None;
        }
        Some(String::from_utf8(out.stdout).ok()?.trim().to_string())
    };
    // The same, but with an empty answer folded into "could not answer" —
    // correct for `rev-parse`, where a blank line is not a commit id.
    let git = |args: &[&str]| -> Option<String> { git_raw(args).filter(|s| !s.is_empty()) };

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
        // MUST be git_raw, not git. `git status --porcelain` prints NOTHING
        // on a clean tree and exits 0, so the empty-is-None helper collapsed
        // "clean" onto "no repository" and every clean build stamped itself
        // `+nogit`. That is not a cosmetic slip: it made `clean` unreachable,
        // so the one field meant to say the tree was intact could only ever
        // say it did not know. Measured on this tag before the fix — a clean
        // build at 2ae0e7f1 reported `+nogit`.
        match git_raw(&["status", "--porcelain"]) {
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
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let rustc_verbose = Command::new(&rustc)
        .arg("-vV")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".into());
    let rustc_v = rustc_verbose.lines().next().unwrap_or("unknown");
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let cargo_verbose = Command::new(&cargo)
        .args(["--version", "--verbose"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".into());
    let cargo_v = cargo_verbose.lines().next().unwrap_or("unknown");
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "unknown".into());
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".into());
    let host = std::env::var("HOST").unwrap_or_else(|_| "unknown".into());
    let rustc_binary_digest = build_tool_digest(&rustc);
    let cargo_binary_digest = build_tool_digest(&cargo);
    let (rust_sysroot_digest, rust_sysroot_components) = rust_sysroot_digest(&rustc);
    let configured_tool_digests = configured_tool_digests(&target, &host);
    let configured_tool_binaries = configured_tool_digests.len();
    let default_linker_digest = default_linker_digest(&rustc, &target);
    let default_linker_binaries = usize::from(default_linker_digest.is_some());
    let tool_binaries =
        usize::from(rustc_binary_digest.is_some()) + usize::from(cargo_binary_digest.is_some());
    let (environment_digest, environment_fields) = build_environment_digest(
        &rustc_verbose,
        &cargo_verbose,
        rustc_binary_digest,
        cargo_binary_digest,
        rust_sysroot_digest,
        &configured_tool_digests,
        default_linker_digest,
        &profile,
        &target,
        &host,
    );
    println!("cargo:rustc-env=BLOCH_BUILD_RUSTC={rustc_v}");
    println!("cargo:rustc-env=BLOCH_BUILD_CARGO={cargo_v}");
    println!("cargo:rustc-env=BLOCH_BUILD_PROFILE={profile}");
    println!("cargo:rustc-env=BLOCH_BUILD_TARGET={target}");
    println!("cargo:rustc-env=BLOCH_BUILD_ENV_DIGEST={environment_digest}");
    println!("cargo:rustc-env=BLOCH_BUILD_ENV_FIELDS={environment_fields}");
    println!("cargo:rustc-env=BLOCH_BUILD_TOOL_BINARIES={tool_binaries}");
    println!("cargo:rustc-env=BLOCH_BUILD_SYSROOT_COMPONENTS={rust_sysroot_components}");
    println!("cargo:rustc-env=BLOCH_BUILD_CONFIGURED_TOOL_BINARIES={configured_tool_binaries}");
    println!("cargo:rustc-env=BLOCH_BUILD_DEFAULT_LINKER_BINARIES={default_linker_binaries}");

    // ── `BLOCH_BUILD_DIRTY` is deliberately NOT stamped ────────────────────
    //
    // `dev/refusal-split-release-20260901` (5e39d7f6) stamped a second
    // tri-state here, `BLOCH_BUILD_DIRTY` in {"true","false","unknown"}, for
    // its `getnodeversion` method. Both are gone, for two separate reasons,
    // and the reasons are recorded here because deleting a field silently is
    // how the next branch reinvents it.
    //
    // 1. It is the SAME FACT as `BLOCH_BUILD_TREE_STATE` above, computed from
    //    the same `dirty` string, with strictly less resolution: `tree_state`
    //    separates `unverified` (the caller asserted a commit, so the tree was
    //    never examined) from `unknown` (there was no repository to examine),
    //    where `dirty` folded both onto "unknown". One question, one stamp.
    //
    // 2. Its `"" => "false"` arm — the only arm that could ever have said
    //    "clean" — was UNREACHABLE on tag g4-node-20260901, and not because of
    //    anything in that branch. The shared `git` helper folded empty output
    //    into `None`, `git status --porcelain` prints nothing and exits 0 on a
    //    clean tree, so `dirty` was `"+nogit"` on a pristine checkout and the
    //    match fell through to `_ => "unknown"`. The preceding
    //    `"" if BLOCH_BUILD_COMMIT is set => "unknown"` arm consumed the only
    //    other way to reach `""`. So `getnodeversion` would have answered
    //    `dirty: null` on every clean release build it was ever run on — the
    //    field existed and could not carry its own load-bearing value.
    //
    // The underlying defect is fixed above (`git_raw` for `status`, `git` for
    // `rev-parse`), so `tree_state` can now actually report `clean`. The dead
    // arm is removed rather than repaired because the field it fed is removed:
    // repairing it would leave two stamps answering one question, which is the
    // shape this whole branch exists to collapse.

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
