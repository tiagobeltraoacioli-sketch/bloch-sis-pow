//! The fuzz harness must resolve, and it must point at the chain that is running.
//!
//! # Why this test exists
//!
//! `fuzz/Cargo.toml` declared `bloch = { path = ".." }` — correct back when the
//! repository root *was* the `bloch` package. Genesis-4 made the root a virtual
//! manifest and moved the proof-of-work node to `legacy/genesis3-node/`, and a
//! path dependency on a virtual manifest is a hard cargo error:
//!
//! ```text
//! found a virtual manifest at `.../Cargo.toml` instead of a package manifest
//! ```
//!
//! So *every* target in the harness failed before a single byte was fuzzed, and
//! nothing went red: the only CI job that touched `fuzz/` needs a nightly
//! toolchain, skips itself when the runner has none, and is `allow_failure`.
//! A fuzz harness that does not build is indistinguishable from one that builds
//! and finds nothing — from the outside, both are a green pipeline.
//!
//! The second half of the defect survives a fixed path: eight of the eleven
//! original targets fuzz Genesis-3, which stopped at height 39,918. The live
//! proof-of-stake decoders had zero coverage. Repointing the manifest without
//! adding those targets would leave the harness compiling and still aimed at a
//! dead chain, so this test checks both.
//!
//! # The rule
//!
//! A fact the build system can check must never live only in a file nobody
//! executes. `cargo metadata` is the cheapest execution of "this manifest
//! resolves" there is, and it needs no nightly, no libFuzzer and no C++
//! toolchain — so it can be a hard test rather than a soft CI job.
//! `.gitlab-ci.yml`'s `fuzz-build` compiles the targets on top of this.

use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repository root")
}

fn fuzz_manifest() -> PathBuf {
    repo_root().join("fuzz/Cargo.toml")
}

/// The regression itself: resolving the harness's dependency graph must
/// succeed. This is the assertion that fails on the unfixed tree.
#[test]
fn fuzz_manifest_resolves() {
    let out = Command::new(env!("CARGO"))
        .arg("metadata")
        .arg("--format-version")
        .arg("1")
        .arg("--manifest-path")
        .arg(fuzz_manifest())
        .output()
        .expect("cargo metadata runs");

    assert!(
        out.status.success(),
        "fuzz/Cargo.toml does not resolve — the harness cannot build, so no target in it \
         is fuzzing anything:\n{}",
        String::from_utf8_lossy(&out.stderr),
    );
}

/// Every `[[bin]]` the manifest declares, and every `#[path]` include those
/// targets make, must name a file that exists. A dangling include is the way a
/// target silently stops covering the module it was written for — the node's
/// sources move, and a harness that is not built by `cargo test` says nothing.
#[test]
fn every_declared_target_and_include_exists() {
    let root = repo_root();
    let manifest = std::fs::read_to_string(fuzz_manifest()).expect("read fuzz/Cargo.toml");

    let mut targets = Vec::new();
    for line in manifest.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("path") {
            let Some(v) = rest.split('"').nth(1) else { continue };
            if v.starts_with("fuzz_targets/") {
                targets.push(root.join("fuzz").join(v));
            }
        }
    }
    assert!(!targets.is_empty(), "no [[bin]] targets found in fuzz/Cargo.toml");

    for t in &targets {
        assert!(t.is_file(), "fuzz target declared but missing: {}", t.display());

        let src = std::fs::read_to_string(t).expect("read fuzz target");
        for line in src.lines() {
            let line = line.trim();
            if !line.starts_with("#[path") {
                continue;
            }
            let Some(v) = line.split('"').nth(1) else { continue };
            // `#[path]` is relative to the file's own directory.
            let inc = t.parent().expect("target dir").join(v);
            assert!(
                inc.is_file(),
                "{} includes a file that does not exist: {}",
                t.file_name().unwrap_or_default().to_string_lossy(),
                v,
            );
        }
    }
}

/// The live chain's untrusted-input decoders must each be reached by some
/// target. Genesis-3 is closed; a harness aimed only at it is coverage of a
/// museum.
#[test]
fn the_live_pos_decoders_are_covered() {
    let dir = repo_root().join("fuzz/fuzz_targets");
    let mut all = String::new();
    for e in std::fs::read_dir(&dir).expect("read fuzz_targets") {
        let p = e.expect("dir entry").path();
        if p.extension().is_some_and(|x| x == "rs") {
            all.push_str(&std::fs::read_to_string(&p).expect("read fuzz target"));
        }
    }

    // (what the fuzzer must call, where it lives)
    const REQUIRED: &[(&str, &str)] = &[
        ("decode_envelope", "the block frame off gossipsub"),
        ("decode_attestation", "the highest-rate frame on the network"),
        ("canonical_deserialize", "the header decode BlockId rests on"),
        ("read_carryover_snapshot", "the parser that reads the opening ledger"),
    ];
    for (needle, what) in REQUIRED {
        assert!(
            all.contains(needle),
            "no fuzz target calls `{needle}` — {what} is unfuzzed",
        );
    }
}

/// Names declared as `[[bin]]` in the manifest.
fn declared_target_names() -> Vec<String> {
    let manifest = std::fs::read_to_string(fuzz_manifest()).expect("read fuzz/Cargo.toml");
    let mut names = Vec::new();
    let mut in_bin = false;
    for line in manifest.lines() {
        let line = line.trim();
        if line == "[[bin]]" {
            in_bin = true;
        } else if line.starts_with('[') {
            in_bin = false;
        } else if in_bin && line.starts_with("name") {
            if let Some(v) = line.split('"').nth(1) {
                names.push(v.to_string());
            }
        }
    }
    names
}

/// OSS-Fuzz copies a hand-written list of binaries into `$OUT`. A target that
/// is built but not listed is never shipped, so it is never run — and the
/// pipeline is green either way. The list is prose in a shell array; this is
/// the execution of it.
#[test]
fn oss_fuzz_ships_every_declared_target() {
    let build_sh = repo_root().join("fuzz/oss-fuzz/build.sh");
    let sh = std::fs::read_to_string(&build_sh).expect("read fuzz/oss-fuzz/build.sh");
    let listed = sh
        .split_once("TARGETS=(")
        .expect("TARGETS array in build.sh")
        .1
        .split_once(')')
        .expect("TARGETS array closes")
        .0;

    for name in declared_target_names() {
        assert!(
            listed.split_whitespace().any(|t| t == name),
            "fuzz target `{name}` is declared in fuzz/Cargo.toml but not shipped by              fuzz/oss-fuzz/build.sh — OSS-Fuzz will never run it",
        );
    }
}
