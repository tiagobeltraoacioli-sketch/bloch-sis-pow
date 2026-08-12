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

use std::process::Command;

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
