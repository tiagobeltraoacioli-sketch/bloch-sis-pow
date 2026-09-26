// SPDX-License-Identifier: AGPL-3.0-or-later
//
// INF-01 reproducer — "the live validator binary is built and shipped by a
// pipeline that exists only outside the repository".
//
// HOW TO RUN (never inside the audited checkout — copy the tree first):
//
//   cp -r /home/user/bloch-sis-pow /tmp/bloch-copy
//   cp repro-INF-01.rs /tmp/bloch-copy/crates/bloch-pos-node/tests/repro_inf_01.rs
//   (cd /tmp/bloch-copy/crates/bloch-pos-node && cargo test --locked --test repro_inf_01)
//
// Idiom: the same repository-reading integration-test shape as
// crates/bloch-pos-node/tests/published_checksums.rs and
// tests/rpc_method_registry.rs (bloch-pos-node is a [[bin]]-only crate, so a
// test cannot `use` its modules; it reads files from CARGO_MANIFEST_DIR/../..).
//
// EXPECTED RESULT ON HEAD 562e2200 (2026-09-16): every test below FAILS. The
// failures ARE the reproduction — each one is a repository fact the finding
// rests on. The tests go green only when the release pipeline that
// deploy/RELEASE-INTEGRITY.md §2-3 specifies actually exists in the tree and
// the rollout runbooks record what was shipped. They are diagnostics, not a
// security pass: a green run proves the recipe exists, not that the fleet
// runs what it produces (that is the §4 sweep, which needs fleet access).

use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repository root")
}

fn read(rel: &str) -> String {
    let p = repo_root().join(rel);
    fs::read_to_string(&p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()))
}

/// Every regular file under the repo except target/, .git/ and the
/// scratchpad; the walk is deliberately hand-rolled so the test needs no
/// dev-dependency the crate does not already have.
fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for e in entries.flatten() {
        let p = e.path();
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name == ".git" || name == "target" || name == "node_modules" {
            continue;
        }
        match e.file_type() {
            Ok(t) if t.is_dir() => walk(&p, out),
            Ok(t) if t.is_file() => out.push(p),
            _ => {}
        }
    }
}

fn all_files() -> Vec<PathBuf> {
    let mut v = Vec::new();
    walk(&repo_root(), &mut v);
    v
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// True when `text` contains a bare 64-hex-digit token (a sha256) that is
/// NOT the OCI image digest already quoted for the epoch-800 image.
fn contains_binary_sha256(text: &str) -> bool {
    text.split(|c: char| !c.is_ascii_hexdigit())
        .any(|tok| is_sha256_hex(tok) && !tok.starts_with("e29a5148"))
}

// ── 1. The runbook names a fleet image nothing in the tree defines ─────────

#[test]
fn inf01_fleet_image_named_by_runbook_has_no_recipe_in_repo() {
    let runbook = read("deploy/FLAG-DAY-EPOCH-800.md");
    assert!(
        runbook.contains("registry.fly.io/bloch-g4:g4-flagday-6a7301ea"),
        "premise moved: deploy/FLAG-DAY-EPOCH-800.md no longer names the fleet image"
    );
    assert!(
        runbook.contains("replaces exactly one file") && runbook.contains("start.sh"),
        "premise moved: the runbook no longer describes the layer-on-previous-image build"
    );

    // A recipe = a Dockerfile (or fly config / start script) that references
    // the bloch-g4 app or image, outside the runbook itself and outside the
    // libp2p protocol-id strings in p2p.rs / docs that merely quote them.
    let recipes: Vec<PathBuf> = all_files()
        .into_iter()
        .filter(|p| {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let is_recipe_shape = name.contains("Dockerfile")
                || name.ends_with(".toml")
                || name.ends_with(".sh")
                || name.ends_with(".yml")
                || name.ends_with(".yaml");
            is_recipe_shape
                && fs::read_to_string(p)
                    .map(|t| t.contains("bloch-g4") || t.contains("start.sh"))
                    .unwrap_or(false)
        })
        .collect();
    assert!(
        !recipes.is_empty(),
        "\nINF-01 reproduced: the image that 49/64 validators run \
         (registry.fly.io/bloch-g4:g4-flagday-6a7301ea) is named only by \
         deploy/FLAG-DAY-EPOCH-800.md. No Dockerfile, fly.toml, start.sh or \
         rollout script in the repository references app/image `bloch-g4` or \
         `start.sh`. The build that produced the fleet binary cannot be \
         re-derived from this tree.\n"
    );
}

// ── 2. No container recipe builds `bloch-pos` at all ───────────────────────

#[test]
fn inf01_no_dockerfile_builds_the_live_binary() {
    let dockerfiles: Vec<PathBuf> = all_files()
        .into_iter()
        .filter(|p| {
            let n = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            n == "Dockerfile" || n.starts_with("Dockerfile.") || n.ends_with(".Dockerfile")
        })
        .collect();
    assert!(!dockerfiles.is_empty(), "premise moved: no Dockerfiles at all");

    // The canonical release container per deploy/RELEASE-INTEGRITY.md §2-3:
    // digest-pinned base, WORKDIR /build, --locked, BLOCH_BUILD_COMMIT set,
    // and it must actually build the `bloch-pos` bin (not `--bin bloch`).
    let canonical: Vec<&PathBuf> = dockerfiles
        .iter()
        .filter(|p| {
            let t = fs::read_to_string(p).unwrap_or_default();
            let builds_pos = t.lines().any(|l| {
                let l = l.trim_start();
                l.starts_with("RUN") && l.contains("cargo build") && l.contains("bloch-pos")
            });
            builds_pos
                && t.contains("@sha256:")
                && t.contains("WORKDIR /build")
                && t.contains("--locked")
                && t.contains("BLOCH_BUILD_COMMIT")
        })
        .collect();
    assert!(
        !canonical.is_empty(),
        "\nINF-01 reproduced: none of {} Dockerfile(s) builds `bloch-pos` in \
         the canonical shape RELEASE-INTEGRITY.md §2-3 requires (digest-pinned \
         FROM, WORKDIR /build, --locked, BLOCH_BUILD_COMMIT). The root \
         Dockerfile builds `--bin bloch` (Genesis-3) and its own header says \
         \"There is deliberately no container image for it here\"; §8.1 says \
         \"No `bloch-pos` release container exists yet\".\n",
        dockerfiles.len()
    );
}

// ── 3. The toolchain the fleet binary was built with is not recorded ───────

#[test]
fn inf01_runbook_records_resolved_rustc_next_to_floating_base_image() {
    let integrity = read("deploy/RELEASE-INTEGRITY.md");
    let pin = read("crates/bloch-pos-node/rust-toolchain.toml");
    assert!(
        pin.contains("channel = \"1.94.1\"") && integrity.contains("1.94.1"),
        "premise moved: the compiler pin is no longer 1.94.1"
    );
    let runbook = read("deploy/FLAG-DAY-EPOCH-800.md");
    assert!(
        runbook.contains("built in rust:1-bookworm"),
        "premise moved: the runbook no longer says the fleet binary was built in rust:1-bookworm"
    );
    // `rust:1` is a floating Docker Hub tag. rustup inside that image only
    // honours crates/bloch-pos-node/rust-toolchain.toml if cargo was invoked
    // from that directory (docs/THIRD-PARTY-QUICKSTART.md §2, "Corrected
    // 2026-09-06"). The runbook must therefore record the rustc that
    // actually ran, or the fleet binary's compiler is unknown.
    assert!(
        runbook.contains("rustc 1.94.1"),
        "\nINF-01 reproduced: deploy/FLAG-DAY-EPOCH-800.md records the build \
         environment as the floating tag `rust:1-bookworm` and never states \
         the rustc version that resolved inside it, while RELEASE-INTEGRITY.md \
         §2 pins 1.94.1 and §3 says a different rustc yields a different \
         binary. The fleet binary's compiler is undetermined from the tree.\n"
    );
}

// ── 4. The post-800 rebuilds recorded no binary hash at all ────────────────

#[test]
fn inf01_epoch_2700_rebuild_records_no_reference_hash() {
    let r2700 = read("deploy/FLAG-DAY-EPOCH-2700.md");
    assert!(
        r2700.contains("Deploy the rebuilt binary"),
        "premise moved: the 2700 runbook no longer describes a fleet-wide rebuild"
    );
    assert!(
        contains_binary_sha256(&r2700),
        "\nINF-01 reproduced: the epoch-2700 flag day rebuilt and redeployed all \
         64 validators (\"The rebuild is all-or-nothing\") and the runbook \
         records no sha256 of the deployed binary, no image digest and no \
         commit id beyond `d953fcc` \"on the round-4 branch\" — a commit that \
         is not in the public clone. The §4 sweep (\"must equal the published \
         release sha256\") has nothing to compare against.\n"
    );
}

// ── 5. The three documents contradict each other on the ship path ──────────

#[test]
fn inf01_dockerfile_header_release_runbook_and_flag_day_agree() {
    let dockerfile = read("Dockerfile");
    let integrity = read("deploy/RELEASE-INTEGRITY.md");
    let r800 = read("deploy/FLAG-DAY-EPOCH-800.md");

    let header_claims_signed_tarball =
        dockerfile.contains("from a signed release tarball");
    let no_signing_key_exists =
        integrity.contains("No release signing key exists yet");
    let fleet_ships_as_fly_image =
        r800.contains("| Fly (`bloch-g4`) | 49 | image update");

    assert!(
        !(header_claims_signed_tarball && no_signing_key_exists && fleet_ships_as_fly_image),
        "\nINF-01 reproduced: Dockerfile:15-17 says the fleet installs \
         `bloch-pos` \"as a systemd unit from a signed release tarball\"; \
         RELEASE-INTEGRITY.md §8.7 says no release signing key exists and no \
         box has one pinned; FLAG-DAY-EPOCH-800.md says 49/64 validators \
         receive an unsigned Fly image update. The path of record and the \
         path in use are different documents, and neither is in the tree.\n"
    );
}

// ── 6. The stamp an auditor would compare is caller-asserted ───────────────
//
// Not a failure of build.rs — it documents this itself — but it is the reason
// the absence above is not mitigated by `getbuildinfo`/`--version`: the
// builder chooses `commit` (BLOCH_BUILD_COMMIT) and controls the tree the
// digest is taken over, so a trojaned build reports whatever the builder
// wants. Pinned here so the mitigation cannot be claimed later without a
// code change that makes this test fail.
#[test]
fn inf01_build_identity_is_asserted_not_attested() {
    let build_rs = read("crates/bloch-pos-node/build.rs");
    let rpc_rs = read("crates/bloch-pos-node/src/rpc.rs");
    assert!(
        build_rs.contains("std::env::var(\"BLOCH_BUILD_COMMIT\")")
            && build_rs.contains("do not second-guess"),
        "build.rs no longer lets the caller assert the commit — re-evaluate INF-01 mitigation"
    );
    assert!(
        rpc_rs.contains("lets a caller assert any commit it likes")
            && rpc_rs.contains("not tamper-PROOF against a liar"),
        "rpc.rs no longer documents getbuildinfo as tamper-evident only — re-evaluate INF-01 mitigation"
    );
    // This test PASSES today: it records the limit, it does not fail on it.
}
