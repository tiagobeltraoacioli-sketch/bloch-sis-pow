//! Regression guard for audit finding SC3-yamux-dedupe (Round 2).
//!
//! The defect: Cargo.lock carried yamux 0.12.1 (GHSA-vxx9-2994-q338, CVSS
//! 8.7, remote DoS reachable by any peer) next to the fixed 0.13.10, and
//! libp2p-yamux 0.47.0 switched the LIVE muxer onto the 0.12 copy the moment
//! `set_max_num_streams` ran — which bloch-pos-node's p2p bootstrap does.
//!
//! The fix: the vendored crate this test ships with (see ../Cargo.toml)
//! removes the 0.12 backend, and the workspace [patch.crates-io] points
//! libp2p-yamux at it. This test fails on the UNFIXED graph (drop the patch,
//! `cargo update`, and yamux 0.12.1 plus a registry libp2p-yamux reappear in
//! the lock) — mutation-verified.
//!
//! It parses Cargo.lock with plain string handling on purpose: a TOML crate
//! here would itself add dependency-graph surface.

use std::path::Path;

/// (name, version, source) triples from the workspace Cargo.lock.
fn lock_packages() -> Vec<(String, String, String)> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let lock_path = Path::new(manifest_dir).join("../../Cargo.lock");
    let lock = std::fs::read_to_string(&lock_path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", lock_path.display()));

    let mut out = Vec::new();
    for block in lock.split("[[package]]").skip(1) {
        let field = |key: &str| -> String {
            block
                .lines()
                .find_map(|l| l.strip_prefix(&format!("{key} = \"")))
                .and_then(|rest| rest.strip_suffix('"'))
                .unwrap_or("")
                .to_string()
        };
        out.push((field("name"), field("version"), field("source")));
    }
    assert!(
        out.len() > 100,
        "Cargo.lock parse looks broken: only {} packages found",
        out.len()
    );
    out
}

fn semver(v: &str) -> (u64, u64, u64) {
    let mut it = v.split(['.', '-', '+']).take(3).map(|p| p.parse().unwrap_or(0));
    (
        it.next().unwrap_or(0),
        it.next().unwrap_or(0),
        it.next().unwrap_or(0),
    )
}

/// GHSA-vxx9-2994-q338: exactly one yamux in the graph, and it is >= 0.13.10.
/// Two yamux entries means the vulnerable dual-backend graph is back.
#[test]
fn exactly_one_yamux_and_it_is_at_least_0_13_10() {
    let yamuxes: Vec<_> = lock_packages()
        .into_iter()
        .filter(|(n, _, _)| n == "yamux")
        .collect();

    assert_eq!(
        yamuxes.len(),
        1,
        "Cargo.lock must contain exactly ONE yamux; a second copy re-opens \
         GHSA-vxx9-2994-q338 (libp2p-yamux silently runs connections on the \
         0.12 line once any config setter is used). Found: {yamuxes:?}"
    );

    let v = &yamuxes[0].1;
    assert!(
        semver(v) >= (0, 13, 10),
        "yamux {v} < 0.13.10: GHSA-vxx9-2994-q338 (CVSS 8.7, remote DoS) is \
         unfixed below 0.13.10"
    );
}

/// The patch must actually be in effect: libp2p-yamux resolving from the
/// registry means the vendored fork (which removed the 0.12 backend) is NOT
/// what links into the node.
#[test]
fn libp2p_yamux_is_the_vendored_fork_not_the_registry_crate() {
    let entries: Vec<_> = lock_packages()
        .into_iter()
        .filter(|(n, _, _)| n == "libp2p-yamux")
        .collect();

    assert_eq!(entries.len(), 1, "one libp2p-yamux expected: {entries:?}");
    assert!(
        entries[0].2.is_empty(),
        "libp2p-yamux resolves from `{}` instead of the vendored path crate — \
         the [patch.crates-io] in the root Cargo.toml is not in effect, so \
         the yamux-0.12 backend (GHSA-vxx9-2994-q338) is linked back in",
        entries[0].2
    );
}
