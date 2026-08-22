//! The consensus firewall, enforced mechanically (BLOCH-VM-HOST §8).
//!
//! A live 64-validator PoS chain runs from this repository. This crate — and
//! every VM crate — must stay software, not consensus: nothing the node's
//! state-transition path compiles may reach bloch-vm-host, bloch-euvm, or
//! the future SVM crates. Wiring a VM into L1 stays gated on ADR-040 and
//! the SR-2 single-re-freeze rule (BLOCH-L1-EXECUTION-PLAN.md §SR-2); this
//! test turns that gate from a review item into a red build.
//!
//! Mechanism: `cargo metadata --no-deps` over the workspace root gives
//! every workspace member's DECLARED dependencies. We walk normal + build
//! edges (the ones that link code into the shipped `bloch-pos` binary or
//! its build) transitively across workspace members and assert the
//! consensus crates reach no VM crate. Dev edges are excluded by
//! construction: a dev-dependency never links into the shipped binary —
//! and this crate itself dev-depends on bloch-euvm for the §9.1 cross-KATs,
//! which is exactly the kind of edge the firewall must not confuse with a
//! runtime one.
//!
//! §9.5 mutation check: the reachability walker and the edge filter are
//! plain functions, and the CONTROL tests below feed them synthetic graphs
//! where the forbidden edge EXISTS — so neutering the walker (early return,
//! dropped `build` kind, skipped transitivity) reddens a control test
//! rather than silently passing the firewall forever.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::process::Command;

/// The crates that constitute the node's state-transition path today.
const CONSENSUS_ROOTS: &[&str] = &["bloch-pos-node", "bloch-pos-committee"];

/// The VM plane: this crate + every VM crate, present or planned (spec §8).
/// Names of crates with zero code today are listed anyway — the firewall is
/// in force from their first commit, not from when someone remembers it.
const VM_PLANE: &[&str] = &["bloch-vm-host", "bloch-euvm", "bloch-sbpf", "bloch-svm"];

/// Adjacency map `package -> {dep package}` keeping only edges that link
/// into a shipped artifact: kind `null` (normal) and `"build"`. Kind
/// `"dev"` is dropped — see the module doc for why that is load-bearing.
fn runtime_edges(metadata: &serde_json::Value) -> BTreeMap<String, BTreeSet<String>> {
    let mut edges: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for pkg in metadata["packages"].as_array().expect("packages array") {
        let name = pkg["name"].as_str().expect("package name").to_string();
        let entry = edges.entry(name).or_default();
        for dep in pkg["dependencies"].as_array().expect("dependencies array") {
            let kind = &dep["kind"];
            let is_runtime = kind.is_null() || kind.as_str() == Some("build");
            if is_runtime {
                entry.insert(dep["name"].as_str().expect("dep name").to_string());
            }
        }
    }
    edges
}

/// Breadth-first reachability over `edges` from `from` to `to`. External
/// (non-workspace) deps appear as edge targets without their own adjacency
/// entry and terminate naturally — a crates.io package cannot depend back
/// on a path-only workspace crate, so paths through them cannot exist.
fn reaches(edges: &BTreeMap<String, BTreeSet<String>>, from: &str, to: &str) -> bool {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut queue: VecDeque<&str> = VecDeque::new();
    queue.push_back(from);
    while let Some(cur) = queue.pop_front() {
        if cur == to {
            return true;
        }
        if !seen.insert(cur) {
            continue;
        }
        if let Some(nexts) = edges.get(cur) {
            for n in nexts {
                queue.push_back(n.as_str());
            }
        }
    }
    false
}

/// `cargo metadata --no-deps` at the workspace root (two levels above this
/// crate's manifest). `--no-deps` keeps it hermetic: no network, no
/// registry resolution — only the workspace's own declared manifests.
fn workspace_metadata() -> serde_json::Value {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.toml");
    let out = Command::new(env!("CARGO"))
        .args(["metadata", "--format-version", "1", "--no-deps", "--manifest-path", root])
        .output()
        .expect("cargo metadata must run");
    assert!(
        out.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("cargo metadata emits JSON")
}

// ────────────────────────────────────────────────────────────────────────────
// The firewall itself
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn consensus_crates_reach_no_vm_crate() {
    let metadata = workspace_metadata();
    let edges = runtime_edges(&metadata);
    for root in CONSENSUS_ROOTS {
        assert!(
            edges.contains_key(*root),
            "{root} missing from workspace metadata — the firewall cannot see \
             the consensus crates it exists to guard; fix the members list or \
             this test before anything merges"
        );
        for vm in VM_PLANE {
            assert!(
                !reaches(&edges, root, vm),
                "CONSENSUS FIREWALL BREACH: {root} reaches {vm} in the runtime \
                 dependency graph. The VM plane is software, not consensus \
                 (docs/specs/BLOCH-VM-HOST.md §8); wiring a VM into the node's \
                 state-transition path is gated on ADR-040 and the SR-2 \
                 single-re-freeze rule (BLOCH-L1-EXECUTION-PLAN.md). Remove \
                 the dependency; do not weaken this test."
            );
        }
    }
}

/// Guard against vacuity: the walker must actually SEE this crate. If
/// bloch-vm-host ever leaves the workspace members list, the firewall test
/// above would pass because the name matches nothing — this control makes
/// that failure loud instead.
#[test]
fn control_vm_host_is_visible_to_the_walker() {
    let metadata = workspace_metadata();
    let edges = runtime_edges(&metadata);
    assert!(
        edges.contains_key("bloch-vm-host"),
        "bloch-vm-host not in workspace metadata — restore it to the root \
         members list (root Cargo.toml forbids private workspaces)"
    );
    assert!(
        edges.contains_key("bloch-euvm"),
        "bloch-euvm not in workspace metadata"
    );
}

/// CONTROL (real graph): reachability does find edges that exist —
/// bloch-pos-node declares bloch-pos-committee (crates/bloch-pos-node/
/// Cargo.toml [dependencies]). A walker mutated into "return false" passes
/// the firewall vacuously; this test is what dies instead.
#[test]
fn control_walker_finds_the_real_node_to_committee_edge() {
    let metadata = workspace_metadata();
    let edges = runtime_edges(&metadata);
    assert!(
        reaches(&edges, "bloch-pos-node", "bloch-pos-committee"),
        "walker failed to find a dependency that exists — it cannot be \
         trusted to prove the absence of forbidden ones"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// §9.5 — the firewall's own mutation checks, as synthetic-graph controls
// ────────────────────────────────────────────────────────────────────────────

/// CONTROL (synthetic): a planted TRANSITIVE runtime path node → x →
/// vm-host must be detected. Kills mutations that drop transitivity
/// (checking only direct deps) or early-return false.
#[test]
fn control_synthetic_transitive_breach_is_detected() {
    let mut edges: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    edges.entry("bloch-pos-node".into()).or_default().insert("x".into());
    edges.entry("x".into()).or_default().insert("bloch-vm-host".into());
    assert!(reaches(&edges, "bloch-pos-node", "bloch-vm-host"));
    // ...and its negative twin: absent the planted edge, no path.
    let mut clean = edges.clone();
    clean.get_mut("x").unwrap().clear();
    assert!(!reaches(&clean, "bloch-pos-node", "bloch-vm-host"));
}

/// CONTROL (synthetic): a dependency CYCLE must not hang the walker, and
/// unreachable targets stay unreachable through it.
#[test]
fn control_synthetic_cycle_terminates() {
    let mut edges: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    edges.entry("a".into()).or_default().insert("b".into());
    edges.entry("b".into()).or_default().insert("a".into());
    assert!(!reaches(&edges, "a", "bloch-vm-host"));
    assert!(reaches(&edges, "a", "b"));
}

/// CONTROL (synthetic metadata): the edge filter keeps normal and build
/// kinds and drops dev — each kind pinned individually, so flipping the
/// filter in any direction reddens this test. This is the §9.5 "adding the
/// dep must make the assertion fire" check in its testable form: the
/// forbidden dep is present in the manifest-shaped input, and detection is
/// asserted per kind.
#[test]
fn control_edge_filter_kinds() {
    let metadata: serde_json::Value = serde_json::json!({
        "packages": [{
            "name": "bloch-pos-node",
            "dependencies": [
                { "name": "normal-dep", "kind": null },
                { "name": "build-dep",  "kind": "build" },
                { "name": "bloch-vm-host", "kind": "dev" },
            ],
        }]
    });
    let edges = runtime_edges(&metadata);
    let node = &edges["bloch-pos-node"];
    assert!(node.contains("normal-dep"), "normal deps are runtime edges");
    assert!(node.contains("build-dep"), "build deps are runtime edges");
    assert!(
        !node.contains("bloch-vm-host"),
        "dev deps must NOT count as runtime edges (this crate itself \
         dev-depends on bloch-euvm for the cross-KATs)"
    );
    // Negative twin: promote the SAME dep to a normal edge and the
    // firewall condition fires — the filter, not the name, decided above.
    let metadata2: serde_json::Value = serde_json::json!({
        "packages": [{
            "name": "bloch-pos-node",
            "dependencies": [ { "name": "bloch-vm-host", "kind": null } ],
        }]
    });
    let edges2 = runtime_edges(&metadata2);
    assert!(reaches(&edges2, "bloch-pos-node", "bloch-vm-host"));
}
