// SPDX-License-Identifier: AGPL-3.0-or-later

//! The checkpoint-sync test: **a node bootstraps from a signed
//! weak-subjectivity checkpoint plus a downloaded state snapshot and reaches
//! the same chain as the nodes that replayed from genesis — without ever
//! applying a block from before its checkpoint.**
//!
//! `cold_start.rs` proves a third party can join by replaying everything.
//! This test proves the road that scales: the whole pipeline the docs
//! describe, executed for real —
//!
//! 1. two founders build and finalize a chain over libp2p;
//! 2. the ceremony tooling mints the epoch-2 checkpoint against their RPCs
//!    (`ws-checkpoint`), a 2-of-3 signer set signs it (`ws-keygen`,
//!    `ws-signer-set`, `ws-sign`, `ws-envelope`), and `ws-verify` accepts the
//!    envelope exactly as a booting node would;
//! 3. the boundary-state snapshot is exported by replay
//!    (`--export-state-epoch`) and placed in a founder's snapshot store;
//! 4. a fresh node — empty data dir, observer, no donated database — boots
//!    with `--ws-checkpoint … --state-sync`, DOWNLOADS the state from its
//!    peers in verified chunks, installs it only after the recomputed state
//!    root reproduces the checkpoint's, and syncs forward from the boundary.
//!
//! Asserted at the end:
//!
//! - the synced node installed the snapshot (its log says so, with the
//!   checkpoint's epoch);
//! - it applied NO block at or below the boundary slot — it started from the
//!   checkpoint, not from genesis;
//! - for every slot both it and a founder applied, block id AND post-state
//!   root agree — the "identical roots" claim, per common slot, exactly as
//!   `cold_start.rs` argues it must be compared.
//!
//! Wall-clock test with real sockets and real hybrid PQ signatures; the
//! chain must live long enough to finalize epoch 2 (~130 slots at 1 s), so
//! it runs for a few minutes. Deliberately tolerant about chain density —
//! identity, not cadence, is under test.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_bloch-pos");

const SLOT_MS: u64 = 1000;
/// Epoch the checkpoint attests. Its boundary block is the last block before
/// slot `2 * 32 = 64`.
const CHECKPOINT_EPOCH: u64 = 2;
/// Where every node stops. Finality can skip epochs (a missed epoch delays
/// the two-round rule, so "finalized >= 2" was measured arriving as late as
/// FINALIZED epoch 4, ~slot 190); the stop leaves the synced node room after
/// that plus ceremony time.
const STOP_SLOT: u64 = 300;
const GENESIS_START_IN_SECS: u64 = 6;

struct Fleet(Vec<Child>);

impl Drop for Fleet {
    fn drop(&mut self) {
        for c in &mut self.0 {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

fn tmp_root() -> PathBuf {
    let d = std::env::temp_dir().join(format!("bloch-pos-cksync-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("create test root");
    d
}

fn run_to_completion(args: &[&str]) -> String {
    let out = Command::new(BIN).args(args).output().expect("spawn bloch-pos");
    assert!(
        out.status.success(),
        "bloch-pos {args:?} failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let p = l.local_addr().expect("addr").port();
    drop(l);
    p
}

/// `slot -> (block id, post-state root)`, parsed from a node's own log
/// (same format and same rationale as `cold_start.rs`).
fn applied(log: &str) -> BTreeMap<u64, (String, String)> {
    let mut out = BTreeMap::new();
    for line in log.lines() {
        let Some(rest) = line.strip_prefix("[slot ") else { continue };
        let Some((slot_s, rest)) = rest.split_once("] applied ") else { continue };
        let Ok(slot) = slot_s.parse::<u64>() else { continue };
        let Some((id, rest)) = rest.split_once(" by v") else { continue };
        let Some((_, rest)) = rest.split_once("head root ") else { continue };
        let root = rest.split(',').next().unwrap_or_default();
        out.insert(slot, (id.to_string(), root.to_string()));
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn spawn_node(dir: &Path, genesis: &Path, listen: u16, rpc: u16, peers: &[u16], log: &Path, extra: &[&str]) -> Child {
    let peer_list = peers
        .iter()
        .map(|p| format!("/ip4/127.0.0.1/tcp/{p}"))
        .collect::<Vec<_>>()
        .join(",");
    let out = std::fs::File::create(log).expect("create log");
    let err = out.try_clone().expect("dup log");
    let mut args: Vec<String> = [
        "run",
        "--data-dir",
        dir.to_str().unwrap(),
        "--genesis",
        genesis.to_str().unwrap(),
        "--transport",
        "libp2p",
        "--p2p-listen",
        &format!("/ip4/127.0.0.1/tcp/{listen}"),
        "--p2p-peer",
        &peer_list,
        "--rpc-port",
        &rpc.to_string(),
        "--stop-at-slot",
        &STOP_SLOT.to_string(),
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    args.extend(extra.iter().map(|s| s.to_string()));
    Command::new(BIN)
        .args(&args)
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .expect("spawn node")
}

/// Wait until `log` reports `*** FINALIZED epoch N` with `N >= min_epoch`.
/// Finality can legitimately SKIP epochs (an epoch that misses justification
/// delays the two-round rule, and the next finalization jumps past it), so
/// this parses every finalization line rather than grepping for one literal
/// epoch — the first version did exactly that and timed out on a healthy
/// chain that finalized 1 and then 4.
fn wait_for_finalized(log: &Path, min_epoch: u64, for_secs: u64) {
    let deadline = Instant::now() + Duration::from_secs(for_secs);
    loop {
        if let Ok(s) = std::fs::read_to_string(log) {
            let best = s
                .lines()
                .filter_map(|l| l.strip_prefix("*** FINALIZED epoch "))
                .filter_map(|r| r.split_whitespace().next()?.parse::<u64>().ok())
                .max();
            if best.is_some_and(|b| b >= min_epoch) {
                return;
            }
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for finalized epoch >= {min_epoch} in {}:\n{}",
            log.display(),
            std::fs::read_to_string(log).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Recursive copy (the export replays a live founder's log from a copy, so
/// the running process's appends cannot race the replay).
fn copy_dir(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).expect("mkdir");
    for e in std::fs::read_dir(src).expect("read dir") {
        let e = e.expect("dir entry");
        let to = dst.join(e.file_name());
        if e.file_type().expect("ft").is_dir() {
            copy_dir(&e.path(), &to);
        } else {
            std::fs::copy(e.path(), &to).expect("copy");
        }
    }
}

#[test]
fn a_node_bootstraps_from_checkpoint_plus_downloaded_state_and_matches_the_replayers() {
    let root = tmp_root();
    let genesis = root.join("genesis.bin");

    // Three founding validators (a 2-of-3 quorum tolerates one missed vote
    // per epoch, which two validators cannot); the syncing node will be an
    // observer with an EMPTY data dir — no keystore, no donated database.
    for i in 0..3 {
        let dir = root.join(format!("d{i}"));
        run_to_completion(&["keygen", "--dir", dir.to_str().unwrap(), "--index", &i.to_string()]);
    }
    let keys = (0..3)
        .map(|i| root.join(format!("d{i}")).to_str().unwrap().to_string())
        .collect::<Vec<_>>()
        .join(",");
    run_to_completion(&[
        "genesis",
        "--keys",
        &keys,
        "--out",
        genesis.to_str().unwrap(),
        "--slot-ms",
        &SLOT_MS.to_string(),
        "--start-in",
        &GENESIS_START_IN_SECS.to_string(),
    ]);

    let ports: Vec<u16> = (0..4).map(|_| free_port()).collect();
    let rpc_ports: Vec<u16> = (0..4).map(|_| free_port()).collect();

    let mut fleet = Fleet(Vec::new());
    for i in 0..3 {
        fleet.0.push(spawn_node(
            &root.join(format!("d{i}")),
            &genesis,
            ports[i],
            rpc_ports[i],
            &ports[..3],
            &root.join(format!("n{i}.log")),
            &[],
        ));
    }

    // ── Wait until finality has passed the checkpoint epoch on BOTH RPC
    //    witnesses the mint will use. ──
    wait_for_finalized(&root.join("n0.log"), CHECKPOINT_EPOCH, 260);
    wait_for_finalized(&root.join("n1.log"), CHECKPOINT_EPOCH, 90);

    // ── Mint the checkpoint against both RPCs (they must agree). ──
    let ck_prefix = root.join("wsck");
    run_to_completion(&[
        "ws-checkpoint",
        "--genesis",
        genesis.to_str().unwrap(),
        "--rpc",
        &format!("127.0.0.1:{},127.0.0.1:{}", rpc_ports[0], rpc_ports[1]),
        "--epoch",
        &CHECKPOINT_EPOCH.to_string(),
        "--signer-set-id",
        "1",
        "--out",
        ck_prefix.to_str().unwrap(),
    ]);
    let ck_bin = root.join("wsck.bin");
    assert!(ck_bin.is_file(), "ws-checkpoint wrote no artifact");

    // ── The 2-of-3 ceremony, exactly as the runbook stages it. ──
    for name in ["s0", "s1", "s2"] {
        run_to_completion(&["ws-keygen", "--out", root.join(name).to_str().unwrap()]);
    }
    let set_path = root.join("signer-set-1.bin");
    run_to_completion(&[
        "ws-signer-set",
        "--id",
        "1",
        "--threshold",
        "2",
        "--min-external",
        "1",
        "--adopted-epoch",
        "0",
        "--signer",
        &format!("{}:internal", root.join("s0.pk").display()),
        "--signer",
        &format!("{}:internal", root.join("s1.pk").display()),
        "--signer",
        &format!("{}:external", root.join("s2.pk").display()),
        "--out",
        set_path.to_str().unwrap(),
    ]);
    for (name, sig) in [("s0", "sig0"), ("s2", "sig2")] {
        run_to_completion(&[
            "ws-sign",
            "--key",
            root.join(format!("{name}.sk")).to_str().unwrap(),
            "--pubkey",
            root.join(format!("{name}.pk")).to_str().unwrap(),
            "--checkpoint",
            ck_bin.to_str().unwrap(),
            "--out",
            root.join(sig).to_str().unwrap(),
        ]);
    }
    let envelope = root.join("wsck.envelope.bin");
    run_to_completion(&[
        "ws-envelope",
        "--checkpoint",
        ck_bin.to_str().unwrap(),
        "--sig",
        &format!("0:{}", root.join("sig0").display()),
        "--sig",
        &format!("2:{}", root.join("sig2").display()),
        "--out",
        envelope.to_str().unwrap(),
    ]);
    run_to_completion(&[
        "ws-verify",
        "--envelope",
        envelope.to_str().unwrap(),
        "--signer-set",
        set_path.to_str().unwrap(),
        "--genesis",
        genesis.to_str().unwrap(),
    ]);

    // ── Export the boundary state by replaying a COPY of founder 0's log,
    //    then place the artifact where the running founder serves it. ──
    let replay_dir = root.join("replay");
    copy_dir(&root.join("d0"), &replay_dir);
    let artifact = root.join("boundary.snap");
    let export_out = run_to_completion(&[
        "run",
        "--data-dir",
        replay_dir.to_str().unwrap(),
        "--genesis",
        genesis.to_str().unwrap(),
        "--listen",
        &free_port().to_string(),
        "--rpc-port",
        "off",
        "--export-state-epoch",
        &CHECKPOINT_EPOCH.to_string(),
        "--export-state-out",
        artifact.to_str().unwrap(),
    ]);
    // Parse ", state root <hex64>," and " (slot N)," from the export report.
    let state_root_hex = export_out
        .split("state root ")
        .nth(1)
        .and_then(|s| s.split(',').next())
        .expect("export printed the state root")
        .trim()
        .to_string();
    assert_eq!(state_root_hex.len(), 64, "export output changed shape:\n{export_out}");
    let boundary_slot: u64 = export_out
        .split("(slot ")
        .nth(1)
        .and_then(|s| s.split(')').next())
        .expect("export printed the boundary slot")
        .parse()
        .expect("boundary slot parses");
    assert!(boundary_slot < CHECKPOINT_EPOCH * 32, "boundary must precede the epoch");
    let store = root.join("d0/snapshots");
    std::fs::create_dir_all(&store).expect("snapshot store");
    std::fs::copy(&artifact, store.join(format!("{state_root_hex}.snap"))).expect("publish");

    // ── The synced node: empty dir, checkpoint + state download, no replay. ──
    let sync_dir = root.join("sync");
    std::fs::create_dir_all(&sync_dir).expect("sync dir");
    fleet.0.push(spawn_node(
        &sync_dir,
        &genesis,
        ports[3],
        rpc_ports[3],
        &ports[..3],
        &root.join("sync.log"),
        &[
            "--ws-checkpoint",
            envelope.to_str().unwrap(),
            "--ws-signer-set",
            set_path.to_str().unwrap(),
            "--state-sync",
        ],
    ));

    for c in &mut fleet.0 {
        let status = c.wait().expect("node exits");
        assert!(status.success(), "a node exited with {status}");
    }
    fleet.0.clear();

    let founder_log = std::fs::read_to_string(root.join("n0.log")).expect("founder log");
    let sync_log = std::fs::read_to_string(root.join("sync.log")).expect("sync log");
    let ctx = || format!("\n--- founder ---\n{founder_log}\n--- synced ---\n{sync_log}");

    // The snapshot was downloaded, verified and installed.
    assert!(
        sync_log.contains(&format!("state INSTALLED at checkpoint epoch {CHECKPOINT_EPOCH}")),
        "the node never installed the snapshot{}",
        ctx()
    );
    assert!(
        sync_log.contains("artifact verified"),
        "the downloaded artifact was never verified against the checkpoint{}",
        ctx()
    );

    let founder = applied(&founder_log);
    let synced = applied(&sync_log);

    // It started FROM the checkpoint: nothing at or below the boundary slot
    // was ever applied — the exact opposite of cold_start's assertion 1, and
    // the whole point of checkpoint sync.
    let below = synced.keys().filter(|s| **s <= boundary_slot).count();
    assert_eq!(
        below,
        0,
        "the synced node applied {below} blocks at or below its boundary slot \
         {boundary_slot} — it replayed history it was supposed to skip{}",
        ctx()
    );
    assert!(
        synced.len() >= 2,
        "the synced node applied only {} blocks after installing — it never followed the \
         chain forward{}",
        synced.len(),
        ctx()
    );

    // Identical chain, identical roots, at every common slot.
    let common: Vec<u64> = synced.keys().filter(|s| founder.contains_key(s)).copied().collect();
    assert!(
        common.len() >= 2,
        "only {} slots in common — not enough to compare{}",
        common.len(),
        ctx()
    );
    for slot in &common {
        assert_eq!(
            synced[slot], founder[slot],
            "synced node and founder disagree at slot {slot}: the checkpoint-synced state \
             did not continue into the same chain{}",
            ctx()
        );
    }

    let _ = std::fs::remove_dir_all(&root);
}
