// SPDX-License-Identifier: AGPL-3.0-or-later

//! The cold-node test: **a new node builds the chain itself, from genesis.**
//!
//! This is the one test that answers the question an exchange asks before it
//! will credit a deposit:
//!
//! > *"As an exchange we must run our own validating node — we cannot credit
//! > customer deposits based on a chain view we did not verify ourselves."*
//!
//! On Genesis-3 the answer is no, permanently: `docs/CARRYOVER.md` says syncing
//! from genesis is unsupported, and the block bodies such a sync would need
//! were dropped network-wide before the retention fix. A node bootstrapped from
//! the producer's datadir has verified nothing, and no test can change that.
//!
//! Here, three real `bloch-pos` processes run over the **libp2p transport**.
//! Two start at genesis. The third starts late with a data dir that holds
//! **only its own keystore** — no `blocks.log`, no `meta.bin`, nothing copied
//! from anyone. It must reach the same chain by asking peers for blocks and
//! validating every one of them through the same `Transition::apply_block` the
//! producers ran.
//!
//! What is asserted, and why each assertion is the honest one:
//!
//! 1. The cold node applied blocks from slots **before it existed** — so it
//!    walked history rather than merely following the live tip.
//! 2. For every slot both it and a founding node applied, the **block id and
//!    the post-state root agree**. That is state-root equality at a common
//!    point, which is what "we verified it ourselves and got the same answer"
//!    means. It is compared per slot rather than at the final head on purpose:
//!    nodes stop at a wall-clock slot and the last block can legitimately land
//!    on one node and not another, so a final-root comparison would be a race,
//!    not a proof.
//! 3. The two block logs agree byte-for-byte over their common prefix. The
//!    transition is deterministic (pinned by the pure crate), so identical
//!    inputs in identical order are identical state — this is the same claim as
//!    (2) made over the persisted artifact.
//!
//! It is a wall-clock test with real sockets and real post-quantum signatures,
//! so it takes roughly a minute and is deliberately tolerant about *how much*
//! chain gets built — the consensus cadence under a debug build on a loaded
//! machine is not what is under test.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_bloch-pos");

/// Slot cadence for the test chain. Fast enough to finish, slow enough that a
/// debug build with hybrid ML-DSA-65 ‖ Falcon-1024 signing keeps up.
const SLOT_MS: u64 = 1000;
/// Where the run stops. Must leave the cold node enough slots after it joins.
const STOP_SLOT: u64 = 45;
/// Seconds the genesis manifest puts between `genesis` and slot 0.
const GENESIS_START_IN_SECS: u64 = 6;
/// How long after launching the founders the cold node is started, in seconds.
const COLD_START_DELAY_SECS: u64 = 18;
/// The slot the chain has reached when the cold node's process begins. Blocks
/// at earlier slots cannot have been gossiped to it live — it can only have
/// them by asking a peer for history and validating what came back.
const COLD_JOIN_SLOT: u64 = (COLD_START_DELAY_SECS - GENESIS_START_IN_SECS) * 1000 / SLOT_MS;

struct Fleet(Vec<Child>);

impl Drop for Fleet {
    fn drop(&mut self) {
        // A panicking assertion must not leave validator processes running.
        for c in &mut self.0 {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

fn tmp_root() -> PathBuf {
    let d = std::env::temp_dir().join(format!("bloch-pos-coldstart-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("create test root");
    d
}

fn run_to_completion(args: &[&str]) -> String {
    let out = Command::new(BIN).args(args).output().expect("spawn bloch-pos");
    assert!(
        out.status.success(),
        "bloch-pos {args:?} failed: {}",
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

/// `slot -> (block id, post-state root)`, parsed out of a node's own log.
///
/// The line is the node's account of what it applied and what state it reached:
/// `[slot 12] applied 14df0967 by v1 — head root cd7612c4, …`
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

fn spawn_node(
    dir: &Path,
    genesis: &Path,
    listen: u16,
    peers: &[u16],
    log: &Path,
) -> Child {
    let peer_list = peers
        .iter()
        .map(|p| format!("/ip4/127.0.0.1/tcp/{p}"))
        .collect::<Vec<_>>()
        .join(",");
    let out = std::fs::File::create(log).expect("create log");
    let err = out.try_clone().expect("dup log");
    Command::new(BIN)
        .args([
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
            // Three nodes on one machine: the RPC's default port is a single
            // number, so leaving it on would have two of them fail to bind and
            // exit. A real operator gives each node its own; the test does the
            // same rather than disabling the server and testing less.
            "--rpc-port",
            &(listen + 1000).to_string(),
            "--stop-at-slot",
            &STOP_SLOT.to_string(),
        ])
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .expect("spawn node")
}

#[test]
fn a_cold_node_builds_the_same_chain_from_genesis_without_a_donated_datadir() {
    let root = tmp_root();
    let genesis = root.join("genesis.bin");

    // Three validator keystores. `keygen` is explicitly throwaway devnet key
    // material; nothing here generates or touches a production key.
    for i in 0..3 {
        let dir = root.join(format!("d{i}"));
        run_to_completion(&[
            "keygen",
            "--dir",
            dir.to_str().unwrap(),
            "--index",
            &i.to_string(),
        ]);
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

    let ports: Vec<u16> = (0..3).map(|_| free_port()).collect();
    let all: Vec<u16> = ports.clone();

    let mut fleet = Fleet(Vec::new());
    for i in 0..2 {
        fleet.0.push(spawn_node(
            &root.join(format!("d{i}")),
            &genesis,
            ports[i],
            &all,
            &root.join(format!("n{i}.log")),
        ));
    }

    // The cold node joins late. Its data dir holds `validator.key` and nothing
    // else — no block log, no meta marker, no state. That is the whole point:
    // it is not handed a database, it is handed a genesis manifest and a set of
    // peers, exactly like an exchange standing up a node today.
    std::thread::sleep(Duration::from_secs(COLD_START_DELAY_SECS));
    let cold_dir = root.join("d2");
    let cold_files: Vec<String> = std::fs::read_dir(&cold_dir)
        .expect("read cold dir")
        .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
        .collect();
    assert_eq!(
        cold_files,
        vec!["validator.key".to_string()],
        "the cold node's data dir must contain only its own keystore, not a donated database"
    );
    fleet.0.push(spawn_node(
        &cold_dir,
        &genesis,
        ports[2],
        &all,
        &root.join("n2.log"),
    ));

    for c in &mut fleet.0 {
        let status = c.wait().expect("node exits");
        assert!(status.success(), "a node exited with {status}");
    }
    fleet.0.clear();

    let logs: Vec<String> = (0..3)
        .map(|i| std::fs::read_to_string(root.join(format!("n{i}.log"))).expect("read log"))
        .collect();
    let founder = applied(&logs[0]);
    let cold = applied(&logs[2]);

    let ctx = || {
        format!(
            "\n--- founder log ---\n{}\n--- cold log ---\n{}",
            logs[0], logs[2]
        )
    };

    // Thresholds are deliberately minimal. How MUCH chain three debug-build
    // nodes with hybrid post-quantum signing manage to produce in 45 seconds
    // depends on how loaded the machine is, and that is not what is under
    // test — the claim is about the identity of the chain the cold node built,
    // not its density. An earlier version of this test asserted eight blocks
    // and failed only when it ran next to a workspace build.
    assert!(
        cold.len() >= 3,
        "the cold node applied only {} blocks — it never caught up{}",
        cold.len(),
        ctx()
    );

    // 1. It walked history. Two claims, neither of which depends on how fast
    //    the chain grew: the cold node's earliest block is no later than the
    //    founder's earliest (so it started where the chain started), and at
    //    least one of its blocks predates its own process (so that block could
    //    only have come from a peer's log, validated on arrival).
    let first_cold_slot = *cold.keys().next().expect("cold node applied something");
    let first_founder_slot = *founder.keys().next().expect("founder applied something");
    assert!(
        first_cold_slot <= first_founder_slot,
        "the cold node starts at slot {first_cold_slot} but the chain starts at \
         {first_founder_slot}: it followed the live tip instead of syncing from genesis{}",
        ctx()
    );
    let before_it_existed = cold.keys().filter(|s| **s < COLD_JOIN_SLOT).count();
    assert!(
        before_it_existed >= 1,
        "the cold node applied nothing from before slot {COLD_JOIN_SLOT}, when its process \
         started — nothing here proves it synced history{}",
        ctx()
    );

    // 2. Where both nodes applied a block for the same slot, they must agree on
    //    which block it was AND on the state it produced.
    let common: Vec<u64> = cold.keys().filter(|s| founder.contains_key(s)).copied().collect();
    assert!(
        common.len() >= 2,
        "only {} slots in common — not enough to compare{}",
        common.len(),
        ctx()
    );
    for slot in &common {
        assert_eq!(
            cold[slot], founder[slot],
            "cold node and founder disagree at slot {slot}: the independently rebuilt state \
             is not the same state{}",
            ctx()
        );
    }

    // 3. The persisted inputs agree over their common prefix. The transition is
    //    deterministic, so this is the same claim as (2) about the artifact on
    //    disk rather than about a log line.
    let a = std::fs::read(root.join("d0/blocks.log")).expect("founder block log");
    let b = std::fs::read(cold_dir.join("blocks.log")).expect("cold block log");
    let n = a.len().min(b.len());
    assert!(n > 0, "one of the block logs is empty");
    assert_eq!(
        &a[..n],
        &b[..n],
        "the block logs diverge: the cold node stored a different chain"
    );

    let _ = std::fs::remove_dir_all(&root);
}
