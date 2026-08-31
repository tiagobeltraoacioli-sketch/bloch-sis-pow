// SPDX-License-Identifier: AGPL-3.0-or-later

//! **The merge gate for consensus-state changes: replay a copy of the live
//! chain's `blocks.log` and reach its head with identical roots.**
//!
//! Why this test exists: the Coherence wave moved the shielded-pool state
//! into `CommittedState` behind the `COHERENCE_ACTIVATION_EPOCH` flag day
//! (`bloch-pos-committee/src/params.rs`). The claim that gate makes — "while
//! the epoch is below activation, the transition is **bit-identical** to what
//! the fleet runs" — cannot be proven by unit tests over synthetic chains; it
//! is a claim about the real log. This test proves it the only way it can be
//! proven: fold the actual mainnet log through the actual `apply_block`.
//!
//! The byte-exact check is not the printed summary line — it is INSIDE the
//! fold: `Transition::apply_block` refuses any block whose header
//! `state_root` differs from the recomputed post-state root (step 12), and
//! the engine's boot replay applies every logged block through it. A binary
//! whose committed state drifted by one byte anywhere since genesis stops at
//! that block; **reaching the logged head at all is the identity proof.**
//! The head-slot/root-prefix assertions below only pin *which* head was
//! reached, so a log truncated in transit cannot pass silently.
//!
//! ## Running it
//!
//! Needs artifacts only an operator has, so it is env-gated and reports
//! itself as skipped (loudly, on stderr) when they are absent:
//!
//! ```text
//! BLOCH_LIVE_REPLAY_DATADIR      dir holding blocks.log + meta.bin copied
//!                                from a live node (the test re-copies them
//!                                into a temp dir; the originals are never
//!                                opened for writing)
//! BLOCH_LIVE_REPLAY_GENESIS      the mainnet genesis manifest (genesis.json)
//! BLOCH_LIVE_REPLAY_CARRYOVER    carryover file, iff the manifest commits one
//! BLOCH_LIVE_REPLAY_EXPECT_SLOT  (optional) head slot the copy is known to hold
//! BLOCH_LIVE_REPLAY_EXPECT_ROOT8 (optional) first 8 hex chars of the head
//!                                state root, as `getchaininfo`/the boot line
//!                                print it
//! BLOCH_LIVE_REPLAY_TIMEOUT_SECS (optional) deadline, default 3600
//! ```
//!
//! Run it `--release`: the replay hashes hybrid PQ signatures for every
//! block, and a debug build against the real chain is hours, not minutes.
//!
//! ```text
//! BLOCH_LIVE_REPLAY_DATADIR=... BLOCH_LIVE_REPLAY_GENESIS=... \
//!   cargo test --release -p bloch-pos-node --test replay_live_gate -- --nocapture
//! ```

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_bloch-pos");

struct Node(Child);

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral")
        .local_addr()
        .expect("local addr")
        .port()
}

#[test]
fn a_copy_of_the_live_log_replays_to_its_head_with_identical_roots() {
    let Some(datadir) = std::env::var_os("BLOCH_LIVE_REPLAY_DATADIR") else {
        eprintln!(
            "replay_live_gate: SKIPPED — set BLOCH_LIVE_REPLAY_DATADIR (+ _GENESIS) to a copy \
             of a live node's data dir to run the merge gate"
        );
        return;
    };
    let genesis = PathBuf::from(
        std::env::var_os("BLOCH_LIVE_REPLAY_GENESIS")
            .expect("BLOCH_LIVE_REPLAY_DATADIR is set but BLOCH_LIVE_REPLAY_GENESIS is not"),
    );
    let src = PathBuf::from(datadir);
    let timeout = std::env::var("BLOCH_LIVE_REPLAY_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3600u64);

    // Work on a private copy: the node opens blocks.log with an append handle
    // and a reorg would rewrite it; the operator's copy stays pristine either
    // way, and the test stays re-runnable.
    let work = std::env::temp_dir().join(format!("bloch-replay-gate-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).expect("create work dir");
    for name in ["blocks.log", "meta.bin"] {
        let from = src.join(name);
        assert!(from.exists(), "{} not found in BLOCH_LIVE_REPLAY_DATADIR", name);
        std::fs::copy(&from, work.join(name)).expect("copy datadir artifact");
    }

    let listen = free_port().to_string();
    let mut args: Vec<String> = [
        "run",
        "--data-dir",
        work.to_str().unwrap(),
        "--genesis",
        genesis.to_str().unwrap(),
        "--listen",
        &listen,
        "--rpc-port",
        "off",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    if let Some(carry) = std::env::var_os("BLOCH_LIVE_REPLAY_CARRYOVER") {
        args.push("--carryover".into());
        args.push(PathBuf::from(carry).to_str().unwrap().into());
    }

    let mut child = Command::new(BIN)
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn bloch-pos");
    let stdout = child.stdout.take().expect("piped stdout");
    let mut node = Node(child);

    // The boot sequence prints exactly one of these before the network side
    // starts: "replayed {n} blocks: head slot {s}, state root {r8}, ...".
    // Progress lines ("replay {i}/{n} ...") stream before it on long logs.
    let deadline = Instant::now() + Duration::from_secs(timeout);
    let (done_tx, done_rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            eprintln!("[node] {line}");
            if line.starts_with("replayed ") || line.contains("bloch-pos: ") {
                let _ = done_tx.send(line);
                return;
            }
        }
        // Stream ended without the summary: the node exited mid-replay.
        let _ = done_tx.send(String::new());
    });
    let summary = done_rx
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .expect("replay did not finish before BLOCH_LIVE_REPLAY_TIMEOUT_SECS");
    drop(node.0.kill());

    assert!(
        summary.starts_with("replayed "),
        "boot ended without a replay summary — a logged block failed apply_block \
         (root/consensus divergence) or the node exited: `{summary}`"
    );

    // "replayed N blocks: head slot S, state root R8, justified eJ, finalized eF"
    let n: u64 = summary["replayed ".len()..]
        .split(' ')
        .next()
        .and_then(|w| w.parse().ok())
        .expect("malformed replay summary");
    assert!(n > 0, "the log copy replayed zero blocks — wrong file, not a passing gate");

    let field = |tag: &str| -> Option<String> {
        summary
            .split_once(tag)
            .map(|(_, rest)| rest.split([',', ' ']).next().unwrap_or("").to_string())
    };
    let head_slot = field("head slot ").expect("summary carries the head slot");
    let root8 = field("state root ").expect("summary carries the root prefix");

    if let Ok(want) = std::env::var("BLOCH_LIVE_REPLAY_EXPECT_SLOT") {
        assert_eq!(head_slot, want, "replayed head slot differs from the live copy's");
    }
    if let Ok(want) = std::env::var("BLOCH_LIVE_REPLAY_EXPECT_ROOT8") {
        assert_eq!(root8, want.to_lowercase(), "replayed head state root differs from the live copy's");
    }
    eprintln!(
        "replay_live_gate: PASSED — {n} blocks refolded through apply_block \
         (per-block root identity enforced inside the fold), head slot {head_slot}, \
         state root {root8}…"
    );
    let _ = std::fs::remove_dir_all(&work);
}
