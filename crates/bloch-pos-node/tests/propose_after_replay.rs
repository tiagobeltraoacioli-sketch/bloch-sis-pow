// SPDX-License-Identifier: AGPL-3.0-or-later

//! **A validator emerging from replay must not propose on the head it
//! replayed to.**
//!
//! This is the mechanism that cost v10 and v63. It is not a race and it is not
//! load: it is a grace period measured from the wrong instant, and on mainnet
//! it is spent with certainty before it can ever do its job.
//!
//! ─────────────────────────────────────────────────────────────────────────
//! # 1. The defect, in five lines of `engine.rs`
//!
//! ```text
//! 2298:   live: false            // engine constructed
//! 2301:   booted_ms: now_ms()    // the grace clock is stamped HERE
//! 2350:   engine.live = true     // set AFTER the replay loop
//! 2520:   let in_grace = now.saturating_sub(engine.booted_ms) < 2 * slot_ms;
//! 2527:   if !in_grace && now >= propose_at && slot > last_built { …propose… }
//! ```
//!
//! `booted_ms` is stamped at construction, forty-nine lines *above* the point
//! where replay ends. The grace is two slots — 60 s at the mainnet cadence.
//! Mainnet replay takes 16–26 minutes. So on every real restart the grace is
//! already fully spent by the time the node is capable of doing anything at
//! all, and the first thing it does on emerging is take its next proposing
//! duty on a head that is however many minutes stale.
//!
//! Two further details make the window worse than it looks, and both are
//! visible in the same loop:
//!
//! * **The queue is not drained first.** The transport is started *before*
//!   replay (`engine.rs` ~2240), so blocks gossiped during those minutes are
//!   already sitting in `rx`. The loop's order is grace-check, attest,
//!   propose, sync, *then* `rx.recv_timeout`. The node therefore proposes on
//!   the stale head while the network's real head is in its own inbox.
//! * **The sync request is held back longer than the proposal is.** `behind`
//!   requires `now - last_applied_ms > 2 * slot_ms`, and `last_applied_ms` was
//!   refreshed by the *last block of replay*. So the node is allowed to
//!   propose immediately and not allowed to ask for blocks for two more slots.
//!
//! # 2. Why the damage sticks, and why this file does not assert on it
//!
//! Once the stale-head block is applied, the node's own head slot is the wall
//! slot. `behind` is now false, so it will never ask again; `behind_by_slots`
//! reads **0**, so every monitor calls it healthy. The only remaining route
//! back is `needs_sync`, set when a gossiped block's lineage is missing — and
//! that depends on gossip arriving from a mesh the node has only just started
//! dialling. When it does not, the node extends its own branch at every duty
//! and stays there. That is v63: three repairs handed it a good store and
//! restarted the same binary, which ran the same five lines again.
//!
//! Whether the fork *sticks* depends on mesh timing and host load, so this
//! file does not assert on it. It asserts on the **cause**, which is
//! deterministic: a block proposed on a parent tens of slots below its own
//! slot. A test that waited for the wedge would be a test of the host.
//!
//! # 3. Reproducing it deterministically, without faking it
//!
//! The obvious reproduction — restart a validator behind the chain and watch —
//! is a race, and it was MEASURED to be one. First run of this file, debug
//! build, four validators: the node emerged from replay with nine blocks
//! already queued from the peers it had connected to *during* replay, spent
//! ~30 s applying them (this build needs seconds per block), and by the time it
//! returned to the top of the slot loop it was at the tip. It never proposed on
//! the stale head — not because the defect is not there, but because the engine
//! thread was too busy to reach a duty. Whether the failure appears at all is a
//! coin toss on whether the node holds a proposing duty in the one slot between
//! replay ending and its inbox draining.
//!
//! So the reproduction removes the coin toss without touching the node: **the
//! founders are stopped while the validator replays.** Its inbox is then empty
//! when it emerges, and it holds that stale head across many slots — long
//! enough to hold real duties, several proposing and at least one attesting
//! (committees partition the active set, so a validator gets exactly one
//! attesting duty per epoch). Nothing about the node changes: same data dir,
//! same configured peers, no flags. It is isolated by nothing except that its
//! peers are not answering, which is precisely the state a validator is in for
//! the first seconds after any restart, and the state v63 was in.
//!
//! This is different from `probe/warm-start-validator`, which isolates a node
//! by *configuration* — started with no `--p2p-peer` at all. That produces a
//! rival branch reliably and was the right tool for its question. Here the
//! peers are configured and the node knows it; what it does not have is an
//! answer from any of them. That distinction is the whole subject: a node that
//! has been told nothing must not act as though it had been told it is at the
//! head. The harness below is `warm_join.rs`'s, borrowed wholesale — the RPC
//! client, `Chain`, `first_disagreement`, `founders_fractured`, the sampling
//! budget, and the reasons for all of them.
//!
//! # 4. What the assertions are
//!
//! 1. **Precondition.** Replay outlasted the two-slot grace. Asserted, because
//!    a run where it did not proves nothing and must not pass quietly.
//! 2. **The gate.** Across `SILENT_WINDOW_SLOTS` with its peers down, the
//!    restarted validator signs **nothing** — no block, no attestation. This is
//!    the assertion the defect fails: the old grace is spent inside replay, so
//!    a defective build takes its duties here, on a head tens of slots stale.
//! 3. **Not vacuous.** Once the founders come back, the validator must go on to
//!    propose `MIN_PROPOSALS_AFTER_RESTART` blocks that the founders *adopt*. A
//!    gate that silenced a validator forever would satisfy (2) and is not the
//!    fix; this is what separates the two, and it is why the test costs what it
//!    costs.
//! 4. **It stepped over almost nothing.** For every block it proposed, the
//!    founders' canonical chain holds at most `MAX_BLOCKS_SKIPPED` blocks
//!    between that block's parent and itself. This is what "stale head" means
//!    after the fact, once three simpler formulations have been ruled out by
//!    measurement — see that constant. A secondary guard: (2) is the one that
//!    discriminates, and it needs no threshold. Its proposals are read from its
//!    own stdout, which now carries the parent's slot — a field added for this,
//!    because `behind_by_slots` reads 0 the instant a stale-head block lands.
//! 5. **No divergence.** At every slot both sides sampled, they hold the same
//!    block.
//!
//! # 5. Cost, and the ceiling on the run
//!
//! Four real nodes signing hybrid ML-DSA-65 ‖ Falcon-1024. Run with
//! `--test-threads=1`. This build needs seconds per signature, which is why
//! `SLOT_MS` is what it is: at 1 s the fleet produced one block per ten slots
//! and every duty was a race against the engine thread. The whole run is kept
//! under ~250 slots because a devnet on this build stops agreeing with itself
//! past slot ~300 with nobody joining and nothing to blame — see
//! `founders_fractured`, inherited verbatim from `warm_join.rs` along with its
//! measurements. A run that lands in that regime reports VOID rather than
//! failing, because no claim about the subject can be made from inside it.
//!
//! Nothing here reads, generates near, or touches production or treasury key
//! material: `keygen` makes throwaway devnet keys under a temp dir.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_bloch-pos");

/// Mirrors `bloch_pos_committee::params::SLOTS_PER_EPOCH`. Restated rather
/// than imported because `bloch-pos` is a binary crate and `tests/` cannot
/// reach into `src/`. Pinned by `slots_per_epoch_matches_the_node`.
const SLOTS_PER_EPOCH: u64 = 32;

/// Slot cadence.
///
/// Four seconds, and the number is MEASURED rather than chosen. A debug build
/// signing hybrid ML-DSA-65 ‖ Falcon-1024 needs roughly 3.5 s to produce or
/// replay one block: a single-validator chain left running for 400 slots at
/// 200 ms produced **10 blocks**, and replaying those 10 took **35 s**. At the
/// 1 s cadence this file first used, the fleet therefore produced about one
/// block per ten slots and no duty could be relied on to happen at all. At 4 s
/// a slot comfortably exceeds the cost of a duty, so proposals land in the slot
/// they belong to and the run is about the gate rather than about the CPU.
const SLOT_MS: u64 = 4000;

/// Seconds the genesis manifest puts between `genesis` and slot 0.
const GENESIS_START_IN_SECS: u64 = 6;

const VALIDATORS: usize = 4;
const FOUNDERS: usize = 3;

/// Index of the validator that gets stopped and restarted, and of its data
/// dir `d3`.
const RESTARTED: usize = 3;

/// Wall slot the fleet must reach before the restarted validator is stopped.
///
/// This is what fills its block log, and replaying it has to outlast the
/// two-slot grace — the whole precondition. MEASURED on this host: this build
/// replays a block in ~170 ms at devnet state size, so 30 blocks took 5.2 s
/// against an 8 s grace and the run correctly refused to conclude anything.
/// Three epochs of a fleet producing one block per slot is ~96 blocks, ~17 s,
/// which clears it with room. (Mainnet needs no such arrangement: 0.59 s per
/// block over 12,000 blocks is where the sixteen-to-twenty-six minutes comes
/// from.)
///
/// The run asserts the outcome rather than trusting this number, so a faster
/// host that replays inside the grace fails loudly instead of passing for the
/// wrong reason.
const BUILDUP_UNTIL_SLOT: u64 = 3 * SLOTS_PER_EPOCH;

/// Slots the founders run on alone while the restarted validator is down.
///
/// The size of the staleness, in blocks the network moved on by. It has to be
/// far above `MAX_BLOCKS_SKIPPED` so that "built on a head tens of blocks old"
/// and "missed the last block to propagation" cannot be the same measurement.
/// MEASURED on the defect: eighteen canonical blocks between the parent it
/// built on and the block it built.
const AWAY_SLOTS: u64 = 20;

/// Slots the restarted validator is watched for while its peers are DOWN.
///
/// It must hold real duties in this window or assertion (2) is vacuous, and it
/// must end before `CATCHUP_ALONE_SLOTS` (two epochs, 64 slots) or the gate's
/// deliberate fail-open floor releases the node and the window stops being a
/// test of the gate.
///
/// Forty-eight: one and a half epochs. Committees partition the active set
/// across an epoch's 32 slots, so a validator holds **exactly one** attesting
/// duty per epoch — at least one lands here by construction, not by luck. With
/// four validators the proposer rotation gives it about twelve proposing duties
/// in the same window, so `0.75^12 ≈ 3%` is the chance a defective build gets
/// through on the proposing half alone, and the attesting half has no chance
/// element at all.
const SILENT_WINDOW_SLOTS: u64 = 48;

/// Canonical blocks the network may hold between a proposal's parent and the
/// proposal itself before the proposer counts as having built on a stale head.
///
/// The unit is BLOCKS SKIPPED, not slots, and that took three tries to get
/// right. MEASURED, each failure on a run where the fix was working:
///
/// * "the parent is within N slots" — WRONG. After the founders come back the
///   chain has a real hole where every node was down, so the first block
///   legitimately sits ~74 slots above its parent while skipping nothing.
/// * "the block is on the founders' canonical chain" — WRONG. v3 released at
///   182 and proposed at 187 on the true tip; n2 released at 187 and proposed
///   at 188 on the SAME parent before v3's block reached it. Fork choice kept
///   n2's. An honest proposer can lose a race.
/// * "the network held NOTHING in between" — WRONG. v3 proposed at 196 on a
///   parent at 193 while a block existed at 195. One block of propagation lag,
///   on a build that needs seconds per block, is ordinary.
///
/// What separates the regimes is the COUNT. Ordinary lag skips one block,
/// occasionally two when several validators come back at once and publish into
/// the same slot. The defect skipped **eighteen** — its fork at slot 150 sat on
/// a parent at 102 with the founders holding blocks at 103..120. Four is above
/// everything measured as honest here and four and a half times below the
/// defect, so it separates them without being tuned to either.
///
/// This is the SECONDARY guard. The load-bearing assertion is the silent
/// window, which is threshold-free: across 48 slots with its peers down the
/// validator signs nothing, and the defective build signs there.
const MAX_BLOCKS_SKIPPED: usize = 4;

/// Proposals by the restarted validator that the FOUNDERS must have adopted
/// before the run is allowed to conclude anything.
///
/// This is what stops the fix being "never propose again". Counted on the
/// founders' canonical chain, because a block the restarted node built and
/// nobody adopted is a fork, not a duty performed.
const MIN_PROPOSALS_AFTER_RESTART: usize = 2;

/// Deadline for the fleet to reach `BUILDUP_UNTIL_SLOT`.
const BUILDUP_DEADLINE: Duration = Duration::from_secs(600);

/// Deadline for the founders to run `AWAY_SLOTS` further on their own.
const AWAY_DEADLINE: Duration = Duration::from_secs(300);

/// Deadline for the restarted validator to finish replay.
const REPLAY_DEADLINE: Duration = Duration::from_secs(300);

/// Deadline for the restarted validator to converge and take enough duties
/// once its peers are back.
///
/// Generous on purpose. The claim under test is "it does not act on a stale
/// head"; the only honest way to fail the second half is "it never acted at
/// all", and a tight deadline would turn that into a race.
const REJOIN_DEADLINE: Duration = Duration::from_secs(600);

/// Slots below a node's own head that each reading samples. See `chain_at`.
const TIP_WINDOW: u64 = 48;

/// Upper bound on the prefix scanned. Constant, so reading cost does not grow
/// with run length.
const SETTLE_SCAN_MAX: u64 = 200;

/// Consecutive polls a founder fracture must persist for before the run is
/// called void rather than failed.
const FRACTURE_POLLS: u32 = 3;

// ───────────────────────────────────────────────────────────────────────────
// Harness. Borrowed from `warm_join.rs` (probe/warm-start-validator); the
// reasoning for each piece lives in that file's header and doc comments.
// ───────────────────────────────────────────────────────────────────────────

struct Fleet(Vec<Option<Child>>);

impl Fleet {
    fn kill(&mut self, i: usize) {
        if let Some(mut c) = self.0[i].take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
    fn assert_alive(&mut self, root: &Path) {
        for i in 0..self.0.len() {
            if let Some(c) = self.0[i].as_mut() {
                if let Ok(Some(status)) = c.try_wait() {
                    panic!("n{i} exited early with {status}{}", logs(root));
                }
            }
        }
    }
}

impl Drop for Fleet {
    fn drop(&mut self) {
        for c in self.0.iter_mut().flatten() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

fn tmp_root(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("bloch-pos-replaygrace-{tag}-{}", std::process::id()));
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

/// Spawn a node. The log path is a parameter rather than derived from the
/// index because the restart needs a SEPARATE file: `File::create` truncates,
/// and the whole assertion is "which blocks did this process propose", which
/// must not be able to see the pre-restart process's lines.
fn spawn_node(
    dir: &Path,
    genesis: &Path,
    listen: u16,
    rpc_port: u16,
    peers: &[u16],
    log: &Path,
) -> Child {
    let out = std::fs::File::create(log).expect("create log");
    let err = out.try_clone().expect("dup log");
    let mut args: Vec<String> = vec![
        "run".into(),
        "--data-dir".into(),
        dir.to_str().unwrap().into(),
        "--genesis".into(),
        genesis.to_str().unwrap().into(),
        "--transport".into(),
        "libp2p".into(),
        "--p2p-listen".into(),
        format!("/ip4/127.0.0.1/tcp/{listen}"),
        // Own RPC port from `free_port`, not `listen + 1000`: an OS-chosen
        // ephemeral port on macOS is in 49152-65535 and `+ 1000` overflows.
        "--rpc-port".into(),
        rpc_port.to_string(),
    ];
    if !peers.is_empty() {
        args.push("--p2p-peer".into());
        args.push(
            peers
                .iter()
                .map(|p| format!("/ip4/127.0.0.1/tcp/{p}"))
                .collect::<Vec<_>>()
                .join(","),
        );
    }
    Command::new(BIN)
        .args(&args)
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .expect("spawn node")
}

fn rpc(port: u16, method: &str, params: &str) -> Option<String> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(10))).ok()?;
    s.set_write_timeout(Some(Duration::from_secs(10))).ok()?;
    let body = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{params}}}"#);
    let req = format!(
        "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).ok()?;
    let mut out = String::new();
    s.read_to_string(&mut out).ok()?;
    Some(out)
}

fn field<'a>(json: &'a str, key: &str, from: usize) -> Option<&'a str> {
    let needle = format!("\"{key}\":");
    let at = json[from..].find(&needle)? + from + needle.len();
    let rest = &json[at..];
    if let Some(stripped) = rest.strip_prefix('"') {
        let end = stripped.find('"')?;
        Some(&stripped[..end])
    } else {
        let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
        if end == 0 { None } else { Some(&rest[..end]) }
    }
}

fn checkpoint(json: &str, key: &str) -> Option<(u64, String)> {
    let at = json.find(&format!("\"{key}\":{{"))?;
    Some((field(json, "epoch", at)?.parse().ok()?, field(json, "root", at)?.to_string()))
}

type Blk = (String, String, u64);

#[derive(Debug, Clone)]
struct Chain {
    /// `slot -> (block id, post-state root, proposer index)`, from
    /// `getblockbyslot`, which reads what fork choice maintains.
    blocks: BTreeMap<u64, Blk>,
    head_slot: u64,
    wall_slot: u64,
    behind_by_slots: u64,
    height: u64,
    finalized: (u64, String),
    justified: (u64, String),
}

impl Chain {
    fn short(&self) -> String {
        format!(
            "head slot {} (wall {}, behind {}), height {}, {} sampled blocks, \
             justified e{} {}, finalized e{} {}",
            self.head_slot,
            self.wall_slot,
            self.behind_by_slots,
            self.height,
            self.blocks.len(),
            self.justified.0,
            &self.justified.1[..self.justified.1.len().min(12)],
            self.finalized.0,
            &self.finalized.1[..self.finalized.1.len().min(12)],
        )
    }
}

/// Read a node's canonical chain at a BOUNDED set of slots. Every
/// `getblockbyslot` crosses the engine channel — the same thread that runs
/// consensus — so an unbounded sweep is load applied to the thing being
/// measured. See `warm_join.rs::chain_at` for the run that proved it.
fn chain_at(port: u16, settled: &[u64]) -> Option<Chain> {
    let info = rpc(port, "getchaininfo", "[]")?;
    let head_slot: u64 = field(&info, "slot", 0)?.parse().ok()?;
    let c = Chain {
        blocks: BTreeMap::new(),
        head_slot,
        wall_slot: field(&info, "wall_slot", 0)?.parse().ok()?,
        behind_by_slots: field(&info, "behind_by_slots", 0)?.parse().ok()?,
        height: field(&info, "height", 0)?.parse().ok()?,
        finalized: checkpoint(&info, "finalized")?,
        justified: checkpoint(&info, "justified")?,
    };
    let mut want: BTreeSet<u64> = settled.iter().copied().filter(|s| *s <= head_slot).collect();
    want.extend(head_slot.saturating_sub(TIP_WINDOW).max(1)..=head_slot);
    let mut blocks = BTreeMap::new();
    for slot in want {
        let Some(resp) = rpc(port, "getblockbyslot", &format!("[{slot}]")) else { continue };
        let (Some(id), Some(root), Some(prop)) = (
            field(&resp, "block_id", 0),
            field(&resp, "state_root", 0),
            field(&resp, "proposer_index", 0),
        ) else {
            continue; // a slot with no canonical block: an ordinary miss
        };
        blocks.insert(slot, (id.to_string(), root.to_string(), prop.parse().unwrap_or(u64::MAX)));
    }
    Some(Chain { blocks, ..c })
}

/// Just the head slot: ONE round trip.
///
/// The phases that are only waiting for the clock use this rather than
/// `chain_of`, which costs `SETTLE_SCAN_MAX` round trips across the consensus
/// thread. On a two-second poll that is 100 calls per second per node aimed at
/// the same thread that signs post-quantum — load applied to the thing being
/// measured, which is the mistake `warm_join.rs::chain_at` documents. The full
/// reading is taken once, at the end of each phase, for the record.
fn head_slot_of(port: u16) -> Option<u64> {
    let info = rpc(port, "getchaininfo", "[]")?;
    field(&info, "slot", 0)?.parse().ok()
}

fn chain_of(port: u16) -> Option<Chain> {
    let prefix: Vec<u64> = (1..=SETTLE_SCAN_MAX).collect();
    chain_at(port, &prefix)
}

/// The first slot at which two chains hold DIFFERENT canonical blocks.
fn first_disagreement(a: &Chain, b: &Chain) -> Option<(u64, Blk, Blk)> {
    for (slot, av) in &a.blocks {
        if let Some(bv) = b.blocks.get(slot) {
            if av != bv {
                return Some((*slot, av.clone(), bv.clone()));
            }
        }
    }
    None
}

/// Are the founders still a usable REFERENCE for each other?
///
/// Inherited from `warm_join.rs`, measurements and all: a four-validator
/// devnet on this build simply stops agreeing with itself somewhere past slot
/// ~300, on an idle host, with nobody joining. This is a precondition, not an
/// assertion about the restarted node — it says "the reference stopped being a
/// reference, stop here".
fn founders_fractured(refs: &[Chain]) -> Option<String> {
    let describe = || -> String {
        refs.iter()
            .enumerate()
            .map(|(i, c)| format!("n{i} justified e{} height {} ", c.justified.0, c.height))
            .collect()
    };
    let lo = refs.iter().map(|c| c.justified.0).min()?;
    let hi = refs.iter().map(|c| c.justified.0).max()?;
    if hi.saturating_sub(lo) > 2 {
        return Some(format!("justified epochs {lo}..{hi}: {}", describe()));
    }
    for i in 0..refs.len() {
        for j in (i + 1)..refs.len() {
            if let Some((slot, a, b)) = first_disagreement(&refs[i], &refs[j]) {
                return Some(format!(
                    "n{i} and n{j} hold different blocks at slot {slot} ({} vs {}): {}",
                    &a.0[..8],
                    &b.0[..8],
                    describe()
                ));
            }
        }
    }
    None
}

fn make_chain(root: &Path) -> PathBuf {
    for i in 0..VALIDATORS {
        let dir = root.join(format!("d{i}"));
        run_to_completion(&["keygen", "--dir", dir.to_str().unwrap(), "--index", &i.to_string()]);
    }
    let keys = (0..VALIDATORS)
        .map(|i| root.join(format!("d{i}")).to_str().unwrap().to_string())
        .collect::<Vec<_>>()
        .join(",");
    let genesis = root.join("genesis.bin");
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
    genesis
}

fn read_log(root: &Path, name: &str) -> String {
    std::fs::read_to_string(root.join(name)).unwrap_or_default()
}

fn logs(root: &Path) -> String {
    let mut s = String::new();
    for name in [
        "n0.log", "n1.log", "n2.log", "n3.log",
        "n0-restart.log", "n1-restart.log", "n2-restart.log", "n3-restart.log",
    ] {
        s.push_str(&format!("\n--- {name} ---\n{}", tail(&read_log(root, name), 120)));
    }
    s
}

/// Logs here run to thousands of lines; a panic message that dumps all of them
/// buries its own first line.
fn tail(s: &str, n: usize) -> String {
    let lines: Vec<&str> = s.lines().collect();
    lines[lines.len().saturating_sub(n)..].join("\n")
}

// ── the measurement this file is actually about ────────────────────────────

/// One duty this process signed, as its own stdout reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Duty {
    /// The slot the duty was for.
    slot: u64,
    /// The slot of the head it was signed over: a proposal's parent, or an
    /// attestation's `head`.
    on: u64,
    proposal: bool,
}

impl Duty {
    fn gap(&self) -> u64 {
        self.slot.saturating_sub(self.on)
    }
    fn what(&self) -> &'static str {
        if self.proposal { "proposed a block" } else { "signed an attestation" }
    }
}

/// Every duty this process signed, from its own stdout.
///
/// Read from the log rather than over the RPC on purpose. The head's slot is
/// the ONLY field that distinguishes a stale-head duty from a healthy one, and
/// it is unrecoverable afterwards: the moment a stale-head block is applied the
/// node's head is at the wall slot, so `getchaininfo` reports
/// `behind_by_slots: 0` and `getblockbyslot` reports a perfectly ordinary
/// block. That is exactly why v10 and v63 read healthy while forked. An
/// attestation leaves no RPC trace at all.
///
/// Both lines carry that slot only because this change added it. Neither did
/// before, which is a large part of why the failure was hard to see.
fn duties(log: &str) -> Vec<Duty> {
    let mut out = Vec::new();
    for line in log.lines() {
        // "[slot 87] proposing block ab12cd34 on parent slot 41 (...)"
        // "[slot 87] attested (epoch 2, head ab12cd34 at slot 41, target ...)"
        let Some(rest) = line.strip_prefix("[slot ") else { continue };
        let Some((slot_s, rest)) = rest.split_once(']') else { continue };
        let Ok(slot) = slot_s.trim().parse::<u64>() else { continue };
        let (marker, proposal) = if rest.contains(" proposing block ") {
            (" on parent slot ", true)
        } else if rest.contains(" attested (") {
            (" at slot ", false)
        } else {
            continue;
        };
        let Some(at) = rest.find(marker) else { continue };
        let tail = &rest[at + marker.len()..];
        let end = tail.find(|c: char| !c.is_ascii_digit()).unwrap_or(tail.len());
        let Ok(on) = tail[..end].parse::<u64>() else { continue };
        out.push(Duty { slot, on, proposal });
    }
    out
}

/// Blocks replayed, from the node's own `replayed N blocks` line. `None` while
/// replay is still running.
fn replay_finished(log: &str) -> Option<u64> {
    log.lines()
        .find(|l| l.starts_with("replayed ") && l.contains(" blocks: head slot "))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|n| n.parse::<u64>().ok())
}

/// Has the node printed the line it prints *before* replay begins?
fn replay_started(log: &str) -> bool {
    log.lines().any(|l| l.starts_with("replaying ") && l.contains(" blocks from the log"))
}

fn wait_for<T>(deadline: Duration, poll: Duration, mut f: impl FnMut() -> Option<T>) -> Option<T> {
    let start = Instant::now();
    loop {
        if let Some(v) = f() {
            return Some(v);
        }
        if start.elapsed() >= deadline {
            return None;
        }
        std::thread::sleep(poll);
    }
}

/// The wall slot from any node that will answer, so the test's own sense of
/// time comes from the chain's clock rather than from a second one of its own.
fn wall_slot(ports: &[u16]) -> Option<u64> {
    ports
        .iter()
        .find_map(|p| rpc(*p, "getchaininfo", "[]").and_then(|j| field(&j, "wall_slot", 0)?.parse().ok()))
}

// ───────────────────────────────────────────────────────────────────────────
// The coverage.
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn a_validator_emerging_from_replay_does_not_act_on_its_stale_head() {
    let root = tmp_root("stalehead");
    let genesis = make_chain(&root);

    let listen: Vec<u16> = (0..VALIDATORS).map(|_| free_port()).collect();
    let rpc_ports: Vec<u16> = (0..VALIDATORS).map(|_| free_port()).collect();
    let peers_of = |i: usize| -> Vec<u16> {
        listen.iter().enumerate().filter(|(j, _)| *j != i).map(|(_, p)| *p).collect()
    };
    let start = |i: usize, log: &str| -> Child {
        spawn_node(
            &root.join(format!("d{i}")),
            &genesis,
            listen[i],
            rpc_ports[i],
            &peers_of(i),
            &root.join(log),
        )
    };

    let mut fleet =
        Fleet((0..VALIDATORS).map(|i| Some(start(i, &format!("n{i}.log")))).collect());

    // ── Phase 1: let the subject accumulate a block log ────────────────────
    wait_for(BUILDUP_DEADLINE, Duration::from_secs(2), || {
        fleet.assert_alive(&root);
        head_slot_of(rpc_ports[RESTARTED]).filter(|h| *h >= BUILDUP_UNTIL_SLOT)
    })
    .unwrap_or_else(|| {
        panic!("v{RESTARTED} never reached slot {BUILDUP_UNTIL_SLOT}{}", logs(&root))
    });
    let built = chain_of(rpc_ports[RESTARTED])
        .unwrap_or_else(|| panic!("v{RESTARTED} stopped answering{}", logs(&root)));
    let stale_head = built.head_slot;
    println!("phase 1: v{RESTARTED} at {}", built.short());

    // ── Phase 2: stop it; let the founders run on ──────────────────────────
    fleet.kill(RESTARTED);
    println!("phase 2: v{RESTARTED} stopped at head slot {stale_head}");

    let target = stale_head + AWAY_SLOTS;
    wait_for(AWAY_DEADLINE, Duration::from_secs(2), || {
        fleet.assert_alive(&root);
        head_slot_of(rpc_ports[0]).filter(|h| *h >= target)
    })
    .unwrap_or_else(|| panic!("the founders never reached slot {target}{}", logs(&root)));
    let ahead = chain_of(rpc_ports[0])
        .unwrap_or_else(|| panic!("n0 stopped answering{}", logs(&root)));
    println!("phase 2: founders at {}", ahead.short());

    // ── Phase 3: stop the founders, then restart the subject ───────────────
    //
    // The founders come down so that the subject's inbox is EMPTY when it
    // emerges from replay, and stays empty. Nothing about the subject changes:
    // same data dir, same `--p2p-peer` list, no flags. It simply has no answer
    // from anyone — which is the state every validator is in for the first
    // seconds after a restart, held open long enough to be measured. See §3.
    for i in 0..FOUNDERS {
        fleet.kill(i);
    }
    println!("phase 3: founders stopped; restarting v{RESTARTED} into silence");

    let restart_at = Instant::now();
    fleet.0[RESTARTED] = Some(start(RESTARTED, "n3-restart.log"));

    // Replay start and end are both timed, because `booted_ms` is stamped
    // between them: everything before the "replaying" line is boot cost the
    // grace does not cover, and quoting it would overstate the case.
    let poll = Duration::from_millis(100);
    let started_at = wait_for(REPLAY_DEADLINE, poll, || {
        replay_started(&read_log(&root, "n3-restart.log")).then(|| restart_at.elapsed())
    })
    .unwrap_or_else(|| panic!("v{RESTARTED} never began replay{}", logs(&root)));
    let replayed = wait_for(REPLAY_DEADLINE, poll, || {
        fleet.assert_alive(&root);
        replay_finished(&read_log(&root, "n3-restart.log"))
    })
    .unwrap_or_else(|| panic!("v{RESTARTED} never finished replay{}", logs(&root)));
    let replay_ms = (restart_at.elapsed() - started_at).as_millis() as u64;
    println!(
        "phase 3: replayed {replayed} blocks in {replay_ms} ms (boot to replay start: {} ms)",
        started_at.as_millis()
    );

    // (1) The precondition. A run where replay finished INSIDE the two-slot
    // grace cannot say anything about a grace consumed by replay.
    assert!(
        replay_ms > 2 * SLOT_MS,
        "INCONCLUSIVE: replay of {replayed} blocks took {replay_ms} ms, inside the \
         {}-ms boot grace. The defect under test is a grace period spent inside replay; \
         raise BUILDUP_UNTIL_SLOT until replay outlasts it.",
        2 * SLOT_MS
    );

    // ── Phase 4: the gate. Peers down; the subject must sign nothing. ──────
    // Retried: the RPC does not bind until after replay AND after the
    // weak-subjectivity gate, so the first read can land in the gap between
    // the "replayed" line and the listener.
    let watch_from = wait_for(Duration::from_secs(60), Duration::from_millis(500), || {
        wall_slot(&[rpc_ports[RESTARTED]])
    })
    .unwrap_or_else(|| panic!("v{RESTARTED} did not answer after replay{}", logs(&root)));
    let watch_until = watch_from + SILENT_WINDOW_SLOTS;
    println!("phase 4: watching slots {watch_from}..{watch_until} with the founders down");

    let silent_deadline = Duration::from_millis(SILENT_WINDOW_SLOTS * SLOT_MS + 60_000);
    let reached = wait_for(silent_deadline, Duration::from_secs(1), || {
        fleet.assert_alive(&root);
        let log = read_log(&root, "n3-restart.log");
        // Checked continuously so a violation is reported at the slot it
        // happened, not at the end of the window.
        if let Some(d) = duties(&log).into_iter().find(|d| d.slot >= watch_from) {
            panic!(
                "v{RESTARTED} ACTED ON A STALE HEAD: at slot {} it {} over a head at slot \
                 {} — {} slots stale. It was stopped at head slot {stale_head}, its peers \
                 are DOWN, and it had heard nothing from any of them since restarting. It \
                 spent {replay_ms} ms in replay, longer than the {}-ms boot grace, so it \
                 emerged with the grace already spent and took the next duty it held.{}",
                d.slot,
                d.what(),
                d.on,
                d.gap(),
                2 * SLOT_MS,
                logs(&root)
            );
        }
        wall_slot(&[rpc_ports[RESTARTED]]).filter(|w| *w >= watch_until)
    });
    let reached = reached.unwrap_or_else(|| {
        panic!("v{RESTARTED} stopped answering during the silent window{}", logs(&root))
    });
    println!("phase 4: v{RESTARTED} reached slot {reached} having signed nothing");

    // Not vacuous on its own terms: the window has to be long enough that the
    // node HELD duties in it. Committees partition the active set over an
    // epoch, so at least one attesting duty falls inside 48 slots by
    // construction — this asserts the window really did span one.
    assert!(
        reached.saturating_sub(watch_from) >= SLOTS_PER_EPOCH,
        "the silent window spanned {} slots, less than the {SLOTS_PER_EPOCH}-slot epoch \
         that guarantees the subject held an attesting duty inside it",
        reached.saturating_sub(watch_from)
    );

    // ── Phase 5: bring the founders back; it must catch up and act ─────────
    println!("phase 5: founders back");
    for i in 0..FOUNDERS {
        fleet.0[i] = Some(start(i, &format!("n{i}-restart.log")));
    }

    let settled: Vec<u64> = (1..=SETTLE_SCAN_MAX).collect();
    let mut fractures = 0u32;
    let mut last: Option<(Vec<Chain>, Chain)> = None;

    let outcome = wait_for(REJOIN_DEADLINE, Duration::from_secs(3), || {
        fleet.assert_alive(&root);

        let refs: Vec<Chain> =
            (0..FOUNDERS).filter_map(|i| chain_at(rpc_ports[i], &settled)).collect();
        if refs.len() < FOUNDERS {
            return None;
        }
        let mine = chain_at(rpc_ports[RESTARTED], &settled)?;

        if let Some(why) = founders_fractured(&refs) {
            fractures += 1;
            if fractures >= FRACTURE_POLLS {
                return Some(Err(why));
            }
            return None;
        }
        fractures = 0;

        // (3) Not vacuous: the FOUNDERS must have adopted its blocks.
        let adopted: Vec<u64> = refs[0]
            .blocks
            .iter()
            .filter(|(s, b)| {
                **s > watch_until
                    && b.2 == RESTARTED as u64
                    // Required on its reading too: the two samplings take their
                    // tip window from different heads, so a slot inside the
                    // founder's window can be outside the subject's, and
                    // comparing Some against None is a sampling artefact
                    // wearing the costume of a fork.
                    && mine.blocks.get(s) == Some(*b)
            })
            .map(|(s, _)| *s)
            .collect();

        last = Some((refs.clone(), mine.clone()));
        (adopted.len() >= MIN_PROPOSALS_AFTER_RESTART).then(|| Ok((refs, mine, adopted)))
    });

    let (refs, mine, adopted) = match outcome {
        Some(Ok(v)) => v,
        Some(Err(why)) => {
            eprintln!(
                "VOID: the founders fractured with nothing to blame it on — {why}. No \
                 conclusion about v{RESTARTED} is available from this run."
            );
            return;
        }
        None => {
            let (refs, mine) = match last {
                Some((r, m)) => (r, Some(m)),
                None => (Vec::new(), None),
            };
            panic!(
                "v{RESTARTED} never had {MIN_PROPOSALS_AFTER_RESTART} proposals adopted \
                 after its peers came back. It did not act on a stale head — but a gate \
                 that silences a validator forever is not the fix.\n  founder: {}\n  \
                 subject: {}\n  its duties: {:?}{}",
                refs.first().map(|c| c.short()).unwrap_or_else(|| "unread".into()),
                mine.map(|c| c.short()).unwrap_or_else(|| "unread".into()),
                duties(&read_log(&root, "n3-restart.log")),
                logs(&root)
            );
        }
    };

    // (4) It never built on a head the network had already moved past.
    //
    // The after-the-fact form of the claim. Three simpler formulations were
    // tried and each was ruled out by a run in which the FIX was working and
    // the assertion was wrong; `MAX_BLOCKS_SKIPPED` records all three and the
    // measurements. What separates a stale head from ordinary lag is the number
    // of canonical blocks the proposer stepped over, not slot arithmetic and
    // not whether its block survived fork choice.
    //
    // Read only off blocks the founders actually reported. `chain_at` samples a
    // bounded set of slots, so a slot it did not read is missing evidence — but
    // that can only hide a violation, never invent one, which is the safe
    // direction for a check whose failure message accuses the node of forking.
    for d in duties(&read_log(&root, "n3-restart.log")).into_iter().filter(|d| d.proposal) {
        let passed: Vec<u64> =
            refs[0].blocks.keys().copied().filter(|q| *q > d.on && *q < d.slot).collect();
        assert!(
            passed.len() <= MAX_BLOCKS_SKIPPED,
            "v{RESTARTED} PROPOSED ON A STALE HEAD: its block at slot {} was built on a \
             parent at slot {}, stepping over {} canonical blocks the founders hold at \
             {:?} — far past the {MAX_BLOCKS_SKIPPED} that ordinary propagation lag \
             explains.\n  founder: {}\n  its duties: {:?}{}",
            d.slot,
            d.on,
            passed.len(),
            passed,
            refs[0].short(),
            duties(&read_log(&root, "n3-restart.log")),
            logs(&root)
        );
    }

    // (5) And they are on the same chain.
    for (i, r) in refs.iter().enumerate() {
        if let Some((slot, a, b)) = first_disagreement(r, &mine) {
            panic!(
                "v{RESTARTED} and founder n{i} hold different blocks at slot {slot}: {} (by \
                 v{}) vs {} (by v{}){}",
                &a.0[..8],
                a.2,
                &b.0[..8],
                b.2,
                logs(&root)
            );
        }
    }

    println!(
        "PASS: v{RESTARTED} replayed {replayed} blocks in {replay_ms} ms (the grace it \
         replaces is {} ms), signed NOTHING across slots {watch_from}..{reached} while its \
         peers were down, then caught up and had blocks adopted at slots {adopted:?}. Its \
         duties: {:?}\n  founder: {}\n  subject: {}",
        2 * SLOT_MS,
        duties(&read_log(&root, "n3-restart.log")),
        refs[0].short(),
        mine.short(),
    );
}
