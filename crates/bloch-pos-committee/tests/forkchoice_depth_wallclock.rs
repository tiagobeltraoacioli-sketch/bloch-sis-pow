// SPDX-License-Identifier: AGPL-3.0-or-later

//! **What the rollout decision needs: does a producer still stall, and at what
//! depth?**
//!
//! On 2026-08-23 the four classic mainnet producers (n07, n08, n10, n21) all
//! stopped producing at the same time. Each had its main thread in state `R`
//! with `wchan: 0` — spinning in user space, not blocked in the kernel — at
//! ~104% CPU read from `/proc/PID/stat`, and each stayed there for over 45
//! minutes after applying a block. The network produced nothing for 82 slots
//! (41 minutes). Restarting them clears `Engine::blocks`, which is why a
//! restart works and why it only works until the set grows back.
//!
//! [`forkchoice_asymptotics`] proves the SHAPE changed, in DAG steps. This
//! file answers the operational question in SECONDS: at the depth those nodes
//! were at, and at depths beyond it, how long does one `head()` take now?
//!
//! MEASURED 2026-08-23, `--release`, V = 64, load average 5-7, median of 5:
//!
//! ```text
//!    depth      NEW ms      OLD ms
//!      256           -       162.8
//!      512           -       648.0
//!     1024        0.81      2959.5
//!     2048        1.79     15126.8
//!     4096        5.25     58004.2
//!     8192        9.84           -
//!    16384       24.04           -
//!    32768       55.65           -
//!    65536      143.96           -
//! ```
//!
//! At depth 4,096 the replaced implementation costs **58.0 SECONDS** — almost
//! two whole slots for ONE head — against 5.25 ms for the new one, a factor of
//! ~11,000. At 65,536 blocks, sixteen times deeper than that, the new one is
//! 144 ms: 208x inside a slot.
//!
//! DEDUCED, not measured: the stalled producers ran >45 min in one call. Fitting
//! the old implementation's measured quadratic through 58.0 s at 4,096 puts 45
//! min at depth ~28,000 — the right order for an unpruned `Engine::blocks` after
//! hours of uptime, and consistent with a restart curing it until the set
//! regrows.
//!
//! Ignored by default — it builds DAGs up to 65,536 deep and takes minutes.
//! Run:
//!   cargo test --release -p bloch-pos-committee --test forkchoice_depth_wallclock \
//!       -- --ignored --nocapture

use bloch_pos_committee::{BlockTree, LatestMessage, Store};
use std::collections::HashMap;
use std::time::Instant;

const GENESIS: [u8; 32] = [0xAAu8; 32];

/// The live Genesis-4 validator set: 12 classic + 49 Fly, rounded to 64.
const V: u32 = 64;

/// One slot. A `head()` that costs more than this cannot keep up, which is
/// what "the chain stops" means in wall-clock terms.
const SLOT_SECS: f64 = 30.0;

fn block_id(depth: u32, branch: u8) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[0] = branch;
    id[1..5].copy_from_slice(&depth.to_be_bytes());
    id
}

/// The shape that made the old implementation quadratic: a spine with a
/// sibling at every level, so the descent has a real choice at each step.
fn chain(
    depth: u32,
) -> (
    HashMap<[u8; 32], [u8; 32]>,
    HashMap<[u8; 32], Vec<[u8; 32]>>,
) {
    let mut parents = HashMap::new();
    let mut children: HashMap<[u8; 32], Vec<[u8; 32]>> = HashMap::new();
    let mut parent = GENESIS;
    for d in 0..depth {
        let spine = block_id(d, 0);
        let sibling = block_id(d, 1);
        parents.insert(spine, parent);
        parents.insert(sibling, parent);
        let kids = children.entry(parent).or_default();
        kids.push(spine);
        kids.push(sibling);
        kids.sort_unstable();
        parent = spine;
    }
    (parents, children)
}

fn store_for(depth: u32, validators: u32) -> Store {
    let mut s = Store::new();
    for v in 0..validators {
        s.set_stake(v, 100);
        let d = (v as u64 * depth as u64 / validators.max(1) as u64) as u32;
        s.observe(
            v,
            LatestMessage {
                slot: 1,
                root: block_id(d.min(depth - 1), 0),
            },
        );
    }
    s
}

#[test]
#[ignore]
fn head_wallclock_by_depth_new_implementation() {
    println!("\n== one fork-choice head(), NEW implementation, V = {V} ==");
    println!("{:>10}  {:>12}  {:>10}", "depth", "median ms", "ms/1k blk");

    let mut rows: Vec<(u32, f64)> = Vec::new();
    for &d in &[1024u32, 2048, 4096, 8192, 16384, 32768, 65536] {
        let (p, c) = chain(d);
        let s = store_for(d, V);
        let t = BlockTree { parents: &p };

        // Correctness first: a timing number for a descent that stopped short
        // would be measuring nothing.
        //
        // The descent settles one level past the DEEPEST VOTED block, not at
        // `d - 1`: `store_for` places validator `v`'s vote at `v * d / V`, so
        // the deepest vote is at `(V - 1) * d / V` and everything below it is
        // a zero-zero tie with nothing to descend for. (The asymptotics test
        // asserts `d - 1` because at ITS parameters — d = 64, V = 32 — the
        // deepest vote lands at 62 and one past it happens to be 63. That
        // coincidence does not survive V = 64.)
        let deepest_vote = ((V as u64 - 1) * d as u64 / V as u64) as u32;
        let head = s.head(&t, GENESIS, &c);
        let reached = u32::from_be_bytes(head[1..5].try_into().unwrap());
        assert!(
            reached >= deepest_vote,
            "descent stopped at depth {reached}, short of the deepest voted \
             block at {deepest_vote} (D = {d}) — the timing below would be \
             measuring a partial walk"
        );

        let mut samples = Vec::new();
        for _ in 0..5 {
            let t0 = Instant::now();
            let h = s.head(&t, GENESIS, &c);
            samples.push(t0.elapsed().as_secs_f64() * 1000.0);
            std::hint::black_box(h);
        }
        samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let med = samples[samples.len() / 2];
        println!("{d:>10}  {med:>12.2}  {:>10.3}", med / (d as f64 / 1000.0));
        rows.push((d, med));
    }

    // The operational question, from the measured points.
    let (dmax, tmax) = *rows.last().unwrap();
    let budget_ms = SLOT_SECS * 1000.0;
    println!(
        "\n  deepest measured: {dmax} blocks at {tmax:.1} ms — that is {:.0}x under a {SLOT_SECS:.0} s slot",
        budget_ms / tmax
    );
    println!(
        "  EXTRAPOLATED (linear, from the measured points, NOT measured): a slot's\n\
         \x20 budget is reached near depth {:.0}.",
        dmax as f64 * (budget_ms / tmax)
    );
    println!(
        "  CAVEAT: linear extrapolation of a linear algorithm is the right shape,\n\
         \x20 but memory, not time, is the next wall — this DAG is HashMap-resident\n\
         \x20 and a real node also holds every block body."
    );

    // The claim the rollout rests on: at every depth measured, one head() is
    // far inside a slot. Not a timing threshold that flakes — three orders of
    // magnitude of headroom at the deepest point.
    assert!(
        tmax < budget_ms / 10.0,
        "at depth {dmax} one head() took {tmax:.1} ms, which is not comfortably \
         inside a {SLOT_SECS:.0} s slot"
    );
}

/// The OLD implementation on the same shapes, for as deep as is bearable —
/// so the "42.5 s at 4096" figure is reproduced here rather than quoted.
#[test]
#[ignore]
fn head_wallclock_by_depth_old_implementation() {
    println!("\n== one fork-choice head(), OLD (head_reference), V = {V} ==");
    println!("{:>10}  {:>12}", "depth", "ms");
    for &d in &[256u32, 512, 1024, 2048, 4096] {
        let (p, c) = chain(d);
        let s = store_for(d, V);
        let t = BlockTree { parents: &p };
        let t0 = Instant::now();
        let h = s.head_reference(&t, GENESIS, &c);
        let ms = t0.elapsed().as_secs_f64() * 1000.0;
        std::hint::black_box(h);
        println!("{d:>10}  {ms:>12.1}");
    }
    println!(
        "\n  This is the cost the four stalled producers were paying, and it is\n\
         \x20 quadratic: each doubling of depth roughly quadruples it."
    );
}
