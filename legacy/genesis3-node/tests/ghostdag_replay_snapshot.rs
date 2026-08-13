//! Real-snapshot GhostDAG differential replay harness (READ-ONLY decision tool).
//!
//! This is the authoritative step the synthetic `tests/ghostdag_differential.rs`
//! suite defers to: it replays a REAL mainnet RocksDB snapshot through BOTH the
//! deployed `Legacy` (bounded-BFS) coloring and the `Fast` (interval-index)
//! coloring and reports whether they are byte-identical on every historical
//! block.
//!
//! # What it decides
//!
//!   * **Identical everywhere** ⇒ `Fast` is a transparent, no-fork speedup: it
//!     reproduces the exact on-chain coloring and can be adopted without an
//!     activation gate.
//!   * **Any divergence** ⇒ adopting `Fast` is a consensus change and MUST be
//!     activation-gated via [`CORRECTED_COLORING_ACTIVATION_HEIGHT`] at a future
//!     height, so historical (already-mined) blocks keep their `Legacy`
//!     coloring and no token/balance is ever recomputed. The harness prints the
//!     LOWEST height at which the two disagree plus a per-field summary.
//!
//! # Safety
//!
//! The snapshot is opened **read-only** (`Storage::open_read_only` →
//! `open_cf_descriptors_read_only`): no write lock, nothing created, every
//! mutating call rejected. This harness NEVER writes to the snapshot. It only
//! reads CF_DAG and replays into two fresh in-memory DAGs.
//!
//! # Running
//!
//! Ignored by default (needs a real snapshot, which CI does not have):
//!
//! ```text
//! BLOCH_SNAPSHOT=/path/to/node/data-dir \
//!   cargo test --test ghostdag_replay_snapshot -- --ignored --nocapture
//! ```
//!
//! `BLOCH_SNAPSHOT` is the node data-dir (the directory holding the RocksDB
//! column families — the same path passed to `Storage::open`).

use std::collections::{HashMap, HashSet, VecDeque};

use bloch::consensus::{
    canonical_encode, BlockHash, ColoringMode, GhostDAG, GhostdagData,
    CORRECTED_COLORING_ACTIVATION_HEIGHT,
};
use bloch::core::GHOSTDAG_K;
use bloch::storage::Storage;

// ── comparison helpers (mirror tests/ghostdag_differential.rs) ────────────────

/// Human-readable per-field diff of two `GhostdagData`, matching the fields the
/// differential suite compares: blue_score, blue_work, selected_parent,
/// mergeset_blues/reds, blues_anticone_sizes.
fn field_diff(a: &GhostdagData, b: &GhostdagData) -> String {
    let mut s = String::new();
    if a.blue_score != b.blue_score {
        s += &format!("blue_score {}!={} ", a.blue_score, b.blue_score);
    }
    if a.blue_work != b.blue_work {
        s += &format!("blue_work {}!={} ", a.blue_work, b.blue_work);
    }
    if a.selected_parent != b.selected_parent {
        s += "selected_parent differs ";
    }
    if a.mergeset_blues != b.mergeset_blues {
        s += &format!(
            "mergeset_blues len {}!={} ",
            a.mergeset_blues.len(),
            b.mergeset_blues.len()
        );
    }
    if a.mergeset_reds != b.mergeset_reds {
        s += &format!(
            "mergeset_reds len {}!={} ",
            a.mergeset_reds.len(),
            b.mergeset_reds.len()
        );
    }
    if a.blues_anticone_sizes != b.blues_anticone_sizes {
        s += &format!(
            "blues_anticone_sizes len {}!={} ",
            a.blues_anticone_sizes.len(),
            b.blues_anticone_sizes.len()
        );
    }
    if s.is_empty() {
        s = "canonical bytes differ (unknown field)".into();
    }
    s
}

fn short(h: &BlockHash) -> String {
    hex::encode(&h[..4])
}

/// Kahn topological sort over the parent graph. Parents strictly precede
/// children (required for `add_block`); among ready nodes we prefer ascending
/// `blue_score` then `height` then hash, so the replay follows the on-chain
/// blue_score order as closely as the DAG allows. Returns `Err` if the graph is
/// not a DAG or references a parent absent from the snapshot (an incomplete
/// snapshot), naming an offending block.
fn topo_sort(
    entries: &HashMap<BlockHash, GhostdagData>,
) -> Result<Vec<BlockHash>, String> {
    // Indegree = number of parents that exist within the snapshot.
    let mut indegree: HashMap<BlockHash, usize> = HashMap::new();
    let mut children: HashMap<BlockHash, Vec<BlockHash>> = HashMap::new();
    for h in entries.keys() {
        indegree.entry(*h).or_insert(0);
    }
    for (h, d) in entries {
        for p in &d.parents {
            if !entries.contains_key(p) {
                return Err(format!(
                    "block {} references parent {} absent from snapshot (incomplete snapshot)",
                    short(h),
                    short(p)
                ));
            }
            *indegree.get_mut(h).unwrap() += 1;
            children.entry(*p).or_default().push(*h);
        }
    }

    // Deterministic ready-set ordering by (blue_score, height, hash).
    let key = |h: &BlockHash| {
        let d = &entries[h];
        (d.blue_score, d.height, *h)
    };
    let mut ready: Vec<BlockHash> = indegree
        .iter()
        .filter(|(_, &deg)| deg == 0)
        .map(|(h, _)| *h)
        .collect();
    ready.sort_by_key(|h| key(h));
    let mut queue: VecDeque<BlockHash> = ready.into_iter().collect();

    let mut out = Vec::with_capacity(entries.len());
    while let Some(h) = queue.pop_front() {
        out.push(h);
        if let Some(ch) = children.get(&h) {
            let mut newly_ready = Vec::new();
            for c in ch {
                let deg = indegree.get_mut(c).unwrap();
                *deg -= 1;
                if *deg == 0 {
                    newly_ready.push(*c);
                }
            }
            // Insert newly-ready nodes in blue_score order relative to the queue
            // tail. Cheap re-sort keeps the traversal deterministic.
            if !newly_ready.is_empty() {
                let mut rest: Vec<BlockHash> = queue.drain(..).collect();
                rest.extend(newly_ready);
                rest.sort_by_key(|h| key(h));
                queue = rest.into_iter().collect();
            }
        }
    }

    if out.len() != entries.len() {
        return Err(format!(
            "topological sort visited {}/{} blocks — the parent graph has a cycle",
            out.len(),
            entries.len()
        ));
    }
    Ok(out)
}

/// Replay the topologically-ordered snapshot into a fresh DAG of the given mode.
/// Per-block PoW `work` is recovered exactly from the stored cumulative
/// `blue_work`: `work(b) = b.blue_work - selected_parent(b).blue_work`
/// (`add_block` sets `blue_work = sp.blue_work + work`), so parent selection —
/// which tie-breaks on `blue_work` — is reproduced faithfully.
fn replay(
    order: &[BlockHash],
    snapshot: &HashMap<BlockHash, GhostdagData>,
    mode: ColoringMode,
) -> GhostDAG {
    let mut dag = match mode {
        ColoringMode::Legacy => GhostDAG::with_k(GHOSTDAG_K),
        ColoringMode::Fast => GhostDAG::with_k_fast(GHOSTDAG_K),
    };
    for h in order {
        let d = &snapshot[h];
        if d.parents.is_empty() {
            dag.add_genesis(*h, d.timestamp);
        } else {
            let sp = d
                .selected_parent
                .expect("non-genesis block has a selected parent");
            let sp_work = snapshot
                .get(&sp)
                .map(|s| s.blue_work)
                .unwrap_or(0);
            let work = d.blue_work.saturating_sub(sp_work);
            dag.add_block(*h, d.parents.clone(), d.timestamp, work)
                .unwrap_or_else(|e| {
                    panic!("replay add_block failed for {}: {e:?}", short(h))
                });
        }
    }
    dag
}

/// FAST validation of WS-B: replay ONLY the Fast (compact, O(k)) coloring — no
/// O(N²) in-test Legacy rebuild — and compare its DECISIONS against the ON-DISK
/// snapshot, which IS the real Legacy-produced mainnet chain. Confirms 0
/// decision-flips + a correct-subset compact anticone map on real history in the
/// time of one Fast replay (minutes) instead of ~23 min.
#[test]
#[ignore = "requires a real mainnet RocksDB snapshot at $BLOCH_SNAPSHOT; run with --ignored --nocapture"]
fn replay_snapshot_fast_vs_ondisk() {
    let path = match std::env::var("BLOCH_SNAPSHOT") {
        Ok(p) if !p.is_empty() => p,
        _ => { eprintln!("BLOCH_SNAPSHOT not set — skipping."); return; }
    };
    eprintln!("=== WS-B Fast vs on-disk (the real Legacy chain), READ-ONLY ===");
    let storage = Storage::open_read_only(std::path::Path::new(&path))
        .expect("open snapshot read-only (is $BLOCH_SNAPSHOT a node data-dir/db?)");
    let raw = storage.load_all_dag_data().expect("load CF_DAG");
    let snapshot: HashMap<BlockHash, GhostdagData> = raw.into_iter().collect();
    let total = snapshot.len();
    assert!(total > 0, "snapshot CF_DAG is empty");
    let order = topo_sort(&snapshot).expect("snapshot is a valid DAG");

    // Only the Fast replay — O(N·k), not the O(N²) Legacy rebuild.
    let fast = replay(&order, &snapshot, ColoringMode::Fast);
    eprintln!("replayed {total} blocks through WS-B Fast coloring");

    let mut decision_flips = 0usize;
    let mut map_value_errors = 0usize;
    let mut compact_smaller = 0usize;
    let mut lowest_flip: Option<(u64, BlockHash, String)> = None;

    for h in &order {
        let df = fast.get_block_data(h).expect("fast replay has every block");
        let ds = &snapshot[h]; // on-disk == the live Legacy chain

        // (1) DECISIONS must be byte-identical to the real chain.
        let mut flip = String::new();
        if df.blue_score != ds.blue_score {
            flip += &format!("blue_score {}!={} ", df.blue_score, ds.blue_score);
        }
        if df.blue_work != ds.blue_work {
            flip += &format!("blue_work {}!={} ", df.blue_work, ds.blue_work);
        }
        if df.selected_parent != ds.selected_parent { flip += "selected_parent "; }
        if df.mergeset_blues != ds.mergeset_blues {
            flip += &format!("mergeset_blues {}!={} ", df.mergeset_blues.len(), ds.mergeset_blues.len());
        }
        if df.mergeset_reds != ds.mergeset_reds {
            flip += &format!("mergeset_reds {}!={} ", df.mergeset_reds.len(), ds.mergeset_reds.len());
        }
        if !flip.is_empty() {
            decision_flips += 1;
            let ht = ds.height;
            if lowest_flip.as_ref().map_or(true, |(lh, ..)| ht < *lh) {
                lowest_flip = Some((ht, *h, flip));
            }
        }

        // (2) Compact map correctness: every Fast entry appears in the on-disk
        //     whole-history map with the SAME value (compact ⊆ whole, equal values).
        for (k, v) in &df.blues_anticone_sizes {
            match ds.blues_anticone_sizes.get(k) {
                Some(sv) if sv == v => {}
                _ => map_value_errors += 1,
            }
        }
        if df.blues_anticone_sizes.len() < ds.blues_anticone_sizes.len() {
            compact_smaller += 1;
        }
    }

    eprintln!("--- WS-B RESULT (real mainnet, {total} blocks) ---");
    eprintln!("decision-flips (Fast vs on-disk Legacy): {decision_flips}");
    eprintln!("compact-map value errors: {map_value_errors}");
    eprintln!("blocks where compact map is strictly smaller: {compact_smaller} / {total}");
    if let Some((h, hash, f)) = &lowest_flip {
        eprintln!("LOWEST decision-flip at height {h} ({}): {f}", short(hash));
    }
    assert_eq!(decision_flips, 0,
        "WS-B Fast must not flip any decision vs the real Legacy chain");
    assert_eq!(map_value_errors, 0,
        "compact anticone values must match the whole-history values on real history");
    assert!(compact_smaller > 0,
        "expected the compact map to be strictly smaller on real deep history");
    eprintln!("✓ WS-B correct: 0 decision-flips + correct-subset compact map on {total} real blocks.");
}

#[test]
#[ignore = "requires a real mainnet RocksDB snapshot at $BLOCH_SNAPSHOT; run with --ignored --nocapture"]
fn replay_snapshot_legacy_vs_fast() {
    let path = match std::env::var("BLOCH_SNAPSHOT") {
        Ok(p) if !p.is_empty() => p,
        _ => {
            eprintln!(
                "BLOCH_SNAPSHOT not set — skipping. \
                 Run: BLOCH_SNAPSHOT=/path/to/data-dir cargo test \
                 --test ghostdag_replay_snapshot -- --ignored --nocapture"
            );
            return;
        }
    };
    eprintln!("=== GhostDAG snapshot differential replay (READ-ONLY) ===");
    eprintln!("snapshot: {path}");
    eprintln!(
        "activation height (corrected coloring gate): {}{}",
        CORRECTED_COLORING_ACTIVATION_HEIGHT,
        if CORRECTED_COLORING_ACTIVATION_HEIGHT == u64::MAX {
            "  (DISABLED — Legacy is the live effective mode)"
        } else {
            "  (ARMED)"
        }
    );

    // 1. Open READ-ONLY and load CF_DAG via the repo's own decoder. Never writes.
    let storage = Storage::open_read_only(std::path::Path::new(&path))
        .expect("open snapshot read-only (is $BLOCH_SNAPSHOT a node data-dir?)");
    let raw = storage
        .load_all_dag_data()
        .expect("load CF_DAG (GhostdagData) from snapshot");

    let snapshot: HashMap<BlockHash, GhostdagData> = raw.into_iter().collect();
    let total = snapshot.len();
    assert!(total > 0, "snapshot CF_DAG is empty — nothing to replay");
    eprintln!("blocks in CF_DAG: {total}");

    // 2. Topological (blue_score-ordered) replay order.
    let order = topo_sort(&snapshot).expect("snapshot is a valid DAG");

    // 3. Replay through BOTH colorings.
    let legacy = replay(&order, &snapshot, ColoringMode::Legacy);
    let fast = replay(&order, &snapshot, ColoringMode::Fast);

    // 4a. Sanity: does the Legacy replay reproduce the on-disk coloring exactly?
    //     This validates the harness's work/order reconstruction against the
    //     real chain. Reported, not asserted.
    let mut legacy_vs_snapshot_mismatch = 0usize;
    for h in &order {
        if let Some(rl) = legacy.get_block_data(h) {
            if canonical_encode(rl) != canonical_encode(&snapshot[h]) {
                legacy_vs_snapshot_mismatch += 1;
            }
        }
    }
    eprintln!(
        "legacy-replay vs on-disk snapshot mismatches: {legacy_vs_snapshot_mismatch} / {total} \
         (0 = replay faithfully reproduces the stored chain)"
    );

    // 4b. THE decision: Legacy vs Fast, byte-identical GhostdagData per block.
    //     Track the LOWEST-height divergence and a per-field summary.
    let mut divergences = 0usize;
    let mut lowest: Option<(u64, BlockHash, String)> = None;
    let mut fields_seen: HashSet<&'static str> = HashSet::new();

    for h in &order {
        let (dl, df) = match (legacy.get_block_data(h), fast.get_block_data(h)) {
            (Some(dl), Some(df)) => (dl, df),
            _ => {
                divergences += 1;
                let height = snapshot[h].height;
                if lowest.as_ref().map_or(true, |(lh, ..)| height < *lh) {
                    lowest = Some((height, *h, "block missing in one replay".into()));
                }
                continue;
            }
        };
        if canonical_encode(dl) != canonical_encode(df) {
            divergences += 1;
            let diff = field_diff(dl, df);
            if dl.blue_score != df.blue_score { fields_seen.insert("blue_score"); }
            if dl.mergeset_blues != df.mergeset_blues { fields_seen.insert("mergeset_blues"); }
            if dl.mergeset_reds != df.mergeset_reds { fields_seen.insert("mergeset_reds"); }
            if dl.blues_anticone_sizes != df.blues_anticone_sizes {
                fields_seen.insert("blues_anticone_sizes");
            }
            let height = snapshot[h].height;
            if lowest.as_ref().map_or(true, |(lh, ..)| height < *lh) {
                lowest = Some((height, *h, diff));
            }
        }
    }

    // 4c. Stall-line report: the live chain froze at blue_score 395897 because
    //     the bounded Legacy path diverged the selected chain. Report the max
    //     blue_score each replay reaches so the operator can see whether Fast
    //     advances past the stall where Legacy stalled.
    const STALL_BLUE_SCORE: u64 = 395_897;
    let max_bs = |dag: &GhostDAG| -> u64 {
        order.iter().filter_map(|h| dag.get_block_data(h)).map(|d| d.blue_score).max().unwrap_or(0)
    };
    let (legacy_max, fast_max) = (max_bs(&legacy), max_bs(&fast));
    eprintln!("--- STALL-LINE (blue_score {STALL_BLUE_SCORE}) ---");
    eprintln!("legacy max blue_score reached: {legacy_max}");
    eprintln!("fast   max blue_score reached: {fast_max}");
    eprintln!(
        "fast advances past the stall line: {}  (legacy past it: {})",
        fast_max > STALL_BLUE_SCORE, legacy_max > STALL_BLUE_SCORE,
    );

    // 4d. Truncation-signature report. A block can have the SAME coloring
    //     decision (blue_score, mergeset_blues, mergeset_reds) yet different
    //     canonical bytes when only its `blues_anticone_sizes` map differs —
    //     that is the fingerprint of a truncated Legacy blue-set seed that did
    //     NOT flip a classification. `decision_flips` are the stronger case
    //     where the decision itself changed. Reported (not asserted): whether a
    //     divergence is consensus-relevant is the gate decision below.
    let mut metadata_only = 0usize;
    let mut decision_flips = 0usize;
    for h in &order {
        if let (Some(dl), Some(df)) = (legacy.get_block_data(h), fast.get_block_data(h)) {
            if canonical_encode(dl) == canonical_encode(df) { continue; }
            let same_decision = dl.blue_score == df.blue_score
                && dl.mergeset_blues == df.mergeset_blues
                && dl.mergeset_reds == df.mergeset_reds;
            if same_decision { metadata_only += 1; } else { decision_flips += 1; }
        }
    }
    eprintln!(
        "divergence breakdown: {decision_flips} decision-flip(s) (blue_score/mergeset changed), \
         {metadata_only} metadata-only (blues_anticone_sizes seed truncated, decision unchanged)"
    );

    eprintln!("--- RESULT ---");
    eprintln!("blocks replayed: {total}");
    if divergences == 0 {
        eprintln!(
            "Legacy == Fast on EVERY block (byte-identical GhostdagData).\n\
             ⇒ Fast is a transparent, no-fork speedup: it reproduces the exact \
             on-chain coloring. No activation gate is required to adopt it."
        );
    } else {
        let (h, hash, diff) = lowest.as_ref().unwrap();
        eprintln!(
            "Legacy != Fast on {divergences} / {total} block(s).\n\
             LOWEST diverging height: {h}  (block {})\n\
             first-divergence field summary: {diff}\n\
             divergent fields across all blocks: {:?}\n\
             ⇒ Adopting Fast is a CONSENSUS CHANGE. It MUST be activation-gated \
             (CORRECTED_COLORING_ACTIVATION_HEIGHT) at a FUTURE height so every \
             already-mined block below it keeps its Legacy coloring — no reorg, \
             no token/balance recompute.",
            short(hash),
            fields_seen,
        );
    }

    // The harness is a decision/reporting tool: divergence is a finding to be
    // gated, not a test failure. We only fail on operational errors (bad path,
    // empty CF, non-DAG), which are handled by the asserts above. Do NOT assert
    // Legacy == Fast here — that would turn a legitimate consensus finding into
    // a red build.
    let _ = divergences;
}

/// Fast DAG-shape probe (READ-ONLY, no re-classification): reads the on-disk
/// GhostdagData and reports the mergeset-width / anticone-size distribution.
/// A narrow DAG (tiny anticones, ~linear) cannot be under-counted by the
/// bounded Legacy BFS, so Legacy == Fast (DROP-IN). Wide anticones are the only
/// place divergence can appear. Runs in seconds (no O(depth) classification).
#[test]
#[ignore]
fn dag_shape_stats() {
    let path = std::env::var("BLOCH_SNAPSHOT")
        .expect("set BLOCH_SNAPSHOT to the snapshot RocksDB path");
    let storage = Storage::open_read_only(std::path::Path::new(&path))
        .expect("open snapshot read-only");
    let raw = storage.load_all_dag_data().expect("load CF_DAG");
    let snapshot: std::collections::HashMap<BlockHash, GhostdagData> =
        raw.into_iter().collect();

    let n = snapshot.len().max(1);
    let (mut max_mergeset, mut max_anticone) = (0usize, 0usize);
    let (mut wide_merges, mut merges_gt_k) = (0usize, 0usize);
    let mut max_blue_score = 0u64;
    for gd in snapshot.values() {
        let w = gd.mergeset_blues.len() + gd.mergeset_reds.len();
        max_mergeset = max_mergeset.max(w);
        if w > 1 { wide_merges += 1; }
        if w > GHOSTDAG_K as usize { merges_gt_k += 1; }
        if let Some(&m) = gd.blues_anticone_sizes.values().max() {
            max_anticone = max_anticone.max(m);
        }
        max_blue_score = max_blue_score.max(gd.blue_score);
    }
    println!("=== DAG SHAPE STATS (predicts DROP-IN vs GATED) ===");
    println!("blocks: {n}  max_blue_score: {max_blue_score}  K: {}", GHOSTDAG_K);
    println!("max mergeset width (blues+reds): {max_mergeset}");
    println!("max blues_anticone_size: {max_anticone}");
    println!(
        "blocks with mergeset width > 1: {wide_merges} ({:.4}%)",
        100.0 * wide_merges as f64 / n as f64
    );
    println!("blocks with mergeset width > K: {merges_gt_k}");
    if max_anticone < GHOSTDAG_K as usize && max_mergeset <= GHOSTDAG_K as usize {
        println!("VERDICT: narrow DAG (max anticone < K) => Legacy cannot under-count => DROP-IN.");
    } else {
        println!("VERDICT: wide anticones present => run the full differential to confirm GATED.");
    }
}
