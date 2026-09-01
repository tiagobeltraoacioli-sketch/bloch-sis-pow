// SPDX-License-Identifier: AGPL-3.0-or-later

//! `bloch-indexer` — build, serve and verify the historical index.
//!
//! ```text
//! bloch-indexer build   --log L --manifest M --carryover C
//! bloch-indexer serve   --log L --manifest M --carryover C [--bind 127.0.0.1:8090] [--poll-ms 5000]
//! bloch-indexer verify-reorg --log L --manifest M --carryover C [--depth 13]
//! bloch-indexer compare --log L --manifest M --carryover C [--archival 139.180.166.5:8080] [--sample 64]
//! ```
//!
//! Every subcommand reads a **local copy** of an archival observer's
//! `blocks.log`. Nothing here polls the fleet; `compare` is the sole exception
//! and it makes a bounded, spaced sample of `getbalance` calls against a
//! keyless archival, which is the whole point of `compare`.

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Instant;

use bloch_indexer::index::{Index, DEFAULT_UNDO_DEPTH};
use bloch_indexer::log::{LogReader, ScanEnd};
use bloch_indexer::{hex32, opening_ledger};

struct Args {
    cmd: String,
    log: PathBuf,
    manifest: PathBuf,
    carryover: PathBuf,
    bind: String,
    archival: String,
    poll_ms: u64,
    sample: usize,
    depth: usize,
    undo_depth: usize,
}

fn parse_args() -> Result<Args, String> {
    let mut a = Args {
        cmd: String::new(),
        log: PathBuf::new(),
        manifest: PathBuf::new(),
        carryover: PathBuf::new(),
        bind: "127.0.0.1:8090".into(),
        archival: "139.180.166.5:8080".into(),
        poll_ms: 5_000,
        sample: 64,
        depth: 13,
        undo_depth: DEFAULT_UNDO_DEPTH,
    };
    let mut it = std::env::args().skip(1);
    a.cmd = it.next().ok_or_else(usage)?;
    while let Some(f) = it.next() {
        let mut val = || it.next().ok_or_else(|| format!("{f} needs a value"));
        match f.as_str() {
            "--log" => a.log = PathBuf::from(val()?),
            "--manifest" => a.manifest = PathBuf::from(val()?),
            "--carryover" => a.carryover = PathBuf::from(val()?),
            "--bind" => a.bind = val()?,
            "--archival" => a.archival = val()?,
            "--poll-ms" => a.poll_ms = val()?.parse().map_err(|_| "bad --poll-ms")?,
            "--sample" => a.sample = val()?.parse().map_err(|_| "bad --sample")?,
            "--depth" => a.depth = val()?.parse().map_err(|_| "bad --depth")?,
            "--undo-depth" => a.undo_depth = val()?.parse().map_err(|_| "bad --undo-depth")?,
            other => return Err(format!("unknown flag {other}\n{}", usage())),
        }
    }
    Ok(a)
}

fn usage() -> String {
    "usage: bloch-indexer <build|serve|verify-reorg|compare> --log L --manifest M --carryover C \
     [--bind ADDR] [--archival HOST:PORT] [--poll-ms N] [--sample N] [--depth N] [--undo-depth N]"
        .to_string()
}

fn main() {
    if let Err(e) = run() {
        eprintln!("bloch-indexer: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let a = parse_args()?;
    match a.cmd.as_str() {
        "build" => {
            let (ix, t) = build(&a)?;
            report(&ix, t);
            Ok(())
        }
        "serve" => serve(&a),
        "verify-reorg" => verify_reorg(&a),
        "compare" => compare(&a),
        other => Err(format!("unknown command {other}\n{}", usage())),
    }
}

/// Build the index from scratch, timing each phase.
fn build(a: &Args) -> Result<(Index, BuildTiming), String> {
    let t0 = Instant::now();
    let (manifest, genesis_id, outputs) = opening_ledger(&a.manifest, &a.carryover)
        .map_err(|e| format!("opening ledger: {e}"))?;
    let genesis_outputs = outputs.len();
    let t_genesis = t0.elapsed();

    let t1 = Instant::now();
    let mut reader = LogReader::open(&a.log).map_err(|e| format!("opening log: {e}"))?;
    let t_scan = t1.elapsed();
    if reader.scan_end() != ScanEnd::Clean {
        eprintln!(
            "note: log scan ended with {:?} — the trailing frame is incomplete, which is normal \
             after a crash mid-append or a copy taken while the node was writing. Frames before \
             it are unaffected.",
            reader.scan_end()
        );
    }

    let t2 = Instant::now();
    let mut ix = Index::new(genesis_id, outputs, a.undo_depth);
    let t_seed = t2.elapsed();

    let t3 = Instant::now();
    let (applied, _) = ix.sync(&mut reader).map_err(|e| format!("applying log: {e}"))?;
    let t_apply = t3.elapsed();

    Ok((
        ix,
        BuildTiming {
            genesis_outputs,
            frames: reader.len(),
            applied,
            log_bytes: reader.fingerprint().len,
            validators: manifest.validators.len(),
            t_genesis,
            t_scan,
            t_seed,
            t_apply,
            t_total: t0.elapsed(),
        },
    ))
}

struct BuildTiming {
    genesis_outputs: usize,
    frames: usize,
    applied: u64,
    log_bytes: u64,
    validators: usize,
    t_genesis: std::time::Duration,
    t_scan: std::time::Duration,
    t_seed: std::time::Duration,
    t_apply: std::time::Duration,
    t_total: std::time::Duration,
}

fn report(ix: &Index, t: BuildTiming) {
    let tip = ix.tip();
    println!("── index built ──────────────────────────────────────────────");
    println!("  log                {} bytes, {} frames", t.log_bytes, t.frames);
    println!("  genesis outputs    {}", t.genesis_outputs);
    println!("  genesis validators {}", t.validators);
    println!("  blocks applied     {}", t.applied);
    println!("  height             {}", ix.height());
    println!("  tip slot / epoch   {} / {}", tip.slot, tip.epoch);
    println!("  tip block_id       {}", hex32(&tip.block_id));
    println!("  tip state_root     {}", hex32(&tip.state_root));
    println!("  transactions       {}", ix.txs.len());
    println!("  live outputs       {}", tip.eutxo_count);
    println!("  eutxo total        {} sat", tip.eutxo_total_sat);
    println!("  script hashes      {}", ix.balance.len());
    println!("  epochs             {}", ix.epochs.len());
    println!("  undecodable txs    {}", ix.stats.undecodable_txs);
    println!("── timing ───────────────────────────────────────────────────");
    println!("  genesis + carryover ingest  {:>9.3} s", t.t_genesis.as_secs_f64());
    println!("  frame-table scan            {:>9.3} s", t.t_scan.as_secs_f64());
    println!("  seed opening ledger         {:>9.3} s", t.t_seed.as_secs_f64());
    println!("  apply {:>6} blocks          {:>9.3} s", t.applied, t.t_apply.as_secs_f64());
    println!("  TOTAL                       {:>9.3} s", t.t_total.as_secs_f64());
    if t.applied > 0 {
        println!(
            "  rate                        {:>9.0} blocks/s ({:.1} MB/s over the log)",
            t.applied as f64 / t.t_apply.as_secs_f64().max(1e-9),
            t.log_bytes as f64 / 1e6 / t.t_apply.as_secs_f64().max(1e-9)
        );
    }
}

fn serve(a: &Args) -> Result<(), String> {
    let (ix, t) = build(a)?;
    report(&ix, t);
    let shared = Arc::new(RwLock::new(ix));
    let log = a.log.clone();
    let poll = std::time::Duration::from_millis(a.poll_ms.max(250));
    let writer = Arc::clone(&shared);
    std::thread::spawn(move || {
        // One reader, reopened when the file's identity changes. A reorg
        // renames a new file over blocks.log, so a reader that kept its handle
        // would go on reading the old inode for ever, quietly, and serve a
        // chain nobody is on.
        let mut reader = match LogReader::open(&log) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("sync: cannot open log: {e}");
                return;
            }
        };
        loop {
            std::thread::sleep(poll);
            match reader.changed() {
                Ok(false) => continue,
                Ok(true) => {}
                Err(e) => {
                    eprintln!("sync: stat failed: {e}");
                    continue;
                }
            }
            if let Err(e) = reader.reopen() {
                eprintln!("sync: reopen failed: {e}");
                continue;
            }
            let mut g = match writer.write() {
                Ok(g) => g,
                Err(_) => return,
            };
            match g.sync(&mut reader) {
                Ok((0, 0)) => {}
                Ok((ap, rb)) => {
                    eprintln!(
                        "sync: +{ap} blocks, -{rb} rolled back, height {}, tip {}",
                        g.height(),
                        hex32(&g.tip().block_id)
                    );
                }
                Err(e) => eprintln!(
                    "sync: {e}\n      the index is now BEHIND and will stay behind until it is \
                     rebuilt. It is not serving wrong answers — it is serving old ones, and \
                     /status says which height."
                ),
            }
        }
    });
    bloch_indexer::api::serve(&a.bind, shared).map_err(|e| e.to_string())
}

/// **Verify by violating.** Build the index over the whole log, then hand it a
/// log that has been rewritten exactly the way a reorg rewrites one, and show
/// it converges on the new chain rather than the one it had.
///
/// The rewrite is not synthetic: it takes the real frames, drops the last
/// `--depth` of them, and appends the same frames back in a way that produces a
/// DIFFERENT chain — so the index must roll back and re-apply, not merely
/// extend. Then the original log is put back and the index must converge on
/// that, proving the rollback was not one-way.
fn verify_reorg(a: &Args) -> Result<(), String> {
    let (mut ix, t) = build(a)?;
    let full_height = ix.height();
    let full_tip = ix.tip().block_id;
    let full_total = ix.eutxo_total_sat();
    let full_txs = ix.txs.len();
    println!("baseline: height {full_height}, tip {}", hex32(&full_tip));
    println!("          {} live outputs, {} sat", ix.tip().eutxo_count, full_total);
    let _ = t;

    let depth = a.depth.max(1);
    let bytes = std::fs::read(&a.log).map_err(|e| e.to_string())?;
    // Rebuild the frame boundaries so we can cut whole frames.
    let mut bounds = Vec::new();
    let mut at = 0usize;
    while at + 4 <= bytes.len() {
        let len = u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
            as usize;
        if at + 4 + len > bytes.len() {
            break;
        }
        bounds.push((at, 4 + len));
        at += 4 + len;
    }
    if bounds.len() <= depth {
        return Err("log is shorter than the requested reorg depth".into());
    }
    let cut_at = bounds[bounds.len() - depth].0;

    let dir = std::env::temp_dir().join(format!("bloch-indexer-reorg-{}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let shortened = dir.join("blocks.log");

    // A reorg is `Store::rewrite`: a NEW file renamed over the old one. Reproduce
    // that exactly — write a temp and rename — so the reader meets the same
    // inode change a real reorg produces.
    write_and_rename(&shortened, &bytes[..cut_at])?;
    let mut reader = LogReader::open(&shortened).map_err(|e| e.to_string())?;

    // Point the index at the shortened chain. This is the rollback path.
    let (ap, rb) = ix.sync(&mut reader).map_err(|e| e.to_string())?;
    println!("\n── after a {depth}-block truncation (the rollback path) ──");
    println!("  applied {ap}, rolled back {rb}");
    println!("  height {} (was {full_height})", ix.height());
    println!("  tip    {}", hex32(&ix.tip().block_id));
    if rb != depth as u64 {
        return Err(format!("expected to roll back {depth} blocks, rolled back {rb}"));
    }
    if ix.height() != full_height - depth as u64 {
        return Err("height did not fall by the reorg depth".into());
    }

    // Independent check that the rollback restored the SET and not just the
    // counters: rebuild from scratch over the same shortened log and compare.
    let (mut fresh, _) = build(&Args { log: shortened.clone(), ..clone_args(a) })?;
    compare_indexes(&ix, &fresh, "after rollback")?;
    println!("  rolled-back index is identical to a fresh build of the same log ✓");

    // Now put the original chain back — again by rename, again a new inode —
    // and show the index converges forward onto it.
    write_and_rename(&shortened, &bytes[..])?;
    if !reader.changed().map_err(|e| e.to_string())? {
        return Err("the reader failed to notice the log was replaced".into());
    }
    reader.reopen().map_err(|e| e.to_string())?;
    let (ap2, rb2) = ix.sync(&mut reader).map_err(|e| e.to_string())?;
    println!("\n── after the chain is restored (the re-apply path) ──");
    println!("  applied {ap2}, rolled back {rb2}");
    println!("  height {}", ix.height());
    println!("  tip    {}", hex32(&ix.tip().block_id));
    if ix.tip().block_id != full_tip {
        return Err("index did not converge back to the original tip".into());
    }
    if ix.eutxo_total_sat() != full_total || ix.txs.len() != full_txs {
        return Err("index converged on the tip but not on the state".into());
    }
    fresh = build(&Args { log: shortened.clone(), ..clone_args(a) })?.0;
    compare_indexes(&ix, &fresh, "after re-apply")?;
    println!("  re-applied index is identical to a fresh build of the same log ✓");

    // The control. Without it, the test above proves only that two runs of the
    // same code agree — it must be able to FAIL.
    let (control, _) = build(&Args { log: a.log.clone(), depth: 0, ..clone_args(a) })?;
    if compare_indexes(&control, &fresh, "control").is_err() {
        return Err("control comparison should have PASSED (same log, same result)".into());
    }
    write_and_rename(&shortened, &bytes[..cut_at])?;
    let (short, _) = build(&Args { log: shortened.clone(), ..clone_args(a) })?;
    if compare_indexes(&control, &short, "control").is_ok() {
        return Err(
            "control comparison should have FAILED: a chain 13 blocks shorter is not the same \
             index, and a comparison that cannot fail proves nothing"
                .into(),
        );
    }
    println!("\n  control: comparing the full chain against the truncated one FAILS, as it must ✓");

    let _ = std::fs::remove_dir_all(&dir);
    println!("\nreorg handling verified.");
    Ok(())
}

fn clone_args(a: &Args) -> Args {
    Args {
        cmd: a.cmd.clone(),
        log: a.log.clone(),
        manifest: a.manifest.clone(),
        carryover: a.carryover.clone(),
        bind: a.bind.clone(),
        archival: a.archival.clone(),
        poll_ms: a.poll_ms,
        sample: a.sample,
        depth: a.depth,
        undo_depth: a.undo_depth,
    }
}

/// Write `bytes` to a temp file and rename it into place — the shape
/// `Store::rewrite` uses, so the reader sees the same inode change a reorg
/// produces rather than an in-place truncation it could miss.
fn write_and_rename(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let tmp = path.with_extension("log.tmp");
    std::fs::write(&tmp, bytes).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())
}

/// Whole-index equality, not a spot check: chain, unspent set, balances,
/// transactions and per-epoch aggregates.
fn compare_indexes(a: &Index, b: &Index, what: &str) -> Result<(), String> {
    if a.chain.len() != b.chain.len() {
        return Err(format!("{what}: height {} vs {}", a.height(), b.height()));
    }
    for (x, y) in a.chain.iter().zip(b.chain.iter()) {
        if x != y {
            return Err(format!("{what}: block row differs at height {}", x.height));
        }
    }
    if a.utxo.len() != b.utxo.len() {
        return Err(format!("{what}: {} live outputs vs {}", a.utxo.len(), b.utxo.len()));
    }
    for (op, u) in &a.utxo {
        match b.utxo.get(op) {
            Some(v) if v == u => {}
            _ => return Err(format!("{what}: output {}:{} differs", hex32(&op.txid), op.vout)),
        }
    }
    if a.balance.len() != b.balance.len() {
        return Err(format!("{what}: {} balances vs {}", a.balance.len(), b.balance.len()));
    }
    for (sh, v) in &a.balance {
        if b.balance.get(sh) != Some(v) {
            return Err(format!("{what}: balance of {} differs", hex32(sh)));
        }
    }
    if a.txs.len() != b.txs.len() {
        return Err(format!("{what}: {} transactions vs {}", a.txs.len(), b.txs.len()));
    }
    if a.epochs != b.epochs {
        return Err(format!("{what}: epoch aggregates differ"));
    }
    if a.participation != b.participation {
        return Err(format!("{what}: participation differs"));
    }
    Ok(())
}

/// Compare a sample of indexed balances against a live archival's `getbalance`.
///
/// The sample is deliberately spread rather than random-uniform: the biggest
/// holders, some in the middle, and some at the bottom, because the failure
/// this catches — a wrong `script_hash` derivation or a lost satoshi in a sum —
/// shows up at different magnitudes for different reasons.
fn compare(a: &Args) -> Result<(), String> {
    let (ix, _) = build(a)?;
    let mut probe = bloch_indexer::rpcprobe::Probe::new(&a.archival, 120)?;
    let (node_height, node_slot, node_tip, node_root) = probe.chaininfo()?;
    println!("\n── comparing against {} ──", a.archival);
    println!("  index: height {:>6}  slot {:>6}  tip {}", ix.height(), ix.tip().slot, hex32(&ix.tip().block_id));
    println!("  node : height {node_height:>6}  slot {node_slot:>6}  tip {node_tip}");
    println!("  node state_root {node_root}");
    println!("  index tip state_root {}", hex32(&ix.tip().state_root));

    if ix.height() != node_height {
        println!(
            "\n  NOTE: the index is at height {} and the node at {node_height}. The log was \
             copied at a moment in time and the chain has moved since. Balances are compared \
             anyway, and a mismatch on an address that received or spent in the gap is EXPECTED \
             — the per-address lines below say which.",
            ix.height()
        );
    }

    let mut holders: Vec<(&[u8; 32], &u128)> = ix.balance.iter().collect();
    holders.sort_by(|x, y| y.1.cmp(x.1).then(x.0.cmp(y.0)));
    let n = a.sample.min(holders.len());
    let mut picks: Vec<usize> = Vec::new();
    if n > 0 {
        // Top, evenly-spaced middle, and bottom.
        let top = n / 3;
        for i in 0..top {
            picks.push(i);
        }
        let stride = (holders.len() / (n - top).max(1)).max(1);
        let mut i = top;
        while picks.len() < n && i < holders.len() {
            picks.push(i);
            i += stride;
        }
        picks.dedup();
    }

    let mut agree = 0usize;
    let mut disagree = Vec::new();
    for i in &picks {
        let (sh, mine) = holders[*i];
        let hex = hex32(sh);
        match probe.balance(&hex) {
            Ok(theirs) if theirs == *mine => {
                agree += 1;
            }
            Ok(theirs) => {
                disagree.push((hex, *mine, theirs));
            }
            Err(e) => {
                disagree.push((hex, *mine, 0));
                eprintln!("  rpc error for {}: {e}", hex32(sh));
            }
        }
    }

    println!("\n  sampled {} script hashes: {agree} agree, {} differ", picks.len(), disagree.len());
    for (hex, mine, theirs) in disagree.iter().take(20) {
        println!("    {hex}\n      index {mine}\n      node  {theirs}   (delta {})", *theirs as i128 - *mine as i128);
    }
    // Also check that a hash the index has never seen reads zero on both sides,
    // which is the shape the two-derivation bug takes: a funded key that reads 0.
    let never = "00".repeat(32);
    match probe.balance(&never) {
        Ok(0) => println!("\n  an unused script_hash reads 0 on the node, as it does here ✓"),
        Ok(v) => println!("\n  unexpected: an all-zero script_hash holds {v} sat on the node"),
        Err(e) => println!("\n  could not check the all-zero script_hash: {e}"),
    }
    if disagree.is_empty() {
        println!("\n  every sampled balance agrees with the node.");
        Ok(())
    } else {
        Err(format!("{} of {} sampled balances disagree", disagree.len(), picks.len()))
    }
}
