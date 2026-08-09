//! bloch-pool — reference pool daemon.
//!
//! Wiring: template poll loop (upstream RPC) + stratum server (miners)
//! + dashboard (HTTP). See lib.rs for the architecture and the honesty
//! guardrails; run with RUST_LOG=info for a readable event stream.

use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use log::{error, info, warn};

use bloch_crypto::address::Address;
use bloch_pool::job::Job;
use bloch_pool::payout::MAX_FEE_BPS;
use bloch_pool::state::{Config, PoolState};
use bloch_pool::{dashboard, stratum};

#[derive(Parser, Debug)]
#[command(
    name = "bloch-pool",
    about = "REFERENCE mining pool for Bloch-SIS-PoW — for coordination and testing, \
             not profit. Fork it; run your own; keep every pool small.",
)]
struct Cli {
    /// Bloch node JSON-RPC endpoint (needs the getblocktemplate/submitblock seam).
    #[arg(long, default_value = "http://127.0.0.1:16210")]
    node_rpc: String,

    /// Pool payout address (bloch1q… / bloch1t…). Block rewards land here;
    /// PPLNS credits are split off-chain from it.
    #[arg(long)]
    pool_address: String,

    /// Pool fee in basis points (100 = 1%). Default 0. Capped at 1000 (10%),
    /// mirroring the node's FeeSplit guardrail.
    #[arg(long, default_value = "0")]
    fee_bps: u16,

    /// Compact share difficulty (hex, e.g. 2100ffff). Shares must meet this
    /// target on the SHAKE-256 aux hash; blocks additionally meet the chain
    /// target. Fixed for the whole pool (no vardiff in the reference).
    #[arg(long, default_value = "2100ffff")]
    share_bits: String,

    /// PPLNS window size, in shares.
    #[arg(long, default_value = "4096")]
    pplns_window: usize,

    /// Miner-facing stratum listen address.
    #[arg(long, default_value = "0.0.0.0:3335")]
    listen: String,

    /// Dashboard HTTP listen address.
    #[arg(long, default_value = "127.0.0.1:8650")]
    dashboard: String,

    /// Template poll interval (seconds).
    #[arg(long, default_value = "5")]
    refresh_secs: u64,

    /// Coinbase attribution tag.
    #[arg(long, default_value = "bloch-pool-ref/v0.1")]
    coinbase_tag: String,

    /// Blocks are credited only once canonical at this depth. Credits
    /// from a block that gets orphaned/reorged before maturity are
    /// dropped, never booked.
    #[arg(long, default_value = "10")]
    confirm_depth: u64,

    /// Append-only JSONL share/credit journal, replayed at startup so
    /// a restart cannot erase owed balances or the PPLNS window.
    /// Pass an empty string to run memory-only (testing).
    #[arg(long, default_value = "bloch-pool.journal")]
    journal: String,

    /// Disable the address-ownership proof at mining.authorize
    /// (default ON: miners must sign the session challenge with the
    /// key controlling their payout address).
    #[arg(long)]
    no_auth_proof: bool,
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();

    // ── Validate config ──────────────────────────────────────────
    let addr = match Address::parse(&cli.pool_address) {
        Ok(a) => a,
        Err(e) => {
            error!("--pool-address is not a valid Bloch address: {}", e);
            std::process::exit(1);
        }
    };
    if cli.fee_bps > MAX_FEE_BPS {
        error!("--fee-bps {} exceeds the 10% cap ({})", cli.fee_bps, MAX_FEE_BPS);
        std::process::exit(1);
    }
    let share_bits = match u32::from_str_radix(cli.share_bits.trim_start_matches("0x"), 16) {
        Ok(b) => b,
        Err(_) => {
            error!("--share-bits must be compact bits in hex (e.g. 2100ffff)");
            std::process::exit(1);
        }
    };

    // ── The honest banner, in the operator's face at startup ─────
    info!("──────────────────────────────────────────────────────────────");
    info!("bloch-pool — OPEN-SOURCE REFERENCE POOL (unaudited, not production)");
    info!("· Pools centralize what should be decentralized. A pool with >51%");
    info!("  of hashrate IS a 51%-attack vector. Healthy = several independent");
    info!("  small pools + solo miners. Fork this and run your own.");
    info!("· The coin is worth nothing by design (mainnet-beta, unaudited,");
    info!("  young/51%-attackable). This is for coordination + testing, not profit.");
    info!("· Solo mining stays the default: `bloch --mine` needs no pool.");
    info!("· PoW = SHAKE-256 hashcash + Module-SIS structural gate. Shares are");
    info!("  hash-difficulty shares. It is NOT lattice-hard.");
    info!("──────────────────────────────────────────────────────────────");

    let cfg = Config {
        node_rpc:     cli.node_rpc,
        pool_address: cli.pool_address.clone(),
        pool_spk:     addr.hash().to_vec(),
        fee_bps:      cli.fee_bps,
        share_bits,
        pplns_window: cli.pplns_window,
        listen:       cli.listen,
        dashboard:    cli.dashboard,
        refresh_secs: cli.refresh_secs.max(1),
        coinbase_tag: cli.coinbase_tag,
        confirm_depth: cli.confirm_depth.max(1),
        journal:      if cli.journal.is_empty() { None } else { Some(cli.journal) },
        require_auth_proof: !cli.no_auth_proof,
    };
    info!("payouts → {} | fee {} bps | share bits 0x{:08x} | PPLNS window {} shares \
           | confirm depth {} | journal {} | ownership proof {}",
        cfg.pool_address, cfg.fee_bps, cfg.share_bits, cfg.pplns_window,
        cfg.confirm_depth,
        cfg.journal.as_deref().unwrap_or("OFF (memory-only)"),
        if cfg.require_auth_proof { "required" } else { "OFF" });

    let pool = match PoolState::new(cfg) {
        Ok(p) => Arc::new(p),
        Err(e) => {
            error!("cannot start: {}", e);
            std::process::exit(1);
        }
    };

    // ── Template poll loop ────────────────────────────────────────
    let pool_t = pool.clone();
    tokio::spawn(async move { template_loop(pool_t).await });

    // ── Block confirmation loop (maturity gate) ───────────────────
    let pool_c = pool.clone();
    tokio::spawn(async move { confirm_loop(pool_c).await });

    // ── Dashboard ─────────────────────────────────────────────────
    let pool_d = pool.clone();
    tokio::spawn(async move {
        if let Err(e) = dashboard::run(pool_d).await {
            error!("dashboard exited: {}", e);
        }
    });

    // ── Stratum server (foreground) ───────────────────────────────
    if let Err(e) = stratum::run(pool).await {
        error!("stratum server exited: {}", e);
        std::process::exit(1);
    }
}

/// Poll the node for work. A new job is cut when the parents/height
/// change (clean_jobs=true: old work can no longer win) or every
/// `refresh_secs * 6` ticks to absorb mempool churn (clean=false).
async fn template_loop(pool: Arc<PoolState>) {
    let mut ticks: u64 = 0;
    let refresh = Duration::from_secs(pool.cfg.refresh_secs);

    loop {
        ticks += 1;
        let pool2 = pool.clone();
        let tmpl = tokio::task::spawn_blocking(move || pool2.upstream.get_block_template())
            .await
            .unwrap_or_else(|e| Err(format!("join: {}", e)));

        match tmpl {
            Err(e) => warn!("getblocktemplate failed (node down?): {}", e),
            Ok(tmpl) => {
                // Never trust a divergent node across a halving (or across the
                // Emission V3 flag-day): the subsidy must match consensus for
                // the EMISSION height — block_subsidy_sat takes the absolute
                // emission height (local + carry-over offset), which the node
                // reports as `emission_height`. Checking against the LOCAL
                // height would compute the wrong epoch from the V3 fork
                // (local 40,000 = emission 453,743) onward.
                let expect = bloch_crypto::core::tokenomics_v2::block_subsidy_sat(tmpl.emission_height);
                if tmpl.subsidy_sat != expect {
                    error!("template subsidy {} sat != consensus {} sat at h={} (emission h={}) — \
                            refusing to cut a job from a divergent node",
                        tmpl.subsidy_sat, expect, tmpl.height, tmpl.emission_height);
                    tokio::time::sleep(refresh).await;
                    continue;
                }
                pool.note_template_ok();
                let current = pool.current_job();
                let tip_changed = current.as_ref()
                    .map(|j| j.height != tmpl.height || j.block.header.parents != tmpl.parents)
                    .unwrap_or(true);
                let periodic = ticks % 6 == 0;

                if tip_changed || periodic {
                    let job = Job::build(
                        &tmpl, &pool.cfg.pool_spk, &pool.cfg.coinbase_tag, pool.next_job_id());
                    let job = pool.push_job(job);
                    let sessions = pool.authorized_sessions();
                    info!("job {} h={} bits=0x{:08x} reward={} sat ({} txs) → {} miners{}",
                        job.id, job.height, job.bits, job.reward_sat,
                        job.block.transactions.len() - 1, sessions.len(),
                        if tip_changed { " [clean]" } else { "" });
                    let line = stratum::notify_line(&job, tip_changed);
                    for s in sessions {
                        let _ = s.send_line(line.clone());
                    }
                }
            }
        }

        tokio::time::sleep(refresh).await;
    }
}

/// Maturity gate: pending blocks are confirmed (credits booked) only
/// once they are the canonical block at their height at
/// `confirm_depth`; a pending block whose height has a DIFFERENT
/// canonical hash at that depth was reorged out — its snapshotted
/// credit is dropped, never booked. Until one of those verdicts, the
/// block stays pending (visible as such on the dashboard).
async fn confirm_loop(pool: Arc<PoolState>) {
    let interval = Duration::from_secs(pool.cfg.refresh_secs.max(5));
    let depth = pool.cfg.confirm_depth;

    loop {
        tokio::time::sleep(interval).await;

        let pending = pool.ledger.lock().pending_blocks();
        if pending.is_empty() {
            continue;
        }

        let pool2 = pool.clone();
        let tip = tokio::task::spawn_blocking(move || pool2.upstream.get_tip())
            .await
            .unwrap_or_else(|e| Err(format!("join: {}", e)));
        let tip_height = match tip {
            Ok((_, h)) => h,
            Err(e) => { warn!("confirm loop: get_tip failed: {}", e); continue; }
        };

        for (height, hash_hex) in pending {
            if tip_height < height.saturating_add(depth) {
                continue; // not deep enough yet
            }
            let pool2 = pool.clone();
            let canonical = tokio::task::spawn_blocking(move || {
                pool2.upstream.get_canonical_hash_at(height)
            }).await.unwrap_or_else(|e| Err(format!("join: {}", e)));

            match canonical {
                Ok(Some(h)) if h == hash_hex => {
                    if let Some(payouts) = pool.ledger.lock().confirm_block(&hash_hex) {
                        info!("block h={} {} CONFIRMED at depth {} — credited {} miners",
                            height, &hash_hex[..hash_hex.len().min(16)],
                            depth, payouts.len());
                    }
                }
                Ok(_) => {
                    // Different canonical hash (or none) at maturity:
                    // our block did not make it. Drop the credit.
                    if pool.ledger.lock().orphan_block(&hash_hex) {
                        warn!("block h={} {} ORPHANED — pending credit dropped",
                            height, &hash_hex[..hash_hex.len().min(16)]);
                    }
                }
                Err(e) => warn!("confirm loop: getblockhash h={} failed: {}", height, e),
            }
        }
    }
}
