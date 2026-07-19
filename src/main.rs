//! Bloch-SIS Protocol Node — Minimum energy. Maximum stability.
//!
//! Fixes applied:
//!   #1  Real ML-DSA-65 signatures
//!   #2  Full IBD: PeerTip → GetHeaders → Headers → GetBlock → NewBlock response
//!   #3  Block structural + TX signature validation before storing
//!   #4  Persistent P2P identity
//!   #5  Mempool with fee ordering
//!   #6  Peer memory (known_peers.json)
//!   #7  Difficulty retargeting every 2016 blocks (seconds, not ms)
//!   #8  Founder/miner address uses proper 20-byte pubkey hash
//!   #9  Intra-block double-spend prevention via spent-set tracking
//!   #10 Unified TX validation (single code path for block/mempool/RPC)
//!   #11 Removed duplicated mining loop

// The crypto/wallet/tx island moved to the `bloch-crypto` crate
// (crates/bloch-crypto). Re-export its modules under `crate::` so every
// `core::…` / `crate::crypto::…` path in this binary and its sibling node
// modules keeps resolving unchanged.
use bloch_crypto::{crypto, core, address};

mod consensus;
mod mining;
mod storage;
mod network;
mod rpc;
mod metrics;
mod pow;         // Sprint B5 — Module-SIS PoW adapter
mod transport;
mod mempool;
mod analytics;
mod reorg;
mod attestation;  // L3 attestation (referenced by rpc)
mod coherence;    // Coherence C2 shielded pool
mod dandelion;    // Coherence P3 Dandelion++ tx-relay privacy
mod stratum;  // Sprint AA.1 — stratum V1 mining server
mod stratum_v2;   // Sprint 10-alpha — stratum V2 mining server (NOISE_NX + SV2)
mod sync;         // Phase 2 — drop-in Kaspa sync-negotiation layer

use clap::Parser;
use log::{info, warn, error, debug};
use std::sync::Arc;
use std::collections::HashSet;
use std::path::PathBuf;
use parking_lot::RwLock;
use tokio::sync::{mpsc, broadcast};

#[derive(Parser)]
#[command(name = "bloch")]
#[command(about = "Bloch-SIS Protocol — Module-SIS PoW · Falcon‖ML-DSA · GhostDAG-Q")]
#[command(version)]
struct Cli {
    #[arg(long)]                                         mine: bool,
    /// Number of CPU cores the SIS miner grinds across in parallel. Each worker
    /// searches a disjoint nonce range under the same regime (result-identical
    /// to single-thread mining — pure throughput). Defaults to all logical CPUs.
    #[arg(long)]                                         mine_threads: Option<usize>,
    /// Keep EVERY block body — never prune. An archival node is what lets a
    /// FRESH node bootstrap: the default pruning depth (10,000 blocks) deletes
    /// bodies from CF_BLOCKS while the header/DAG map keeps every entry, so a
    /// pruned node still ADVERTISES headers it can no longer serve. With no
    /// archival peer anywhere on the network, a new node asks for block 0, is
    /// promised 500 headers, receives no bodies, and loops forever at height 1.
    /// That is the observed failure on this fleet (2026-07-19): every node had
    /// pruned below ~394,913, so those bodies exist nowhere and cannot be
    /// recovered. Run at least one archival node, or new nodes cannot join.
    /// Costs disk: the full chain instead of the last 10,000 blocks.
    /// Re-derive the carry-over root FROM THE DATABASE and exit. Verifies what
    /// this data-dir actually CONTAINS, not what a file hashed to when it was
    /// ingested — the meta stamp is a copied string and proves nothing about the
    /// ledger now. Run this on any data-dir you did not build yourself, and
    /// especially on one you downloaded: a "fast bootstrap" tarball is exactly
    /// the case the stamp cannot catch. Exits 0 on match, 1 on mismatch.
    #[arg(long)]                                         verify_carryover: bool,
    #[arg(long)]                                         archive: bool,
    /// Genesis-2 carry-over: path to the blessed UTXO snapshot TSV, ingested
    /// once at FIRST boot. Before anything is written the file is fully
    /// verified against the baked-in constants (bloch-crypto core): SHAKE-256
    /// over its RAW bytes must equal CARRYOVER_SNAPSHOT_ROOT, its line count
    /// CARRYOVER_UTXO_COUNT, and its summed value CARRYOVER_TOTAL_SAT. Any
    /// mismatch → the node logs the specific failure(s) and refuses to start
    /// (exit 1), like the genesis PoW check. A chain-id that REQUIRES
    /// carry-over refuses to start if this flag is absent.
    #[arg(long)]                                         carryover_snapshot: Option<PathBuf>,
    #[arg(long)]                                         testnet: bool,
    #[arg(long, default_value = "./bloch-data")]          data_dir: String,
    /// RPC bind address. SECURITY: defaults to 127.0.0.1 (local only).
    /// Use --rpc-public to bind 0.0.0.0, which exposes RPC to the internet.
    #[arg(long, default_value = "127.0.0.1")]            rpc_bind: String,
    /// Override rpc_bind to 0.0.0.0. DANGEROUS when unauthenticated.
    #[arg(long)]                                         rpc_public: bool,
    #[arg(long, default_value = "16210")]                rpc_port: u16,

    // ── Sprint M: authentication ────────────────────────────────────
    /// Shared-secret API key required for authenticated endpoints.
    /// Takes precedence over --rpc-api-key-file. Passing via CLI leaks
    /// the key into `ps aux`; prefer --rpc-api-key-file in production.
    #[arg(long)]                                         rpc_api_key: Option<String>,
    /// File containing the API key (first line, trimmed). Safer than --rpc-api-key.
    /// Suggested permissions: 0600, owned by the node user.
    #[arg(long)]                                         rpc_api_key_file: Option<std::path::PathBuf>,
    /// When true, writes (sendrawtransaction) require X-API-Key.
    /// Requires --rpc-api-key or --rpc-api-key-file to be set.
    /// Reads remain public (explorers need them).
    #[arg(long)]                                         rpc_require_auth_for_writes: bool,

    // ── Sprint M: rate limiting ─────────────────────────────────────
    /// Per-IP read-method rate limit, requests per minute. Default 60.
    /// Localhost (127.0.0.1, ::1) is exempt.
    #[arg(long, default_value = "60")]                   rpc_rate_limit_reads: u32,
    /// Per-IP write-method rate limit, requests per minute. Default 5.
    #[arg(long, default_value = "5")]                    rpc_rate_limit_writes: u32,

    /// Sprint M-patch1: also trust RFC1918 (10/8, 172.16/12, 192.168/16) and
    /// IPv6 ULA (fc00::/7) as "loopback" for auth/rate-limit bypass.
    /// This is needed when running in Docker with default bridge networking,
    /// where the host's 127.0.0.1 traffic appears as 172.17.0.1 inside the
    /// container. SECURITY: only enable on trusted single-tenant hosts. On
    /// Kubernetes, shared VLANs, or any multi-tenant network, leave this off.
    #[arg(long)]                                         rpc_trust_private_ranges: bool,

    // ── Sprint D: Prometheus metrics ─────────────────────────────────
    /// Enable Prometheus metrics server. Off by default (opt-in).
    /// Convention follows Geth: endpoint at /debug/metrics/prometheus.
    #[arg(long)]                                         metrics: bool,
    /// Metrics bind address. Default 127.0.0.1 (localhost-only).
    #[arg(long, default_value = "127.0.0.1")]            metrics_addr: String,
    /// Metrics port. Default 16310 (Bloch-SIS Protocol namespace).
    #[arg(long, default_value = "16310")]                metrics_port: u16,
    /// Shortcut: binds metrics to 0.0.0.0 (publicly reachable).
    /// DANGER: reveals version, peer count, timing data. Use only if you
    /// accept that the node advertises its status publicly.
    #[arg(long)]                                         metrics_public: bool,
    #[arg(long, default_value = "/ip4/0.0.0.0/tcp/16110")] listen: String,
    #[arg(long)]                                         peer: Vec<String>,
    #[arg(long)]                                         miner_address: Option<String>,
    /// Sprint P: allow RFC1918 / loopback addresses via PEX. Dev/test only.
    /// Production deployments should leave this off; it opens a scanning vector.
    #[arg(long)]                                         allow_private_peers: bool,
    /// Mesh fix: set when this node sits behind a TCP proxy / NAT that makes
    /// many peers share one source IP (fly.io edge, k8s ingress, CGNAT). The
    /// gossipsub ip-colocation penalty (-50 x excess^2 above 3 peers/IP) would
    /// otherwise graylist the whole mesh at ~6 peers and silently blackhole
    /// every tip announcement. Disables only that weight; all other peer
    /// scoring stays active. Non-consensus — purely an operator knob.
    #[arg(long)]                                         behind_proxy: bool,
    /// Maximum peer connections (inbound cap). Raise this on a well-provisioned
    /// bootstrap / hub node so newcomers aren't rejected once the cap fills;
    /// keep it modest on a leaf node. Non-consensus — purely an operator knob.
    #[arg(long, default_value_t = 50)]                   max_peers: usize,
    /// Optional DNS seed hostname(s): the node resolves each to its A/AAAA
    /// records and dials them as peers (default port 16110; pass host:port to
    /// override). Bitcoin-style cold-start convenience — NON-privileged and
    /// opt-in: the shipped DEFAULT_SEEDS stays empty, so nobody's seed is
    /// required and you can point at (or run) any seed you trust. Repeatable.
    #[arg(long)]                                         dns_seed: Vec<String>,

    // ── Sprint 2 (AA.1 pt 3): stratum V1 mining server ──────────────
    /// Enable the stratum V1 mining server. Miners can connect at
    /// stratum+tcp://<host>:<stratum_port>. See docs/operations/stratum.md.
    #[arg(long)]                                         stratum: bool,
    /// Bind address for the stratum server.
    #[arg(long, default_value = "0.0.0.0:3333")]         stratum_addr: String,
    /// Stratum operating mode: 'solo' only for now. 'pool' is Sprint AA.2.
    #[arg(long, default_value = "solo")]                 stratum_mode: String,
    /// Max concurrent stratum sessions.
    #[arg(long, default_value = "256")]                  stratum_max_sessions: usize,
    /// Coinbase tag written into mined block coinbases for attribution.
    #[arg(long, default_value = "bloch-sis/v0.1")] stratum_coinbase_tag: String,

    // ── Sprint 10-alpha: stratum V2 mining server ─────────────────────
    /// Enable the stratum V2 mining server. Miners connect at
    /// <host>:<sv2_port>. V2 uses NOISE_NX handshake (encrypted
    /// from byte 0) and SV2 binary framing. Runs in parallel to
    /// V1; both can be enabled at once on different ports.
    #[arg(long)]                                         sv2_enable: bool,
    /// Bind address for the stratum V2 server. Default 0.0.0.0:3334.
    #[arg(long, default_value = "0.0.0.0:3334")]         sv2_addr: String,
    /// Max concurrent V2 sessions.
    #[arg(long, default_value = "500")]                  sv2_max_sessions: usize,
    /// Path to the SV2 authority keypair JSON file. Auto-generated on
    /// first run if absent. Default: <data_dir>/sv2-authority-keypair.json.
    /// PROTECT THIS FILE: compromise allows any peer to impersonate
    /// this pool. Suggested permissions: 0600, owned by the node user.
    #[arg(long)]                                         sv2_cert_path: Option<PathBuf>,
}

// Bloch-SIS founder address. Unified with tokenomics_v2::FOUNDER_ADDRESS_HASH
// so the genesis coinbase and the monthly vesting output pay the SAME wallet.
// This is the founder-owned keystore (~/bloch-founder.json, password held by
// the founder only) — NOT the old public dev seed.
const FOUNDER_ADDRESS_HEX: &str = "bloch1qe986db5149cff7499b282a048272a09aff0af4ff84242073";

/// FIX #8: Extract the 20-byte pubkey hash from a bloch1q/bloch1t address string.
/// Address format: prefix (6 chars) + 40 hex chars (20-byte hash) + 8 hex chars (4-byte checksum)
fn address_to_script_pubkey(addr: &str) -> Vec<u8> {
    let stripped = addr
        .trim_start_matches(core::MAINNET_PREFIX)
        .trim_start_matches(core::TESTNET_PREFIX);
    // First 40 hex chars = 20-byte pubkey hash
    let hash_hex = &stripped[..40.min(stripped.len())];
    hex::decode(hash_hex).unwrap_or_else(|_| addr.as_bytes().to_vec())
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info")
    ).init();

    let cli = Cli::parse();

    // Roadmap #8: wire the node-level chain-id ONCE at startup from the runtime
    // network selection, before any validation runs. The miner and every
    // validator read core::node_chain_id() (design §4.3 invariant 6); without
    // this call a testnet node would default to the Mainnet sighash domain and
    // reject every correctly-signed testnet transaction.
    core::set_node_chain_id(
        if cli.testnet { core::ChainId::Testnet } else { core::ChainId::Mainnet }
    ).expect("node chain-id must be settable exactly once at startup");

    // FIX v0.5.1 BLK-3: apply --rpc-public escape hatch.
    let rpc_bind = if cli.rpc_public { "0.0.0.0".to_string() } else { cli.rpc_bind.clone() };

    // ── Sprint M: load API key (CLI takes precedence over file) ────
    let api_key: Option<String> = match (&cli.rpc_api_key, &cli.rpc_api_key_file) {
        (Some(k), _) => Some(k.trim().to_string()),
        (None, Some(path)) => {
            match std::fs::read_to_string(path) {
                Ok(contents) => {
                    let k = contents.lines().next().unwrap_or("").trim().to_string();
                    if k.is_empty() {
                        eprintln!("⚠  --rpc-api-key-file {:?} is empty; ignoring.", path);
                        None
                    } else {
                        Some(k)
                    }
                }
                Err(e) => {
                    eprintln!("⚠  failed to read --rpc-api-key-file {:?}: {}", path, e);
                    None
                }
            }
        }
        (None, None) => None,
    };

    // Guard: --rpc-require-auth-for-writes without a key is a config error
    if cli.rpc_require_auth_for_writes && api_key.is_none() {
        eprintln!("❌ --rpc-require-auth-for-writes requires --rpc-api-key or --rpc-api-key-file");
        std::process::exit(2);
    }

    // Warnings on public bind
    if cli.rpc_trust_private_ranges {
        eprintln!("⚠  --rpc-trust-private-ranges: RFC1918 and IPv6 ULA ranges");
        eprintln!("   will bypass auth and rate limits. Only safe on trusted");
        eprintln!("   single-tenant hosts. DO NOT use on Kubernetes or shared VLANs.");
    }

    // ── Sprint D: resolve metrics bind, print warnings ───────────────
    let metrics_bind = if cli.metrics_public {
        "0.0.0.0".to_string()
    } else {
        cli.metrics_addr.clone()
    };
    if cli.metrics && cli.metrics_public {
        eprintln!("⚠  --metrics-public: Prometheus endpoint on 0.0.0.0:{}", cli.metrics_port);
        eprintln!("   Reveals version, peer count, hashrate, timing data.");
        eprintln!("   For most operators, prefer localhost + SSH tunnel or Grafana Agent push.");
    }

    if cli.rpc_public {
        eprintln!("⚠  --rpc-public binds RPC to 0.0.0.0 (all interfaces).");
        if api_key.is_none() {
            eprintln!("⚠  No --rpc-api-key set. Writes are rate-limited but not authenticated.");
            eprintln!("⚠  Recommend: --rpc-api-key-file <PATH> --rpc-require-auth-for-writes");
        } else if !cli.rpc_require_auth_for_writes {
            eprintln!("ℹ  API key set but --rpc-require-auth-for-writes is off.");
            eprintln!("ℹ  Writes will still accept unauthenticated requests (rate-limited).");
        } else {
            eprintln!("✓  RPC public with auth required for writes.");
        }
    }

    println!();
    println!("  ╔══════════════════════════════════════════════════╗");
    println!("  ║            ◆  B L O C H - S I S  ◆              ║");
    println!("  ║  Module-SIS PoW · Falcon‖ML-DSA · GhostDAG-Q     ║");
    println!("  ║    Fair-launch. Post-quantum. Pure PoW.  BLOCH   ║");
    println!("  ╚══════════════════════════════════════════════════╝");
    println!();

    let data_path = PathBuf::from(&cli.data_dir);
    std::fs::create_dir_all(&data_path).expect("create data dir");

    // ── Storage ───────────────────────────────────────────────────────────────
    let store = match storage::Storage::open(&data_path.join("db")) {
        Ok(s)  => { info!("storage ready"); Arc::new(s) }
        Err(e) => { error!("storage: {}", e); std::process::exit(1); }
    };



    // ── Consensus ─────────────────────────────────────────────────────────────
    // `with_default_k_env` == `with_default_k` (Legacy) unless the dev/test
    // override `BLOCH_GHOSTDAG_COLORING=fast` is set. The live gate
    // (CORRECTED_COLORING_ACTIVATION_HEIGHT) is unchanged; see ColoringMode docs.
    let dag = Arc::new(RwLock::new(consensus::GhostDAG::with_default_k_env()));

    // ── Genesis + DAG reload ─────────────────────────────────────────────────
    // --verify-carryover: audit the data-dir and exit. Runs before anything else
    // starts so it can be pointed at a live node's directory without racing it.
    if cli.verify_carryover {
        match store.derive_carryover_root() {
            Ok((root, count, total)) => {
                let expected = core::CARRYOVER_SNAPSHOT_ROOT;
                println!("carry-over audit — derived FROM THE DATABASE, not from any file");
                println!("  data-dir      : {}", cli.data_dir);
                println!("  utxo count    : {count}  (chain requires {})", core::CARRYOVER_UTXO_COUNT);
                println!("  total value   : {total} sat  (chain requires {})", core::CARRYOVER_TOTAL_SAT);
                println!("  derived root  : {}", hex::encode(root));
                println!("  required root : {}", hex::encode(expected));
                let ok = root == expected
                    && count == core::CARRYOVER_UTXO_COUNT
                    && total == core::CARRYOVER_TOTAL_SAT;
                if ok {
                    println!();
                    println!("MATCH — this database contains exactly the carried-over ledger.");
                    std::process::exit(0);
                }
                eprintln!();
                eprintln!("MISMATCH — this data-dir does NOT contain the ledger this binary expects.");
                eprintln!("If you downloaded it, do not run a node on it. The meta stamp inside a");
                eprintln!("data-dir records what a file hashed to at ingest time; it is copied text");
                eprintln!("and a tampered directory can carry a correct-looking one. This check is");
                eprintln!("the one that reads the actual UTXO set back out.");
                std::process::exit(1);
            }
            Err(e) => {
                eprintln!("carry-over audit failed to read the UTXO set: {e}");
                std::process::exit(1);
            }
        }
    }

    // Archival mode is process-wide and fixed; set it before any block is accepted.
    if cli.archive {
        ARCHIVE_MODE.store(true, std::sync::atomic::Ordering::Relaxed);
        info!("--archive: pruning DISABLED, every block body retained. This node can \
               bootstrap fresh peers; a pruned node cannot.");
    }

    // ── Genesis-2 carry-over gate (fail closed) ──────────────────────────────
    // Runs BEFORE genesis initialisation so that on first boot the snapshot is
    // fully verified before this process writes ANY chain state. Order of
    // operations on first boot: verify (root + count + supply, all reported) →
    // ingest (one atomic WriteBatch, UTXOs + marker together) → genesis init.
    // A crash between ingest and genesis init re-runs both next boot
    // (idempotent: same keys, same verified bytes).
    let first_boot = store.get_meta("genesis_hash").ok().flatten().is_none();
    let carryover_required = core::chain_requires_carryover(core::node_chain_id());
    if carryover_required && cli.carryover_snapshot.is_none() {
        error!("this chain-id ({:?}) REQUIRES a carry-over snapshot: pass \
                --carryover-snapshot <file.tsv> whose SHAKE-256 root is {}. \
                Refusing to start.",
               core::node_chain_id(), hex::encode(core::CARRYOVER_SNAPSHOT_ROOT));
        std::process::exit(1);
    }
    if let Some(snap_path) = &cli.carryover_snapshot {
        if !carryover_required {
            warn!("--carryover-snapshot on a chain-id ({:?}) that does not require it — \
                   dev/test use only; the snapshot is still verified fail-closed.",
                  core::node_chain_id());
        }
        if first_boot {
            info!("carry-over: verifying {} against baked-in constants \
                   (root {}…, count {}, supply {} sat)…",
                  snap_path.display(),
                  &hex::encode(core::CARRYOVER_SNAPSHOT_ROOT)[..16],
                  core::CARRYOVER_UTXO_COUNT, core::CARRYOVER_TOTAL_SAT);
            match storage::verify_carryover_snapshot(snap_path) {
                Ok(snap) => {
                    info!("carry-over snapshot VERIFIED: root {}, {} UTXOs, {} sat",
                          hex::encode(snap.root), snap.count, snap.total_sat);
                    match store.ingest_carryover(&snap) {
                        Ok(n) => info!("carry-over ingested: {n} UTXOs written atomically \
                                        (meta carryover_root stamped)"),
                        Err(e) => {
                            error!("carry-over ingestion FAILED after verification: {e}. \
                                    The write batch is atomic — nothing was persisted. \
                                    Refusing to start.");
                            std::process::exit(1);
                        }
                    }
                }
                Err(failures) => {
                    for f in &failures {
                        error!("carry-over verification FAILED: {f}");
                    }
                    error!("REFUSING TO START: {} carry-over check(s) failed; nothing was \
                            written. Supply this chain's exact blessed snapshot file — \
                            the loader verifies the bytes it is given and never sorts or \
                            repairs them.", failures.len());
                    std::process::exit(1);
                }
            }
        } else {
            // Already-initialised data-dir: never re-ingest. Prove the ingestion
            // actually happened, against the SAME root this binary requires.
            match store.get_meta("carryover_root").ok().flatten() {
                Some(r) if r.as_slice() == core::CARRYOVER_SNAPSHOT_ROOT => {
                    info!("carry-over already ingested (meta carryover_root matches {}…); \
                           snapshot file not re-read.",
                          &hex::encode(core::CARRYOVER_SNAPSHOT_ROOT)[..16]);
                }
                Some(r) => {
                    error!("carry-over marker MISMATCH: data-dir was ingested from root {} \
                            but this binary requires {}. This data-dir belongs to a \
                            different carry-over lineage. Refusing to start.",
                           hex::encode(&r), hex::encode(core::CARRYOVER_SNAPSHOT_ROOT));
                    std::process::exit(1);
                }
                None => {
                    error!("carry-over marker ABSENT: this data-dir was initialised WITHOUT \
                            carry-over ingestion, and grafting a snapshot onto existing \
                            chain state is not supported. Start from a fresh data-dir. \
                            Refusing to start.");
                    std::process::exit(1);
                }
            }
        }
    }

    if store.get_meta("genesis_hash").ok().flatten().is_none() {
        // NOT mining: the genesis PoW witness is the pre-mined constant
        // GENESIS_POW_SOLUTION (bloch-crypto core/mod.rs:321), exactly like the
        // entanglement-layer GENESIS_NONCE pattern. This path CONSTRUCTS the
        // canonical genesis from constants and VERIFIES it, then refuses to start
        // if it does not check out. The old "MINING genesis block — this will take
        // a few seconds" message described work that never happens, and it costs
        // real diagnosis time: an operator who sees it next to 0% CPU concludes the
        // node hung during genesis, when in fact this step already finished.
        info!("Initialising canonical genesis (pre-mined PoW witness) and verifying...");
        let founder_spk = address_to_script_pubkey(FOUNDER_ADDRESS_HEX);
        // V2 (ADR-028): miner slot at genesis uses founder address (genesis
        // bootstrapping convention). Pool addresses come from tokenomics_v2
        // and panic before Phase 6 — deliberate fail-loud: a node configured
        // for mainnet without these populated must not produce blocks.
        let validator_pool_spk = core::tokenomics_v2::validator_pool_address_hash();
        let oracle_pool_spk    = core::tokenomics_v2::oracle_pool_address_hash();
        let genesis = core::create_genesis_block(
            &founder_spk,
            &validator_pool_spk,
            &oracle_pool_spk,
        );

        // Genesis carries a mined Module-SIS PoW witness (B5e); refuse to start
        // if it does not verify (wrong GENESIS_POW_SOLUTION / bits / address).
        if !genesis.validate_pow() {
            error!("Genesis Module-SIS PoW invalid — GENESIS_POW_SOLUTION does not \
                    verify against the canonical genesis. Regenerate via B5e.");
            std::process::exit(1);
        }

        let hash = genesis.block_hash();
        store.put_block(&genesis).expect("store genesis");
        store.put_meta("genesis_hash", &hash).expect("meta genesis_hash");
        store.put_meta("tip_hash", &hash).expect("meta tip_hash");
        // Sprint L fix: initialize current_bits meta at genesis so that accept_block's
        // `expected_bits = get_meta("current_bits").unwrap_or(0x1d00ffff)` has a real
        // value from block 1 onwards (not the fallback constant). Prevents a class of
        // subtle bugs where a retarget could write a different value than accept_block
        // reads on a fresh node.
        store.put_meta("current_bits", &core::GENESIS_BITS.to_le_bytes())
            .expect("meta current_bits");
        dag.write().add_genesis(hash, genesis.header.timestamp);
        if let Some(gdata) = dag.read().get_block_data(&hash).cloned() {
            // Sprint Y (M-2): atomic put to CF_DAG + CF_DAG_INTEGRITY.
            // Genesis anchors the hash-chain with an all-zero parent
            // integrity; see `compute_integrity_hash` for the convention.
            store.put_dag_with_integrity(&hash, &gdata)
                .expect("persist genesis dag + integrity");
            // Phase 1: when the reachability index is maintained (Fast / armed),
            // persist the genesis reachability record + version tag + root.
            // (Live Legacy path leaves CF_REACHABILITY untouched.)
            if dag.read().maintains_reachability_index() {
                let _ = dag.write().reach_take_delta(); // start tracking clean
                store.store_reachability_snapshot(&dag.read().reach_export_all(),
                                                  dag.read().reach_root())
                    .expect("persist genesis reachability index");
            }
        }
        for tx in &genesis.transactions {
            let txid = tx.txid();
            store.put_tx_index(&txid, &hash, 0).expect("tx_index");
            for (j, out) in tx.outputs.iter().enumerate() {
                store.put_utxo(&txid, j as u32, out).expect("utxo");
            }
        }
        info!("Genesis: {}", hex::encode(hash));
        // V2 supply (ADR-028): 1B nominal = 800M mining + 30M validator/oracle
        // pool + 170M founder vesting (12m cliff + 348m linear over 30 years).
        info!(
            "V2 supply (BLOCH): mining {} | validator/oracle pool {} | founder vesting {} | total {}",
            core::tokenomics_v2::MINING_EMISSION_NOMINAL_SAT / 100_000_000,
            core::tokenomics_v2::VALIDATOR_ORACLE_POOL_SAT / 100_000_000,
            core::tokenomics_v2::FOUNDER_PREMINE_TOTAL_SAT / 100_000_000,
            core::tokenomics_v2::NOMINAL_TOTAL_SUPPLY_SAT / 100_000_000,
        );
    } else {
        // Full DAG reconstruction from persisted data.
        //
        // Sprint Y (M-2): load_persisted_validated verifies a hash-chain
        // over GhostdagData before inserting into the in-memory DAG. If
        // the database was written by a pre-Sprint-Y binary, the integrity
        // CF will be empty — the loader self-heals by computing and
        // returning a fresh map, which we persist immediately so the next
        // boot validates strictly.
        //
        // Any mismatch is fatal: we log loudly and exit. The operator
        // can then investigate disk integrity / provenance of the data
        // directory before the node rejoins the network.
        match store.load_all_dag_data() {
            Ok(entries) if !entries.is_empty() => {
                let _count = entries.len();
                let integrity_map = store.load_all_integrity_hashes()
                    .unwrap_or_else(|e| {
                        warn!("failed to read CF_DAG_INTEGRITY ({}); \
                              assuming pre-Sprint-Y DB, will self-heal", e);
                        std::collections::HashMap::new()
                    });

                match dag.write().load_persisted_validated(entries, integrity_map) {
                    Ok(loaded) => {
                        if loaded.self_healed {
                            warn!("CF_DAG_INTEGRITY was empty — self-healed \
                                   {} integrity records. This is expected on \
                                   first boot after Sprint Y upgrade. Subsequent \
                                   boots will validate strictly.",
                                  loaded.blocks_loaded);
                            if let Some(fresh) = loaded.fresh_map {
                                for (h, integrity) in &fresh {
                                    if let Err(e) = store.put_integrity_hash(h, integrity) {
                                        warn!("self-heal: failed to persist \
                                               integrity for block {}: {}",
                                              hex::encode(&h[..8]), e);
                                    }
                                }
                            }
                            info!("DAG loaded from disk (self-healed): {} blocks",
                                  loaded.blocks_loaded);
                        } else {
                            info!("DAG loaded from disk (integrity verified): {} blocks",
                                  loaded.blocks_loaded);
                        }
                    }
                    Err(e) => {
                        error!("GhostDAG integrity check FAILED: {}", e);
                        error!("Refusing to continue with unverifiable DAG state.");
                        error!("Investigate: disk corruption, targeted tampering, \
                               or a partial restore from a mismatched backup.");
                        std::process::exit(1);
                    }
                }
            }
            _ => {
                // Fallback: at least load genesis
                let gh = store.get_meta("genesis_hash").unwrap().unwrap();
                let gh32: [u8;32] = gh.as_slice().try_into().unwrap_or([0u8;32]);
                if let Ok(Some(blk)) = store.get_block(&gh32) {
                    dag.write().add_genesis(blk.block_hash(), blk.header.timestamp);
                    info!("Genesis loaded (fallback): {}", hex::encode(&gh));
                }
            }
        }
    }

    // ── Phase 2: durable reachability index — load-or-rebuild on boot ─────────
    //
    // `load_persisted*` above inserts blocks straight into the in-memory DAG
    // WITHOUT feeding the reachability index (it bypasses `add_block`). So when
    // the index is maintained (Fast / armed activation) it is empty here and
    // must be initialized before it colors any block:
    //
    //   * Fast-path: if CF_REACHABILITY carries the matching schema version and
    //     covers every CF_DAG block, load it directly (no O(chain) recompute).
    //   * Migration: otherwise rebuild by replaying the SAME `reach.add_block`
    //     code path in topological order, then persist the fresh snapshot.
    //   * Guard: random-sample self-check against the brute-force oracle before
    //     trusting the index; a loaded index that fails is rebuilt once.
    //
    // This whole block is inert on the live Legacy path (the gate is disabled),
    // so it never runs on a mainnet node from this branch. No peer resync ever.
    if dag.read().maintains_reachability_index() && dag.read().block_count() > 0 {
        let want_ver = storage::Storage::REACHABILITY_SCHEMA_VERSION;
        let have_ver = store.get_reachability_version().ok().flatten();
        let block_count = dag.read().block_count();

        let mut loaded_ok = false;
        if have_ver == Some(want_ver) {
            match store.load_all_reachability() {
                Ok(records) if records.len() == block_count => {
                    let root = store.get_reachability_root().ok().flatten();
                    match dag.write().reach_load_records(&records, root) {
                        Ok(()) => {
                            loaded_ok = true;
                            info!("reachability index loaded from disk: {} records", records.len());
                        }
                        Err(e) => warn!("reachability load failed ({e}); will rebuild"),
                    }
                }
                Ok(records) => warn!(
                    "reachability CF covers {}/{} blocks (partial/torn); will rebuild",
                    records.len(), block_count
                ),
                Err(e) => warn!("reachability CF read failed ({e}); will rebuild"),
            }
        } else {
            info!(
                "reachability index absent/version-mismatch (have {:?}, want {}); \
                 rebuilding from CF_DAG (one-time)",
                have_ver, want_ver
            );
        }

        let persist_rebuilt = |dag: &Arc<RwLock<consensus::GhostDAG>>, store: &storage::Storage| {
            let snap = dag.read().reach_export_all();
            let root = dag.read().reach_root();
            let _ = dag.write().reach_take_delta(); // clear the rebuild's dirty flags
            if let Err(e) = store.store_reachability_snapshot(&snap, root) {
                warn!("failed to persist rebuilt reachability index: {e}");
            }
        };

        if !loaded_ok {
            match dag.write().rebuild_reachability_from_store() {
                Ok(n) => info!("reachability index rebuilt from CF_DAG: {} blocks", n),
                Err(e) => {
                    error!("reachability rebuild FAILED: {e}");
                    error!("Refusing to continue with an uninitialized Fast-coloring index.");
                    std::process::exit(1);
                }
            }
            persist_rebuilt(&dag, &store);
        }

        // Self-check the (loaded or rebuilt) index against the unbounded oracle.
        if let Err(e) = dag.read().reach_self_check_sample(2000, 0xB10C_5157) {
            if loaded_ok {
                warn!("loaded reachability failed self-check ({e}); rebuilding from CF_DAG");
                match dag.write().rebuild_reachability_from_store() {
                    Ok(n) => info!("reachability rebuilt after failed self-check: {} blocks", n),
                    Err(e2) => { error!("rebuild after failed self-check errored: {e2}"); std::process::exit(1); }
                }
                persist_rebuilt(&dag, &store);
                if let Err(e2) = dag.read().reach_self_check_sample(2000, 0x5157_B10C) {
                    error!("reachability STILL fails self-check after rebuild: {e2}");
                    std::process::exit(1);
                }
                info!("reachability self-check OK after rebuild");
            } else {
                error!("rebuilt reachability failed self-check: {e}");
                std::process::exit(1);
            }
        } else {
            info!("reachability self-check OK (sampled pairs match brute-force oracle)");
        }
    }

    // ── Heal poisoned finality checkpoint (blue-score/height unit bug) ─────────
    // Older builds persisted finalized_height = tip_blue_score − CHECKPOINT_DEPTH,
    // which runs ahead of the selected tip's *height* by the DAG width and can
    // exceed it once the skew passes CHECKPOINT_DEPTH — bricking block ingestion
    // (every chain-extending block is <= finalized_height and gets rejected). The
    // monotonic guard in accept_block cannot lower the value, so clamp it down to
    // a height-based ceiling here, once, at startup.
    {
        let tip_h = {
            let d = dag.read();
            d.selected_tip()
                .and_then(|h| d.get_block_data(&h).map(|x| x.height))
                .unwrap_or(0)
        };
        let cap = tip_h.saturating_sub(core::CHECKPOINT_DEPTH);
        let cur = store.get_meta("finalized_height").ok().flatten()
            .and_then(|b| b.as_slice().try_into().ok().map(u64::from_le_bytes))
            .unwrap_or(0);
        if cur > cap {
            warn!("finalized_height {} exceeds height-based cap {} \
                   (blue-score/height unit bug) — clamping to heal ingestion", cur, cap);
            store.put_meta("finalized_height", &cap.to_le_bytes()).ok();
        }
    }

    // ── Mempool + Network ─────────────────────────────────────────────────────
    let mempool  = Arc::new(mempool::Mempool::new());
    let net_cfg  = network::NetworkConfig {
        listen_addr:     cli.listen.clone(),
        bootstrap_peers: cli.peer.clone(),
        dns_seeds:       cli.dns_seed.clone(),
        max_peers:       cli.max_peers,
        data_dir:        data_path.clone(),
        allow_private_peers: cli.allow_private_peers,
        behind_proxy:    cli.behind_proxy,
    };
    let node = match network::NetworkNode::new(net_cfg) {
        Ok(n)  => { info!("P2P: {}", n.peer_id); n }
        Err(e) => { error!("network: {}", e); std::process::exit(1); }
    };

    let (our_score, our_count) = {
        let d = dag.read();
        (d.tip_blue_score(), d.block_count() as u64)
    };

    let node_state = Arc::new(RwLock::new(rpc::NodeState {
        tip_blue_score: our_score,
        block_count:    our_count,
        version:        env!("CARGO_PKG_VERSION").into(),
        ..Default::default()
    }));

    let (block_tx, mut block_rx) = mpsc::channel::<network::NetworkMessage>(1000);
    let (outbound_tx, outbound_rx) = mpsc::channel::<network::NetworkMessage>(1000);

    // ── Sprint 2.c: Tip-change broadcast channel ─────────────────────────────
    //
    // Fired whenever the selected DAG tip moves (Extension or Reorg disposition
    // in accept_block, or successful add_block in the miner loop). Stratum
    // server subscribes and re-broadcasts mining.notify with clean_jobs=true.
    //
    // Capacity 64: generous for burst tolerance; a lagging subscriber
    // (Lagged error variant) triggers a warn-and-continue in the server loop.
    //
    // When no subscriber exists (stratum disabled), send() returns Err and
    // all senders `let _ = ...` it. Safe no-op.
    let (tip_tx, _) = broadcast::channel::<stratum::TipChanged>(64);

    // Coherence C2: the node's shielded-pool engine (in-memory).
    let shielded = Arc::new(RwLock::new(crate::coherence::ShieldedPool::new()));

    // ── Message processor ─────────────────────────────────────────────────────
    let store2    = store.clone();
    let shielded2 = shielded.clone();
    let dag2    = dag.clone();
    let state2  = node_state.clone();
    let mem2    = mempool.clone();
    let otx2    = outbound_tx.clone();
    let tip_tx2 = tip_tx.clone();

    // ── Phase-2 Kaspa sync-negotiation shared state (drop-in, additive) ───────
    // `peer_state`: PeerId-keyed chain-state table, written by the network loop
    // (P4) where the real libp2p PeerId is in scope; read here by the processor
    // + nudge. `frontier`: in-flight tip-request tracker gating IBD release.
    // Lock order everywhere: dag → peer_state → frontier → node_state.
    let peer_state = Arc::new(sync::peer_state::PeerStateTable::new());
    let frontier   = Arc::new(parking_lot::Mutex::new(sync::frontier::FrontierState::new()));
    let peer_state2 = peer_state.clone();
    let frontier2   = frontier.clone();

    tokio::spawn(async move {
        use futures::future::FutureExt;
        // ── P0 supervision (roadmap §2.5, top reliability risk #1) ───────────
        // Before this, the single message-processor task was `tokio::spawn`ed
        // with no supervision: a panic in accept_block / block decode / orphan
        // handling silently killed the task. The process stayed "up", RPC kept
        // answering, but the node stopped syncing FOREVER with no error
        // surfaced. Here we catch a panic, log it loudly + meter it
        // (`task_panics_total`), back off, and restart the processing loop
        // without dropping the node. The processor's BEHAVIOUR is unchanged —
        // only its supervision is added.
        //
        // Orphan-pool state lives inside the restartable closure, so a panic
        // rebuilds it empty (the in-flight orphan buffer is lost — acceptable;
        // peers resend). A clean channel close (all senders dropped) exits.
        let mut backoff = std::time::Duration::from_millis(100);
        const MAX_BACKOFF: std::time::Duration = std::time::Duration::from_secs(30);
        loop {
          let processor = async {
            // Orphan pool: blocks received before their parents
            const MAX_ORPHANS: usize = 10_000;
            let mut orphans: std::collections::HashMap<[u8; 32], (core::Block, Vec<u8>, u64)> =
                std::collections::HashMap::new();
            // Reverse index: parent_hash → set of orphan hashes waiting for it
            let mut waiting_for: std::collections::HashMap<[u8; 32], HashSet<[u8; 32]>> =
                std::collections::HashMap::new();
            // Mesh fix (reciprocal tip): rate limiter for answering behind-
            // peers' PeerTip announcements with our own tip. None = never sent.
            let mut last_reciprocal_tip: Option<std::time::Instant> = None;

            while let Some(msg) = block_rx.recv().await {
            match msg {

                // IBD step 1: peer tip — if behind, request headers
                network::NetworkMessage::PeerTip { blue_score: peer_s, ref peer_id, .. } => {
                    let our_s = dag2.read().tip_blue_score();
                    {
                        let mut s = state2.write();
                        s.seen_first_tip = true;
                        // Phase-2: best_seen_blue_score is kept ONLY as an RPC
                        // display hint — it no longer releases the IBD latch. A
                        // peer can announce any blue_score; release is decided
                        // solely by maybe_release_ibd (blue_work-verified below).
                        if peer_s > s.best_seen_blue_score { s.best_seen_blue_score = peer_s; }
                    }
                    if peer_s > our_s {
                        info!("Peer {} ahead ({}), requesting headers", peer_id, peer_s);
                        // Retained legacy over-trigger fallback (entering IBD is
                        // always safe); the announced score never RELEASES it.
                        state2.write().is_syncing = true;
                        let _ = otx2.send(network::NetworkMessage::GetHeaders { from_blue_score: our_s, limit: 500, nonce: getblock_nonce() }).await;
                    } else if peer_s < our_s {
                        // Mesh fix (reciprocal tip): the announcing peer is
                        // BEHIND us, and its other ways of learning our tip are
                        // all fragile — the on-connect announce races its
                        // Subscribe, and our 60s periodic PeerTip is byte-
                        // identical while our tip is unchanged (dedup-fragile).
                        // Answer with a fresh-timestamp Version (unique bytes,
                        // can never be dedup-dropped) carrying our blue_score;
                        // the peer's Version arm below treats it as an IBD
                        // trigger. Rate-limited so a burst of behind-tips from
                        // many peers can't make us spam the sync topic.
                        let due = last_reciprocal_tip
                            .map(|t| t.elapsed() >= std::time::Duration::from_secs(15))
                            .unwrap_or(true);
                        if due {
                            last_reciprocal_tip = Some(std::time::Instant::now());
                            let height = dag2.read().block_count() as u64;
                            debug!("peer {} behind (score {} < {}), sending reciprocal tip", peer_id, peer_s, our_s);
                            let _ = otx2.send(network::NetworkMessage::Version {
                                version:    network::PROTOCOL_VERSION,
                                user_agent: format!("bloch-layer/{}", env!("CARGO_PKG_VERSION")),
                                blue_score: our_s,
                                height,
                                timestamp:  std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map(|d| d.as_secs()).unwrap_or(0),
                            }).await;
                        }
                    }
                    maybe_release_ibd(&dag2, &peer_state2, &frontier2, &state2);
                }

                // Frontier reconciliation: a peer asks for our DAG frontier.
                // Reply with every tip (as SyncEntry) plus an exponential
                // block-locator over our selected chain (common-ancestor hint).
                network::NetworkMessage::GetTips => {
                    let (entries, locator) = {
                        let d = dag2.read();
                        let entries: Vec<network::SyncEntry> = d.tips().iter()
                            .filter_map(|h| d.get_node(h).map(|n| network::SyncEntry {
                                hash: *h, blue_score: n.blue_score, height: n.height,
                            }))
                            .collect();
                        let locator = sync::locator::build_locator(&d.selected_chain());
                        (entries, locator)
                    };
                    let _ = otx2.send(network::NetworkMessage::Tips { tips: entries, locator }).await;
                }

                // Frontier reconciliation: a peer's advertised frontier. GetBlock
                // every advertised tip we lack; a frontier gap means we are
                // behind, so enter IBD. Missing parents of the fetched tips flow
                // into the EXISTING orphan pool via the NewBlock arm — no new
                // orphan logic here.
                network::NetworkMessage::Tips { tips, .. } => {
                    let advertised: Vec<[u8; 32]> = tips.iter().map(|e| e.hash).collect();
                    let now = std::time::Instant::now();
                    let to_req = {
                        let d = dag2.read();
                        frontier2.lock().to_request(&advertised, |h| d.has_block(h), now)
                    };
                    if !to_req.is_empty() {
                        // Frontier gap → enter IBD (blue_work-verified release).
                        state2.write().is_syncing = true;
                        for h in &to_req {
                            let _ = otx2.send(network::NetworkMessage::GetBlock { block_hash: *h, nonce: getblock_nonce() }).await;
                        }
                    }
                    maybe_release_ibd(&dag2, &peer_state2, &frontier2, &state2);
                }

                // IBD step 2: someone asks for our headers
                network::NetworkMessage::GetHeaders { from_blue_score, limit, .. } => {
                    let entries: Vec<network::SyncEntry> = {
                        let d = dag2.read();
                        d.ordered_hashes_from(from_blue_score, limit as usize)
                            .iter()
                            .filter_map(|h| d.get_node(h).map(|n| network::SyncEntry { hash: *h,
                                blue_score: n.blue_score, height: n.height,
                            }))
                            .collect()
                    };
                    if !entries.is_empty() {
                        let _ = otx2.send(network::NetworkMessage::Headers { entries }).await;
                    }
                }

                // IBD step 3: received headers — request missing blocks
                network::NetworkMessage::Headers { entries } => {
                    let missing: Vec<_> = entries.iter()
                        .filter(|e| !dag2.read().has_block(&e.hash))
                        .map(|e| e.hash).collect();
                    info!("IBD: need {}/{} blocks", missing.len(), entries.len());
                    for hash in missing {
                        let _ = otx2.send(network::NetworkMessage::GetBlock { block_hash: hash, nonce: getblock_nonce() }).await;
                    }
                    if entries.is_empty() {
                        // Phase-2: an empty Headers reply no longer clears
                        // is_syncing (a lying/lagging peer must not fake
                        // completion). Release is blue_work-verified only.
                        maybe_release_ibd(&dag2, &peer_state2, &frontier2, &state2);
                    } else if entries.len() >= 500 {
                        // Pipeline IBD: a full batch means the serving peer has
                        // more. Re-request the next batch IMMEDIATELY from the
                        // highest blue_score we just learned, instead of waiting
                        // for the 30s nudge. Turns IBD from ~500 headers / 30s
                        // into a continuous stream so a node thousands of blocks
                        // behind converges in seconds, not minutes. At parity
                        // the batch comes back < 500 (or empty) and the stream
                        // stops, so steady-state cost is zero.
                        let next_from = entries.iter().map(|e| e.blue_score).max().unwrap_or(0);
                        let _ = otx2.send(network::NetworkMessage::GetHeaders { from_blue_score: next_from, limit: 500, nonce: getblock_nonce() }).await;
                    }
                }

                // A peer told us it cannot serve this body — it pruned it, or never
                // had it. Log it and move on: the point of the message is that the
                // requester now KNOWS, instead of waiting on silence and re-asking
                // the same batch every 30s. If every peer answers NotFound for the
                // early chain, no archival peer exists and a fresh node genuinely
                // cannot bootstrap — a condition worth surfacing rather than hiding
                // behind an apparently-healthy log full of header traffic.
                network::NetworkMessage::BlockNotFound { block_hash, .. } => {
                    warn!("peer cannot serve block {} (pruned or unknown) — an \
                           archival peer is needed to bootstrap from this height",
                          hex::encode(&block_hash[..8]));
                }

                // IBD step 4: respond to GetBlock with the actual block
                network::NetworkMessage::GetBlock { block_hash, .. } => {
                    match store2.get_block(&block_hash) {
                        Ok(Some(block)) => {
                            // Sprint 1.c: Bitcoin-format wire.
                            let data = block.to_bitcoin_bytes();
                            let _ = otx2.send(network::NetworkMessage::NewBlock {
                                block_hash,
                                blue_score: block.blue_score,
                                height:     block.height,
                                block_data: data,
                            }).await;
                        }
                        // Answer explicitly instead of dropping the frame. A silent
                        // non-answer is unrecoverable for the requester: it cannot
                        // tell "body pruned" from "packet lost" from "peer busy", so
                        // it waits, re-asks the same batch on the 30s nudge, and loops
                        // forever — exactly how a fresh node sat at height 1 through
                        // 4,397 identical rounds with 15 peers connected. warn!, not
                        // debug!: a node advertising headers whose bodies it pruned is
                        // a real operational fault, and at RUST_LOG=info the old debug
                        // line made it invisible.
                        _ => {
                            warn!("GetBlock: body unavailable (pruned or unknown) for {} \
                                   — replying NotFound so the peer can try another source",
                                  hex::encode(&block_hash[..8]));
                            let _ = otx2.send(network::NetworkMessage::BlockNotFound {
                                block_hash, nonce: getblock_nonce(),
                            }).await;
                        }
                    }
                }

                // Full validation before storing — with orphan pool support
                network::NetworkMessage::NewBlock { block_data, block_hash, height, .. } => {
                    if dag2.read().has_block(&block_hash) { continue; }
                    // Sprint 1.c: Bitcoin-format wire. A malformed block_data
                    // payload gets warned about and dropped; peer may re-send
                    // or stay on a divergent chain.
                    match core::Block::from_bitcoin_bytes(&block_data) {
                        Err(e) => warn!("block deserialise: {}", e),
                        Ok(block) => {
                            // SECURITY (audit H2): bind the wire-supplied block_hash/height to
                            // the actual block content BEFORE any dedup or DAG insertion.
                            // Otherwise an attacker rebroadcasts a valid block under endless
                            // random ids, each minting a distinct GhostDAG node → unbounded
                            // memory/disk growth at zero PoW cost.
                            let real_hash = block.block_hash();
                            if real_hash != block_hash {
                                warn!("block id mismatch: claimed {} but content hashes to {}; dropping",
                                    hex::encode(&block_hash[..8]), hex::encode(&real_hash[..8]));
                                continue;
                            }
                            if height != block.height {
                                warn!("block {} height mismatch: claimed {} vs content {}; dropping",
                                    hex::encode(&block_hash[..8]), height, block.height);
                                continue;
                            }

                            // Structural validation (PoW, merkle, coinbase) — always do first
                            if let Err(reason) = block.validate_structure() {
                                warn!("block {} rejected ({})", hex::encode(&block_hash[..8]), reason);
                                continue;
                            }

                            // Check if all parents are in the DAG
                            let missing_parents: Vec<[u8; 32]> = block.header.parents.iter()
                                .filter(|p| !dag2.read().has_block(p))
                                .cloned()
                                .collect();

                            if !missing_parents.is_empty() {
                                // Orphan: parents not yet available — buffer for later
                                if orphans.len() >= MAX_ORPHANS {
                                    // Evict oldest orphan (by height, lowest first)
                                    if let Some((&evict_hash, _)) = orphans.iter()
                                        .min_by_key(|(_, (b, _, _))| b.height)
                                    {
                                        let evict_parents: Vec<[u8;32]> = orphans[&evict_hash].0.header.parents.clone();
                                        orphans.remove(&evict_hash);
                                        for p in &evict_parents {
                                            if let Some(set) = waiting_for.get_mut(p) {
                                                set.remove(&evict_hash);
                                                if set.is_empty() { waiting_for.remove(p); }
                                            }
                                        }
                                    }
                                }
                                debug!("orphan block h={} (missing {} parents), buffered (pool={})",
                                    height, missing_parents.len(), orphans.len() + 1);
                                for mp in &missing_parents {
                                    let first_waiter = !waiting_for.contains_key(mp);
                                    waiting_for.entry(*mp).or_default().insert(block_hash);
                                    // Kaspa-style recursive ancestor resolution
                                    // (RequestRelayBlocks): explicitly request each
                                    // missing parent so the past cone closes even
                                    // when IBD-by-blue_score hasn't reached this
                                    // branch. Without this the orphan waits forever
                                    // and the node silently partitions onto a
                                    // sub-DAG. Skip parents already buffered or
                                    // already awaited (their arrival chains the next
                                    // request), so a deep gap fans out one level at a
                                    // time instead of duplicating GetBlocks.
                                    if first_waiter && !orphans.contains_key(mp) {
                                        let _ = otx2.send(network::NetworkMessage::GetBlock {
                                            block_hash: *mp, nonce: getblock_nonce(),
                                        }).await;
                                    }
                                }
                                orphans.insert(block_hash, (block, block_data, height));
                                continue;
                            }

                            // All parents present — try to accept
                            let _t_validate = std::time::Instant::now();
                            match accept_block(
                                &block, block_hash, height,
                                &dag2, &store2, &mem2, &state2,
                                Some(&tip_tx2), &shielded2,
                            ) {
                            Err(e) => {
                                crate::metrics::observe_block_validation(_t_validate.elapsed().as_secs_f64());
                                crate::metrics::inc_block_rejected();
                                warn!("block {} h={} REJECTED: {}", hex::encode(&block_hash[..8]), height, e);
                            }
                            Ok(accepted_hash) => {
                                crate::metrics::observe_block_validation(_t_validate.elapsed().as_secs_f64());
                                crate::metrics::inc_block_accepted();
                                // Process any orphans that were waiting for this block
                                process_orphans(
                                    accepted_hash,
                                    &mut orphans,
                                    &mut waiting_for,
                                    &dag2, &store2, &mem2, &state2,
                                    Some(&tip_tx2), &shielded2,
                                );
                                // Phase-2 frontier: this tip (if it was in flight)
                                // is now present — clear it and re-test the IBD
                                // latch. Orphans drained by process_orphans that
                                // were themselves advertised tips get cleared by
                                // the next Tips round (to_request skips present
                                // blocks), so clearing block_hash here suffices.
                                frontier2.lock().note_received(&block_hash);
                                maybe_release_ibd(&dag2, &peer_state2, &frontier2, &state2);
                            }}
                        }
                    }
                }

                network::NetworkMessage::PeerCount { count, addresses } => {
                    let mut s = state2.write();
                    s.peer_count = count as u32;
                    s.peer_addresses = addresses;
                }

                // Add validated tx to mempool
                network::NetworkMessage::NewTransaction { tx_data, .. } => {
                    // Sprint 1.d: Bitcoin-format tx wire.
                    if let Ok(tx) = core::Transaction::from_stratum_bytes(&tx_data) {
                        if !tx.is_coinbase() {
                            let height = dag2.read().block_count() as u64;
                            // P0 (roadmap §1.2 / §2.5 #6): move CPU-bound PQ
                            // signature verification off the async reactor so a
                            // gossiped valid-tx flood can't stall this task's
                            // worker thread. Logic unchanged — only the thread.
                            let store_v = store2.clone();
                            let tx_v = tx.clone();
                            let verified = tokio::task::spawn_blocking(move || {
                                validate_tx_standalone(&tx_v, &store_v, height)
                            }).await;
                            match verified {
                                Ok(Ok(fee)) => { let _ = mem2.add(tx, fee); }
                                Ok(Err(e))  => debug!("mempool reject: {}", e),
                                Err(e)      => warn!("tx verify task failed: {}", e),
                            }
                        }
                        state2.write().mempool_size = mem2.size();
                    }
                }

                // Mesh fix (fresh-joiner IBD): Version was a no-op here, yet it
                // is the only tip-carrying frame on the wire whose bytes are
                // always unique (fresh `timestamp` → unique gossipsub
                // MessageId, so it can never be Duplicate-dropped the way a
                // byte-identical PeerTip can). Treat it exactly like a PeerTip
                // for IBD triggering: on-connect handshakes, post-Subscribed
                // re-announces, periodic announces, and reciprocal tips all
                // arrive as Version frames.
                //
                // SHARED-LATCH NOTE ([stall] interface): this arm feeds the
                // same is_syncing / best_seen_blue_score / seen_first_tip
                // latch as the PeerTip arm above, with IDENTICAL semantics.
                // It widens the set of messages that can raise the
                // best_seen_blue_score high-water mark (still unvalidated,
                // peer-supplied). Any [stall]-side fix that decays or
                // validates that mark must cover this arm too.
                network::NetworkMessage::Version { version, blue_score: peer_s, .. } => {
                    if version < network::MIN_PROTOCOL_VERSION { continue; }
                    let our_s = dag2.read().tip_blue_score();
                    {
                        let mut s = state2.write();
                        s.seen_first_tip = true;
                        // Phase-2: RPC hint only — never releases the latch.
                        if peer_s > s.best_seen_blue_score { s.best_seen_blue_score = peer_s; }
                    }
                    if peer_s > our_s {
                        info!("Version peer ahead (score {} > {}), requesting headers", peer_s, our_s);
                        // Retained legacy over-trigger fallback (safe).
                        state2.write().is_syncing = true;
                        let _ = otx2.send(network::NetworkMessage::GetHeaders { from_blue_score: our_s, limit: 500, nonce: getblock_nonce() }).await;
                    }
                    maybe_release_ibd(&dag2, &peer_state2, &frontier2, &state2);
                }
                network::NetworkMessage::VersionAck
                | network::NetworkMessage::PeerExchange { .. }
                | network::NetworkMessage::PeerRequest => {}
            }
            }
          };
          // Catch a panic that escapes the processing loop, meter + log it, and
          // restart with bounded exponential backoff. Ok(()) means the input
          // channel closed cleanly (every sender dropped) → exit the task.
          match std::panic::AssertUnwindSafe(processor).catch_unwind().await {
              Ok(()) => {
                  info!("message-processor: input channel closed; task exiting cleanly");
                  break;
              }
              Err(panic) => {
                  crate::metrics::inc_task_panic("message_processor");
                  let detail = panic.downcast_ref::<&str>().map(|s| (*s).to_string())
                      .or_else(|| panic.downcast_ref::<String>().cloned())
                      .unwrap_or_else(|| "<non-string panic payload>".to_string());
                  error!("message-processor PANICKED: {} — node stays up; restarting loop in {:?}",
                      detail, backoff);
                  tokio::time::sleep(backoff).await;
                  backoff = (backoff * 2).min(MAX_BACKOFF);
              }
          }
        }
    });

    // ── Mesh fix: proactive IBD nudge ─────────────────────────────────────────
    //
    // A fresh joiner can miss every inbound tip signal: the seed's on-connect
    // announce races our Subscribe, the 60s periodic PeerTip is dedup-fragile,
    // and colocation scoring can graylist proxied peers. Don't wait to be told
    // we're behind — while we have peers and either (a) we've never seen a
    // remote tip, or (b) we know we're behind (is_syncing latched, or the
    // best announced blue_score exceeds ours), publish GetHeaders every 30s.
    //
    // This also un-crawls multi-batch IBD: the Headers handler requests one
    // 500-block batch and never issues a follow-up GetHeaders, so a node
    // thousands of blocks behind previously advanced one batch per 60s tip
    // re-announce. With the nudge it re-requests from its ADVANCING blue_score
    // at least every 30s. At parity the nudge stops (and the serving side
    // suppresses empty Headers replies), so steady-state cost is zero.
    {
        let dag_n        = dag.clone();
        let state_n      = node_state.clone();
        let otx_n        = outbound_tx.clone();
        let peer_state_n = peer_state.clone();
        let frontier_n   = frontier.clone();
        tokio::spawn(async move {
            let mut nudge = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                nudge.tick().await;
                let our_s = dag_n.read().tip_blue_score();
                let (peers, syncing, best_seen, seen_tip) = {
                    let s = state_n.read();
                    (s.peer_count, s.is_syncing, s.best_seen_blue_score, s.seen_first_tip)
                };
                if peers > 0 {
                    // Retained legacy fallback (gossip path): only when we have a
                    // reason to believe we're behind, exactly as before.
                    if syncing || !seen_tip || best_seen > our_s {
                        debug!("IBD nudge: GetHeaders from score {} (best_seen={} syncing={} seen_tip={})",
                            our_s, best_seen, syncing, seen_tip);
                        let _ = otx_n.send(network::NetworkMessage::GetHeaders { from_blue_score: our_s, limit: 500, nonce: getblock_nonce() }).await;
                    }
                    // Phase-2 frontier reconciliation: every peer replies Tips.
                    let _ = otx_n.send(network::NetworkMessage::GetTips).await;
                    // Re-request timed-out tip GetBlocks.
                    let now = std::time::Instant::now();
                    let stale = frontier_n.lock().expired(sync::TIP_REQUEST_TIMEOUT, now);
                    for h in stale {
                        let _ = otx_n.send(network::NetworkMessage::GetBlock { block_hash: h, nonce: getblock_nonce() }).await;
                    }
                    // Re-test the blue_work-verified IBD latch so a node never
                    // wedges in is_syncing after it has actually caught up —
                    // the liveness backstop against a fabricated high announced
                    // score freezing the node.
                    maybe_release_ibd(&dag_n, &peer_state_n, &frontier_n, &state_n);
                }
            }
        });
    }

    // ── Ready ─────────────────────────────────────────────────────────────────
    let (score, count) = { let d = dag.read(); (d.tip_blue_score(), d.block_count()) };
    info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    info!("  P2P   {}", cli.listen);
    info!("  RPC   {}:{}", cli.rpc_bind, cli.rpc_port);
    info!("  Mine  {}", if cli.mine { "ON" } else { "OFF" });
    info!("  DAG   {} blocks, score={}", count, score);

    // ── UTXO Reindex DISABLED (needs topological ordering for DAG) ──
    /*
    {
        let bc = dag.read().block_count() as u64;
        if bc > 1 {
            info!("Reindexing UTXOs from {} blocks...", bc);
            let _ = store.clear_utxos();
            let mut all_blocks = store.iter_all_blocks();
            // Sort by height for correct topological processing
            all_blocks.sort_by_key(|(_, b)| b.height);
            let mut reindexed = 0u64;
            for (hash, block) in &all_blocks {
                for tx in &block.transactions {
                    let txid = tx.txid();
                    for (j, out) in tx.outputs.iter().enumerate() {
                        let _ = store.put_utxo(&txid, j as u32, out);
                    }
                    if !tx.is_coinbase() {
                        for inp in &tx.inputs {
                            let _ = store.delete_utxo(&inp.prev_txid, inp.prev_index);
                        }
                    }
                }
                reindexed += 1;
            }
            info!("UTXO reindex complete: {} blocks processed", reindexed);
        }
    }*/

    info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");


    // ── Continuous Mining Loop ────────────────────────────────────────────────
    if cli.mine {
        // Fresh-miner fork guard: if the operator configured a bootstrap peer
        // or DNS seed they intend to JOIN an existing network, so mining before
        // we have any peer would fork from genesis on the forgeable chain.
        // Nodes with no peer/seed configured (intentional solo / island) keep
        // mining immediately.
        let wants_to_join = !cli.peer.is_empty() || !cli.dns_seed.is_empty();
        let store_m  = store.clone();
        let dag_m    = dag.clone();
        let state_m  = node_state.clone();
        let mem_m    = mempool.clone();
        let otx_m    = outbound_tx.clone();
        let tip_tx_m = tip_tx.clone();  // Sprint 2.c: tip broadcast for stratum
        let miner_addr = cli.miner_address.clone()
            .unwrap_or_else(|| FOUNDER_ADDRESS_HEX.to_string());
        // FIX #8: Convert miner address to proper 20-byte script_pubkey
        let miner_spk = address_to_script_pubkey(&miner_addr);

        // Capacity: grind the SIS search across all logical CPUs by default
        // (result-identical — see pow::mine_sis_pow_parallel). Override with
        // --mine-threads. Clamp to >=1.
        let mine_threads = cli.mine_threads
            .unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1))
            .max(1);

        tokio::spawn(async move {
            info!("⛏  Miner started → {} ({} thread(s))", miner_addr, mine_threads);
            let mut mining_round: u64 = 0;
            // Sprint GG: warn once when we first see IBD active, log
            // transition back to ready so operators see the transition.
            let mut was_syncing_last_tick: bool = false;
            let mut warned_no_peers: bool = false;
            // Sync-stall release: is_syncing pauses mining during genuine IBD,
            // but must never latch forever. If the tip has not advanced for
            // SYNC_STALL_SECS while syncing — peers cannot deliver the announced
            // best_seen tip (e.g. the whole network is wedged behind the
            // reachability perf wall) — resume mining on the best local tip.
            // is_syncing STAYS true so the IBD nudge keeps pulling; PoW advances
            // the chain in the meantime and we reorg to any heavier chain the
            // instant its blocks arrive. This is what stops a network-wide
            // freeze from being permanent.
            const SYNC_STALL_SECS: u64 = 90;
            let mut last_seen_tip: u64 = dag_m.read().tip_blue_score();
            let mut last_tip_advance = std::time::Instant::now();
            let mut warned_stall_release: bool = false;
            loop {
                // Fresh-miner fork guard (see wants_to_join above): a node told
                // to join a network but with 0 peers so far must not mine — it
                // would build an isolated fork from genesis that the network
                // rejects on cumulative work. Pause until at least one peer.
                // Wait not just for a connection but for the first remote tip:
                // there is a window where peer_count>0 but no PeerTip has been
                // evaluated yet, during which a fresh joiner would mine a
                // genesis fork. seen_first_tip closes that race.
                let (has_no_peer, no_tip_yet) = {
                    let s = state_m.read();
                    (s.peer_count == 0, !s.seen_first_tip)
                };
                if wants_to_join && (has_no_peer || no_tip_yet) {
                    if !warned_no_peers {
                        info!("⛏  not ready to mine yet — waiting to connect and see the network tip (would otherwise fork from genesis); still trying to reach the configured peer/seed");
                        warned_no_peers = true;
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    continue;
                }
                if warned_no_peers {
                    info!("⛏  connected and tip evaluated — miner active");
                    warned_no_peers = false;
                }
                // Sprint GG fix (pre-IBD mining bug, 2026-04-22):
                // During IBD the DAG tip reflects the local view, which
                // lags the network by up to thousands of blocks. Mining
                // against a stale tip produces blocks at low height
                // which the rest of the network rejects via the finality
                // rule (block at or below finalized_height). Pre-fix,
                // fresh miners would burn CPU for hours producing
                // orphan blocks that never paid out — an awful new-user
                // experience that looked like a protocol fault.
                //
                // This check pauses the miner loop while is_syncing is
                // true. The heartbeat logs the transition once in each
                // direction so operators can see when IBD started and
                // when mining resumed.
                let syncing_now = state_m.read().is_syncing;
                // Track tip progress for the sync-stall release.
                {
                    let cur_tip = dag_m.read().tip_blue_score();
                    if cur_tip > last_seen_tip {
                        last_seen_tip = cur_tip;
                        last_tip_advance = std::time::Instant::now();
                        warned_stall_release = false;
                    }
                }
                let sync_stalled = last_tip_advance.elapsed()
                    >= std::time::Duration::from_secs(SYNC_STALL_SECS);
                // [no-fork] Freeze finality while mining through a stall (the
                // announced heaviest tip is unreachable and we mine our local
                // tip to stay live): a strictly-heavier chain must still be able
                // to deep-reorg us back once its holder becomes reachable, so
                // mine-through can never self-finalize a solo fork. Unfrozen
                // whenever we are synced or catching up normally.
                FINALITY_FROZEN.store(syncing_now && sync_stalled,
                    std::sync::atomic::Ordering::Relaxed);
                if syncing_now && !sync_stalled {
                    if !was_syncing_last_tick {
                        info!("⛏  IBD in progress — miner paused, will resume when sync completes");
                        was_syncing_last_tick = true;
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    continue;
                }
                if syncing_now && sync_stalled && !warned_stall_release {
                    warn!("⛏  sync stalled {}s at tip {} (announced best_seen unreachable) — resuming mining on best local tip; will reorg when heavier blocks arrive",
                        SYNC_STALL_SECS, last_seen_tip);
                    warned_stall_release = true;
                }
                if was_syncing_last_tick && !syncing_now {
                    info!("⛏  IBD complete — miner resumed at tip");
                    was_syncing_last_tick = false;
                }

                let (tips, current_bits, current_height) = {
                    let d = dag_m.read();
                    let tips = d.tips();
                    let h = tips.iter()
                        .filter_map(|t| d.get_block_data(t))
                        .map(|data| data.height)
                        .max()
                        .unwrap_or(0);
                    // ASERT-Lattice difficulty anchored at genesis (B5c): bits
                    // are computed per-block from the parent timestamp, not read
                    // from a windowed-retarget meta key.
                    let parent_ts = store_m.get_timestamp_at_height(h).ok().flatten()
                        .unwrap_or(core::GENESIS_TIMESTAMP);
                    let bits = pow::next_bits(core::GENESIS_BITS, core::GENESIS_TIMESTAMP, parent_ts, h + 1);
                    (tips, bits, h)
                };

                // Re-broadcast mempool TXs before mining
                {
                    let pending = mem_m.get_for_block(100);
                    for tx in &pending {
                        let txid = tx.txid();
                        // Sprint 1.d: Bitcoin-format tx wire.
                        let data = tx.to_stratum_bytes(true);
                        let _ = otx_m.try_send(network::NetworkMessage::NewTransaction {
                            txid, tx_data: data,
                        });
                    }
                }
                // Re-broadcast mempool TXs every ~30s to ensure propagation
                if mining_round % 10 == 0 {
                    let pending = mem_m.get_for_block(100);
                    for tx in &pending {
                        let txid = tx.txid();
                        let data = tx.to_stratum_bytes(true);
                        let _ = otx_m.try_send(network::NetworkMessage::NewTransaction {
                            txid, tx_data: data,
                        });
                    }
                }
                mining_round += 1;
                let txs = mem_m.get_for_block(2000);

                // FIX VULN-05: Compute fees and include in coinbase
                let total_fees: u64 = txs.iter().map(|tx| {
                    let total_in: u64 = tx.inputs.iter()
                        .filter_map(|inp| store_m.get_utxo(&inp.prev_txid, inp.prev_index).ok().flatten())
                        .map(|out| out.value)
                        .sum();
                    let total_out: u64 = tx.outputs.iter()
                        .try_fold(0u64, |acc, o| acc.checked_add(o.value))
                        .unwrap_or(u64::MAX); // overflow → caller will reject
                    total_in.saturating_sub(total_out)
                }).sum();

                // V2 coinbase per TOKENOMICS_V2 §4 (ADR-028):
                //   output[0] = miner          = 70% subsidy + total_fees
                //   output[1] = validator_pool = 25% subsidy
                //   output[2] = oracle_pool    =  5% subsidy
                //   output[3] = founder        = vesting delta (if > 0)
                //
                // Pool addresses come from tokenomics_v2 panicking accessors
                // — deliberate fail-loud until Phase 6 sets the constants.
                let block_height = current_height + 1;
                let subsidy = core::tokenomics_v2::block_subsidy_sat(block_height);
                let founder_vesting =
                    core::tokenomics_v2::founder_vesting_delta_sat(block_height);

                // Pure PoW (B3): 100% of subsidy + fees to the miner.
                let mut cb_outputs = vec![
                    core::TxOutput {
                        value:         subsidy.saturating_add(total_fees),
                        script_pubkey: miner_spk.clone(),
                    },
                ];
                if founder_vesting > 0 {
                    cb_outputs.push(core::TxOutput {
                        value:         founder_vesting,
                        script_pubkey: core::tokenomics_v2::founder_address_hash().to_vec(),
                    });
                }

                let coinbase = core::Transaction {
                    version: 1,
                    inputs: vec![core::TxInput {
                        prev_txid:  [0u8; 32],
                        prev_index: u32::MAX,
                        script_sig: format!("height:{}", block_height).into_bytes(),
                        sequence:   u32::MAX,
                    }],
                    outputs: cb_outputs,
                    locktime: 0,
                };

                let all_txs: Vec<core::Transaction> = std::iter::once(coinbase).chain(txs).collect();
                let merkle = core::Transaction::merkle_root(&all_txs);

                let mut block = core::Block {
                    header: core::BlockHeader {
                        version:     1,
                        parents:     tips.clone(),
                        merkle_root: merkle,
                        timestamp:   std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default().as_secs(),
                        bits:        current_bits,
                        nonce:       0,
                    },
                    transactions: all_txs,
                    blue_score:   dag_m.read().tip_blue_score() + 1,
                    height:       current_height + 1,
                    pow_solution: Vec::new(),
                    shielded_transactions: Vec::new(),                };

                // Bloch-SIS PoW (B5b-2b): mine a Module-SIS solution. The
                // preimage excludes the nonce (the miner varies the nonce
                // internally); on success we attach the solution vector as the
                // block's PoW witness.
                //
                // Soft fork SF-1: the residual width is selected by the height
                // of the block BEING MINED (tip + 1), matching what
                // Block::validate_pow will check on acceptance — k = 4 below
                // CANONICAL_K_ACTIVATION_HEIGHT, k = 8 at/above it.
                let preimage = block.header.pow_preimage();
                let bits = block.header.bits;
                let mine_height = block.height;
                let mined = tokio::task::spawn_blocking(move || {
                    pow::mine_sis_pow_parallel(&preimage, bits, mine_height, 0, 50_000_000, mine_threads)
                }).await;

                match mined {
                    Ok(Some((nonce, solution))) => {
                        block.header.nonce = nonce;
                        block.pow_solution = solution.to_vec();
                        let hash = block.block_hash();
                        info!("⛏  Block found! h={} {}", block.height, hex::encode(&hash[..8]));

                        let ts      = block.header.timestamp;
                        let parents = block.header.parents.clone();
                        if let Err(e) = store_m.put_block(&block) {
                            warn!("store mined block: {}", e);
                            continue;
                        }
                        store_m.put_meta("tip_hash", &hash).ok();

                        // Sprint DD (PR-2 fix): capture undo data during mutation.
                        //
                        // The pre-DD code applied UTXO/tx_index/coinbase mutations
                        // inline here (written before Sprint U landed) but never
                        // recorded UndoData. Any locally-mined block was therefore
                        // unrollback-able — a fatal problem the moment IBD arrived
                        // from a peer with a heavier chain, because the resulting
                        // reorg plan would fail on the first rollback_block call
                        // with "no undo data for block ..". Observed in production
                        // 2026-04-21: Akash worker minered h=1 locally, seed IBD
                        // delivered multiple competing h=1 blocks, reorg aborted,
                        // worker stuck at height=1.
                        //
                        // Routing through apply_block_utxo_mutations gives us the
                        // byte-identical mutation sequence this branch had before,
                        // plus the UndoData record required by reorg.
                        if let Err(e) = reorg::apply_block_utxo_mutations(&store_m, &block) {
                            warn!("DD: apply_block_utxo_mutations for mined block h={}: {}",
                                block.height, e);
                            // Keep going — partial mutation is still better than
                            // erroring out of the miner loop and freezing the node.
                        }

                        let work = pow::work_from_bits(block.header.bits);
                        // Sprint 2.c: snapshot old tip so we can detect and
                        // broadcast when our mined block advances the chain.
                        let old_tip_mined = { dag_m.read().selected_tip() };
                        if let Err(e) = dag_m.write().add_block(hash, parents, ts, work) {
                            // M-9: a locally-mined block should never hit these
                            // preconditions — no-parents or duplicate-hash here
                            // would indicate a miner bug, not a peer attack. Log
                            // loud and skip this block so the miner doesn't spin.
                            log::error!(
                                "mining: DAG rejected our own block {}: {}. Skipping.",
                                hex::encode(hash), e,
                            );
                            continue;
                        }
                        // Persist DAG data + integrity hash (Sprint Y, M-2).
                        // Phase 1: fold the reachability delta into the same
                        // atomic write when the index is maintained; live Legacy
                        // path is byte-for-byte unchanged.
                        if let Some(ddata) = dag_m.read().get_block_data(&hash).cloned() {
                            if dag_m.read().maintains_reachability_index() {
                                let (upserts, removals) = dag_m.write().reach_take_delta();
                                store_m.put_dag_with_integrity_and_reach(&hash, &ddata, &upserts, &removals).ok();
                            } else {
                                store_m.put_dag_with_integrity(&hash, &ddata).ok();
                            }
                        }
                        {
                            let mut s = state_m.write();
                            s.tip_blue_score = dag_m.read().tip_blue_score();
                            s.block_count    = dag_m.read().block_count() as u64;
                            s.mempool_size   = mem_m.size();
                        }

                        // Difficulty is per-block ASERT-Lattice (B5c) — no
                        // windowed retarget / current_bits meta write.

                        let confirmed: Vec<[u8;32]> = block.transactions.iter().map(|t| t.txid()).collect();
                        mem_m.remove_confirmed(&confirmed);

                        // Sprint 2.c: broadcast tip change so stratum sessions
                        // get fresh templates. Mined blocks almost always
                        // extend the tip, but we still guard with the
                        // old_tip != new_tip check — during a network-driven
                        // reorg racing our add_block, the tip may not actually
                        // be our block.
                        {
                            let new_tip = { dag_m.read().selected_tip() };
                            if new_tip != old_tip_mined {
                                if let Some(tip_hash) = new_tip {
                                    let d = dag_m.read();
                                    if let Some(data) = d.get_block_data(&tip_hash).cloned() {
                                        let tips_parents: Vec<[u8; 32]> = d.tips();
                                        drop(d);
                                        let bits = store_m.get_meta("current_bits").ok().flatten()
                                            .and_then(|b| b.as_slice().try_into().ok().map(u32::from_le_bytes))
                                            .unwrap_or(0x1d00ffff_u32);
                                        let _ = tip_tx_m.send(stratum::TipChanged {
                                            hash:       tip_hash,
                                            height:     data.height,
                                            blue_score: data.blue_score,
                                            parents:    tips_parents,
                                            bits,
                                        });
                                    }
                                }
                            }
                        }

                        // Sprint 1.c: Bitcoin-format wire (replaces bincode).
                        // Infallible — no Result to unwrap.
                        let data = block.to_bitcoin_bytes();
                        let _ = otx_m.send(network::NetworkMessage::NewBlock {
                            block_hash: hash,
                            blue_score: block.blue_score,
                            height:     block.height,
                            block_data: data,
                        }).await;
                    }
                    _ => {
                        tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
                    }
                }
            }
        });
    }

    // ── Sprint 2.a/b — Stratum V1 mining server ──────────────────────────────
    //
    // Opt-in via --stratum. When enabled, constructs an AcceptBlockFn closure
    // that captures Arc clones of the DAG / store / mempool / node_state /
    // outbound_tx, wraps the existing accept_block() function, and feeds
    // Sprint 1.c's Bitcoin-format broadcast path on success.
    //
    // Tip broadcast (2.c) and per-session template generation (2.d) are
    // wired in subsequent commits. This scaffolding brings the server
    // online; miners can connect + subscribe + authorize but will not
    // yet receive mining.notify until 2.d.
    // ───────── Sprint 10-epsilon Phase 5.a: hoisted accept_block_cb ─────────
    //
    // Constructed once at top-level main() scope so both V1 (stratum) and V2
    // (stratum_v2) servers can route found blocks through the same consensus
    // pipeline. The closure captures Arcs of dag/store/mempool/etc. and is
    // itself an Arc<AcceptBlockFn> that's cheap to clone into each config.
    //
    // Lock discipline: accept_block itself takes dag.write() briefly. Each
    // caller is on its own tokio task (one per session), so serialization
    // is the same as any other network-path accept_block caller.
    //
    // Audit H2: construction moved into the named builder
    // `make_stratum_accept_block_cb` (below `accept_block`) so the structural
    // gate can be regression-tested — see `external_submission_tests`.
    let accept_block_cb: Arc<stratum::AcceptBlockFn> = make_stratum_accept_block_cb(
        dag.clone(), store.clone(), mempool.clone(), node_state.clone(),
        shielded.clone(), outbound_tx.clone(), tip_tx.clone(),
    );

    // ───────── B5f pool seam: RPC submitblock hook ─────────
    //
    // Stratum V1/V2 cannot carry the Module-SIS solution vector (see the
    // refusal below), so external pool software mines COMPLETE SIS blocks
    // and hands them in via the `submitblock` RPC method instead. This hook
    // mirrors the gossipsub NewBlock path exactly:
    //
    //   1. identity  = Block::block_hash()  (SHA3, binds the SIS witness —
    //                  NOT header.pow_hash(); same as the network path)
    //   2. dedup     = dag.has_block
    //   3. structure = Block::validate_structure() (PoW witness, merkle,
    //                  coinbase format) — same call the NewBlock handler makes
    //   4. consensus = the shared accept_block() pipeline
    //   5. gossip    = broadcast NewBlock so peers learn about it
    //
    // The reference pool consuming this lives in pool/.
    //
    // Construction lives in the named builder `make_rpc_submit_block_cb`
    // (below `accept_block`) so the stratum and RPC gates can be
    // regression-tested side by side — see `external_submission_tests`.
    let rpc_submit_block: Arc<rpc::SubmitBlockFn> = make_rpc_submit_block_cb(
        dag.clone(), store.clone(), mempool.clone(), node_state.clone(),
        shielded.clone(), outbound_tx.clone(), tip_tx.clone(),
    );

        // Sprint B5f: Stratum V1/V2 are hash-PoW pool protocols — the share
        // message (`[user, job, en2, ntime, nonce]`) has no field for the
        // Module-SIS solution vector `s`, so a stratum-submitted block carries
        // no PoW witness and fails validate_pow. Pool mining therefore requires
        // a SIS-native share protocol (future work). Refuse to start the server
        // under Module-SIS rather than silently produce rejected blocks. Solo
        // mining (--mine) uses the node's SIS miner.
        if cli.stratum {
            error!("stratum mining is unsupported under Module-SIS PoW (no share \
                    field for the lattice solution). Use solo mining (--mine). \
                    A SIS-native pool protocol is future work (see B5f).");
            std::process::exit(1);
        }
        if false {
        // Parse + validate CLI params
        let bind_addr: std::net::SocketAddr = match cli.stratum_addr.parse() {
            Ok(a)  => a,
            Err(e) => {
                error!("invalid --stratum-addr '{}': {}", cli.stratum_addr, e);
                std::process::exit(1);
            }
        };

        let mode: stratum::StratumMode = match cli.stratum_mode.parse() {
            Ok(m)  => m,
            Err(e) => {
                error!("invalid --stratum-mode '{}': {}", cli.stratum_mode, e);
                std::process::exit(1);
            }
        };

        // Build the accept_block callback. When a miner's share meets the
        // block target, the submit path (src/stratum/submit.rs) invokes
        // Sprint 10-epsilon Phase 5.a: accept_block_cb is now constructed
        // at top-level scope (before `if cli.stratum`) so it can be shared
        // with V2. See the hoisted construction above.

        let stratum_config = stratum::StratumConfig {
            bind_addr,
            mode,
            max_sessions: cli.stratum_max_sessions,
            coinbase_tag: cli.stratum_coinbase_tag.clone(),
            accept_block: Some(accept_block_cb.clone()),
            // Sprint 2.d: bundle dag/store/mempool handles for per-session
            // template generation in handle_authorize + tip_rx re-notify.
            node_ctx: Some(Arc::new(stratum::TemplateContext {
                dag:          dag.clone(),
                store:        store.clone(),
                mempool:      mempool.clone(),
                coinbase_tag: cli.stratum_coinbase_tag.clone(),
            })),
        };

        let tip_rx_for_server = tip_tx.subscribe();

        info!("stratum: starting server on {} (mode={}, max_sessions={})",
              stratum_config.bind_addr, stratum_config.mode, stratum_config.max_sessions);

        tokio::spawn(async move {
            if let Err(e) = stratum::run(stratum_config, tip_rx_for_server).await {
                error!("stratum: server terminated: {}", e);
            }
        });
    }



    // --- Sprint 10-alpha: stratum V2 server ---
    //
    // Runs in parallel to V1. Both subscribe to the same TipChanged
    // broadcast channel (tip_tx). Their wire protocols and session
    // state machines are independent.
    //
    // V2 uses NOISE_NX handshake (encrypted from byte 0) + SV2
    // binary framing. Default port 3334 (V1 stays on 3333).
    //
    // The authority keypair at --sv2-cert-path is auto-generated on
    // first run and must be preserved across restarts -- its fingerprint
    // is what miners pin. Losing it invalidates all miner trust.
    if cli.sv2_enable {
        // Sprint B5f: same as Stratum V1 — the SV2 SubmitShares message carries
        // no Module-SIS solution vector, so it cannot produce valid Bloch-SIS
        // blocks. Refuse to start; solo mining (--mine) uses the SIS miner.
        error!("stratum V2 mining is unsupported under Module-SIS PoW (no share \
                field for the lattice solution). Use solo mining (--mine). \
                A SIS-native pool protocol is future work (see B5f).");
        std::process::exit(1);
    }
    if false {
        let sv2_bind: std::net::SocketAddr = match cli.sv2_addr.parse() {
            Ok(a)  => a,
            Err(e) => {
                error!("invalid --sv2-addr '{}': {}", cli.sv2_addr, e);
                std::process::exit(1);
            }
        };

        let sv2_cert = cli.sv2_cert_path.clone()
            .unwrap_or_else(|| {
                PathBuf::from(&cli.data_dir).join("sv2-authority-keypair.json")
            });

        let mut sv2_config = match stratum_v2::Sv2Config::new(
            sv2_bind,
            cli.sv2_max_sessions,
            sv2_cert,
        ) {
            Ok(c)  => c,
            Err(e) => {
                error!("invalid stratum_v2 config: {}", e);
                std::process::exit(1);
            }
        };

        // Sprint 10-delta-Etapa-1: share V1's TemplateContext with V2.
        // Reuses the same DAG/store/mempool handles already built for V1.
        sv2_config.node_ctx = Some(Arc::new(stratum::TemplateContext {
            dag:          dag.clone(),
            store:        store.clone(),
            mempool:      mempool.clone(),
            coinbase_tag: cli.stratum_coinbase_tag.clone(),
        }));

        // Sprint 10-epsilon Phase 5.a: share the hoisted accept_block_cb
        // with V2. Both V1 and V2 route found blocks through the same
        // consensus pipeline. CHECKME-epsilon-v2-standalone resolved.
        sv2_config.accept_block = Some(accept_block_cb.clone());

        let tip_rx_v2 = tip_tx.subscribe();

        info!(
            "stratum_v2: spawning on {} (max_sessions={})",
            sv2_config.bind_addr, sv2_config.max_sessions
        );

        tokio::spawn(async move {
            if let Err(e) = stratum_v2::run(sv2_config, tip_rx_v2).await {
                error!("stratum_v2: listener terminated: {}", e);
            }
        });
    }

    // ── Sprint D: metrics state (shared across server + instrumented modules) ──
    let metrics_state = std::sync::Arc::new(
        crate::metrics::MetricsState::new(
            env!("CARGO_PKG_VERSION"),
            if cli.testnet { "testnet" } else { "mainnet" },
        )
    );
    let metrics_config = crate::metrics::MetricsConfig {
        enabled:      cli.metrics,
        bind_address: metrics_bind,
        port:         cli.metrics_port,
    };
    // Install as process-wide singleton so instrumentation points in other
    // modules can increment counters via free functions without plumbing.
    if cli.metrics {
        crate::metrics::install(metrics_state.clone());
    }

    // Periodic sync of gauges from NodeState to Prometheus.
    // Runs every 5s. Cheap — just atomic reads + atomic gauge sets.
    let state_for_metrics = node_state.clone();
    let mempool_for_metrics = mempool.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
        loop {
            interval.tick().await;
            let (height, peers) = {
                let s = state_for_metrics.read();
                (s.block_count as i64, s.peer_count as i64)
            };
            crate::metrics::set_block_count(height);
            crate::metrics::set_peer_count(peers);
            crate::metrics::set_mempool_size(mempool_for_metrics.size() as i64);
        }
    });

    tokio::select! {
        _ = crate::metrics::start_metrics_server(
                metrics_config,
                metrics_state.clone(),
            ) => { error!("metrics exited"); }
        _ = rpc::start_rpc_server(
                rpc::RpcConfig {
                    bind_address:              rpc_bind,
                    port:                      cli.rpc_port,
                    api_key,
                    require_auth_for_writes:   cli.rpc_require_auth_for_writes,
                    rate_limit_reads_per_min:  cli.rpc_rate_limit_reads,
                    rate_limit_writes_per_min: cli.rpc_rate_limit_writes,
                    trust_private_ranges:      cli.rpc_trust_private_ranges,
                },
                node_state.clone(), store.clone(), mempool.clone(), dag.clone(), outbound_tx.clone(),
                // B5f pool seam: submitblock hook (see rpc::SubmitBlockFn).
                Some(rpc_submit_block.clone()),
            ) => { error!("RPC exited"); }
        _ = node.run(block_tx, outbound_rx, dag.clone(), peer_state.clone()) => {
            error!("Network exited");
        }
    }
}

// ── External block submission callbacks (stratum V1/V2 + RPC submitblock) ────
//
// Both builders wrap the shared `accept_block` consensus pipeline. They are
// named functions (not inline closures in main()) so their gates can be
// unit-tested — see `external_submission_tests` at the bottom of this file.

/// Build the AcceptBlockFn shared by the Stratum V1 and V2 servers
/// (Sprint 10-epsilon Phase 5.a).
///
/// SECURITY (audit H2): the callback runs `Block::validate_structure()` —
/// Module-SIS PoW witness, merkle binding, coinbase format, duplicate-tx and
/// dust checks — BEFORE handing the block to `accept_block`, mirroring the
/// gossipsub NewBlock path and the RPC `submitblock` hook. `accept_block`
/// itself checks bits/height/timestamp/tx-validity but does NOT re-run the
/// structural checks, so without this gate a stratum-submitted block with no
/// (or a forged) SIS witness or a non-binding merkle root would enter the
/// DAG, storage, and gossip broadcast.
///
/// NOTE (pre-existing, unchanged here): this path identifies the block by
/// `header.pow_hash()` while the network/RPC paths use `Block::block_hash()`
/// (SHA3, binds the SIS witness). Stratum V1/V2 are currently refused at
/// startup under Module-SIS (see B5f), so the callback is dormant; the
/// identity unification belongs to the future SIS-native share protocol.
fn make_stratum_accept_block_cb(
    dag:        Arc<RwLock<consensus::GhostDAG>>,
    store:      Arc<storage::Storage>,
    mempool:    Arc<mempool::Mempool>,
    node_state: Arc<RwLock<rpc::NodeState>>,
    shielded:   Arc<RwLock<crate::coherence::ShieldedPool>>,
    otx:        mpsc::Sender<network::NetworkMessage>,
    tip_tx:     broadcast::Sender<stratum::TipChanged>,
) -> Arc<stratum::AcceptBlockFn> {
    Arc::new(move |block: core::Block| -> Result<String, String> {
        // ── SECURITY (audit H2): structural gate FIRST ──────────────────
        // Same call + same error shape as `make_rpc_submit_block_cb`, so
        // stratum submissions cannot bypass the SIS/merkle/coinbase gate.
        block.validate_structure()
            .map_err(|e| format!("structural validation: {}", e))?;

        let block_hash = block.header.pow_hash();
        let height     = block.height;
        let blue_score = block.blue_score;

        // Delegate all consensus validation + DAG mutation + retarget +
        // UTXO updates + mempool cleanup to the existing accept_block path.
        accept_block(
            &block, block_hash, height,
            &dag, &store, &mempool, &node_state,
            Some(&tip_tx), &shielded,
        )?;

        // Refresh RPC-visible state (mirrors miner loop).
        {
            let mut s = node_state.write();
            s.tip_blue_score = dag.read().tip_blue_score();
            s.block_count    = dag.read().block_count() as u64;
            s.mempool_size   = mempool.size();
        }

        // Broadcast to gossipsub — other peers learn about the block.
        let data = block.to_bitcoin_bytes();
        let msg = network::NetworkMessage::NewBlock {
            block_hash,
            blue_score,
            height,
            block_data: data,
        };
        let otx_clone = otx.clone();
        tokio::spawn(async move { let _ = otx_clone.send(msg).await; });

        Ok(hex::encode(block_hash))
    })
}

/// Build the RPC `submitblock` hook (B5f pool seam). Behavior is unchanged
/// from the previous inline closure: `Block::block_hash()` identity, dedup,
/// `validate_structure()`, then the shared `accept_block` pipeline + gossip.
fn make_rpc_submit_block_cb(
    dag:        Arc<RwLock<consensus::GhostDAG>>,
    store:      Arc<storage::Storage>,
    mempool:    Arc<mempool::Mempool>,
    node_state: Arc<RwLock<rpc::NodeState>>,
    shielded:   Arc<RwLock<crate::coherence::ShieldedPool>>,
    otx:        mpsc::Sender<network::NetworkMessage>,
    tip_tx:     broadcast::Sender<stratum::TipChanged>,
) -> Arc<rpc::SubmitBlockFn> {
    Arc::new(move |block: core::Block| -> Result<String, String> {
        let block_hash = block.block_hash();
        if dag.read().has_block(&block_hash) {
            return Err("duplicate block".to_string());
        }
        block.validate_structure()
            .map_err(|e| format!("structural validation: {}", e))?;

        accept_block(
            &block, block_hash, block.height,
            &dag, &store, &mempool, &node_state,
            Some(&tip_tx), &shielded,
        )?;

        // Refresh RPC-visible state (mirrors the miner loop).
        {
            let mut s = node_state.write();
            s.tip_blue_score = dag.read().tip_blue_score();
            s.block_count    = dag.read().block_count() as u64;
            s.mempool_size   = mempool.size();
        }

        // Broadcast to gossipsub — other peers learn about the block.
        let data = block.to_bitcoin_bytes();
        let msg = network::NetworkMessage::NewBlock {
            block_hash,
            blue_score: block.blue_score,
            height:     block.height,
            block_data: data,
        };
        let otx_clone = otx.clone();
        tokio::spawn(async move { let _ = otx_clone.send(msg).await; });

        Ok(hex::encode(block_hash))
    })
}

// ── Block acceptance + Orphan processing ─────────────────────────────────────

/// [no-fork] Set true while the miner is mining through a stalled IBD latch
/// (the announced heaviest tip is unreachable and we mine our locally-heaviest
/// validated tip to keep the chain live). While frozen we do NOT advance
/// `finalized_height`, so a strictly-heavier chain can still deep-reorg us back
/// once its holder becomes reachable — mine-through can never self-finalize a
/// solo fork. Driven by the miner loop; cleared when synced / catching up.
/// A per-request nonce whose ONLY job is to make each GetBlock unique on the
/// wire, so gossipsub's duplicate cache cannot swallow a retry. Monotonic rather
/// than random: retries must differ from each other, and a counter guarantees
/// that without depending on an RNG or on the clock's resolution.
fn getblock_nonce() -> u64 {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

static FINALITY_FROZEN: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Set once from `--archive` at startup. Same static-flag shape as
/// FINALITY_FROZEN above: accept_block runs far from the CLI struct and
/// threading a bool through every caller would be noise for a value that is
/// fixed for the process lifetime.
static ARCHIVE_MODE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Validate TX contents, add block to DAG + storage, update UTXO set.
/// Returns Ok(block_hash) on success.
fn accept_block(
    block:      &core::Block,
    block_hash: [u8; 32],
    height:     u64,
    dag:        &Arc<RwLock<consensus::GhostDAG>>,
    store:      &Arc<storage::Storage>,
    mempool:    &Arc<mempool::Mempool>,
    node_state: &Arc<RwLock<rpc::NodeState>>,
    // Sprint 2.c: tip-change broadcast for stratum re-notify.
    // None disables notification (tests, CLI without --stratum).
    tip_tx:     Option<&broadcast::Sender<stratum::TipChanged>>,
    // Coherence C2: the node's shielded-pool engine. Block's shielded txs are
    // validated + applied here before the block is committed.
    shielded:   &Arc<RwLock<crate::coherence::ShieldedPool>>,
) -> Result<[u8; 32], String> {

    // Sprint 2.c: snapshot selected tip BEFORE any DAG mutation so we
    // can detect whether this block changed the chain's head. Nested
    // {} scope ensures the lock drops immediately.
    let old_tip = { dag.read().selected_tip() };

    // ── FIX VULN-01: Validate difficulty bits match expected ──────────
    // ASERT-Lattice (B5c): expected bits are derived per-block from the
    // parent timestamp + genesis anchor — miner and validator agree by
    // computing the same function (src/pow::next_bits).
    let parent_ts = store.get_timestamp_at_height(block.height.saturating_sub(1))
        .ok().flatten().unwrap_or(core::GENESIS_TIMESTAMP);
    let expected_bits = pow::next_bits(
        core::GENESIS_BITS, core::GENESIS_TIMESTAMP, parent_ts, block.height,
    );
    if block.header.bits != expected_bits {
        return Err(format!(
            "invalid difficulty: block bits 0x{:08x} != expected 0x{:08x}",
            block.header.bits, expected_bits
        ));
    }

    // ── FIX VULN-02: Validate height matches DAG position ────────────
    {
        let d = dag.read();
        // For non-genesis: height must be parent's max height + 1
        let expected_height = if block.header.parents.is_empty() {
            0
        } else {
            let max_parent_height = block.header.parents.iter()
                .filter_map(|p| d.get_block_data(p))
                .map(|data| data.height)
                .max()
                .unwrap_or(0);
            max_parent_height + 1
        };
        if block.height != expected_height {
            return Err(format!(
                "invalid height: block claims h={} but expected h={}",
                block.height, expected_height
            ));
        }
    }

    // ── Finality checkpoint: reject deep reorgs ──────────────────────
    {
        let finalized_height = store.get_meta("finalized_height").ok().flatten()
            .and_then(|b| b.as_slice().try_into().ok().map(u64::from_le_bytes))
            .unwrap_or(0);
        if block.height <= finalized_height {
            return Err(format!(
                "finality: block h={} at or below finalized height {}",
                block.height, finalized_height
            ));
        }
    }

    // ── FIX VULN-04: Validate timestamp ──────────────────────────────
    {
        let parent_ts = block.header.parents.iter()
            .filter_map(|p| dag.read().get_block_data(p).map(|d| d.timestamp))
            .max()
            .unwrap_or(0);
        block.validate_timestamp(parent_ts)
            .map_err(|e| format!("timestamp rejected: {}", e))?;
    }

    // ── Validate non-coinbase TXs + compute fees ─────────────────────
    let current_height = {
        let d = dag.read();
        d.block_count() as u64
    };
    let mut spent_in_block: HashSet<([u8; 32], u32)> = HashSet::new();
    let mut total_fees: u64 = 0;
    for tx in block.transactions.iter().skip(1) {
        let fee = validate_tx_in_block_with_maturity(
            block, tx, store, &mut spent_in_block, current_height
        )?;
        total_fees = total_fees.saturating_add(fee);
    }

    // ── FIX VULN-05: Validate coinbase value includes fees ───────────
    block.validate_coinbase_value(total_fees)
        .map_err(|e| format!("coinbase rejected: {}", e))?;

    // ── Difficulty: per-block ASERT-Lattice (B5c) ─────────────────────
    // No windowed retarget: `expected_bits` above is computed from the
    // genesis anchor + parent timestamp, so difficulty tracks the 30 s
    // target continuously. The legacy windowed `core::retarget_bits` is no
    // longer on the consensus path (its Sprint-L tests were removed with B5c).

    // ── Add to DAG ───────────────────────────────────────────────────
    //
    // Sprint U.4 — capture the selected tip BEFORE add_block so we can
    // classify what this block did to the selected chain once GhostDAG
    // recomputes after insertion.
    let old_selected_tip = dag.read().selected_tip();

    let ts      = block.header.timestamp;
    let parents = block.header.parents.clone();
    let work    = pow::work_from_bits(block.header.bits);
    // M-9: propagate consensus rejection upward instead of panicking.
    // NoParents / DuplicateBlock here mean the caller (the sync path or
    // gossipsub) handed us a structurally-broken block; we reject with
    // a string error just like the other validation steps above.
    // Coherence C2/P1: validate + apply this block's shielded transactions
    // before committing, using the pool's configured ShieldedVerifier — RejectAll
    // by default (safe: no unverifiable value admitted), or the SP1/FRI verifier
    // with `BLOCH_SHIELDED_VERIFY=sp1` (feature `sp1-verify`). Transparent blocks
    // (no shielded txs) are a no-op. NOTE: the shielded state does not yet track
    // reorgs; that lands with the live SP1 verifier. Merkle-binding already
    // commits the shielded txs into the PoW, so they are non-malleable.
    shielded.write().apply_block_self(block_hash, &block.shielded_transactions)
        .map_err(|e| format!("shielded consensus rejection: {:?}", e))?;

    dag.write().add_block(block_hash, parents, ts, work)
        .map_err(|e| format!("consensus rejection: {}", e))?;

    // CONSENSUS-HALT FIX (DAG-vs-UTXO ordering): the CF_DAG /
    // CF_DAG_INTEGRITY persist that used to happen right here is DEFERRED
    // until after the disposition match below succeeds. `add_block` above is
    // still needed first (GhostDAG selection is the single source of truth
    // for classifying this block), but if the disposition is REFUSED — e.g.
    // `execute_reorg` rejects an over-deep fork flip — the in-memory
    // insertion is rolled back via `GhostDAG::remove_block` and nothing was
    // persisted, so DAG store, CF_DAG and the applied UTXO state move
    // together or not at all. Previously the insertion was persisted
    // unconditionally: a refused deep reorg left `selected_tip()` pinned to
    // the attacker fork forever (every legitimate extension misclassified as
    // ForkLoser) — a durable consensus halt.

    // Persist block body — even if this block ends up in a losing fork, we
    // keep its bytes so a future reorg can apply it without re-downloading.
    // This must happen BEFORE the disposition match: `execute_reorg` reads
    // the bodies of `to_apply` blocks (including this one) from CF_BLOCKS.
    // Block bodies are not consensus state — selected-tip / blue-work
    // decisions are driven solely by CF_DAG, which is only written after
    // success — so a body left behind by a rejected block is inert.
    // On a body-persist failure, roll the in-memory insertion back.
    if let Err(e) = store.put_block(block) {
        dag.write().remove_block(&block_hash);
        return Err(e.to_string());
    }

    // ── Sprint U.4: disposition-based state application (closes C-1) ──
    //
    // Classify how this block affected the selected chain, then apply
    // UTXO mutations only when appropriate:
    //
    //   * FORK-LOSER   — the selected tip didn't move to this block.
    //                    Persist block + DAG data only; do NOT touch
    //                    UTXO set or mempool. The block lives in the DAG
    //                    and may win later (triggering a reorg).
    //
    //   * EXTENSION    — this block IS the new selected tip, and its
    //                    selected_parent is exactly the old tip. Apply
    //                    forward just like the pre-U.4 path.
    //
    //   * REORG        — this block IS the new selected tip, but its
    //                    selected_parent is NOT the old tip. The fork
    //                    that contains this block has outgrown the old
    //                    chain. Roll back old chain blocks to the LCA,
    //                    apply new chain blocks from LCA to this block,
    //                    reinject still-valid mempool txs.
    //
    // The match is exhaustive over the (old, new) tuple; unexpected
    // transitions (e.g. add_block produced no tip) log a warning and
    // leave state untouched so we don't corrupt anything.
    let new_selected_tip = dag.read().selected_tip();

    enum Disposition {
        Extension,
        ForkLoser,
        Reorg,
        Unexpected,
    }

    let disposition = match (old_selected_tip, new_selected_tip) {
        (None, Some(t)) if t == block_hash => {
            // Post-genesis first block — no prior tip. Treat as extension.
            Disposition::Extension
        }
        (Some(old), Some(new)) if new == old => Disposition::ForkLoser,
        (Some(old), Some(new)) if new == block_hash => {
            let selected_parent = dag.read()
                .get_block_data(&block_hash)
                .and_then(|d| d.selected_parent);
            if selected_parent == Some(old) {
                Disposition::Extension
            } else {
                Disposition::Reorg
            }
        }
        _ => Disposition::Unexpected,
    };

    match disposition {
        Disposition::ForkLoser => {
            info!(
                "block h={} {} accepted into fork (not selected tip)",
                block.height, hex::encode(&block_hash[..8])
            );
            // Intentional no-op on UTXO / mempool / tip_hash. The block is
            // now reachable via CF_BLOCKS + DAG; a future reorg can bring
            // it into the selected chain.
        }

        Disposition::Extension => {
            // Apply this block's mutations forward. Uses the shared helper
            // (src/reorg.rs) so extension and reorg re-apply go through
            // identical code — they must produce byte-identical UndoData.
            if let Err(e) = reorg::apply_block_utxo_mutations(store, block) {
                warn!(
                    "U.4: apply_block_utxo_mutations returned partial failure for h={}: {}",
                    block.height, e
                );
            }

            let confirmed: Vec<[u8; 32]> = block.transactions.iter().map(|t| t.txid()).collect();
            mempool.remove_confirmed(&confirmed);
            store.put_meta("tip_hash", &block_hash).ok();
        }

        Disposition::Reorg => {
            // new_selected_tip must be Some here (we matched on it).
            let new_tip = new_selected_tip.expect("reorg disposition implies Some(new_tip)");
            let old_tip = old_selected_tip.expect("reorg disposition implies Some(old_tip)");

            let plan = {
                let d = dag.read();
                reorg::compute_reorg_plan(&d, &old_tip, &new_tip)
            };
            let plan = match plan {
                Some(p) => p,
                None => {
                    // CONSENSUS-HALT FIX: roll the in-memory DAG insertion
                    // back before rejecting — nothing has been persisted to
                    // CF_DAG yet, so DAG and applied UTXO state stay in sync.
                    dag.write().remove_block(&block_hash);
                    return Err(format!(
                        "U.4: tip changed to {} via reorg but compute_reorg_plan returned None (old={}, new={})",
                        hex::encode(&new_tip[..8]),
                        hex::encode(&old_tip[..8]),
                        hex::encode(&new_tip[..8]),
                    ));
                }
            };

            info!(
                "🔀 Reorg at h={}: rollback {} blocks, apply {} blocks (lca={})",
                block.height,
                plan.to_rollback.len(),
                plan.to_apply.len(),
                hex::encode(&plan.lca[..8]),
            );

            let outcome = match reorg::execute_reorg(store, mempool, &plan) {
                Ok(o) => o,
                Err(e) => {
                    // CONSENSUS-HALT FIX: a refused reorg (e.g. deeper than
                    // reorg::MAX_REORG_DEPTH) or a failed one left the UTXO
                    // store untouched by design. The in-memory DAG insertion
                    // must be undone as well — otherwise selected_tip()
                    // permanently adopts a fork whose state was never
                    // applied, and every legitimate extension of the real
                    // chain is misclassified as ForkLoser: a durable halt.
                    // Nothing was persisted to CF_DAG (deferred until after
                    // this match), so the undo is purely in-memory.
                    if !dag.write().remove_block(&block_hash) {
                        warn!(
                            "U.4: failed to roll back DAG insertion of {} after refused reorg \
                             (block gained children concurrently?) — tip may be inconsistent",
                            hex::encode(&block_hash[..8]),
                        );
                    }
                    return Err(format!("U.4: execute_reorg failed: {}", e));
                }
            };

            info!(
                "   reorg done: rolled_back={}, applied={}, txs_reinjected={}, txs_discarded={}",
                outcome.rolled_back, outcome.applied,
                outcome.txs_reinjected, outcome.txs_discarded,
            );

            // execute_reorg already applied all to_apply blocks (including
            // the one we just accepted). Now remove those txs from mempool
            // in case any had slipped in between rollback and apply.
            let confirmed: Vec<[u8; 32]> = block.transactions.iter().map(|t| t.txid()).collect();
            mempool.remove_confirmed(&confirmed);
            store.put_meta("tip_hash", &new_tip).ok();
        }

        Disposition::Unexpected => {
            warn!(
                "U.4: unexpected selected-tip transition during accept of block h={} \
                 (old={:?}, new={:?}, block={})",
                block.height, old_selected_tip, new_selected_tip, hex::encode(&block_hash[..8])
            );
            // Refuse to mutate state on an unexpected transition.
            // CONSENSUS-HALT FIX: previously the block stayed in the DAG
            // (and was persisted) while UTXO state was left untouched — the
            // same DAG-vs-UTXO divergence as the refused-reorg case. Roll
            // the in-memory insertion back and reject, so a re-submission
            // can be classified cleanly later.
            dag.write().remove_block(&block_hash);
            return Err(format!(
                "U.4: unexpected selected-tip transition (old={:?}, new={:?}); block {} rejected",
                old_selected_tip, new_selected_tip, hex::encode(&block_hash[..8]),
            ));
        }
    }

    // CONSENSUS-HALT FIX: the DAG entry is persisted only NOW, after the
    // disposition above has been applied successfully. Every refusal path
    // above rolled the in-memory insertion back and returned Err, so CF_DAG
    // can never adopt a fork tip whose chain state was refused.
    if let Some(ddata) = dag.read().get_block_data(&block_hash).cloned() {
        // Sprint Y (M-2): atomic put to CF_DAG + CF_DAG_INTEGRITY.
        // Phase 1: when the reachability index is maintained, fold its delta
        // (which may span several blocks if this insert triggered a reindex)
        // into the SAME WriteBatch, so a crash here leaves CF_DAG and
        // CF_REACHABILITY consistent all-or-nothing. Live Legacy: unchanged.
        if dag.read().maintains_reachability_index() {
            let (upserts, removals) = dag.write().reach_take_delta();
            store.put_dag_with_integrity_and_reach(&block_hash, &ddata, &upserts, &removals).ok();
        } else {
            store.put_dag_with_integrity(&block_hash, &ddata).ok();
        }
    }

    // ── Update node state ────────────────────────────────────────────
    {
        let mut s = node_state.write();
        s.tip_blue_score = dag.read().tip_blue_score();
        s.block_count    = dag.read().block_count() as u64;
        s.mempool_size   = mempool.size();
    }
    info!("✓ block h={} accepted", height);

    // ── Update finality checkpoint ───────────────────────────────────
    // Once tip is CHECKPOINT_DEPTH ahead, finalize everything below.
    // NOTE: this MUST be the selected tip's *height*, not tip_blue_score().
    // finalized_height is compared against block.height at the finality gate
    // above; feeding it blue_score (which runs ahead of height by the DAG
    // width) makes the node "finalize" a height above its own tip once the
    // skew exceeds CHECKPOINT_DEPTH, permanently rejecting every
    // chain-extending block. Same height unit feeds the pruning block below.
    let tip_height = {
        let d = dag.read();
        d.selected_tip()
            .and_then(|h| d.get_block_data(&h).map(|data| data.height))
            .unwrap_or(0)
    };
    // [no-fork] Do not advance finality while mining through a stalled latch —
    // freezing finalized_height keeps a heavier chain able to reorg us back.
    if tip_height > core::CHECKPOINT_DEPTH
        && !FINALITY_FROZEN.load(std::sync::atomic::Ordering::Relaxed)
    {
        let new_finalized = tip_height - core::CHECKPOINT_DEPTH;
        let current_finalized = store.get_meta("finalized_height").ok().flatten()
            .and_then(|b| b.as_slice().try_into().ok().map(u64::from_le_bytes))
            .unwrap_or(0);
        if new_finalized > current_finalized {
            store.put_meta("finalized_height", &new_finalized.to_le_bytes()).ok();
        }
    }

    // ── Prune old block bodies ───────────────────────────────────────
    // Remove full block data beyond PRUNING_DEPTH (keeps height→hash, DAG, TX index)
    if ARCHIVE_MODE.load(std::sync::atomic::Ordering::Relaxed) {
        // Archival node: keep everything. Logged once per prune window so an
        // operator can see the choice is in effect rather than inferring it.
        if tip_height % 10_000 == 0 {
            info!("archival mode: retaining ALL block bodies (h={}); pruning disabled", tip_height);
        }
    } else if tip_height > core::PRUNING_DEPTH {
        let prune_below = tip_height - core::PRUNING_DEPTH;
        let last_pruned = store.pruned_height();
        if prune_below > last_pruned + 1000 { // batch: prune every 1000 blocks
            match store.prune_blocks_below(prune_below) {
                Ok(n) if n > 0 => info!("Pruned {} block bodies below h={}", n, prune_below),
                Err(e)         => warn!("Prune failed: {}", e),
                _ => {}
            }
        }
    }

    // ── Sprint 2.c: emit TipChanged if the selected tip moved ────────
    //
    // This hook runs regardless of how the block got here (network
    // gossipsub, stratum submit, orphan resurrection, miner loop —
    // miner loop has its own inline hook because it doesn't route
    // through this function). If `tip_tx` is None (no subscriber or
    // unit test) the work is skipped entirely.
    //
    // Semantics of TipChanged fields: describe the CURRENT tip
    // (post-accept). Stratum consumers use this + dag.tips() +
    // current_bits to build a fresh template for the NEXT block.
    if let Some(tip_tx) = tip_tx {
        let new_tip = { dag.read().selected_tip() };
        if new_tip != old_tip {
            if let Some(tip_hash) = new_tip {
                let d = dag.read();
                if let Some(data) = d.get_block_data(&tip_hash).cloned() {
                    let tips_parents: Vec<[u8; 32]> = d.tips();
                    drop(d);

                    let bits = store.get_meta("current_bits").ok().flatten()
                        .and_then(|b| b.as_slice().try_into().ok().map(u32::from_le_bytes))
                        .unwrap_or(0x1d00ffff_u32);

                    // send() returns Err(SendError) iff there are 0
                    // receivers — we intentionally ignore that case
                    // since stratum might not be running.
                    let _ = tip_tx.send(stratum::TipChanged {
                        hash:       tip_hash,
                        height:     data.height,
                        blue_score: data.blue_score,
                        parents:    tips_parents,
                        bits,
                    });
                }
            }
        }
    }

    Ok(block_hash)
}

/// Blue_work-VERIFIED IBD release — the ONLY path that clears `is_syncing`.
///
/// Phase-2 sync-negotiation invariant: announced blue_score NEVER releases the
/// latch (a peer can lie). We clear IBD only when, computed locally from the
/// DAG: (1) the frontier is reconciled — we `has_block` every connected peer's
/// advertised tip AND nothing is in flight — AND (2) our selected-tip
/// `blue_work` is at least the greatest locally-verified `blue_work` reachable
/// from a connected peer (`servable_blue_work`). Tips we cannot verify against
/// our own DAG contribute 0, so unbacked high announcements cannot gate release.
///
/// Lock order (must match every other call-site): dag → peer_state → frontier
/// → node_state. All read locks drop before node_state.write().
fn maybe_release_ibd(
    dag:        &Arc<RwLock<consensus::GhostDAG>>,
    peer_state: &Arc<sync::peer_state::PeerStateTable>,
    frontier:   &Arc<parking_lot::Mutex<sync::frontier::FrontierState>>,
    node_state: &Arc<RwLock<rpc::NodeState>>,
) {
    let (our_work, our_score, servable, reconciled, have_frontier) = {
        let d = dag.read();
        let selected = d.selected_tip().and_then(|h| d.get_node(&h));
        let our_work = selected.as_ref().map(|n| n.blue_work).unwrap_or(0);
        let our_score = selected.as_ref().map(|n| n.blue_score).unwrap_or(0);
        let servable = peer_state.servable_blue_work(|h| d.get_node(h).map(|n| n.blue_work));
        let advertised = peer_state.connected_advertised_tips();
        let have_frontier = !advertised.is_empty();
        // Frontier lock taken into a local guard (lock order dag→peer_state→
        // frontier→node_state); compute outstanding + reconciled, drop before write.
        let fr = frontier.lock();
        let outstanding = fr.outstanding();
        let reconciled = sync::frontier::reconciled(
            &advertised, |h| d.has_block(h), outstanding, |h| fr.is_abandoned(h),
        );
        drop(fr);
        (our_work, our_score, servable, reconciled, have_frontier)
    };
    let best_announced = peer_state.best_announced_blue_score();
    // Release the IBD latch on the FIRST of two signals (both backstopped by the
    // 90s mine-through valve, so neither can freeze the miner):
    //  (A) VERIFIED / griefer-proof: we hold every advertised tip (or it is
    //      abandoned-as-unreachable, per Fix #1) AND our selected chain is at
    //      least the best VERIFIED reachable work. Gated on `have_frontier` so an
    //      empty advertised set cannot vacuously release us mid-catch-up.
    //  (B) LAG / mining-lag tolerant: our selected tip is within IBD_EXIT_LAG
    //      blue_score of the best ANNOUNCED tip — normal operation, not a bulk
    //      backlog. This is what lets a trailing MINER keep mining (leapfrog)
    //      instead of freezing as a pure follower: the canary proved the strict
    //      verified gate (A) never completes while a peer mines continuously (the
    //      chased frontier keeps moving). Announced score is UNTRUSTED and only
    //      ever RELEASES here (never blocks); a lying high-announce peer keeps us
    //      out of (A)+(B) and we fall back to the 90s throttled mine-through — it
    //      can never freeze us and never fakes a completion during a real backlog.
    let verified  = have_frontier && reconciled && our_work >= servable;
    let caught_up = our_score.saturating_add(sync::IBD_EXIT_LAG) >= best_announced;
    if verified || caught_up {
        let mut s = node_state.write();
        if s.is_syncing {
            s.is_syncing = false;
            info!("IBD complete (verified={} caught_up={}; score {} best_announced {}; work {} servable {})",
                verified, caught_up, our_score, best_announced, our_work, servable);
        }
    }
}

/// After accepting a block, check if any orphans can now be processed.
/// Recursively processes orphans whose parents become available.
fn process_orphans(
    accepted_hash: [u8; 32],
    orphans:       &mut std::collections::HashMap<[u8; 32], (core::Block, Vec<u8>, u64)>,
    waiting_for:   &mut std::collections::HashMap<[u8; 32], HashSet<[u8; 32]>>,
    dag:           &Arc<RwLock<consensus::GhostDAG>>,
    store:         &Arc<storage::Storage>,
    mempool:       &Arc<mempool::Mempool>,
    node_state:    &Arc<RwLock<rpc::NodeState>>,
    // Sprint 2.c: propagate tip broadcast through orphan resurrection.
    tip_tx:        Option<&broadcast::Sender<stratum::TipChanged>>,
    shielded:      &Arc<RwLock<crate::coherence::ShieldedPool>>,
) {
    // Collect orphans waiting for the accepted block
    let candidates: Vec<[u8; 32]> = waiting_for.remove(&accepted_hash)
        .unwrap_or_default()
        .into_iter()
        .collect();

    for orphan_hash in candidates {
        let all_parents_present = orphans.get(&orphan_hash)
            .map(|(b, _, _)| b.header.parents.iter().all(|p| dag.read().has_block(p)))
            .unwrap_or(false);

        if !all_parents_present { continue; }

        // Remove from orphan pool
        if let Some((block, _block_data, height)) = orphans.remove(&orphan_hash) {
            // Clean up waiting_for entries for this orphan
            for p in &block.header.parents {
                if let Some(set) = waiting_for.get_mut(p) {
                    set.remove(&orphan_hash);
                    if set.is_empty() { waiting_for.remove(p); }
                }
            }

            match accept_block(&block, orphan_hash, height, dag, store, mempool, node_state, tip_tx, shielded) {
                Ok(hash) => {
                    info!("✓ orphan h={} accepted (pool={})", height, orphans.len());
                    // Recursively process orphans waiting for THIS block
                    process_orphans(hash, orphans, waiting_for, dag, store, mempool, node_state, tip_tx, shielded);
                }
                Err(e) => {
                    warn!("orphan h={} rejected: {}", height, e);
                }
            }
        }
    }
}

// ── Unified TX validation ────────────────────────────────────────────────────
// FIX #10: Single validation core used by all code paths.

/// Core input validation logic shared by all TX validation paths.
/// Resolves each input's UTXO, checks pubkey hash match, verifies ML-DSA-65
/// signature, and accumulates total input value.
fn validate_tx_inputs(
    tx:           &core::Transaction,
    utxo_lookup:  &dyn Fn(&[u8; 32], u32) -> Result<Option<core::TxOutput>, String>,
    mut spent_set: Option<&mut HashSet<([u8; 32], u32)>>,
) -> Result<u64, String> {
    let mut total_in = 0u64;

    for (i, inp) in tx.inputs.iter().enumerate() {
        let outpoint = (inp.prev_txid, inp.prev_index);

        // FIX #9: Check for double-spend within the same validation context
        if let Some(spent) = spent_set.as_ref() {
            if spent.contains(&outpoint) {
                return Err(format!("double-spend: {}:{} already consumed",
                    hex::encode(&inp.prev_txid[..8]), inp.prev_index));
            }
        }

        // Resolve UTXO
        let utxo = utxo_lookup(&inp.prev_txid, inp.prev_index)?
            .ok_or_else(|| format!("UTXO {}:{} not found",
                hex::encode(&inp.prev_txid[..8]), inp.prev_index))?;

        total_in = total_in.checked_add(utxo.value).ok_or("input overflow")?;

        // Parse and verify script_sig
        let (sig, pk) = core::Transaction::parse_script_sig(&inp.script_sig)
            .ok_or_else(|| format!("malformed script_sig at input {}", i))?;

        // Verify pubkey hash matches UTXO script_pubkey
        let pk_hash = {
            use sha3::{Sha3_256, Digest};
            Sha3_256::digest(&pk)[..20].to_vec()
        };
        if pk_hash != utxo.script_pubkey {
            return Err(format!("pubkey mismatch at input {}", i));
        }

        // Verify hybrid ML-DSA-65 ‖ Falcon-1024 signature. Chain-id (Roadmap #8)
        // is the node-level single source of truth — miner and validator share it
        // (see core::node_chain_id / set_node_chain_id).
        let sighash = tx.sighash(i, core::node_chain_id());
        if !crypto::verify(&pk, &sighash, &sig) {
            return Err(format!("invalid signature at input {}", i));
        }

        // Mark outpoint as spent
        if let Some(spent) = spent_set.as_mut() {
            spent.insert(outpoint);
        }
    }

    let total_out: u64 = tx.outputs.iter()
        .try_fold(0u64, |acc, o| acc.checked_add(o.value))
        .ok_or("output sum overflow")?;
    if total_in < total_out {
        return Err(format!("inputs {} < outputs {}", total_in, total_out));
    }
    Ok(total_in - total_out)
}

/// Validate a transaction within a block context.
/// Uses both in-block outputs and persistent UTXO set, with double-spend tracking.
fn validate_tx_in_block(
    block:          &core::Block,
    tx:             &core::Transaction,
    store:          &Arc<storage::Storage>,
    spent_in_block: &mut HashSet<([u8; 32], u32)>,
) -> Result<(), String> {
    validate_tx_in_block_with_maturity(block, tx, store, spent_in_block, 0)?;
    Ok(())
}

/// FIX VULN-03: Validate TX within a block, including coinbase maturity check.
/// Returns the fee (total_in - total_out) for coinbase value validation.
fn validate_tx_in_block_with_maturity(
    block:          &core::Block,
    tx:             &core::Transaction,
    store:          &Arc<storage::Storage>,
    spent_in_block: &mut HashSet<([u8; 32], u32)>,
    current_height: u64,
) -> Result<u64, String> {
    // Build lookup map from block's own transaction outputs
    let block_utxos: std::collections::HashMap<([u8; 32], u32), core::TxOutput> = block.transactions
        .iter()
        .flat_map(|t| {
            let txid = t.txid();
            t.outputs.iter().enumerate().map(move |(i, o)| ((txid, i as u32), o.clone()))
        })
        .collect();

    // Coinbase maturity check (VULN-03). Single source of truth in
    // core::check_coinbase_maturity; this call site is one of two.
    core::check_coinbase_maturity(tx, current_height, |txid| {
        store.get_coinbase_height(txid).ok().flatten()
    })?;

    let lookup = |txid: &[u8; 32], idx: u32| -> Result<Option<core::TxOutput>, String> {
        if let Some(out) = block_utxos.get(&(*txid, idx)) {
            return Ok(Some(out.clone()));
        }
        store.get_utxo(txid, idx).map_err(|e| e.to_string())
    };

    validate_tx_inputs(tx, &lookup, Some(spent_in_block))
}

/// Standalone tx validation (for mempool / sendrawtransaction).
/// Returns the fee (total_in - total_out).
/// Also checks coinbase maturity (VULN-03).
fn validate_tx_standalone(
    tx:    &core::Transaction,
    store: &Arc<storage::Storage>,
    current_height: u64,
) -> Result<u64, String> {
    // Coinbase maturity check
    if current_height > 0 {
        for (i, inp) in tx.inputs.iter().enumerate() {
            if let Ok(Some(cb_height)) = store.get_coinbase_height(&inp.prev_txid) {
                let depth = current_height.saturating_sub(cb_height);
                if depth < core::COINBASE_MATURITY {
                    return Err(format!(
                        "coinbase maturity: input {} needs {} more confirmations",
                        i, core::COINBASE_MATURITY - depth
                    ));
                }
            }
        }
    }
    let lookup = |txid: &[u8; 32], idx: u32| -> Result<Option<core::TxOutput>, String> {
        store.get_utxo(txid, idx).map_err(|e| e.to_string())
    };
    validate_tx_inputs(tx, &lookup, None)
}
// v0.2.0 PoI
// v0.2.1 reconnect
// v0.2.2 ws+pex
// v0.2.2 ws+pex
// v0.2.3 block-debug
// v0.2.4 height-fix
// v0.2.5 tx-rebroadcast
// v0.2.6 peer-count
// v0.2.7 utxo-reindex
// v0.2.8 dag-reindex
// v0.2.9 topo-sort
// v0.3.0 getpeers
// v0.3.0 getpeers
// v0.3.1 utxo-fix
// v0.3.2 balance-fix
// v0.3.3 recentblocks

// ─────────────────────────────────────────────────────────────────────────────
// Audit H2 regression tests — external-submission structural gate.
//
// The vulnerability: the stratum accept_block_cb handed miner-submitted
// blocks straight to `accept_block`, which checks bits/height/timestamp/tx
// validity but NOT `Block::validate_structure()` (Module-SIS PoW witness,
// merkle binding, coinbase format). A block with no SIS witness therefore
// passed the stratum path while the gossipsub and RPC paths rejected it.
//
// These tests build the callbacks through the same builders `main()` uses,
// so they exercise the real submission closures, not a re-implementation.
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod external_submission_tests {
    use super::*;
    use tempfile::TempDir;

    fn unix_now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    struct TestNode {
        _tmp:       TempDir,
        dag:        Arc<RwLock<consensus::GhostDAG>>,
        store:      Arc<storage::Storage>,
        mempool:    Arc<mempool::Mempool>,
        node_state: Arc<RwLock<rpc::NodeState>>,
        shielded:   Arc<RwLock<crate::coherence::ShieldedPool>>,
        otx:        mpsc::Sender<network::NetworkMessage>,
        // Keep the receiver alive so post-accept broadcasts don't error.
        _orx:       mpsc::Receiver<network::NetworkMessage>,
        tip_tx:     broadcast::Sender<stratum::TipChanged>,
    }

    impl TestNode {
        fn stratum_cb(&self) -> Arc<stratum::AcceptBlockFn> {
            make_stratum_accept_block_cb(
                self.dag.clone(), self.store.clone(), self.mempool.clone(),
                self.node_state.clone(), self.shielded.clone(),
                self.otx.clone(), self.tip_tx.clone(),
            )
        }
        fn rpc_cb(&self) -> Arc<rpc::SubmitBlockFn> {
            make_rpc_submit_block_cb(
                self.dag.clone(), self.store.clone(), self.mempool.clone(),
                self.node_state.clone(), self.shielded.clone(),
                self.otx.clone(), self.tip_tx.clone(),
            )
        }
    }

    fn mk_coinbase(height: u64, value: u64) -> core::Transaction {
        core::Transaction {
            version: 1,
            inputs: vec![core::TxInput {
                prev_txid:  [0u8; 32],
                prev_index: u32::MAX,
                script_sig: format!("height:{}", height).into_bytes(),
                sequence:   u32::MAX,
            }],
            outputs: vec![core::TxOutput {
                value,
                script_pubkey: vec![0xAB; 20],
            }],
            locktime: 0,
        }
    }

    /// Fixture genesis. Deliberately NOT structurally valid (no SIS witness) —
    /// `accept_block` never re-validates ancestors, it only needs the genesis
    /// present in the DAG (for height/parent checks) and in storage (for the
    /// height-0 timestamp that seeds ASERT). The timestamp is "now" so ASERT
    /// eases difficulty for block 1, keeping the mined-block test fast.
    fn mk_genesis(ts: u64) -> core::Block {
        core::Block {
            header: core::BlockHeader {
                version:     1,
                parents:     vec![],
                merkle_root: core::MerkleRoot::ZERO,
                timestamp:   ts,
                bits:        core::GENESIS_BITS,
                nonce:       0,
            },
            transactions: vec![mk_coinbase(0, 0)],
            blue_score: 0,
            height: 0,
            pow_solution: Vec::new(),
            shielded_transactions: Vec::new(),
        }
    }

    fn node_with_genesis(genesis: &core::Block) -> TestNode {
        let tmp   = TempDir::new().expect("tempdir");
        let store = Arc::new(storage::Storage::open(&tmp.path().join("db")).expect("storage"));
        let dag   = Arc::new(RwLock::new(consensus::GhostDAG::with_default_k()));

        let gh = genesis.block_hash();
        store.put_block(genesis).expect("store genesis");
        dag.write().add_genesis(gh, genesis.header.timestamp);

        let (otx, orx) = mpsc::channel::<network::NetworkMessage>(64);
        let (tip_tx, _) = broadcast::channel::<stratum::TipChanged>(8);

        TestNode {
            _tmp: tmp,
            dag,
            store,
            mempool:    Arc::new(mempool::Mempool::new()),
            node_state: Arc::new(RwLock::new(rpc::NodeState::default())),
            shielded:   Arc::new(RwLock::new(crate::coherence::ShieldedPool::new())),
            otx,
            _orx: orx,
            tip_tx,
        }
    }

    /// Build a height-1 child of the fixture genesis that satisfies every
    /// check `accept_block` performs (bits, height, finality, timestamp,
    /// coinbase value). With `mine == false` the block carries NO Module-SIS
    /// witness and a stale merkle root, so it fails `validate_structure()`
    /// while still being acceptable to `accept_block` — exactly the H2 gap.
    /// With `mine == true` a real SIS witness is mined (k = 4 regime below
    /// the SF-1 activation height) and the merkle root is binding.
    fn mk_child(node: &TestNode, genesis: &core::Block, mine: bool) -> core::Block {
        let gh = genesis.block_hash();
        let parent_ts = node.store.get_timestamp_at_height(0)
            .expect("ts read").expect("genesis ts present");
        let bits = pow::next_bits(
            core::GENESIS_BITS, core::GENESIS_TIMESTAMP, parent_ts, 1,
        );
        let subsidy = core::tokenomics_v2::block_subsidy_sat(1);
        assert_eq!(
            core::tokenomics_v2::founder_vesting_delta_sat(1), 0,
            "fixture assumes no founder vesting output at height 1",
        );

        let all_txs = vec![mk_coinbase(1, subsidy)];
        let merkle  = core::Transaction::merkle_root(&all_txs);

        let mut block = core::Block {
            header: core::BlockHeader {
                version:     1,
                parents:     vec![gh],
                merkle_root: if mine { merkle } else { core::MerkleRoot::ZERO },
                timestamp:   parent_ts + 30,
                bits,
                nonce:       0,
            },
            transactions: all_txs,
            blue_score: 1,
            height: 1,
            pow_solution: Vec::new(),
            shielded_transactions: Vec::new(),
        };

        if mine {
            let preimage = block.header.pow_preimage();
            let (nonce, solution) =
                pow::mine_sis_pow(&preimage, bits, block.height, 0, 50_000_000)
                    .expect("SIS solve within attempt budget");
            block.header.nonce  = nonce;
            block.pow_solution  = solution.to_vec();
            assert!(
                block.validate_structure().is_ok(),
                "mined fixture block must be structurally valid",
            );
        } else {
            assert!(
                block.validate_structure().is_err(),
                "fixture block must fail validate_structure",
            );
        }
        block
    }

    /// H2 regression: a block with NO Module-SIS witness (and a non-binding
    /// merkle root) must be rejected by the stratum accept_block_cb BEFORE it
    /// reaches the DAG/storage. Without the structural gate in
    /// `make_stratum_accept_block_cb` this block is fully accepted (it passes
    /// every check `accept_block` makes) and this test fails.
    #[tokio::test(flavor = "multi_thread")]
    async fn stratum_accept_block_cb_rejects_structure_invalid_block() {
        let genesis = mk_genesis(unix_now());
        let node = node_with_genesis(&genesis);
        let bad = mk_child(&node, &genesis, false);

        let res = (node.stratum_cb())(bad);
        assert!(
            res.is_err(),
            "H2: stratum accept_block_cb must reject a block that fails \
             validate_structure, got acceptance: {:?}", res,
        );
        let msg = res.unwrap_err();
        assert!(
            msg.contains("structural validation"),
            "rejection must come from the structural gate, got: {}", msg,
        );
        // Nothing may have leaked into consensus state.
        assert_eq!(node.dag.read().block_count(), 1, "DAG must contain only genesis");
    }

    /// The stratum and RPC submission gates must agree: both reject the same
    /// structurally-invalid block with the same error shape.
    #[tokio::test(flavor = "multi_thread")]
    async fn stratum_and_rpc_submit_agree_on_structure_invalid_block() {
        let genesis = mk_genesis(unix_now());
        let node_a = node_with_genesis(&genesis);
        let node_b = node_with_genesis(&genesis);
        let bad = mk_child(&node_a, &genesis, false);

        let stratum_err = (node_a.stratum_cb())(bad.clone()).unwrap_err();
        let rpc_err     = (node_b.rpc_cb())(bad).unwrap_err();

        assert!(stratum_err.contains("structural validation"), "stratum: {}", stratum_err);
        assert!(rpc_err.contains("structural validation"),     "rpc: {}",     rpc_err);
        assert_eq!(node_a.dag.read().block_count(), 1);
        assert_eq!(node_b.dag.read().block_count(), 1);
    }

    /// Positive control: a genuinely mined block (real SIS witness, binding
    /// merkle) is accepted by BOTH the stratum callback and the RPC
    /// submitblock callback (each against its own fresh node sharing the same
    /// genesis), proving the added gate does not over-reject.
    #[tokio::test(flavor = "multi_thread")]
    async fn stratum_and_rpc_submit_agree_on_valid_block() {
        let genesis = mk_genesis(unix_now());
        let node_a = node_with_genesis(&genesis);
        let node_b = node_with_genesis(&genesis);
        let good = mk_child(&node_a, &genesis, true);

        let stratum_res = (node_a.stratum_cb())(good.clone());
        assert!(stratum_res.is_ok(), "stratum must accept a valid block: {:?}", stratum_res);
        assert_eq!(node_a.dag.read().block_count(), 2);

        let rpc_res = (node_b.rpc_cb())(good);
        assert!(rpc_res.is_ok(), "rpc submitblock must accept a valid block: {:?}", rpc_res);
        assert_eq!(node_b.dag.read().block_count(), 2);
    }

    // ── CONSENSUS-HALT regression (DAG-vs-UTXO ordering) ────────────────────
    //
    // Drive the REAL `accept_block` pipeline (add_block → disposition →
    // execute_reorg) — NOT a synthetic ReorgPlan — with an attacker fork
    // whose accumulated blue_work beats the live chain but whose reorg depth
    // exceeds reorg::MAX_REORG_DEPTH. On the unfixed baseline the flipping
    // fork block is inserted + persisted into the DAG BEFORE the depth cap
    // runs; the refusal then leaves selected_tip() pinned to the fork
    // forever, freezing the real chain (durable halt).

    /// Submit a block through the real `accept_block` pipeline. This is the
    /// exact function the stratum/RPC callbacks delegate to; those wrappers
    /// only add the H2 `validate_structure()` pre-gate, which is orthogonal
    /// to the consensus ordering under test and would force mining a real
    /// SIS witness for every fixture block.
    fn accept(node: &TestNode, block: &core::Block) -> Result<[u8; 32], String> {
        accept_block(
            block, block.block_hash(), block.height,
            &node.dag, &node.store, &node.mempool, &node.node_state,
            Some(&node.tip_tx), &node.shielded,
        )
    }

    /// Build an H2-fixture-style (structurally lax) child of `parent` at
    /// `height` that satisfies every check `accept_block` performs (bits,
    /// height, finality, timestamp, coinbase value). The merkle root is
    /// ZERO for these fixtures, so `nonce` is what differentiates
    /// same-position blocks on competing chains (block_hash covers it).
    fn mk_block_at(
        node: &TestNode,
        parent: [u8; 32],
        height: u64,
        ts: u64,
        nonce: u64,
    ) -> core::Block {
        let parent_ts = node.store.get_timestamp_at_height(height - 1)
            .expect("ts read").expect("parent-height timestamp present");
        let bits = pow::next_bits(
            core::GENESIS_BITS, core::GENESIS_TIMESTAMP, parent_ts, height,
        );
        let subsidy = core::tokenomics_v2::block_subsidy_sat(height);
        assert_eq!(
            core::tokenomics_v2::founder_vesting_delta_sat(height), 0,
            "fixture assumes no founder vesting output at h={}", height,
        );
        core::Block {
            header: core::BlockHeader {
                version:     1,
                parents:     vec![parent],
                merkle_root: core::MerkleRoot::ZERO,
                timestamp:   ts,
                bits,
                nonce,
            },
            transactions: vec![mk_coinbase(height, subsidy)],
            blue_score: height,
            height,
            pow_solution: Vec::new(),
            shielded_transactions: Vec::new(),
        }
    }

    /// Acceptance regression for the DAG-vs-UTXO ordering halt.
    ///
    /// FAILS on baseline cad723c (tip poisoned by the refused fork; real
    /// chain frozen as ForkLoser), PASSES with the fix (GhostDAG undo +
    /// deferred CF_DAG persist).
    #[tokio::test(flavor = "multi_thread")]
    async fn refused_deep_reorg_must_not_poison_dag_selected_tip() {
        let d = reorg::MAX_REORG_DEPTH;
        assert!(
            d <= 16,
            "this regression builds chains of length MAX_REORG_DEPTH+2 through \
             the real accept path; keep the cfg(test) cap small (got {})", d,
        );

        let g_ts    = unix_now();
        let genesis = mk_genesis(g_ts);
        let node    = node_with_genesis(&genesis);
        let gh      = genesis.block_hash();

        // (a) Real chain R: genesis → r1 … r_{D+1}, all through accept_block.
        let mut parent = gh;
        for i in 1..=(d + 1) {
            let b = mk_block_at(&node, parent, i, g_ts + 30 * i, i);
            accept(&node, &b).expect("real-chain block must be accepted");
            parent = b.block_hash();
        }
        let real_tip = parent;
        assert_eq!(
            node.dag.read().selected_tip(), Some(real_tip),
            "sanity: R's head is the selected tip before the attack",
        );

        // (b) Attacker fork F branching at genesis: f1 … f_{D+2}, same
        // per-height timestamps as R (so expected bits — hence per-block
        // work — match per height) but distinct nonces (distinct hashes).
        // The fork block at height D+1 TIES R's tip on blue_work; grind its
        // nonce so its hash LOSES the deterministic tie-break (blue_work,
        // then blue_score, then lexicographic hash — larger wins) and stays
        // a fork-loser. The flip then happens deterministically at f_{D+2},
        // which strictly out-weighs R and forces to_rollback.len() == D+1 > D.
        let mut fparent = gh;
        let mut flip_res: Result<[u8; 32], String> = Err("unreached".into());
        for i in 1..=(d + 2) {
            let mut nonce = 1_000_000 + i;
            let mut fb = mk_block_at(&node, fparent, i, g_ts + 30 * i, nonce);
            if i == d + 1 {
                while fb.block_hash() >= real_tip {
                    nonce += 1;
                    fb = mk_block_at(&node, fparent, i, g_ts + 30 * i, nonce);
                }
            }
            let res = accept(&node, &fb);
            if i <= d + 1 {
                assert!(
                    res.is_ok(),
                    "non-flipping fork block f{} must be accepted as a \
                     fork-loser, got: {:?}", i, res,
                );
                assert_eq!(
                    node.dag.read().selected_tip(), Some(real_tip),
                    "fork-loser f{} must not move the selected tip", i,
                );
            }
            fparent = fb.block_hash();
            flip_res = res;
        }

        // (1) The flipping fork block is REFUSED by the reorg depth cap.
        let err = flip_res.expect_err(
            "over-deep flipping fork block must be rejected by accept_block",
        );
        assert!(
            err.contains(reorg::ERR_REORG_DEPTH),
            "rejection must be the depth-cap refusal, got: {}", err,
        );

        // (2) HALT GUARD: the refusal must leave the DAG selected tip on the
        // real chain. Baseline fails HERE: add_block already adopted (and
        // persisted) the fork tip before execute_reorg refused.
        assert_eq!(
            node.dag.read().selected_tip(), Some(real_tip),
            "refused deep reorg must NOT poison the DAG selected tip",
        );

        // (3) LIVENESS GUARD: a further legitimate extension of the real
        // chain is still accepted AND applied. Baseline fails here too: with
        // the tip pinned to the poison fork, R_next is misclassified and the
        // applied chain state never advances.
        let r_next = mk_block_at(
            &node, real_tip, d + 2, g_ts + 30 * (d + 2), 424_242,
        );
        let r_next_hash = r_next.block_hash();
        let res = accept(&node, &r_next);
        assert!(
            res.is_ok(),
            "legitimate extension of the real chain must still be accepted \
             after the refused fork, got: {:?}", res,
        );
        assert_eq!(
            node.dag.read().selected_tip(), Some(r_next_hash),
            "real chain must re-take / keep the selected tip",
        );
        let tip_meta = node.store.get_meta("tip_hash")
            .expect("meta read").expect("tip_hash meta present");
        assert_eq!(
            tip_meta.as_slice(), &r_next_hash[..],
            "applied chain state (tip_hash meta / UTXO apply) must advance \
             with the real chain",
        );
    }
}
