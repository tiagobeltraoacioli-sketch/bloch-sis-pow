//! bloch-pool-miner — trivial reference CPU miner for the pool's
//! SIS-native stratum dialect. Exists to (a) document the miner side of
//! the protocol in runnable code and (b) smoke-test the pool.
//!
//! It is the same brute-force search the node's solo miner runs
//! (`bloch_sis_pow::solver::mine`), pointed at the pool's SHARE target
//! instead of the block target, over the session's assigned nonce range.
//!
//! Flow:
//!   connect → mining.subscribe (get nonce_base + ownership challenge)
//!   → mining.authorize [address, "x", pubkey_hex, signature_hex]
//!     (the pool requires proving control of the payout address by
//!     default: pass --auth-seed so the miner can derive the wallet
//!     keypair and sign "bloch-pool-authorize-v1" ‖ challenge)
//!   → receive mining.set_difficulty [share_bits] + mining.notify
//!     [job_id, preimage_hex, block_bits_hex, height, clean]
//!   → mine in short bursts, polling the socket between bursts
//!   → mining.submit [address, job_id, nonce_hex, solution_hex]

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;

use clap::Parser;
use serde_json::{json, Value};

use bloch_sis_pow::solver::{mine, MineConfig};
use bloch_sis_pow::{bits_to_target, MineError, Target};

#[derive(Parser, Debug)]
#[command(name = "bloch-pool-miner", about = "Reference CPU miner for bloch-pool (testing)")]
struct Cli {
    /// Pool stratum address.
    #[arg(long, default_value = "127.0.0.1:3335")]
    pool: String,

    /// Your payout address (bloch1q… / bloch1t…). Shares are credited to it.
    #[arg(long)]
    address: String,

    /// Exit after this many accepted shares (0 = mine forever).
    #[arg(long, default_value = "0")]
    max_shares: u64,

    /// Candidate budget per mining burst (socket is polled between bursts).
    #[arg(long, default_value = "200000")]
    burst: u64,

    /// Wallet seed (hex, 32+ bytes) controlling --address. Used to
    /// derive the hybrid keypair and sign the pool's ownership
    /// challenge. Required unless the pool runs --no-auth-proof.
    #[arg(long)]
    auth_seed: Option<String>,

    /// Diversified-address index for --auth-seed (omit if --address is
    /// the seed's base address).
    #[arg(long)]
    auth_index: Option<u32>,
}

struct CurrentJob {
    id:       String,
    preimage: Vec<u8>,
    /// Height of the block this job mines — selects the residual-gate width
    /// (k=4 below the k=8 soft-fork activation height, k=8 at/above it) so the
    /// miner produces witnesses the node's height-aware `validate_pow` accepts.
    height:   u64,
}

fn send(stream: &mut TcpStream, v: Value) -> std::io::Result<()> {
    let mut line = v.to_string();
    line.push('\n');
    stream.write_all(line.as_bytes())
}

fn main() -> std::io::Result<()> {
    let cli = Cli::parse();

    println!("bloch-pool-miner: reference miner — coordination/testing only; \
              the coin is worth nothing by design. Solo mining (`bloch --mine`) \
              needs no pool.");

    // Derive the auth keypair up front (fail fast on a wrong seed).
    let auth_keys: Option<(Vec<u8>, Vec<u8>)> = match cli.auth_seed.as_deref() {
        None => None,
        Some(hexseed) => {
            let seed = hex::decode(hexseed).unwrap_or_else(|e| {
                eprintln!("--auth-seed must be hex: {}", e);
                std::process::exit(1);
            });
            let derived = match cli.auth_index {
                Some(i) => bloch_crypto::crypto::diversified_keypair(&seed, i),
                None    => bloch_crypto::crypto::generate_keypair_from_seed(&seed),
            };
            let (pk, sk) = derived.unwrap_or_else(|e| {
                eprintln!("keypair derivation failed: {}", e);
                std::process::exit(1);
            });
            // The derived key must actually BE the payout address, or
            // the pool will (correctly) refuse the proof.
            let addr = bloch_crypto::address::Address::parse(&cli.address)
                .unwrap_or_else(|e| {
                    eprintln!("--address is not a valid Bloch address: {}", e);
                    std::process::exit(1);
                });
            let derived_addr = bloch_crypto::crypto::address_from_pubkey(
                &pk, addr.is_testnet());
            if derived_addr != cli.address {
                eprintln!("--auth-seed derives {} but --address is {} \
                           (wrong seed or missing --auth-index?)",
                    derived_addr, cli.address);
                std::process::exit(1);
            }
            Some((pk, sk))
        }
    };

    let stream = TcpStream::connect(&cli.pool)?;
    stream.set_read_timeout(Some(Duration::from_millis(200)))?;
    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);

    send(&mut writer, json!({
        "id": 1, "method": "mining.subscribe", "params": ["bloch-pool-miner/0.1"]
    }))?;
    // authorize is sent once the subscribe response delivers the
    // ownership challenge (see below).

    let mut challenge: Option<Vec<u8>> = None;
    let mut sent_authorize = false;
    let mut nonce_base: u64 = 0;
    let mut nonce_cursor: u64 = 0;
    let mut share_target: Option<Target> = None;
    let mut job: Option<CurrentJob> = None;
    let mut accepted: u64 = 0;
    let mut submitted_id: u64 = 100;
    let mut line = String::new();

    loop {
        // ── Drain any pending server messages ─────────────────────
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => {
                    println!("pool closed the connection");
                    return Ok(());
                }
                Ok(_) => {
                    let msg: Value = match serde_json::from_str(line.trim()) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    handle_message(
                        &msg, &mut nonce_base, &mut nonce_cursor,
                        &mut share_target, &mut job, &mut accepted,
                        &mut challenge,
                    );
                    // Subscribe response seen → authorize (with the
                    // ownership proof when we hold the wallet seed).
                    if !sent_authorize && challenge.is_some() {
                        sent_authorize = true;
                        let mut params = vec![json!(cli.address), json!("x")];
                        if let Some((pk, sk)) = &auth_keys {
                            let mut m = b"bloch-pool-authorize-v1".to_vec();
                            m.extend_from_slice(challenge.as_ref().unwrap());
                            match bloch_crypto::crypto::sign(sk, &m) {
                                Ok(sig) => {
                                    params.push(json!(hex::encode(pk)));
                                    params.push(json!(hex::encode(sig)));
                                }
                                Err(e) => {
                                    eprintln!("signing the ownership challenge failed: {}", e);
                                    std::process::exit(1);
                                }
                            }
                        } else {
                            println!("no --auth-seed: authorizing WITHOUT ownership \
                                      proof (works only if the pool runs --no-auth-proof)");
                        }
                        send(&mut writer, json!({
                            "id": 2, "method": "mining.authorize", "params": params
                        }))?;
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
                           || e.kind() == std::io::ErrorKind::TimedOut => break,
                Err(e) => return Err(e),
            }
        }

        if cli.max_shares > 0 && accepted >= cli.max_shares {
            println!("reached {} accepted shares — exiting", accepted);
            return Ok(());
        }

        // ── Mine a burst on the current job ───────────────────────
        let (Some(target), Some(j)) = (share_target.as_ref(), job.as_ref()) else {
            std::thread::sleep(Duration::from_millis(100));
            continue;
        };

        let cfg = MineConfig {
            start_nonce:          nonce_cursor,
            candidates_per_nonce: 2048,
            max_total_attempts:   cli.burst,
            // Height-aware gate width: matches the node's consensus selection
            // (k=4 below the soft-fork activation height, k=8 at/above it).
            residual_coeffs:      bloch_crypto::core::canonical_residual_coeffs(j.height),
        };
        match mine(&j.preimage, target, &cfg, None) {
            Ok(found) => {
                nonce_cursor = found.nonce + 1;
                let sol_bytes = bloch_sis_pow::encode::encode_s(&found.solution)
                    .expect("mined solution must encode");
                submitted_id += 1;
                send(&mut writer, json!({
                    "id": submitted_id,
                    "method": "mining.submit",
                    "params": [
                        cli.address,
                        j.id,
                        format!("{:016x}", found.nonce),
                        hex::encode(sol_bytes),
                    ],
                }))?;
                println!("share found (job={} nonce={:x}, {} attempts) — submitted",
                    j.id, found.nonce, found.attempts);
            }
            Err(MineError::AttemptsExhausted) => {
                // Advance the cursor past exactly the nonces this burst
                // consumed (ceil; the candidate stream per nonce is
                // deterministic, so re-scanning a nonce is pure waste).
                let cpn = cfg.candidates_per_nonce.max(1);
                let nonces_scanned = (cli.burst + cpn - 1) / cpn;
                nonce_cursor = nonce_cursor.wrapping_add(nonces_scanned.max(1));
            }
            Err(e) => {
                eprintln!("miner error: {:?}", e);
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }
}

fn handle_message(
    msg:          &Value,
    nonce_base:   &mut u64,
    nonce_cursor: &mut u64,
    share_target: &mut Option<Target>,
    job:          &mut Option<CurrentJob>,
    accepted:     &mut u64,
    challenge:    &mut Option<Vec<u8>>,
) {
    // Response to subscribe (id 1):
    // [[..subs..], nonce_base_hex, 0, challenge_hex]
    if msg.get("id").and_then(|i| i.as_u64()) == Some(1) {
        if let Some(base_hex) = msg.pointer("/result/1").and_then(|v| v.as_str()) {
            *nonce_base = u64::from_str_radix(base_hex, 16).unwrap_or(0);
            *nonce_cursor = *nonce_base;
            println!("subscribed: nonce range starts at {:#x}", nonce_base);
        }
        *challenge = Some(
            msg.pointer("/result/3").and_then(|v| v.as_str())
                .and_then(|s| hex::decode(s).ok())
                .unwrap_or_default(),
        );
        return;
    }
    // Response to authorize (id 2).
    if msg.get("id").and_then(|i| i.as_u64()) == Some(2) {
        match msg.get("result").and_then(|r| r.as_bool()) {
            Some(true) => println!("authorized"),
            _ => {
                eprintln!("authorize rejected: {:?} (does this pool require \
                           an ownership proof? pass --auth-seed)", msg.get("error"));
                std::process::exit(1);
            }
        }
        return;
    }

    match msg.get("method").and_then(|m| m.as_str()) {
        Some("mining.set_difficulty") => {
            if let Some(bits) = msg.pointer("/params/0").and_then(|v| v.as_u64()) {
                println!("share difficulty: bits=0x{:08x}", bits as u32);
                *share_target = Some(bits_to_target(bits as u32));
            }
        }
        Some("mining.notify") => {
            let id = msg.pointer("/params/0").and_then(|v| v.as_str()).unwrap_or_default();
            let preimage_hex = msg.pointer("/params/1").and_then(|v| v.as_str()).unwrap_or_default();
            let height = msg.pointer("/params/3").and_then(|v| v.as_u64()).unwrap_or(0);
            let clean = msg.pointer("/params/4").and_then(|v| v.as_bool()).unwrap_or(true);
            if let Ok(preimage) = hex::decode(preimage_hex) {
                if preimage.len() == 76 {
                    println!("new job {} (height {}{})", id, height,
                        if clean { ", clean" } else { "" });
                    *job = Some(CurrentJob { id: id.to_string(), preimage, height });
                    // Only restart the nonce search on clean jobs (tip
                    // change). A periodic refresh keeps the cursor so
                    // the search keeps exploring its range instead of
                    // re-treading the low end forever.
                    if clean {
                        *nonce_cursor = *nonce_base;
                    }
                }
            }
        }
        _ => {
            // Response to a submit: result true = accepted.
            if msg.get("result").and_then(|r| r.as_bool()) == Some(true) {
                *accepted += 1;
                println!("share ACCEPTED ({} total)", accepted);
            } else if let Some(err) = msg.get("error") {
                if !err.is_null() {
                    eprintln!("share rejected: {}", err);
                }
            }
        }
    }
}
