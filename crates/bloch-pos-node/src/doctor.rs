// SPDX-License-Identifier: AGPL-3.0-or-later

//! `bloch-pos doctor` — the preflight a third-party operator runs BEFORE
//! starting a validator, and the first command to run when one misbehaves.
//!
//! ## Why this exists
//!
//! Until now every diagnosis on this fleet assumed someone who can SSH into
//! the box and read `node.log` — and most of the incidents this command
//! checks for were found exactly that way, late:
//!
//! - all 64 fleet nodes ran for weeks with their RPC bound to a routable
//!   interface (found 2026-08-30);
//! - a node's P2P egress was silently DROPped by leftover iptables rules —
//!   SSH and stratum reachable, every consensus port timing out — and hours
//!   went to suspecting consensus first (2026-08-07);
//! - a fresh full sync ran out of memory past 7.5 GiB on a box that looked
//!   fine at boot;
//! - a rolled-back VM clock is the cheapest way to defeat the
//!   weak-subjectivity boot decision (2026-08-31 audit), and nothing checked
//!   the clock until the node was already running.
//!
//! Each check below answers one of those with a PASS/WARN/FAIL line and the
//! action to take. **Everything here is node-local and read-only**: no check
//! changes consensus behaviour, writes to the data dir, or talks to the
//! network beyond dialing the peers the operator already configured (for a
//! clock sample) and the local RPC port (to summarize a running node).
//!
//! ## What this deliberately does NOT claim
//!
//! - **Inbound reachability.** Whether the internet can reach this node's
//!   P2P port depends on NAT and firewalls upstream of this host; no local
//!   check can prove it. The check reports the local bind state and says so.
//! - **A verdict on a clock with no peers.** With nobody to compare
//!   against, the clock check reports "no samples" rather than inventing
//!   confidence (same rule as the boot gate in `time_check`).

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::path::Path;
use std::time::Duration;

use crate::time_check;

/// Outcome of one check. `Skip` is honest absence ("nothing to check
/// against"), never a soft pass — the summary counts it separately.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    Warn,
    Fail,
    Skip,
}

impl Verdict {
    fn tag(self) -> &'static str {
        match self {
            Verdict::Pass => "PASS",
            Verdict::Warn => "WARN",
            Verdict::Fail => "FAIL",
            Verdict::Skip => "SKIP",
        }
    }
}

struct Report {
    fails: usize,
    warns: usize,
}

impl Report {
    fn new() -> Report {
        Report { fails: 0, warns: 0 }
    }

    fn add(&mut self, v: Verdict, area: &str, detail: &str) {
        match v {
            Verdict::Fail => self.fails += 1,
            Verdict::Warn => self.warns += 1,
            _ => {}
        }
        // One line per finding, grep-friendly, action inside the detail.
        println!("[{}] {area}: {detail}", v.tag());
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Thresholds — measured on this fleet, not guessed. Each constant cites its
// measurement; when the chain's history grows these need re-measuring, which
// is why they are constants with provenance and not magic numbers inline.
// ───────────────────────────────────────────────────────────────────────────

/// RAM a fresh full replay/sync of the mainnet history was measured to need:
/// a resync OOMed past ~7.5 GiB on 2026-08 mainnet history (the incident
/// that produced the "transplant the blocks.log instead" runbook). Warn
/// below this much AVAILABLE memory.
const SYNC_RAM_WARN_BYTES: u64 = 8 * 1024 * 1024 * 1024;
/// Below this, even steady-state operation is at risk; fail.
const SYNC_RAM_FAIL_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// Free disk under the data dir. The canonical blocks.log peaked around
/// 820 MB by 2026-08 and grows without pruning (`blocks` is unpruned by
/// design); 20 GiB keeps a year of headroom at current cadence.
const DISK_WARN_BYTES: u64 = 20 * 1024 * 1024 * 1024;
const DISK_FAIL_BYTES: u64 = 5 * 1024 * 1024 * 1024;

/// How long to wait for each network probe.
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
/// How long to wait for peer clock samples over libp2p (the transport takes
/// a moment to handshake before the time request can be answered).
const LIBP2P_CLOCK_WAIT: Duration = Duration::from_secs(10);

pub fn print_help() {
    println!(
        "bloch-pos doctor — preflight and diagnosis for a validator host.\n\
         \n\
         Checks, in order:\n\
         1. genesis manifest loads (when --genesis is given)\n\
         2. data dir: validator.key, signing history, blocks.log\n\
         3. disk space under the data dir\n\
         4. memory headroom against the measured full-sync requirement\n\
         5. clock skew against the configured peers (the boot gate's rule)\n\
         6. P2P: listen-port state and outbound reachability of each peer\n\
         7. RPC exposure: is the RPC port answering on a routable interface?\n\
         8. a running node's own health and validator status, via local RPC\n\
         \n\
         Usage: bloch-pos doctor [--data-dir <dir>] [--genesis <file>]\n\
                [--rpc-port <port>] [--rpc-bind <addr>]\n\
                [--peers a:p,b:p] [--p2p-peer <multiaddr,…>]\n\
                [--listen <port>] [--p2p-listen <multiaddr,…>]\n\
         \n\
         Pass the SAME flags you pass (or intend to pass) to `run`; every\n\
         flag is optional and a check with nothing to work on says SKIP.\n\
         Read-only and node-local: no consensus impact, nothing written.\n\
         Exit code: 0 = no failures (warnings possible), 1 = at least one FAIL."
    );
}

pub fn run(args: &[String]) -> i32 {
    let mut r = Report::new();
    let data_dir = crate::arg_value(args, "--data-dir");
    let genesis_path = crate::arg_value(args, "--genesis");
    let rpc_port: u16 = match crate::arg_value(args, "--rpc-port") {
        None => crate::DEFAULT_RPC_PORT,
        Some(s) => match s.parse() {
            Ok(p) => p,
            Err(_) => {
                eprintln!("doctor: --rpc-port must be a port number (got `{s}`)");
                return 1;
            }
        },
    };
    let rpc_bind = crate::arg_value(args, "--rpc-bind");
    let csv = |name: &str| -> Vec<String> {
        crate::arg_value(args, name)
            .map(|s| s.split(',').filter(|p| !p.is_empty()).map(String::from).collect())
            .unwrap_or_default()
    };
    let devnet_peers = csv("--peers");
    let p2p_peers = csv("--p2p-peer");
    let p2p_listen = csv("--p2p-listen");
    let devnet_listen: Option<u16> =
        crate::arg_value(args, "--listen").and_then(|s| s.parse().ok());

    println!("bloch-pos doctor — node-local, read-only; no consensus impact.");

    // ── 1. Genesis manifest ────────────────────────────────────────────────
    let mut slot_ms: u64 = 30_000; // production default; corrected from the manifest below
    match &genesis_path {
        None => r.add(Verdict::Skip, "genesis", "no --genesis given; manifest not checked"),
        Some(p) => match crate::genesis::Manifest::load(Path::new(p)) {
            Ok((m, digest)) => {
                slot_ms = m.slot_ms.max(1);
                r.add(
                    Verdict::Pass,
                    "genesis",
                    &format!(
                        "manifest loads; network digest {}, slot_ms {}, {} genesis validators",
                        crate::codec::hex8(&digest),
                        m.slot_ms,
                        m.validators.len()
                    ),
                );
            }
            Err(e) => r.add(
                Verdict::Fail,
                "genesis",
                &format!("{p}: {e} — the node will refuse to start; fix this first"),
            ),
        },
    }

    // ── 2. Data dir ────────────────────────────────────────────────────────
    match &data_dir {
        None => r.add(Verdict::Skip, "data-dir", "no --data-dir given"),
        Some(d) => check_data_dir(&mut r, Path::new(d)),
    }

    // ── 3. Disk ────────────────────────────────────────────────────────────
    match &data_dir {
        None => r.add(Verdict::Skip, "disk", "no --data-dir given"),
        Some(d) => check_disk(&mut r, d),
    }

    // ── 4. Memory ──────────────────────────────────────────────────────────
    check_memory(&mut r);

    // ── 5. Clock vs peers ──────────────────────────────────────────────────
    check_clock(&mut r, &devnet_peers, &p2p_peers, slot_ms);

    // ── 6. P2P ports ───────────────────────────────────────────────────────
    check_p2p(&mut r, devnet_listen, &p2p_listen, &devnet_peers, &p2p_peers);

    // ── 7 & 8. RPC exposure + running-node summary ─────────────────────────
    check_rpc(&mut r, rpc_port, rpc_bind.as_deref());

    println!(
        "doctor: {} failure(s), {} warning(s).",
        r.fails, r.warns
    );
    if r.fails > 0 {
        1
    } else {
        0
    }
}

// ───────────────────────────────────────────────────────────────────────────
// 2. Data dir
// ───────────────────────────────────────────────────────────────────────────

fn check_data_dir(r: &mut Report, dir: &Path) {
    if !dir.is_dir() {
        r.add(
            Verdict::Warn,
            "data-dir",
            &format!(
                "{} does not exist yet — fine for a first boot ({}), wrong if this node has run here before",
                dir.display(),
                "the node creates it"
            ),
        );
        return;
    }
    let key = dir.join("validator.key");
    let history = dir.join(crate::signing_history::HISTORY_FILE);
    match (key.is_file(), history.is_file()) {
        (true, true) => r.add(
            Verdict::Pass,
            "data-dir",
            "validator.key and signing history both present",
        ),
        (true, false) => r.add(
            Verdict::Warn,
            "data-dir",
            &format!(
                "validator.key is present but {} is not: the node will REFUSE to start. \
                 If this key ever signed anywhere, export/import its history \
                 (`bloch-pos protection-export` / `protection-import`); if it has \
                 genuinely never signed, start once with --accept-new-signing-history",
                history.display()
            ),
        ),
        (false, _) => r.add(
            Verdict::Pass,
            "data-dir",
            "no validator.key: this data dir runs as an observer (no duties, no signing)",
        ),
    }
    match std::fs::metadata(dir.join("blocks.log")) {
        Ok(m) => r.add(
            Verdict::Pass,
            "data-dir",
            &format!(
                "blocks.log is {:.1} MiB; restart will replay it before serving",
                m.len() as f64 / (1024.0 * 1024.0)
            ),
        ),
        Err(_) => r.add(
            Verdict::Pass,
            "data-dir",
            "no blocks.log yet: first boot will sync from genesis (or the configured checkpoint)",
        ),
    }
}

// ───────────────────────────────────────────────────────────────────────────
// 3. Disk — `df -Pk`, the one portable spelling (POSIX output format,
// 1024-byte blocks) shared by macOS and Linux. Shelling out is deliberate:
// this crate links no libc-statvfs wrapper and a diagnostic CLI may.
// ───────────────────────────────────────────────────────────────────────────

fn check_disk(r: &mut Report, dir: &str) {
    let out = std::process::Command::new("df").args(["-Pk", dir]).output();
    let text = match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).into_owned(),
        _ => {
            r.add(Verdict::Skip, "disk", "`df -Pk` unavailable; free space not checked");
            return;
        }
    };
    match parse_df_avail_kb(&text) {
        None => r.add(Verdict::Skip, "disk", "could not parse `df` output"),
        Some(kb) => {
            let bytes = kb.saturating_mul(1024);
            let gib = bytes as f64 / (1024.0 * 1024.0 * 1024.0);
            if bytes < DISK_FAIL_BYTES {
                r.add(
                    Verdict::Fail,
                    "disk",
                    &format!(
                        "{gib:.1} GiB free under the data dir — the append-only block log \
                         will exhaust this; free space before starting"
                    ),
                );
            } else if bytes < DISK_WARN_BYTES {
                r.add(
                    Verdict::Warn,
                    "disk",
                    &format!(
                        "{gib:.1} GiB free — enough for now, but the block log is unpruned \
                         and grows forever; plan for at least {} GiB",
                        DISK_WARN_BYTES / (1024 * 1024 * 1024)
                    ),
                );
            } else {
                r.add(Verdict::Pass, "disk", &format!("{gib:.1} GiB free under the data dir"));
            }
        }
    }
}

/// Fourth column of the POSIX `df -P` body line: available 1K blocks.
/// Public-in-module so the parser is testable without a filesystem.
fn parse_df_avail_kb(df_output: &str) -> Option<u64> {
    df_output
        .lines()
        .nth(1)?
        .split_whitespace()
        .nth(3)?
        .parse()
        .ok()
}

// ───────────────────────────────────────────────────────────────────────────
// 4. Memory — /proc/meminfo where it exists (Linux, i.e. the fleet), sysctl
// + vm_stat on macOS (a dev machine). "Available" is the kernel's own
// estimate on Linux; on macOS it is free+inactive pages, which overstates a
// little — said in the message rather than silently absorbed.
// ───────────────────────────────────────────────────────────────────────────

fn check_memory(r: &mut Report) {
    let (total, avail, method) = match read_memory() {
        Some(t) => t,
        None => {
            r.add(Verdict::Skip, "memory", "could not read memory info on this platform");
            return;
        }
    };
    let gib = |b: u64| b as f64 / (1024.0 * 1024.0 * 1024.0);
    let detail = format!(
        "{:.1} GiB available of {:.1} GiB ({method}). A fresh full sync of the mainnet \
         history was measured to need >7.5 GiB; a node syncing from a snapshot or \
         already caught up needs far less",
        gib(avail),
        gib(total)
    );
    if avail < SYNC_RAM_FAIL_BYTES {
        r.add(Verdict::Fail, "memory", &detail);
    } else if avail < SYNC_RAM_WARN_BYTES {
        r.add(Verdict::Warn, "memory", &detail);
    } else {
        r.add(Verdict::Pass, "memory", &detail);
    }
}

fn read_memory() -> Option<(u64, u64, &'static str)> {
    // Linux: authoritative.
    if let Ok(text) = std::fs::read_to_string("/proc/meminfo") {
        let field = |name: &str| -> Option<u64> {
            text.lines()
                .find(|l| l.starts_with(name))?
                .split_whitespace()
                .nth(1)?
                .parse::<u64>()
                .ok()
                .map(|kb| kb * 1024)
        };
        return Some((field("MemTotal:")?, field("MemAvailable:")?, "/proc/meminfo"));
    }
    // macOS: total via sysctl, available approximated from vm_stat.
    let total: u64 = std::process::Command::new("sysctl")
        .args(["-n", "hw.memsize"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse().ok())?;
    let vm = std::process::Command::new("vm_stat").output().ok()?;
    let text = String::from_utf8_lossy(&vm.stdout).into_owned();
    let page_size: u64 = text
        .lines()
        .next()
        .and_then(|l| l.split("page size of ").nth(1))
        .and_then(|s| s.split(' ').next())
        .and_then(|s| s.parse().ok())
        .unwrap_or(4096);
    let pages = |name: &str| -> u64 {
        text.lines()
            .find(|l| l.starts_with(name))
            .and_then(|l| l.split(':').nth(1))
            .map(|s| s.trim().trim_end_matches('.'))
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0)
    };
    let avail = (pages("Pages free") + pages("Pages inactive")) * page_size;
    Some((total, avail, "sysctl+vm_stat, approximate"))
}

// ───────────────────────────────────────────────────────────────────────────
// 5. Clock vs peers — the boot gate's own rule (`time_check::gate`), run
// before the node exists. Devnet peers are probed with the raw
// FRAME_GET_TIME wire exchange; libp2p peers by standing up the real
// transport briefly (scratch identity, nothing persisted to the node's dir)
// and letting its per-connection time probe collect the same samples the
// boot gate would see.
// ───────────────────────────────────────────────────────────────────────────

fn check_clock(r: &mut Report, devnet_peers: &[String], p2p_peers: &[String], slot_ms: u64) {
    let mut skews: Vec<(String, i64)> = Vec::new();

    for peer in devnet_peers {
        match probe_devnet_clock(peer) {
            Ok(skew) => skews.push((peer.clone(), skew)),
            Err(e) => r.add(
                Verdict::Warn,
                "clock",
                &format!("{peer}: no clock sample ({e}) — an old binary or an unreachable peer"),
            ),
        }
    }

    if !p2p_peers.is_empty() {
        match probe_libp2p_clock(p2p_peers) {
            Ok(mut sampled) => skews.append(&mut sampled),
            Err(e) => r.add(Verdict::Warn, "clock", &format!("libp2p probe failed: {e}")),
        }
    }

    if devnet_peers.is_empty() && p2p_peers.is_empty() {
        r.add(
            Verdict::Skip,
            "clock",
            "no peers configured — nothing to compare the local clock against; \
             weak-subjectivity freshness will rest on this host's clock alone",
        );
        return;
    }

    let margin = time_check::margin_ms(slot_ms);
    let values: Vec<i64> = skews.iter().map(|(_, s)| *s).collect();
    match time_check::gate(&values, margin) {
        time_check::ClockVerdict::NoSamples => r.add(
            Verdict::Warn,
            "clock",
            "no peer answered the time probe; the boot clock gate will also run blind",
        ),
        time_check::ClockVerdict::Ok { median_ms, samples } => r.add(
            Verdict::Pass,
            "clock",
            &format!(
                "median skew {median_ms:+} ms across {samples} peer(s), margin ±{margin} ms"
            ),
        ),
        time_check::ClockVerdict::Refuse { median_ms, samples } => r.add(
            Verdict::Fail,
            "clock",
            &format!(
                "median skew {median_ms:+} ms across {samples} peer(s) EXCEEDS the ±{margin} ms \
                 margin — the node will refuse to start. Fix NTP / the VM clock; if this host's \
                 clock is verifiably right, a majority of its peers is lying to it"
            ),
        ),
    }
}

/// One devnet peer: connect, send FRAME_GET_TIME, wait for FRAME_TIME.
/// Frames that are not the answer (the peer treats us as an inbound
/// broadcast target and may push blocks) are skipped, bounded.
fn probe_devnet_clock(peer: &str) -> Result<i64, String> {
    let addr = resolve(peer).map_err(|e| e.to_string())?;
    let mut sock =
        TcpStream::connect_timeout(&addr, PROBE_TIMEOUT).map_err(|e| e.to_string())?;
    sock.set_read_timeout(Some(PROBE_TIMEOUT)).ok();
    sock.set_write_timeout(Some(PROBE_TIMEOUT)).ok();
    crate::net::write_frame(&mut sock, &[crate::net::FRAME_GET_TIME])
        .map_err(|e| e.to_string())?;
    for _ in 0..32 {
        let frame = crate::net::read_frame(&mut sock).map_err(|e| e.to_string())?;
        if frame.len() == 9 && frame[0] == crate::net::FRAME_TIME {
            let peer_ms = u64::from_le_bytes(frame[1..9].try_into().unwrap());
            let local = time_check::now_ms();
            return Ok(peer_ms as i64 - local as i64);
        }
    }
    Err("peer answered, but never with a time frame".into())
}

/// libp2p peers: run the real transport for a few seconds with a scratch
/// identity and read the clock samples its connection handshake collects —
/// the same code path, and therefore the same numbers, the boot gate uses.
fn probe_libp2p_clock(peers: &[String]) -> Result<Vec<(String, i64)>, String> {
    let scratch = std::env::temp_dir().join(format!("bloch-doctor-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).map_err(|e| e.to_string())?;
    let mut addrs = Vec::new();
    for p in peers {
        addrs.push(p.parse::<crate::p2p::Multiaddr>().map_err(|e| format!("{p}: {e}"))?);
    }
    let clock = std::sync::Arc::new(time_check::PeerClock::new());
    let (tx, rx) = std::sync::mpsc::channel();
    // Drain whatever the mesh pushes at us (gossip subscriptions deliver
    // blocks); the probe only wants the clock samples.
    std::thread::spawn(move || while rx.recv().is_ok() {});
    let _handle = crate::p2p::start(
        crate::p2p::Config {
            listen: Vec::new(), // dial-only: a probe accepts nobody
            peers: addrs,
            data_dir: scratch.clone(),
            max_peers: peers.len().max(4),
            behind_proxy: false,
        },
        tx,
        std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        clock.clone(),
        std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
    )
    .map_err(|e| e.to_string())?;
    clock.wait_for(peers.len().min(time_check::TARGET_SAMPLES), LIBP2P_CLOCK_WAIT);
    let skews = clock.skews();
    let _ = std::fs::remove_dir_all(&scratch);
    Ok(skews)
}

// ───────────────────────────────────────────────────────────────────────────
// 6. P2P ports
// ───────────────────────────────────────────────────────────────────────────

fn check_p2p(
    r: &mut Report,
    devnet_listen: Option<u16>,
    p2p_listen: &[String],
    devnet_peers: &[String],
    p2p_peers: &[String],
) {
    // Listen port state. Binding succeeds → nothing is listening (fine
    // before a start, wrong if the node is supposed to be up); AddrInUse →
    // something (hopefully the node) already holds it.
    let mut listen_ports: Vec<u16> = devnet_listen.into_iter().collect();
    for a in p2p_listen {
        if let Some((_, port)) = parse_multiaddr_tcp(a) {
            listen_ports.push(port);
        }
    }
    if listen_ports.is_empty() {
        r.add(Verdict::Skip, "p2p-listen", "no listen port given");
    }
    for port in listen_ports {
        // Connect first: a listener bound to 127.0.0.1 does not make a
        // 0.0.0.0 bind test fail, so the bind test alone reads a running
        // loopback-bound node as "port free".
        let local = SocketAddr::new(IpAddr::from([127, 0, 0, 1]), port);
        if TcpStream::connect_timeout(&local, Duration::from_millis(500)).is_ok() {
            r.add(
                Verdict::Pass,
                "p2p-listen",
                &format!("port {port} is listening on this host (a node appears to be running)"),
            );
            continue;
        }
        match TcpListener::bind(("0.0.0.0", port)) {
            Ok(_) => r.add(
                Verdict::Pass,
                "p2p-listen",
                &format!(
                    "port {port} is free — nothing is listening yet (expected before a start; \
                     if a node should be RUNNING here, it is not). Note: whether the internet \
                     can reach this port through NAT/firewalls cannot be verified from this \
                     host; test from outside"
                ),
            ),
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => r.add(
                Verdict::Pass,
                "p2p-listen",
                &format!("port {port} is already bound (a node appears to be running)"),
            ),
            Err(e) => r.add(
                Verdict::Warn,
                "p2p-listen",
                &format!("cannot test port {port}: {e}"),
            ),
        }
    }

    // Outbound reachability — the egress check. The 2026-08-07 incident:
    // leftover iptables OUTPUT rules DROPped the consensus ports while SSH
    // worked, and consensus was blamed first. Every configured peer is
    // dialed with a plain TCP connect.
    let mut targets: Vec<(String, Option<SocketAddr>)> = Vec::new();
    for p in devnet_peers {
        targets.push((p.clone(), resolve(p).ok()));
    }
    for p in p2p_peers {
        let addr = parse_multiaddr_tcp(p)
            .and_then(|(host, port)| resolve(&format!("{host}:{port}")).ok());
        targets.push((p.clone(), addr));
    }
    if targets.is_empty() {
        r.add(Verdict::Skip, "p2p-egress", "no peers configured; outbound reachability not tested");
        return;
    }
    let mut unreachable = 0usize;
    for (name, addr) in &targets {
        match addr {
            None => {
                unreachable += 1;
                r.add(Verdict::Warn, "p2p-egress", &format!("{name}: cannot resolve"));
            }
            Some(a) => match TcpStream::connect_timeout(a, PROBE_TIMEOUT) {
                Ok(_) => r.add(Verdict::Pass, "p2p-egress", &format!("{name}: reachable")),
                Err(e) => {
                    unreachable += 1;
                    r.add(Verdict::Warn, "p2p-egress", &format!("{name}: {e}"));
                }
            },
        }
    }
    if unreachable == targets.len() {
        r.add(
            Verdict::Fail,
            "p2p-egress",
            "EVERY configured peer is unreachable. If SSH into this box works but consensus \
             ports time out, check for leftover egress firewall rules first — \
             `iptables -S OUTPUT` (a DROP on the P2P port range caused exactly this on \
             2026-08-07; `ufw status` does NOT show it) — before suspecting the peers",
        );
    }
}

// ───────────────────────────────────────────────────────────────────────────
// 7 & 8. RPC exposure + running-node summary
// ───────────────────────────────────────────────────────────────────────────

fn check_rpc(r: &mut Report, rpc_port: u16, rpc_bind: Option<&str>) {
    // The configured bind, judged statically first: an explicit routable
    // bind is a decision the operator should re-read. (`--rpc-bind` defaults
    // to loopback in `run`.)
    if let Some(bind) = rpc_bind {
        let loopback = bind
            .parse::<IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(bind == "localhost");
        if !loopback {
            r.add(
                Verdict::Fail,
                "rpc-exposure",
                &format!(
                    "--rpc-bind {bind} binds the RPC to a routable interface. \
                     `sendrawtransaction` makes this a WRITE surface with no authentication; \
                     all 64 fleet nodes ran exposed this way until 2026-08-30. Bind to \
                     127.0.0.1 and front it with a reverse proxy / firewall if remote \
                     access is needed"
                ),
            );
        }
    }

    // The live test: does anything answer JSON-RPC on a routable interface
    // of THIS host right now? This is what caught the fleet exposure — the
    // config said one thing, the sockets said another.
    let mut routable: Vec<IpAddr> = local_routable_ips();
    routable.dedup();
    if routable.is_empty() {
        r.add(
            Verdict::Skip,
            "rpc-exposure",
            "could not enumerate this host's routable addresses; test from another host \
             with: curl -s http://<this-host>:<rpc-port>/ (any answer at all is exposure)",
        );
    }
    for ip in routable {
        match rpc_roundtrip(SocketAddr::new(ip, rpc_port), "getchaininfo") {
            RpcProbe::Answered(_) => r.add(
                Verdict::Fail,
                "rpc-exposure",
                &format!(
                    "the node's RPC ANSWERS on routable address {ip}:{rpc_port} — an \
                     unauthenticated write surface (sendrawtransaction) open to whoever \
                     can route here. Restart with the default loopback bind (drop \
                     --rpc-bind), or firewall the port to the intended clients NOW"
                ),
            ),
            RpcProbe::SomethingElse => r.add(
                Verdict::Warn,
                "rpc-exposure",
                &format!(
                    "{ip}:{rpc_port} accepts TCP but does not answer JSON-RPC — another \
                     service shares this port number; confirm what it is"
                ),
            ),
            RpcProbe::Closed => r.add(
                Verdict::Pass,
                "rpc-exposure",
                &format!("{ip}:{rpc_port} does not accept connections (good)"),
            ),
        }
    }

    // Loopback: if a node is running, summarize its health and validator
    // status — the doctor doubles as the no-SSH status command.
    let local = SocketAddr::new(IpAddr::from([127, 0, 0, 1]), rpc_port);
    match rpc_roundtrip(local, "getchaininfo") {
        RpcProbe::Answered(body) => {
            r.add(Verdict::Pass, "node", &summarize_chain_info(&body));
            match rpc_roundtrip(local, "getvalidatorstatus") {
                RpcProbe::Answered(body) => {
                    r.add(Verdict::Pass, "validator", &summarize_validator_status(&body))
                }
                _ => r.add(Verdict::Skip, "validator", "getvalidatorstatus did not answer"),
            }
        }
        _ => r.add(
            Verdict::Skip,
            "node",
            &format!("no node answering RPC on 127.0.0.1:{rpc_port}; live health not read"),
        ),
    }
}

/// The routable (non-loopback) addresses of this host, best effort: the
/// default-route source address via the UDP trick (no packet is sent), plus
/// whatever `ip -o addr` / `ifconfig` lists. Missing tools degrade to fewer
/// addresses, never to an error.
fn local_routable_ips() -> Vec<IpAddr> {
    let mut ips = Vec::new();
    // Default-route source address: connect() on UDP picks it without
    // sending anything.
    if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
        if sock.connect("8.8.8.8:53").is_ok() {
            if let Ok(a) = sock.local_addr() {
                if !a.ip().is_loopback() {
                    ips.push(a.ip());
                }
            }
        }
    }
    for (cmd, args) in [("ip", vec!["-o", "addr", "show"]), ("ifconfig", vec!["-a"])] {
        if let Ok(o) = std::process::Command::new(cmd).args(&args).output() {
            if o.status.success() {
                for token in String::from_utf8_lossy(&o.stdout).split_whitespace() {
                    let candidate = token.split('/').next().unwrap_or(token);
                    if let Ok(ip) = candidate.parse::<IpAddr>() {
                        if !ip.is_loopback() && !ips.contains(&ip) {
                            ips.push(ip);
                        }
                    }
                }
                break; // one tool's answer is enough
            }
        }
    }
    ips
}

enum RpcProbe {
    /// JSON-RPC answered; the raw result body.
    Answered(String),
    /// TCP open, but the answer was not JSON-RPC shaped.
    SomethingElse,
    /// Connection refused / timed out.
    Closed,
}

/// One JSON-RPC call over a raw socket (the server speaks HTTP/1.1 with
/// Connection: close, so read-to-EOF is the whole client).
fn rpc_roundtrip(addr: SocketAddr, method: &str) -> RpcProbe {
    let Ok(mut sock) = TcpStream::connect_timeout(&addr, Duration::from_secs(1)) else {
        return RpcProbe::Closed;
    };
    sock.set_read_timeout(Some(PROBE_TIMEOUT)).ok();
    sock.set_write_timeout(Some(PROBE_TIMEOUT)).ok();
    let body = format!("{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"{method}\"}}");
    let req = format!(
        "POST / HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    if sock.write_all(req.as_bytes()).is_err() {
        return RpcProbe::SomethingElse;
    }
    let mut buf = Vec::new();
    if sock.read_to_end(&mut buf).is_err() && buf.is_empty() {
        return RpcProbe::SomethingElse;
    }
    let text = String::from_utf8_lossy(&buf);
    match text.split("\r\n\r\n").nth(1) {
        Some(json) if json.contains("\"jsonrpc\"") => RpcProbe::Answered(json.to_string()),
        _ => RpcProbe::SomethingElse,
    }
}

fn summarize_chain_info(body: &str) -> String {
    let Ok(v) = crate::rpc::parse_json(body) else {
        return "node answered, but the response did not parse".into();
    };
    let result = v.get("result").cloned().unwrap_or(crate::rpc::Json::Null);
    let u = |path: &[&str]| -> Option<u64> {
        let mut cur = &result;
        for p in path {
            cur = cur.get(p)?;
        }
        cur.as_u64()
    };
    let b = |path: &[&str]| -> Option<bool> {
        let mut cur = &result;
        for p in path {
            cur = cur.get(p)?;
        }
        cur.as_bool()
    };
    let stalled = b(&["health", "stalled"]).unwrap_or(false);
    let state = if stalled {
        "STALLED — not applying blocks; see the [health] lines in the node log"
    } else if b(&["health", "syncing"]).unwrap_or(false) {
        "syncing"
    } else {
        "healthy"
    };
    format!(
        "running node: {state}; height {}, {} slots behind wall clock, last block applied {}s ago",
        u(&["height"]).unwrap_or(0),
        u(&["behind_by_slots"]).unwrap_or(0),
        u(&["health", "secs_since_last_block"]).unwrap_or(0),
    )
}

fn summarize_validator_status(body: &str) -> String {
    let Ok(v) = crate::rpc::parse_json(body) else {
        return "status answered, but the response did not parse".into();
    };
    if let Some(err) = v.get("error") {
        let msg = err.get("message").and_then(|m| m.as_str()).unwrap_or("error");
        return format!("no validator on this node: {msg}");
    }
    let result = v.get("result").cloned().unwrap_or(crate::rpc::Json::Null);
    let idx = result.get("validator_index").and_then(|j| j.as_u64()).unwrap_or(0);
    let in_roster = result
        .get("in_duty_roster")
        .and_then(|j| j.as_bool())
        .unwrap_or(false);
    let reg_state = result
        .get("registry")
        .and_then(|r| r.get("state"))
        .and_then(|s| s.as_str())
        .unwrap_or("unregistered")
        .to_string();
    let next_att = result
        .get("next_attestation_slot")
        .and_then(|j| j.as_u64())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "none in horizon".into());
    format!(
        "validator {idx}: {reg_state}, in duty roster: {in_roster}, next attestation slot: {next_att}"
    )
}

// ───────────────────────────────────────────────────────────────────────────
// Small parsers
// ───────────────────────────────────────────────────────────────────────────

/// `/ip4/1.2.3.4/tcp/16400[/p2p/…]` or `/dns4/host/tcp/16400` → (host, port).
fn parse_multiaddr_tcp(addr: &str) -> Option<(String, u16)> {
    let parts: Vec<&str> = addr.split('/').filter(|s| !s.is_empty()).collect();
    let mut host = None;
    let mut port = None;
    let mut i = 0;
    while i + 1 < parts.len() {
        match parts[i] {
            "ip4" | "ip6" | "dns" | "dns4" | "dns6" => host = Some(parts[i + 1].to_string()),
            "tcp" => port = parts[i + 1].parse::<u16>().ok(),
            _ => {}
        }
        i += 2;
    }
    Some((host?, port?))
}

fn resolve(hostport: &str) -> std::io::Result<SocketAddr> {
    hostport
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no address"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn df_posix_output_yields_the_available_column() {
        let out = "Filesystem 1024-blocks Used Available Capacity Mounted on\n\
                   /dev/disk3s5 971350180 850000000 105511340 89% /\n";
        assert_eq!(parse_df_avail_kb(out), Some(105_511_340));
    }

    #[test]
    fn df_garbage_is_none_not_a_panic() {
        assert_eq!(parse_df_avail_kb(""), None);
        assert_eq!(parse_df_avail_kb("header only\n"), None);
        assert_eq!(parse_df_avail_kb("h\na b c not-a-number e\n"), None);
    }

    #[test]
    fn multiaddr_tcp_parses_the_fleet_shapes() {
        assert_eq!(
            parse_multiaddr_tcp("/ip4/136.244.82.226/tcp/16110"),
            Some(("136.244.82.226".to_string(), 16110))
        );
        assert_eq!(
            parse_multiaddr_tcp("/ip4/10.0.0.1/tcp/16400/p2p/12D3KooWabc"),
            Some(("10.0.0.1".to_string(), 16400))
        );
        assert_eq!(
            parse_multiaddr_tcp("/dns4/node.example.org/tcp/16400"),
            Some(("node.example.org".to_string(), 16400))
        );
        assert_eq!(parse_multiaddr_tcp("/unix/tmp/sock"), None);
        assert_eq!(parse_multiaddr_tcp("garbage"), None);
    }

    /// The exposure verdict logic in one place: an RPC that answers on a
    /// routable address is the failure the fleet actually shipped. This test
    /// stands up the real RPC server on 127.0.0.1 and asserts the probe
    /// recognises a JSON-RPC answer — the same recognition the routable-IP
    /// probe applies.
    #[test]
    fn rpc_probe_recognises_a_real_rpc_server() {
        struct Stub;
        impl crate::rpc::RpcBackend for Stub {
            fn call(&self, _req: crate::rpc::RpcRequest) -> crate::rpc::RpcResult {
                Ok(crate::rpc::Json::obj(vec![("height", crate::rpc::Json::u(7))]))
            }
        }
        let addr = crate::rpc::serve("127.0.0.1", 0, std::sync::Arc::new(Stub))
            .expect("bind the RPC server on an ephemeral port");
        match rpc_roundtrip(addr, "getchaininfo") {
            RpcProbe::Answered(body) => assert!(body.contains("\"height\"")),
            _ => panic!("a live RPC server must be recognised as Answered"),
        }
    }

    #[test]
    fn rpc_probe_reports_a_closed_port_as_closed() {
        // Bind-then-drop guarantees the port was just free; racing another
        // process onto it in the microseconds between is acceptable flake
        // risk for a test this valuable.
        let port = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let addr = SocketAddr::new(IpAddr::from([127, 0, 0, 1]), port);
        assert!(matches!(rpc_roundtrip(addr, "getchaininfo"), RpcProbe::Closed));
    }
}
