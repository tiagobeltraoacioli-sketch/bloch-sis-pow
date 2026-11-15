// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Bloch Sentinel hooks — node-local security signals, OFF by default
//!
//! What the external Sentinel (Postern Cyber probe + analyst, which runs
//! OUTSIDE this process) needs from a validator host, and nothing more:
//!
//! - `getsecuritystatus` on the existing loopback RPC (read-only);
//! - `--security-events <path>`: a bounded JSON-lines event log;
//! - `--admin-socket <path>`: a 0600 unix socket accepting exactly three
//!   bounded commands, `peer.ban`, `peer.unban`, `peer.bans`.
//!
//! The interface is specified in `docs/SENTINEL-HOOKS.md`.
//!
//! ## Why this cannot touch consensus
//!
//! Every hook below is an *observer* or a *connection-admission* decision:
//! it reads values the engine already computed, or refuses a TCP connection
//! from a banned non-configured address. Nothing here is read by the state
//! transition, block or gossip validity, fork choice, or any state root, and
//! nothing here changes a verdict. Replay of canonical history is
//! byte-identical with or without it (`engine/sentinel_hooks.rs` tests).
//!
//! ## Off means off
//!
//! Unless `--security-status`, `--security-events` or `--admin-socket` is
//! given, [`current`] is `None` and every hook returns at its first line;
//! `getsecuritystatus` answers "method not found" exactly as a node without
//! this module would. No thread is started, no file or socket is created.
//!
//! No AI, no network calls, no API keys: the node only exposes local signals
//! and accepts bounded local commands.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::rpc::Json;

pub(crate) mod admin;
mod adverts;
pub(crate) mod bans;
pub(crate) mod cidr;
mod events;
mod window;
#[cfg(test)]
mod tests;

pub(crate) use adverts::{AdvertKind, Observation};
use cidr::Cidr;

pub(crate) const STATUS_SCHEMA: &str = "bloch-sentinel-status/1";
/// Finality-lag thresholds, in epochs behind the wall clock. Normal operation
/// is a lag of 2; an event fires when the lag crosses one of these.
pub(crate) const LAG_THRESHOLDS: [u64; 5] = [4, 8, 16, 32, 64];
const MAX_SOURCE_NAMES: usize = 4096;
const MAX_BUCKETS_REPORTED: usize = 16;

pub(crate) fn unix_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// What the operator asked for. Built from argv in `main.rs`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Config {
    pub(crate) status: bool,
    pub(crate) events: Option<PathBuf>,
    pub(crate) admin_socket: Option<PathBuf>,
    /// `--peers` (host:port, pins already split off) and `--p2p-peer`
    /// (multiaddrs): the protected set the ban table may never cover.
    pub(crate) peers: Vec<String>,
    pub(crate) p2p_peers: Vec<String>,
}

impl Config {
    pub(crate) fn enabled(&self) -> bool {
        self.status || self.events.is_some() || self.admin_socket.is_some()
    }

    /// Literal addresses among the configured peers, as host ranges.
    fn protected_literals(&self) -> Vec<Cidr> {
        let mut out = Vec::new();
        for p in &self.peers {
            if let Ok(sa) = p.parse::<std::net::SocketAddr>() {
                out.push(Cidr::host(sa.ip()));
            }
        }
        for m in &self.p2p_peers {
            // `/ip4/<a>/tcp/<p>/...` or `/ip6/<a>/...`
            let mut parts = m.split('/').filter(|s| !s.is_empty());
            while let Some(proto) = parts.next() {
                if proto == "ip4" || proto == "ip6" {
                    if let Some(ip) = parts.next().and_then(|a| a.parse::<IpAddr>().ok()) {
                        out.push(Cidr::host(ip));
                    }
                }
            }
        }
        out
    }
}

/// What the devnet mesh (the transport mainnet runs) lets the Sentinel see
/// and do. Implemented in `net/sentinel_view.rs`, registered by `net::start`.
pub(crate) trait MeshView: Send + Sync {
    /// Remote addresses of the open inbound connections (bounded by the
    /// mesh's own connection cap).
    fn inbound_addrs(&self) -> Vec<IpAddr>;
    /// The configured-peer sources the mesh knows (literal and resolved),
    /// as the mesh keys them (`connection_limit::limit_key`: an IPv4
    /// address, or an IPv6 /64).
    fn configured_sources(&self) -> Vec<IpAddr>;
    /// Close every open inbound connection from a non-configured address
    /// for which `banned` is true. Returns how many were closed.
    fn disconnect(&self, banned: &dyn Fn(IpAddr) -> bool) -> usize;
}

/// The engine's view, published once per slot (`engine/sentinel_hooks.rs`).
/// Small and `Clone`: a handful of integers and roots, no state.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ChainSnapshot {
    pub(crate) wall_slot: u64,
    pub(crate) wall_epoch: u64,
    pub(crate) live: bool,
    pub(crate) head_slot: u64,
    pub(crate) head_height: u64,
    pub(crate) head_root: [u8; 32],
    pub(crate) justified_epoch: u64,
    pub(crate) justified_root: [u8; 32],
    pub(crate) finalized_epoch: u64,
    pub(crate) finalized_root: [u8; 32],
    pub(crate) finalized_height: Option<u64>,
    /// `Engine::finalized_latch`: (height, root) — the highest finality this
    /// process has held, which can be above the head state's after a reorg.
    pub(crate) latch: Option<(u64, [u8; 32])>,
    pub(crate) transport: &'static str,
    pub(crate) devnet_peers: Option<usize>,
    pub(crate) libp2p_peers: Option<usize>,
    pub(crate) doppelganger: Doppelganger,
    pub(crate) kes: KesView,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Doppelganger {
    pub(crate) observe_until_slot: Option<u64>,
    pub(crate) halted: bool,
}

impl Doppelganger {
    pub(crate) fn state(&self, wall_slot: u64) -> &'static str {
        match self.observe_until_slot {
            _ if self.halted => "halted",
            Some(until) if wall_slot < until => "observing",
            Some(_) => "window_passed",
            None => "inactive",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct KesView {
    /// This node's duty validator in the head state, if it runs one.
    pub(crate) validator: Option<u32>,
    pub(crate) keystore_loaded: bool,
    pub(crate) kes_key_loaded: bool,
    /// `static` | `kes` | `fail_closed` | `no_validator`, by the same
    /// `kes::signing_mode` rule the verifiers run, for the wall epoch,
    /// against the head state.
    pub(crate) mode: &'static str,
    pub(crate) period: Option<u64>,
    /// `kes_enforced_from` of the head state: `Some(None)` = not bound.
    pub(crate) bind_epoch: Option<Option<u64>>,
    /// The epoch of the head state those values were read from. When it is
    /// behind `wall_epoch` the head state is not rolled to the duty epoch,
    /// and a bind decided at the boundary in between is not visible here.
    pub(crate) head_state_epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct KesErrorRecord {
    duty: &'static str,
    class: &'static str,
    validator: u32,
    wall_slot: u64,
    at_ms: u64,
    count: u64,
}

/// Map a signer refusal to a fixed class. The raw text is never kept or
/// emitted (it can name files), so no event can carry a secret or a path.
pub(crate) fn classify_kes_error(why: &str) -> &'static str {
    let w = why.to_ascii_lowercase();
    if w.contains("enforcement state unknown") {
        "enforcement_unknown"
    } else if w.contains("no ") && w.contains("is loaded") {
        "no_kes_key_loaded"
    } else if w.contains("no kes key is registered") {
        "not_registered"
    } else if w.contains("belongs to") {
        "wrong_validator"
    } else if w.contains("is not v") && w.contains("in force") {
        "wrong_tree"
    } else if w.contains("does not cover period") {
        "expired_or_not_started"
    } else if w.contains("is erased") {
        "leaf_erased"
    } else if w.contains("refusing to erase") {
        "evolution_refused_clock_jump"
    } else if w.contains("evolve") {
        "evolution_failed"
    } else {
        "other"
    }
}

fn verdict_str(v: crate::net::Verdict) -> &'static str {
    match v {
        crate::net::Verdict::Accept => "accept",
        crate::net::Verdict::Ignore => "ignore",
        crate::net::Verdict::Reject => "reject",
    }
}

fn lag_level(lag: u64) -> usize {
    LAG_THRESHOLDS.iter().filter(|t| lag >= **t).count()
}

/// Bounded map from an opaque verification source to the address it was
/// derived from, so reports can name `1.2.3.4` instead of a hash.
#[derive(Default)]
struct SourceNames {
    map: HashMap<[u8; 32], IpAddr>,
    order: VecDeque<[u8; 32]>,
}

impl SourceNames {
    fn learn(&mut self, source: [u8; 32], ip: IpAddr) {
        if self.map.insert(source, ip).is_some() {
            return;
        }
        self.order.push_back(source);
        while self.order.len() > MAX_SOURCE_NAMES {
            if let Some(old) = self.order.pop_front() {
                self.map.remove(&old);
            }
        }
    }

    fn name(&self, source: &[u8; 32]) -> Option<IpAddr> {
        self.map.get(source).copied()
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match m.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

pub(crate) struct Sentinel {
    cfg: Config,
    protected: Vec<Cidr>,
    chain: Mutex<Option<(ChainSnapshot, u64)>>,
    adverts: Mutex<adverts::AdvertTable>,
    verdicts: Mutex<window::SourceWindow<[u8; 32]>>,
    handshakes: Mutex<window::SourceWindow<IpAddr>>,
    names: Mutex<SourceNames>,
    bans: Mutex<bans::BanTable>,
    refused_by_ban: AtomicU64,
    kes_error: Mutex<Option<KesErrorRecord>>,
    events: Option<events::EventSink>,
    mesh: OnceLock<Box<dyn MeshView>>,
    admin_commands: AtomicU64,
}

impl Sentinel {
    pub(crate) fn new(cfg: Config, events: Option<events::EventSink>) -> Self {
        let now = Instant::now();
        let protected = cfg.protected_literals();
        Sentinel {
            cfg,
            protected,
            chain: Mutex::new(None),
            adverts: Mutex::new(adverts::AdvertTable::default()),
            verdicts: Mutex::new(window::SourceWindow::new(now)),
            handshakes: Mutex::new(window::SourceWindow::new(now)),
            names: Mutex::new(SourceNames::default()),
            bans: Mutex::new(bans::BanTable::default()),
            refused_by_ban: AtomicU64::new(0),
            kes_error: Mutex::new(None),
            events,
            mesh: OnceLock::new(),
            admin_commands: AtomicU64::new(0),
        }
    }

    pub(crate) fn emit(&self, kind: &'static str, fields: Vec<(&str, Json)>) {
        if let Some(sink) = &self.events {
            sink.emit(kind, fields);
        }
    }

    // ── Chain ───────────────────────────────────────────────────────────

    /// Take the engine's per-slot snapshot and emit the transition events it
    /// implies (finality lag thresholds, doppelganger, KES mode).
    pub(crate) fn publish_chain(&self, next: ChainSnapshot) {
        let now_ms = unix_ms();
        let prev = lock(&self.chain).replace((next.clone(), now_ms)).map(|(p, _)| p);
        let lag = next.wall_epoch.saturating_sub(next.finalized_epoch);
        // Lag is meaningless while replaying or catching up; only a live
        // node's lag is a signal.
        let level = if next.live { lag_level(lag) } else { 0 };
        let prev_level = prev
            .as_ref()
            .filter(|p| p.live)
            .map_or(0, |p| lag_level(p.wall_epoch.saturating_sub(p.finalized_epoch)));
        if level != prev_level {
            let fields = vec![
                ("lag_epochs", Json::u(lag)),
                ("wall_epoch", Json::u(next.wall_epoch)),
                ("finalized_epoch", Json::u(next.finalized_epoch)),
                ("finalized_root", Json::hex(&next.finalized_root)),
                ("threshold_epochs", level.checked_sub(1).and_then(|i| LAG_THRESHOLDS.get(i)).map_or(Json::Null, |t| Json::u(*t))),
                ("direction", Json::s(if level > prev_level { "up" } else { "down" })),
            ];
            self.emit(if level == 0 { "finality_recovered" } else { "finality_lag" }, fields);
        }
        let was_halted = prev.as_ref().is_some_and(|p| p.doppelganger.halted);
        if next.doppelganger.halted && !was_halted {
            self.emit(
                "doppelganger_detected",
                vec![
                    ("validator", next.kes.validator.map_or(Json::Null, |v| Json::u(u64::from(v)))),
                    ("wall_slot", Json::u(next.wall_slot)),
                    ("duties", Json::s("stopped")),
                ],
            );
        }
        let prev_mode = prev.as_ref().map(|p| p.kes.mode);
        if prev_mode.is_some() && prev_mode != Some(next.kes.mode) {
            self.emit(
                "kes_mode_changed",
                vec![
                    ("from", prev_mode.map_or(Json::Null, Json::s)),
                    ("to", Json::s(next.kes.mode)),
                    ("validator", next.kes.validator.map_or(Json::Null, |v| Json::u(u64::from(v)))),
                    ("wall_epoch", Json::u(next.wall_epoch)),
                ],
            );
        }
    }

    pub(crate) fn note_kes_error(&self, duty: &'static str, validator: u32, why: &str) {
        let class = classify_kes_error(why);
        let wall_slot = lock(&self.chain).as_ref().map_or(0, |(c, _)| c.wall_slot);
        let at_ms = unix_ms();
        let count = {
            let mut last = lock(&self.kes_error);
            let count = last.as_ref().filter(|l| l.class == class && l.duty == duty).map_or(0, |l| l.count) + 1;
            *last = Some(KesErrorRecord { duty, class, validator, wall_slot, at_ms, count });
            count
        };
        self.emit(
            "kes_signing_error",
            vec![
                ("duty", Json::s(duty)),
                ("class", Json::s(class)),
                ("validator", Json::u(u64::from(validator))),
                ("wall_slot", Json::u(wall_slot)),
                ("consecutive", Json::u(count)),
            ],
        );
    }

    // ── Peers' finality adverts ─────────────────────────────────────────

    pub(crate) fn observe_advert(&self, obs: Observation) {
        let addr = lock(&self.names).name(&obs.source);
        let kind = obs.kind;
        let fields = vec![
            ("source", Json::s(crate::codec::hex8(&obs.source))),
            ("addr", addr.map_or(Json::Null, |a| Json::s(a.to_string()))),
            ("kind", Json::s(kind.as_str())),
            ("advertised_finalized_root", Json::hex(&obs.advertised_finalized)),
            ("epoch_hint", obs.epoch_hint.map_or(Json::Null, Json::u)),
            ("our_finalized_epoch", Json::u(obs.our_finalized_epoch)),
            ("our_finalized_root", Json::hex(&obs.our_finalized_root)),
            ("block_root", Json::hex(&obs.block_root)),
            ("block_slot", Json::u(obs.block_slot)),
            ("verdict", Json::s(obs.verdict)),
        ];
        let news = lock(&self.adverts).record(obs, addr, Instant::now(), unix_ms());
        if news {
            self.emit(
                if kind == AdvertKind::Conflicting { "conflicting_finalized_checkpoint" } else { "peer_finalized_ahead" },
                fields,
            );
        }
    }

    pub(crate) fn advert_agrees(&self, source: &[u8; 32]) {
        lock(&self.adverts).clear(source);
    }

    // ── Network counters ────────────────────────────────────────────────

    pub(crate) fn learn_source(&self, ip: IpAddr) {
        let ip = cidr::normalize(ip);
        lock(&self.names).learn(crate::net::verification_source_for_ip(ip), ip);
    }

    pub(crate) fn note_verdict(&self, source: Option<[u8; 32]>, verdict: crate::net::Verdict) {
        let Some(source) = source else { return };
        let (rejected, ignored) = match verdict {
            crate::net::Verdict::Accept => return,
            crate::net::Verdict::Reject => (1, 0),
            crate::net::Verdict::Ignore => (0, 1),
        };
        lock(&self.verdicts).add(&source, rejected, ignored, Instant::now());
    }

    pub(crate) fn note_handshake(&self, ip: IpAddr, attempts: u64, failures: u64) {
        lock(&self.handshakes).add(&cidr::normalize(ip), attempts, failures, Instant::now());
    }

    // ── Bans ────────────────────────────────────────────────────────────

    pub(crate) fn register_mesh(&self, view: Box<dyn MeshView>) {
        let _ = self.mesh.set(view);
    }

    fn protected_now(&self) -> Vec<Cidr> {
        let mut p = self.protected.clone();
        if let Some(mesh) = self.mesh.get() {
            for src in mesh.configured_sources() {
                let src = cidr::normalize(src);
                // The mesh keys an IPv6 peer by its /64.
                let range = if src.is_ipv4() { Some(Cidr::host(src)) } else { Cidr::new(src, 64) };
                p.extend(range);
            }
        }
        p
    }

    pub(crate) fn is_banned(&self, ip: IpAddr) -> bool {
        lock(&self.bans).is_banned(ip, Instant::now())
    }

    /// Accept-path check. A configured peer is never refused.
    pub(crate) fn refuse_inbound(&self, ip: IpAddr, configured: bool) -> bool {
        if configured || !self.is_banned(ip) {
            return false;
        }
        self.refused_by_ban.fetch_add(1, Ordering::Relaxed);
        true
    }

    pub(crate) fn ban(&self, range: Cidr, ttl_secs: u64, reason: &str) -> Result<(bans::Ban, usize), String> {
        let protected = self.protected_now();
        let ban = lock(&self.bans)
            .ban(range, ttl_secs, reason, &protected, Instant::now(), unix_ms())
            .map_err(|e| e.to_string())?;
        let disconnected = self.mesh.get().map_or(0, |m| m.disconnect(&|ip| range.contains(ip)));
        println!(
            "sentinel: ban applied {} for {}s ({} session(s) closed): {}",
            ban.range, ban.ttl_secs, disconnected, ban.reason
        );
        self.emit(
            "ban_applied",
            vec![
                ("range", Json::s(ban.range.to_string())),
                ("ttl_secs", Json::u(ban.ttl_secs)),
                ("reason", Json::s(ban.reason.clone())),
                ("disconnected", Json::u(disconnected as u64)),
            ],
        );
        Ok((ban, disconnected))
    }

    pub(crate) fn unban(&self, range: Cidr) -> Option<bans::Ban> {
        let gone = lock(&self.bans).unban(&range)?;
        println!("sentinel: ban removed {}", gone.range);
        self.emit("ban_removed", vec![("range", Json::s(gone.range.to_string())), ("by", Json::s("admin"))]);
        Some(gone)
    }

    /// Expire bans, emitting `ban_expired` for each. Called by the sweeper.
    pub(crate) fn sweep(&self, now: Instant) {
        let gone = lock(&self.bans).expire(now);
        for b in gone {
            println!("sentinel: ban expired {}", b.range);
            self.emit("ban_expired", vec![("range", Json::s(b.range.to_string())), ("ttl_secs", Json::u(b.ttl_secs))]);
        }
    }

    pub(crate) fn bans_json(&self, now: Instant) -> Json {
        let table = lock(&self.bans);
        let entries: Vec<Json> = table
            .active(now)
            .map(|b| {
                Json::obj(vec![
                    ("range", Json::s(b.range.to_string())),
                    ("reason", Json::s(b.reason.clone())),
                    ("ttl_secs", Json::u(b.ttl_secs)),
                    ("expires_in_secs", Json::u(b.remaining_secs(now))),
                    ("created_ms", Json::u(b.created_ms)),
                ])
            })
            .collect();
        Json::obj(vec![
            ("active", Json::u(entries.len() as u64)),
            ("max", Json::u(bans::MAX_ACTIVE_BANS as u64)),
            ("refused_connections", Json::u(self.refused_by_ban.load(Ordering::Relaxed))),
            ("entries", Json::Arr(entries)),
        ])
    }

    pub(crate) fn note_admin_command(&self) {
        self.admin_commands.fetch_add(1, Ordering::Relaxed);
    }

    // ── getsecuritystatus ───────────────────────────────────────────────

    pub(crate) fn status_json(&self) -> Json {
        let now = Instant::now();
        let chain = lock(&self.chain).clone();
        let chain_json = match &chain {
            None => Json::obj(vec![("published", Json::Bool(false))]),
            Some((c, at)) => Json::obj(vec![
                ("published", Json::Bool(true)),
                ("updated_ms", Json::u(*at)),
                ("live", Json::Bool(c.live)),
                ("wall_slot", Json::u(c.wall_slot)),
                ("wall_epoch", Json::u(c.wall_epoch)),
                (
                    "head",
                    Json::obj(vec![
                        ("slot", Json::u(c.head_slot)),
                        ("epoch", Json::u(bloch_pos_committee::epoch_of(c.head_slot))),
                        ("height", Json::u(c.head_height)),
                        ("root", Json::hex(&c.head_root)),
                    ]),
                ),
                ("justified", Json::obj(vec![("epoch", Json::u(c.justified_epoch)), ("root", Json::hex(&c.justified_root))])),
                (
                    "finalized",
                    Json::obj(vec![
                        ("epoch", Json::u(c.finalized_epoch)),
                        ("root", Json::hex(&c.finalized_root)),
                        ("height", c.finalized_height.map_or(Json::Null, Json::u)),
                    ]),
                ),
                (
                    "finalized_latch",
                    c.latch.map_or(Json::Null, |(h, r)| Json::obj(vec![("height", Json::u(h)), ("root", Json::hex(&r))])),
                ),
                ("finality_lag_epochs", Json::u(c.wall_epoch.saturating_sub(c.finalized_epoch))),
                ("lag_thresholds_epochs", Json::Arr(LAG_THRESHOLDS.iter().map(|t| Json::u(*t)).collect())),
            ]),
        };

        let adverts = lock(&self.adverts).live(now);
        let evicted = lock(&self.adverts).evicted;
        let advert_json = Json::obj(vec![
            ("count", Json::u(adverts.len() as u64)),
            ("max_entries", Json::u(adverts::MAX_ENTRIES as u64)),
            ("entry_ttl_secs", Json::u(adverts::ENTRY_TTL.as_secs())),
            ("evicted", Json::u(evicted)),
            (
                "entries",
                Json::Arr(
                    adverts
                        .iter()
                        .map(|e| {
                            Json::obj(vec![
                                ("source", Json::s(crate::codec::hex8(&e.obs.source))),
                                ("addr", e.addr.map_or(Json::Null, |a| Json::s(a.to_string()))),
                                ("kind", Json::s(e.obs.kind.as_str())),
                                ("advertised_finalized_root", Json::hex(&e.obs.advertised_finalized)),
                                ("advertised_justified_root", Json::hex(&e.obs.advertised_justified)),
                                ("root_slot", e.obs.root_slot.map_or(Json::Null, Json::u)),
                                ("epoch_hint", e.obs.epoch_hint.map_or(Json::Null, Json::u)),
                                ("our_finalized_epoch", Json::u(e.obs.our_finalized_epoch)),
                                ("block_root", Json::hex(&e.obs.block_root)),
                                ("block_slot", Json::u(e.obs.block_slot)),
                                ("verdict", Json::s(e.obs.verdict)),
                                ("count", Json::u(e.count)),
                                ("first_seen_ms", Json::u(e.first_seen_ms)),
                                ("last_seen_ms", Json::u(e.last_seen_ms)),
                            ])
                        })
                        .collect(),
                ),
            ),
        ]);

        let names = lock(&self.names);
        let verdicts = lock(&self.verdicts);
        let overflow = verdicts.overflow(now);
        let verdict_json = Json::obj(vec![
            ("window_secs", Json::u(verdicts.window_secs())),
            ("tracked_sources", Json::u(verdicts.tracked() as u64)),
            ("max_sources", Json::u(window::MAX_SOURCES as u64)),
            ("total_rejected", Json::u(verdicts.totals().a)),
            ("total_ignored", Json::u(verdicts.totals().b)),
            ("overflow", Json::obj(vec![("rejected", Json::u(overflow.a)), ("ignored", Json::u(overflow.b))])),
            (
                "top",
                Json::Arr(
                    verdicts
                        .top(window::TOP_N, now)
                        .into_iter()
                        .map(|(src, c)| {
                            Json::obj(vec![
                                ("source", Json::s(crate::codec::hex8(&src))),
                                ("addr", names.name(&src).map_or(Json::Null, |a| Json::s(a.to_string()))),
                                ("rejected", Json::u(c.a)),
                                ("ignored", Json::u(c.b)),
                            ])
                        })
                        .collect(),
                ),
            ),
        ]);
        drop(verdicts);
        drop(names);

        let hs = lock(&self.handshakes);
        let hs_overflow = hs.overflow(now);
        let handshake_json = Json::obj(vec![
            ("window_secs", Json::u(hs.window_secs())),
            ("tracked_sources", Json::u(hs.tracked() as u64)),
            ("total_attempts", Json::u(hs.totals().a)),
            ("total_failures", Json::u(hs.totals().b)),
            ("overflow", Json::obj(vec![("attempts", Json::u(hs_overflow.a)), ("failures", Json::u(hs_overflow.b))])),
            (
                "top",
                Json::Arr(
                    hs.top(window::TOP_N, now)
                        .into_iter()
                        .map(|(ip, c)| {
                            Json::obj(vec![
                                ("addr", Json::s(ip.to_string())),
                                ("attempts", Json::u(c.a)),
                                ("failures", Json::u(c.b)),
                            ])
                        })
                        .collect(),
                ),
            ),
        ]);
        drop(hs);

        let peers_json = self.peers_json(chain.as_ref().map(|(c, _)| c));

        let (dopp_json, kes_json) = match &chain {
            None => (Json::Null, Json::Null),
            Some((c, _)) => {
                let d = &c.doppelganger;
                let dopp = Json::obj(vec![
                    ("state", Json::s(d.state(c.wall_slot))),
                    ("halted", Json::Bool(d.halted)),
                    ("observe_until_slot", d.observe_until_slot.map_or(Json::Null, Json::u)),
                ]);
                let k = &c.kes;
                let last_error = lock(&self.kes_error).clone();
                let kes = Json::obj(vec![
                    ("validator", k.validator.map_or(Json::Null, |v| Json::u(u64::from(v)))),
                    ("keystore_loaded", Json::Bool(k.keystore_loaded)),
                    ("kes_key_loaded", Json::Bool(k.kes_key_loaded)),
                    ("mode", Json::s(k.mode)),
                    ("mode_epoch", Json::u(c.wall_epoch)),
                    ("period", k.period.map_or(Json::Null, Json::u)),
                    (
                        "bind_epoch",
                        match k.bind_epoch {
                            None => Json::s("unknown"),
                            Some(None) => Json::Null,
                            Some(Some(e)) => Json::u(e),
                        },
                    ),
                    ("bound", Json::Bool(matches!(k.bind_epoch, Some(Some(e)) if c.wall_epoch >= e))),
                    ("state_epoch", Json::u(k.head_state_epoch)),
                    ("state_rolled_to_wall_epoch", Json::Bool(k.head_state_epoch >= c.wall_epoch)),
                    (
                        "last_error",
                        last_error.map_or(Json::Null, |e| {
                            Json::obj(vec![
                                ("duty", Json::s(e.duty)),
                                ("class", Json::s(e.class)),
                                ("validator", Json::u(u64::from(e.validator))),
                                ("wall_slot", Json::u(e.wall_slot)),
                                ("at_ms", Json::u(e.at_ms)),
                                ("consecutive", Json::u(e.count)),
                            ])
                        }),
                    ),
                ]);
                (dopp, kes)
            }
        };

        Json::obj(vec![
            ("schema", Json::s(STATUS_SCHEMA)),
            ("node_local", Json::Bool(true)),
            ("generated_ms", Json::u(unix_ms())),
            (
                "enabled",
                Json::obj(vec![
                    ("status", Json::Bool(true)),
                    ("events", Json::Bool(self.events.is_some())),
                    ("admin_socket", Json::Bool(self.cfg.admin_socket.is_some())),
                ]),
            ),
            ("chain", chain_json),
            ("peer_finalized_ahead", advert_json),
            ("gossip_verdicts", verdict_json),
            ("handshakes", handshake_json),
            ("peers", peers_json),
            ("doppelganger", dopp_json),
            ("kes", kes_json),
            ("bans", self.bans_json(now)),
            ("events", self.events.as_ref().map_or_else(|| Json::obj(vec![("enabled", Json::Bool(false))]), |e| e.stats_json())),
            ("admin_commands", Json::u(self.admin_commands.load(Ordering::Relaxed))),
        ])
    }

    fn peers_json(&self, chain: Option<&ChainSnapshot>) -> Json {
        let inbound = self.mesh.get().map(|m| m.inbound_addrs()).unwrap_or_default();
        let mut v4: HashMap<Cidr, u64> = HashMap::new();
        let mut v6: HashMap<Cidr, u64> = HashMap::new();
        for ip in &inbound {
            let bucket = cidr::concentration_bucket(*ip);
            *(if bucket.is_v4() { &mut v4 } else { &mut v6 }).entry(bucket).or_insert(0) += 1;
        }
        let top = |m: HashMap<Cidr, u64>| -> (Json, u64) {
            let mut v: Vec<(Cidr, u64)> = m.into_iter().collect();
            v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.to_string().cmp(&b.0.to_string())));
            let max = v.first().map_or(0, |x| x.1);
            let buckets = v.len() as u64;
            v.truncate(MAX_BUCKETS_REPORTED);
            let arr = Json::Arr(v.into_iter().map(|(c, n)| Json::obj(vec![("prefix", Json::s(c.to_string())), ("count", Json::u(n))])).collect());
            (Json::obj(vec![("buckets", Json::u(buckets)), ("max_in_one", Json::u(max)), ("top", arr)]), max)
        };
        let (v4_json, _) = top(v4);
        let (v6_json, _) = top(v6);
        Json::obj(vec![
            ("transport", chain.map_or(Json::Null, |c| Json::s(c.transport))),
            ("devnet_connections", chain.and_then(|c| c.devnet_peers).map_or(Json::Null, |n| Json::u(n as u64))),
            ("libp2p_peers", chain.and_then(|c| c.libp2p_peers).map_or(Json::Null, |n| Json::u(n as u64))),
            ("mesh_inbound", Json::u(inbound.len() as u64)),
            ("configured_peers", Json::u(self.cfg.peers.len() as u64)),
            ("inbound_by_v4_24", v4_json),
            ("inbound_by_v6_64", v6_json),
        ])
    }
}

// ── Global handle ───────────────────────────────────────────────────────────

static GLOBAL: OnceLock<Arc<Sentinel>> = OnceLock::new();

#[cfg(test)]
thread_local! {
    static TEST_OVERRIDE: std::cell::RefCell<Option<Arc<Sentinel>>> = const { std::cell::RefCell::new(None) };
}

/// The running Sentinel, or `None` when no Sentinel flag was given — which
/// is the default, and makes every hook a no-op.
pub(crate) fn current() -> Option<Arc<Sentinel>> {
    #[cfg(test)]
    {
        if let Some(s) = TEST_OVERRIDE.with(|t| t.borrow().clone()) {
            return Some(s);
        }
    }
    GLOBAL.get().cloned()
}

/// Run `f` with `s` as this thread's Sentinel (tests only).
#[cfg(test)]
pub(crate) fn with_test_sentinel<R>(s: Arc<Sentinel>, f: impl FnOnce() -> R) -> R {
    TEST_OVERRIDE.with(|t| *t.borrow_mut() = Some(s));
    let out = f();
    TEST_OVERRIDE.with(|t| *t.borrow_mut() = None);
    out
}

#[cfg(test)]
pub(crate) fn test_sentinel(cfg: Config) -> Arc<Sentinel> {
    Arc::new(Sentinel::new(cfg, Some(events::EventSink::capture())))
}

#[cfg(test)]
pub(crate) fn captured_events(s: &Sentinel) -> Vec<String> {
    s.events.as_ref().map(|e| e.captured.lock().map(|c| c.clone()).unwrap_or_default()).unwrap_or_default()
}

/// Start the Sentinel per `cfg`. Must run before the engine starts its
/// threads (the admin socket is created under a temporary umask). A no-op
/// returning `Ok` when `cfg` enables nothing.
pub(crate) fn start(cfg: Config) -> Result<(), String> {
    if !cfg.enabled() {
        return Ok(());
    }
    // The socket first: it is the one with a umask window.
    let listener = match &cfg.admin_socket {
        Some(path) => Some(admin::bind(path)?),
        None => None,
    };
    let events = match &cfg.events {
        Some(path) => Some(
            events::EventSink::start(path).map_err(|e| format!("--security-events {}: {e}", path.display()))?,
        ),
        None => None,
    };
    let sentinel = Arc::new(Sentinel::new(cfg.clone(), events));
    if GLOBAL.set(sentinel.clone()).is_err() {
        return Err("sentinel already started".into());
    }
    if let Some(listener) = listener {
        let s = sentinel.clone();
        std::thread::Builder::new()
            .name("sentinel-admin".into())
            .spawn(move || admin::serve(listener, s))
            .map_err(|e| format!("--admin-socket: cannot start its thread: {e}"))?;
        let s = sentinel.clone();
        std::thread::Builder::new()
            .name("sentinel-sweep".into())
            .spawn(move || loop {
                std::thread::sleep(Duration::from_secs(1));
                s.sweep(Instant::now());
            })
            .map_err(|e| format!("--admin-socket: cannot start the ban sweeper: {e}"))?;
    }
    println!(
        "sentinel: node-local security hooks ON (status: yes, events: {}, admin socket: {}); \
         no consensus effect",
        cfg.events.as_ref().map_or("off".to_string(), |p| p.display().to_string()),
        cfg.admin_socket.as_ref().map_or("off".to_string(), |p| p.display().to_string()),
    );
    Ok(())
}

// ── Hook entry points (each a no-op when the Sentinel is off) ──────────────

/// `getsecuritystatus`, or `None` when the Sentinel is off (the RPC then
/// answers "method not found", as a node without it would).
pub(crate) fn status_rpc() -> Option<Json> {
    current().map(|s| s.status_json())
}

/// Mesh accept path: should this inbound connection be closed now?
pub(crate) fn refuse_inbound(ip: IpAddr, configured: bool) -> bool {
    let Some(s) = current() else { return false };
    s.learn_source(ip);
    s.note_handshake(ip, 1, 0);
    s.refuse_inbound(ip, configured)
}

pub(crate) fn note_handshake_failure(ip: IpAddr) {
    if let Some(s) = current() {
        s.note_handshake(ip, 0, 1);
    }
}

/// A connection this node dialed: learn the source name for reports.
pub(crate) fn note_outbound(ip: IpAddr) {
    if let Some(s) = current() {
        s.learn_source(ip);
    }
}

pub(crate) fn note_verdict(source: Option<[u8; 32]>, verdict: crate::net::Verdict) {
    if let Some(s) = current() {
        s.note_verdict(source, verdict);
    }
}

pub(crate) fn note_kes_error(duty: &'static str, validator: u32, why: &str) {
    if let Some(s) = current() {
        s.note_kes_error(duty, validator, why);
    }
}

pub(crate) fn register_mesh(view: impl FnOnce() -> Box<dyn MeshView>) {
    if let Some(s) = current() {
        s.register_mesh(view());
    }
}

pub(crate) fn enabled() -> bool {
    current().is_some()
}

pub(crate) fn verdict_name(v: crate::net::Verdict) -> &'static str {
    verdict_str(v)
}
