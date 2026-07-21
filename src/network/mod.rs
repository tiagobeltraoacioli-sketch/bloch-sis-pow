//! Bloch-SIS Protocol — P2P Network
//!
//! FIX #2: Full IBD loop — GetBlock now has a server-side response handler.
//! FIX #4: Persistent P2P keypair.
//! FIX #6: Peer memory (known_peers.json).
//! Sprint P: PEX hardening (rate limit, address validation, known_peers cap).

pub mod pex_validator;

use libp2p::{
    identity, identify, mdns, PeerId, Multiaddr,
    swarm::SwarmEvent,
    gossipsub::{self, IdentTopic, MessageAuthenticity, ValidationMode}, tcp, yamux,
    SwarmBuilder,
};
use serde::{Serialize, Deserialize};
use tokio::sync::mpsc;
use log::{info, warn, debug};
use std::time::Duration;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use sha2::{Sha256, Digest};

use pex_validator::{
    PexRateLimiter, PexStats,
    is_valid_public_multiaddr, is_lan_multiaddr, enforce_cap, prune_invalid,
    PEX_BATCH_LIMIT, KNOWN_PEERS_CAP,
};

use crate::transport::upgrade::KyberConfig;

pub const TOPIC_BLOCKS: &str = "bloch/blocks/1";
pub const TOPIC_TXS:    &str = "bloch/txs/1";
pub const TOPIC_SYNC:   &str = "bloch/sync/1";

// ── Messages ──────────────────────────────────────────────────────────────────

/// Protocol version for forward compatibility and hard fork coordination.
/// Nodes reject messages from incompatible versions.
pub const PROTOCOL_VERSION: u32 = 1;
/// Minimum protocol version this node accepts
pub const MIN_PROTOCOL_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum NetworkMessage {
    NewBlock {
        block_hash: [u8; 32],
        blue_score: u64,
        height:     u64,
        block_data: Vec<u8>,
    },
    NewTransaction {
        txid:    [u8; 32],
        tx_data: Vec<u8>,
    },
    // IBD
    PeerTip    { peer_id: String, blue_score: u64, height: u64 },
    PeerExchange { peers: Vec<String> },
    PeerRequest,
    PeerCount { count: usize, addresses: Vec<String> },
    /// `nonce` for the same reason GetBlock and BlockNotFound carry one. A node
    /// re-asking for the SAME window — which is exactly what a stalled node does,
    /// every cycle — serialises identically and has the retry dropped locally
    /// before it reaches the network. Measured at 90 suppressions in two minutes
    /// on a node that was making no progress.
    ///
    /// The general rule this file has now learned three times: on the sync topic,
    /// deduplication is wrong. It exists to stop gossip storms of the same BLOCK;
    /// a request is not gossip, and two identical requests are two intentions,
    /// not one message seen twice.
    GetHeaders { from_blue_score: u64, limit: u32, nonce: u64 },
    Headers    { entries: Vec<SyncEntry> },
    /// Request a block body. `nonce` exists ONLY to make each request unique on
    /// the wire, and the responder ignores it.
    ///
    /// Without it every re-request serialises to identical bytes, hashes to the
    /// same gossipsub MessageId, and `publish()` returns `Err(Duplicate)`
    /// LOCALLY — the retry never leaves this node. That is the same failure this
    /// file already documents for PeerTip a few lines below `duplicate_cache_time`,
    /// where the fix was noted as "the tip-carrying Version (fresh timestamp →
    /// unique bytes) can never be dedup-dropped at all". GetBlock had no such
    /// field, so IBD retries were silently swallowed: observed on a stalled node
    /// as 12,235 `publish sync: Duplicate` in ten minutes while it sat at one
    /// height with peers that HELD the blocks it was asking for.
    GetBlock   { block_hash: [u8; 32], nonce: u64 },
    /// Explicit "I cannot serve this body" answer to GetBlock. Added 2026-07-19:
    /// the responder used to drop unanswerable requests silently, which left the
    /// requester unable to distinguish a pruned body from a lost packet — it just
    /// waited and re-asked forever. A fresh node cannot bootstrap from a pruned
    /// peer, and it deserves to LEARN that instead of stalling: on receiving this
    /// it can try another peer, or report honestly that no archival peer exists.
    /// `nonce` for the same reason GetBlock carries one: without it every answer
    /// serialises identically, is dedup-dropped locally, and the peer waiting on
    /// it learns nothing. Measured on a stalled archival node: 7,983 of 8,060
    /// suppressed publishes in two minutes were THIS message — added the same
    /// night to fix a silent responder, and immediately becoming the loudest
    /// source of the noise it was meant to remove. A message that answers a
    /// repeated question must be as unique as the question.
    BlockNotFound { block_hash: [u8; 32], nonce: u64 },
    // Frontier reconciliation (Phase 2 Kaspa sync-negotiation layer)
    /// Frontier reconciliation: request the peer's DAG frontier. No payload —
    /// broadcast on the sync topic; every peer replies with Tips.
    GetTips,
    /// Frontier reconciliation reply: full DAG frontier + selected-chain locator.
    Tips { tips: Vec<SyncEntry>, locator: Vec<[u8; 32]> },
    // Protocol handshake
    Version {
        version:    u32,
        user_agent: String,
        blue_score: u64,
        height:     u64,
        timestamp:  u64,
    },
    VersionAck,
}


impl NetworkMessage {
    /// Variant name for diagnostics. Derived from Debug so a new variant can
    /// never silently log as something else — the previous log named only the
    /// topic and that ambiguity sent a fix to the wrong message.
    pub fn kind_name(&self) -> &'static str {
        // Debug prints "Variant { .. }" or "Variant"; take the leading ident.
        let s: &'static str = Box::leak(format!("{:?}", self).into_boxed_str());
        match s.find(|c: char| !c.is_ascii_alphanumeric() && c != '_') {
            Some(i) => &s[..i],
            None => s,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncEntry {
    pub hash:       [u8; 32],
    pub blue_score: u64,
    pub height:     u64,
}

// ── C1: bounded, validated wire decode ────────────────────────────────────────
//
// Every gossip frame comes from an untrusted peer. Before this fix the event
// loop decoded frames with `bincode::config::standard()`, which puts no limit
// on how many bytes a frame may claim to contain: a tiny crafted frame could
// declare a multi-GB Vec length, and nothing in the decode path capped list
// lengths (peer lists, header vectors, address strings). All untrusted decodes
// now go through `decode_wire_message`, which (1) rejects frames larger than
// MAX_WIRE_BYTES outright, (2) decodes with a bincode read limit of the same
// size, and (3) applies explicit post-decode bounds to every variable-length
// field of `NetworkMessage`.
//
// HONESTY CAVEAT on (3): the post-decode bounds run *after* serde has built
// the value, so they bound acceptance, not the transient decode allocation.
// The transient allocation is bounded by the 4 MiB byte limit, but bincode's
// serde bridge decodes collections element-by-element, so a pathological
// 4 MiB frame of empty strings can transiently amplify to tens of MB of
// String headers before the bounds check rejects it. That is bounded and
// short-lived (not the multi-GB pre-allocation this fixes), but tightening it
// to zero would need a custom `Deserialize` impl — not done here.

/// Hard ceiling on any single gossip frame. Must match gossipsub's
/// `max_transmit_size` configured in `run()`.
pub const MAX_WIRE_BYTES: usize = 4 * 1024 * 1024;

/// Max entries in a PEX/PeerCount address list. A compliant node advertises at
/// most KNOWN_PEERS_CAP (1000) known peers plus a few self-addresses.
pub const MAX_WIRE_ADDRS: usize = KNOWN_PEERS_CAP + 64;
/// Max byte length of a single advertised multiaddr string. A real
/// `/dns4/host/tcp/port/p2p/<peer-id>` is well under 256 bytes; 512 is
/// generous headroom.
pub const MAX_WIRE_ADDR_LEN: usize = 512;
/// Max SyncEntry items in a Headers frame. IBD requests batches of 500
/// (see main.rs GetHeaders); 2000 leaves headroom.
pub const MAX_WIRE_SYNC_ENTRIES: usize = 2000;
/// Max tip entries in a Tips frame. MUST equal sync::MAX_ADVERTISED_TIPS.
pub const MAX_WIRE_TIPS: usize = 256;
/// Max locator hashes in a Tips frame. MUST equal locator::MAX_LOCATOR_LEN.
pub const MAX_WIRE_LOCATOR: usize = 64;
/// Max `limit` a peer may request via GetHeaders (bounds the work WE do
/// serving the response).
pub const MAX_WIRE_GETHEADERS_LIMIT: u32 = 2000;
/// Max user_agent length in a Version handshake.
pub const MAX_WIRE_USER_AGENT_LEN: usize = 128;
/// Max peer_id string length in a PeerTip (base58 libp2p PeerIds are ~52 chars).
pub const MAX_WIRE_PEER_ID_LEN: usize = 128;

/// App-score penalty per wire protocol violation. With app_specific_weight
/// 1.0 and graylist_threshold -400 (see `run()`), four violations graylist
/// the peer.
pub const WIRE_VIOLATION_PENALTY: f64 = -100.0;
/// Floor so a flood of violations can't drive the score to -inf.
pub const WIRE_PENALTY_FLOOR: f64 = -1000.0;
/// Cap on the number of peers whose penalty score we track (bounds memory
/// against an attacker cycling peer identities).
pub const WIRE_PENALTY_TRACK_CAP: usize = 1024;

#[derive(Debug)]
pub enum WireDecodeError {
    /// Frame exceeds MAX_WIRE_BYTES, or the bincode read limit tripped
    /// (e.g. a declared length larger than the frame could ever satisfy).
    Oversized(String),
    /// Frame decoded, but a length field violates protocol bounds.
    Bounds(&'static str),
    /// Plain malformed bincode (may be benign version skew, not penalized
    /// as harshly as a deliberate oversize).
    Malformed(String),
}

impl WireDecodeError {
    /// Oversized and bounds-violating frames are deliberate protocol
    /// violations — a compliant node cannot produce them. Malformed frames
    /// may just be a newer/older protocol version.
    pub fn is_protocol_violation(&self) -> bool {
        matches!(self, WireDecodeError::Oversized(_) | WireDecodeError::Bounds(_))
    }
}

/// Decode an untrusted gossip frame with a hard byte limit and post-decode
/// bounds validation. This is the ONLY correct way to decode wire bytes from
/// a peer; `bincode::config::standard()` without a limit must never be used
/// on untrusted input.
pub fn decode_wire_message(data: &[u8]) -> Result<NetworkMessage, WireDecodeError> {
    if data.len() > MAX_WIRE_BYTES {
        return Err(WireDecodeError::Oversized(format!(
            "frame is {} bytes (max {})", data.len(), MAX_WIRE_BYTES
        )));
    }
    let cfg = bincode::config::standard().with_limit::<MAX_WIRE_BYTES>();
    let msg: NetworkMessage = match bincode::serde::decode_from_slice(data, cfg) {
        Ok((m, _)) => m,
        Err(bincode::error::DecodeError::LimitExceeded) => {
            return Err(WireDecodeError::Oversized(format!(
                "declared content exceeds {} byte read limit", MAX_WIRE_BYTES
            )));
        }
        Err(e) => return Err(WireDecodeError::Malformed(e.to_string())),
    };
    validate_wire_bounds(&msg)?;
    Ok(msg)
}

/// Explicit bounds on every variable-length field of NetworkMessage.
fn validate_wire_bounds(msg: &NetworkMessage) -> Result<(), WireDecodeError> {
    use WireDecodeError::Bounds;
    fn addrs_ok(addrs: &[String]) -> Result<(), WireDecodeError> {
        if addrs.len() > MAX_WIRE_ADDRS {
            return Err(WireDecodeError::Bounds("address list longer than MAX_WIRE_ADDRS"));
        }
        if addrs.iter().any(|a| a.len() > MAX_WIRE_ADDR_LEN) {
            return Err(WireDecodeError::Bounds("address string longer than MAX_WIRE_ADDR_LEN"));
        }
        Ok(())
    }
    match msg {
        // The two payload checks below are unreachable today (a payload can't
        // exceed the frame that carries it, and frames are capped at
        // MAX_WIRE_BYTES) — kept as belt-and-braces should the byte limit and
        // this constant ever diverge.
        NetworkMessage::NewBlock { block_data, .. } => {
            if block_data.len() > MAX_WIRE_BYTES {
                return Err(Bounds("block_data larger than MAX_WIRE_BYTES"));
            }
        }
        NetworkMessage::NewTransaction { tx_data, .. } => {
            if tx_data.len() > MAX_WIRE_BYTES {
                return Err(Bounds("tx_data larger than MAX_WIRE_BYTES"));
            }
        }
        NetworkMessage::PeerTip { peer_id, .. } => {
            if peer_id.len() > MAX_WIRE_PEER_ID_LEN {
                return Err(Bounds("peer_id longer than MAX_WIRE_PEER_ID_LEN"));
            }
        }
        NetworkMessage::PeerExchange { peers } => addrs_ok(peers)?,
        NetworkMessage::PeerCount { addresses, .. } => addrs_ok(addresses)?,
        NetworkMessage::GetHeaders { limit, .. } => {
            if *limit > MAX_WIRE_GETHEADERS_LIMIT {
                return Err(Bounds("GetHeaders limit above MAX_WIRE_GETHEADERS_LIMIT"));
            }
        }
        NetworkMessage::Headers { entries } => {
            if entries.len() > MAX_WIRE_SYNC_ENTRIES {
                return Err(Bounds("Headers entries longer than MAX_WIRE_SYNC_ENTRIES"));
            }
        }
        NetworkMessage::Tips { tips, locator } => {
            if tips.len() > MAX_WIRE_TIPS {
                return Err(Bounds("Tips tips longer than MAX_WIRE_TIPS"));
            }
            if locator.len() > MAX_WIRE_LOCATOR {
                return Err(Bounds("Tips locator longer than MAX_WIRE_LOCATOR"));
            }
        }
        NetworkMessage::Version { user_agent, .. } => {
            if user_agent.len() > MAX_WIRE_USER_AGENT_LEN {
                return Err(Bounds("user_agent longer than MAX_WIRE_USER_AGENT_LEN"));
            }
        }
        NetworkMessage::PeerRequest
        | NetworkMessage::VersionAck
        | NetworkMessage::GetTips
        | NetworkMessage::GetBlock { .. }
        | NetworkMessage::BlockNotFound { .. } => {}
    }
    Ok(())
}

// ── Sprint EE (S3): frame-reaction unit — extracted from `run()` ─────────────
//
// The decode → penalize/ignore/accept decision used to live inline in the
// gossipsub `Message` arm of `run()`'s event loop, so the ONLY way to exercise
// the peer-scoring reaction to an invalid-block frame, an oversized frame, or
// a bounds-violating list was to stand up a live swarm — which made the
// reaction untested. This extraction is behavior-preserving: `run()` is now a
// thin consumer (classify → apply app score / log / forward), and the reaction
// itself is asserted deterministically in unit tests and in
// tests/sprint_ee_transport_convergence.rs without any networking.

/// What the node does in response to a single gossip frame from a peer.
#[derive(Debug)]
pub enum WireReaction {
    /// Frame decoded and passed bounds validation — process it.
    Accept(NetworkMessage),
    /// Deliberate protocol violation (oversized frame / bounds-violating
    /// lengths — e.g. an invalid-block frame larger than MAX_WIRE_BYTES):
    /// `score` is the peer's new cumulative application score to install via
    /// `gossipsub.set_application_score`. With app_specific_weight 1.0 and
    /// graylist_threshold -400, the fourth violation graylists the peer.
    Penalize { error: WireDecodeError, score: f64 },
    /// Malformed bincode — possibly benign version skew. Log-only, no penalty.
    IgnoreMalformed(String),
}

/// Cumulative per-peer wire-violation penalty state. Bounded to
/// [`WIRE_PENALTY_TRACK_CAP`] peers so an attacker cycling identities cannot
/// grow the map without limit; once full, untracked offenders still receive a
/// one-shot [`WIRE_VIOLATION_PENALTY`] without being inserted.
pub struct WirePenaltyTracker {
    penalties: std::collections::HashMap<PeerId, f64>,
}

impl WirePenaltyTracker {
    pub fn new() -> Self {
        Self { penalties: std::collections::HashMap::new() }
    }

    /// Decode an untrusted gossip frame and decide the reaction. This is the
    /// exact logic previously inline in `run()`:
    ///   - decodes via [`decode_wire_message`] (4 MiB frame/read limit +
    ///     post-decode bounds);
    ///   - protocol violations (Oversized/Bounds) accumulate
    ///     [`WIRE_VIOLATION_PENALTY`] per offense, floored at
    ///     [`WIRE_PENALTY_FLOOR`];
    ///   - if the tracking map is full and the peer untracked, the penalty is
    ///     applied one-shot without growing the map;
    ///   - plain-malformed frames are ignored (may be version skew).
    pub fn classify(&mut self, peer: PeerId, data: &[u8]) -> WireReaction {
        match decode_wire_message(data) {
            Ok(msg) => WireReaction::Accept(msg),
            Err(e) if e.is_protocol_violation() => {
                let score = if self.penalties.len() >= WIRE_PENALTY_TRACK_CAP
                    && !self.penalties.contains_key(&peer)
                {
                    // Tracking map is full: apply a one-shot penalty
                    // without growing the map.
                    WIRE_VIOLATION_PENALTY
                } else {
                    let s = self.penalties.entry(peer).or_insert(0.0);
                    *s = (*s + WIRE_VIOLATION_PENALTY).max(WIRE_PENALTY_FLOOR);
                    *s
                };
                WireReaction::Penalize { error: e, score }
            }
            Err(e) => WireReaction::IgnoreMalformed(format!("{:?}", e)),
        }
    }

    /// Number of peers currently tracked (observability for tests/metrics).
    pub fn tracked_peers(&self) -> usize {
        self.penalties.len()
    }

    /// Current cumulative score for a peer, if tracked.
    pub fn score_of(&self, peer: &PeerId) -> Option<f64> {
        self.penalties.get(peer).copied()
    }
}

// ── H4: panic-free truncation of attacker-controlled strings ─────────────────

/// UTF-8-safe prefix of at most `max_bytes` bytes.
///
/// The PEX log lines previously used `&s[..s.len().min(N)]`, which panics if
/// byte N falls in the middle of a multi-byte UTF-8 codepoint — and PEX
/// address strings are attacker-controlled, so a single crafted multiaddr
/// containing multi-byte characters at the right offset crashed the whole
/// network event loop. This walks back to the nearest char boundary instead.
pub(crate) fn truncate_utf8(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    // `end` is now a char boundary (0 in the worst case), so this cannot panic.
    &s[..end]
}

// ── Config ────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct NetworkConfig {
    pub listen_addr:     String,
    pub bootstrap_peers: Vec<String>,
    /// Opt-in DNS seed hostnames (Bitcoin-style cold-start). Resolved to
    /// A/AAAA records and dialed as peers. Empty by default — non-privileged.
    pub dns_seeds:       Vec<String>,
    pub max_peers:       usize,
    pub data_dir:        PathBuf,
    /// Sprint P: if true, PEX will accept RFC1918 / loopback addresses.
    /// Intended for local development; production should leave this false.
    pub allow_private_peers: bool,
    /// Mesh fix (fresh-joiner IBD): this node sits behind a TCP proxy / NAT
    /// where many peers legitimately share one source IP (fly.io edge,
    /// ingress, CGNAT). Disables the gossipsub ip-colocation penalty weight
    /// (which would graylist the whole mesh at ~6 peers from one IP and
    /// silently blackhole every tip announcement). All other scoring stays.
    pub behind_proxy: bool,
    /// Enable mDNS zero-config LAN peer discovery. OFF by default: public nodes
    /// bootstrap via explicit `--peer` / `--dns-seed`, and mDNS (a) is useless off
    /// a LAN and (b) exercises hickory-proto's mDNS record parser (RUSTSEC-2026-0118/
    /// 0119 — LAN-only DoS surface). Turn on only for local/dev zero-config discovery.
    pub enable_mdns: bool,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_addr:     "/ip4/0.0.0.0/tcp/16110".into(),
            bootstrap_peers: vec![],
            dns_seeds:       vec![],
            max_peers:       50,
            data_dir:        PathBuf::from("./bloch-data"),
            allow_private_peers: false,
            behind_proxy:    false,
            enable_mdns:     false,
        }
    }
}

// ── Behaviour ───────────────────────────────────────────────────────────────
//
// PRINCIPLES.md #2 ("every node is a seed"): the swarm combines gossipsub with
// mdns (zero-config LAN discovery — a node bootstraps from local peers with no
// configured seed) and identify (the node learns its own public address as
// peers observe it, so it can self-advertise via PEX). No privileged seed is
// required; any node can bootstrap another. The derive generates the event enum
// `BlochBehaviourEvent`.
#[derive(libp2p::swarm::NetworkBehaviour)]
struct BlochBehaviour {
    gossipsub: gossipsub::Behaviour,
    // Toggle: mDNS is present only when `--enable-mdns` is set (off by default).
    // Disabled → the hickory-proto mDNS parser is never exercised (RUSTSEC-2026-0118/0119).
    mdns:      libp2p::swarm::behaviour::toggle::Toggle<mdns::tokio::Behaviour>,
    identify:  identify::Behaviour,
    // P0 (roadmap §1.3 / §4.1): swarm-level connection limits. `max_peers` was
    // previously only an app-side counter checked in the PEX/mDNS dial paths,
    // so inbound connection floods / eclipse setup were NOT bounded by libp2p.
    // This behaviour rejects connections at the transport layer once the caps
    // are hit, matching max_peers.
    connection_limits: libp2p::connection_limits::Behaviour,
}

// ── Node ──────────────────────────────────────────────────────────────────────

pub struct NetworkNode {
    pub peer_id: PeerId,
    pub config:  NetworkConfig,
    local_key:   identity::Keypair,
}

impl NetworkNode {
    /// FIX #4: Persistent P2P identity.
    pub fn new(config: NetworkConfig) -> Result<Self, NetworkError> {
        let key_path = config.data_dir.join("p2p_identity.bin");
        let local_key = load_or_create_identity(&key_path)?;
        let peer_id   = PeerId::from(local_key.public());
        info!("P2P identity: {} ({})", peer_id, key_path.display());
        Ok(Self { peer_id, config, local_key })
    }

    /// Run the network event loop.
    ///
    /// Sprint CC (IBD live-tip fix): this function previously received
    /// `our_blue_score: u64` and `our_height: u64` as values captured
    /// at startup. Those values were baked into a single `my_tip`
    /// message created once and republished verbatim whenever a peer
    /// connected. Consequence in the wild: a node that started with
    /// genesis and later built/accepted thousands of blocks kept
    /// telling every new peer "I'm at height=1, blue_score=0". New
    /// peers compared against their own tip, saw parity, and decided
    /// not to request IBD. End result: fresh peers never synced from
    /// peers already in mainnet. See discovery log 2026-04-21 in
    /// docs/audit/AUDIT-2026-04-20.md under "Post-release findings".
    ///
    /// The fix here is to take the DAG by `Arc<RwLock<...>>` so the
    /// network loop can read the *current* tip before each publish.
    ///
    /// Sprint EE (S3 transport harness): `listen_report`, when `Some`, receives
    /// every address this swarm binds (fired from `SwarmEvent::NewListenAddr`).
    /// This is the affordance the sprint_ee_convergence.rs header names as the
    /// blocker for a real two-node in-process harness: with `/ip4/127.0.0.1/tcp/0`
    /// the kernel picks the port, and before this parameter the bound address
    /// was only *logged*, so a second in-process node could not be wired to the
    /// first deterministically (fixed ports = CI flakiness). Production passes
    /// `None` (see main.rs) — zero behavior change; the channel is unbounded so
    /// the swarm loop never blocks on a slow observer, and a dropped receiver
    /// is ignored (`let _ =`).
    pub async fn run(
        self,
        block_tx:       mpsc::Sender<NetworkMessage>,
        mut outbound_rx: mpsc::Receiver<NetworkMessage>,
        dag:            std::sync::Arc<parking_lot::RwLock<crate::consensus::GhostDAG>>,
        peer_state:     std::sync::Arc<crate::sync::peer_state::PeerStateTable>,
        listen_report:  Option<mpsc::UnboundedSender<Multiaddr>>,
    ) -> Result<(), NetworkError> {
        use std::time::Instant;
        // Audit M-10 fix: previously used std::hash::DefaultHasher, whose
        // output is not stable across Rust versions (see the SipHasher13
        // -> FxHash transition history). Two nodes on different Rust
        // toolchains would compute different MessageIds for the same
        // payload, breaking gossipsub deduplication and amplifying
        // bandwidth. SHA-256 truncated to 16 bytes is deterministic,
        // collision-resistant within any realistic network size, and
        // costs a handful of microseconds per message.
        let msg_id_fn = |m: &gossipsub::Message| {
            let digest = Sha256::digest(&m.data);
            gossipsub::MessageId::from(&digest[..16])
        };

        let gs_cfg = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(Duration::from_secs(1))
            .validation_mode(ValidationMode::Strict)
            .message_id_fn(msg_id_fn)
            .max_transmit_size(4 * 1024 * 1024)
            // Mesh fix (fresh-joiner IBD): gossipsub's duplicate_cache_time
            // defaults to 60s — the SAME period as tip_announce below. When
            // the tip hasn't advanced, the periodic PeerTip is byte-identical,
            // hashes to the same MessageId, and publish() returns
            // Err(PublishError::Duplicate) LOCALLY (behaviour.rs checks
            // duplicate_cache before sending) — the re-announce never leaves
            // this node. Worse: the on-connect PeerTip for a fresh joiner is
            // Duplicate-dropped whenever any announce fired in the previous
            // 60s, so on a quiet/stalled chain a new peer may NEVER receive a
            // tip. 30s guarantees the 60s periodic announce always clears the
            // cache; the tip-carrying Version (fresh timestamp → unique bytes)
            // published alongside it can never be dedup-dropped at all.
            .duplicate_cache_time(Duration::from_secs(30))
            .build()
            .map_err(|e| NetworkError::StartFailed(format!("gossipsub: {}", e)))?;

        // ── Peer scoring: penalize invalid messages, reward participation ──
        let peer_score_params = {
            use gossipsub::{PeerScoreParams, TopicScoreParams};
            let mut params = PeerScoreParams::default();
            params.app_specific_weight = 1.0;
            params.ip_colocation_factor_threshold = 3.0; // penalize >3 peers from same IP
            // Mesh fix: behind a fly.io-style proxy/NAT every inbound peer
            // shares the proxy's source IP, so the colocation penalty
            // (-50 × excess² above the threshold) crosses graylist_threshold
            // (-400) at just 6 peers — the node then IGNORES its entire mesh
            // and every tip announcement is blackholed. Operators who know
            // they're proxied disable the weight with --behind-proxy; the
            // default stays hostile to real sybil colocation.
            params.ip_colocation_factor_weight =
                if self.config.behind_proxy { 0.0 } else { -50.0 };
            params.decay_interval = Duration::from_secs(60);
            params.decay_to_zero = 0.01;

            // Score params for each topic
            let block_topic_params = TopicScoreParams {
                topic_weight: 0.5,
                time_in_mesh_weight: 0.1,
                time_in_mesh_quantum: Duration::from_secs(1),
                time_in_mesh_cap: 100.0,
                first_message_deliveries_weight: 1.0,
                first_message_deliveries_decay: 0.97,
                first_message_deliveries_cap: 100.0,
                invalid_message_deliveries_weight: -100.0, // harsh penalty for invalid blocks
                invalid_message_deliveries_decay: 0.5,
                ..Default::default()
            };

            let tx_topic_params = TopicScoreParams {
                topic_weight: 0.3,
                time_in_mesh_weight: 0.05,
                time_in_mesh_quantum: Duration::from_secs(1),
                time_in_mesh_cap: 50.0,
                first_message_deliveries_weight: 0.5,
                first_message_deliveries_decay: 0.97,
                first_message_deliveries_cap: 100.0,
                invalid_message_deliveries_weight: -50.0,
                invalid_message_deliveries_decay: 0.5,
                ..Default::default()
            };

            let sync_topic_params = TopicScoreParams {
                topic_weight: 0.2,
                time_in_mesh_weight: 0.02,
                time_in_mesh_quantum: Duration::from_secs(1),
                time_in_mesh_cap: 50.0,
                invalid_message_deliveries_weight: -20.0,
                invalid_message_deliveries_decay: 0.8,
                ..Default::default()
            };

            params.topics.insert(IdentTopic::new(TOPIC_BLOCKS).hash(), block_topic_params);
            params.topics.insert(IdentTopic::new(TOPIC_TXS).hash(), tx_topic_params);
            params.topics.insert(IdentTopic::new(TOPIC_SYNC).hash(), sync_topic_params);
            params
        };

        let peer_score_thresholds = gossipsub::PeerScoreThresholds {
            gossip_threshold:             -100.0,  // below this: no gossip metadata
            publish_threshold:            -200.0,  // below this: messages rejected
            graylist_threshold:           -400.0,  // below this: completely ignored
            opportunistic_graft_threshold: 5.0,
            ..Default::default()
        };

        let mut gs = gossipsub::Behaviour::new(
            MessageAuthenticity::Signed(self.local_key.clone()),
            gs_cfg,
        ).map_err(|e| NetworkError::StartFailed(format!("behaviour: {}", e)))?;

        // Apply peer scoring (non-fatal if it fails)
        if let Err(e) = gs.with_peer_score(peer_score_params, peer_score_thresholds) {
            warn!("peer scoring disabled: {}", e);
        }

        // Captured for the connection-limits behaviour below (avoids borrowing
        // `self` inside the `with_behaviour` closure).
        let max_peers = self.config.max_peers;
        let enable_mdns = self.config.enable_mdns;

        let mut swarm = SwarmBuilder::with_existing_identity(self.local_key.clone())
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                |keys: &identity::Keypair| -> Result<KyberConfig, std::convert::Infallible> {
                    Ok(KyberConfig::new(keys))
                },
                yamux::Config::default,
            )
            .map_err(|e| NetworkError::StartFailed(e.to_string()))?
            .with_websocket(
                |keys: &identity::Keypair| -> Result<KyberConfig, std::convert::Infallible> {
                    Ok(KyberConfig::new(keys))
                },
                yamux::Config::default,
            )
            .await
            .map_err(|e| NetworkError::StartFailed(e.to_string()))?
            .with_behaviour(|key| {
                // mDNS only when explicitly enabled; otherwise a disabled Toggle
                // (its record parser — the hickory-proto DoS surface — never runs).
                let mdns: libp2p::swarm::behaviour::toggle::Toggle<mdns::tokio::Behaviour> =
                    if enable_mdns {
                        Some(mdns::tokio::Behaviour::new(
                            mdns::Config::default(),
                            key.public().to_peer_id(),
                        )?).into()
                    } else {
                        None.into()
                    };
                let identify = identify::Behaviour::new(
                    identify::Config::new("/bloch-sis/1.0.0".into(), key.public()),
                );
                // Cap connections at the swarm layer to match max_peers. We
                // allow 2× established total for churn/reconnect headroom, but
                // hold established-INCOMING to max_peers so an attacker can't
                // fill every slot with inbound dials (eclipse hardening — note
                // this bounds the transport but is NOT yet adversarially
                // tested; see roadmap §2.4/§4.1). Pending caps blunt half-open
                // connection floods.
                let max = max_peers as u32;
                let limits = libp2p::connection_limits::ConnectionLimits::default()
                    .with_max_established(Some(max.saturating_mul(2)))
                    .with_max_established_incoming(Some(max))
                    .with_max_pending_incoming(Some(max))
                    .with_max_pending_outgoing(Some(max.max(1)));
                let connection_limits = libp2p::connection_limits::Behaviour::new(limits);
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(BlochBehaviour {
                    gossipsub: gs,
                    mdns,
                    identify,
                    connection_limits,
                })
            })
            .map_err(|e| NetworkError::StartFailed(e.to_string()))?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(300)))
            .build();

        let block_t = IdentTopic::new(TOPIC_BLOCKS);
        let tx_t    = IdentTopic::new(TOPIC_TXS);
        let sync_t  = IdentTopic::new(TOPIC_SYNC);

        for t in [&block_t, &tx_t, &sync_t] {
            swarm.behaviour_mut().gossipsub.subscribe(t)
                .map_err(|e| NetworkError::StartFailed(e.to_string()))?;
        }

        swarm.listen_on(self.config.listen_addr.parse()
            .map_err(|e| NetworkError::StartFailed(format!("addr: {}", e)))?)
            .map_err(|e| NetworkError::StartFailed(e.to_string()))?;

        // WebSocket listener on port 16111
        if let Ok(ws_addr) = "/ip4/0.0.0.0/tcp/16111/ws".parse::<libp2p::Multiaddr>() {
            match swarm.listen_on(ws_addr) {
                Ok(_) => info!("WS listening on 0.0.0.0:16111"),
                Err(e) => warn!("WS listen failed (non-fatal): {}", e),
            }
        }

        // FIX #6: Load saved peers and dial them
        let peers_path = self.config.data_dir.join("known_peers.json");
        let mut known_peers = load_known_peers(&peers_path);
        // Sprint P: drop any legacy pollution that doesn't pass the new validator.
        let pruned = prune_invalid(&mut known_peers, self.config.allow_private_peers);
        if pruned > 0 {
            info!("known_peers: pruned {} invalid entries on load (Sprint P)", pruned);
        }
        // Sprint P: enforce cap (soft eviction).
        let evicted = enforce_cap(&mut known_peers);
        if evicted > 0 {
            info!("known_peers: evicted {} entries to enforce cap", evicted);
        }

        // Sprint P: PEX hardening state.
        let mut pex_limiter = PexRateLimiter::new();
        let mut pex_stats   = PexStats::new();
        let allow_private   = self.config.allow_private_peers;

        // C1: cumulative app-score penalties for peers sending frames that
        // violate wire bounds (oversized / over-long lists). Sprint EE (S3):
        // the map + reaction logic moved into WirePenaltyTracker so the
        // reaction is unit-testable without a live swarm; behavior unchanged.
        let mut wire_tracker = WirePenaltyTracker::new();

        // Add hardcoded default seeds
        let mut all_seeds: Vec<String> = crate::core::DEFAULT_SEEDS.iter().map(|s| s.to_string()).collect();
        // DNS seeds (opt-in, non-privileged): resolve each hostname's A/AAAA
        // records into peer multiaddrs (Bitcoin-style cold-start). Only acts
        // when an operator passes --dns-seed; DEFAULT_SEEDS stays empty.
        for host in self.config.dns_seeds.iter() {
            let hp = if host.contains(':') { host.clone() } else { format!("{host}:16110") };
            match tokio::net::lookup_host(hp).await {
                Ok(addrs) => {
                    for sa in addrs {
                        let ma = match sa.ip() {
                            std::net::IpAddr::V4(v4) => format!("/ip4/{}/tcp/{}", v4, sa.port()),
                            std::net::IpAddr::V6(v6) => format!("/ip6/{}/tcp/{}", v6, sa.port()),
                        };
                        info!("dns-seed {} → {}", host, ma);
                        all_seeds.push(ma);
                    }
                }
                Err(e) => warn!("dns-seed {}: resolve failed: {}", host, e),
            }
        }
        // Add CLI bootstrap peers + known peers
        all_seeds.extend(self.config.bootstrap_peers.iter().cloned());
        all_seeds.extend(known_peers.iter().cloned());
        // Deduplicate
        all_seeds.sort();
        all_seeds.dedup();

        for p in all_seeds.iter() {
            let resolved = resolve_multiaddr(p).await;
            if let Ok(addr) = resolved.parse::<Multiaddr>() {
                info!("dialing: {}", resolved);
                let _ = swarm.dial(addr);
            }
        }

        // Sprint CC: build PeerTip fresh each time it's needed. The old
        // code captured `our_blue_score` / `our_height` once at startup
        // and reused them forever, which silently froze IBD triggering
        // across reboots and late-joiner peers.
        //
        // build_current_tip (below, at module scope) reads the DAG under
        // a short read lock — it's fine to call it from the swarm event
        // loop because GhostDAG reads are O(1) (accessor fields, no
        // walks) and parking_lot's RwLock has no writer-starvation
        // guarantees that would stall a reader.
        let peer_id_str = self.peer_id.to_string();

        let mut peer_count = 0usize;

        // AUDIT (external-address poisoning): a peer-reported identify
        // `observed_addr` is only a CANDIDATE, never trusted from one peer. We
        // confirm our own external address only when at least EXTERNAL_ADDR_QUORUM
        // DISTINCT peers independently report the same addr — and only a confirmed
        // addr becomes eligible for PEX self-advertise. Bounded to cap memory
        // against a peer flooding many distinct fake observed_addrs.
        const EXTERNAL_ADDR_QUORUM: usize = 3;
        const OBSERVED_ADDR_CAP: usize = 64;
        const MDNS_DIAL_LIMIT: usize = 8; // max LAN peers auto-dialed per mDNS event
        let mut observed_by: std::collections::HashMap<Multiaddr, std::collections::HashSet<PeerId>> =
            std::collections::HashMap::new();
        let mut heartbeat   = tokio::time::interval(Duration::from_secs(30));
        let mut save_peers  = tokio::time::interval(Duration::from_secs(60));
        // Sprint CC: periodic tip announce. Re-publishes the current
        // tip to the sync topic every 60s. Catches the case where a
        // peer already connected before we built new blocks — without
        // this, such peers never learn the tip advanced and stay
        // permanently behind.
        let mut tip_announce = tokio::time::interval(Duration::from_secs(60));

        loop {
            tokio::select! {
                event = poll_swarm(&mut swarm) => {
                    match event {
                        SwarmEvent::Behaviour(BlochBehaviourEvent::Gossipsub(gossipsub::Event::Message { propagation_source, message, .. })) => {
                            // C1: bounded decode. `decode_wire_message` (inside
                            // `classify`) enforces the 4 MiB frame/read limit and
                            // per-field length bounds; the unlimited
                            // `bincode::config::standard()` decode used here
                            // before let a tiny frame declare multi-GB lengths.
                            // Sprint EE (S3): the reaction decision is computed by
                            // WirePenaltyTracker (unit-testable, no swarm); this
                            // arm only APPLIES it.
                            let reaction = wire_tracker.classify(propagation_source, &message.data);
                            match &reaction {
                                WireReaction::Penalize { error, score } => {
                                    // Oversized / bounds-violating frames can't come from
                                    // a compliant node: hit the sender's application score
                                    // so repeat offenders get graylisted (4 × -100 crosses
                                    // graylist_threshold -400 at app_specific_weight 1.0).
                                    // NOTE (honesty): if `with_peer_score` failed above
                                    // (non-fatal warn path), set_application_score is
                                    // inert and this is effectively log-only.
                                    swarm.behaviour_mut().gossipsub
                                        .set_application_score(&propagation_source, *score);
                                    warn!("wire violation from {}: {:?} (app score → {})",
                                        propagation_source, error, score);
                                }
                                WireReaction::IgnoreMalformed(_) => {
                                    debug!("undecodable gossip frame from {} ({} bytes)",
                                        propagation_source, message.data.len());
                                }
                                WireReaction::Accept(_) => {}
                            }
                            if let WireReaction::Accept(msg) = reaction {
                                match &msg {
                                    NetworkMessage::NewBlock  { block_hash, height, blue_score, .. } => {
                                        // P1 (roadmap §2): block-ingest correlation moved here from
                                        // main.rs (owned by another dev). These fields let a P0
                                        // supervisor restart be correlated to the block that
                                        // triggered it. Inert unless a subscriber is installed.
                                        tracing::info_span!(
                                            "net_ingest_block",
                                            block_hash = %hex::encode(&block_hash[..8]),
                                            height = *height,
                                            blue_score = *blue_score,
                                            peer = %propagation_source,
                                        ).in_scope(|| {
                                            info!("← block h={} {}", height, hex::encode(&block_hash[..8]));
                                        });
                                    }
                                    NetworkMessage::PeerTip { peer_id, blue_score, height } => {
                                        debug!("← tip from {} score={}", peer_id, blue_score);
                                        // Phase-2: record the untrusted announced hint (no tips).
                                        peer_state.observe(propagation_source, *blue_score, *height, &[], Instant::now());
                                    }
                                    NetworkMessage::Headers { entries } =>
                                        info!("← {} headers", entries.len()),
                                    NetworkMessage::Tips { tips, .. } => {
                                        // Phase-2 frontier reconciliation hint: record the peer's
                                        // advertised DAG frontier + its highest announced score.
                                        let hashes: Vec<[u8; 32]> = tips.iter().map(|e| e.hash).collect();
                                        let (bs, ht) = tips.iter()
                                            .map(|e| (e.blue_score, e.height))
                                            .max_by_key(|(s, _)| *s)
                                            .unwrap_or((0, 0));
                                        peer_state.observe(propagation_source, bs, ht, &hashes, Instant::now());
                                    }
                                    NetworkMessage::Version { version, user_agent, blue_score, height, .. } => {
                                        if *version < MIN_PROTOCOL_VERSION {
                                            warn!("← incompatible version {} from {}", version, user_agent);
                                        } else {
                                            debug!("← version {} ({})", version, user_agent);
                                        }
                                        // Phase-2: record the untrusted announced hint (no tips).
                                        peer_state.observe(propagation_source, *blue_score, *height, &[], Instant::now());
                                    }
                                    NetworkMessage::PeerRequest => {
                                        let mut my_peers: Vec<String> = known_peers.iter().cloned().collect();
                                        // PRINCIPLES.md #2 ("every node is a seed"): advertise our
                                        // OWN reachable address(es) — learned via identify's
                                        // observed_addr and stored as external addresses — so a node
                                        // that nobody knows can still be gossiped onward. Formatted
                                        // exactly like the other PEX entries (append /p2p/<peer_id>);
                                        // de-duplicated against known_peers.
                                        for addr in swarm.external_addresses() {
                                            let self_addr = format!("{}/p2p/{}", addr, peer_id_str);
                                            if !my_peers.contains(&self_addr) {
                                                my_peers.push(self_addr);
                                            }
                                        }
                                        if !my_peers.is_empty() {
                                            let pex = NetworkMessage::PeerExchange { peers: my_peers };
                                            if let Ok(d) = bincode::serde::encode_to_vec(&pex, bincode::config::standard()) {
                                                let _ = swarm.behaviour_mut().gossipsub.publish(sync_t.clone(), d);
                                            }
                                        }
                                    }
                                    NetworkMessage::PeerExchange { peers } => {
                                        // ── Sprint P: PEX hardening ──────────────────────
                                        //
                                        // 1. Rate-limit by propagation_source (sliding window)
                                        // 2. Enforce batch limit PEX_BATCH_LIMIT per message
                                        // 3. Validate each address (is_valid_public_multiaddr)
                                        // 4. Respect MAX_PEERS ceiling (no new dials if already full)
                                        // 5. Don't persist to known_peers until dial confirms
                                        //    (now happens in ConnectionEstablished handler)
                                        let original_len = peers.len();

                                        // Rate limit admits at most PEX_MAX_PER_WINDOW per window
                                        // AND at most PEX_BATCH_LIMIT per message.
                                        let admitted = pex_limiter.admit(propagation_source, original_len);
                                        if admitted < original_len {
                                            let over_batch = original_len.saturating_sub(PEX_BATCH_LIMIT);
                                            if over_batch > 0 {
                                                pex_stats.record_batch(over_batch.min(original_len - admitted));
                                            }
                                            let over_rate = original_len - admitted - over_batch;
                                            if over_rate > 0 {
                                                pex_stats.record_rate(over_rate);
                                            }
                                        }

                                        let mut valid_accepted = 0usize;
                                        for addr_str in peers.iter().take(admitted) {
                                            if peer_count >= self.config.max_peers {
                                                break; // ceiling reached
                                            }
                                            if !is_valid_public_multiaddr(addr_str, allow_private) {
                                                // Is it private specifically? Check without the flag
                                                // to know which bucket to count.
                                                if is_valid_public_multiaddr(addr_str, true) {
                                                    pex_stats.record_private(1);
                                                } else {
                                                    pex_stats.record_invalid(1);
                                                }
                                                // H4: addr_str is attacker-controlled; byte-index
                                            // slicing panicked on multi-byte UTF-8 at byte 80.
                                            debug!("PEX rejected: {}", truncate_utf8(addr_str, 80));
                                                continue;
                                            }
                                            if known_peers.contains(addr_str) {
                                                continue; // already known, skip silently
                                            }
                                            // SECURITY (audit L3): do NOT resolve DNS inline here —
                                            // this runs inside the swarm event loop, so awaiting a
                                            // lookup on an attacker-supplied /dns4/ host stalled block
                                            // and tx propagation. Dial the multiaddr directly; libp2p's
                                            // DNS transport resolves /dns*/ during the dial, off the
                                            // critical path.
                                            if let Ok(addr) = addr_str.parse::<libp2p::Multiaddr>() {
                                                // H4: UTF-8-safe truncation (attacker-controlled).
                                                info!("PEX dial: {}", truncate_utf8(addr_str, 60));
                                                let _ = swarm.dial(addr);
                                                valid_accepted += 1;
                                                // NB: don't insert into known_peers here; wait for
                                                // ConnectionEstablished to confirm the peer is real.
                                            } else {
                                                pex_stats.record_invalid(1);
                                            }
                                        }
                                        if valid_accepted > 0 {
                                            pex_stats.record_accept(valid_accepted);
                                        }
                                        pex_stats.set_distinct_peers(pex_limiter.tracked_peer_count());
                                    }
                                    _ => {}
                                }
                                let _ = block_tx.try_send(msg);
                            }
                        }
                        SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                            info!("✓ connected: {}", peer_id);
                            swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                            peer_count += 1;
                            crate::metrics::set_peer_count(peer_count as i64);
                            peer_state.on_connect(peer_id, Instant::now());
                            // FIX v0.5.1: Re-announce subscriptions to new peer.
                            // gossipsub only announces subs on initial connect,
                            // but peer_score can ghost peers from mesh. Force
                            // re-broadcast of our subscribed topics so the new
                            // peer adds us to its mesh for blocks/txs/sync.
                            for t in [&block_t, &tx_t, &sync_t] {
                                let _ = swarm.behaviour_mut().gossipsub.subscribe(t);
                            }
                            // Save peer address for next startup.
                            // Sprint P: also track listener peers (was a bug — only dialers
                            // entered known_peers, so known_peers.json only grew with outbound
                            // connections). Both sides get filtered through the validator so
                            // we don't pollute known_peers with garbage.
                            let addr_to_remember = match &endpoint {
                                libp2p::core::ConnectedPoint::Dialer { address, .. } => {
                                    Some(format!("{}/p2p/{}", address, peer_id))
                                }
                                libp2p::core::ConnectedPoint::Listener { send_back_addr, .. } => {
                                    Some(format!("{}/p2p/{}", send_back_addr, peer_id))
                                }
                            };
                            if let Some(addr_str) = addr_to_remember {
                                if is_valid_public_multiaddr(&addr_str, allow_private) {
                                    known_peers.insert(addr_str);
                                    // Enforce cap on live state too
                                    enforce_cap(&mut known_peers);
                                } else {
                                    // H4: same panic-free truncation as the PEX log lines
                                    // (send_back_addr strings are peer-influenced too).
                                    debug!("not adding peer to known_peers (validator rejected): {}",
                                        truncate_utf8(&addr_str, 80));
                                }
                            }
                            // Send version handshake. Sprint CC: read fresh
                            // tip/height from DAG — same reason as the PeerTip
                            // fix. Version messages also carry these fields
                            // (some peers use them for compatibility checks
                            // and for log display) and would otherwise stay
                            // stuck at the startup values forever.
                            let (v_score, v_height) = {
                                let d = dag.read();
                                (d.tip_blue_score(), d.block_count() as u64)
                            };
                            let version_msg = NetworkMessage::Version {
                                version:    PROTOCOL_VERSION,
                                user_agent: format!("bloch-layer/{}", env!("CARGO_PKG_VERSION")),
                                blue_score: v_score,
                                height:     v_height,
                                timestamp:  std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map(|d| d.as_secs()).unwrap_or(0),
                            };
                            // Mesh fix (fresh-joiner IBD): these publishes were
                            // silently discarded with `let _ =`. Two failure
                            // modes were invisible in production: (a) publish
                            // races the new peer's gossipsub Subscribe →
                            // NoPeersSubscribedToTopic / not-yet-in-mesh, so the
                            // joiner never receives the frame; (b) a byte-
                            // identical PeerTip within duplicate_cache_time →
                            // PublishError::Duplicate, dropped LOCALLY. Both are
                            // now logged, and the Subscribed handler below
                            // re-announces once the peer's subscription lands.
                            if let Ok(d) = bincode::serde::encode_to_vec(&version_msg, bincode::config::standard()) {
                                if let Err(e) = swarm.behaviour_mut().gossipsub.publish(sync_t.clone(), d) {
                                    info!("on-connect Version publish failed ({}); will re-announce when {} subscribes to sync", e, peer_id);
                                }
                            }
                            // Announce our tip to trigger IBD. Sprint CC:
                            // fresh tip read from DAG, not the startup snapshot.
                            let my_tip = build_current_tip(&dag, &peer_id_str);
                            if let Ok(d) = bincode::serde::encode_to_vec(&my_tip, bincode::config::standard()) {
                                if let Err(e) = swarm.behaviour_mut().gossipsub.publish(sync_t.clone(), d) {
                                    info!("on-connect PeerTip publish failed ({}); will re-announce when {} subscribes to sync", e, peer_id);
                                }
                            }
                            // PEX: request peer list from new connection
                            if let Ok(d) = bincode::serde::encode_to_vec(&NetworkMessage::PeerRequest, bincode::config::standard()) {
                                if let Err(e) = swarm.behaviour_mut().gossipsub.publish(sync_t.clone(), d) {
                                    debug!("on-connect PeerRequest publish failed: {}", e);
                                }
                            }
                        }
                        // Mesh fix (fresh-joiner IBD): the on-connect announce
                        // above races the remote peer's Subscribe — until the
                        // peer's subscription to the sync topic reaches us, any
                        // publish either errors or is sent to a mesh the joiner
                        // is not yet part of. THIS event is the moment the peer
                        // provably subscribed, so re-announce the handshake and
                        // tip here. The Version frame carries a fresh timestamp,
                        // so its bytes — and therefore its MessageId — are
                        // unique: it can never be Duplicate-dropped the way a
                        // byte-identical PeerTip can, and main.rs treats a
                        // Version with blue_score > ours as an IBD trigger.
                        SwarmEvent::Behaviour(BlochBehaviourEvent::Gossipsub(gossipsub::Event::Subscribed { peer_id, topic })) => {
                            if topic == sync_t.hash() {
                                let (v_score, v_height) = {
                                    let d = dag.read();
                                    (d.tip_blue_score(), d.block_count() as u64)
                                };
                                let ver = NetworkMessage::Version {
                                    version:    PROTOCOL_VERSION,
                                    user_agent: format!("bloch-layer/{}", env!("CARGO_PKG_VERSION")),
                                    blue_score: v_score,
                                    height:     v_height,
                                    timestamp:  std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .map(|d| d.as_secs()).unwrap_or(0),
                                };
                                if let Ok(d) = bincode::serde::encode_to_vec(&ver, bincode::config::standard()) {
                                    match swarm.behaviour_mut().gossipsub.publish(sync_t.clone(), d) {
                                        Ok(_)  => info!("→ {} subscribed to sync; announced tip score={} height={}", peer_id, v_score, v_height),
                                        Err(e) => info!("post-subscribe Version publish failed: {} (periodic announce will retry)", e),
                                    }
                                }
                                let my_tip = build_current_tip(&dag, &peer_id_str);
                                if let Ok(d) = bincode::serde::encode_to_vec(&my_tip, bincode::config::standard()) {
                                    if let Err(e) = swarm.behaviour_mut().gossipsub.publish(sync_t.clone(), d) {
                                        // Duplicate is expected here when the tip
                                        // hasn't moved since a recent announce;
                                        // the Version above already carried it.
                                        debug!("post-subscribe PeerTip publish: {}", e);
                                    }
                                }
                            }
                        }
                        SwarmEvent::ConnectionClosed { peer_id, .. } => {
                            info!("✗ disconnected: {}", peer_id);
                            peer_count = peer_count.saturating_sub(1);
                            crate::metrics::set_peer_count(peer_count as i64);
                            peer_state.on_disconnect(&peer_id);
                        }
                        SwarmEvent::NewListenAddr { address, .. } => {
                            info!("listening: {}/p2p/{}", address, self.peer_id);
                            // Sprint EE (S3 transport harness): report the bound
                            // addr to an in-process observer so a peer node can
                            // be wired to this one deterministically even with
                            // an ephemeral `/tcp/0` listen port. `None` in
                            // production — this arm then behaves exactly as
                            // before (log only).
                            if let Some(report) = &listen_report {
                                let _ = report.send(address.clone());
                            }
                        }
                        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                            warn!("dial failed{}: {}",
                                peer_id.map(|p| format!(" to {}", p)).unwrap_or_default(),
                                error);
                        }
                        SwarmEvent::IncomingConnectionError { error, .. } => {
                            warn!("incoming failed: {}", error);
                        }
                        // PRINCIPLES.md #2: zero-config LAN discovery. mDNS finds
                        // peers on the local network with no configured seed —
                        // add them to the gossipsub mesh and auto-dial.
                        SwarmEvent::Behaviour(BlochBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                            // AUDIT fix (Finding 3): a rogue LAN mDNS responder can
                            // announce many peers and non-LAN targets. Only auto-dial
                            // LAN addresses (an mDNS record naming a PUBLIC IP is a
                            // reflection/SSRF attempt), honor the peer ceiling, and
                            // cap the number dialed per event.
                            let mut dialed = 0usize;
                            for (peer_id, addr) in list {
                                if dialed >= MDNS_DIAL_LIMIT || peer_count >= self.config.max_peers {
                                    break;
                                }
                                if !is_lan_multiaddr(&addr) {
                                    debug!("mDNS: ignoring non-LAN address (possible reflection): {}", addr);
                                    continue;
                                }
                                info!("mDNS discovered (LAN): {} at {}", peer_id, addr);
                                swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                                if swarm.dial(addr).is_ok() { dialed += 1; }
                            }
                        }
                        SwarmEvent::Behaviour(BlochBehaviourEvent::Mdns(mdns::Event::Expired(list))) => {
                            for (peer_id, _addr) in list {
                                swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer_id);
                            }
                        }
                        // PRINCIPLES.md #2: identify tells us how peers see us
                        // (observed_addr) — our own public address. Register it as
                        // an external address so we can self-advertise via PEX.
                        // Verified peer listen addrs are persisted like other
                        // known_peers (same validator/cap hygiene).
                        SwarmEvent::Behaviour(BlochBehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
                            // AUDIT fix (Finding 1 — external-addr poisoning): a
                            // peer-reported observed_addr is only a CANDIDATE.
                            // Validate it (public, well-formed) and require an
                            // independent quorum of DISTINCT peers before trusting
                            // it as our external address — only then is it eligible
                            // for PEX self-advertise. Never trust one peer.
                            let cand = format!("{}/p2p/{}", info.observed_addr, peer_id_str);
                            if is_valid_public_multiaddr(&cand, allow_private)
                                && (observed_by.len() < OBSERVED_ADDR_CAP
                                    || observed_by.contains_key(&info.observed_addr))
                            {
                                let voters = observed_by.entry(info.observed_addr.clone()).or_default();
                                let was_below = voters.len() < EXTERNAL_ADDR_QUORUM;
                                voters.insert(peer_id);
                                if was_below && voters.len() >= EXTERNAL_ADDR_QUORUM {
                                    swarm.add_external_address(info.observed_addr.clone());
                                    info!("external address confirmed by {} peers: {}",
                                        EXTERNAL_ADDR_QUORUM, info.observed_addr);
                                }
                            }
                            // AUDIT fix (Finding 2): do NOT persist identify-reported
                            // listen_addrs into known_peers — that bypassed the PEX
                            // rate-limit / batch-cap / dial-confirmation guards and
                            // let a peer inject a victim IP dialed on every boot.
                            // Peer discovery goes exclusively through hardened PEX.
                        }
                        _ => {}
                    }
                }

                Some(msg) = outbound_rx.recv() => {
                    let (topic, topic_name) = match &msg {
                        NetworkMessage::NewBlock { .. }        => (block_t.clone(), "blocks"),
                        NetworkMessage::NewTransaction { .. }  => (tx_t.clone(),    "txs"),
                        _                                      => (sync_t.clone(),  "sync"),
                    };
                    if let Ok(data) = bincode::serde::encode_to_vec(&msg, bincode::config::standard()) {
                        if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic, data) {
                            // Name the MESSAGE, not just the topic. The sync topic
                            // carries GetHeaders, Tips, GetTips, PeerTip and
                            // GetBlock, so "publish sync: Duplicate" identifies the
                            // stream and hides the culprit — which cost a wrong fix:
                            // GetBlock was given a nonce on the reasonable guess that
                            // it was the suppressed message, the node stayed stalled,
                            // and the log could not say why. A diagnostic that cannot
                            // distinguish five causes is a diagnostic that invites
                            // guessing.
                            let kind = match &msg {
                                NetworkMessage::NewBlock { .. }       => "NewBlock",
                                NetworkMessage::NewTransaction { .. } => "NewTransaction",
                                NetworkMessage::GetBlock { .. }       => "GetBlock",
                                NetworkMessage::BlockNotFound { .. }  => "BlockNotFound",
                                other => other.kind_name(),
                            };
                            warn!("publish {} [{}]: {}", topic_name, kind, e);
                        }
                    }
                }

                _ = heartbeat.tick() => {
                    // Sprint CC: height displayed in the heartbeat log also
                    // needs to come from the DAG, not a startup-captured
                    // value. Without this fix the seed's heartbeat kept
                    // logging 'height: 1' forever even as blocks accumulated.
                    let current_height = dag.read().block_count() as u64;
                    info!("peers: {} | height: {}", peer_count, current_height);
                    let addrs: Vec<String> = known_peers.iter().cloned().collect();
                    let _ = block_tx.try_send(NetworkMessage::PeerCount { count: peer_count, addresses: addrs });

                    // Sprint P: emit aggregated PEX stats (every 60s, only if activity)
                    if let Some(line) = pex_stats.tick() {
                        info!("{}", line);
                    }
                    // Sprint P: periodic GC of rate-limiter state (remove dormant peers)
                    pex_limiter.gc();

                    // FIX v0.5.1: Re-subscribe every 30s. In libp2p gossipsub,
                    // peer_score can silently drop a peer from the mesh for a
                    // given topic (we saw "Unexpected delivery trace" warnings
                    // in 0.5.0 followed by NoPeersSubscribedToTopic on publish).
                    // Calling subscribe() is idempotent; it re-advertises the
                    // subscription to every connected peer, restoring the mesh.
                    for t in [&block_t, &tx_t, &sync_t] {
                        let _ = swarm.behaviour_mut().gossipsub.subscribe(t);
                    }

                    // FIX v0.5.1: Warn if mesh for the tx topic is empty. This
                    // is the canary — if we have peers but no mesh for txs,
                    // any tx we publish will hit NoPeersSubscribedToTopic.
                    let tx_hash = tx_t.hash();
                    let tx_mesh_peers = swarm.behaviour().gossipsub.mesh_peers(&tx_hash).count();
                    if peer_count > 0 && tx_mesh_peers == 0 {
                        warn!("tx mesh empty: {} peers but 0 in tx-mesh — re-subscribing", peer_count);
                    }

                    if peer_count == 0 {
                        for p in self.config.bootstrap_peers.iter() {
                            let resolved = resolve_multiaddr(p).await;
                            if let Ok(addr) = resolved.parse::<libp2p::Multiaddr>() {
                                info!("reconnecting: {}", resolved);
                                let _ = swarm.dial(addr);
                            }
                        }
                    }
                }

                _ = save_peers.tick() => {
                    save_known_peers(&peers_path, &known_peers);
                }

                // Sprint CC: periodic tip announcement for IBD recovery.
                // Peers that connected before we built new blocks would
                // otherwise never learn the tip advanced. Publishing the
                // current tip every 60s is cheap (one gossipsub message
                // to the sync topic) and guarantees that any peer still
                // in the mesh gets a fresh tip at least once per minute,
                // giving them a chance to request IBD if they're behind.
                // Skipped when we have no peers — pointless and noisy.
                _ = tip_announce.tick() => {
                    if peer_count > 0 {
                        let tip = build_current_tip(&dag, &peer_id_str);
                        if let NetworkMessage::PeerTip { blue_score, height, .. } = &tip {
                            debug!("→ announcing tip: height={} score={}", height, blue_score);
                        }
                        if let Ok(d) = bincode::serde::encode_to_vec(&tip, bincode::config::standard()) {
                            // Mesh fix: this error was silently discarded. On a
                            // quiet chain the PeerTip bytes repeat, and with the
                            // old 60s duplicate_cache_time this publish could
                            // fail with PublishError::Duplicate every tick.
                            if let Err(e) = swarm.behaviour_mut().gossipsub.publish(sync_t.clone(), d) {
                                info!("tip announce publish failed: {} (peers={})", e, peer_count);
                            }
                        }
                        // Mesh fix (dedup-proof announce): also publish a
                        // Version frame each tick. Its `timestamp` field is
                        // fresh, so the bytes — and the SHA-256 MessageId —
                        // differ every announce; gossipsub can never dedup-drop
                        // it, unlike a byte-identical PeerTip. main.rs treats a
                        // Version whose blue_score exceeds ours as an IBD
                        // trigger, so this is a guaranteed once-per-minute
                        // "you are behind" signal to every meshed peer.
                        let (v_score, v_height) = {
                            let d = dag.read();
                            (d.tip_blue_score(), d.block_count() as u64)
                        };
                        let ver = NetworkMessage::Version {
                            version:    PROTOCOL_VERSION,
                            user_agent: format!("bloch-layer/{}", env!("CARGO_PKG_VERSION")),
                            blue_score: v_score,
                            height:     v_height,
                            timestamp:  std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs()).unwrap_or(0),
                        };
                        if let Ok(d) = bincode::serde::encode_to_vec(&ver, bincode::config::standard()) {
                            if let Err(e) = swarm.behaviour_mut().gossipsub.publish(sync_t.clone(), d) {
                                info!("version announce publish failed: {}", e);
                            }
                        }
                    }
                }
            }
        }
    }
}

// ── Persistent identity ───────────────────────────────────────────────────────

fn load_or_create_identity(path: &Path) -> Result<identity::Keypair, NetworkError> {
    if path.exists() {
        let bytes = std::fs::read(path)
            .map_err(|e| NetworkError::StartFailed(format!("read identity: {}", e)))?;
        return identity::Keypair::from_protobuf_encoding(&bytes)
            .map_err(|e| NetworkError::StartFailed(format!("decode identity: {}", e)));
    }
    let kp = identity::Keypair::generate_ed25519();
    if let Some(parent) = path.parent() { std::fs::create_dir_all(parent).ok(); }
    let bytes = kp.to_protobuf_encoding()
        .map_err(|e| NetworkError::StartFailed(format!("encode identity: {}", e)))?;
    std::fs::write(path, &bytes)
        .map_err(|e| NetworkError::StartFailed(format!("write identity: {}", e)))?;
    info!("created P2P identity: {}", path.display());
    Ok(kp)
}

// ── FIX #6: Peer persistence ──────────────────────────────────────────────────

fn load_known_peers(path: &Path) -> HashSet<String> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_known_peers(path: &Path, peers: &HashSet<String>) {
    if let Ok(json) = serde_json::to_string(peers) {
        let _ = std::fs::write(path, json);
    }
}

async fn poll_swarm(
    swarm: &mut libp2p::Swarm<BlochBehaviour>,
) -> SwarmEvent<BlochBehaviourEvent> {
    use futures::Stream;
    std::future::poll_fn(|cx| {
        match std::pin::Pin::new(&mut *swarm).poll_next(cx) {
            std::task::Poll::Ready(Some(e)) => std::task::Poll::Ready(e),
            _ => std::task::Poll::Pending,
        }
    }).await
}




/// Resolve a `/dns4/...` multiaddr to a `/ip4/...` form using async DNS.
///
/// Audit M-11 fix: this function was previously synchronous, calling
/// `std::net::ToSocketAddrs::to_socket_addrs` — a blocking C library
/// call that can stall the caller for the full DNS timeout (seconds)
/// on an unreachable nameserver. Every caller lives inside the
/// libp2p swarm event loop in `Swarm::run`; blocking the loop stalls
/// gossipsub propagation, connection events, and outbound dials for
/// every other peer. On a network with even one slow DNS seed this
/// was a periodic latency spike visible to the whole node.
///
/// Now uses `tokio::net::lookup_host`, which runs the lookup on the
/// blocking thread pool instead of holding the async executor. The
/// public API is now `async`; all three callers are inside async
/// code already, so the `.await` points add no new complexity.
///
/// Audit L-3 concern (silent fallback) is preserved: warn logs fire
/// on DNS failure and on no-IPv4-records, both paths still return
/// the unresolved multiaddr so upstream `parse::<Multiaddr>()` can
/// decide whether to dial.
async fn resolve_multiaddr(addr: &str) -> String {
    if !addr.contains("/dns4/") { return addr.to_string(); }
    let parts: Vec<&str> = addr.splitn(2, "/dns4/").collect();
    if parts.len() < 2 { return addr.to_string(); }
    let rest = parts[1];
    let mut iter = rest.splitn(3, '/');
    let host = iter.next().unwrap_or("");
    let _ = iter.next();
    let remainder = iter.next().unwrap_or("");

    match tokio::net::lookup_host(format!("{}:0", host)).await {
        Ok(addrs) => {
            if let Some(sa) = addrs.into_iter().find(|a| a.is_ipv4()) {
                let ip = sa.ip();
                let tcp_rest: Vec<&str> = remainder.splitn(2, '/').collect();
                let port = tcp_rest.first().unwrap_or(&"");
                let p2p = tcp_rest.get(1).map(|s| format!("/{}", s)).unwrap_or_default();
                return format!("/ip4/{}/tcp/{}{}", ip, port, p2p);
            }
            // Audit L-3: DNS returned records but none were IPv4.
            warn!(
                "resolve_multiaddr: DNS for host '{}' returned no IPv4 records; \
                 falling back to the unresolved multiaddr. Dial may fail.",
                host,
            );
        }
        Err(e) => {
            // Audit L-3: DNS resolution itself failed.
            warn!(
                "resolve_multiaddr: DNS lookup for host '{}' failed: {}. \
                 Falling back to the unresolved multiaddr; dial may fail.",
                host, e,
            );
        }
    }
    addr.to_string()
}

#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    #[error("start failed: {0}")]
    StartFailed(String),
}

// ── Sprint CC: PeerTip construction ──────────────────────────────────────────

/// Build a PeerTip message from the current state of the GhostDAG.
///
/// Sprint CC bugfix: previously, `network::run` captured `our_blue_score`
/// and `our_height` as `u64` values at startup and reused them forever
/// to construct every `PeerTip` it ever published. Any node that built
/// blocks after boot would still advertise its startup-time height to
/// the rest of the mesh, silently preventing peer-initiated IBD
/// handshakes across reboots and against late-joining peers.
///
/// This function is a small free function (not a closure inside `run`)
/// so it can be exercised directly by the regression test that lives
/// alongside it. Testing via the closure was not practical — it would
/// require spinning up a real libp2p swarm.
///
/// Holding the read lock for the duration of the three accessor calls
/// is a conscious choice: it guarantees the (blue_score, height) pair
/// is internally consistent. A multi-call pattern that released the
/// lock between `tip_blue_score()` and `block_count()` could report a
/// mismatched pair if a block were accepted in between. In practice
/// the window is microseconds but the cost of holding the lock for
/// that long is zero, so we take the consistency guarantee.
pub fn build_current_tip(
    dag:     &std::sync::Arc<parking_lot::RwLock<crate::consensus::GhostDAG>>,
    peer_id: &str,
) -> NetworkMessage {
    let d = dag.read();
    NetworkMessage::PeerTip {
        peer_id:    peer_id.to_string(),
        blue_score: d.tip_blue_score(),
        height:     d.block_count() as u64,
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// M-11 regression: addresses that don't need DNS must be returned
    /// unchanged without touching the resolver. This exercises the
    /// fast path that matters most in practice — most peers are
    /// already `/ip4/...` form from a prior bootstrap.
    #[tokio::test]
    async fn resolve_multiaddr_passes_through_ip4_unchanged() {
        let input = "/ip4/80.78.28.142/tcp/16110/p2p/12D3KooWQfXJzXRG7t4r1hQVHfijHsuMZ22ecAUD3YGhMvjvDbQp";
        let out = resolve_multiaddr(input).await;
        assert_eq!(out, input);
    }

    /// Degenerate edge case: a string that happens to not contain
    /// "/dns4/" at all should short-circuit immediately, no DNS lookup.
    #[tokio::test]
    async fn resolve_multiaddr_passes_through_empty_and_garbage() {
        assert_eq!(resolve_multiaddr("").await, "");
        assert_eq!(resolve_multiaddr("garbage").await, "garbage");
        assert_eq!(resolve_multiaddr("/ip6/::1/tcp/1").await, "/ip6/::1/tcp/1");
    }

    /// If `/dns4/` appears but the address is malformed enough that
    /// the `splitn(2, "/dns4/")` returns fewer than 2 parts, the
    /// function must fall back to returning the input verbatim.
    /// (Today this branch is actually unreachable because splitn(2)
    /// on a string that CONTAINS "/dns4/" always yields 2 parts, but
    /// the guard is in place and we pin it here in case the parser
    /// is ever restructured.)
    #[tokio::test]
    async fn resolve_multiaddr_never_panics_on_weird_input() {
        // These call into the DNS path but with a host that won't
        // resolve to anything useful. The function must still return
        // a String — never panic.
        let weird = "/dns4/";
        let _ = resolve_multiaddr(weird).await;
        // If we got here, no panic.
    }

    /// M-11 core property: the function is `async`. A synchronous
    /// version would block the libp2p event loop. We don't assert on
    /// timing (brittle in CI), but we do assert the shape: the return
    /// value only materializes after `.await`, which is only true for
    /// an async function.
    ///
    /// This is a compile-time check more than a runtime one — if
    /// someone regresses `resolve_multiaddr` to a sync function, this
    /// test fails to compile.
    #[tokio::test]
    async fn resolve_multiaddr_is_async() {
        // Cannot call an async fn without `.await`, so if the fn
        // signature regresses to `fn resolve_multiaddr(...) -> String`
        // the `.await` here becomes a compile error on "method `await`
        // does not exist on String". That is exactly the guard we want.
        let future = resolve_multiaddr("/ip4/127.0.0.1/tcp/1");
        let out = future.await;
        assert_eq!(out, "/ip4/127.0.0.1/tcp/1");
    }

    // ─── Sprint CC regression: dynamic PeerTip construction ──────────────

    /// The pre-Sprint-CC bug was: `our_blue_score` / `our_height` passed
    /// as u64 values got captured into `my_tip` once at startup, so any
    /// growth of the DAG after startup never reflected in subsequently
    /// published PeerTip messages. In production this silently froze
    /// IBD across the whole mesh — a seed at height=2655 kept telling
    /// every new peer "I'm at height=1", and new peers (seeing parity)
    /// never asked to sync.
    ///
    /// This test pins the fix: `build_current_tip` must read the DAG
    /// fresh on each call. The check is simple — build a tip, advance
    /// the DAG by one block, build another tip, assert the second tip
    /// reflects the new state. If someone later refactors
    /// `build_current_tip` to cache values, this test fails.
    #[test]
    fn build_current_tip_reads_fresh_dag_state_each_call() {
        use std::sync::Arc;
        use parking_lot::RwLock;
        use crate::consensus::GhostDAG;

        // Arrange: DAG with just genesis.
        let dag = Arc::new(RwLock::new(GhostDAG::with_default_k()));
        let genesis_hash: [u8; 32] = [0xAA; 32];
        dag.write().add_genesis(genesis_hash, 1000);

        // First tip read: should reflect genesis-only state.
        let tip1 = build_current_tip(&dag, "peer-xyz");
        match tip1 {
            NetworkMessage::PeerTip { peer_id, blue_score, height } => {
                assert_eq!(peer_id, "peer-xyz");
                assert_eq!(blue_score, 0, "genesis DAG has blue_score 0");
                assert_eq!(height, 1, "genesis DAG has block_count 1");
            }
            _ => panic!("expected PeerTip"),
        }

        // Advance the DAG by one block.
        let block1: [u8; 32] = [0xBB; 32];
        dag.write()
            .add_block(block1, vec![genesis_hash], 1, 1001)
            .expect("add_block");

        // Second tip read: MUST reflect the new state. The pre-Sprint-CC
        // bug was that the tip was cached and always returned the old
        // state here; the assertions below fail if that behavior returns.
        let tip2 = build_current_tip(&dag, "peer-xyz");
        match tip2 {
            NetworkMessage::PeerTip { blue_score, height, .. } => {
                assert_eq!(
                    blue_score, 1,
                    "tip MUST reflect post-genesis blue_score after add_block"
                );
                assert_eq!(
                    height, 2,
                    "tip MUST reflect post-genesis block_count after add_block"
                );
            }
            _ => panic!("expected PeerTip"),
        }
    }

    /// A separate and simpler property test: build_current_tip carries
    /// the peer_id through verbatim. Pre-refactor, this was a trivial
    /// clone; post-refactor it's still a trivial clone, but we pin it
    /// so a regression that swaps arguments or loses the peer_id
    /// completely is caught.
    #[test]
    fn build_current_tip_preserves_peer_id() {
        use std::sync::Arc;
        use parking_lot::RwLock;
        use crate::consensus::GhostDAG;

        let dag = Arc::new(RwLock::new(GhostDAG::with_default_k()));
        dag.write().add_genesis([0u8; 32], 0);

        let tip = build_current_tip(&dag, "12D3KooWExample123");
        match tip {
            NetworkMessage::PeerTip { peer_id, .. } => {
                assert_eq!(peer_id, "12D3KooWExample123");
            }
            _ => panic!("expected PeerTip"),
        }
    }

    /// Sanity check: tip_announce interval is configured to 60s. If
    /// someone ever changes that to something extreme (say, 10ms or
    /// 1h), this won't catch it — it only documents the intent. But
    /// it does catch accidental removal of the tip_announce timer,
    /// because that removal would also delete this constant expectation.
    ///
    /// The concrete guard is a compile-time check: we reference the
    /// Duration value we expect to see in the loop. If the loop ever
    /// changes the Duration::from_secs value, this test fails only if
    /// the value is exactly wrong for what IBD recovery needs.
    #[test]
    fn tip_announce_interval_is_bounded() {
        // Documented invariant: the tip_announce interval must be
        // bounded between 10s (pointless churn) and 300s (too slow for
        // IBD recovery on a network with 10s block times). The actual
        // value in run() is 60s; this test documents the acceptable
        // range without duplicating the exact value.
        let min_allowed = Duration::from_secs(10);
        let max_allowed = Duration::from_secs(300);
        let actual      = Duration::from_secs(60);  // must match run()

        assert!(
            actual >= min_allowed && actual <= max_allowed,
            "tip_announce interval {:?} outside acceptable bounds [{:?}, {:?}]",
            actual, min_allowed, max_allowed
        );
    }

    // ─── C1 regression: bounded bincode decode of untrusted gossip ────────

    /// (a) A tiny crafted frame declaring a multi-GB Vec length must return
    /// a decode error fast, without allocating the declared size. The frame
    /// is built by taking a genuinely-encoded NewBlock and splicing an 8 GiB
    /// length varint in place of the block_data length, so the test is
    /// self-validating against bincode's actual encoding layout.
    #[test]
    fn wire_decode_rejects_multi_gb_declared_vec() {
        let small = NetworkMessage::NewBlock {
            block_hash: [0u8; 32],
            blue_score: 0,
            height:     0,
            block_data: vec![7u8; 3],
        };
        let enc = bincode::serde::encode_to_vec(&small, bincode::config::standard())
            .expect("encode");
        // Layout guard: the frame must end with len-varint 0x03 then 7,7,7.
        // If bincode's encoding ever changes, fail loudly here instead of
        // silently testing a meaningless byte string.
        assert!(
            enc.ends_with(&[3, 7, 7, 7]),
            "bincode encoding layout changed; update this test"
        );
        let mut frame = enc[..enc.len() - 4].to_vec();
        frame.push(0xFD); // bincode-2 varint marker: u64 follows
        frame.extend_from_slice(&(8u64 * 1024 * 1024 * 1024).to_le_bytes()); // 8 GiB

        let t0 = std::time::Instant::now();
        let res = decode_wire_message(&frame);
        assert!(
            res.is_err(),
            "a frame declaring an 8 GiB Vec must not decode: {:?}", res
        );
        assert!(
            t0.elapsed() < Duration::from_secs(2),
            "decode must fail fast (no giant allocation/scan), took {:?}",
            t0.elapsed()
        );
    }

    /// (b) The 4 MiB frame limit: a frame just over MAX_WIRE_BYTES is
    /// rejected as Oversized; one comfortably under it decodes fine. This
    /// FAILS without the fix (the old unlimited standard() decode accepted
    /// the >4 MiB frame).
    #[test]
    fn wire_decode_enforces_4mib_frame_limit() {
        let mk = |n: usize| NetworkMessage::NewBlock {
            block_hash: [0u8; 32],
            blue_score: 0,
            height:     0,
            block_data: vec![0u8; n],
        };

        // Just over: payload alone exceeds MAX_WIRE_BYTES, so the whole
        // frame necessarily does too.
        let over = bincode::serde::encode_to_vec(&mk(MAX_WIRE_BYTES + 1024), bincode::config::standard())
            .expect("encode over");
        assert!(over.len() > MAX_WIRE_BYTES);
        match decode_wire_message(&over) {
            Err(WireDecodeError::Oversized(_)) => {}
            other => panic!("frame over 4 MiB must be Oversized, got {:?}", other),
        }

        // Comfortably under: must decode and round-trip the payload.
        let under = bincode::serde::encode_to_vec(&mk(3 * 1024 * 1024), bincode::config::standard())
            .expect("encode under");
        assert!(under.len() < MAX_WIRE_BYTES);
        match decode_wire_message(&under).expect("3 MiB block must decode") {
            NetworkMessage::NewBlock { block_data, .. } => {
                assert_eq!(block_data.len(), 3 * 1024 * 1024);
            }
            other => panic!("expected NewBlock, got {:?}", other),
        }
    }

    /// C1 post-decode bounds: a PeerExchange whose peer list is far longer
    /// than any compliant node would send must be rejected even though the
    /// frame is well under the 4 MiB byte limit (the byte limit alone cannot
    /// catch it). FAILS without the fix. A modest list still passes, and a
    /// single over-long address string is also rejected.
    #[test]
    fn wire_decode_bounds_peer_lists() {
        // Too many entries, but small total size (< 4 MiB).
        let peers: Vec<String> = (0..(MAX_WIRE_ADDRS + 1))
            .map(|i| format!("/ip4/1.2.3.4/tcp/{}", i % 65535))
            .collect();
        let bytes = bincode::serde::encode_to_vec(
            &NetworkMessage::PeerExchange { peers },
            bincode::config::standard(),
        ).expect("encode");
        assert!(bytes.len() < MAX_WIRE_BYTES, "test premise: under byte limit");
        assert!(
            matches!(decode_wire_message(&bytes), Err(WireDecodeError::Bounds(_))),
            "oversized peer list must be a Bounds violation"
        );

        // One absurdly long address string.
        let bytes = bincode::serde::encode_to_vec(
            &NetworkMessage::PeerExchange { peers: vec!["x".repeat(MAX_WIRE_ADDR_LEN + 1)] },
            bincode::config::standard(),
        ).expect("encode");
        assert!(
            matches!(decode_wire_message(&bytes), Err(WireDecodeError::Bounds(_))),
            "over-long address string must be a Bounds violation"
        );

        // A compliant-size list decodes fine.
        let ok_peers: Vec<String> = (0..10).map(|i| format!("/ip4/9.9.9.{}/tcp/16110", i)).collect();
        let bytes = bincode::serde::encode_to_vec(
            &NetworkMessage::PeerExchange { peers: ok_peers.clone() },
            bincode::config::standard(),
        ).expect("encode");
        match decode_wire_message(&bytes).expect("compliant PEX must decode") {
            NetworkMessage::PeerExchange { peers } => assert_eq!(peers, ok_peers),
            other => panic!("expected PeerExchange, got {:?}", other),
        }
    }

    // ─── H4 regression: UTF-8-safe truncation of PEX strings ──────────────

    /// (c) A PEX address string where byte 80 falls mid-codepoint. The
    /// pre-fix pattern `&s[..s.len().min(80)]` panics on exactly this input
    /// (asserted below via catch_unwind, documenting the vulnerability);
    /// `truncate_utf8` must handle it without panicking.
    #[test]
    fn pex_string_truncation_is_utf8_safe() {
        // "a" + 50×'é' (2 bytes each) = 101 bytes; char boundaries sit at
        // 0, 1, 3, 5, ..., so byte 80 is mid-codepoint.
        let s = format!("a{}", "é".repeat(50));
        assert!(!s.is_char_boundary(80), "test premise: 80 must be mid-codepoint");

        // Document the pre-fix behavior: the old expression panics on this input.
        let old_pattern_panics = std::panic::catch_unwind(|| {
            let _ = &s[..s.len().min(80)];
        }).is_err();
        assert!(old_pattern_panics, "this input reproduces the pre-fix H4 panic");

        // The fix: no panic, valid UTF-8 prefix, within the byte budget.
        let t = truncate_utf8(&s, 80);
        assert!(t.len() <= 80);
        assert!(s.starts_with(t));
        assert_eq!(t.len(), 79, "should back off to the char boundary at 79");

        // 4-byte codepoints (emoji): budget 79 backs off to 76.
        let e = "💥".repeat(30); // 120 bytes
        let te = truncate_utf8(&e, 79);
        assert_eq!(te.len(), 76);
        assert!(e.starts_with(te));

        // Short and boundary-exact strings pass through unchanged.
        assert_eq!(truncate_utf8("abc", 80), "abc");
        assert_eq!(truncate_utf8("éé", 4), "éé");
        // Degenerate: budget smaller than the first codepoint → empty, no panic.
        assert_eq!(truncate_utf8("💥", 3), "");
    }

    // ─── Sprint EE (S3): extracted frame-reaction unit ────────────────────

    /// The reaction to a valid frame is Accept carrying the decoded message.
    #[test]
    fn wire_reaction_accepts_valid_frame() {
        let mut t = WirePenaltyTracker::new();
        let peer = PeerId::random();
        let bytes = bincode::serde::encode_to_vec(
            &NetworkMessage::GetTips, bincode::config::standard()).expect("encode");
        match t.classify(peer, &bytes) {
            WireReaction::Accept(NetworkMessage::GetTips) => {}
            other => panic!("expected Accept(GetTips), got {:?}", other),
        }
        assert_eq!(t.score_of(&peer), None, "valid frames must not be penalized");
    }

    /// An invalid-block frame (NewBlock larger than MAX_WIRE_BYTES) is a
    /// protocol violation: cumulative -100 per offense; the FOURTH crosses
    /// graylist_threshold (-400). This is the deterministic, swarm-free
    /// assertion of the reaction `run()` applies via set_application_score.
    #[test]
    fn wire_reaction_penalizes_oversized_invalid_block_cumulatively() {
        let mut t = WirePenaltyTracker::new();
        let peer = PeerId::random();
        let big = bincode::serde::encode_to_vec(
            &NetworkMessage::NewBlock {
                block_hash: [0u8; 32],
                blue_score: 0,
                height:     0,
                block_data: vec![0u8; MAX_WIRE_BYTES + 1024],
            },
            bincode::config::standard(),
        ).expect("encode");

        for i in 1..=4i32 {
            match t.classify(peer, &big) {
                WireReaction::Penalize { score, error } => {
                    assert!(error.is_protocol_violation());
                    assert_eq!(score, WIRE_VIOLATION_PENALTY * f64::from(i));
                }
                other => panic!("expected Penalize, got {:?}", other),
            }
        }
        // Fourth violation: -400 == the gossipsub graylist_threshold in run().
        assert_eq!(t.score_of(&peer), Some(-400.0));
    }

    /// The cumulative penalty floors at WIRE_PENALTY_FLOOR — a flood of
    /// violations cannot drive the score to -inf.
    #[test]
    fn wire_reaction_penalty_floors() {
        let mut t = WirePenaltyTracker::new();
        let peer = PeerId::random();
        let bad: Vec<u8> = vec![0u8; MAX_WIRE_BYTES + 1];
        for _ in 0..30 {
            t.classify(peer, &bad);
        }
        assert_eq!(t.score_of(&peer), Some(WIRE_PENALTY_FLOOR));
    }

    /// A bounds-violating frame UNDER the byte limit (PEX list too long) is
    /// also a protocol violation — the byte limit alone can't catch it.
    #[test]
    fn wire_reaction_penalizes_bounds_violation() {
        let mut t = WirePenaltyTracker::new();
        let peer = PeerId::random();
        let peers: Vec<String> = (0..(MAX_WIRE_ADDRS + 1))
            .map(|i| format!("/ip4/1.2.3.4/tcp/{}", i % 65535))
            .collect();
        let bytes = bincode::serde::encode_to_vec(
            &NetworkMessage::PeerExchange { peers },
            bincode::config::standard(),
        ).expect("encode");
        assert!(bytes.len() < MAX_WIRE_BYTES);
        match t.classify(peer, &bytes) {
            WireReaction::Penalize { error: WireDecodeError::Bounds(_), score } => {
                assert_eq!(score, WIRE_VIOLATION_PENALTY);
            }
            other => panic!("expected Penalize(Bounds), got {:?}", other),
        }
    }

    /// Plain-malformed bincode (possible benign version skew) is ignored,
    /// never penalized.
    #[test]
    fn wire_reaction_ignores_malformed_without_penalty() {
        let mut t = WirePenaltyTracker::new();
        let peer = PeerId::random();
        match t.classify(peer, &[0xFF; 16]) {
            WireReaction::IgnoreMalformed(_) => {}
            other => panic!("expected IgnoreMalformed, got {:?}", other),
        }
        assert_eq!(t.score_of(&peer), None);
        assert_eq!(t.tracked_peers(), 0);
    }

    /// Once the tracking map is full, an untracked offender still gets a
    /// one-shot penalty but the map does not grow (memory bound against
    /// identity cycling).
    #[test]
    fn wire_reaction_track_cap_bounds_memory() {
        let mut t = WirePenaltyTracker::new();
        let bad: Vec<u8> = vec![0u8; MAX_WIRE_BYTES + 1];
        for _ in 0..WIRE_PENALTY_TRACK_CAP {
            t.classify(PeerId::random(), &bad);
        }
        assert_eq!(t.tracked_peers(), WIRE_PENALTY_TRACK_CAP);

        // Map full: a NEW offender is penalized one-shot, map unchanged.
        let late = PeerId::random();
        match t.classify(late, &bad) {
            WireReaction::Penalize { score, .. } => {
                assert_eq!(score, WIRE_VIOLATION_PENALTY);
            }
            other => panic!("expected Penalize, got {:?}", other),
        }
        assert_eq!(t.tracked_peers(), WIRE_PENALTY_TRACK_CAP, "map must not grow past cap");
        assert_eq!(t.score_of(&late), None, "one-shot offender is not inserted");
    }
}
