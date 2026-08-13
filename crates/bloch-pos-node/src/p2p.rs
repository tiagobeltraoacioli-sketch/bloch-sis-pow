// SPDX-License-Identifier: AGPL-3.0-or-later

//! The production network layer: libp2p + gossipsub, with the Genesis-3
//! incident record carried over rather than re-learned.
//!
//! `net.rs` is the devnet transport — a TCP full mesh with no relay logic, no
//! scoring and no admission control. It proved the consensus (a 64-validator,
//! 5-host devnet finalized on it), and it stays available behind
//! `--transport devnet`. This module is what a public network needs instead.
//!
//! ## What was ported, and from where
//!
//! Everything below that reads like an over-explained constant is a scar. The
//! source is the Genesis-3 node's `src/network/mod.rs` + `src/network/sync_rr.rs`,
//! which run on mainnet:
//!
//! - **No `add_explicit_peer()`, ever** (2026-08-07 mesh defect (a)). An
//!   "explicit peer" in gossipsub is DELIBERATELY EXCLUDED from mesh
//!   construction: libp2p-gossipsub 0.49.5 `behaviour.rs:2224` filters graft
//!   candidates with `!explicit_peers.contains(peer)`, and `:1395` answers an
//!   incoming GRAFT from an explicit peer by PRUNING it on every topic.
//!   Marking every connection explicit made the mesh permanently unbuildable:
//!   "Mesh low. Topic contains: 0" forever, `publish()` →
//!   `NoPeersSubscribedToTopic`, and the producer's blocks never left the box.
//!   The connection handler here therefore does *nothing* to gossipsub — the
//!   behaviour learns about peers by itself.
//!
//! - **No `..Default::default()` in [`TopicScoreParams`]** (2026-08-07 mesh
//!   defect (b)). The default ships P3 `mesh_message_deliveries_weight = -1.0`
//!   with `threshold = 20.0` and `activation = 5s`. Five seconds after a peer
//!   grafts, gossipsub charges `-1.0 × (20 − delivered)² × topic_weight`. A
//!   30 s slot chain delivers 0 in that window, so every peer took ≈ −400
//!   summed across topics — exactly `graylist_threshold`. Every peer that
//!   grafted was guaranteed to be pruned within seconds. [`topic_params`]
//!   therefore writes **every field explicitly**; the struct literal has no
//!   `..Default::default()` tail, so adding a field upstream breaks the build
//!   instead of silently re-arming the penalty. [`score_params_have_no_p3`]
//!   pins it.
//!
//! - **[`MAX_YAMUX_STREAMS`] must exceed [`MAX_CONCURRENT_SYNC_STREAMS`]**.
//!   yamux does not backpressure at its substream cap, it KILLS the connection
//!   ("maximum number of streams reached" → disconnect). A node catching up
//!   opens a burst of sync substreams and the transport drops the very peer it
//!   is syncing from. Pinned by a `const` assertion below.
//!
//! - **[`REGOSSIP_SUPPRESS_TTL`] ≥ [`DUPLICATE_CACHE_TIME`]**. The message id
//!   is a content hash, so a re-publish inside the duplicate window is refused
//!   by gossipsub *locally* anyway — after paying the encode and the hash of a
//!   multi-hundred-KB body. A shorter suppression window is pure waste. Also
//!   pinned by a `const` assertion.
//!
//! ## What is new here, and deliberate
//!
//! - **A protocol prefix of its own.** Genesis-4 speaks
//!   `/bloch-g4/meshsub/1.1.0`, `/bloch-g4/sync/1` and identify
//!   `/bloch-g4/1.0.0`; Genesis-3 speaks `/meshsub/1.1.0`, `/bloch/sync/1` and
//!   `/bloch-sis/1.0.0`. Multistream-select finds no common protocol, so a
//!   Genesis-4 node cannot join a Genesis-3 mesh by accident even if someone
//!   points it at one. The topic names differ too (`bloch-g4/…` vs `bloch/…`),
//!   which is the second, independent barrier.
//!
//! - **`gossip.rs` is wired.** Gossipsub runs with `validate_messages()`, so
//!   nothing is relayed until the node says so. Attestations go to the engine
//!   carrying an [`Origin`]; the engine runs
//!   [`AttestationPool::process`](bloch_pos_committee::gossip::AttestationPool::process)
//!   and maps the returned [`GossipDecision`](bloch_pos_committee::gossip::GossipDecision)
//!   back through [`Handle::report`] onto
//!   `report_message_validation_result`. That is the contract the pure
//!   module's own docs state, and the reason `Ignore` and `Reject` are
//!   different types there: only `Reject` may ever feed a peer penalty.
//!
//! - **Sync is a directed pull, never a broadcast.** `get-blocks` is the one
//!   request the devnet transport had; here it is a `/bloch-g4/sync/1`
//!   request-response to a small set of chosen peers, not a mesh broadcast.
//!   The Genesis-3 root cause is on the record: sweeping IBD fetches onto the
//!   gossip topic produced O(peers × blocks) amplification that saturated the
//!   send queue and stalled the chain. Responses are capped
//!   ([`MAX_SYNC_BLOCKS`], [`MAX_SYNC_FRAME`]) so no peer can answer a small
//!   question with a history dump — the 2026-08-09 backfill flood, where one
//!   stale node pushed 1,270 old blocks and stopped production network-wide,
//!   is structurally unavailable over this path.
//!
//! ## Cold start: a new node builds its own state, from genesis
//!
//! This is a first-class requirement, not a consequence, and it is the
//! question an exchange asks before it will credit a deposit: *can we run a
//! node that verifies the chain itself, or must someone hand us a database?*
//!
//! On Genesis-3 the honest answer is no, permanently: `docs/CARRYOVER.md`
//! states that syncing from genesis is unsupported, and the block bodies a
//! from-scratch sync would need were dropped from the whole network before the
//! retention fix. Nothing can bring them back. A node bootstrapped from the
//! producer's datadir has verified nothing, and its confirmation counts mean
//! nothing.
//!
//! Genesis-4 starts clean, and this transport is built so that stays true:
//!
//! - A node with **only the genesis manifest** and an empty data dir asks its
//!   peers for everything after slot 0 and walks forward. Every block it
//!   receives goes through the same `Transition::apply_block` the producer
//!   ran — signatures, state root, body root, attestation quorum, all of it.
//!   Nothing about "this came from sync" makes validation lighter; the sync
//!   path feeds `NetEvent::Block`, exactly like gossip does.
//! - Because one answer is capped at [`MAX_SYNC_BLOCKS`], a cold node's
//!   request is **paginated**: a full page is immediately followed by a
//!   request for the next one, from the same peer, until a short page says the
//!   peer has no more. That is what makes "ask from genesis" work rather than
//!   merely be accepted. [`MAX_PAGES_WITHOUT_PROGRESS`] bounds the loop so a
//!   peer feeding blocks the engine will not apply cannot page forever.
//! - The serving side reads its **whole** block log, so a request for
//!   `after_slot = 0` is answered from the beginning of the chain. There is no
//!   "recent blocks only" fast path, and there is no datadir-donation path.
//!
//! **The trust boundary, stated plainly (do not bury this).** Downloading and
//! validating every block proves the chain is *internally* valid; it does not
//! by itself prove it is *the* chain, because a set of validators that has
//! already withdrawn its stake can sign an alternative history at no cost —
//! the long-range problem every proof-of-stake system has. Genesis-4's answer
//! is weak subjectivity (`ws_boot`, `BLOCH-WEAK-SUBJECTIVITY.md`), and it has
//! exactly two regimes:
//!
//! 1. **While the chain is younger than
//!    [`WS_PERIOD_EPOCHS`](bloch_pos_committee::ws::WS_PERIOD_EPOCHS) —
//!    2016 epochs, ≈ 22.4 days at the 30 s cadence — a fresh node needs
//!    nothing but the genesis manifest.** The genesis block is its own
//!    subjectivity anchor, no signature from anyone is required, and cold sync
//!    is fully trustless.
//! 2. **After that, a node with an empty database requires a signed
//!    checkpoint** (`--ws-checkpoint` + `--ws-signer-set`) and refuses to sync
//!    without one. That is a real trust input and it is named as one: the node
//!    trusts the checkpoint signers for the single fact of *which* finalized
//!    root is real at one epoch. It does **not** trust them for state — every
//!    block after the anchor is still downloaded and revalidated locally, and
//!    a checkpoint that contradicts finality this node reached on its own is
//!    an alarm that cannot reorganize it (`enforce_ws_anchor`).
//!
//! The distance between (2) and "copy the producer's datadir" is the whole
//! point: 32 bytes an operator can compare against independent publication
//! channels, versus a database whose contents nobody verified.
//!
//! ## What this module does NOT do (say it here, not in a status meeting)
//!
//! - **The transport handshake is Noise (X25519), not the Genesis-3 Kyber768
//!   upgrade.** `src/transport/` in the Genesis-3 tree implements a hybrid PQ
//!   handshake; porting it means copying ~1,500 lines that depend on that
//!   crate's `crate::crypto`, and doing that badly is worse than not doing it.
//!   Consensus signatures are unaffected — blocks and attestations are hybrid
//!   ML-DSA-65 ‖ Falcon-1024 either way, and this node verifies them itself.
//!   What is exposed is *transport* confidentiality against a
//!   harvest-now-decrypt-later adversary. Named as the next piece of work.
//!
//! - **Blocks and transactions are relayed on decodability, not on validity.**
//!   The relay decision for those two topics is taken at the edge (does it
//!   decode?), because gating relay on the full state transition would put a
//!   consensus round-trip in front of every forward. Attestations are the ones
//!   that get the full `gossip.rs` treatment. An invalid-but-decodable block
//!   is therefore relayed once before the engine rejects it; the sender is
//!   *not* penalized for it. Closing that needs the engine's verdict on the
//!   block path too, the same shape as the attestation path.
//!
//! - **No peer persistence, no PEX, no DNS seeds, no mDNS.** Peers come from
//!   `--p2p-peer` and are re-dialled on a timer. `known_peers.json`, peer
//!   exchange and its whole hardening surface (rate limits, address
//!   validation, the canonical-address idempotency fix) are Genesis-3 code
//!   that is not ported yet.
//!
//! - **The channel to the engine is unbounded.** During a cold sync the
//!   in-flight ceiling is roughly `MAX_PAGES_WITHOUT_PROGRESS × MAX_SYNC_BLOCKS`
//!   blocks per serving peer — a real bound, but a generous one (tens of MB),
//!   and it is a bound on *memory*, not backpressure. Genesis-3 learned the
//!   other side of this: a bounded channel that sheds under load dropped the
//!   very sync replies the orphan pool was waiting on, in silence. Neither
//!   answer is free; this one is chosen because a syncing node that stalls is
//!   worse than one that is briefly fat, and it is named rather than assumed.

use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::Sender as EngineSender;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use futures::prelude::*;
use libp2p::gossipsub::{
    self, IdentTopic, MessageAcceptance, MessageAuthenticity, MessageId, PeerScoreParams,
    PeerScoreThresholds, TopicScoreParams, ValidationMode,
};
use libp2p::request_response::{self, Codec as RrCodec, Config as RrConfig, ProtocolSupport};
use libp2p::swarm::SwarmEvent;
use libp2p::{identify, identity, noise, yamux, PeerId, StreamProtocol, SwarmBuilder};

/// Re-exported so the composition root can parse `--p2p-listen`/`--p2p-peer`
/// without depending on libp2p directly.
pub use libp2p::Multiaddr;

use crate::net::NetEvent;

// ── Protocol identity: a Genesis-4 node must never speak to a Genesis-3 one ──

/// Gossipsub protocol prefix. The negotiated protocol becomes
/// `/bloch-g4/meshsub/1.1.0`; Genesis-3 runs the library default
/// `/meshsub/1.1.0`. Multistream-select finds no overlap, so the two networks
/// cannot form a mesh even when pointed at each other.
pub const GOSSIP_PROTOCOL_PREFIX: &str = "/bloch-g4";

/// Identify protocol. Distinct from Genesis-3's `/bloch-sis/1.0.0`.
pub const IDENTIFY_PROTOCOL: &str = "/bloch-g4/1.0.0";

/// Directed sync protocol. Distinct from Genesis-3's `/bloch/sync/1`.
pub const SYNC_PROTOCOL: StreamProtocol = StreamProtocol::new("/bloch-g4/sync/1");

/// Block gossip topic. Genesis-3 uses `bloch/blocks/1`.
pub const TOPIC_BLOCKS: &str = "bloch-g4/blocks/1";
/// Attestation gossip topic. Genesis-3 has no equivalent — it is proof of work.
pub const TOPIC_ATTESTATIONS: &str = "bloch-g4/attestations/1";
/// Transaction gossip topic. Genesis-3 uses `bloch/txs/1`.
pub const TOPIC_TXS: &str = "bloch-g4/txs/1";

// ── Bounds that are load-bearing, each pinned by an assertion ────────────────

/// Largest gossip frame. A block with the full validator set attesting is
/// dominated by hybrid signatures (~4.6 KB each), so this is generous rather
/// than tight; `codec::MAX_FIELD_LEN` (8 MiB) remains the decoder's own cap.
pub const MAX_GOSSIP_BYTES: usize = 4 * 1024 * 1024;

/// Gossipsub's duplicate-cache retention. See [`REGOSSIP_SUPPRESS_TTL`].
pub const DUPLICATE_CACHE_TIME: Duration = Duration::from_secs(30);

/// How long this node suppresses re-publishing a block it has already
/// published or received.
///
/// MUST be `>= DUPLICATE_CACHE_TIME`. The message id is a content hash, so a
/// re-publish inside the duplicate window is refused by gossipsub locally
/// (`PublishError::Duplicate`) *after* the encode and the hash have been paid.
/// A shorter window is a band of guaranteed waste — Genesis-3 shipped 10 s
/// against a 30 s cache and measured exactly that.
pub const REGOSSIP_SUPPRESS_TTL: Duration = Duration::from_secs(30);

const _: () = assert!(
    REGOSSIP_SUPPRESS_TTL.as_secs() >= DUPLICATE_CACHE_TIME.as_secs(),
    "re-gossip suppression shorter than the duplicate cache is pure waste"
);

/// Concurrent request-response substreams per connection before new inbound
/// streams are dropped. libp2p's default is 100; a node catching up opens a
/// burst well past that and then loses the peer's deliveries.
pub const MAX_CONCURRENT_SYNC_STREAMS: usize = 2048;

/// Yamux substream cap per connection.
///
/// MUST exceed [`MAX_CONCURRENT_SYNC_STREAMS`]. yamux does not backpressure at
/// the cap — it terminates the connection (`Action::Terminate` inbound,
/// `ConnectionError::TooManyStreams` outbound), logged as "maximum number of
/// streams reached" followed by a disconnect. Genesis-3 raised the rr cap to
/// 2048 while leaving `yamux::Config::default` at its 512, and node4 answered
/// with a 0↔3-peer connect/disconnect oscillation.
///
/// KNOWN TRADE-OFF, verified in libp2p-yamux 0.47's own source: any setter —
/// including `set_max_num_streams` — switches the muxer backend from yamux
/// 0.13 to 0.12 (the crate's `config_set_switches_to_v012` test pins this as
/// intended). There is no way to raise the 0.13 cap through the public API.
/// 0.12 speaks the same wire protocol, so this is a local choice, not a fork.
pub const MAX_YAMUX_STREAMS: usize = 4096;

const _: () = assert!(
    MAX_YAMUX_STREAMS > MAX_CONCURRENT_SYNC_STREAMS,
    "yamux would terminate the connection the sync layer is allowed to fill"
);

/// Blocks one sync response may carry. Bounds the answer to a `get-blocks`
/// so a peer cannot turn a small question into a history dump.
pub const MAX_SYNC_BLOCKS: usize = 128;

/// Byte ceiling on a sync frame, checked while building the response and again
/// while reading it.
pub const MAX_SYNC_FRAME: u64 = 8 * 1024 * 1024;

/// Peers a single `get-blocks` is directed at. Not one (a silent peer would
/// stall recovery), not all (that is the broadcast this replaces).
const SYNC_FANOUT: usize = 3;

/// Consecutive **full** sync pages this node will chase from one peer without
/// its own applied head advancing.
///
/// Pagination is what makes cold sync from genesis work: one answer is capped
/// at [`MAX_SYNC_BLOCKS`], so a node 400,000 blocks behind must ask again, and
/// again, and the honest way to do that is to ask the moment a full page
/// arrives rather than on the engine's 2-slot sync timer. The bound exists
/// because the same loop, unbounded, is a free amplifier for a peer serving
/// blocks that never apply: 64 × 128 = 8,192 blocks of no progress is the most
/// this node will pull before it stops asking that peer. Any real progress
/// resets the counter, so a genuine multi-year backfill is unaffected.
const MAX_PAGES_WITHOUT_PROGRESS: u32 = 64;

/// How often unconnected configured peers are re-dialled.
const REDIAL_INTERVAL: Duration = Duration::from_secs(10);

// ── The validation verdict the engine hands back ────────────────────────────

/// Where a gossip message came from, opaque to the engine.
///
/// Carried on [`NetEvent::Attestation`] so the engine's decision can be routed
/// back to the exact message and peer. [`Origin::none`] is what the devnet
/// transport supplies and what locally-produced messages carry; reporting on
/// it is a no-op.
#[derive(Clone, Debug, Default)]
pub struct Origin {
    inner: Option<(MessageId, PeerId)>,
}

impl Origin {
    /// No provenance: devnet transport, or a message this node produced.
    pub fn none() -> Self {
        Origin { inner: None }
    }
}

/// The three verbs gossipsub understands, and the only mapping
/// [`GossipDecision`](bloch_pos_committee::gossip::GossipDecision) is allowed.
///
/// The split exists so a caller *cannot* wire an `Ignore` into a peer penalty:
/// `Ignore` drops the message and says nothing about the peer, `Reject` drops
/// it and counts against the peer's P4 score. Confusing the two is how a mesh
/// graylists its honest peers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Valid: relay it and count the peer's delivery.
    Accept,
    /// Drop without relaying. No penalty — every honest race lands here.
    Ignore,
    /// Provable violation. Drop, and penalize the forwarding peer.
    Reject,
}

impl From<Verdict> for MessageAcceptance {
    fn from(v: Verdict) -> Self {
        match v {
            Verdict::Accept => MessageAcceptance::Accept,
            Verdict::Ignore => MessageAcceptance::Ignore,
            Verdict::Reject => MessageAcceptance::Reject,
        }
    }
}

// ── Directed sync wire format ───────────────────────────────────────────────
//
// Hand-rolled, fixed-order, little-endian — the same discipline `codec.rs`
// states and for the same reason: no serde, no reflection, and a decoder that
// refuses `encode(x) ‖ junk`. Block bytes inside the response are exactly
// `codec::encode_envelope` output, so a synced block and a gossiped block are
// the same object, not two encodings that can disagree.

/// A directed sync request. One variant today; the tag byte is there so a
/// second one does not need a new protocol id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncRequest {
    /// Every block with `slot > after_slot`, capped at `limit`.
    GetBlocks { after_slot: u64, limit: u32 },
}

/// The answer to a [`SyncRequest`]: encoded block envelopes, in chain order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncResponse {
    Blocks { envelopes: Vec<Vec<u8>> },
}

const SYNC_TAG_GET_BLOCKS: u8 = 0x01;
const SYNC_TAG_BLOCKS: u8 = 0x01;

pub fn encode_sync_request(req: &SyncRequest) -> Vec<u8> {
    match req {
        SyncRequest::GetBlocks { after_slot, limit } => {
            let mut out = Vec::with_capacity(13);
            out.push(SYNC_TAG_GET_BLOCKS);
            out.extend_from_slice(&after_slot.to_le_bytes());
            out.extend_from_slice(&limit.to_le_bytes());
            out
        }
    }
}

pub fn decode_sync_request(buf: &[u8]) -> Result<SyncRequest, crate::codec::DecodeErr> {
    let mut r = crate::codec::Reader::new(buf);
    match r.u8()? {
        SYNC_TAG_GET_BLOCKS => {
            let after_slot = r.u64()?;
            let limit = r.u32()?;
            r.finish()?;
            Ok(SyncRequest::GetBlocks { after_slot, limit })
        }
        _ => Err(crate::codec::DecodeErr("unknown sync request tag")),
    }
}

pub fn encode_sync_response(resp: &SyncResponse) -> Vec<u8> {
    match resp {
        SyncResponse::Blocks { envelopes } => {
            let mut out = Vec::with_capacity(5 + envelopes.iter().map(|e| e.len() + 4).sum::<usize>());
            out.push(SYNC_TAG_BLOCKS);
            out.extend_from_slice(&(envelopes.len() as u32).to_le_bytes());
            for e in envelopes {
                crate::codec::put_bytes(&mut out, e);
            }
            out
        }
    }
}

pub fn decode_sync_response(buf: &[u8]) -> Result<SyncResponse, crate::codec::DecodeErr> {
    let mut r = crate::codec::Reader::new(buf);
    match r.u8()? {
        SYNC_TAG_BLOCKS => {
            let n = r.u32()? as usize;
            if n > MAX_SYNC_BLOCKS {
                return Err(crate::codec::DecodeErr("sync response over the block cap"));
            }
            let mut envelopes = Vec::with_capacity(n);
            for _ in 0..n {
                envelopes.push(r.bytes()?);
            }
            r.finish()?;
            Ok(SyncResponse::Blocks { envelopes })
        }
        _ => Err(crate::codec::DecodeErr("unknown sync response tag")),
    }
}

/// Delimited-by-EOF codec: request-response opens a fresh substream per
/// message and closes the write half, so `read_to_end` frames it exactly.
#[derive(Clone, Default)]
pub struct SyncCodec;

#[async_trait]
impl RrCodec for SyncCodec {
    type Protocol = StreamProtocol;
    type Request = SyncRequest;
    type Response = SyncResponse;

    async fn read_request<T>(&mut self, _: &StreamProtocol, io: &mut T) -> io::Result<SyncRequest>
    where
        T: AsyncRead + Unpin + Send,
    {
        let buf = read_capped(io).await?;
        decode_sync_request(&buf).map_err(bad_data)
    }

    async fn read_response<T>(&mut self, _: &StreamProtocol, io: &mut T) -> io::Result<SyncResponse>
    where
        T: AsyncRead + Unpin + Send,
    {
        let buf = read_capped(io).await?;
        decode_sync_response(&buf).map_err(bad_data)
    }

    async fn write_request<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        req: SyncRequest,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(&encode_sync_request(&req)).await
    }

    async fn write_response<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        resp: SyncResponse,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(&encode_sync_response(&resp)).await
    }
}

async fn read_capped<T: AsyncRead + Unpin + Send>(io: &mut T) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    io.take(MAX_SYNC_FRAME).read_to_end(&mut buf).await?;
    Ok(buf)
}

fn bad_data(e: crate::codec::DecodeErr) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

// ── Behaviour ───────────────────────────────────────────────────────────────

#[derive(libp2p::swarm::NetworkBehaviour)]
struct G4Behaviour {
    gossipsub: gossipsub::Behaviour,
    identify: identify::Behaviour,
    sync: request_response::Behaviour<SyncCodec>,
    connection_limits: libp2p::connection_limits::Behaviour,
}

/// Yamux config for the swarm. See [`MAX_YAMUX_STREAMS`].
fn yamux_config() -> yamux::Config {
    let mut cfg = yamux::Config::default();
    cfg.set_max_num_streams(MAX_YAMUX_STREAMS);
    cfg
}

/// Per-topic score parameters, **every field written out**.
///
/// The `..Default::default()` this deliberately does not have is mesh defect
/// (b) of 2026-08-07: the default carries P3
/// (`mesh_message_deliveries_weight = -1.0`, threshold 20, activation 5 s) and
/// P3b, which a 30 s slot chain can never satisfy — every grafted peer crossed
/// `graylist_threshold` within seconds and the mesh could not hold anyone.
///
/// P3/P3b are set to `0.0` (the library's documented "disabled" value) and, as
/// importantly, are *visible here*: a reader can see they were decided, not
/// inherited. Because the literal is exhaustive, a new upstream field is a
/// compile error rather than a silently re-armed penalty.
pub fn topic_params(weight: f64, invalid_weight: f64) -> TopicScoreParams {
    TopicScoreParams {
        topic_weight: weight,

        // P1 — time in mesh. Small positive: sticking around is mildly good.
        time_in_mesh_weight: 0.1,
        time_in_mesh_quantum: Duration::from_secs(1),
        time_in_mesh_cap: 100.0,

        // P2 — first deliveries. The reward that actually distinguishes a
        // useful peer on a low-rate chain.
        first_message_deliveries_weight: 1.0,
        first_message_deliveries_decay: 0.97,
        first_message_deliveries_cap: 100.0,

        // P3 — mesh message deliveries: OFF. See the doc comment.
        mesh_message_deliveries_weight: 0.0,
        mesh_message_deliveries_decay: 0.0,
        mesh_message_deliveries_cap: 0.0,
        mesh_message_deliveries_threshold: 0.0,
        mesh_message_deliveries_window: Duration::from_secs(0),
        mesh_message_deliveries_activation: Duration::from_secs(0),

        // P3b — sticky mesh failure penalty: OFF, for the same reason. It
        // only fires on peers already carrying a P3 penalty, which cannot
        // exist now; leaving it armed would be leaving a trap for whoever
        // re-enables P3.
        mesh_failure_penalty_weight: 0.0,
        mesh_failure_penalty_decay: 0.0,

        // P4 — invalid messages. This is the penalty that should exist: it
        // fires only on a `Reject`, which `gossip.rs` reserves for provable
        // violations.
        invalid_message_deliveries_weight: invalid_weight,
        invalid_message_deliveries_decay: 0.5,
    }
}

/// Peer score parameters for the three Genesis-4 topics.
///
/// `behind_proxy` zeroes the IP-colocation weight. Behind a proxy/NAT every
/// inbound peer shares one source IP, and the colocation penalty (−50 ×
/// excess² over the threshold) crosses `graylist_threshold` at six peers — the
/// node then ignores its entire mesh. Off by default: the penalty is the right
/// answer to real sybil colocation, and an operator who knows they are proxied
/// says so.
pub fn peer_score_params(behind_proxy: bool) -> PeerScoreParams {
    let mut params = PeerScoreParams {
        app_specific_weight: 1.0,
        ip_colocation_factor_threshold: 3.0,
        ip_colocation_factor_weight: if behind_proxy { 0.0 } else { -50.0 },
        decay_interval: Duration::from_secs(60),
        decay_to_zero: 0.01,
        ..PeerScoreParams::default()
    };
    // Blocks carry the chain; a peer that lies about one is the worst kind.
    params.topics.insert(IdentTopic::new(TOPIC_BLOCKS).hash(), topic_params(0.5, -100.0));
    // Attestations are the highest-rate topic and the one `gossip.rs` judges.
    params
        .topics
        .insert(IdentTopic::new(TOPIC_ATTESTATIONS).hash(), topic_params(0.4, -100.0));
    params.topics.insert(IdentTopic::new(TOPIC_TXS).hash(), topic_params(0.3, -50.0));
    params
}

/// Score thresholds, as Genesis-3 runs them.
pub fn peer_score_thresholds() -> PeerScoreThresholds {
    PeerScoreThresholds {
        gossip_threshold: -100.0,
        publish_threshold: -200.0,
        graylist_threshold: -400.0,
        opportunistic_graft_threshold: 5.0,
        ..PeerScoreThresholds::default()
    }
}

/// The gossipsub config.
///
/// `validate_messages()` is the switch that makes `gossip.rs` load-bearing:
/// with it on, gossipsub relays nothing until the node reports a verdict, so
/// this node never forwards an attestation it has not judged.
pub fn gossipsub_config() -> Result<gossipsub::Config, String> {
    // Message id = SHA3-256 of the payload, truncated. Deterministic across
    // toolchains (the default hasher is not — two nodes on different Rust
    // versions computed different ids and broke dedup), and sha3 is already
    // this tree's only hash.
    let msg_id_fn = |m: &gossipsub::Message| {
        use sha3::{Digest, Sha3_256};
        let d = Sha3_256::digest(&m.data);
        MessageId::from(&d[..16])
    };
    gossipsub::ConfigBuilder::default()
        .protocol_id_prefix(GOSSIP_PROTOCOL_PREFIX)
        .heartbeat_interval(Duration::from_secs(1))
        .validation_mode(ValidationMode::Strict)
        .validate_messages()
        .message_id_fn(msg_id_fn)
        .max_transmit_size(MAX_GOSSIP_BYTES)
        .duplicate_cache_time(DUPLICATE_CACHE_TIME)
        .build()
        .map_err(|e| format!("gossipsub config: {e}"))
}

// ── Handle ──────────────────────────────────────────────────────────────────

enum Command {
    /// A typed frame from the engine (`net::FRAME_*` byte, then payload),
    /// routed to a topic or to the directed-sync path by that byte.
    Broadcast(Vec<u8>),
    /// The engine's verdict on a gossip message it was handed.
    Report(Origin, Verdict),
}

/// The engine's view of the libp2p stack: publish frames, report verdicts.
pub struct Handle {
    cmd: tokio::sync::mpsc::UnboundedSender<Command>,
    /// This node's libp2p identity. Public information; printed at boot so an
    /// operator can build the `/p2p/<id>` multiaddr peers dial.
    pub peer_id: PeerId,
}

impl Handle {
    /// Publish one engine frame. Routing is by the leading `net::FRAME_*`
    /// byte, so the engine's call sites are identical on both transports.
    pub fn broadcast(&self, frame: Vec<u8>) {
        let _ = self.cmd.send(Command::Broadcast(frame));
    }

    /// Report the engine's decision on a gossip message. A no-op for an
    /// [`Origin::none`].
    pub fn report(&self, origin: &Origin, verdict: Verdict) {
        if origin.inner.is_some() {
            let _ = self.cmd.send(Command::Report(origin.clone(), verdict));
        }
    }
}

/// What `start` needs to bring a node onto the network.
pub struct Config {
    /// Addresses to listen on. `/ip4/0.0.0.0/tcp/16400` is the usual one.
    pub listen: Vec<Multiaddr>,
    /// Peers to dial and keep dialling.
    pub peers: Vec<Multiaddr>,
    /// Where `p2p_identity.bin` lives and where the block log is read from
    /// when serving a sync request.
    pub data_dir: PathBuf,
    /// Connection ceiling, enforced at the transport by `connection_limits`.
    pub max_peers: usize,
    /// Zero the IP-colocation penalty (see [`peer_score_params`]).
    pub behind_proxy: bool,
}

/// Load, or create, this node's libp2p transport identity.
///
/// **This is a transport identity, not a validator key and not a spending
/// key.** It authenticates a socket; it signs no block, no attestation and no
/// value. Validator keys are produced by `keygen` for devnet and by the
/// air-gapped ceremony of BLOCH-GENESIS-KEYS.md for anything real — never
/// here, never as a side effect of starting a node.
fn load_or_create_identity(path: &std::path::Path) -> io::Result<identity::Keypair> {
    match std::fs::read(path) {
        Ok(bytes) => identity::Keypair::from_protobuf_encoding(&bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("p2p identity: {e}"))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let kp = identity::Keypair::generate_ed25519();
            let bytes = kp
                .to_protobuf_encoding()
                .map_err(|e| io::Error::other(format!("p2p identity: {e}")))?;
            std::fs::write(path, &bytes)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
            }
            Ok(kp)
        }
        Err(e) => Err(e),
    }
}

/// Start the libp2p stack on its own thread and return the engine's handle.
///
/// The swarm runs on a current-thread tokio runtime in a dedicated OS thread;
/// the engine stays synchronous and keeps receiving [`NetEvent`]s on the same
/// `std::sync::mpsc` channel the devnet transport feeds. Nothing about the
/// engine's shape changes with the transport.
pub fn start(
    cfg: Config,
    events: EngineSender<NetEvent>,
    head_slot: Arc<AtomicU64>,
) -> io::Result<Handle> {
    std::fs::create_dir_all(&cfg.data_dir)?;
    let keypair = load_or_create_identity(&cfg.data_dir.join("p2p_identity.bin"))?;
    let peer_id = PeerId::from(keypair.public());

    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<io::Result<()>>();

    std::thread::Builder::new().name("bloch-p2p".into()).spawn(move || {
        let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
            Ok(rt) => rt,
            Err(e) => {
                let _ = ready_tx.send(Err(e));
                return;
            }
        };
        rt.block_on(async move {
            match build_swarm(&keypair, &cfg) {
                Ok(swarm) => {
                    let _ = ready_tx.send(Ok(()));
                    run_swarm(swarm, cfg, cmd_rx, events, head_slot).await;
                }
                Err(e) => {
                    let _ = ready_tx.send(Err(e));
                }
            }
        });
    })?;

    match ready_rx.recv() {
        Ok(Ok(())) => Ok(Handle { cmd: cmd_tx, peer_id }),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(io::Error::other("p2p thread died before it started")),
    }
}

type Swarm = libp2p::Swarm<G4Behaviour>;

fn build_swarm(keypair: &identity::Keypair, cfg: &Config) -> io::Result<Swarm> {
    let gs_cfg = gossipsub_config().map_err(io::Error::other)?;
    let mut gs = gossipsub::Behaviour::new(MessageAuthenticity::Signed(keypair.clone()), gs_cfg)
        .map_err(|e| io::Error::other(format!("gossipsub: {e}")))?;
    if let Err(e) = gs.with_peer_score(peer_score_params(cfg.behind_proxy), peer_score_thresholds()) {
        // Non-fatal, but say it: with scoring off, every `Reject` this node
        // reports is log-only and a hostile peer pays nothing.
        eprintln!("p2p: peer scoring DISABLED ({e}) — rejections carry no penalty");
    }

    let max_peers = cfg.max_peers as u32;
    let mut swarm = SwarmBuilder::with_existing_identity(keypair.clone())
        .with_tokio()
        .with_tcp(libp2p::tcp::Config::default(), noise::Config::new, yamux_config)
        .map_err(|e| io::Error::other(e.to_string()))?
        .with_dns()
        .map_err(|e| io::Error::other(e.to_string()))?
        .with_behaviour(|key| {
            let identify = identify::Behaviour::new(identify::Config::new(
                IDENTIFY_PROTOCOL.into(),
                key.public(),
            ));
            // Hold established-incoming at max_peers so inbound dials cannot
            // fill every slot (eclipse hardening — bounded, not adversarially
            // tested); allow 2× total for churn headroom.
            let limits = libp2p::connection_limits::ConnectionLimits::default()
                .with_max_established(Some(max_peers.saturating_mul(2)))
                .with_max_established_incoming(Some(max_peers))
                .with_max_pending_incoming(Some(max_peers))
                .with_max_pending_outgoing(Some(max_peers.max(1)));
            G4Behaviour {
                gossipsub: gs,
                identify,
                sync: request_response::Behaviour::with_codec(
                    SyncCodec,
                    std::iter::once((SYNC_PROTOCOL, ProtocolSupport::Full)),
                    RrConfig::default()
                        .with_request_timeout(Duration::from_secs(30))
                        .with_max_concurrent_streams(MAX_CONCURRENT_SYNC_STREAMS),
                ),
                connection_limits: libp2p::connection_limits::Behaviour::new(limits),
            }
        })
        .map_err(|e| io::Error::other(e.to_string()))?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(300)))
        .build();

    for t in [TOPIC_BLOCKS, TOPIC_ATTESTATIONS, TOPIC_TXS] {
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&IdentTopic::new(t))
            .map_err(|e| io::Error::other(format!("subscribe {t}: {e}")))?;
    }
    for addr in &cfg.listen {
        swarm.listen_on(addr.clone()).map_err(|e| io::Error::other(e.to_string()))?;
    }
    Ok(swarm)
}

/// State the swarm loop owns.
struct Loop {
    events: EngineSender<NetEvent>,
    data_dir: PathBuf,
    head_slot: Arc<AtomicU64>,
    /// Highest block slot each peer has been seen forwarding. A relayer holds
    /// what it relays, so this is a sound (if conservative) hint for choosing
    /// who to ask for missing blocks.
    peer_head: HashMap<PeerId, u64>,
    /// Blocks published or received within [`REGOSSIP_SUPPRESS_TTL`]. Pruned
    /// on insert, so it stays bounded by the TTL and not by uptime.
    recent_blocks: HashMap<[u8; 32], Instant>,
    /// Full sync pages chased since the engine's applied head last moved. See
    /// [`MAX_PAGES_WITHOUT_PROGRESS`].
    pages_since_progress: u32,
    /// The applied head at the last page, so progress can be detected.
    head_at_last_page: u64,
    /// Address → the peer id reachable there, learned from a successful dial
    /// and from identify's advertised listen addresses. Lets an address-only
    /// `--p2p-peer` be recognised as already connected on the redial tick.
    ///
    /// The identify half matters more than it looks: when a pair of nodes both
    /// list each other, one side's connection is *inbound*, so it never dials
    /// and never learns the mapping from a dial. Without identify it redials
    /// that peer forever — and libp2p's TCP port reuse makes each of those
    /// dials fail with EADDRINUSE against the connection that already exists,
    /// which reads in the log exactly like a peer that cannot be reached.
    dialed: HashMap<Multiaddr, PeerId>,
    topics: Topics,
}

struct Topics {
    blocks: IdentTopic,
    attestations: IdentTopic,
    txs: IdentTopic,
}

impl Loop {
    fn note_block(&mut self, id: [u8; 32]) -> bool {
        let now = Instant::now();
        self.recent_blocks.retain(|_, t| now.duration_since(*t) < REGOSSIP_SUPPRESS_TTL);
        self.recent_blocks.insert(id, now).is_none()
    }

    fn emit(&self, ev: NetEvent) -> bool {
        self.events.send(ev).is_ok()
    }

    /// May this node chase another full page? Advancing the applied head is
    /// what buys the next 64 — see [`MAX_PAGES_WITHOUT_PROGRESS`].
    fn may_chase_page(&mut self) -> bool {
        let head = self.head_slot.load(Ordering::Relaxed);
        if head > self.head_at_last_page {
            self.head_at_last_page = head;
            self.pages_since_progress = 0;
        }
        if self.pages_since_progress >= MAX_PAGES_WITHOUT_PROGRESS {
            return false;
        }
        self.pages_since_progress += 1;
        true
    }
}

async fn run_swarm(
    mut swarm: Swarm,
    cfg: Config,
    mut cmd_rx: tokio::sync::mpsc::UnboundedReceiver<Command>,
    events: EngineSender<NetEvent>,
    head_slot: Arc<AtomicU64>,
) {
    let mut st = Loop {
        events,
        data_dir: cfg.data_dir.clone(),
        head_slot,
        peer_head: HashMap::new(),
        recent_blocks: HashMap::new(),
        pages_since_progress: 0,
        head_at_last_page: 0,
        dialed: HashMap::new(),
        topics: Topics {
            blocks: IdentTopic::new(TOPIC_BLOCKS),
            attestations: IdentTopic::new(TOPIC_ATTESTATIONS),
            txs: IdentTopic::new(TOPIC_TXS),
        },
    };

    // A node's own listen address commonly appears in a peer list that was
    // written once and handed to every node in a fleet. Dialling yourself is
    // never useful and produces a permanent stream of dial errors, so drop it
    // here rather than making every operator maintain N different lists.
    let peers: Vec<Multiaddr> =
        cfg.peers.iter().filter(|a| !cfg.listen.contains(a)).cloned().collect();
    for addr in &peers {
        if let Err(e) = swarm.dial(addr.clone()) {
            eprintln!("p2p: dial {addr}: {e}");
        }
    }

    // Sync responses are read off disk on a blocking pool, then handed back
    // here to be written to the substream — the swarm loop must never sit in
    // a file read while blocks and attestations wait behind it.
    let (resp_tx, mut resp_rx) = tokio::sync::mpsc::unbounded_channel::<(
        request_response::ResponseChannel<SyncResponse>,
        SyncResponse,
    )>();

    let mut redial = tokio::time::interval(REDIAL_INTERVAL);
    redial.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            ev = swarm.select_next_some() => {
                if !handle_swarm_event(&mut swarm, &mut st, &resp_tx, ev) {
                    return; // engine gone
                }
            }
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(c) => handle_command(&mut swarm, &mut st, c),
                    None => return, // engine dropped the handle
                }
            }
            Some((channel, resp)) = resp_rx.recv() => {
                let _ = swarm.behaviour_mut().sync.send_response(channel, resp);
            }
            _ = redial.tick() => {
                let connected: Vec<PeerId> = swarm.connected_peers().copied().collect();
                for addr in &peers {
                    // A configured peer may be written with or without its
                    // `/p2p/<id>` suffix — an operator pasting a listen address
                    // has no reason to know the id yet. When it is absent the
                    // id learned from the last successful dial of that exact
                    // address stands in, so an already-connected peer is not
                    // dialled again every tick (which would pile up a second
                    // connection per interval for the whole session).
                    let id = peer_id_of(addr).or_else(|| st.dialed.get(addr).copied());
                    if !id.is_some_and(|p| connected.contains(&p)) {
                        let _ = swarm.dial(addr.clone());
                    }
                }
            }
        }
    }
}

fn peer_id_of(addr: &Multiaddr) -> Option<PeerId> {
    addr.iter().find_map(|p| match p {
        libp2p::multiaddr::Protocol::P2p(id) => Some(id),
        _ => None,
    })
}

fn handle_command(swarm: &mut Swarm, st: &mut Loop, cmd: Command) {
    match cmd {
        Command::Report(origin, verdict) => {
            if let Some((msg_id, source)) = origin.inner {
                swarm
                    .behaviour_mut()
                    .gossipsub
                    .report_message_validation_result(&msg_id, &source, verdict.into());
            }
        }
        Command::Broadcast(frame) => {
            let Some((&tag, payload)) = frame.split_first() else { return };
            match tag {
                crate::net::FRAME_BLOCK => {
                    // Re-gossip suppression. A block this node produced has a
                    // content hash nobody has seen, so its own announcement is
                    // never suppressed; a block that arrived on the mesh in the
                    // last TTL would be refused by gossipsub's duplicate cache
                    // anyway, after paying the hash of the whole body.
                    if let Ok(env) = crate::codec::decode_envelope(payload) {
                        let id = *env.block_id().as_bytes();
                        if !st.note_block(id) {
                            return;
                        }
                    }
                    publish(swarm, st.topics.blocks.clone(), payload.to_vec(), "blocks");
                }
                crate::net::FRAME_ATT => {
                    publish(swarm, st.topics.attestations.clone(), payload.to_vec(), "attestations");
                }
                crate::net::FRAME_TX => {
                    publish(swarm, st.topics.txs.clone(), payload.to_vec(), "txs");
                }
                crate::net::FRAME_GET_BLOCKS => {
                    if payload.len() != 8 {
                        return;
                    }
                    let after = u64::from_le_bytes(payload.try_into().unwrap());
                    request_blocks(swarm, st, after);
                }
                _ => {}
            }
        }
    }
}

/// Per-message wire tracing, off unless `BLOCH_P2P_TRACE` is set.
///
/// Not `log`/`tracing`: this binary has no logging framework wired, and adding
/// one to get a diagnostic is a bigger decision than the diagnostic. The
/// closure keeps the formatting cost at zero when the switch is off.
fn trace(f: impl FnOnce() -> String) {
    use std::sync::OnceLock;
    static ON: OnceLock<bool> = OnceLock::new();
    if *ON.get_or_init(|| std::env::var_os("BLOCH_P2P_TRACE").is_some()) {
        eprintln!("p2p: {}", f());
    }
}

fn publish(swarm: &mut Swarm, topic: IdentTopic, data: Vec<u8>, name: &str) {
    let n = data.len();
    match swarm.behaviour_mut().gossipsub.publish(topic, data) {
        Ok(_) => trace(|| format!("→ published {n} bytes on {name}")),
        // Duplicate is expected and cheap to reach (we re-publish an
        // attestation released from the pending pool, for instance); it is not
        // an error worth a line per slot.
        Err(gossipsub::PublishError::Duplicate) => {}
        Err(e) => eprintln!("p2p: publish {name}: {e}"),
    }
}

/// Direct a `get-blocks` at the peers most likely to hold what we are missing.
///
/// Not a broadcast: the Genesis-3 root cause was exactly that, and it produced
/// O(peers × blocks) amplification that stalled the chain. Not a single peer
/// either — a silent one would stall recovery — so [`SYNC_FANOUT`] peers,
/// preferring the highest observed head.
fn request_blocks(swarm: &mut Swarm, st: &Loop, after_slot: u64) {
    let mut peers: Vec<PeerId> = swarm.connected_peers().copied().collect();
    if peers.is_empty() {
        return;
    }
    peers.sort_by_key(|p| {
        // Descending by observed head, then by PeerId so ties are stable and
        // the choice is not a function of HashMap iteration order.
        (std::cmp::Reverse(st.peer_head.get(p).copied().unwrap_or(0)), p.to_bytes())
    });
    let req = SyncRequest::GetBlocks { after_slot, limit: MAX_SYNC_BLOCKS as u32 };
    for p in peers.into_iter().take(SYNC_FANOUT) {
        swarm.behaviour_mut().sync.send_request(&p, req.clone());
    }
}

/// Returns false when the engine's receiver is gone (the node is shutting
/// down) — the loop then exits.
fn handle_swarm_event(
    swarm: &mut Swarm,
    st: &mut Loop,
    resp_tx: &tokio::sync::mpsc::UnboundedSender<(
        request_response::ResponseChannel<SyncResponse>,
        SyncResponse,
    )>,
    ev: SwarmEvent<G4BehaviourEvent>,
) -> bool {
    match ev {
        SwarmEvent::NewListenAddr { address, .. } => {
            println!("p2p: listening on {address}");
        }
        SwarmEvent::ConnectionEstablished { peer_id, ref endpoint, .. } => {
            println!("p2p: connected {peer_id}");
            if let libp2p::core::ConnectedPoint::Dialer { address, .. } = endpoint {
                st.dialed.insert(address.clone(), peer_id);
            }
            // DO NOT call `gossipsub.add_explicit_peer()` here — see this
            // module's header. An explicit peer is excluded from mesh
            // construction and is PRUNED when it GRAFTs; marking every
            // connection explicit is what made the Genesis-3 mesh unbuildable
            // on 2026-08-07. gossipsub learns about the peer on its own.
            //
            // Ask what we are missing, immediately. This is the restart path:
            // a node that comes back with a short log gets the rest from the
            // first peer it reaches, without waiting for the engine's sync
            // timer.
            let after = st.head_slot.load(Ordering::Relaxed);
            swarm.behaviour_mut().sync.send_request(
                &peer_id,
                SyncRequest::GetBlocks { after_slot: after, limit: MAX_SYNC_BLOCKS as u32 },
            );
        }
        SwarmEvent::ConnectionClosed { peer_id, num_established, cause, .. } => {
            if num_established == 0 {
                st.peer_head.remove(&peer_id);
                // The cause is the whole diagnostic value of this line. A bare
                // "disconnected" is what made the Genesis-3 yamux stream-cap
                // failure take days to find: the transport was terminating
                // connections and the log said only that peers came and went.
                match cause {
                    Some(e) => println!("p2p: disconnected {peer_id}: {e}"),
                    None => println!("p2p: disconnected {peer_id} (closed cleanly)"),
                }
            }
        }
        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
            // Loud only while this node has NOBODY, which is the state an
            // operator has to act on. With a peer already established, a failed
            // dial is usually libp2p's TCP port reuse colliding with the
            // connection that exists (EADDRINUSE on the local bind) or a
            // simultaneous dial from both ends — noise that reads exactly like
            // a real outage and would teach an operator to ignore the line.
            if swarm.connected_peers().next().is_none() {
                eprintln!("p2p: NO PEERS — dial failed ({peer_id:?}): {error}");
            } else {
                trace(|| format!("dial failed ({peer_id:?}): {error}"));
            }
        }
        SwarmEvent::IncomingConnectionError { error, send_back_addr, .. } => {
            eprintln!("p2p: inbound connection from {send_back_addr} failed: {error}");
        }
        SwarmEvent::Behaviour(G4BehaviourEvent::Identify(identify::Event::Received {
            peer_id,
            info,
            ..
        })) => {
            for addr in info.listen_addrs {
                st.dialed.insert(addr, peer_id);
            }
        }
        SwarmEvent::Behaviour(G4BehaviourEvent::Gossipsub(gossipsub::Event::Message {
            propagation_source,
            message_id,
            message,
        })) => {
            return on_gossip(swarm, st, propagation_source, message_id, message);
        }
        SwarmEvent::Behaviour(G4BehaviourEvent::Sync(request_response::Event::Message {
            peer,
            message,
            ..
        })) => match message {
            request_response::Message::Request { request, channel, .. } => {
                serve_sync(st, resp_tx.clone(), request, channel);
            }
            request_response::Message::Response { response, .. } => {
                let SyncResponse::Blocks { envelopes } = response;
                let was_full = envelopes.len() >= MAX_SYNC_BLOCKS;
                let mut highest = 0u64;
                for bytes in envelopes {
                    match crate::codec::decode_envelope(&bytes) {
                        Ok(env) => {
                            let slot = env.header.slot;
                            highest = highest.max(slot);
                            let e = st.peer_head.entry(peer).or_insert(0);
                            *e = (*e).max(slot);
                            if !st.emit(NetEvent::Block(env)) {
                                return false;
                            }
                        }
                        Err(e) => {
                            eprintln!("p2p: undecodable block in sync response from {peer}: {e}");
                        }
                    }
                }
                // Cold start: a full page means the peer has more. Ask for the
                // next one now, from the SAME peer, instead of waiting for the
                // engine's sync timer — that is the difference between "a
                // request from genesis is accepted" and "a node can actually
                // sync from genesis". A short page ends the walk.
                if was_full && highest > 0 && st.may_chase_page() {
                    swarm.behaviour_mut().sync.send_request(
                        &peer,
                        SyncRequest::GetBlocks {
                            after_slot: highest,
                            limit: MAX_SYNC_BLOCKS as u32,
                        },
                    );
                }
            }
        },
        SwarmEvent::Behaviour(G4BehaviourEvent::Sync(request_response::Event::OutboundFailure {
            peer,
            error,
            ..
        })) => {
            // A peer that does not speak /bloch-g4/sync/1 is not a Genesis-4
            // node. Nothing to fall back to — deliberately: Genesis-3
            // compatibility is not a goal, it is the thing the prefix prevents.
            eprintln!("p2p: sync request to {peer} failed: {error}");
        }
        _ => {}
    }
    true
}

/// Map one gossip message onto an engine event, reporting the verdict the edge
/// can already decide.
///
/// Blocks and transactions are judged here (does it decode?) and relayed at
/// once. Attestations are handed to the engine with their [`Origin`] and are
/// **not** relayed until it answers — that is the whole point of
/// `validate_messages()`, and the reason `gossip.rs` can be the admission
/// control rather than a library nobody calls.
fn on_gossip(
    swarm: &mut Swarm,
    st: &mut Loop,
    source: PeerId,
    message_id: MessageId,
    message: gossipsub::Message,
) -> bool {
    let topic = message.topic.clone();
    let report = |swarm: &mut Swarm, v: Verdict| {
        swarm
            .behaviour_mut()
            .gossipsub
            .report_message_validation_result(&message_id, &source, v.into());
    };

    if topic == st.topics.blocks.hash() {
        match crate::codec::decode_envelope(&message.data) {
            Ok(env) => {
                report(swarm, Verdict::Accept);
                trace(|| {
                    format!("← block slot {} from {source}", env.header.slot)
                });
                let slot = env.header.slot;
                let e = st.peer_head.entry(source).or_insert(0);
                *e = (*e).max(slot);
                st.note_block(*env.block_id().as_bytes());
                return st.emit(NetEvent::Block(env));
            }
            Err(e) => {
                // Undecodable bytes on the block topic cannot come from a
                // compliant node: that is a Reject, and P4 counts it.
                eprintln!("p2p: undecodable block from {source}: {e}");
                report(swarm, Verdict::Reject);
            }
        }
    } else if topic == st.topics.attestations.hash() {
        let mut r = crate::codec::Reader::new(&message.data);
        match crate::codec::decode_attestation(&mut r).and_then(|a| r.finish().map(|()| a)) {
            Ok(att) => {
                // No verdict yet. The engine decides through `gossip.rs` and
                // calls `Handle::report`, which is what finally relays it.
                let origin = Origin { inner: Some((message_id, source)) };
                return st.emit(NetEvent::Attestation(att, origin));
            }
            Err(e) => {
                eprintln!("p2p: undecodable attestation from {source}: {e}");
                report(swarm, Verdict::Reject);
            }
        }
    } else if topic == st.topics.txs.hash() {
        match bloch_pos_committee::transition::PosTransaction::from_canonical_bytes(&message.data) {
            Ok(tx) => {
                report(swarm, Verdict::Accept);
                return st.emit(NetEvent::Transaction(tx));
            }
            Err(e) => {
                eprintln!("p2p: undecodable transaction from {source}: {e}");
                report(swarm, Verdict::Reject);
            }
        }
    } else {
        // A topic we never subscribed to cannot reach here; if it somehow
        // does, ignoring it is the answer that penalizes nobody.
        report(swarm, Verdict::Ignore);
    }
    true
}

/// Answer a `get-blocks` off the blocking pool, capped in both blocks and
/// bytes, then hand the response back to the swarm loop to write.
fn serve_sync(
    st: &Loop,
    resp_tx: tokio::sync::mpsc::UnboundedSender<(
        request_response::ResponseChannel<SyncResponse>,
        SyncResponse,
    )>,
    request: SyncRequest,
    channel: request_response::ResponseChannel<SyncResponse>,
) {
    let SyncRequest::GetBlocks { after_slot, limit } = request;
    let dir = st.data_dir.clone();
    let limit = (limit as usize).min(MAX_SYNC_BLOCKS);
    tokio::task::spawn_blocking(move || {
        // `after_slot = 0` is the from-genesis case and is served like any
        // other: the scan starts at the first logged block. There is no
        // "recent only" path and no datadir donation.
        let envelopes = match crate::store::Store::blocks_after(&dir, after_slot, limit) {
            Ok(all) => {
                let mut out = Vec::new();
                let mut bytes = 0usize;
                for b in all.into_iter() {
                    // Byte cap as well as block cap: one answer must never
                    // become a history dump. Leave slack for the framing.
                    if bytes + b.len() + 4 > (MAX_SYNC_FRAME as usize) - 1024 {
                        break;
                    }
                    bytes += b.len() + 4;
                    out.push(b);
                }
                out
            }
            Err(e) => {
                eprintln!("p2p: serving get-blocks failed: {e}");
                Vec::new()
            }
        };
        let _ = resp_tx.send((channel, SyncResponse::Blocks { envelopes }));
    });
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// THE regression test for mesh defect (b) of 2026-08-07.
    ///
    /// It asserts twice: that the library default really does carry the
    /// poisonous P3/P3b (so the test is testing something), and that no topic
    /// this node configures inherits it. If the first assertion ever fails
    /// upstream, this test should be re-read, not deleted.
    #[test]
    fn score_params_have_no_p3() {
        let d = TopicScoreParams::default();
        assert!(
            d.mesh_message_deliveries_weight < 0.0,
            "upstream default no longer arms P3 — re-read this test before trusting it"
        );
        assert!(
            d.mesh_message_deliveries_threshold > 0.0,
            "upstream default no longer sets a P3 threshold — re-read this test"
        );

        let params = peer_score_params(false);
        assert_eq!(params.topics.len(), 3, "all three Genesis-4 topics must be scored");
        for (topic, t) in &params.topics {
            assert_eq!(
                t.mesh_message_deliveries_weight, 0.0,
                "P3 is armed on {topic:?}: a 30 s slot chain graylists its whole mesh"
            );
            assert_eq!(
                t.mesh_failure_penalty_weight, 0.0,
                "P3b is armed on {topic:?}"
            );
            assert_eq!(t.mesh_message_deliveries_threshold, 0.0, "P3 threshold left set on {topic:?}");
            assert!(
                t.mesh_message_deliveries_activation.is_zero(),
                "P3 activation left set on {topic:?}"
            );
            // The penalty that SHOULD exist, so "disable everything" cannot
            // pass this test.
            assert!(
                t.invalid_message_deliveries_weight < 0.0,
                "P4 disabled on {topic:?}: a Reject would cost the peer nothing"
            );
        }
    }

    /// The two bounds that killed connections when they drifted apart.
    #[test]
    fn bounds_hold() {
        assert!(MAX_YAMUX_STREAMS > MAX_CONCURRENT_SYNC_STREAMS);
        assert!(REGOSSIP_SUPPRESS_TTL >= DUPLICATE_CACHE_TIME);
    }

    /// A Genesis-4 node must not be able to talk to a Genesis-3 one. The
    /// Genesis-3 values are hard-coded here on purpose: this test fails if
    /// someone ever "simplifies" a prefix back to the default.
    #[test]
    fn protocol_ids_differ_from_genesis3() {
        assert_ne!(GOSSIP_PROTOCOL_PREFIX, "");
        assert_ne!(SYNC_PROTOCOL.as_ref(), "/bloch/sync/1");
        assert_ne!(IDENTIFY_PROTOCOL, "/bloch-sis/1.0.0");
        for t in [TOPIC_BLOCKS, TOPIC_ATTESTATIONS, TOPIC_TXS] {
            assert!(t.starts_with("bloch-g4/"), "{t} is not in the Genesis-4 namespace");
        }
        // The prefix must be a real one and not the library default (which is
        // `/meshsub`, exactly what Genesis-3 negotiates). `Config` exposes no
        // public reader for its protocol ids, so this asserts the input the
        // builder is given; `gossipsub_config` is the single place it is used.
        assert!(
            GOSSIP_PROTOCOL_PREFIX.starts_with("/bloch-g4"),
            "the gossipsub prefix left the Genesis-4 namespace"
        );
        assert_ne!(GOSSIP_PROTOCOL_PREFIX, "/meshsub", "that is the default Genesis-3 speaks");

        let cfg = gossipsub_config().expect("config builds");
        assert!(cfg.validate_messages(), "gossip.rs cannot gate relay without validate_messages");
        assert_eq!(cfg.duplicate_cache_time(), DUPLICATE_CACHE_TIME);
        assert!(
            REGOSSIP_SUPPRESS_TTL >= cfg.duplicate_cache_time(),
            "the suppression window is shorter than the cache it exists to match"
        );
    }

    #[test]
    fn sync_frames_round_trip() {
        let req = SyncRequest::GetBlocks { after_slot: 4242, limit: 64 };
        assert_eq!(decode_sync_request(&encode_sync_request(&req)).unwrap(), req);

        let resp = SyncResponse::Blocks { envelopes: vec![vec![1, 2, 3], vec![], vec![9; 100]] };
        assert_eq!(decode_sync_response(&encode_sync_response(&resp)).unwrap(), resp);
    }

    #[test]
    fn sync_frames_reject_trailing_bytes() {
        let mut b = encode_sync_request(&SyncRequest::GetBlocks { after_slot: 1, limit: 1 });
        b.push(0);
        assert!(decode_sync_request(&b).is_err(), "encode(x) ‖ junk must not decode");

        let mut b = encode_sync_response(&SyncResponse::Blocks { envelopes: vec![vec![7]] });
        b.push(0);
        assert!(decode_sync_response(&b).is_err());
    }

    #[test]
    fn sync_response_block_cap_is_enforced_on_decode() {
        // A hostile peer claiming more blocks than the cap must be refused
        // before the decoder allocates for them.
        let mut b = vec![SYNC_TAG_BLOCKS];
        b.extend_from_slice(&((MAX_SYNC_BLOCKS as u32) + 1).to_le_bytes());
        assert!(decode_sync_response(&b).is_err());
    }

    // ── Two live swarms on localhost ────────────────────────────────────────
    //
    // These bring up real sockets, a real noise handshake, a real gossipsub
    // mesh and the real request-response protocol. They deliberately do NOT
    // run consensus: what is under test is the transport, and a test that also
    // had to wait for sortition, proposals and fork choice would fail for
    // reasons that have nothing to do with the network. Consensus over this
    // transport is covered end-to-end by tests/cold_start.rs.

    use bloch_pos_committee::header::{BlockEnvelope, BlockHeaderV4, Body, VERSION_G4};
    use std::sync::mpsc::Receiver;

    fn envelope(slot: u64) -> BlockEnvelope {
        BlockEnvelope {
            header: BlockHeaderV4 {
                version: VERSION_G4,
                parent: [1; 32],
                state_root: [2; 32],
                body_root: [3; 32],
                slot,
                proposer_index: 0,
                randao_reveal: [4; 32],
                randao_mix: [5; 32],
                justified_root: [6; 32],
                finalized_root: [7; 32],
                attestation_root: [8; 32],
                coherence_root: [9; 32],
            },
            // Non-trivial length so a page is not accidentally tiny, and
            // slot-dependent so every block has a distinct message id.
            proposer_sig: vec![(slot % 251) as u8; 96],
            body: Body { transactions: Vec::new(), attestations: Vec::new() },
        }
    }

    /// A port nobody is listening on right now. Racy in principle; in practice
    /// the window between closing this listener and the swarm binding is
    /// microseconds, and the alternative (fixed ports) collides between
    /// parallel test binaries for certain.
    fn free_port() -> u16 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let p = l.local_addr().expect("addr").port();
        drop(l);
        p
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "bloch-pos-p2p-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("mkdir");
        d
    }

    struct Node {
        handle: Handle,
        rx: Receiver<NetEvent>,
        head: Arc<AtomicU64>,
        addr: Multiaddr,
        _dir: PathBuf,
    }

    /// Bring up one node's transport over a store seeded with blocks at slots
    /// `1..=blocks`.
    fn node(tag: &str, blocks: u64, peers: &[Multiaddr]) -> Node {
        let dir = tmpdir(tag);
        let mut store = crate::store::Store::open(&dir, &[9u8; 32]).expect("store");
        for slot in 1..=blocks {
            store.append(&envelope(slot)).expect("append");
        }
        let port = free_port();
        let addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/{port}").parse().expect("addr");
        let (tx, rx) = std::sync::mpsc::channel();
        let head = Arc::new(AtomicU64::new(blocks));
        let handle = start(
            Config {
                listen: vec![addr.clone()],
                peers: peers.to_vec(),
                data_dir: dir.clone(),
                max_peers: 16,
                // Every node in these tests shares 127.0.0.1, and the
                // colocation penalty is -50 × (peers_on_ip − 3)². Four nodes on
                // one host would graylist each other before the test could
                // observe anything. This is the same switch a fleet behind one
                // proxy needs, and it is why it exists.
                behind_proxy: true,
            },
            tx,
            head.clone(),
        )
        .expect("p2p starts");
        Node { handle, rx, head, addr, _dir: dir }
    }

    /// Collect events until `want` blocks have arrived or the deadline passes.
    fn collect_blocks(rx: &Receiver<NetEvent>, want: usize, secs: u64) -> Vec<u64> {
        let deadline = Instant::now() + Duration::from_secs(secs);
        let mut slots = Vec::new();
        while slots.len() < want && Instant::now() < deadline {
            match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(NetEvent::Block(env)) => slots.push(env.header.slot),
                Ok(_) => {}
                Err(_) => {}
            }
        }
        slots
    }

    /// Two nodes must form a mesh and keep it: after the first delivery lands,
    /// every subsequent publish must land too.
    ///
    /// "No `NoPeersSubscribedToTopic` in regime" is asserted by *observation*
    /// rather than by grepping a log: that error is precisely the state in
    /// which a publish reaches nobody, so a run of publishes that all arrive is
    /// the same claim, made where it cannot drift out of date. This is the
    /// regression test for the 2026-08-07 pair of mesh defects — with either of
    /// them present, the mesh never holds a peer and this test never sees a
    /// single block.
    #[test]
    fn two_nodes_form_a_mesh_and_keep_exchanging_blocks() {
        let a = node("mesh-a", 0, &[]);
        let b = node("mesh-b", 0, &[a.addr.clone()]);

        // Gossipsub needs the subscription exchange and a heartbeat before a
        // publish has anywhere to go, so the first block is retried — with
        // DIFFERENT bytes each attempt, which is not a detail. The message id
        // is a content hash and `publish()` inserts into the duplicate cache
        // before it looks for peers, so a retry of the identical block is
        // refused locally for the next 30 s and never leaves the node. That is
        // the same defect Genesis-3 hit twice (a re-announce and an IBD
        // re-request, both silently swallowed as `Duplicate`); a test that
        // re-published one fixed block would hang for reasons it blamed on the
        // mesh.
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut attempt = 0u64;
        let mut connected = false;
        while Instant::now() < deadline && !connected {
            attempt += 1;
            a.handle.broadcast(crate::net::block_frame(&envelope(900 + attempt)));
            connected = !collect_blocks(&b.rx, 1, 1).is_empty();
        }
        assert!(connected, "the mesh never formed: no block ever reached the peer");

        // Drain whatever else the retry loop put in flight, so the next
        // assertion is about the publishes it names and nothing else.
        while b.rx.recv_timeout(Duration::from_millis(300)).is_ok() {}

        // In regime now. Ten distinct blocks, one publish each, all must land.
        for slot in 2..=11u64 {
            a.handle.broadcast(crate::net::block_frame(&envelope(slot)));
        }
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut got: Vec<u64> = Vec::new();
        while got.len() < 10 && Instant::now() < deadline {
            if let Ok(NetEvent::Block(env)) = b.rx.recv_timeout(Duration::from_millis(200)) {
                if (2..=11).contains(&env.header.slot) {
                    got.push(env.header.slot);
                }
            }
        }
        got.sort_unstable();
        assert_eq!(
            got,
            (2..=11).collect::<Vec<_>>(),
            "the mesh dropped publishes after it had formed"
        );

        // And it is bidirectional — b was never told about a, it only accepted
        // a's dial, and it must still be able to publish back.
        b.handle.broadcast(crate::net::block_frame(&envelope(500)));
        assert_eq!(collect_blocks(&a.rx, 1, 20), vec![500], "reverse direction never delivered");
    }

    /// The exchange's question, at the transport layer: a node with an EMPTY
    /// store asks from genesis and must receive the whole chain — which means
    /// the answer has to be paginated, because one response is capped at
    /// [`MAX_SYNC_BLOCKS`].
    #[test]
    fn a_cold_node_is_served_the_whole_chain_from_genesis() {
        // Deliberately more than two full pages, so this fails if the
        // page-chasing loop is removed and only the first answer arrives.
        let total = (MAX_SYNC_BLOCKS * 2 + 37) as u64;
        let server = node("cold-server", total, &[]);
        let cold = node("cold-client", 0, &[server.addr.clone()]);
        assert_eq!(cold.head.load(Ordering::Relaxed), 0, "the cold node starts at genesis");

        let mut got = collect_blocks(&cold.rx, total as usize, 60);
        got.sort_unstable();
        assert_eq!(
            got.len(),
            total as usize,
            "a node asking from genesis got {} of {total} blocks — pagination stopped early",
            got.len()
        );
        assert_eq!(got.first(), Some(&1), "the walk did not start at the first block");
        assert_eq!(got.last(), Some(&total), "the walk did not reach the tip");
        assert_eq!(got, (1..=total).collect::<Vec<_>>(), "a block was skipped");
    }

    /// A node that was there, went away, and came back gets exactly the gap.
    #[test]
    fn a_restarted_node_recovers_only_what_it_missed() {
        let total = 200u64;
        let missed_from = 60u64;
        let server = node("restart-server", total, &[]);
        let restarted = node("restart-client", missed_from, &[server.addr.clone()]);
        assert_eq!(restarted.head.load(Ordering::Relaxed), missed_from);

        let want = (total - missed_from) as usize;
        let mut got = collect_blocks(&restarted.rx, want, 60);
        got.sort_unstable();
        assert_eq!(
            got,
            ((missed_from + 1)..=total).collect::<Vec<_>>(),
            "a restarted node did not get exactly the blocks after its head"
        );
    }

    #[test]
    fn verdict_maps_onto_gossipsub_verbs() {
        // Ignore must never become Reject: that mapping is how a mesh
        // graylists its honest peers.
        assert!(matches!(MessageAcceptance::from(Verdict::Accept), MessageAcceptance::Accept));
        assert!(matches!(MessageAcceptance::from(Verdict::Ignore), MessageAcceptance::Ignore));
        assert!(matches!(MessageAcceptance::from(Verdict::Reject), MessageAcceptance::Reject));
    }
}
