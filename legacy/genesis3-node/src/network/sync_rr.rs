//! Announce-then-pull directed sync — the IBD PULL path over libp2p
//! `request-response`.
//!
//! ## Why this module exists (root cause)
//!
//! The outbound router in `mod.rs` used to send every message that was not
//! `NewBlock`/`NewTransaction` to the shared "sync" **gossipsub** topic:
//!
//! ```text
//! NewBlock => "blocks", NewTransaction => "txs", _ => "sync"
//! ```
//!
//! That `_` arm swept in `GetBlock` / `GetHeaders` / `GetTips` — the IBD block
//! and header **fetch** requests. So a fresh node in IBD *broadcast* a
//! `GetBlock` for every missing block to the ENTIRE mesh (max-peers up to 500),
//! and every peer tried to answer: O(peers × blocks) amplification. That
//! saturated libp2p's gossipsub send queue ("Send Queue full"), starved real
//! `NewBlock` propagation, and stalled the chain. It also produced the
//! "an archival peer is needed" flood (asking the whole mesh, pruned peers
//! answer `BlockNotFound`).
//!
//! ## The fix: announce on gossip, PULL over request-response
//!
//! Lightweight ANNOUNCEMENTS (`PeerTip`, `Version`) stay on gossip — they are
//! small and benefit from mesh flooding. The PULL path (`GetBlock`,
//! `GetHeaders`, `GetTips`) is moved to a **directed** libp2p
//! `request-response` protocol (`/bloch/sync/1`): one request → one chosen
//! peer, not a broadcast. This removes the O(peers) IBD amplification entirely.
//!
//! ## Mixed-fleet compatibility
//!
//! Some fleet nodes still run the old binary and only speak gossip `GetBlock`.
//! The router therefore degrades gracefully: a directed request that fails with
//! `OutboundFailure` (peer doesn't speak `/bloch/sync/1`, dial failure, or
//! timeout) is **re-published on the gossip sync topic**, so an old peer can
//! still answer. See `mod.rs`'s `SyncRr` event arm.

use async_trait::async_trait;
use futures::prelude::*;
use libp2p::request_response::{self, Codec as RrCodec, Config as RrConfig, ProtocolSupport};
use libp2p::{PeerId, StreamProtocol};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io;
use std::time::Duration;

use super::{
    NetworkMessage, SyncEntry, MAX_WIRE_ADDR_LEN, MAX_WIRE_ADDRS, MAX_WIRE_BYTES,
    MAX_WIRE_GETHEADERS_LIMIT, MAX_WIRE_LOCATOR, MAX_WIRE_SYNC_ENTRIES, MAX_WIRE_TIPS,
};

/// Wire protocol id for the Bloch directed-sync request-response family.
pub const SYNC_PROTOCOL: StreamProtocol = StreamProtocol::new("/bloch/sync/1");

/// Max encoded frame — mirrors gossipsub `max_transmit_size` (one block body).
/// Kept as `u64` because `AsyncReadExt::take` wants that type; `MAX_FRAME_LIMIT`
/// below is the same value as `usize` for bincode's `with_limit`.
const MAX_FRAME: u64 = 4 * 1024 * 1024;
/// H-R3-4: `MAX_FRAME` as a `usize`, for `bincode::config::with_limit`. Frame
/// bytes are already capped at the transport by `.take(MAX_FRAME)`, but that
/// bounds only the RAW READ — see the `decode_*` functions below for why the
/// bincode-level limit is not redundant with it.
const MAX_FRAME_LIMIT: usize = MAX_FRAME as usize;

// ── Wire types ─────────────────────────────────────────────────────────────

/// A directed sync request (the PULL path). Deliberately carries NO `nonce`:
/// gossip dedup is irrelevant to request-response (each request is its own
/// substream), so the anti-dedup nonces the gossip variants need are dropped.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncRequest {
    GetBlock { block_hash: [u8; 32] },
    GetHeaders { from_blue_score: u64, limit: u32 },
    GetTips,
    /// M-10 (audit): directed peer-exchange request, added to move
    /// `PeerRequest`/`PeerExchange` off the gossip mesh. A ~2-byte
    /// `PeerRequest` used to make the receiver PUBLISH its whole known-peers
    /// table (up to `KNOWN_PEERS_CAP` entries) to the ENTIRE gossip mesh —
    /// a broadcast-amplifying reply to a broadcast request, and the
    /// receiver's complete peer table handed to anyone who asked (the
    /// reconnaissance step for an eclipse attempt). Routing this through
    /// `/bloch/sync/1` makes it what it always should have been: one
    /// requester, one direct answer.
    GetPeers,
}

/// A directed sync response, returned to the ONE requesting peer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncResponse {
    Block {
        block_hash: [u8; 32],
        blue_score: u64,
        height: u64,
        block_data: Vec<u8>,
    },
    BlockNotFound {
        block_hash: [u8; 32],
    },
    Headers {
        entries: Vec<SyncEntry>,
    },
    Tips {
        tips: Vec<SyncEntry>,
        locator: Vec<[u8; 32]>,
    },
    /// M-10: answer to [`SyncRequest::GetPeers`] — a bounded, RANDOM SAMPLE
    /// of the responder's known peers (never the whole table; see
    /// `network::mod::PEX_RESPONSE_SAMPLE_SIZE`), sent to the ONE requester.
    Peers {
        peers: Vec<String>,
    },
}

/// Map an outbound `NetworkMessage` to a `SyncRequest` IFF it is a PULL message
/// that must go out as a directed request rather than a gossip broadcast.
///
/// Returns `None` for everything that stays on the gossip announce/response
/// path (`PeerTip`, `Version`, `NewBlock`, `NewTransaction`, `Headers`, `Tips`,
/// `BlockNotFound`, PEX …). This is the router's single source of truth for
/// "does this leave the node as a directed pull, or as gossip?" — and is unit
/// tested to prove IBD fetches never hit the gossip mesh.
pub fn as_pull_request(msg: &NetworkMessage) -> Option<SyncRequest> {
    match msg {
        NetworkMessage::GetBlock { block_hash, .. } => {
            Some(SyncRequest::GetBlock { block_hash: *block_hash })
        }
        NetworkMessage::GetHeaders { from_blue_score, limit, .. } => Some(SyncRequest::GetHeaders {
            from_blue_score: *from_blue_score,
            limit: *limit,
        }),
        NetworkMessage::GetTips => Some(SyncRequest::GetTips),
        // M-10: PeerRequest is now a directed pull too — see `SyncRequest::GetPeers`.
        NetworkMessage::PeerRequest => Some(SyncRequest::GetPeers),
        _ => None,
    }
}

/// Convert a received `SyncResponse` into the `NetworkMessage` the existing
/// `main.rs` message-processor already understands, so directed-pull answers
/// flow through the SAME ingest path as the legacy gossip answers — no change
/// to the processor's block/header handling.
pub fn response_to_message(resp: SyncResponse) -> NetworkMessage {
    match resp {
        SyncResponse::Block { block_hash, blue_score, height, block_data } => {
            NetworkMessage::NewBlock { block_hash, blue_score, height, block_data }
        }
        // nonce is meaningless off the gossip topic; the processor ignores it.
        SyncResponse::BlockNotFound { block_hash } => {
            NetworkMessage::BlockNotFound { block_hash, nonce: 0 }
        }
        SyncResponse::Headers { entries } => NetworkMessage::Headers { entries },
        SyncResponse::Tips { tips, locator } => NetworkMessage::Tips { tips, locator },
        // M-10: feeds into the SAME `PeerExchange` ingest path gossip PEX
        // already uses (rate limit, batch cap, address validation, no
        // persistence until a dial confirms) — no new client-side logic
        // needed, only the transport (directed vs. broadcast) changed.
        SyncResponse::Peers { peers } => NetworkMessage::PeerExchange { peers },
    }
}

// ── Codec ──────────────────────────────────────────────────────────────────

/// Length-delimited-by-EOF bincode codec (mirrors libp2p's own cbor codec: the
/// request-response framework opens a fresh substream per message and closes
/// the write half after writing, so `read_to_end` cleanly delimits the frame).
#[derive(Clone, Default)]
pub struct BlochSyncCodec;

#[async_trait]
impl RrCodec for BlochSyncCodec {
    type Protocol = StreamProtocol;
    type Request = SyncRequest;
    type Response = SyncResponse;

    async fn read_request<T>(&mut self, _: &StreamProtocol, io: &mut T) -> io::Result<SyncRequest>
    where
        T: AsyncRead + Unpin + Send,
    {
        let buf = read_raw_frame(io).await?;
        decode_request(&buf)
    }

    async fn read_response<T>(&mut self, _: &StreamProtocol, io: &mut T) -> io::Result<SyncResponse>
    where
        T: AsyncRead + Unpin + Send,
    {
        let buf = read_raw_frame(io).await?;
        decode_response(&buf)
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
        let data = encode_frame(&req)?;
        io.write_all(&data).await
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
        let data = encode_frame(&resp)?;
        io.write_all(&data).await
    }
}

/// Read the raw frame bytes off the wire, capped at [`MAX_FRAME`]. This bounds
/// the READ; it does not by itself bound what bincode does with the bytes
/// (see [`decode_frame`]'s doc comment) — it only stops a peer from streaming
/// unbounded data down an open substream.
async fn read_raw_frame<T>(io: &mut T) -> io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin + Send,
{
    let mut buf = Vec::new();
    io.take(MAX_FRAME).read_to_end(&mut buf).await?;
    Ok(buf)
}

/// Bincode-encode a frame (same wire config as the gossip path uses).
pub fn encode_frame<M: Serialize>(m: &M) -> io::Result<Vec<u8>> {
    bincode::serde::encode_to_vec(m, bincode::config::standard())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

/// H-R3-4: this used to decode with `bincode::config::standard()` — NO
/// read limit — the exact anti-pattern `network/mod.rs::decode_wire_message`
/// exists to forbid on untrusted input ("`bincode::config::standard()`
/// without a limit must never be used on untrusted input"). The 4 MiB
/// `read_raw_frame` cap made the immediate blast radius accidental, not
/// structural: raise `MAX_FRAME`, or decode a buffer sourced any other way,
/// and `claim_container_read` becomes a no-op again and a small frame can
/// declare a multi-GB `Vec` length. This function is now the ONLY correct
/// way to decode a `/bloch/sync/1` frame: it (1) applies a bincode read
/// limit equal to `MAX_FRAME`, so an over-declared length is rejected before
/// allocation, and (2) rejects trailing bytes — `decode_from_slice` reports
/// how many bytes it consumed, and a frame padded past its logical content
/// (e.g. a 1-byte `GetTips` padded to 4 MiB) used to decode successfully with
/// the remainder silently discarded.
///
/// Field-level bounds (`GetHeaders.limit`, `Headers.entries.len()`, etc.) are
/// NOT applied here — see [`decode_request`] / [`decode_response`], which
/// call this and then apply the mirror of `validate_wire_bounds` for the
/// gossip path.
pub fn decode_frame<M: for<'de> Deserialize<'de>>(buf: &[u8]) -> io::Result<M> {
    let cfg = bincode::config::standard().with_limit::<MAX_FRAME_LIMIT>();
    let (msg, consumed) = bincode::serde::decode_from_slice(buf, cfg).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, e.to_string())
    })?;
    if consumed != buf.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "sync frame has {} trailing byte(s) after a {}-byte decode",
                buf.len() - consumed,
                consumed
            ),
        ));
    }
    Ok(msg)
}

/// Decode + bounds-validate an inbound [`SyncRequest`]. The directed-sync
/// analogue of `network/mod.rs::decode_wire_message` for the gossip path:
/// same read-limit discipline, same per-field bounds, so a peer cannot use
/// the directed protocol to bypass limits enforced on the gossip one.
pub fn decode_request(buf: &[u8]) -> io::Result<SyncRequest> {
    let req: SyncRequest = decode_frame(buf)?;
    validate_sync_request_bounds(&req)?;
    Ok(req)
}

/// Decode + bounds-validate an inbound [`SyncResponse`]. Without this, a
/// malicious peer answering our `GetHeaders` could return ~123,000
/// `SyncEntry`s in one 4 MiB frame instead of the `MAX_WIRE_SYNC_ENTRIES`
/// (2000) the gossip path enforces, and the processor would then walk the
/// whole thing and issue a `GetBlock` per unknown entry.
pub fn decode_response(buf: &[u8]) -> io::Result<SyncResponse> {
    let resp: SyncResponse = decode_frame(buf)?;
    validate_sync_response_bounds(&resp)?;
    Ok(resp)
}

fn bounds_violation(msg: &'static str) -> io::Error {
    // `InvalidData` is the marker the caller (network/mod.rs's SyncRr event
    // arm) uses to recognise a deliberate protocol violation — as opposed to
    // a transport-level `InboundFailure`/`OutboundFailure::Io` (timeout,
    // connection reset) which must NOT be treated as an attack — and route it
    // to `WirePenaltyTracker`, mirroring the gossip path's reaction to
    // `WireDecodeError::Bounds`.
    io::Error::new(io::ErrorKind::InvalidData, format!("sync wire bounds violation: {msg}"))
}

/// Mirrors `network/mod.rs::validate_wire_bounds` for [`SyncRequest`]. This is
/// what closes the gap C-1/H-4 both name: the directed protocol previously
/// enforced NONE of the bounds the gossip protocol enforces on the same
/// logical fields.
fn validate_sync_request_bounds(req: &SyncRequest) -> io::Result<()> {
    match req {
        SyncRequest::GetHeaders { limit, .. } => {
            if *limit > MAX_WIRE_GETHEADERS_LIMIT {
                return Err(bounds_violation("GetHeaders limit above MAX_WIRE_GETHEADERS_LIMIT"));
            }
        }
        SyncRequest::GetBlock { .. } | SyncRequest::GetTips | SyncRequest::GetPeers => {}
    }
    Ok(())
}

/// Mirrors `network/mod.rs::validate_wire_bounds` for [`SyncResponse`].
fn validate_sync_response_bounds(resp: &SyncResponse) -> io::Result<()> {
    match resp {
        SyncResponse::Block { block_data, .. } => {
            // Belt-and-braces: unreachable today (a response body can't
            // exceed the MAX_FRAME-capped frame that carries it), kept in
            // case the two constants ever diverge — same rationale as the
            // gossip path's NewBlock/NewTransaction checks.
            if block_data.len() > MAX_WIRE_BYTES {
                return Err(bounds_violation("block_data larger than MAX_WIRE_BYTES"));
            }
        }
        SyncResponse::BlockNotFound { .. } => {}
        SyncResponse::Headers { entries } => {
            if entries.len() > MAX_WIRE_SYNC_ENTRIES {
                return Err(bounds_violation("Headers entries longer than MAX_WIRE_SYNC_ENTRIES"));
            }
        }
        SyncResponse::Tips { tips, locator } => {
            if tips.len() > MAX_WIRE_TIPS {
                return Err(bounds_violation("Tips tips longer than MAX_WIRE_TIPS"));
            }
            if locator.len() > MAX_WIRE_LOCATOR {
                return Err(bounds_violation("Tips locator longer than MAX_WIRE_LOCATOR"));
            }
        }
        // M-10: mirrors the gossip PeerExchange/PeerCount bound exactly —
        // same field, same cap, whichever transport it arrives over.
        SyncResponse::Peers { peers } => {
            if peers.len() > MAX_WIRE_ADDRS {
                return Err(bounds_violation("Peers list longer than MAX_WIRE_ADDRS"));
            }
            if peers.iter().any(|a| a.len() > MAX_WIRE_ADDR_LEN) {
                return Err(bounds_violation("Peers address string longer than MAX_WIRE_ADDR_LEN"));
            }
        }
    }
    Ok(())
}

/// True iff an `io::Error` surfaced from this codec (via `InboundFailure::Io`
/// / `OutboundFailure::Io` in the caller) represents a DELIBERATE protocol
/// violation (oversized/malformed/out-of-bounds frame) rather than an
/// ordinary transport failure (peer disconnected, timed out, reset). Callers
/// use this to decide whether to apply a `WirePenaltyTracker` penalty —
/// penalizing a peer for a network hiccup would be a correctness bug, not
/// just an accounting one.
pub fn is_sync_protocol_violation(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::InvalidData
}

// ── Behaviour ──────────────────────────────────────────────────────────────

pub type Behaviour = request_response::Behaviour<BlochSyncCodec>;
pub type Event = request_response::Event<SyncRequest, SyncResponse>;

/// Max concurrent request-response streams (inbound + outbound) the handler keeps
/// open per connection before it drops new INBOUND streams with
/// "Dropping inbound stream because we are at capacity". libp2p's default is 100,
/// which a node catching up across the wide damaged-fork anticone blows past: the
/// recursive missing-parent resolution (`GetBlock` per absent ancestor) opens a
/// burst of streams, and once at capacity the peer's new-block deliveries AND its
/// inbound peering handshake get dropped — the follower sits `syncing:false` at its
/// snapshot tip and never converges.
///
/// H-R3-1: the original justification for raising this to 2048 ("DoS headroom
/// is a non-issue on the small trusted fleet") is exactly the assumption this
/// finding rejects — `/bloch/sync/1` is not restricted to a trusted fleet, and
/// 2048 concurrent inbound streams per connection was 2048 concurrently
/// in-flight `serve_sync_request` calls before the `ordered_hashes_from`
/// bound and the per-peer token bucket below existed. Lowered to 256: still
/// well above the observed ~80 streams/s legitimate IBD burst this constant
/// exists to serve, while no longer being an order of magnitude beyond it.
/// Combined with [`SyncRequestLimiter`] (per-peer request RATE) and the now
/// O(limit) cost of any single served request, the product of
/// (concurrent streams) × (per-request cost) is bounded on every axis, not
/// just this one.
const MAX_CONCURRENT_SYNC_STREAMS: usize = 256;

// ── H-R3-1 fix #4: per-peer token bucket on inbound sync requests ──────────
//
// Even with `ordered_hashes_from` now O(limit) and every SyncRequest/
// SyncResponse field bounded (H-R3-4), a single peer could still open
// MAX_CONCURRENT_SYNC_STREAMS legitimately-shaped requests back-to-back and
// impose Σ(per-request cost) on the node — the algorithmic fix bounds a
// single request's cost, not the aggregate RATE. This bucket bounds the rate,
// independent of it.

/// Bucket capacity (burst allowance) per peer.
const SYNC_BUCKET_CAPACITY: u32 = 64;
/// Refill rate per peer, tokens/second. At capacity 64 this allows a burst of
/// 64 immediately, then a sustained 8 req/s — comfortably above what one
/// honest IBD follower needs (it directs pulls to ONE selected peer at a
/// time, see `select_pull_peer`) while bounding what a single hostile
/// identity can sustain against us.
const SYNC_BUCKET_REFILL_PER_SEC: u32 = 8;
/// Cap on the number of peers tracked, mirroring
/// `network::WIRE_PENALTY_TRACK_CAP` — bounds memory against an attacker
/// cycling libp2p identities (free to generate).
const SYNC_LIMITER_TRACK_CAP: usize = 1024;

/// Per-peer token bucket for inbound `/bloch/sync/1` REQUESTS (as opposed to
/// [`super::WirePenaltyTracker`], which scores DECODE/BOUNDS violations).
/// `allow` is the only entry point: it refills lazily on each call (no
/// background task) and consumes one token per call, returning whether the
/// request should be served.
pub struct SyncRequestLimiter {
    buckets: HashMap<PeerId, (std::time::Instant, u32)>,
}

impl Default for SyncRequestLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl SyncRequestLimiter {
    pub fn new() -> Self {
        Self { buckets: HashMap::new() }
    }

    /// Returns `true` iff a token was available (and is now consumed) for
    /// `peer`. Callers must NOT serve the request when this returns `false`.
    pub fn allow(&mut self, peer: PeerId) -> bool {
        use std::time::Instant;
        let now = Instant::now();
        if self.buckets.len() >= SYNC_LIMITER_TRACK_CAP && !self.buckets.contains_key(&peer) {
            // Tracking map full and this is an UNKNOWN peer: fail CLOSED.
            // Unlike WirePenaltyTracker (where failing open under a full map
            // just under-penalizes an already-misbehaving peer), failing
            // open here would mean an identity-cycling attacker gets an
            // unlimited request rate by always looking "new" once the map
            // fills — exactly the amplification this bucket exists to stop.
            return false;
        }
        let entry = self.buckets.entry(peer).or_insert((now, SYNC_BUCKET_CAPACITY));
        let elapsed = now.saturating_duration_since(entry.0).as_secs_f64();
        // checked/saturating throughout: `elapsed` is always >= 0.0 (Instant
        // is monotonic and we saturate the duration), and the refill amount
        // is clamped to the bucket capacity before it can overflow a u32.
        let refill = (elapsed * SYNC_BUCKET_REFILL_PER_SEC as f64).floor();
        if refill >= 1.0 {
            let refill_tokens = if refill.is_finite() && refill <= u32::MAX as f64 {
                refill as u32
            } else {
                SYNC_BUCKET_CAPACITY
            };
            entry.1 = entry.1.saturating_add(refill_tokens).min(SYNC_BUCKET_CAPACITY);
            entry.0 = now;
        }
        if entry.1 > 0 {
            entry.1 -= 1;
            true
        } else {
            false
        }
    }

    /// Number of peers currently tracked (observability for tests/metrics).
    pub fn tracked_peers(&self) -> usize {
        self.buckets.len()
    }
}

/// Build the request-response behaviour for `/bloch/sync/1`. `Full` support =
/// this node both serves inbound pulls and issues outbound pulls.
pub fn new_behaviour() -> Behaviour {
    Behaviour::with_codec(
        BlochSyncCodec,
        std::iter::once((SYNC_PROTOCOL, ProtocolSupport::Full)),
        RrConfig::default()
            .with_request_timeout(Duration::from_secs(30))
            .with_max_concurrent_streams(MAX_CONCURRENT_SYNC_STREAMS),
    )
}

// ── Peer selection (archival-preferred) ──────────────────────────────────────

/// Per-peer sync hint tracked in the network loop: highest announced blue_score
/// and whether the peer advertises itself as archival (learned from the
/// identify agent-version handshake; `None` = old binary / unknown).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PeerSync {
    pub blue_score: u64,
    pub archival: Option<bool>,
}

/// Choose the single peer to direct an IBD pull to.
///
/// Priority (per design): a known-**archival** peer → the explicit `--peer` →
/// the highest `blue_score` peer. Ties break deterministically by PeerId bytes.
/// Returns `None` when no peer is connected (caller then falls back to gossip).
pub fn select_pull_peer(
    peers: &HashMap<PeerId, PeerSync>,
    explicit: &HashSet<PeerId>,
) -> Option<PeerId> {
    // 1. Archival-preferred: highest blue_score among known-archival peers.
    if let Some(p) = peers
        .iter()
        .filter(|(_, s)| s.archival == Some(true))
        .max_by(|a, b| score_cmp(a, b))
        .map(|(p, _)| *p)
    {
        return Some(p);
    }
    // 2. Explicit --peer that is currently connected (highest blue_score).
    if let Some(p) = peers
        .iter()
        .filter(|(p, _)| explicit.contains(p))
        .max_by(|a, b| score_cmp(a, b))
        .map(|(p, _)| *p)
    {
        return Some(p);
    }
    // 3. Highest blue_score peer (archival unknown).
    peers.iter().max_by(|a, b| score_cmp(a, b)).map(|(p, _)| *p)
}

fn score_cmp(
    a: &(&PeerId, &PeerSync),
    b: &(&PeerId, &PeerSync),
) -> std::cmp::Ordering {
    a.1.blue_score
        .cmp(&b.1.blue_score)
        .then_with(|| a.0.to_bytes().cmp(&b.0.to_bytes()))
}

// ── Archival advertisement over the identify handshake (wire-safe) ───────────

/// The identify agent-version string this node advertises. We do NOT add a
/// field to the gossip `Version` frame (that would change the bincode wire
/// layout and break the mixed old/new fleet); instead archival is carried in
/// the standard libp2p identify agent-version string — a plain, self-describing
/// field that old binaries simply don't parse.
///
/// Format: `bloch/<pkg-version>/a` (archival) or `bloch/<pkg-version>/n`.
pub fn agent_version(archive: bool) -> String {
    format!(
        "bloch/{}/{}",
        env!("CARGO_PKG_VERSION"),
        if archive { "a" } else { "n" }
    )
}

/// Parse the archival bit out of a peer's identify agent-version. Returns
/// `None` for peers that don't speak our scheme (old binaries / other agents),
/// so peer-selection treats their archival status as unknown.
pub fn parse_archival_agent(agent_version: &str) -> Option<bool> {
    if !agent_version.starts_with("bloch/") {
        return None;
    }
    match agent_version.rsplit('/').next() {
        Some("a") => Some(true),
        Some("n") => Some(false),
        _ => None,
    }
}

/// Extract PeerIds from `--peer` multiaddrs (the trailing `/p2p/<id>`), used to
/// recognise explicitly-configured peers in `select_pull_peer`.
pub fn explicit_peer_ids(multiaddrs: &[String]) -> HashSet<PeerId> {
    multiaddrs
        .iter()
        .filter_map(|s| {
            s.rsplit("/p2p/")
                .next()
                .filter(|tail| *tail != s.as_str()) // require an actual /p2p/ segment
                .and_then(|id| id.parse::<PeerId>().ok())
        })
        .collect()
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_requests() -> Vec<SyncRequest> {
        vec![
            SyncRequest::GetBlock { block_hash: [7u8; 32] },
            SyncRequest::GetHeaders { from_blue_score: 42, limit: 500 },
            SyncRequest::GetTips,
            SyncRequest::GetPeers,
        ]
    }

    fn sample_responses() -> Vec<SyncResponse> {
        vec![
            SyncResponse::Block {
                block_hash: [9u8; 32],
                blue_score: 123,
                height: 45,
                block_data: vec![1, 2, 3, 4, 5],
            },
            SyncResponse::BlockNotFound { block_hash: [3u8; 32] },
            SyncResponse::Headers {
                entries: vec![
                    SyncEntry { hash: [1u8; 32], blue_score: 1, height: 1 },
                    SyncEntry { hash: [2u8; 32], blue_score: 2, height: 2 },
                ],
            },
            SyncResponse::Tips {
                tips: vec![SyncEntry { hash: [4u8; 32], blue_score: 9, height: 9 }],
                locator: vec![[5u8; 32], [6u8; 32]],
            },
            SyncResponse::Peers {
                peers: vec!["/ip4/1.2.3.4/tcp/16110/p2p/x".to_string()],
            },
        ]
    }

    // 1. Pure bincode frame round-trip for every request/response variant.
    #[test]
    fn frame_roundtrip() {
        for req in sample_requests() {
            let bytes = encode_frame(&req).unwrap();
            let back: SyncRequest = decode_frame(&bytes).unwrap();
            assert_eq!(req, back, "request frame round-trip");
        }
        for resp in sample_responses() {
            let bytes = encode_frame(&resp).unwrap();
            let back: SyncResponse = decode_frame(&bytes).unwrap();
            assert_eq!(resp, back, "response frame round-trip");
        }
    }

    // 2. Exercise the ACTUAL async Codec methods (write_* then read_* over an
    //    in-memory stream), proving the /bloch/sync/1 wire encode/decode works.
    #[test]
    fn codec_async_roundtrip() {
        use futures::executor::block_on;
        use futures::io::Cursor;

        block_on(async {
            let mut codec = BlochSyncCodec;
            for req in sample_requests() {
                let mut out = Cursor::new(Vec::new());
                codec
                    .write_request(&SYNC_PROTOCOL, &mut out, req.clone())
                    .await
                    .unwrap();
                let mut input = Cursor::new(out.into_inner());
                let back = codec.read_request(&SYNC_PROTOCOL, &mut input).await.unwrap();
                assert_eq!(req, back, "async request round-trip");
            }
            for resp in sample_responses() {
                let mut out = Cursor::new(Vec::new());
                codec
                    .write_response(&SYNC_PROTOCOL, &mut out, resp.clone())
                    .await
                    .unwrap();
                let mut input = Cursor::new(out.into_inner());
                let back = codec.read_response(&SYNC_PROTOCOL, &mut input).await.unwrap();
                assert_eq!(resp, back, "async response round-trip");
            }
        });
    }

    // 3. THE core assertion: IBD fetches route as directed pulls, never gossip.
    #[test]
    fn pull_variants_never_gossip_others_do() {
        // PULL variants -> directed request-response (Some).
        assert!(as_pull_request(&NetworkMessage::GetBlock { block_hash: [0u8; 32], nonce: 1 }).is_some());
        assert!(as_pull_request(&NetworkMessage::GetHeaders { from_blue_score: 0, limit: 500, nonce: 1 }).is_some());
        assert!(as_pull_request(&NetworkMessage::GetTips).is_some());
        // M-10: PeerRequest joined the directed pull side — no more
        // broadcasting "please tell me your peers" to the whole mesh.
        assert_eq!(as_pull_request(&NetworkMessage::PeerRequest), Some(SyncRequest::GetPeers));

        // Announce / response / block / tx -> stay on gossip (None).
        assert!(as_pull_request(&NetworkMessage::PeerTip { peer_id: "p".into(), blue_score: 1, height: 1 }).is_none());
        assert!(as_pull_request(&NetworkMessage::Version {
            version: 1, user_agent: "x".into(), blue_score: 1, height: 1, timestamp: 0,
        }).is_none());
        assert!(as_pull_request(&NetworkMessage::NewBlock {
            block_hash: [0u8; 32], blue_score: 0, height: 0, block_data: vec![],
        }).is_none());
        assert!(as_pull_request(&NetworkMessage::NewTransaction { txid: [0u8; 32], tx_data: vec![] }).is_none());
        assert!(as_pull_request(&NetworkMessage::Headers { entries: vec![] }).is_none());
        assert!(as_pull_request(&NetworkMessage::Tips { tips: vec![], locator: vec![] }).is_none());
        assert!(as_pull_request(&NetworkMessage::BlockNotFound { block_hash: [0u8; 32], nonce: 1 }).is_none());
        // PeerExchange (the ANSWER) stays off the directed-request path — it
        // only ever travels as a SyncResponse::Peers, never as a SyncRequest.
        assert!(as_pull_request(&NetworkMessage::PeerExchange { peers: vec![] }).is_none());
    }

    // 4. Peer selection: archival > explicit --peer > highest blue_score.
    #[test]
    fn peer_selection_prefers_archival() {
        let archival = PeerId::random();
        let explicit_peer = PeerId::random();
        let high_score = PeerId::random();

        let mut peers = HashMap::new();
        // archival peer has a LOWER score than the high-score peer, to prove
        // archival preference wins over raw score.
        peers.insert(archival, PeerSync { blue_score: 10, archival: Some(true) });
        peers.insert(explicit_peer, PeerSync { blue_score: 20, archival: Some(false) });
        peers.insert(high_score, PeerSync { blue_score: 99, archival: None });

        let mut explicit = HashSet::new();
        explicit.insert(explicit_peer);

        assert_eq!(select_pull_peer(&peers, &explicit), Some(archival),
            "an archival peer must win even over a higher-score non-archival peer");
    }

    #[test]
    fn peer_selection_falls_back_to_explicit_then_score() {
        let explicit_peer = PeerId::random();
        let high_score = PeerId::random();
        let low_score = PeerId::random();

        // No archival peer known -> explicit --peer wins next.
        let mut peers = HashMap::new();
        peers.insert(explicit_peer, PeerSync { blue_score: 5, archival: Some(false) });
        peers.insert(high_score, PeerSync { blue_score: 99, archival: None });
        peers.insert(low_score, PeerSync { blue_score: 1, archival: None });
        let mut explicit = HashSet::new();
        explicit.insert(explicit_peer);
        assert_eq!(select_pull_peer(&peers, &explicit), Some(explicit_peer),
            "with no archival peer, the explicit --peer is chosen");

        // No archival, no explicit -> highest blue_score.
        let empty = HashSet::new();
        assert_eq!(select_pull_peer(&peers, &empty), Some(high_score),
            "with neither archival nor explicit, the highest blue_score peer is chosen");
    }

    #[test]
    fn peer_selection_empty_is_none() {
        let peers: HashMap<PeerId, PeerSync> = HashMap::new();
        assert_eq!(select_pull_peer(&peers, &HashSet::new()), None);
    }

    // 5. Archival advertisement over the identify agent-version.
    #[test]
    fn archival_agent_roundtrip() {
        assert_eq!(parse_archival_agent(&agent_version(true)), Some(true));
        assert_eq!(parse_archival_agent(&agent_version(false)), Some(false));
        // old binary / other agent -> unknown.
        assert_eq!(parse_archival_agent("rust-libp2p/0.56.0"), None);
        assert_eq!(parse_archival_agent(""), None);
    }

    #[test]
    fn explicit_peer_id_parsing() {
        let id = PeerId::random();
        let with = format!("/ip4/1.2.3.4/tcp/16110/p2p/{}", id);
        let without = "/ip4/1.2.3.4/tcp/16110".to_string();
        let set = explicit_peer_ids(&[with, without]);
        assert!(set.contains(&id));
        assert_eq!(set.len(), 1, "only the addr carrying /p2p/<id> yields a PeerId");
    }

    #[test]
    fn response_maps_to_ingest_message() {
        // A directed Block answer must ingest exactly like a gossip NewBlock.
        let m = response_to_message(SyncResponse::Block {
            block_hash: [1u8; 32], blue_score: 7, height: 3, block_data: vec![9, 9],
        });
        match m {
            NetworkMessage::NewBlock { block_hash, blue_score, height, block_data } => {
                assert_eq!(block_hash, [1u8; 32]);
                assert_eq!((blue_score, height), (7, 3));
                assert_eq!(block_data, vec![9, 9]);
            }
            other => panic!("expected NewBlock, got {:?}", other.kind_name()),
        }
    }

    /// M-10: a directed `Peers` answer must ingest exactly like a gossip
    /// `PeerExchange` — same rate limit, batch cap, address validation,
    /// dial-before-persist discipline, just a different transport.
    #[test]
    fn peers_response_maps_to_peer_exchange_ingest_message() {
        let m = response_to_message(SyncResponse::Peers { peers: vec!["/ip4/9.9.9.9/tcp/1".to_string()] });
        match m {
            NetworkMessage::PeerExchange { peers } => {
                assert_eq!(peers, vec!["/ip4/9.9.9.9/tcp/1".to_string()]);
            }
            other => panic!("expected PeerExchange, got {:?}", other.kind_name()),
        }
    }

    // ── H-R3-4 regressions ──────────────────────────────────────────────────

    /// A genuine length-bomb frame: bincode-encode a `SyncResponse::Headers`
    /// whose length PREFIX declares far more `SyncEntry` items than the frame
    /// actually carries (truncate the real encoding down to a handful of
    /// bytes after the length prefix). Before the fix,
    /// `bincode::config::standard()` (no limit) would walk `claim_container_read`
    /// as a no-op and attempt to satisfy the declared length against a starved
    /// buffer; with the read limit configured, this must fail fast as a
    /// bounds/limit violation rather than attempt to allocate or read past
    /// what the frame contains.
    #[test]
    fn length_bomb_frame_is_rejected_not_decoded() {
        // A real encoding of a big-but-legal Headers response, so the length
        // prefix is authentic bincode varint output for a large count.
        let huge: Vec<SyncEntry> = (0..100_000u32)
            .map(|i| SyncEntry { hash: [0u8; 32], blue_score: i as u64, height: i as u64 })
            .collect();
        let full = encode_frame(&SyncResponse::Headers { entries: huge }).unwrap();
        assert!(full.len() > 1_000_000, "test premise: the full encoding is large");

        // Truncate to just past the enum discriminant + length prefix: the
        // declared entry count is still ~100,000, but almost none of the
        // per-entry bytes are present. This is exactly the "declared length
        // vastly exceeds actual bytes" shape of a length bomb.
        let bomb = &full[..full.len().min(32)];
        let err = decode_response(bomb).expect_err("a starved/truncated declared-length frame must be rejected");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(is_sync_protocol_violation(&err));
    }

    /// Trailing bytes after a fully-decoded frame must be rejected, not
    /// silently ignored. Before the fix, `decode_from_slice`'s second return
    /// value (`bytes_read`) was discarded, so a valid small message padded
    /// with arbitrary trailing bytes decoded successfully.
    #[test]
    fn trailing_bytes_after_valid_frame_are_rejected() {
        let req = SyncRequest::GetTips;
        let mut bytes = encode_frame(&req).unwrap();
        let clean_len = bytes.len();
        bytes.extend_from_slice(&[0xAAu8; 16]); // pad with trailing garbage

        // The generic decode_frame must reject the padded buffer...
        let err = decode_frame::<SyncRequest>(&bytes).expect_err("trailing bytes must be rejected");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(is_sync_protocol_violation(&err));

        // ...while the unpadded buffer decodes cleanly, proving the
        // rejection is specifically about the trailing bytes.
        let clean: SyncRequest = decode_frame(&bytes[..clean_len]).unwrap();
        assert_eq!(clean, req);
    }

    /// GetHeaders.limit above MAX_WIRE_GETHEADERS_LIMIT must be rejected by
    /// decode_request — mirrors the gossip path's validate_wire_bounds for
    /// the same logical field, closing the gap the directed protocol left
    /// open (a peer could ask for far more than 2000 headers per pull).
    #[test]
    fn oversized_getheaders_limit_is_rejected() {
        let req = SyncRequest::GetHeaders { from_blue_score: 0, limit: MAX_WIRE_GETHEADERS_LIMIT + 1 };
        let bytes = encode_frame(&req).unwrap();
        let err = decode_request(&bytes).expect_err("limit above MAX_WIRE_GETHEADERS_LIMIT must be rejected");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(is_sync_protocol_violation(&err));

        // At-the-cap is accepted.
        let ok_req = SyncRequest::GetHeaders { from_blue_score: 0, limit: MAX_WIRE_GETHEADERS_LIMIT };
        let ok_bytes = encode_frame(&ok_req).unwrap();
        assert_eq!(decode_request(&ok_bytes).unwrap(), ok_req);
    }

    /// A `Headers` response carrying more entries than MAX_WIRE_SYNC_ENTRIES
    /// must be rejected by decode_response — the scenario the annex names
    /// directly: a malicious peer answering our GetHeaders with ~123,000
    /// SyncEntry items instead of the 2000-entry cap the gossip path
    /// enforces.
    #[test]
    fn oversized_headers_response_rejected() {
        let entries: Vec<SyncEntry> = (0..(MAX_WIRE_SYNC_ENTRIES + 1))
            .map(|i| SyncEntry { hash: [0u8; 32], blue_score: i as u64, height: i as u64 })
            .collect();
        let resp = SyncResponse::Headers { entries };
        let bytes = encode_frame(&resp).unwrap();
        let err = decode_response(&bytes).expect_err("entries beyond MAX_WIRE_SYNC_ENTRIES must be rejected");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(is_sync_protocol_violation(&err));
    }

    /// A `Tips` response carrying more tips or locator hashes than the wire
    /// caps must be rejected.
    #[test]
    fn oversized_tips_response_rejected() {
        let too_many_tips = SyncResponse::Tips {
            tips: (0..(MAX_WIRE_TIPS + 1))
                .map(|i| SyncEntry { hash: [0u8; 32], blue_score: i as u64, height: i as u64 })
                .collect(),
            locator: vec![],
        };
        let bytes = encode_frame(&too_many_tips).unwrap();
        assert!(decode_response(&bytes).is_err());

        let too_long_locator = SyncResponse::Tips {
            tips: vec![],
            locator: (0..(MAX_WIRE_LOCATOR + 1)).map(|i| {
                let mut h = [0u8; 32];
                h[0] = (i % 256) as u8;
                h
            }).collect(),
        };
        let bytes2 = encode_frame(&too_long_locator).unwrap();
        assert!(decode_response(&bytes2).is_err());
    }

    /// M-10: a `Peers` response is bounded exactly like the gossip
    /// `PeerExchange`/`PeerCount` fields it now shares a transport with —
    /// too many entries, or one entry too long, must be rejected.
    #[test]
    fn oversized_peers_response_rejected() {
        let too_many = SyncResponse::Peers {
            peers: (0..(MAX_WIRE_ADDRS + 1)).map(|i| format!("/ip4/1.2.3.{}/tcp/1", i % 256)).collect(),
        };
        let bytes = encode_frame(&too_many).unwrap();
        assert!(decode_response(&bytes).is_err());

        let too_long_addr = SyncResponse::Peers {
            peers: vec!["x".repeat(MAX_WIRE_ADDR_LEN + 1)],
        };
        let bytes2 = encode_frame(&too_long_addr).unwrap();
        assert!(decode_response(&bytes2).is_err());

        // A well-formed sample must still decode cleanly.
        let ok = SyncResponse::Peers { peers: vec!["/ip4/1.2.3.4/tcp/16110/p2p/x".to_string()] };
        let ok_bytes = encode_frame(&ok).unwrap();
        assert_eq!(decode_response(&ok_bytes).unwrap(), ok);
    }

    /// `GetPeers` carries no fields to bound — it must always decode cleanly
    /// (a mutation guard: if a field is ever added here, this test should be
    /// revisited alongside a matching bounds check).
    #[test]
    fn get_peers_request_roundtrips() {
        let bytes = encode_frame(&SyncRequest::GetPeers).unwrap();
        assert_eq!(decode_request(&bytes).unwrap(), SyncRequest::GetPeers);
    }

    /// Ordinary transport failures (not protocol violations) must NOT be
    /// classified as a violation — penalizing a peer for a connection reset
    /// or timeout would be a correctness bug in the caller's reaction logic.
    #[test]
    fn transport_errors_are_not_protocol_violations() {
        let timeout = io::Error::new(io::ErrorKind::TimedOut, "timed out");
        let reset = io::Error::new(io::ErrorKind::ConnectionReset, "reset");
        assert!(!is_sync_protocol_violation(&timeout));
        assert!(!is_sync_protocol_violation(&reset));
    }

    // ── H-R3-1 fix #4: SyncRequestLimiter ───────────────────────────────────

    /// A peer can burst up to SYNC_BUCKET_CAPACITY requests immediately, then
    /// the (capacity + 1)-th is rejected until tokens refill.
    #[test]
    fn sync_request_limiter_bounds_burst() {
        let mut lim = SyncRequestLimiter::new();
        let peer = PeerId::random();
        for i in 0..SYNC_BUCKET_CAPACITY {
            assert!(lim.allow(peer), "request {} within burst capacity must be allowed", i);
        }
        assert!(!lim.allow(peer), "request beyond burst capacity must be rejected");
    }

    /// Different peers get independent buckets — one peer exhausting its
    /// burst must not affect another.
    #[test]
    fn sync_request_limiter_is_per_peer() {
        let mut lim = SyncRequestLimiter::new();
        let attacker = PeerId::random();
        let honest = PeerId::random();
        for _ in 0..SYNC_BUCKET_CAPACITY {
            assert!(lim.allow(attacker));
        }
        assert!(!lim.allow(attacker), "attacker's bucket must be exhausted");
        assert!(lim.allow(honest), "an unrelated peer's bucket must be untouched");
    }

    /// Once the tracked-peer cap is reached, a genuinely NEW (never-seen)
    /// peer must be refused rather than silently granted an unbounded bucket
    /// — the map must fail CLOSED, unlike WirePenaltyTracker's fail-open
    /// one-shot penalty (a false ALLOW here is a served request, not merely
    /// an under-counted score).
    #[test]
    fn sync_request_limiter_fails_closed_when_tracking_map_is_full() {
        let mut lim = SyncRequestLimiter::new();
        for _ in 0..SYNC_LIMITER_TRACK_CAP {
            let p = PeerId::random();
            assert!(lim.allow(p), "each distinct peer's first request must be allowed while under cap");
        }
        assert_eq!(lim.tracked_peers(), SYNC_LIMITER_TRACK_CAP);
        let overflow_peer = PeerId::random();
        assert!(
            !lim.allow(overflow_peer),
            "a brand-new peer arriving after the tracking cap is full must be refused, not granted an unlimited bucket"
        );
    }
}
