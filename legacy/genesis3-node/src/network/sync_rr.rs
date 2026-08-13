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

use super::{NetworkMessage, SyncEntry};

/// Wire protocol id for the Bloch directed-sync request-response family.
pub const SYNC_PROTOCOL: StreamProtocol = StreamProtocol::new("/bloch/sync/1");

/// Max encoded frame — mirrors gossipsub `max_transmit_size` (one block body).
const MAX_FRAME: u64 = 4 * 1024 * 1024;

// ── Wire types ─────────────────────────────────────────────────────────────

/// A directed sync request (the PULL path). Deliberately carries NO `nonce`:
/// gossip dedup is irrelevant to request-response (each request is its own
/// substream), so the anti-dedup nonces the gossip variants need are dropped.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncRequest {
    GetBlock { block_hash: [u8; 32] },
    GetHeaders { from_blue_score: u64, limit: u32 },
    GetTips,
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
        read_frame(io).await
    }

    async fn read_response<T>(&mut self, _: &StreamProtocol, io: &mut T) -> io::Result<SyncResponse>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_frame(io).await
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

async fn read_frame<T, M>(io: &mut T) -> io::Result<M>
where
    T: AsyncRead + Unpin + Send,
    M: for<'de> Deserialize<'de>,
{
    let mut buf = Vec::new();
    io.take(MAX_FRAME).read_to_end(&mut buf).await?;
    decode_frame(&buf)
}

/// Bincode-encode a frame (same wire config as the gossip path uses).
pub fn encode_frame<M: Serialize>(m: &M) -> io::Result<Vec<u8>> {
    bincode::serde::encode_to_vec(m, bincode::config::standard())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

/// Bincode-decode a frame.
pub fn decode_frame<M: for<'de> Deserialize<'de>>(buf: &[u8]) -> io::Result<M> {
    bincode::serde::decode_from_slice(buf, bincode::config::standard())
        .map(|(m, _)| m)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
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
/// snapshot tip and never converges. Raised well above the observed ~80 streams/s so
/// sync bursts flow; DoS headroom is a non-issue on the small trusted fleet.
const MAX_CONCURRENT_SYNC_STREAMS: usize = 2048;

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
}
