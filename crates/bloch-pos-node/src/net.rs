// SPDX-License-Identifier: AGPL-3.0-or-later

//! Transport selection, and the devnet TCP mesh.
//!
//! Two transports live behind [`Net`]:
//!
//! - [`p2p`](crate::p2p) — **the production layer**: libp2p, gossipsub with
//!   the 2026-08-07 mesh fixes, a Genesis-4-only protocol prefix, directed
//!   paginated sync, and `gossip.rs` wired as admission control.
//! - the devnet full mesh below — kept, unchanged, because a 64-validator
//!   devnet across five hosts finalized on it and that result must stay
//!   reproducible. Selected with `--transport devnet`, which is still the
//!   default; `--transport libp2p` opts into the production stack.
//!
//! The engine talks to both through the same two calls — [`Net::broadcast`]
//! with a typed frame, and [`Net::report`] with a verdict — so nothing in the
//! consensus loop knows which transport it is running on.
//!
//! ## The devnet mesh, and what it is not
//!
//! **This is not the production network layer.** What a devnet needs from the
//! network is only: every node eventually sees every block and attestation,
//! and a restarted node can ask a peer for the blocks it missed. A full mesh
//! over localhost delivers exactly that with no relay logic (everyone sends to
//! everyone, so nothing needs re-gossiping) and no peer scoring. It has no
//! authentication, no admission control, and it does not carry an [`Origin`],
//! so `gossip.rs`'s verdicts have nowhere to go on this path — the engine
//! still runs the pool, but a `Reject` costs the sender nothing here.
//!
//! Wire: `u32 LE frame length ‖ type byte ‖ payload`.
//! Types: 0x01 block envelope, 0x02 attestation, 0x03 get-blocks{after_slot},
//! 0x04 transaction, 0x05 get-time, 0x06 time{now_ms} (see the constants).
//!
//! Topology per peer pair: each side dials the other (two TCP connections per
//! pair). A node broadcasts on its *outbound* connections; sync requests go
//! out on outbound connections and are answered by the peer's inbound handler
//! on the same socket.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use bloch_pos_committee::attestation::Attestation;
use bloch_pos_committee::header::BlockEnvelope;

use crate::engine::EngineEvent;

pub const FRAME_BLOCK: u8 = 0x01;
pub const FRAME_ATT: u8 = 0x02;
pub const FRAME_GET_BLOCKS: u8 = 0x03;
/// Payload is one transaction's canonical bytes — the same bytes a block body
/// carries, so what a peer gossips and what a proposer commits to are the same
/// object and no second encoding exists to disagree with the first.
pub const FRAME_TX: u8 = 0x04;
/// Ask a peer for its clock. Empty payload; answered with [`FRAME_TIME`] on
/// the same socket. **This is a wire addition** (2026-08-31, the
/// clock-vs-peer-time gate): it is backward-safe — a pre-addition binary's
/// read loop drops any frame type it does not know, silently — but such a
/// peer contributes no sample, so the clock check only sees peers running
/// this build or newer. No flag day needed; rolling the fleet forward is
/// what arms the check.
pub const FRAME_GET_TIME: u8 = 0x05;
/// The answer: 8 bytes, the responder's unix time in milliseconds, LE. Time,
/// not slot: milliseconds are manifest-independent, and the requester judges
/// skew on its own slot geometry.
pub const FRAME_TIME: u8 = 0x06;

pub use crate::p2p::{Origin, Verdict};

/// What the engine receives from a transport.
pub enum NetEvent {
    Block(BlockEnvelope),
    /// An attestation and where it came from. The [`Origin`] is what lets the
    /// engine's `gossip.rs` decision reach gossipsub's
    /// `report_message_validation_result`; on the devnet mesh it is
    /// [`Origin::none`] and reporting is a no-op.
    Attestation(Attestation, Origin),
    Transaction(bloch_pos_committee::transition::PosTransaction),
}

/// The transport the engine holds. One of two, chosen at startup.
pub enum Net {
    Devnet(DevnetMesh),
    Libp2p(crate::p2p::Handle),
}

impl Net {
    /// Publish one frame (a `FRAME_*` type byte followed by its payload, no
    /// length prefix). The devnet mesh sends it to every peer; libp2p routes
    /// it by that type byte onto the matching gossip topic, or onto the
    /// directed sync path for `FRAME_GET_BLOCKS`.
    pub fn broadcast(&self, frame: Vec<u8>) {
        match self {
            Net::Devnet(m) => m.broadcast(frame),
            Net::Libp2p(h) => h.broadcast(frame),
        }
    }

    /// Hand a gossip message's verdict back to the transport.
    ///
    /// This is the other half of wiring `gossip.rs`: with gossipsub in
    /// `validate_messages()` mode nothing is relayed until this is called, so
    /// an attestation the pool has not judged is one this node does not
    /// forward. The devnet mesh has no such notion and drops it.
    pub fn report(&self, origin: &Origin, verdict: Verdict) {
        match self {
            Net::Devnet(_) => {}
            Net::Libp2p(h) => h.report(origin, verdict),
        }
    }
}

/// Depth of an inbound peer's broadcast queue before frames are dropped.
///
/// Bounded, unlike the outbound queues, because inbound connections are not
/// something this node chose: a box with 104 of them (measured on Genesis-4
/// mainnet, 2026-08-21) would let unbounded queues turn one stalled peer into
/// this node's memory problem. A dropped frame is recoverable — the peer asks
/// for what it missed with `FRAME_GET_BLOCKS` — so dropping is the safe end of
/// this trade.
/// How many peers may be answering our history request at the same time.
///
/// **Why this is not "all of them".** Every outbound dialer used to send
/// `FRAME_GET_BLOCKS` the moment it connected, and `serve_get_blocks` answered
/// UNCAPPED — the whole chain, in one burst, per peer. With a stale peer list
/// where most entries were dead that went unnoticed for months. On 2026-08-21
/// the list was corrected to 60 reachable peers and every one of them answered
/// at once: 60 x 145 MB of block frames into a node that was still replaying
/// and could not drain them. Twenty-two validators were OOM-killed at
/// 7.9 GB on 8 GB machines, 55 seconds after boot, and Fly stopped them after
/// ten restarts each.
///
/// Two peers is enough to make progress and to survive one of them being slow
/// or lying; the rest stay connected and still deliver broadcasts, they just do
/// not each dump a copy of history.
const SYNC_FANOUT: usize = 2;

/// Blocks in one `FRAME_GET_BLOCKS` answer.
///
/// The production transport already pages (`p2p::MAX_SYNC_BLOCKS`); this one
/// answered `usize::MAX` under a comment calling that deliberate, because "a
/// restarting node's single request must be answered in full or it never
/// catches up". That reasoning holds only while nobody re-asks. The requester
/// now re-asks from its new head while it holds a sync slot, so a bounded page
/// costs a few more round trips and removes the burst that was taking nodes
/// down.
const SYNC_PAGE_BLOCKS: usize = 512;

/// Network events queued for the engine before the transport starts shedding.
///
/// The engine consumes one channel on one thread, and during replay it does not
/// consume at all — replay is hours at Genesis-4's state size. An unbounded
/// queue in front of a consumer that is asleep is just a slower way to run out
/// of memory. Blocks and attestations are both recoverable (asked for again,
/// gossiped again), so shedding beats dying.
const ENGINE_QUEUE_CAP: usize = 4096;

const INBOUND_QUEUE_DEPTH: usize = 256;

/// The devnet TCP mesh: one queue per peer we dialed, plus one per peer that
/// dialed us.
pub struct DevnetMesh {
    peers: Vec<Sender<Vec<u8>>>,
    /// Broadcast queues for connections we did NOT dial.
    ///
    /// **Why this exists.** The module header describes a full mesh in which
    /// "each side dials the other", and under that assumption broadcasting on
    /// outbound connections alone reaches everyone. On Genesis-4 mainnet the
    /// assumption is false: 49 of the 64 validators run on Fly, which accepts
    /// no inbound TCP on the P2P ports — verified by scanning all 64 ports on
    /// three of them, all closed. They dial out and are never dialed back.
    ///
    /// With no relay logic in this transport ("everyone sends to everyone, so
    /// nothing needs re-gossiping"), a node nobody dials never receives a
    /// single broadcast. Its only path to a new block is polling with
    /// `FRAME_GET_BLOCKS`, so it runs permanently behind — which makes its
    /// attestations land on a stale view (rejected as `NotInCommittee`) and
    /// its proposals build on a stale parent. Those 49 validators held their
    /// slots in the proposer schedule and could not produce a block that
    /// stuck: ~94% of slots empty, and blocks arriving every 19 to 63 slots
    /// against a design of one per slot.
    ///
    /// Pushing on inbound connections costs nothing — the socket is already
    /// open and the peer is already reading it.
    inbound: Arc<Mutex<Vec<SyncSender<Vec<u8>>>>>,
    /// Where the listener actually bound — the real port when `listen_port`
    /// was 0. Tests dial it; production reads it never.
    local_addr: std::net::SocketAddr,
}

impl DevnetMesh {
    /// The address the inbound listener bound (test hook; see the field).
    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.local_addr
    }

    /// Broadcast one frame (type byte + payload, no length prefix) to every
    /// peer, dialed or dialing.
    pub fn broadcast(&self, frame: Vec<u8>) {
        for p in &self.peers {
            let _ = p.send(frame.clone());
        }
        // `retain` both sends and prunes: a closed receiver is a connection
        // whose writer thread has exited, and keeping its sender would leak one
        // entry per reconnect for as long as the node runs.
        if let Ok(mut inbound) = self.inbound.lock() {
            inbound.retain(|p| !matches!(p.try_send(frame.clone()), Err(TrySendError::Disconnected(_))));
        }
    }
}

/// Hand one network event to the engine, or drop it if the engine is behind.
///
/// The engine consumes on a single thread, and during replay it does not
/// consume at all — hours, at Genesis-4's state size. An unbounded queue in
/// front of a sleeping consumer is a slower way to run out of memory, which is
/// exactly how twenty-two validators died on 2026-08-21.
///
/// Shedding is safe here in a way it would not be for a request/response
/// protocol: a dropped block is asked for again by the sync pump, and a dropped
/// attestation is re-gossiped by its author's next broadcast. Losing one costs
/// a round trip. Keeping all of them costs the process.
///
/// Returns false when the engine is gone, so callers can stop their thread.
fn send_to_engine(
    events: &Sender<EngineEvent>,
    inflight: &Arc<std::sync::atomic::AtomicUsize>,
    ev: NetEvent,
) -> bool {
    if inflight.load(Ordering::Acquire) >= ENGINE_QUEUE_CAP {
        return true; // shed, but the connection stays healthy
    }
    inflight.fetch_add(1, Ordering::AcqRel);
    if events.send(EngineEvent::Net(ev)).is_err() {
        inflight.fetch_sub(1, Ordering::AcqRel);
        return false;
    }
    true
}

pub fn block_frame(env: &BlockEnvelope) -> Vec<u8> {
    let mut f = vec![FRAME_BLOCK];
    f.extend_from_slice(&crate::codec::encode_envelope(env));
    f
}

pub fn att_frame(att: &Attestation) -> Vec<u8> {
    let mut f = vec![FRAME_ATT];
    crate::codec::encode_attestation(&mut f, att);
    f
}

pub fn get_blocks_frame(after_slot: u64) -> Vec<u8> {
    let mut f = vec![FRAME_GET_BLOCKS];
    f.extend_from_slice(&after_slot.to_le_bytes());
    f
}

/// Send one transaction to a running node and disconnect.
///
/// The node gossips it onward, so any peer is an equally good entry point.
/// There is no acknowledgement: this transport has no request/response shape,
/// and inventing one for a devnet injector would be inventing wire protocol.
/// Confirmation is seeing the transaction land in a block.
pub fn send_transaction(addr: &str, tx_bytes: &[u8]) -> std::io::Result<()> {
    let mut sock = TcpStream::connect(addr)?;
    let mut frame = Vec::with_capacity(1 + tx_bytes.len());
    frame.push(FRAME_TX);
    frame.extend_from_slice(tx_bytes);
    write_frame(&mut sock, &frame)
}

pub(crate) fn write_frame(sock: &mut TcpStream, frame: &[u8]) -> std::io::Result<()> {
    let mut buf = Vec::with_capacity(4 + frame.len());
    buf.extend_from_slice(&(frame.len() as u32).to_le_bytes());
    buf.extend_from_slice(frame);
    sock.write_all(&buf)
}

pub(crate) fn read_frame(sock: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut len4 = [0u8; 4];
    sock.read_exact(&mut len4)?;
    let len = u32::from_le_bytes(len4) as usize;
    if len == 0 || len > crate::codec::MAX_FIELD_LEN {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "bad frame length"));
    }
    let mut buf = vec![0u8; len];
    sock.read_exact(&mut buf)?;
    Ok(buf)
}

/// Decode a data frame into an engine event. Get-blocks is handled by the
/// socket owner (it needs write access), not here.
fn decode_event(frame: &[u8]) -> Option<NetEvent> {
    match frame.first()? {
        &FRAME_BLOCK => {
            crate::codec::decode_envelope(&frame[1..]).ok().map(NetEvent::Block)
        }
        &FRAME_ATT => {
            let mut r = crate::codec::Reader::new(&frame[1..]);
            let att = crate::codec::decode_attestation(&mut r).ok()?;
            r.finish().ok()?;
            Some(NetEvent::Attestation(att, Origin::none()))
        }
        &FRAME_TX => {
            // Decoding here, at the edge, is deliberate: a frame that does not
            // decode never reaches the mempool, so a proposer cannot be handed
            // bytes it would later commit to and fail to reproduce.
            bloch_pos_committee::transition::PosTransaction::from_canonical_bytes(&frame[1..])
                .ok()
                .map(NetEvent::Transaction)
        }
        _ => None,
    }
}

/// Serve one get-blocks request on `sock` from the local block log.
/// Answer a peer's `FRAME_GET_BLOCKS` on the socket it asked over.
///
/// Takes the shared write half rather than a `&mut TcpStream` because this is
/// no longer the only writer: broadcasts go down inbound sockets too. Both
/// sides lock around a WHOLE frame, so the two can interleave between frames
/// and never inside one — a half-written frame followed by another writer's
/// bytes is not a slow peer, it is a corrupt stream the peer cannot resync.
///
/// The lock is taken per frame, not held across the whole dump: a full history
/// answer is hundreds of megabytes, and holding it throughout would stall every
/// broadcast to this peer for the duration.
fn serve_get_blocks(sock: &Arc<Mutex<TcpStream>>, data_dir: &PathBuf, frame: &[u8]) {
    if frame.len() != 9 {
        return;
    }
    let after = u64::from_le_bytes(frame[1..9].try_into().unwrap());
    // Paged at `SYNC_PAGE_BLOCKS`. This used to answer `usize::MAX` — the whole
    // chain in one burst — under a comment calling that deliberate, since "a
    // restarting node's single request must be answered in full or it never
    // catches up". That was true only while nobody re-asked. The dialer now
    // re-asks from its new head for as long as it holds a sync slot, so the
    // full history still arrives; it just no longer arrives as one allocation
    // large enough to kill the receiver.
    match crate::store::Store::blocks_after(data_dir, after, SYNC_PAGE_BLOCKS) {
        Ok(blocks) => {
            for b in blocks {
                let mut f = Vec::with_capacity(1 + b.len());
                f.push(FRAME_BLOCK);
                f.extend_from_slice(&b);
                let Ok(mut w) = sock.lock() else { return };
                if write_frame(&mut w, &f).is_err() {
                    return;
                }
            }
        }
        Err(e) => eprintln!("net: get-blocks failed: {e}"),
    }
}

/// Start the mesh: listen on `bind_addr:listen_port`, dial every peer, feed
/// decoded events into `events`. `head_slot` is read when (re)dialing to ask
/// peers for everything after our head.
///
/// `bind_addr` defaults to `127.0.0.1` at the call site and that default is
/// the safe one. This transport has **no authentication, no admission control
/// and no peer scoring** — `gossip.rs` is not wired here — so anything that
/// can reach the port can feed it frames. Binding a routable address is
/// therefore opt-in (`--listen-addr`), and when it is used the operator is
/// responsible for restricting the port to known peers at the firewall. The
/// production answer is the libp2p stack, not this.
/// RAII increment of the live-connection gauge: `inc` on construction, a
/// decrement on drop. Drop-based on purpose — the reader loops leave through
/// several `return`s and an `Err` arm, and a counter that must be decremented
/// by hand at each of them is a counter that will drift the first time one is
/// added. The gauge feeds `bloch_pos_peers_connected` (observability only;
/// nothing in consensus reads it).
struct ConnGauge(Arc<std::sync::atomic::AtomicUsize>);

impl ConnGauge {
    fn inc(gauge: Arc<std::sync::atomic::AtomicUsize>) -> ConnGauge {
        gauge.fetch_add(1, Ordering::Relaxed);
        ConnGauge(gauge)
    }
}

impl Drop for ConnGauge {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

pub fn start(
    bind_addr: &str,
    listen_port: u16,
    peer_addrs: Vec<String>,
    events: Sender<EngineEvent>,
    data_dir: PathBuf,
    head_slot: Arc<AtomicU64>,
    inflight: Arc<std::sync::atomic::AtomicUsize>,
    clock: Arc<crate::time_check::PeerClock>,
    peers_gauge: Arc<std::sync::atomic::AtomicUsize>,
) -> std::io::Result<DevnetMesh> {
    // Inbound: accept, then per-connection: read frames; data frames go to
    // the engine, get-blocks is answered in place from the log.
    let listener = TcpListener::bind((bind_addr, listen_port))?;
    let local_addr = listener.local_addr()?;
    let inbound: Arc<Mutex<Vec<SyncSender<Vec<u8>>>>> = Arc::new(Mutex::new(Vec::new()));
    {
        let events = events.clone();
        let data_dir = data_dir.clone();
        let inbound = inbound.clone();
        let inflight = inflight.clone();
        let peers_gauge = peers_gauge.clone();
        thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(sock) = conn else { continue };
                // Reading and writing need separate handles: the reader blocks
                // in `read_frame` for as long as the peer is quiet, and a
                // broadcast must not wait behind it.
                let Ok(rsock) = sock.try_clone() else { continue };
                let wsock = Arc::new(Mutex::new(sock));

                // One writer thread per connection, fed by a bounded queue, so
                // a peer that stops reading fills its own queue and is dropped
                // from there rather than blocking this node's broadcast loop.
                let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(INBOUND_QUEUE_DEPTH);
                {
                    let wsock = wsock.clone();
                    thread::spawn(move || {
                        for frame in rx {
                            let Ok(mut w) = wsock.lock() else { return };
                            if write_frame(&mut w, &frame).is_err() {
                                return; // dropping `rx` disconnects the sender,
                                        // which `broadcast` prunes on its next pass
                            }
                        }
                    });
                }
                if let Ok(mut reg) = inbound.lock() {
                    reg.push(tx);
                }

                let events = events.clone();
                let data_dir = data_dir.clone();
                let inflight = inflight.clone();
                let mut rsock = rsock;
                // The reader's lifetime IS the connection's: it blocks in
                // `read_frame` until the socket dies, whatever else happens
                // on the writer side. So the gauge guard lives here.
                let conn_gauge = ConnGauge::inc(peers_gauge.clone());
                thread::spawn(move || {
                    let _conn = conn_gauge;
                    loop {
                    match read_frame(&mut rsock) {
                        Ok(frame) => {
                            if frame.first() == Some(&FRAME_GET_BLOCKS) {
                                serve_get_blocks(&wsock, &data_dir, &frame);
                            } else if frame.as_slice() == [FRAME_GET_TIME] {
                                // The peer is running the clock-vs-peer-time
                                // gate; answer with our clock on the socket it
                                // asked over. NOT recorded as a sample here:
                                // inbound peers chose us, and a median open to
                                // volunteers is a median an attacker can pack.
                                let mut f = Vec::with_capacity(9);
                                f.push(FRAME_TIME);
                                f.extend_from_slice(&crate::time_check::now_ms().to_le_bytes());
                                let Ok(mut w) = wsock.lock() else { return };
                                if write_frame(&mut w, &f).is_err() {
                                    return;
                                }
                            } else if let Some(ev) = decode_event(&frame) {
                                if !send_to_engine(&events, &inflight, ev) {
                                    return;
                                }
                            }
                        }
                        Err(_) => return,
                    }
                    }
                });
            }
        });
    }

    // Outbound: one dialer per peer with a frame queue; a reader thread on
    // the same socket receives the peer's sync responses.
    //
    // `sync_slots` is what keeps a corrected peer list from being a denial of
    // service against ourselves: at most `SYNC_FANOUT` dialers may be asking
    // for history at any moment, however many peers are configured.
    let sync_slots = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut peers = Vec::new();
    for addr in peer_addrs {
        let (tx, rx): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = mpsc::channel();
        peers.push(tx);
        let events = events.clone();
        let head_slot = head_slot.clone();
        let sync_slots = sync_slots.clone();
        let inflight = inflight.clone();
        let clock = clock.clone();
        let peers_gauge = peers_gauge.clone();
        thread::spawn(move || loop {
            let Ok(sock) = TcpStream::connect(&addr) else {
                thread::sleep(Duration::from_millis(300));
                continue;
            };
            // One gauge unit per established dial, released when this
            // iteration ends (write failure -> `break` -> reconnect, or the
            // engine hanging up -> `return`). The devnet topology dials both
            // ways, so a fully-meshed pair counts twice here — the gauge
            // counts CONNECTIONS on this transport, and says so in the docs.
            let _conn = ConnGauge::inc(peers_gauge.clone());
            let mut wsock = sock;
            // Reader half: the peer answers our get-blocks on this socket.
            if let Ok(mut rsock) = wsock.try_clone() {
                let events = events.clone();
                let inflight = inflight.clone();
                let clock = clock.clone();
                let addr = addr.clone();
                thread::spawn(move || loop {
                    match read_frame(&mut rsock) {
                        Ok(frame) => {
                            if frame.len() == 9 && frame[0] == FRAME_TIME {
                                // The answer to the FRAME_GET_TIME sent below.
                                // Keyed by the CONFIGURED address: only peers
                                // the operator chose get a clock vote.
                                let peer_ms = u64::from_le_bytes(frame[1..9].try_into().unwrap());
                                clock.record(&addr, peer_ms, crate::time_check::now_ms());
                            } else if let Some(ev) = decode_event(&frame) {
                                if !send_to_engine(&events, &inflight, ev) {
                                    return;
                                }
                            }
                        }
                        Err(_) => return,
                    }
                });
            }
            // Ask for the peer's clock, once per connection, before anything
            // else — the boot gate may be waiting on this sample. An old
            // binary at the other end drops the frame silently and simply
            // never answers; the gate treats an unanswered peer as absent.
            let _ = write_frame(&mut wsock, &[FRAME_GET_TIME]);
            // Claim one of the `SYNC_FANOUT` sync slots before asking for
            // history. A dialer that cannot claim one stays connected and keeps
            // receiving broadcasts — it just does not add another concurrent
            // copy of the chain to a node that may still be replaying.
            let holds_slot = sync_slots
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                    (n < SYNC_FANOUT).then_some(n + 1)
                })
                .is_ok();
            if holds_slot
                && write_frame(&mut wsock, &get_blocks_frame(head_slot.load(Ordering::Relaxed)))
                    .is_err()
            {
                sync_slots.fetch_sub(1, Ordering::AcqRel);
                continue;
            }
            let drop_slot = |held: &mut bool| {
                if *held {
                    sync_slots.fetch_sub(1, Ordering::AcqRel);
                    *held = false;
                }
            };
            let mut held = holds_slot;
            loop {
                match rx.recv_timeout(Duration::from_secs(5)) {
                    Ok(frame) => {
                        if write_frame(&mut wsock, &frame).is_err() {
                            drop_slot(&mut held);
                            break; // reconnect
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        // The idle tick is the sync pump: while this dialer
                        // holds a slot, re-ask from wherever the engine has got
                        // to. Each answer is one page, so this walks the chain
                        // forward instead of demanding it at once, and a node
                        // that falls behind later notices on the next tick.
                        //
                        // It asks on EVERY tick, not only when the head moved.
                        // The first version released the slot the moment a tick
                        // found the head unchanged, on the theory that an
                        // unchanged head meant "caught up". Two things made
                        // that wrong, and the canary showed both:
                        //
                        //   - Nothing re-acquired the slot. `held` went false
                        //     and no path set it back inside the connection
                        //     loop, so a stable TCP connection meant the node
                        //     never asked again — it could only fall further
                        //     behind, silently, forever.
                        //   - Five seconds is shorter than the work. Applying
                        //     one block costs ~0.9s of state root at this
                        //     state size, so a 512-block page takes minutes.
                        //     The head is *supposed* to look unchanged on the
                        //     next tick. The release fired on the first tick
                        //     essentially always, which turned the sync pump
                        //     off after a single request.
                        //
                        // Asking unconditionally costs a request every five
                        // seconds from at most SYNC_FANOUT peers, and an
                        // already-caught-up node gets an empty page back. That
                        // is the cheap end of the trade; the other end was a
                        // validator attesting to a head it could no longer
                        // advance, which is what this was measured doing.
                        if held {
                            let at = head_slot.load(Ordering::Relaxed);
                            if write_frame(&mut wsock, &get_blocks_frame(at)).is_err() {
                                drop_slot(&mut held);
                                break;
                            }
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        drop_slot(&mut held);
                        return;
                    }
                }
            }
        });
    }

    Ok(DevnetMesh { peers, inbound, local_addr })
}

// ---------------------------------------------------------------------------
// Tests — the time probe over the real wire
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "bloch-net-test-{tag}-{}-{}",
            std::process::id(),
            crate::time_check::now_ms()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn read_one_frame(sock: &mut TcpStream) -> std::io::Result<Vec<u8>> {
        let mut len4 = [0u8; 4];
        sock.read_exact(&mut len4)?;
        let mut buf = vec![0u8; u32::from_le_bytes(len4) as usize];
        sock.read_exact(&mut buf)?;
        Ok(buf)
    }

    fn write_one_frame(sock: &mut TcpStream, frame: &[u8]) -> std::io::Result<()> {
        sock.write_all(&(frame.len() as u32).to_le_bytes())?;
        sock.write_all(frame)
    }

    /// The audit scenario, end to end over the real devnet wire: this node's
    /// clock is (from the peers' point of view) three days out, the peer
    /// answers the FRAME_GET_TIME probe with real time, and the recorded skew
    /// puts the boot gate in `Refuse`. The "peer" is a scripted socket, so the
    /// skew is simulated exactly where an attacker would place it — in the
    /// relation between the peer's report and the local clock — without
    /// touching the host clock.
    #[test]
    fn outbound_time_probe_catches_a_three_day_skew() {
        let three_days_ms: u64 = 3 * 86_400_000;
        // The lying/honest peer: accepts the node's dial, answers the time
        // probe with `local now + 3 days` (equivalently: an honest peer
        // answering a node whose clock is 3 days slow), ignores everything
        // else, and stays connected.
        let peer = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let peer_addr = peer.local_addr().unwrap();
        thread::spawn(move || {
            let (mut sock, _) = peer.accept().unwrap();
            let mut wsock = sock.try_clone().unwrap();
            loop {
                let Ok(frame) = read_one_frame(&mut sock) else { return };
                if frame.as_slice() == [FRAME_GET_TIME] {
                    let mut f = vec![FRAME_TIME];
                    f.extend_from_slice(
                        &(crate::time_check::now_ms() + three_days_ms).to_le_bytes(),
                    );
                    let _ = write_one_frame(&mut wsock, &f);
                }
                // FRAME_GET_BLOCKS etc.: ignored, connection kept open.
            }
        });

        let (events, _events_rx) = mpsc::channel::<EngineEvent>();
        let clock = Arc::new(crate::time_check::PeerClock::new());
        let _mesh = start(
            "127.0.0.1",
            0,
            vec![peer_addr.to_string()],
            events,
            scratch_dir("probe"),
            Arc::new(AtomicU64::new(0)),
            Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            clock.clone(),
            Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        )
        .unwrap();

        let n = clock.wait_for(1, Duration::from_secs(10));
        assert_eq!(n, 1, "the dialer must probe and record exactly this peer");
        let named = clock.skews();
        assert_eq!(named[0].0, peer_addr.to_string(), "sample keyed by the CONFIGURED address");
        let skews: Vec<i64> = named.iter().map(|(_, s)| *s).collect();
        // Mainnet geometry: margin is half an epoch = 16 × 30 s.
        let margin = crate::time_check::margin_ms(30_000);
        match crate::time_check::gate(&skews, margin) {
            crate::time_check::ClockVerdict::Refuse { median_ms, samples } => {
                assert_eq!(samples, 1);
                // Within a second of the injected three days (the slack is
                // the probe's round trip).
                assert!((median_ms - three_days_ms as i64).abs() < 1_000);
            }
            v => panic!("a three-day skew booted: {v:?}"),
        }
    }

    /// The answering side, plus the sybil property: an INBOUND stranger gets
    /// its FRAME_GET_TIME answered (so this build interoperates with peers
    /// running the check) but earns no clock vote — only peers this node
    /// dialed can move the median.
    #[test]
    fn inbound_get_time_is_answered_but_earns_no_vote() {
        let (events, _events_rx) = mpsc::channel::<EngineEvent>();
        let clock = Arc::new(crate::time_check::PeerClock::new());
        let mesh = start(
            "127.0.0.1",
            0,
            vec![], // dials nobody
            events,
            scratch_dir("inbound"),
            Arc::new(AtomicU64::new(0)),
            Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            clock.clone(),
            Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        )
        .unwrap();

        let mut sock = TcpStream::connect(mesh.local_addr()).unwrap();
        write_one_frame(&mut sock, &[FRAME_GET_TIME]).unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let before = crate::time_check::now_ms();
        let frame = read_one_frame(&mut sock).unwrap();
        let after = crate::time_check::now_ms();
        assert_eq!(frame.len(), 9);
        assert_eq!(frame[0], FRAME_TIME);
        let reported = u64::from_le_bytes(frame[1..9].try_into().unwrap());
        assert!(reported >= before && reported <= after, "the answer is the responder's clock");
        // And the stranger got no vote: a median open to inbound volunteers
        // would be a median an attacker can pack with free sybils.
        assert_eq!(clock.len(), 0, "inbound peers must not enter the clock median");
    }
}
