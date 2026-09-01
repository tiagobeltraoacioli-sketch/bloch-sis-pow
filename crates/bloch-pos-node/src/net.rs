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
//! ## Running both at once — [`Net::Both`], `--transport dual`, OFF BY DEFAULT
//!
//! The two transports used to be mutually exclusive, which made any move
//! between them a flag day: the fleet crosses together, or it becomes two
//! networks that both look healthy. [`Net::Both`] removes that, and it does so
//! WITHOUT inventing a bridge.
//!
//! **What a dual node does.** It listens on both, it is dialled on both, and
//! [`Net::broadcast`] hands the *same frame bytes* to both. Every call site in
//! the engine is unchanged; the frame is built once and copied, so a dual node
//! cannot put two encodings of one object on two wires.
//!
//! **What a dual node deliberately does NOT do: relay mesh-to-mesh.** It does
//! not take a message off one transport and push it onto the other. The engine
//! publishes exactly three classes of thing, and this is the whole list:
//!
//!   1. blocks and attestations it *authored* (`engine.rs` `propose`, `attest`),
//!   2. transactions that passed its own `admissible` check on the way into
//!      its mempool, and
//!   3. attestations released from the pending pool on
//!      `GossipDecision::Accept` — full signature and committee check.
//!
//! Every one of those is something this node has itself validated to the
//! standard its peers will apply. That is the property that makes a dual node
//! safe to attach to an authenticated mesh while it is also attached to an
//! unauthenticated one: **the devnet mesh has no authentication and no
//! admission control, but nothing arriving on it can be laundered onto
//! gossipsub under this node's identity without first being validated here.**
//! A hostile devnet peer therefore cannot spend this node's gossipsub peer
//! score, which is the poisoning path a naive bridge would open.
//!
//! It also removes the other naive-bridge failure. A relaying bridge needs a
//! seen-set or it loops: the devnet mesh has no duplicate cache at all (it
//! never needed one — it is a full mesh with no relay), so two bridges would
//! amplify one block forever. Not relaying means there is no loop to bound.
//!
//! The cost of not relaying is that a message crosses between the two
//! populations only via the *sync* path (`FRAME_GET_BLOCKS` / the libp2p
//! directed sync), which is a pull, is paged, and is rate-limited. That is
//! slower than gossip and it is the honest price. It is also why the migration
//! order is "everyone → dual → everyone → libp2p" rather than "put one bridge
//! in the middle and leave it there".
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
//! Types: 0x01 block envelope, 0x02 attestation, 0x03 get-blocks{after_slot}.
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

/// The transport the engine holds, chosen at startup.
///
/// `Devnet` and `Libp2p` are what they always were. [`Net::Both`] is the
/// dual stack described in the module header: both live in one process, no
/// mesh-to-mesh relay, off unless `--transport dual` asks for it.
pub enum Net {
    Devnet(DevnetMesh),
    Libp2p(crate::p2p::Handle),
    /// Both transports at once. **Off by default.** See the module header for
    /// why this is not a bridge and must not become one.
    Both(DevnetMesh, crate::p2p::Handle),
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
            Net::Both(m, h) => {
                // The SAME bytes on both wires. `frame` was built once by the
                // caller (`block_frame`, `att_frame`, `get_blocks_frame`, or
                // the transaction frame in `on_transaction`) and each
                // transport gets a copy of it, so there is no second encoding
                // that could disagree with the first.
                //
                // Both calls are non-blocking: the devnet mesh pushes onto per
                // peer queues and the libp2p handle onto an unbounded command
                // channel, so a stalled peer on one transport cannot hold up
                // publication on the other.
                m.broadcast(frame.clone());
                h.broadcast(frame);
            }
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
            // On `Both` this routes only the messages that actually came from
            // gossipsub. An attestation the devnet mesh delivered carries
            // `Origin::none()` — that transport does not construct an origin —
            // and [`crate::p2p::Handle::report`] is a no-op for it. So a
            // verdict on a devnet-sourced message can never be charged against
            // a libp2p peer that never sent it.
            Net::Libp2p(h) | Net::Both(_, h) => h.report(origin, verdict),
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
}

impl DevnetMesh {
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

fn write_frame(sock: &mut TcpStream, frame: &[u8]) -> std::io::Result<()> {
    let mut buf = Vec::with_capacity(4 + frame.len());
    buf.extend_from_slice(&(frame.len() as u32).to_le_bytes());
    buf.extend_from_slice(frame);
    sock.write_all(&buf)
}

fn read_frame(sock: &mut TcpStream) -> std::io::Result<Vec<u8>> {
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
pub fn start(
    bind_addr: &str,
    listen_port: u16,
    peer_addrs: Vec<String>,
    events: Sender<EngineEvent>,
    data_dir: PathBuf,
    head_slot: Arc<AtomicU64>,
    inflight: Arc<std::sync::atomic::AtomicUsize>,
) -> std::io::Result<DevnetMesh> {
    // Inbound: accept, then per-connection: read frames; data frames go to
    // the engine, get-blocks is answered in place from the log.
    let listener = TcpListener::bind((bind_addr, listen_port))?;
    let inbound: Arc<Mutex<Vec<SyncSender<Vec<u8>>>>> = Arc::new(Mutex::new(Vec::new()));
    {
        let events = events.clone();
        let data_dir = data_dir.clone();
        let inbound = inbound.clone();
        let inflight = inflight.clone();
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
                thread::spawn(move || loop {
                    match read_frame(&mut rsock) {
                        Ok(frame) => {
                            if frame.first() == Some(&FRAME_GET_BLOCKS) {
                                serve_get_blocks(&wsock, &data_dir, &frame);
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
        thread::spawn(move || loop {
            let Ok(sock) = TcpStream::connect(&addr) else {
                thread::sleep(Duration::from_millis(300));
                continue;
            };
            let mut wsock = sock;
            // Reader half: the peer answers our get-blocks on this socket.
            if let Ok(mut rsock) = wsock.try_clone() {
                let events = events.clone();
                let inflight = inflight.clone();
                thread::spawn(move || loop {
                    match read_frame(&mut rsock) {
                        Ok(frame) => {
                            if let Some(ev) = decode_event(&frame) {
                                if !send_to_engine(&events, &inflight, ev) {
                                    return;
                                }
                            }
                        }
                        Err(_) => return,
                    }
                });
            }
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

    Ok(DevnetMesh { peers, inbound })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Freeze every allocated frame byte at its registered value.
    ///
    /// `docs/WIRE-NAMESPACE-REGISTRY.md` §2 allocates these, and §7 gap 1
    /// records that **nothing froze them**: the dispatch in this file matches
    /// `&FRAME_BLOCK` as a binding-by-reference and compares `FRAME_GET_BLOCKS`
    /// at runtime, so two constants with different names and the same value
    /// produce no error, no warning, and no `unreachable_patterns`. This test
    /// and the boot-time block in `main::self_check` are the entire mechanism.
    ///
    /// Dual-stack is why it lands now: the same four bytes are dispatched by
    /// `net.rs` on the devnet wire AND routed by `p2p.rs::handle_command` onto
    /// gossip topics, and with `--transport dual` both happen inside one
    /// process against one vocabulary.
    #[test]
    fn frame_bytes_are_frozen() {
        assert_eq!(FRAME_BLOCK, 0x01, "FRAME_BLOCK moved off its allocation");
        assert_eq!(FRAME_ATT, 0x02, "FRAME_ATT moved off its allocation");
        assert_eq!(FRAME_GET_BLOCKS, 0x03, "FRAME_GET_BLOCKS moved off its allocation");
        assert_eq!(FRAME_TX, 0x04, "FRAME_TX moved off its allocation");
        let all = [
            ("FRAME_BLOCK", FRAME_BLOCK),
            ("FRAME_ATT", FRAME_ATT),
            ("FRAME_GET_BLOCKS", FRAME_GET_BLOCKS),
            ("FRAME_TX", FRAME_TX),
        ];
        for (i, (na, a)) in all.iter().enumerate() {
            for (nb, b) in all.iter().skip(i + 1) {
                assert_ne!(a, b, "frame bytes {na} and {nb} collide");
            }
        }
    }

    /// A frame is a function of its payload alone — never of the transport.
    ///
    /// This is the invariant `Net::Both` leans on: it clones one `Vec<u8>` and
    /// hands a copy to each transport, so if a builder ever grew a
    /// transport-dependent branch, a dual node would emit two different
    /// encodings of one object and the two populations would disagree about
    /// what they had seen.
    #[test]
    fn frame_builders_are_transport_independent() {
        let f = get_blocks_frame(7);
        assert_eq!(f.len(), 9);
        assert_eq!(f[0], FRAME_GET_BLOCKS);
        assert_eq!(&f[1..], &7u64.to_le_bytes());
        // Same input, same bytes, every time.
        assert_eq!(get_blocks_frame(7), f);
    }

    /// The bug `--transport dual` would have inherited, stated as arithmetic.
    ///
    /// `engine::run`'s loop decrements `inflight` once per `EngineEvent::Net`
    /// it handles, unconditionally. Before this change only the devnet path
    /// incremented; the libp2p forwarder did not. One uncounted event is
    /// therefore enough to take an `AtomicUsize` at zero to `usize::MAX` —
    /// which is not "slightly wrong", it is permanently above
    /// [`ENGINE_QUEUE_CAP`], so `send_to_engine` sheds every frame for the
    /// life of the process.
    ///
    /// On `--transport libp2p` nothing reads the counter, so the wrap was
    /// invisible. On `--transport dual` the devnet half reads it, and a node
    /// would come up connected on both transports, log nothing, and receive
    /// nothing on one of them.
    #[test]
    fn one_uncounted_event_wraps_the_counter_into_permanent_shedding() {
        use std::sync::atomic::AtomicUsize;
        let n = AtomicUsize::new(0);
        // Exactly what the engine loop does for an event nobody counted in.
        n.fetch_sub(1, Ordering::AcqRel);
        assert_eq!(n.load(Ordering::Acquire), usize::MAX);
        assert!(
            n.load(Ordering::Acquire) >= ENGINE_QUEUE_CAP,
            "a wrapped counter is above the shed threshold, i.e. shed everything, forever"
        );
    }

    /// `send_to_engine` sheds above the cap and delivers below it — the two
    /// halves of the behaviour the counter drives.
    #[test]
    fn send_to_engine_sheds_above_the_cap_and_delivers_below_it() {
        use std::sync::atomic::AtomicUsize;
        let (tx, rx) = mpsc::channel::<EngineEvent>();

        // Below the cap: delivered, and counted in.
        let inflight = Arc::new(AtomicUsize::new(0));
        assert!(send_to_engine(
            &tx,
            &inflight,
            NetEvent::Attestation(sample_attestation(), Origin::none())
        ));
        assert_eq!(inflight.load(Ordering::Acquire), 1);
        assert!(rx.try_recv().is_ok(), "an event below the cap must reach the engine");

        // At (or above) the cap: shed, silently, and the connection stays
        // healthy — `send_to_engine` returns true.
        let full = Arc::new(AtomicUsize::new(ENGINE_QUEUE_CAP));
        assert!(send_to_engine(
            &tx,
            &full,
            NetEvent::Attestation(sample_attestation(), Origin::none())
        ));
        assert_eq!(full.load(Ordering::Acquire), ENGINE_QUEUE_CAP, "shedding must not count");
        assert!(rx.try_recv().is_err(), "an event at the cap must be shed");

        // And the wrapped counter sheds too — this is the dual-stack failure.
        let wrapped = Arc::new(AtomicUsize::new(usize::MAX));
        assert!(send_to_engine(
            &tx,
            &wrapped,
            NetEvent::Attestation(sample_attestation(), Origin::none())
        ));
        assert!(rx.try_recv().is_err(), "a wrapped counter sheds every frame");
    }

    fn sample_attestation() -> Attestation {
        Attestation {
            data: bloch_pos_committee::attestation::AttestationData {
                slot: 1,
                head: [1u8; 32],
                source_epoch: 0,
                source_root: [0u8; 32],
                target_epoch: 0,
                target_root: [0u8; 32],
            },
            validator: 0,
            signature: Vec::new(),
        }
    }
}
