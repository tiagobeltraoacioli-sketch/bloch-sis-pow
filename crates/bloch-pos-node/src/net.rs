// SPDX-License-Identifier: AGPL-3.0-or-later

//! Transport selection, and the `Transport::Devnet` TCP mesh.
//!
//! Two transports live behind [`Net`]:
//!
//! - [`p2p`](crate::p2p) — the libp2p layer: gossipsub with the 2026-08-07
//!   mesh fixes, a Genesis-4-only protocol prefix, directed paginated sync,
//!   and `gossip.rs` wired as admission control.
//! - the full mesh below — **this is what the live Genesis-4 fleet runs.**
//!   The 64-validator cohort across five hosts finalized on it and still
//!   does. Selected with `--transport devnet`, which is still the default;
//!   `--transport libp2p` opts into the libp2p stack.
//!
//! The name is historical and the transport is exactly what the name says:
//! **a point-to-point TCP full mesh over a fixed peer list, with no discovery
//! and no authentication.** That is the reason a third party cannot yet join
//! the network — not a policy, a missing mechanism. Do not read
//! `--transport devnet` as "the chain is a devnet": Genesis-4 is a live
//! mainnet, and this is the transport it runs on.
//!
//! The engine talks to both through the same two calls — [`Net::broadcast`]
//! with a typed frame, and [`Net::report`] with a verdict — so nothing in the
//! consensus loop knows which transport it is running on.
//!
//! ## The mesh, and what it is not
//!
//! **This is not a public network layer, and it is running on mainnet.** What
//! a fixed, single-operator fleet needs from the network is only: every node
//! eventually sees every block and attestation, and a restarted node can ask a
//! peer for the blocks it missed. A full mesh over a known peer list delivers
//! exactly that with no relay logic (everyone sends to everyone, so nothing
//! needs re-gossiping) and no peer scoring. It has no discovery, no
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
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
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

/// The devnet TCP full mesh: one queue per peer.
pub struct DevnetMesh {
    peers: Vec<Sender<Vec<u8>>>,
}

impl DevnetMesh {
    /// Broadcast one frame (type byte + payload, no length prefix) to every
    /// peer. Slow/dead peers just accumulate a queue until reconnect.
    pub fn broadcast(&self, frame: Vec<u8>) {
        for p in &self.peers {
            let _ = p.send(frame.clone());
        }
    }
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
fn serve_get_blocks(sock: &mut TcpStream, data_dir: &PathBuf, frame: &[u8]) {
    if frame.len() != 9 {
        return;
    }
    let after = u64::from_le_bytes(frame[1..9].try_into().unwrap());
    // Uncapped on this transport, deliberately: this mesh has no pagination,
    // so a restarting node's single request must be answered in full or it
    // never catches up. That is one of the reasons this transport must not be
    // exposed to a public network — the libp2p path pages
    // (`p2p::MAX_SYNC_BLOCKS`) so no single answer can become a history dump.
    // The live fleet runs THIS transport, behind a firewall and a fixed peer
    // list; that containment is what makes an uncapped answer acceptable.
    match crate::store::Store::blocks_after(data_dir, after, usize::MAX) {
        Ok(blocks) => {
            for b in blocks {
                let mut f = Vec::with_capacity(1 + b.len());
                f.push(FRAME_BLOCK);
                f.extend_from_slice(&b);
                if write_frame(sock, &f).is_err() {
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
/// responsible for restricting the port to known peers at the firewall — which
/// is exactly how the live fleet runs it. The answer for a network anyone can
/// join is the libp2p stack, not this; until that is the default, the peer set
/// is fixed and no third party can join.
pub fn start(
    bind_addr: &str,
    listen_port: u16,
    peer_addrs: Vec<String>,
    events: Sender<EngineEvent>,
    data_dir: PathBuf,
    head_slot: Arc<AtomicU64>,
) -> std::io::Result<DevnetMesh> {
    // Inbound: accept, then per-connection: read frames; data frames go to
    // the engine, get-blocks is answered in place from the log.
    let listener = TcpListener::bind((bind_addr, listen_port))?;
    {
        let events = events.clone();
        let data_dir = data_dir.clone();
        thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(mut sock) = conn else { continue };
                let events = events.clone();
                let data_dir = data_dir.clone();
                thread::spawn(move || loop {
                    match read_frame(&mut sock) {
                        Ok(frame) => {
                            if frame.first() == Some(&FRAME_GET_BLOCKS) {
                                serve_get_blocks(&mut sock, &data_dir, &frame);
                            } else if let Some(ev) = decode_event(&frame) {
                                if events.send(EngineEvent::Net(ev)).is_err() {
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
    let mut peers = Vec::new();
    for addr in peer_addrs {
        let (tx, rx): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = mpsc::channel();
        peers.push(tx);
        let events = events.clone();
        let head_slot = head_slot.clone();
        thread::spawn(move || loop {
            let Ok(sock) = TcpStream::connect(&addr) else {
                thread::sleep(Duration::from_millis(300));
                continue;
            };
            let mut wsock = sock;
            // Reader half: the peer answers our get-blocks on this socket.
            if let Ok(mut rsock) = wsock.try_clone() {
                let events = events.clone();
                thread::spawn(move || loop {
                    match read_frame(&mut rsock) {
                        Ok(frame) => {
                            if let Some(ev) = decode_event(&frame) {
                                if events.send(EngineEvent::Net(ev)).is_err() {
                                    return;
                                }
                            }
                        }
                        Err(_) => return,
                    }
                });
            }
            // Ask for everything we missed, then drain the broadcast queue.
            if write_frame(&mut wsock, &get_blocks_frame(head_slot.load(Ordering::Relaxed)))
                .is_err()
            {
                continue;
            }
            loop {
                match rx.recv_timeout(Duration::from_secs(5)) {
                    Ok(frame) => {
                        if write_frame(&mut wsock, &frame).is_err() {
                            break; // reconnect
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        // Keepalive-by-doing-nothing; TCP notices dead peers
                        // on the next write.
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => return,
                }
            }
        });
    }

    Ok(DevnetMesh { peers })
}
