// SPDX-License-Identifier: AGPL-3.0-or-later

//! Devnet networking: a TCP full mesh with length-prefixed frames.
//!
//! **This is not the production network layer.** The integration plan (§4)
//! calls for the Genesis-3 libp2p/gossipsub stack copied-and-adapted with the
//! 2026-08-07 mesh fixes and a new protocol prefix; that work is not done.
//! What a devnet needs from the network is only: every node eventually sees
//! every block and attestation, and a restarted node can ask a peer for the
//! blocks it missed. A full mesh over localhost delivers exactly that with no
//! relay logic (everyone sends to everyone, so nothing needs re-gossiping)
//! and no peer scoring. The `gossip.rs` admission-control layer of the pure
//! crate (AttestationPool, GossipDecision) is likewise NOT wired here — the
//! engine does its own dedup + validity check on admission.
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

pub const FRAME_BLOCK: u8 = 0x01;
pub const FRAME_ATT: u8 = 0x02;
pub const FRAME_GET_BLOCKS: u8 = 0x03;

/// What the engine receives from the mesh.
pub enum NetEvent {
    Block(BlockEnvelope),
    Attestation(Attestation),
}

pub struct Net {
    peers: Vec<Sender<Vec<u8>>>,
}

impl Net {
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
            Some(NetEvent::Attestation(att))
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
    match crate::store::Store::blocks_after(data_dir, after) {
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

/// Start the mesh: listen on `listen_port`, dial every peer, feed decoded
/// events into `events`. `head_slot` is read when (re)dialing to ask peers
/// for everything after our head.
pub fn start(
    listen_port: u16,
    peer_addrs: Vec<String>,
    events: Sender<NetEvent>,
    data_dir: PathBuf,
    head_slot: Arc<AtomicU64>,
) -> std::io::Result<Net> {
    // Inbound: accept, then per-connection: read frames; data frames go to
    // the engine, get-blocks is answered in place from the log.
    let listener = TcpListener::bind(("127.0.0.1", listen_port))?;
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
                                if events.send(ev).is_err() {
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
                                if events.send(ev).is_err() {
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

    Ok(Net { peers })
}
