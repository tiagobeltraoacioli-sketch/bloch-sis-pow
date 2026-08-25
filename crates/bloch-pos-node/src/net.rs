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
//! Types: 0x01 block envelope, 0x02 attestation, 0x03 get-blocks{after_slot}.
//!
//! Topology per peer pair: each side dials the other (two TCP connections per
//! pair). A node broadcasts on its *outbound* connections; sync requests go
//! out on outbound connections and are answered by the peer's inbound handler
//! on the same socket.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use bloch_pos_committee::attestation::Attestation;
use bloch_pos_committee::header::{BlockEnvelope, BlockHeaderV4};

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
    /// Returns false when the frame reached NO peer at all. The transports
    /// log and count the loss themselves — see [`BroadcastDrops`] — so a
    /// caller that has nothing to add may ignore the result; a caller that
    /// can name what was lost (the proposer knows its slot) should say so.
    pub fn broadcast(&self, frame: Vec<u8>, prov: Provenance) -> bool {
        match self {
            Net::Devnet(m) => m.broadcast(frame, prov),
            Net::Libp2p(h) => h.broadcast(frame, prov),
        }
    }

    /// Counters for frames this node failed to put on the wire.
    pub fn drops(&self) -> &Arc<BroadcastDrops> {
        match self {
            Net::Devnet(m) => &m.drops,
            Net::Libp2p(h) => h.drops(),
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

// ── The engine's byte budget ────────────────────────────────────────────────
//
// **What this replaces, and why.** The queue in front of the engine used to be
// bounded at 4096 EVENTS. An event is not a unit of memory: on this transport
// a frame may be anything up to `codec::MAX_FIELD_LEN` (8 MiB), and a block
// carrying a full quorum is ~300 KB of hybrid signatures on an ordinary slot.
// 4096 events is therefore a bound of 1.2 GB in the ordinary case and 32 GiB
// in the worst one — on 8 GB machines. It did not bound anything that matters.
// That is the queue 60 peers dumped 145 MB pages into on 2026-08-21, and
// twenty-two validators were OOM-killed at 7.9 GB.
//
// The budget below is in BYTES, which is the quantity the kernel kills for.
//
// **Total: 32 MiB.** Chosen against the machine that died, not against a
// throughput target: 32 MiB is 0.4% of an 8 GB box, so the queue can no longer
// be a material contributor to an OOM however many peers are shouting. It is
// also enough to keep the engine fed — the engine drains at its own speed
// (0.59 s per block during replay at Genesis-4's state size, so under two
// blocks a second), and 32 MiB is ~100 ordinary blocks of runway, far more
// than a slow consumer can use before the next page is asked for again.
//
// A shed frame is recoverable: a block is re-requested by the sync pump, an
// attestation is re-gossiped by its author. Shedding costs a round trip;
// queueing costs the process.

/// Bytes of block traffic the engine may owe at once.
///
/// **Blocks get their own budget** so that a flood of attestations cannot shed
/// them. This is the half of the incident this constant is aimed at: with one
/// shared budget, anything cheap to produce and expensive to ignore can fill
/// the queue and blocks are what gets dropped.
///
/// KNOWN LIMITATION, stated plainly: separate budgets stop an attestation
/// flood from *shedding* blocks. They do NOT stop it from *delaying* them —
/// both classes still travel one FIFO channel to one consumer, so a block
/// queued behind 5,000 attestations still waits for those attestations to be
/// handled. Fixing that needs a second channel or a priority queue at the
/// engine, which is a larger change than this one and is not made here.
pub const BLOCK_BYTE_BUDGET: usize = 24 * 1024 * 1024;

/// Bytes of attestation and transaction traffic the engine may owe at once.
pub const GOSSIP_BYTE_BUDGET: usize = 8 * 1024 * 1024;

/// Charged to every queued event on top of its payload.
///
/// Two reasons. The decoded form of an event is bigger than its wire form (a
/// `Vec` per signature, per transaction, per attestation), so the payload
/// alone understates what the queue actually retains. And without it a stream
/// of near-empty events would be free, which would put the old unbounded-count
/// hole back under a new name: with it, the gossip budget admits at most
/// `GOSSIP_BYTE_BUDGET / 256` = 32,768 events however small they are.
const PER_EVENT_OVERHEAD_BYTES: usize = 256;

/// Which budget an event is charged against.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Class {
    Block,
    Gossip,
}

impl Class {
    fn of(ev: &NetEvent) -> Self {
        match ev {
            NetEvent::Block(_) => Class::Block,
            NetEvent::Attestation(..) | NetEvent::Transaction(_) => Class::Gossip,
        }
    }

    fn cap(self) -> usize {
        match self {
            Class::Block => BLOCK_BYTE_BUDGET,
            Class::Gossip => GOSSIP_BYTE_BUDGET,
        }
    }
}

/// Bytes of network events handed to the engine and not yet handled.
///
/// Shared by every reader thread on both transports, which is the point: the
/// budget is a property of this node's memory, not of one connection, so 60
/// peers cannot each be under the cap and the node over it.
#[derive(Default, Debug)]
pub struct EngineBudget {
    block_bytes: AtomicUsize,
    gossip_bytes: AtomicUsize,
    shed_blocks: AtomicU64,
    shed_gossip: AtomicU64,
    refund_underflows: AtomicU64,
}

impl EngineBudget {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn cell(&self, class: Class) -> &AtomicUsize {
        match class {
            Class::Block => &self.block_bytes,
            Class::Gossip => &self.gossip_bytes,
        }
    }

    /// Bytes currently owed for `class`.
    pub fn in_flight(&self, class: Class) -> usize {
        self.cell(class).load(Ordering::Acquire)
    }

    /// Events shed for want of budget, since boot.
    pub fn shed(&self, class: Class) -> u64 {
        match class {
            Class::Block => self.shed_blocks.load(Ordering::Relaxed),
            Class::Gossip => self.shed_gossip.load(Ordering::Relaxed),
        }
    }

    /// Refunds that tried to release more than was owed. Zero on a correct
    /// build, and observable rather than fatal — see [`Charge::drop`].
    pub fn refund_underflows(&self) -> u64 {
        self.refund_underflows.load(Ordering::Relaxed)
    }

    /// Reserve `bytes` against `class`, or refuse.
    ///
    /// The reservation is ONE atomic read-modify-write, not a load followed by
    /// an add. With a load-then-add, every reader thread that observed room
    /// added its own frame on top of it — 104 inbound connections could each
    /// pass the same check and overshoot the cap by 104 frames. `fetch_update`
    /// makes the check and the reservation the same operation.
    pub fn charge(self: &Arc<Self>, class: Class, bytes: usize) -> Option<Charge> {
        self.cell(class)
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                let next = n.checked_add(bytes)?;
                (next <= class.cap()).then_some(next)
            })
            .ok()?;
        Some(Charge { budget: self.clone(), class, bytes })
    }

    fn note_shed(&self, class: Class) {
        match class {
            Class::Block => self.shed_blocks.fetch_add(1, Ordering::Relaxed),
            Class::Gossip => self.shed_gossip.fetch_add(1, Ordering::Relaxed),
        };
    }
}

/// The receipt for bytes reserved in an [`EngineBudget`]; refunds them on drop.
///
/// **This type is the whole correctness argument for the budget.** The charge
/// and the refund must be the same number, and the only way to guarantee that
/// is to never compute it twice: `bytes` is measured once, at
/// [`send_to_engine`], and carried alongside the event it paid for. The engine
/// refunds by dropping this value, not by measuring anything.
///
/// It also makes the refund unconditional. Every path that loses an event —
/// the channel being closed on shutdown, the engine thread ending with a queue
/// still in it, a `SendError` handing the event back — drops the `Charge` with
/// it and returns the bytes. An `inflight` that leaks on those paths wedges the
/// queue shut permanently, and there is no path here that can leak.
pub struct Charge {
    budget: Arc<EngineBudget>,
    class: Class,
    bytes: usize,
}

impl Charge {
    /// What this event reserved. Exactly what its drop will return.
    pub fn bytes(&self) -> usize {
        self.bytes
    }
}

impl std::fmt::Debug for Charge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Charge({:?}, {} B)", self.class, self.bytes)
    }
}

impl Drop for Charge {
    fn drop(&mut self) {
        let bytes = self.bytes;
        // Saturating, and counted. Under-flowing an unsigned counter would set
        // it near `usize::MAX` and shut the queue for the lifetime of the
        // process — a wedged validator, from an accounting slip. This cannot
        // happen while every `Charge` comes from `charge()` and drops once, but
        // "cannot happen" is not a reason to make the failure unrecoverable,
        // and `debug_assert!` is not an option: this fleet builds with
        // `overflow-checks` and WITHOUT `debug-assertions`, so a debug
        // assertion is not in the binary at all.
        let prev = self
            .budget
            .cell(self.class)
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| Some(n.saturating_sub(bytes)))
            .unwrap_or(0);
        if prev < bytes {
            self.budget.refund_underflows.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// What one queued event costs the budget.
///
/// Structural, and computed WITHOUT re-encoding: the size of an event is read
/// off the lengths it already carries. It is called exactly once per event, by
/// [`send_to_engine`]; the refund never calls it. Both transports use this one
/// function, so "what a block costs" has a single definition.
pub fn event_bytes(ev: &NetEvent) -> usize {
    /// `AttestationData` (8 + 32 + 8 + 32 + 8 + 32) plus the u32 validator index.
    const ATT_FIXED_BYTES: usize = 120 + 4;
    let att = |a: &Attestation| ATT_FIXED_BYTES + a.signature.len();
    PER_EVENT_OVERHEAD_BYTES
        + match ev {
            NetEvent::Block(env) => {
                BlockHeaderV4::ENCODED_LEN
                    + env.proposer_sig.len()
                    + env.body.transactions.iter().map(|t| t.len()).sum::<usize>()
                    + env.body.attestations.iter().map(att).sum::<usize>()
            }
            NetEvent::Attestation(a, _) => att(a),
            // The only variant whose size is not already lying about in a
            // length field. Transactions are mempool-rate, not gossip-rate, so
            // one encode on the inbound path is a cost worth paying to keep a
            // single size function.
            NetEvent::Transaction(tx) => tx.canonical_bytes().len(),
        }
}

// ── Broadcast provenance and drop accounting ────────────────────────────────

/// Whether a frame being published is this node's own work or someone else's.
///
/// The distinction exists because the consequences are not the same. A relayed
/// frame that this node fails to forward is still in the network: its author
/// published it, other peers carry it, and the mesh routes around the loss. A
/// frame this node ORIGINATED — the block it just built and signed, the
/// attestation it just cast, the history it is asking for — exists nowhere
/// else. If this node fails to put it on the wire, it is gone, the slot is
/// lost, and until now that happened with `let _ = ...` and no log line at all.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Provenance {
    /// Produced by this node. Every failure is logged, individually.
    Originated,
    /// Forwarding someone else's. Failures are counted, and logged sparsely.
    Relayed,
}

/// Frames this node failed to put on the wire, by provenance.
///
/// Read through [`Net::drops`]. Counters rather than a log-only story because
/// an operator needs to be able to ask "is this node publishing?" and get a
/// number, and because a test can assert on a number.
#[derive(Default, Debug)]
pub struct BroadcastDrops {
    originated_lost: AtomicU64,
    originated_partial: AtomicU64,
    relayed_lost: AtomicU64,
    relayed_partial: AtomicU64,
}

impl BroadcastDrops {
    /// Frames of our own that reached no peer at all.
    pub fn originated_lost(&self) -> u64 {
        self.originated_lost.load(Ordering::Relaxed)
    }
    /// Frames of our own that reached some peers and not others.
    pub fn originated_partial(&self) -> u64 {
        self.originated_partial.load(Ordering::Relaxed)
    }
    /// Relayed frames that reached no peer at all.
    pub fn relayed_lost(&self) -> u64 {
        self.relayed_lost.load(Ordering::Relaxed)
    }
    /// Relayed frames that reached some peers and not others.
    pub fn relayed_partial(&self) -> u64 {
        self.relayed_partial.load(Ordering::Relaxed)
    }

    /// The frame reached nobody.
    pub(crate) fn lost(&self, prov: Provenance, frame: &[u8], reason: &str, refused: usize) {
        let tag = frame.first().copied().unwrap_or(0);
        let len = frame.len();
        match prov {
            Provenance::Originated => {
                let n = self.originated_lost.fetch_add(1, Ordering::Relaxed) + 1;
                // EVERY one of these, always. This line is the difference
                // between "we lost a proposal" and a silent empty slot.
                eprintln!(
                    "net: LOST OUR OWN FRAME type 0x{tag:02x} len {len} B: {reason} \
                     ({refused} peer(s) refused it, 0 accepted) — \
                     {n} originated frame(s) lost since boot"
                );
            }
            Provenance::Relayed => {
                let n = self.relayed_lost.fetch_add(1, Ordering::Relaxed) + 1;
                // Rate-limited by count, not by clock: the 1st, 2nd, 4th, 8th …
                // A relay drop is a normal consequence of a slow peer and a
                // line per event would be the whole log during a flood, but
                // going entirely silent is what this work package exists to
                // stop. Doubling keeps the volume constant per order of
                // magnitude and the count exact.
                if n.is_power_of_two() {
                    eprintln!(
                        "net: dropped a RELAYED frame type 0x{tag:02x} len {len} B: {reason} \
                         ({refused} peer(s) refused it, 0 accepted) — \
                         {n} relayed frame(s) lost since boot"
                    );
                }
            }
        }
    }

    /// The frame reached some peers but not all of them.
    pub(crate) fn partial(&self, prov: Provenance, frame: &[u8], accepted: usize, refused: usize) {
        let tag = frame.first().copied().unwrap_or(0);
        let len = frame.len();
        let (cell, what) = match prov {
            Provenance::Originated => (&self.originated_partial, "OUR OWN"),
            Provenance::Relayed => (&self.relayed_partial, "a relayed"),
        };
        let n = cell.fetch_add(1, Ordering::Relaxed) + 1;
        // Partial delivery is not a lost frame — the mesh may still carry it —
        // so this is rate-limited on both paths. It is logged at all because
        // "our block reached 3 of 60 peers" is the shape of the 2026-08-21
        // incident and nothing in this node could see it.
        if n.is_power_of_two() {
            eprintln!(
                "net: {what} frame type 0x{tag:02x} len {len} B reached {accepted} peer(s), \
                 {refused} refused it — {n} partial broadcast(s) since boot"
            );
        }
    }
}

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
    /// Frames this mesh could not put on any wire. See [`BroadcastDrops`].
    drops: Arc<BroadcastDrops>,
}

impl DevnetMesh {
    /// Broadcast one frame (type byte + payload, no length prefix) to every
    /// peer, dialed or dialing.
    ///
    /// Returns false when the frame reached NO peer. Every send here used to be
    /// `let _ = p.send(...)`: a node whose peers had all gone away, or which had
    /// none, published its own blocks into a closed sender and said nothing.
    /// The result is now counted and — for frames this node originated —
    /// logged, every time.
    pub fn broadcast(&self, frame: Vec<u8>, prov: Provenance) -> bool {
        let mut accepted = 0usize;
        let mut refused = 0usize;
        for p in &self.peers {
            match p.send(frame.clone()) {
                Ok(()) => accepted += 1,
                // The dialer thread for this peer has exited. It respawns on
                // reconnect, so the sender stays in the list; the frame is
                // simply gone.
                Err(_) => refused += 1,
            }
        }
        // `retain` both sends and prunes: a closed receiver is a connection
        // whose writer thread has exited, and keeping its sender would leak one
        // entry per reconnect for as long as the node runs.
        if let Ok(mut inbound) = self.inbound.lock() {
            inbound.retain(|p| match p.try_send(frame.clone()) {
                Ok(()) => {
                    accepted += 1;
                    true
                }
                // A full queue is a peer that is not reading fast enough. It
                // keeps its slot — it is alive — but this frame is lost to it,
                // and that is the loss the old code could not see.
                Err(TrySendError::Full(_)) => {
                    refused += 1;
                    true
                }
                Err(TrySendError::Disconnected(_)) => {
                    refused += 1;
                    false
                }
            });
        }
        if accepted == 0 {
            let reason = if refused == 0 {
                "no peer is connected"
            } else {
                "every peer refused it (queue full or connection gone)"
            };
            self.drops.lost(prov, &frame, reason, refused);
            return false;
        }
        if refused > 0 {
            self.drops.partial(prov, &frame, accepted, refused);
        }
        true
    }

    /// Counters for frames this mesh failed to put on the wire.
    pub fn drops(&self) -> &Arc<BroadcastDrops> {
        &self.drops
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
/// The size is measured HERE, once, and travels with the event as a [`Charge`].
/// Nothing downstream measures it again: the engine refunds by dropping the
/// charge, so the number returned is by construction the number reserved.
///
/// Returns false when the engine is gone, so callers can stop their thread.
pub(crate) fn send_to_engine(
    events: &Sender<EngineEvent>,
    budget: &Arc<EngineBudget>,
    ev: NetEvent,
) -> bool {
    let class = Class::of(&ev);
    let Some(charge) = budget.charge(class, event_bytes(&ev)) else {
        budget.note_shed(class);
        return true; // shed, but the connection stays healthy
    };
    // On `SendError` the event — and the charge inside it — is handed back and
    // dropped here, which refunds the reservation. No manual undo, and no path
    // that forgets one.
    events.send(EngineEvent::Net(ev, charge)).is_ok()
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
    budget: Arc<EngineBudget>,
) -> std::io::Result<DevnetMesh> {
    // Inbound: accept, then per-connection: read frames; data frames go to
    // the engine, get-blocks is answered in place from the log.
    let listener = TcpListener::bind((bind_addr, listen_port))?;
    let inbound: Arc<Mutex<Vec<SyncSender<Vec<u8>>>>> = Arc::new(Mutex::new(Vec::new()));
    {
        let events = events.clone();
        let data_dir = data_dir.clone();
        let inbound = inbound.clone();
        let budget = budget.clone();
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
                let budget = budget.clone();
                let mut rsock = rsock;
                thread::spawn(move || loop {
                    match read_frame(&mut rsock) {
                        Ok(frame) => {
                            if frame.first() == Some(&FRAME_GET_BLOCKS) {
                                serve_get_blocks(&wsock, &data_dir, &frame);
                            } else if let Some(ev) = decode_event(&frame) {
                                if !send_to_engine(&events, &budget, ev) {
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
        let budget = budget.clone();
        thread::spawn(move || loop {
            let Ok(sock) = TcpStream::connect(&addr) else {
                thread::sleep(Duration::from_millis(300));
                continue;
            };
            let mut wsock = sock;
            // Reader half: the peer answers our get-blocks on this socket.
            if let Ok(mut rsock) = wsock.try_clone() {
                let events = events.clone();
                let budget = budget.clone();
                thread::spawn(move || loop {
                    match read_frame(&mut rsock) {
                        Ok(frame) => {
                            if let Some(ev) = decode_event(&frame) {
                                if !send_to_engine(&events, &budget, ev) {
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

    Ok(DevnetMesh { peers, inbound, drops: Arc::new(BroadcastDrops::default()) })
}
