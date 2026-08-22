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

// ── Engine admission: one channel, a quota per class ─────────────────────────
//
// **What this replaces, and why.** Until 2026-08-22 every network event was
// counted against ONE cap of 4096 items, and shedding was silent. On Genesis-4
// mainnet the 49 Fly validators proposed on schedule, applied their own block,
// and broadcast it — and it never arrived. Measured, not inferred: `grep` for
// the block id in a classic node's log returned 0; that log held 4,140
// `REJECTED:` lines and every one was an attestation (`NotInCommittee`), not a
// block; and the TCP connections to those classics were established the whole
// time. The classics were chewing through a flood of stale attestations, and
// once that flood filled the shared cap the block arriving behind it was
// dropped with no log, no verdict, and no broken connection. Three of 64
// validators delivered a block; 77% of slots went empty.
//
// The circle closed on itself: those attestations are rejected BECAUSE
// finality is stuck, and they were eating the quota the blocks needed to
// unstick it.
//
// **Why a quota per class and not a second queue.** Two channels would need a
// `select` that `std::sync::mpsc` does not have — so either polling both ends,
// in a node whose known failure mode is spinning at 100% CPU, or a new
// dependency inside a live consensus binary. And, decisively, two queues break
// FIFO *between* classes: an attestation queued before a block would start
// being handled after it, changing which attestations are in the pool when
// LMD-GHOST runs, and so which head is chosen. That is consensus, not
// transport. Splitting the ADMISSION test instead leaves ordering exactly as it
// was — one channel, in order — while a block's admission test no longer reads
// a counter the attestation flood moves.
//
// Eviction (drop a queued attestation to make room) was the other candidate:
// `std::mpsc` cannot remove a queued item, so it would mean replacing the
// channel this whole engine loop is built on, and it buys nothing a quota does
// not already give — under a quota the attestation never takes the block's
// place, so there is nothing to evict.
//
// **The cost is not symmetric**, and that is what the quotas encode: a shed
// attestation is one vote, which its author re-gossips; a shed block is a slot
// of the entire network, unrecoverable.

/// Blocks the engine may have queued but not yet handled.
///
/// Not a round number: it is exactly what this node's own sync design can have
/// legitimately in flight — `SYNC_FANOUT` peers each answering with one
/// `SYNC_PAGE_BLOCKS` page. Written as the product so that changing either
/// constant carries the quota with it instead of letting it drift.
const BLOCK_ITEMS: usize = SYNC_FANOUT * SYNC_PAGE_BLOCKS;

/// Bytes of block frames queued but not yet handled.
///
/// **Item counts are not a memory bound.** `read_frame` accepts any frame up to
/// `codec::MAX_FIELD_LEN` (8 MiB), and `decode_attestation` reads its signature
/// with `Reader::bytes` under that same cap and no tighter one — so the old
/// 4096-item cap had a worst case of 32 GiB, on the 8 GB machines where
/// twenty-two validators were OOM-killed on 2026-08-21. What actually saved
/// those machines was `SYNC_FANOUT` and `SYNC_PAGE_BLOCKS`, not the cap.
/// Counting bytes is what turns "4096 things" into a number of megabytes.
const BLOCK_BYTES: usize = 256 * 1024 * 1024;

/// Attestations queued but not yet handled.
///
/// A full Genesis-4 committee round is 64 attestations, so this is ~32 rounds
/// of backlog — enough that an engine busy applying one block does not lose the
/// votes for it, far short of letting a flood accumulate. At ~4.8 KB for a
/// hybrid ML-DSA-65‖Falcon-1024 signature that is ~9.8 MB in the ordinary case,
/// so under honest load the ITEM quota is what bites and the byte quota below
/// only bites on frames built to be large. That ordering is deliberate: the
/// common case is limited by count, the adversarial case by memory.
const ATT_ITEMS: usize = 2048;
const ATT_BYTES: usize = 32 * 1024 * 1024;

/// Transactions queued but not yet handled. A shed transaction is the mildest
/// loss of the three — the sender resubmits, and nothing in consensus waits on
/// it — so it gets the smallest share and the quietest log.
const TX_ITEMS: usize = 1024;
const TX_BYTES: usize = 32 * 1024 * 1024;

// The three item quotas sum to 4096 — exactly the single `ENGINE_QUEUE_CAP`
// they replace — and the three byte quotas to 320 MiB against that cap's 32 GiB
// worst case. Nothing here is a loosening: the queue admits no more items than
// before, and two orders of magnitude fewer bytes, so the 2026-08-21 failure
// mode is not reopened by the sum. `queue_tests::total_never_exceeds_the_caps`
// pins both numbers as literals, on purpose — a test that recomputes the sum
// from the constants would pass even if a constant grew to a million.

/// Which quota a queued network event draws on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    Block = 0,
    Attestation = 1,
    Transaction = 2,
}

impl Class {
    fn of(ev: &NetEvent) -> Class {
        match ev {
            NetEvent::Block(_) => Class::Block,
            NetEvent::Attestation(..) => Class::Attestation,
            NetEvent::Transaction(_) => Class::Transaction,
        }
    }

    fn caps(self) -> (usize, usize) {
        match self {
            Class::Block => (BLOCK_ITEMS, BLOCK_BYTES),
            Class::Attestation => (ATT_ITEMS, ATT_BYTES),
            Class::Transaction => (TX_ITEMS, TX_BYTES),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Class::Block => "block",
            Class::Attestation => "attestation",
            Class::Transaction => "transaction",
        }
    }

    /// How long this class stays quiet after printing a shed line.
    ///
    /// Asymmetric for the same reason the quotas are. A shed block is a lost
    /// slot and the line nobody had for weeks, so the first one prints on the
    /// spot and then at most one every ten seconds. Shedding attestations under
    /// a flood is the DESIGNED behaviour, and a line per event would simply be
    /// the flood again, in the log this time.
    fn log_gap_ms(self) -> u64 {
        match self {
            Class::Block => 10_000,
            Class::Attestation | Class::Transaction => 60_000,
        }
    }
}

/// `fetch_add` that refuses rather than exceeding `cap`.
///
/// `fetch_update` and not load-then-add: two threads at the boundary must not
/// both read "there is room" and both take it, or the ceiling the OOM
/// regression rests on is only true on average.
fn take_up_to(a: &AtomicUsize, add: usize, cap: usize) -> bool {
    a.fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
        (n.saturating_add(add) <= cap).then_some(n + add)
    })
    .is_ok()
}

/// One class's occupancy, plus what it has thrown away.
#[derive(Default)]
struct ClassMeter {
    items: AtomicUsize,
    bytes: AtomicUsize,
    /// Monotonic for the life of the process and never reset. A counter you can
    /// only read as a rate is a counter that hides the burst you are hunting.
    shed: AtomicU64,
    shed_at_last_log: AtomicU64,
    last_log_ms: AtomicU64,
}

/// What one shed event may say, on the occasions the rate limiter lets it.
struct ShedReport {
    total: u64,
    since_last: u64,
}

impl ClassMeter {
    /// Take one item and `bytes` bytes, or take nothing at all.
    ///
    /// The two dimensions are reserved in order and the first is handed back if
    /// the second does not fit, so neither counter is ever *observed* above its
    /// cap — not even transiently.
    fn take(&self, bytes: usize, cap_items: usize, cap_bytes: usize) -> bool {
        if take_up_to(&self.items, 1, cap_items) {
            if take_up_to(&self.bytes, bytes, cap_bytes) {
                return true;
            }
            self.items.fetch_sub(1, Ordering::AcqRel);
        }
        false
    }

    fn give_back(&self, bytes: usize) {
        self.items.fetch_sub(1, Ordering::AcqRel);
        self.bytes.fetch_sub(bytes, Ordering::AcqRel);
    }

    /// Count one shed event; return a report only if this one may be printed.
    ///
    /// The caller formats nothing unless this returns `Some`, so a flood costs
    /// one `fetch_add` and one load per event and never an allocation. The
    /// `compare_exchange` picks a single winner per window: losers return
    /// immediately rather than blocking or retrying.
    fn note_shed(&self, gap_ms: u64) -> Option<ShedReport> {
        let total = self.shed.fetch_add(1, Ordering::AcqRel) + 1;
        let now = now_ms();
        let last = self.last_log_ms.load(Ordering::Acquire);
        // `last` is 0 before the first line, and `now` is a Unix millisecond,
        // so the very first shed of a class always clears the gap and speaks.
        if now.saturating_sub(last) < gap_ms {
            return None;
        }
        if self
            .last_log_ms
            .compare_exchange(last, now, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return None;
        }
        let prev = self.shed_at_last_log.swap(total, Ordering::AcqRel);
        Some(ShedReport { total, since_last: total.saturating_sub(prev) })
    }
}

/// What one class has queued and lost, for `getchaininfo`.
#[derive(Default, Clone, Copy)]
pub struct ClassStats {
    pub items: usize,
    pub bytes: usize,
    pub shed: u64,
}

/// The whole queue's occupancy, as a value the RPC can render.
///
/// Exposed because a counter nobody can read from outside the process is a
/// counter nobody checks — and not being able to see this one from outside is
/// half of why the bug above survived weeks.
#[derive(Default, Clone, Copy)]
pub struct QueueStats {
    pub block: ClassStats,
    pub attestation: ClassStats,
    pub transaction: ClassStats,
}

/// The engine's inbound quota: one channel, one meter per class.
#[derive(Default)]
pub struct EngineQueue {
    classes: [ClassMeter; 3],
}

impl EngineQueue {
    pub fn new() -> EngineQueue {
        EngineQueue::default()
    }

    /// Reserve room for one event of `class`, or return `None`.
    ///
    /// The [`Permit`] IS the reservation: it rides on the queued event and
    /// gives the quota back when it drops, so no path can admit without
    /// releasing. The code this replaces decremented by hand in the engine
    /// loop — and the libp2p forwarder never incremented at all, so on that
    /// transport the first event subtracted from zero, wrapped the counter to
    /// ~2^64, and left the cap permanently saturated. It was harmless only
    /// because the two transports never run in one process. RAII deletes that
    /// entire class of bug rather than fixing this instance of it.
    pub fn admit(q: &Arc<EngineQueue>, class: Class, bytes: usize) -> Option<Permit> {
        let (cap_items, cap_bytes) = class.caps();
        q.classes[class as usize]
            .take(bytes, cap_items, cap_bytes)
            .then(|| Permit { queue: q.clone(), class, bytes })
    }

    /// [`admit`](EngineQueue::admit) for a decoded event: classifies it, and on
    /// refusal leaves a trace.
    ///
    /// Silence is what hid the original bug, so nothing is dropped without at
    /// least moving a counter; the rate limiter decides whether it also speaks.
    pub fn admit_event(q: &Arc<EngineQueue>, ev: &NetEvent, bytes: usize) -> Option<Permit> {
        let class = Class::of(ev);
        if let Some(p) = EngineQueue::admit(q, class, bytes) {
            return Some(p);
        }
        if let Some(r) = q.classes[class as usize].note_shed(class.log_gap_ms()) {
            match ev {
                // The line whose absence cost this investigation weeks. It
                // names the block, because "a block was shed" and "block
                // 57282c3f for slot 25750 was shed" are different amounts of
                // help at 3am.
                NetEvent::Block(env) => eprintln!(
                    "net: SHED block {} slot {} — block queue full ({} items / {} MiB); \
                     {} shed since the last line, {} since boot. A shed block is a LOST SLOT.",
                    crate::codec::hex8(env.header.id().as_bytes()),
                    env.header.slot,
                    BLOCK_ITEMS,
                    BLOCK_BYTES / (1024 * 1024),
                    r.since_last,
                    r.total,
                ),
                _ => eprintln!(
                    "net: shed {} {} since the last line, {} since boot — {} queue full",
                    r.since_last,
                    class.name(),
                    r.total,
                    class.name(),
                ),
            }
        }
        None
    }

    pub fn stats(&self) -> QueueStats {
        let one = |c: Class| {
            let m = &self.classes[c as usize];
            ClassStats {
                items: m.items.load(Ordering::Acquire),
                bytes: m.bytes.load(Ordering::Acquire),
                shed: m.shed.load(Ordering::Acquire),
            }
        };
        QueueStats {
            block: one(Class::Block),
            attestation: one(Class::Attestation),
            transaction: one(Class::Transaction),
        }
    }
}

/// One event's reservation in the engine queue, released when it drops.
///
/// Carried on `EngineEvent::Net` all the way into the engine's match arm, so
/// the quota is held until the work is DONE rather than until the event is
/// dequeued. The comment on the old hand-written decrement claimed exactly
/// that; the code subtracted before the `match` and did the opposite.
pub struct Permit {
    queue: Arc<EngineQueue>,
    class: Class,
    bytes: usize,
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.queue.classes[self.class as usize].give_back(self.bytes);
    }
}

/// Milliseconds since the Unix epoch — for the shed rate limiter only, which
/// needs a shared clock across threads, not a monotonic one.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Depth of an inbound peer's broadcast queue before frames are dropped.
///
/// Bounded, unlike the outbound queues, because inbound connections are not
/// something this node chose: a box with 104 of them (measured on Genesis-4
/// mainnet, 2026-08-21) would let unbounded queues turn one stalled peer into
/// this node's memory problem.
///
/// This is the OUTBOUND side of a peer's socket, so what is lost here is a copy
/// of something this node already has. That is a different trade from shedding
/// on the way IN (see [`EngineQueue`]), and it is the reason this one is a
/// single depth and not a quota per class.
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

/// Hand one network event to the engine, or shed it if that class's quota is
/// full.
///
/// The engine consumes on a single thread, and during replay it does not
/// consume at all — hours, at Genesis-4's state size. An unbounded queue in
/// front of a sleeping consumer is a slower way to run out of memory, which is
/// exactly how twenty-two validators died on 2026-08-21. So there is still a
/// hard ceiling; what changed is WHO loses when it is reached.
///
/// **The justification this comment used to carry was false.** It read: "a
/// dropped block is asked for again by the sync pump". It is not. A node that
/// finishes replay has been observed pinned at 100% CPU asking for nothing at
/// all, so a shed block is not a block delayed by one round trip — it is a slot
/// of the whole network spent on nothing, and there were weeks of them. A shed
/// attestation genuinely is re-gossiped by its author. That asymmetry is the
/// entire reason the two no longer draw on the same quota.
///
/// `frame_len` is the bytes this event cost on the wire; the caller already has
/// the frame, so nothing is re-encoded to find out.
///
/// Returns false when the engine is gone, so callers can stop their thread.
fn send_to_engine(
    events: &Sender<EngineEvent>,
    queue: &Arc<EngineQueue>,
    ev: NetEvent,
    frame_len: usize,
) -> bool {
    let Some(permit) = EngineQueue::admit_event(queue, &ev, frame_len) else {
        // Shed: counted, and logged if the rate limiter allows. The connection
        // stays healthy — this peer did nothing wrong.
        return true;
    };
    // On a send failure the permit drops here and returns the quota by itself.
    events.send(EngineEvent::Net(ev, permit)).is_ok()
}

impl NetEvent {
    /// What this event costs the queue, in bytes.
    ///
    /// Only the libp2p path needs this: there the frame is consumed before the
    /// event exists, while the devnet mesh passes the frame length it already
    /// read. Exact for attestations and transactions. The block re-encodes,
    /// which is one memcpy beside the milliseconds of hybrid PQ verification
    /// that block is about to cost, and blocks are the rare class.
    pub fn wire_bytes(&self) -> usize {
        match self {
            NetEvent::Block(env) => 1 + crate::codec::encode_envelope(env).len(),
            NetEvent::Attestation(att, _) => 1 + ATT_WIRE_FIXED + att.signature.len(),
            NetEvent::Transaction(tx) => 1 + tx.canonical_bytes().len(),
        }
    }
}

/// Attestation wire bytes before the signature: slot 8, head 32, source epoch 8
/// and root 32, target epoch 8 and root 32, validator 4, signature length 4.
///
/// A number written by hand here is a number that can drift away from the
/// codec, so `queue_tests::wire_bytes_matches_the_real_frame` pins it against
/// what [`att_frame`] actually produces.
const ATT_WIRE_FIXED: usize = 128;

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
    queue: Arc<EngineQueue>,
) -> std::io::Result<DevnetMesh> {
    // Inbound: accept, then per-connection: read frames; data frames go to
    // the engine, get-blocks is answered in place from the log.
    let listener = TcpListener::bind((bind_addr, listen_port))?;
    let inbound: Arc<Mutex<Vec<SyncSender<Vec<u8>>>>> = Arc::new(Mutex::new(Vec::new()));
    {
        let events = events.clone();
        let data_dir = data_dir.clone();
        let inbound = inbound.clone();
        let queue = queue.clone();
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
                let queue = queue.clone();
                let mut rsock = rsock;
                thread::spawn(move || loop {
                    match read_frame(&mut rsock) {
                        Ok(frame) => {
                            if frame.first() == Some(&FRAME_GET_BLOCKS) {
                                serve_get_blocks(&wsock, &data_dir, &frame);
                            } else if let Some(ev) = decode_event(&frame) {
                                if !send_to_engine(&events, &queue, ev, frame.len()) {
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
        let queue = queue.clone();
        thread::spawn(move || loop {
            let Ok(sock) = TcpStream::connect(&addr) else {
                thread::sleep(Duration::from_millis(300));
                continue;
            };
            let mut wsock = sock;
            // Reader half: the peer answers our get-blocks on this socket.
            if let Ok(mut rsock) = wsock.try_clone() {
                let events = events.clone();
                let queue = queue.clone();
                thread::spawn(move || loop {
                    match read_frame(&mut rsock) {
                        Ok(frame) => {
                            if let Some(ev) = decode_event(&frame) {
                                if !send_to_engine(&events, &queue, ev, frame.len()) {
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
mod queue_tests {
    //! The admission quota, tested without a socket or an engine.
    //!
    //! Every negative here is paired with its control. "A block gets through"
    //! means nothing unless "a block is refused" is also shown, or the test
    //! passes just as well against a queue with no ceiling at all — which is
    //! the failure mode that killed twenty-two validators on 2026-08-21 and the
    //! one this must not reintroduce under a new name.

    use super::*;
    use bloch_pos_committee::attestation::{Attestation, AttestationData};
    use bloch_pos_committee::header::{BlockEnvelope, BlockHeaderV4, Body};

    fn block(slot: u64) -> NetEvent {
        NetEvent::Block(envelope(slot))
    }

    fn envelope(slot: u64) -> BlockEnvelope {
        BlockEnvelope {
            header: BlockHeaderV4 {
                version: 4,
                parent: [0u8; 32],
                state_root: [0u8; 32],
                body_root: [0u8; 32],
                slot,
                proposer_index: 17,
                randao_reveal: [0u8; 32],
                randao_mix: [0u8; 32],
                justified_root: [0u8; 32],
                finalized_root: [0u8; 32],
                attestation_root: [0u8; 32],
                coherence_root: [0u8; 32],
            },
            proposer_sig: vec![7u8; 64],
            body: Body { attestations: Vec::new(), transactions: Vec::new() },
        }
    }

    fn attestation(slot: u64, sig_len: usize) -> NetEvent {
        NetEvent::Attestation(
            Attestation {
                data: AttestationData {
                    slot,
                    head: [0u8; 32],
                    source_epoch: 0,
                    source_root: [0u8; 32],
                    target_epoch: 0,
                    target_root: [0u8; 32],
                },
                validator: 3,
                signature: vec![9u8; sig_len],
            },
            Origin::none(),
        )
    }

    /// Fill a class to its item cap, keeping every permit alive.
    fn saturate(q: &Arc<EngineQueue>, class: Class, bytes: usize) -> Vec<Permit> {
        let (cap_items, _) = class.caps();
        let held: Vec<Permit> = (0..cap_items)
            .filter_map(|_| EngineQueue::admit(q, class, bytes))
            .collect();
        assert_eq!(held.len(), cap_items, "the class should fill to exactly its item cap");
        assert!(
            EngineQueue::admit(q, class, bytes).is_none(),
            "a saturated class must refuse the next item"
        );
        held
    }

    /// **The bug, as a test.** With the attestation class saturated — which is
    /// precisely the mainnet state: 4,140 `NotInCommittee` rejections in one
    /// classic node's log while the 49 Fly validators proposed into silence —
    /// an arriving block must still reach the engine.
    ///
    /// Under the single shared cap this replaces, it did not: the block was
    /// dropped with no log, no verdict and a healthy TCP connection, which is
    /// why `grep` for the block id in the receiver's log returned 0.
    #[test]
    fn a_block_still_arrives_while_attestations_are_saturated() {
        let q = Arc::new(EngineQueue::new());
        let (tx, rx) = mpsc::channel::<EngineEvent>();

        let _flood = saturate(&q, Class::Attestation, 4_800);
        // Prove the flood really is being turned away, so this is not a test
        // that quietly saturated nothing: one more attestation is shed.
        assert!(send_to_engine(&tx, &q, attestation(25_750, 4_800), 4_929));
        assert!(rx.try_recv().is_err(), "the attestation class is full, so it must not queue");
        // One: `saturate` reserves through the raw `admit`, which is the
        // bookkeeping primitive and counts nothing. Only `admit_event`, the
        // path a real frame takes, records a shed.
        assert_eq!(q.stats().attestation.shed, 1, "the flood is being turned away, and counted");

        assert!(
            send_to_engine(&tx, &q, block(25_750), 700),
            "a live engine channel means send_to_engine reports success"
        );
        match rx.try_recv() {
            Ok(EngineEvent::Net(NetEvent::Block(env), _permit)) => {
                assert_eq!(env.header.slot, 25_750, "and it is the block we sent");
            }
            other => panic!(
                "the block must reach the engine with attestations saturated; got {}",
                match other {
                    Ok(_) => "some other event",
                    Err(_) => "nothing at all — this IS the mainnet bug",
                }
            ),
        }
    }

    /// The CONTROL half. Saturate BLOCKS instead, and the protection must still
    /// hold: the next block is refused, does not reach the engine, and is
    /// counted. Without this, the fix above could be "no ceiling at all",
    /// which passes the positive test and reopens the OOM.
    #[test]
    fn a_block_is_shed_and_counted_when_blocks_themselves_are_saturated() {
        let q = Arc::new(EngineQueue::new());
        let (tx, rx) = mpsc::channel::<EngineEvent>();

        let _full = saturate(&q, Class::Block, 700);
        let before = q.stats().block.shed;

        assert!(
            send_to_engine(&tx, &q, block(99), 700),
            "shedding keeps the connection healthy: it must not report failure"
        );
        assert!(
            rx.try_recv().is_err(),
            "a block over the block quota must NOT reach the engine — the ceiling is the point"
        );
        assert_eq!(
            q.stats().block.shed,
            before + 1,
            "and it must leave a trace: silence is what hid this for weeks"
        );
    }

    /// The symmetric control: attestations are shed and counted too. The fix
    /// gives blocks their own room, not an exemption for everyone.
    #[test]
    fn an_attestation_is_shed_and_counted_when_attestations_are_saturated() {
        let q = Arc::new(EngineQueue::new());
        let (tx, rx) = mpsc::channel::<EngineEvent>();

        let _full = saturate(&q, Class::Attestation, 4_800);
        let before = q.stats().attestation.shed;

        assert!(send_to_engine(&tx, &q, attestation(1, 4_800), 4_929));
        assert!(rx.try_recv().is_err(), "an attestation over its quota must not be queued");
        assert_eq!(q.stats().attestation.shed, before + 1);
    }

    /// Bytes are a real dimension, not decoration: a class can refuse while its
    /// item count is still far below the cap.
    ///
    /// This is the case item counting alone cannot see. `read_frame` accepts
    /// frames up to `codec::MAX_FIELD_LEN` (8 MiB), so 1024 admitted blocks are
    /// 8 GiB of worst case — on the 8 GB machines where twenty-two validators
    /// were OOM-killed.
    #[test]
    fn a_class_refuses_on_bytes_long_before_its_item_cap() {
        let q = Arc::new(EngineQueue::new());
        let huge = 8 * 1024 * 1024; // one maximal frame
        let mut held = Vec::new();
        while let Some(p) = EngineQueue::admit(&q, Class::Block, huge) {
            held.push(p);
        }
        assert_eq!(held.len(), BLOCK_BYTES / huge, "it must stop exactly at the byte cap");
        assert!(
            held.len() < BLOCK_ITEMS,
            "and it must stop while the item counter still has room, or bytes changed nothing"
        );
        assert!(q.stats().block.bytes <= BLOCK_BYTES);
    }

    /// The pair to the one above: small blocks are NOT penalised. Ordinary
    /// traffic fills to the item cap, so the byte dimension only bites frames
    /// built to be large.
    #[test]
    fn small_blocks_fill_all_the_way_to_the_item_cap() {
        let q = Arc::new(EngineQueue::new());
        let mut held = Vec::new();
        while let Some(p) = EngineQueue::admit(&q, Class::Block, 4_000) {
            held.push(p);
        }
        assert_eq!(held.len(), BLOCK_ITEMS, "1024 x 4 KB is 4 MB — nowhere near the byte cap");
    }

    /// A refusal must cost nothing.
    ///
    /// `take` reserves the two dimensions in order, so a refusal on BYTES
    /// happens with an item already speculatively taken. Leaking that item is
    /// invisible in the ordinary case and terminal in the one that matters: a
    /// class refused on bytes over and over ratchets its item counter up to the
    /// cap and then refuses everything forever, while `getchaininfo` shows the
    /// byte counter empty and every permit released — a wedge that looks like
    /// nothing at all, which is the exact shape of the bug this commit exists
    /// to kill.
    #[test]
    fn a_refusal_on_bytes_leaves_no_item_behind() {
        let q = Arc::new(EngineQueue::new());
        let over = BLOCK_BYTES + 1; // never fits, whatever the item count says
        for _ in 0..64 {
            assert!(EngineQueue::admit(&q, Class::Block, over).is_none());
        }
        let s = q.stats();
        assert_eq!(s.block.items, 0, "a refused admission must not keep an item");
        assert_eq!(s.block.bytes, 0, "nor any bytes");

        // The property the leak destroys: the class is still whole afterwards.
        let held = saturate(&q, Class::Block, 4_000);
        assert_eq!(held.len(), BLOCK_ITEMS, "64 refusals must not have eaten 64 slots");
    }

    /// The shed log is deliberately ASYMMETRIC, and the asymmetry IS the
    /// requirement.
    ///
    /// A shed block is a lost slot of the whole network and has to be visible
    /// immediately; a line per shed attestation under a flood is just the flood
    /// again, in the log this time. So every class speaks on its FIRST loss and
    /// then goes quiet for its own window — and the block's window is strictly
    /// the shorter of the two. Flattening the two gaps to one number passes
    /// every other test in this module.
    #[test]
    fn the_shed_log_speaks_once_then_rate_limits_per_class() {
        for class in [Class::Block, Class::Attestation, Class::Transaction] {
            let m = ClassMeter::default();
            let gap = class.log_gap_ms();
            assert!(m.note_shed(gap).is_some(), "the first loss of a class always speaks");
            for _ in 0..10_000 {
                assert!(m.note_shed(gap).is_none(), "then it stays quiet inside its window");
            }
            // Quiet is not the same as uncounted: silence was the bug.
            assert_eq!(m.shed.load(Ordering::Acquire), 10_001);
        }
        assert!(
            Class::Block.log_gap_ms() < Class::Attestation.log_gap_ms()
                && Class::Block.log_gap_ms() < Class::Transaction.log_gap_ms(),
            "a lost slot must be reported sooner than a shed vote, or this is not the \
             asymmetric policy the asymmetric cost demands"
        );
    }

    /// **The 2026-08-21 regression.** Every class hammered at once by many
    /// threads, with a consumer that never consumes — the replaying engine.
    /// Total occupancy must stay under a hard ceiling in BOTH dimensions.
    ///
    /// The bounds are written as literals on purpose. A test asserting
    /// `BLOCK_ITEMS + ATT_ITEMS + TX_ITEMS` would pass unchanged if a constant
    /// were raised to a million, which is exactly the mutation that must fail.
    /// 4096 items is the single cap this replaces; 320 MiB is the new one,
    /// against that cap's 32 GiB worst case.
    #[test]
    fn total_never_exceeds_the_caps() {
        let q = Arc::new(EngineQueue::new());
        let stop = Arc::new(AtomicU64::new(0));
        let worst = Arc::new(AtomicUsize::new(0));
        let worst_bytes = Arc::new(AtomicUsize::new(0));

        let mut hands = Vec::new();
        for t in 0..6u64 {
            let (q, stop, worst, worst_bytes) =
                (q.clone(), stop.clone(), worst.clone(), worst_bytes.clone());
            hands.push(thread::spawn(move || {
                let class = [Class::Block, Class::Attestation, Class::Transaction][(t % 3) as usize];
                let mut held: Vec<Permit> = Vec::new();
                while stop.load(Ordering::Relaxed) == 0 {
                    if let Some(p) = EngineQueue::admit(&q, class, 64 * 1024) {
                        held.push(p);
                    }
                    let s = q.stats();
                    let items = s.block.items + s.attestation.items + s.transaction.items;
                    let bytes = s.block.bytes + s.attestation.bytes + s.transaction.bytes;
                    worst.fetch_max(items, Ordering::AcqRel);
                    worst_bytes.fetch_max(bytes, Ordering::AcqRel);
                    // Give some back, so this is churn and not one long fill.
                    if held.len() > 8 {
                        held.truncate(4);
                    }
                }
            }));
        }
        thread::sleep(Duration::from_millis(250));
        stop.store(1, Ordering::Relaxed);
        for h in hands {
            h.join().expect("no admission thread may panic");
        }

        let peak = worst.load(Ordering::Acquire);
        assert!(peak > 0, "the threads must actually have queued something");
        assert!(peak <= 4096, "queued {peak} items; the ceiling this replaces was 4096");
        let peak_bytes = worst_bytes.load(Ordering::Acquire);
        assert!(
            peak_bytes <= 320 * 1024 * 1024,
            "queued {peak_bytes} bytes; the byte ceiling is 320 MiB"
        );
    }

    /// Dropping a permit returns exactly what it took — no more, no less.
    ///
    /// The "no more" half is not pedantry. The counter this replaces was
    /// decremented by hand in the engine loop for every `Net` event, including
    /// the libp2p ones nothing had ever incremented: the first such event
    /// subtracted from zero, wrapped to ~2^64, and left the cap permanently
    /// saturated. A doubled release reproduces that wrap, and this test sees it.
    #[test]
    fn a_dropped_permit_returns_exactly_its_quota() {
        let q = Arc::new(EngineQueue::new());
        let p = EngineQueue::admit(&q, Class::Block, 4_096).expect("an empty queue admits");
        assert_eq!(q.stats().block.items, 1);
        assert_eq!(q.stats().block.bytes, 4_096);
        drop(p);
        assert_eq!(q.stats().block.items, 0, "one in, one out");
        assert_eq!(q.stats().block.bytes, 0);
    }

    /// Fill every class, drain everything, and demand a true zero. A release
    /// that runs twice lands on `usize::MAX` rather than on 0, and an admission
    /// that forgets to release leaves the quota shrinking silently for the life
    /// of the process — the shape of the original underflow, and the reason the
    /// release is RAII and not a statement someone must remember to write.
    #[test]
    fn every_counter_returns_to_zero_after_a_drain() {
        let q = Arc::new(EngineQueue::new());
        let (tx, rx) = mpsc::channel::<EngineEvent>();
        for i in 0..64u64 {
            assert!(send_to_engine(&tx, &q, block(i), 1_000));
            assert!(send_to_engine(&tx, &q, attestation(i, 4_800), 4_929));
        }
        let s = q.stats();
        assert_eq!(s.block.items, 64, "they must really be in flight before the drain");
        assert_eq!(s.attestation.items, 64);

        let mut drained = 0;
        while let Ok(ev) = rx.try_recv() {
            drop(ev); // the permit rides on the event and releases with it
            drained += 1;
        }
        assert_eq!(drained, 128);

        let s = q.stats();
        assert_eq!(s.block.items, 0, "block items after a full drain");
        assert_eq!(s.block.bytes, 0, "block bytes after a full drain");
        assert_eq!(s.attestation.items, 0, "attestation items after a full drain");
        assert_eq!(s.attestation.bytes, 0, "attestation bytes after a full drain");
        assert_eq!(s.block.shed, 0, "nothing was over quota, so nothing may be counted shed");
    }

    /// A block must be charged to the block quota and an attestation to the
    /// attestation quota. Classifying a block as an attestation would put it
    /// straight back into the flood's path — the bug, restored.
    #[test]
    fn each_event_is_charged_to_its_own_class() {
        let q = Arc::new(EngineQueue::new());
        let (tx, _rx) = mpsc::channel::<EngineEvent>();
        assert!(send_to_engine(&tx, &q, block(1), 700));
        let s = q.stats();
        assert_eq!(s.block.items, 1, "the block must land on the block meter");
        assert_eq!(s.attestation.items, 0, "and nowhere else");

        assert!(send_to_engine(&tx, &q, attestation(1, 4_800), 4_929));
        let s = q.stats();
        assert_eq!(s.block.items, 1, "the attestation must not touch the block meter");
        assert_eq!(s.attestation.items, 1);
    }

    /// `wire_bytes` is what the libp2p path charges, and it is computed rather
    /// than measured — so it is pinned to the frame the devnet path actually
    /// puts on the wire. If it drifts low, the byte ceiling loosens silently,
    /// which is the same species of lie this commit is removing elsewhere.
    #[test]
    fn wire_bytes_matches_the_real_frame() {
        for sig_len in [64usize, 4_800, 9_999] {
            let ev = attestation(7, sig_len);
            let NetEvent::Attestation(att, _) = &ev else { unreachable!() };
            assert_eq!(
                ev.wire_bytes(),
                att_frame(att).len(),
                "attestation wire_bytes must equal the frame, sig_len {sig_len}"
            );
        }
        let ev = block(42);
        let NetEvent::Block(env) = &ev else { unreachable!() };
        assert_eq!(ev.wire_bytes(), block_frame(env).len(), "block wire_bytes must equal the frame");
    }

    /// The item quotas sum to exactly the single cap they replace, so the split
    /// admits no more than before. Literals again, for the reason above.
    #[test]
    fn the_split_admits_no_more_items_than_the_cap_it_replaces() {
        assert_eq!(BLOCK_ITEMS, 1024, "SYNC_FANOUT x SYNC_PAGE_BLOCKS");
        assert_eq!(ATT_ITEMS, 2048);
        assert_eq!(TX_ITEMS, 1024);
        assert_eq!(
            BLOCK_ITEMS + ATT_ITEMS + TX_ITEMS,
            4096,
            "the sum must not exceed the ENGINE_QUEUE_CAP this replaces"
        );
        assert_eq!((BLOCK_BYTES + ATT_BYTES + TX_BYTES) / (1024 * 1024), 320);
    }
}
