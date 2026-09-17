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
//! Types: 0x01 block envelope, 0x02 attestation, 0x03 get-blocks{after_slot},
//! 0x04 transaction ([`FRAME_TX`], payload = one transaction's canonical
//! bytes). All four are live: 0x04 is written by [`send_transaction`], decoded
//! by `decode_event`, and republished on the production transport by `p2p`.
//!
//! Topology per peer pair: each side dials the other (two TCP connections per
//! pair). A node broadcasts in **both** directions — [`DevnetMesh::broadcast`]
//! sends to every peer it dialed and to every connection that dialed it —
//! because the "each side dials the other" assumption does not hold on
//! Genesis-4 mainnet, where broadcasting outbound-only silently stranded every
//! peer this node had not dialed (the `inbound` field carries that story).
//! Sync requests still go out on outbound connections only, and are answered
//! by the peer's inbound handler on the same socket.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, Weak};
use std::thread;
use std::time::{Duration, Instant};

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
    /// A block and where it came from. The [`Origin`] carries the same
    /// deferred-verdict contract the attestation arm has always had: the p2p
    /// edge stays silent, the engine's `ingest_judged` decides, and only then
    /// is the block relayed (or the peer charged). On the devnet mesh it is
    /// [`Origin::none`] and reporting is a no-op.
    Block(BlockEnvelope, Origin),
    /// An attestation and where it came from. The [`Origin`] is what lets the
    /// engine's `gossip.rs` decision reach gossipsub's
    /// `report_message_validation_result`; on the devnet mesh it is
    /// [`Origin::none`] and reporting is a no-op.
    Attestation(Attestation, Origin),
    /// Relay is deferred until the engine validates against its committed state.
    Transaction(bloch_pos_committee::transition::PosTransaction, Origin),
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
    /// an attestation the pool has not judged — or a block `ingest_judged`
    /// has not judged — is one this node does not forward. The devnet mesh has
    /// no such notion and drops it.
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

    /// Peers attached right now, **per stack**, for the RPC to report.
    ///
    /// `None` means "this node runs no such stack", which is a different
    /// answer from `Some(0)`, "it runs one and nobody is on it". A single
    /// number could not tell those apart, and on `--transport dual` telling
    /// them apart is the entire point: a dual node whose libp2p half reads
    /// `Some(0)` is bound, reachable by nobody, and about to be mistaken for
    /// a node that is bridging two populations.
    pub fn peer_counts(&self) -> (Option<usize>, Option<usize>) {
        match self {
            Net::Devnet(m) => (Some(m.peer_count()), None),
            Net::Libp2p(h) => (None, Some(h.peer_count())),
            Net::Both(m, h) => (Some(m.peer_count()), Some(h.peer_count())),
        }
    }

    /// The `--transport` spelling of what this node is actually running.
    pub fn transport_name(&self) -> &'static str {
        match self {
            Net::Devnet(_) => "devnet",
            Net::Libp2p(_) => "libp2p",
            Net::Both(..) => "dual",
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

/// Bytes of block payload in one `FRAME_GET_BLOCKS` answer (audit NET-17 /
/// NET-05, 2026-09-16).
///
/// [`SYNC_PAGE_BLOCKS`] bounds a COUNT, and a count of 512 blocks that may
/// each be [`crate::codec::MAX_FIELD_LEN`] (8 MiB) bounds nothing useful — the
/// same "bounded counts do not establish a safe memory budget" shape as
/// [`ENGINE_QUEUE_BYTES_CAP`], on the serving side. The production transport
/// stops a page at `MAX_SYNC_FRAME − 1 KiB` (`p2p::read_sync_page`); this is
/// that number, so the two transports serve the same worst-case page
/// whichever wire a peer asks over. Each block is its own frame here, so the
/// 4-byte length prefix is charged per block exactly as libp2p charges it.
const SYNC_PAGE_BYTES: usize = (crate::p2p::MAX_SYNC_FRAME as usize).saturating_sub(1024);

/// Network events queued for the engine before the transport starts shedding.
///
/// The engine consumes one channel on one thread, and during replay it does not
/// consume at all — replay is hours at Genesis-4's state size. An unbounded
/// queue in front of a consumer that is asleep is just a slower way to run out
/// of memory. Blocks and attestations are both recoverable (asked for again,
/// gossiped again), so shedding beats dying.
pub const ENGINE_QUEUE_CAP: usize = 4096;

/// Byte budget for network events queued in front of the engine (external
/// audit 2026-09-07, O06 "bounded counts do not establish a safe memory
/// budget").
///
/// [`ENGINE_QUEUE_CAP`] bounds a COUNT. A count of 4,096 events whose frames
/// may each be [`crate::codec::MAX_FIELD_LEN`] (8 MiB) bounds nothing useful:
/// the product is 32 GiB of wire payload a stalled consumer could be made to
/// hold. This second budget bounds the BYTES of every event that has been
/// reserved and not yet handled, on both transports, so that the queue's
/// contribution to resident memory is `ENGINE_QUEUE_BYTES_CAP` plus the
/// allocator's slack — independent of how large individual frames are.
///
/// 64 MiB: a maximal Genesis-4 block body is 512 KiB
/// (`fee_market::MAX_BLOCK_TX_BYTES_V2`), so the budget holds four epochs of
/// maximal blocks (4 × 32 × 512 KiB) — far more than an engine that is
/// merely busy falls behind by, and exactly the situation (a replaying
/// engine that consumes nothing for hours) in which shedding is the correct
/// outcome. Shed events are recoverable by construction: blocks are asked
/// for again by the sync pump, attestations are re-gossiped, transactions
/// are re-broadcast by their wallets.
pub const ENGINE_QUEUE_BYTES_CAP: usize = 64 << 20;

/// Which class of event a [`NetEvent`] is, for the per-class quota below.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventClass {
    Block,
    Attestation,
    Transaction,
}

/// The class of `ev`.
pub fn class_of(ev: &NetEvent) -> EventClass {
    match ev {
        NetEvent::Block(..) => EventClass::Block,
        NetEvent::Attestation(..) => EventClass::Attestation,
        NetEvent::Transaction(..) => EventClass::Transaction,
    }
}

/// The bytes an event is charged to the budget: its canonical wire size.
///
/// A PURE function of the event value, evaluated identically at reservation
/// (`try_reserve`) and at release (`release`). That is the whole accounting
/// invariant: because both sides compute the same number from the same value,
/// `bytes` after a release equals `bytes` before the matching reservation,
/// with no ticket to thread through the engine's event type. Encoding a block
/// costs one allocation the size of the block; the engine already encodes
/// every block it stores, and the hybrid signature check it runs on each is
/// four orders of magnitude more expensive, so this is not on the critical
/// path.
pub fn queued_bytes(ev: &NetEvent) -> usize {
    match ev {
        NetEvent::Block(env, _) => crate::codec::encode_envelope(env).len(),
        NetEvent::Attestation(att, _) => {
            let mut b = Vec::new();
            crate::codec::encode_attestation(&mut b, att);
            b.len()
        }
        NetEvent::Transaction(tx, _) => tx.canonical_bytes().len(),
    }
}

/// Per-class share of [`ENGINE_QUEUE_BYTES_CAP`] a class may fill.
///
/// The overload policy the audit asked for, stated as three numbers: blocks
/// may use the WHOLE budget (they are what sync progress and control traffic
/// consist of, and a node that sheds blocks while queuing transactions has its
/// priorities inverted); attestations up to three quarters; transactions up to
/// half. So under memory pressure transactions are shed first, attestations
/// second, blocks last — and a flood of one class can never exclude a higher
/// class from the budget.
fn class_bytes_cap(class: EventClass, bytes_cap: usize) -> usize {
    match class {
        EventClass::Block => bytes_cap,
        // Integer arithmetic on a compile-time constant: `bytes_cap / 4 * 3`
        // cannot overflow (it only shrinks) and is exact to the byte for any
        // cap divisible by 4, which the constant is.
        EventClass::Attestation => bytes_cap.checked_div(4).unwrap_or(0).saturating_mul(3),
        EventClass::Transaction => bytes_cap.checked_div(2).unwrap_or(0),
    }
}

/// The admission budget shared by every transport that feeds the engine.
///
/// Two invariants, each maintained by an atomic compare-and-swap rather than
/// by a `load` followed by an `increment` (the race the audit named: N
/// concurrent readers could each observe `count < CAP` and all increment, so
/// the stated cap was exceeded by up to N − 1):
///
/// 1. `count <= ENGINE_QUEUE_CAP` at every instant;
/// 2. `bytes <= ENGINE_QUEUE_BYTES_CAP` at every instant, and for each class
///    `c`, the bytes reserved by events of class `c` never push the total past
///    `class_bytes_cap(c)`.
///
/// A reservation that passes the count check but fails the byte check gives
/// the count back before returning, so a refusal leaves both counters exactly
/// as it found them. Releases are saturating: a double release cannot wrap a
/// counter to `usize::MAX`, which is the failure that once made a dual-
/// transport node shed every frame forever (see `engine::run`).
pub struct QueueBudget {
    count: std::sync::atomic::AtomicUsize,
    bytes: std::sync::atomic::AtomicUsize,
    count_cap: usize,
    bytes_cap: usize,
    shed_blocks: AtomicU64,
    shed_attestations: AtomicU64,
    shed_transactions: AtomicU64,
}

impl QueueBudget {
    /// The production budget: [`ENGINE_QUEUE_CAP`] events, [`ENGINE_QUEUE_BYTES_CAP`] bytes.
    pub fn new() -> Arc<QueueBudget> {
        Arc::new(Self::with_caps(ENGINE_QUEUE_CAP, ENGINE_QUEUE_BYTES_CAP))
    }

    /// A budget with explicit caps. Tests use small caps so every branch of
    /// the policy is reachable in milliseconds; production never calls this
    /// with anything but the two constants.
    pub fn with_caps(count_cap: usize, bytes_cap: usize) -> QueueBudget {
        QueueBudget {
            count: std::sync::atomic::AtomicUsize::new(0),
            bytes: std::sync::atomic::AtomicUsize::new(0),
            count_cap,
            bytes_cap,
            shed_blocks: AtomicU64::new(0),
            shed_attestations: AtomicU64::new(0),
            shed_transactions: AtomicU64::new(0),
        }
    }

    /// Reserve room for `ev`, or record a shed and return `false`.
    ///
    /// Count first (cheap, and the invariant everything else already relies
    /// on), then bytes under the class cap; the count is handed back if the
    /// bytes are refused. Both steps are compare-and-swap loops, so the
    /// invariants hold under any interleaving of any number of callers.
    pub fn try_reserve(&self, ev: &NetEvent) -> bool {
        let class = class_of(ev);
        let size = queued_bytes(ev);
        let admitted = self.reserve_raw(class, size);
        if !admitted {
            self.shed_counter(class).fetch_add(1, Ordering::Relaxed);
        }
        admitted
    }

    fn reserve_raw(&self, class: EventClass, size: usize) -> bool {
        let count_cap = self.count_cap;
        if self
            .count
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                if n < count_cap { n.checked_add(1) } else { None }
            })
            .is_err()
        {
            return false;
        }
        let class_cap = class_bytes_cap(class, self.bytes_cap);
        let reserved = self
            .bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |b| {
                b.checked_add(size).filter(|total| *total <= class_cap)
            })
            .is_ok();
        if !reserved {
            // Give the count back: a refusal must leave the budget as it was.
            let _ = self.count.fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                Some(n.saturating_sub(1))
            });
        }
        reserved
    }

    /// Release the reservation made for `ev` — the same pure size function,
    /// so the two calls cancel exactly.
    pub fn release(&self, ev: &NetEvent) {
        self.release_raw(queued_bytes(ev));
    }

    /// Release a reservation whose event has already been moved away (the
    /// send-failure path), given the size that was reserved for it.
    pub fn release_raw(&self, size: usize) {
        let _ = self.count.fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
            Some(n.saturating_sub(1))
        });
        let _ = self.bytes.fetch_update(Ordering::AcqRel, Ordering::Acquire, |b| {
            Some(b.saturating_sub(size))
        });
    }

    fn shed_counter(&self, class: EventClass) -> &AtomicU64 {
        match class {
            EventClass::Block => &self.shed_blocks,
            EventClass::Attestation => &self.shed_attestations,
            EventClass::Transaction => &self.shed_transactions,
        }
    }

    /// Events reserved and not yet handled.
    pub fn inflight(&self) -> usize {
        self.count.load(Ordering::Acquire)
    }

    /// Bytes reserved and not yet handled.
    pub fn inflight_bytes(&self) -> usize {
        self.bytes.load(Ordering::Acquire)
    }

    /// Events shed since start, per class: (blocks, attestations, transactions).
    pub fn shed(&self) -> (u64, u64, u64) {
        (
            self.shed_blocks.load(Ordering::Relaxed),
            self.shed_attestations.load(Ordering::Relaxed),
            self.shed_transactions.load(Ordering::Relaxed),
        )
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
const INBOUND_QUEUE_DEPTH: usize = 256;

/// Depth of an outbound (dialer) peer's broadcast queue before frames are
/// dropped (R3 M-4 / R1 A3-M2).
///
/// This used to be `mpsc::channel()` — UNBOUNDED. [`DevnetMesh::broadcast`]
/// pushes one frame per broadcast into EVERY configured peer's queue
/// regardless of whether that peer is reachable — the dialer thread below
/// retries a dead address forever and never removes its sender from
/// `DevnetMesh::peers` while it is down (see that field's own doc: `peers.len()`
/// "reads the same whether the peer is answering or has been down for a
/// week"). A single misconfigured or genuinely offline peer address therefore
/// queued every block and every attestation this node ever broadcast, for the
/// life of the process, with no bound — the same unbounded-queue-behind-a-
/// stalled-consumer shape that OOM-killed 22 validators on 2026-08-21 (see
/// [`ENGINE_QUEUE_CAP`]), just on the send side instead of the receive side.
/// Bounded identically to the already-bounded inbound queue: a full queue
/// drops the newest frame rather than growing, and every OTHER connection
/// this node holds stays unaffected.
const OUTBOUND_QUEUE_DEPTH: usize = 256;

/// Inbound TCP connections this transport will accept concurrently (R3 M-4 /
/// R1 A3-M2).
///
/// This transport authenticates nothing and admits nothing (see the module
/// header): binding a routable address is opt-in and, once bound, ANY TCP
/// connection this node accepts costs two threads (one reader, one writer)
/// and one bounded queue for as long as it stays open — before this bound,
/// forever. `engine::Config::max_peers` defaults to 64 configured/dialed
/// peers; this is double that, generous headroom for inbound connections
/// from peers that dialed first, past which a new connection is closed
/// immediately, before either thread is spawned.
const MAX_INBOUND_CONNECTIONS: usize = 128;

/// Inbound TCP connections this transport will hold from ONE source address
/// at once (audit NET-03, 2026-09-16).
///
/// [`MAX_INBOUND_CONNECTIONS`] is a per-process count. Counted that way, one
/// host that opens 128 sockets to a public bootnode and sends a 5-byte frame
/// on each every ~100 s holds every slot for as long as it likes, and every
/// third party following the quickstart is refused at accept — the only
/// public onboarding path, denied for the price of 128 idle sockets. The
/// fleet peer list has exactly ONE connection per peer host in each
/// direction (each side dials the other once), so an honest host never needs
/// more than one inbound slot here; four leaves room for a host that runs a
/// couple of nodes or an injector (`send_transaction` opens and closes its
/// own) next to its validator, and still means a single source can take at
/// most 4 of 128 slots. Checked at accept, alongside the global cap, and
/// released when the connection ends.
const MAX_INBOUND_PER_IP: usize = 4;

/// The devnet transport's tunables, as one value, so [`start`] has exactly
/// one production setting and the tests that need a small number have a
/// named way to ask for it (audit NET-03 / NET-09, 2026-09-16). Production
/// goes through `start` and always gets [`DevnetTuning::PRODUCTION`].
#[derive(Clone, Copy)]
struct DevnetTuning {
    /// [`MAX_INBOUND_PER_IP`].
    max_inbound_per_ip: usize,
    /// [`DEVNET_IO_TIMEOUT`], as the inbound reader's deadline: how long an
    /// accepted connection may go without a decodable frame.
    inbound_idle: Duration,
    /// [`DIAL_STALE_AFTER`].
    dial_stale_after: Duration,
}

impl DevnetTuning {
    const PRODUCTION: DevnetTuning = DevnetTuning {
        max_inbound_per_ip: MAX_INBOUND_PER_IP,
        inbound_idle: DEVNET_IO_TIMEOUT,
        dial_stale_after: DIAL_STALE_AFTER,
    };
}

/// Socket read/write timeout for the devnet mesh (R3 M-4 / R1 A3-M2). This
/// transport had none: a peer that stopped reading its socket could stall
/// `write_frame` forever once the kernel send buffer filled (one thread
/// leaked, permanently, per such peer), and a peer that never wrote anything
/// held its reader thread — and its slot under [`MAX_INBOUND_CONNECTIONS`] —
/// open forever.
///
/// An honest connection that holds a sync slot re-asks for history every
/// 5 seconds and is never idle anywhere near this long. The other
/// connections are NOT that busy (audit NET-09, 2026-09-16): this transport
/// does not relay, so one direction of a socket carries only what that
/// endpoint itself originates — its own attestation once per epoch (~16 min)
/// and its proposals — and between those the accepting side closes it here.
/// That is fine, and it is now handled rather than hidden: the dialer below
/// notices the close through its reader thread and re-dials before it writes
/// the next frame, so the idle close costs a reconnect and never a frame.
///
/// On the inbound side the deadline is anchored at the last DECODABLE frame
/// (audit NET-03): a frame of an unknown type renews nothing, so a peer
/// sending only keepalive junk is closed at exactly the moment a silent peer
/// would be.
const DEVNET_IO_TIMEOUT: Duration = Duration::from_secs(120);

/// How long a dialed socket may go without this node WRITING to it before
/// the next queued frame goes out on a fresh socket instead (audit NET-09,
/// 2026-09-16).
///
/// The accepting side closes an inbound connection [`DEVNET_IO_TIMEOUT`]
/// after the last decodable frame it read — that is, after this dialer's
/// last write. The dialer's reader thread notices that close once the FIN
/// arrives and the writer loop re-dials (see [`ReaderOpen`]); this closes
/// the window before the FIN has arrived, and the race between the peer's
/// close and this node's next write, deterministically: a socket this node
/// has not written to for this long is one the peer is about to close, and
/// a frame due for it is written on a new socket. Fifteen seconds under the
/// peer's deadline covers scheduling skew between two hosts; a connection
/// that holds a sync slot writes every 5 s and never comes near it.
const DIAL_STALE_AFTER: Duration = Duration::from_secs(105);

/// Sustained `get-blocks` answers this transport will build per source
/// address, per second, and the burst above it before the sustained rate
/// binds — same values and the same reasoning as
/// [`crate::p2p::SYNC_ANSWERS_PER_SEC`] / [`crate::p2p::SYNC_ANSWER_BURST`]
/// on the production transport, which this mirrors (R3 M-4 / R1 A3-M2): the
/// devnet serving path had NO rate limit at all, so a connected peer could
/// issue `get-blocks` back to back forever, each one paying a
/// `Store::blocks_after` disk read.
///
/// Per source ADDRESS, not per connection (audit NET-05, 2026-09-16): a
/// per-connection bucket multiplies by however many connections one host
/// may hold, and the budget it bought was 128 × 8 × 512 blocks/s from one
/// host. Every connection from one address now draws on ONE bucket, and the
/// bucket outlives the connection (see [`InboundByIp`]) so closing and
/// re-dialing does not refill it.
const GET_BLOCKS_ANSWERS_PER_SEC: f64 = 8.0;
const GET_BLOCKS_BURST: f64 = 32.0;

/// The devnet TCP mesh: one queue per peer we dialed, plus one per peer that
/// dialed us.
pub struct DevnetMesh {
    /// Bounded per [`OUTBOUND_QUEUE_DEPTH`] (R3 M-4 / R1 A3-M2) — see that
    /// constant's doc for why an unbounded queue here was a memory leak
    /// waiting on a peer that never connects.
    peers: Vec<SyncSender<Vec<u8>>>,
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
    inbound: Arc<Mutex<Vec<InboundPeer>>>,
    /// TCP connections up **right now**, inbound and outbound together.
    ///
    /// Not `peers.len()`: that is one entry per *configured* peer address and
    /// its dialer thread retries forever, so it reads the same whether the
    /// peer is answering or has been down for a week. This counter is
    /// incremented when a socket is established and decremented when its
    /// connection workers end, by [`ConnCount`], so it is a fact about the
    /// network rather than about the command line.
    ///
    /// It exists so `getchaininfo` can say which stacks a node is actually
    /// attached to. On `--transport dual` that is the whole proof that the
    /// node is on both.
    live: Arc<std::sync::atomic::AtomicUsize>,
}

/// Holds one unit of [`DevnetMesh::live`] for the lifetime of a connection.
///
/// A guard rather than a matching `fetch_sub` at each exit: the reader
/// threads below leave by `return` from several arms and by unwinding, and a
/// counter that leaks on one of those paths reports a node as connected
/// forever — which is worse than not reporting at all.
struct ConnCount(Arc<std::sync::atomic::AtomicUsize>);

impl ConnCount {
    fn new(c: &Arc<std::sync::atomic::AtomicUsize>) -> Self {
        c.fetch_add(1, Ordering::AcqRel);
        ConnCount(c.clone())
    }
}

impl Drop for ConnCount {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Clears a dialer's "reader is running" flag when its reader thread leaves,
/// by any path (audit NET-09, 2026-09-16). A guard, like [`ConnCount`], so an
/// unwind clears it too; a flag that stayed set would leave the writer loop
/// trusting a socket whose other half is gone.
struct ReaderOpen(Arc<AtomicBool>);

impl Drop for ReaderOpen {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

struct InboundPeer {
    frames: SyncSender<Vec<u8>>,
    connection: Weak<InboundConnection>,
}

impl InboundPeer {
    fn is_open(&self) -> bool {
        self.connection.upgrade().is_some_and(|c| !c.closed.load(Ordering::Acquire))
    }
}

/// Both workers share one counted lifetime. Exiting either half shuts down
/// the socket; capacity is released only after BOTH workers have stopped.
struct InboundConnection {
    socket: TcpStream,
    closed: AtomicBool,
    _counts: (ConnCount, ConnCount),
    /// The source address's slot under [`MAX_INBOUND_PER_IP`] (audit NET-03,
    /// 2026-09-16), released on the same terms as `_counts`: after BOTH
    /// workers have stopped. `None` only for the tests that build a
    /// connection by hand without an accept loop.
    _ip_slot: Option<IpSlot>,
}

struct InboundHalf(Arc<InboundConnection>);

impl Drop for InboundHalf {
    fn drop(&mut self) {
        self.0.closed.store(true, Ordering::Release);
        let _ = self.0.socket.shutdown(Shutdown::Both);
    }
}

fn run_inbound_writer(
    rx: Receiver<Vec<u8>>,
    socket: Arc<Mutex<TcpStream>>,
    half: InboundHalf,
) {
    while !half.0.closed.load(Ordering::Acquire) {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(frame) => {
                let Ok(mut writer) = socket.lock() else { return };
                if write_frame(&mut writer, &frame).is_err() { return; }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
        }
    }
}

impl DevnetMesh {
    /// TCP connections established right now. See [`DevnetMesh::live`].
    pub fn peer_count(&self) -> usize {
        self.live.load(Ordering::Acquire)
    }

    /// Broadcast one frame (type byte + payload, no length prefix) to every
    /// peer, dialed or dialing.
    pub fn broadcast(&self, frame: Vec<u8>) {
        // `try_send`, not `send` (R3 M-4 / R1 A3-M2): the queue is bounded now,
        // so a peer whose dialer is stuck (unreachable address, or reachable
        // but not draining fast enough) gets this frame DROPPED rather than
        // this call blocking or the queue growing without limit. Dropped
        // frames are recoverable the same way an inbound-side drop is: the
        // peer's own dialer re-asks for history on its idle tick the moment
        // it connects or catches up.
        for p in &self.peers {
            let _ = p.try_send(frame.clone());
        }
        // `retain` both sends and prunes: a closed receiver is a connection
        // whose writer thread has exited, and keeping its sender would leak one
        // entry per reconnect for as long as the node runs.
        if let Ok(mut inbound) = self.inbound.lock() {
            inbound.retain(|p| p.is_open()
                && !matches!(p.frames.try_send(frame.clone()), Err(TrySendError::Disconnected(_))));
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
fn send_to_engine(events: &Sender<EngineEvent>, budget: &QueueBudget, ev: NetEvent) -> bool {
    // Atomic reservation of BOTH the count and the bytes (O06): the old
    // `load >= CAP` followed by `fetch_add` let concurrent readers overshoot
    // the cap, and no byte budget existed at all.
    if !budget.try_reserve(&ev) {
        return true; // shed, but the connection stays healthy
    }
    let size = queued_bytes(&ev);
    if events.send(EngineEvent::Net(ev)).is_err() {
        budget.release_raw(size);
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
    // Capacity hint only: saturating is the intended semantics.
    let mut frame = Vec::with_capacity(1usize.saturating_add(tx_bytes.len()));
    frame.push(FRAME_TX);
    frame.extend_from_slice(tx_bytes);
    write_frame(&mut sock, &frame)
}

/// Send one block envelope to a running node and disconnect — the
/// `FRAME_BLOCK` twin of [`send_transaction`], for the devnet equivocation
/// injector (`devnet_tools::equivocate`). Same contract: the node judges it
/// through `ingest_judged` exactly as a gossiped block, and nothing is
/// acknowledged.
pub fn send_block(addr: &str, env: &BlockEnvelope) -> std::io::Result<()> {
    let mut sock = TcpStream::connect(addr)?;
    write_frame(&mut sock, &block_frame(env))
}

fn write_frame(sock: &mut TcpStream, frame: &[u8]) -> std::io::Result<()> {
    // Capacity hint only: saturating is the intended semantics.
    let mut buf = Vec::with_capacity(4usize.saturating_add(frame.len()));
    buf.extend_from_slice(&(frame.len() as u32).to_le_bytes());
    buf.extend_from_slice(frame);
    sock.write_all(&buf)
}

fn read_frame(sock: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let deadline = Instant::now().checked_add(DEVNET_IO_TIMEOUT)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "frame deadline out of range"))?;
    read_frame_until(sock, deadline)
}

fn read_frame_until(sock: &mut TcpStream, deadline: Instant) -> std::io::Result<Vec<u8>> {
    let mut len4 = [0u8; 4];
    read_exact_until(sock, &mut len4, deadline)?;
    let len = u32::from_le_bytes(len4) as usize;
    if len == 0 || len > crate::codec::MAX_FIELD_LEN {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "bad frame length"));
    }
    let mut buf = vec![0u8; len];
    read_exact_until(sock, &mut buf, deadline)?;
    Ok(buf)
}

/// A single frame budget covers both its length prefix and payload. `read_exact`
/// with a fixed socket timeout would renew the budget on every partial read.
fn read_exact_until(sock: &mut TcpStream, mut buf: &mut [u8], deadline: Instant) -> std::io::Result<()> {
    while !buf.is_empty() {
        let remaining = deadline.checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::TimedOut, "frame deadline exceeded"))?;
        sock.set_read_timeout(Some(remaining))?;
        match sock.read(buf) {
            Ok(0) => return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "incomplete frame")),
            Ok(n) => buf = &mut buf[n..],
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Decode a data frame into an engine event. Get-blocks is handled by the
/// socket owner (it needs write access), not here.
fn decode_event(frame: &[u8]) -> Option<NetEvent> {
    match frame.first()? {
        &FRAME_BLOCK => {
            crate::codec::decode_envelope(&frame[1..])
                .ok()
                .map(|env| NetEvent::Block(env, Origin::none()))
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
                .map(|tx| NetEvent::Transaction(tx, Origin::none()))
        }
        _ => None,
    }
}

/// Admission for `get-blocks` on the devnet transport (R3 M-4 / R1 A3-M2): a
/// token bucket, same shape and same values as the production transport's
/// [`crate::p2p::SyncLimiter`], simplified because a devnet connection has
/// exactly one reader thread and therefore exactly one `get-blocks` in flight
/// at a time BY CONSTRUCTION — `serve_get_blocks` runs inline in that thread,
/// so there is no concurrency to cap here, only rate. One bucket per source
/// address, held in [`InboundByIp`] (audit NET-05, 2026-09-16); it used to be
/// one per connection.
///
/// Time is a parameter, not a call to `Instant::now()` inside, for the same
/// reason `SyncLimiter` takes one: testable refill arithmetic without
/// sleeping.
struct GetBlocksLimiter {
    tokens: f64,
    last: Instant,
}

impl GetBlocksLimiter {
    fn new() -> Self {
        GetBlocksLimiter { tokens: GET_BLOCKS_BURST, last: Instant::now() }
    }

    fn refill(&mut self, now: Instant) {
        let dt = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + dt * GET_BLOCKS_ANSWERS_PER_SEC).min(GET_BLOCKS_BURST);
    }

    /// Admit one request now, or refuse. Refusing costs the peer nothing but
    /// silence — no frames are read from the log and none are written back,
    /// so a peer over its budget gets an answer that looks exactly like "the
    /// tip has not moved", which is indistinguishable from the truth and
    /// costs this node one comparison.
    fn admit(&mut self, now: Instant) -> bool {
        self.refill(now);
        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }

    /// True once nothing of the burst is spent any more — the state a fresh
    /// bucket starts in, so an entry in this state carries no information
    /// worth keeping.
    fn is_full(&mut self, now: Instant) -> bool {
        self.refill(now);
        self.tokens >= GET_BLOCKS_BURST
    }
}

/// What this node holds against one inbound source address.
struct PerIp {
    /// Inbound connections from this address up right now.
    conns: usize,
    /// The address's `get-blocks` budget, shared by every one of `conns`.
    get_blocks: GetBlocksLimiter,
}

/// Per-source-address accounting for the inbound side (audit NET-03 and
/// NET-05, 2026-09-16): the connection count that [`MAX_INBOUND_PER_IP`]
/// binds, and the `get-blocks` bucket that [`GET_BLOCKS_ANSWERS_PER_SEC`]
/// refills. One table, one lock, keyed by the address `accept` reported —
/// which this transport cannot verify, but which an attacker cannot forge
/// either, since a TCP connection only completes to the address that
/// answered the handshake.
///
/// An entry lives while the address has a connection up OR its bucket is
/// not full: dropping the entry with the last connection would hand a
/// re-dialing peer a fresh burst, and that is exactly the budget the
/// per-connection limiter used to hand out. Entries whose bucket has refilled
/// are pruned on the next accept, so the table holds at most the connected
/// addresses plus those that spent budget in the last
/// `GET_BLOCKS_BURST / GET_BLOCKS_ANSWERS_PER_SEC` (4) seconds.
struct InboundByIp {
    max_per_ip: usize,
    by_ip: Mutex<HashMap<IpAddr, PerIp>>,
}

impl InboundByIp {
    fn new(max_per_ip: usize) -> Arc<Self> {
        Arc::new(InboundByIp { max_per_ip, by_ip: Mutex::new(HashMap::new()) })
    }

    /// Take one of `ip`'s [`MAX_INBOUND_PER_IP`] slots, or refuse. The slot
    /// is a guard, for the same reason [`ConnCount`] is one: the connection
    /// workers leave by several returns and by unwinding, and a slot that
    /// leaks on one of them is a slot that address never gets back.
    fn try_admit(self: &Arc<Self>, ip: IpAddr, now: Instant) -> Option<IpSlot> {
        let mut by_ip = self.by_ip.lock().ok()?;
        by_ip.retain(|_, s| s.conns > 0 || !s.get_blocks.is_full(now));
        let entry = by_ip
            .entry(ip)
            .or_insert_with(|| PerIp { conns: 0, get_blocks: GetBlocksLimiter::new() });
        if entry.conns >= self.max_per_ip {
            return None;
        }
        entry.conns = entry.conns.saturating_add(1);
        Some(IpSlot { table: self.clone(), ip })
    }

    /// One `get-blocks` from `ip`, against the bucket every connection from
    /// that address shares. An address with no entry has never been admitted
    /// here; it is refused rather than given a bucket, since only
    /// `try_admit` creates entries and only its holders ask.
    fn admit_get_blocks(&self, ip: IpAddr, now: Instant) -> bool {
        let Ok(mut by_ip) = self.by_ip.lock() else { return false };
        by_ip.get_mut(&ip).is_some_and(|s| s.get_blocks.admit(now))
    }

    fn release(&self, ip: IpAddr, now: Instant) {
        let Ok(mut by_ip) = self.by_ip.lock() else { return };
        if let Some(s) = by_ip.get_mut(&ip) {
            s.conns = s.conns.saturating_sub(1);
            if s.conns == 0 && s.get_blocks.is_full(now) {
                by_ip.remove(&ip);
            }
        }
    }
}

/// Holds one of an address's inbound slots for the lifetime of a connection.
struct IpSlot {
    table: Arc<InboundByIp>,
    ip: IpAddr,
}

impl Drop for IpSlot {
    fn drop(&mut self) {
        self.table.release(self.ip, Instant::now());
    }
}

/// The blocks of one `get-blocks` answer that fit under [`SYNC_PAGE_BYTES`]
/// (audit NET-17 / NET-05, 2026-09-16), in log order, stopping at the first
/// that does not — the same arithmetic as `p2p::read_sync_page`, so the two
/// transports serve the same worst-case page. The page stops here even when
/// fewer than [`SYNC_PAGE_BLOCKS`] have gone out, and the requester's next
/// ask starts from wherever its head got to. Each block is charged its
/// length plus the 4-byte prefix `write_frame` puts in front of it.
/// Saturating for the same reason as there: a block larger than `usize::MAX`
/// is impossible, and must still fail this check rather than wrap past it.
fn page_within_bytes(blocks: Vec<Vec<u8>>) -> impl Iterator<Item = Vec<u8>> {
    let mut bytes = 0usize;
    blocks.into_iter().take_while(move |b| {
        let next = bytes.saturating_add(b.len()).saturating_add(4);
        if next > SYNC_PAGE_BYTES {
            return false;
        }
        bytes = next;
        true
    })
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
fn serve_get_blocks(
    sock: &Arc<Mutex<TcpStream>>,
    data_dir: &PathBuf,
    frame: &[u8],
    by_ip: &InboundByIp,
    ip: IpAddr,
) {
    if frame.len() != 9 {
        return;
    }
    // R3 M-4 / R1 A3-M2: rate-limited BEFORE the disk is touched — the whole
    // point is that `Store::blocks_after` below is the expensive step this
    // guards. Against the source ADDRESS's bucket (audit NET-05, 2026-09-16),
    // so a second connection from the same host draws on the same budget.
    if !by_ip.admit_get_blocks(ip, Instant::now()) {
        return;
    }
    // `frame.len() != 9` already returned above, so `frame[1..9]` is always
    // exactly 8 bytes and the conversion cannot fail; the `else` arm keeps it
    // panic-free by construction rather than by an `unwrap`.
    let Ok(after_bytes) = frame[1..9].try_into() else {
        return;
    };
    let after = u64::from_le_bytes(after_bytes);
    // Paged at `SYNC_PAGE_BLOCKS`. This used to answer `usize::MAX` — the whole
    // chain in one burst — under a comment calling that deliberate, since "a
    // restarting node's single request must be answered in full or it never
    // catches up". That was true only while nobody re-asked. The dialer now
    // re-asks from its new head for as long as it holds a sync slot, so the
    // full history still arrives; it just no longer arrives as one allocation
    // large enough to kill the receiver.
    match crate::store::Store::blocks_after(data_dir, after, SYNC_PAGE_BLOCKS) {
        Ok(blocks) => {
            // Byte cap as well as block cap (audit NET-17 / NET-05,
            // 2026-09-16): see `page_within_bytes`.
            for b in page_within_bytes(blocks) {
                // Capacity hint only: saturating is the intended semantics.
                let mut f = Vec::with_capacity(1usize.saturating_add(b.len()));
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

/// The inbound reader loop: data frames go to the engine, get-blocks is
/// answered in place from the log. Returns when the connection is done —
/// the caller's [`InboundHalf`] then shuts the socket down.
///
/// The deadline is anchored at the last DECODABLE frame (audit NET-03,
/// 2026-09-16), not at the last frame. `read_frame` renewed a full
/// [`DEVNET_IO_TIMEOUT`] on every frame, and a 5-byte frame of an unknown
/// type decodes to nothing and cost nothing, so one such frame per ~100 s
/// held a slot forever. Now a frame that neither the engine nor
/// `serve_get_blocks` can use leaves the deadline where it was, and a peer
/// that sends only those is closed at the moment a silent peer would be.
/// `idle` is [`DEVNET_IO_TIMEOUT`] in production and a parameter here so the
/// test does not wait two minutes.
#[allow(clippy::too_many_arguments)]
fn run_inbound_reader(
    mut rsock: TcpStream,
    wsock: Arc<Mutex<TcpStream>>,
    data_dir: PathBuf,
    events: Sender<EngineEvent>,
    inflight: Arc<QueueBudget>,
    by_ip: Arc<InboundByIp>,
    ip: IpAddr,
    idle: Duration,
) {
    let mut last_decodable = Instant::now();
    loop {
        let Some(deadline) = last_decodable.checked_add(idle) else { return };
        match read_frame_until(&mut rsock, deadline) {
            Ok(frame) => {
                let decodable = if frame.first() == Some(&FRAME_GET_BLOCKS) {
                    serve_get_blocks(&wsock, &data_dir, &frame, &by_ip, ip);
                    frame.len() == 9
                } else if let Some(ev) = decode_event(&frame) {
                    if !send_to_engine(&events, &inflight, ev) {
                        return;
                    }
                    true
                } else {
                    false
                };
                if decodable {
                    last_decodable = Instant::now();
                }
            }
            Err(_) => return,
        }
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
    inflight: Arc<QueueBudget>,
) -> std::io::Result<DevnetMesh> {
    start_with_tuning(
        bind_addr, listen_port, peer_addrs, events, data_dir, head_slot, inflight,
        DevnetTuning::PRODUCTION,
    )
}

/// [`start`] with the tunables as a parameter (audit NET-03 / NET-09,
/// 2026-09-16). Production goes through `start` and always gets
/// [`DevnetTuning::PRODUCTION`]; this exists so the global-cap test, which
/// fills all `MAX_INBOUND_CONNECTIONS` from loopback, can lift the
/// per-address bound it would otherwise hit first, and so the idle and
/// stale deadlines can be tested in milliseconds rather than minutes.
#[allow(clippy::too_many_arguments)]
fn start_with_tuning(
    bind_addr: &str,
    listen_port: u16,
    peer_addrs: Vec<String>,
    events: Sender<EngineEvent>,
    data_dir: PathBuf,
    head_slot: Arc<AtomicU64>,
    inflight: Arc<QueueBudget>,
    tuning: DevnetTuning,
) -> std::io::Result<DevnetMesh> {
    // Inbound: accept, then per-connection: read frames; data frames go to
    // the engine, get-blocks is answered in place from the log.
    let listener = TcpListener::bind((bind_addr, listen_port))?;
    // Per source address (audit NET-03 / NET-05, 2026-09-16): the slot count
    // the accept loop checks and the `get-blocks` bucket the reader threads
    // draw on, keyed by the address each connection came from.
    let by_ip = InboundByIp::new(tuning.max_inbound_per_ip);
    let inbound: Arc<Mutex<Vec<InboundPeer>>> = Arc::new(Mutex::new(Vec::new()));
    let live = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    // Counted separately from `live` (R3 M-4 / R1 A3-M2): `live` also holds
    // OUTBOUND connections (this node's own configured peers), and the cap
    // below must bind INBOUND connections alone — a node with a full
    // configured peer list must not have its accept path refuse legitimate
    // inbound peers because of its own outbound count, and a node under an
    // inbound flood must not have that flood count against the outbound
    // side's accounting either.
    let inbound_live = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    {
        let events = events.clone();
        let data_dir = data_dir.clone();
        let inbound = inbound.clone();
        let inflight = inflight.clone();
        let live = live.clone();
        let inbound_live = inbound_live.clone();
        let by_ip = by_ip.clone();
        thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(sock) = conn else { continue };
                // A quiet mesh may never broadcast. Prune on accept too, so
                // connection churn cannot retain one dead sender per dial.
                if let Ok(mut reg) = inbound.lock() {
                    reg.retain(InboundPeer::is_open);
                }
                // R3 M-4 / R1 A3-M2: past the cap, close the socket immediately
                // — `sock` drops at the end of this iteration — before either
                // thread below is spawned and before the socket costs this
                // node anything beyond the accept itself.
                if inbound_live.load(Ordering::Acquire) >= MAX_INBOUND_CONNECTIONS {
                    continue;
                }
                // Audit NET-03 (2026-09-16): and past THIS address's share of
                // the cap, the same immediate close. A socket whose peer
                // address cannot be read is one this node cannot account
                // for, and is closed the same way. The slot is a guard that
                // travels with the connection below, so every early `continue`
                // between here and the spawn hands it straight back.
                let Ok(peer_ip) = sock.peer_addr().map(|a| a.ip()) else { continue };
                let Some(ip_slot) = by_ip.try_admit(peer_ip, Instant::now()) else { continue };
                // R3 M-4 / R1 A3-M2: bounded so a peer that stops reading or
                // never writes cannot hold a thread and a queue open forever.
                if sock.set_read_timeout(Some(DEVNET_IO_TIMEOUT)).is_err()
                    || sock.set_write_timeout(Some(DEVNET_IO_TIMEOUT)).is_err()
                {
                    continue;
                }
                // Reading and writing need separate handles: the reader blocks
                // in `read_frame` for as long as the peer is quiet, and a
                // broadcast must not wait behind it.
                let Ok(rsock) = sock.try_clone() else { continue };
                let Ok(shutdown_socket) = sock.try_clone() else { continue };
                let connection = Arc::new(InboundConnection {
                    socket: shutdown_socket,
                    closed: AtomicBool::new(false),
                    _counts: (ConnCount::new(&live), ConnCount::new(&inbound_live)),
                    _ip_slot: Some(ip_slot),
                });
                let wsock = Arc::new(Mutex::new(sock));

                // One writer thread per connection, fed by a bounded queue, so
                // a peer that stops reading fills its own queue and is dropped
                // from there rather than blocking this node's broadcast loop.
                let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(INBOUND_QUEUE_DEPTH);
                {
                    let wsock = wsock.clone();
                    let half = InboundHalf(connection.clone());
                    thread::spawn(move || {
                        run_inbound_writer(rx, wsock, half);
                    });
                }
                if let Ok(mut reg) = inbound.lock() {
                    reg.push(InboundPeer { frames: tx, connection: Arc::downgrade(&connection) });
                }

                let events = events.clone();
                let data_dir = data_dir.clone();
                let inflight = inflight.clone();
                let by_ip = by_ip.clone();
                // Counted from here to wherever this thread leaves. The guard
                // is moved into the closure, so every `return` inside the
                // reader and any unwind releases it.
                let half = InboundHalf(connection);
                thread::spawn(move || {
                    let _half = half;
                    run_inbound_reader(
                        rsock, wsock, data_dir, events, inflight, by_ip, peer_ip,
                        tuning.inbound_idle,
                    );
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
        // R3 M-4 / R1 A3-M2: bounded — see [`OUTBOUND_QUEUE_DEPTH`].
        let (tx, rx): (SyncSender<Vec<u8>>, Receiver<Vec<u8>>) =
            mpsc::sync_channel(OUTBOUND_QUEUE_DEPTH);
        peers.push(tx);
        let events = events.clone();
        let head_slot = head_slot.clone();
        let sync_slots = sync_slots.clone();
        let inflight = inflight.clone();
        let live = live.clone();
        thread::spawn(move || {
            // Audit NET-09 (2026-09-16): a frame taken off the queue and not
            // delivered — because the socket turned out to be dead, or the
            // write failed — is carried across the reconnect and written
            // first on the new socket, so no broadcast is lost to an idle
            // close. `None` between reconnects; `Some` survives failed dials.
            let mut pending: Option<Vec<u8>> = None;
            loop {
            let Ok(sock) = TcpStream::connect(&addr) else {
                thread::sleep(Duration::from_millis(300));
                continue;
            };
            // Counted from a SUCCESSFUL connect, and released when this
            // connection's inner loop breaks to reconnect. A dialer retrying a
            // peer that is down therefore contributes nothing, which is the
            // difference between this number and `peers.len()`.
            let _counted = ConnCount::new(&live);
            let mut wsock = sock;
            // Audit NET-09 (2026-09-16): when this node last wrote to this
            // socket — the moment the peer's idle deadline is anchored at.
            // See [`DIAL_STALE_AFTER`].
            let mut last_write = Instant::now();
            // R3 M-4 / R1 A3-M2: same bound as the inbound side — see
            // [`DEVNET_IO_TIMEOUT`]. Best-effort; a platform that refuses the
            // option gets an unbounded-latency socket, not a broken one.
            let _ = wsock.set_read_timeout(Some(DEVNET_IO_TIMEOUT));
            let _ = wsock.set_write_timeout(Some(DEVNET_IO_TIMEOUT));
            // Audit NET-09 (2026-09-16): the reader half is what notices the
            // peer closing this socket — the accepting side closes it after
            // `DEVNET_IO_TIMEOUT` idle, which on a connection that holds no
            // sync slot is the honest cadence (one attestation per ~16 min).
            // Before this, the reader returned silently and nothing told the
            // writer loop; by TCP semantics the writer's FIRST write into the
            // dead socket then succeeded locally (the peer answers RST) and
            // only the SECOND failed, so the first frame after an idle period
            // — this node's own attestation or proposal, most likely — was
            // lost, every time. The writer loop below reads this flag before
            // every write and on every idle tick, and re-dials instead.
            //
            // Chosen over a keepalive frame: a keepalive is a new type byte
            // on a wire this change must not alter, and it would have to
            // count as decodable on the inbound side (see
            // `run_inbound_reader`) or it would not renew anything. The
            // reconnect reuses the dial/re-dial path that already exists two
            // lines below for a failed write, costs one TCP handshake per
            // idle close, and keeps the wire exactly as it was.
            let reader_open = Arc::new(AtomicBool::new(true));
            // Reader half: the peer answers our get-blocks on this socket.
            if let Ok(mut rsock) = wsock.try_clone() {
                let events = events.clone();
                let inflight = inflight.clone();
                let open = ReaderOpen(reader_open.clone());
                thread::spawn(move || {
                    let _open = open;
                    loop {
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
                    }
                });
            }
            // Claim one of the `SYNC_FANOUT` sync slots before asking for
            // history. A dialer that cannot claim one stays connected and keeps
            // receiving broadcasts — it just does not add another concurrent
            // copy of the chain to a node that may still be replaying.
            let holds_slot = sync_slots
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                    // `n` only ever takes small values near `SYNC_FANOUT`
                    // (== 2): this same closure is the only place that
                    // increments it, and only when `n < SYNC_FANOUT`; the
                    // rest of this module only decrements it. Nowhere near
                    // overflowing `usize`.
                    #[allow(clippy::arithmetic_side_effects)]
                    let next = n + 1;
                    (n < SYNC_FANOUT).then_some(next)
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
            // Audit NET-09 (2026-09-16): the frame the previous socket did
            // not deliver goes first on this one.
            if let Some(frame) = pending.take() {
                if write_frame(&mut wsock, &frame).is_err() {
                    pending = Some(frame);
                    drop_slot(&mut held);
                    continue;
                }
                last_write = Instant::now();
            }
            loop {
                match rx.recv_timeout(Duration::from_secs(5)) {
                    Ok(frame) => {
                        // Audit NET-09 (2026-09-16): a socket whose reader
                        // has gone, or that this node has not written to
                        // for `dial_stale_after` (so the peer's idle close
                        // is due, whether or not its FIN has arrived yet),
                        // is not written to — the write would succeed and
                        // deliver nothing. The frame is kept for the next
                        // socket either way.
                        if !reader_open.load(Ordering::Acquire)
                            || last_write.elapsed() >= tuning.dial_stale_after
                            || write_frame(&mut wsock, &frame).is_err()
                        {
                            pending = Some(frame);
                            drop_slot(&mut held);
                            break; // reconnect
                        }
                        last_write = Instant::now();
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        // Audit NET-09 (2026-09-16): re-dial a closed socket
                        // on the idle tick too, so a peer that closed us is
                        // back within five seconds whether or not this node
                        // has anything to say yet.
                        if !reader_open.load(Ordering::Acquire) {
                            drop_slot(&mut held);
                            break; // reconnect
                        }
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
                            last_write = Instant::now();
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        drop_slot(&mut held);
                        return;
                    }
                }
            }
            }
        });
    }

    Ok(DevnetMesh { peers, inbound, live })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_inbound_reader_exit_reclaims_idle_writer_and_capacity() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let _client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (socket, _) = listener.accept().unwrap();
        let live = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let inbound_live = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let connection = Arc::new(InboundConnection {
            socket: socket.try_clone().unwrap(),
            closed: AtomicBool::new(false),
            _counts: (ConnCount::new(&live), ConnCount::new(&inbound_live)),
            _ip_slot: None,
        });
        let reader = InboundHalf(connection.clone());
        let writer = InboundHalf(connection.clone());
        let (frames, rx) = mpsc::sync_channel(INBOUND_QUEUE_DEPTH);
        let peer = InboundPeer { frames, connection: Arc::downgrade(&connection) };
        drop(connection);
        assert!(peer.is_open());
        assert_eq!(inbound_live.load(Ordering::Acquire), 1);
        // Keep the registry's sender alive and never broadcast: the exact
        // condition that previously stranded `for frame in rx` forever.
        let (done_tx, done_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            run_inbound_writer(rx, Arc::new(Mutex::new(socket)), writer);
            done_tx.send(()).unwrap();
        });
        drop(reader);
        done_rx.recv_timeout(Duration::from_secs(5)).expect("idle writer leaked after reader exit");
        worker.join().unwrap();
        assert!(!peer.is_open());
        assert_eq!(live.load(Ordering::Acquire), 0);
        assert_eq!(inbound_live.load(Ordering::Acquire), 0);
        assert!(matches!(peer.frames.try_send(vec![1]), Err(TrySendError::Disconnected(_))));
    }

    #[test]
    fn audit_inbound_writer_exit_interrupts_reader_without_releasing_early() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let _client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut socket, _) = listener.accept().unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let live = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let connection = Arc::new(InboundConnection {
            socket: socket.try_clone().unwrap(),
            closed: AtomicBool::new(false),
            _counts: (ConnCount::new(&live), ConnCount::new(&live)),
            _ip_slot: None,
        });
        let reader = InboundHalf(connection.clone());
        let writer = InboundHalf(connection);
        drop(writer);
        assert_eq!(live.load(Ordering::Acquire), 2, "reader still owns capacity");
        // Closing either half shuts down every clone of this socket.
        assert_eq!(socket.read(&mut [0; 1]).unwrap(), 0);
        drop(reader);
        assert_eq!(live.load(Ordering::Acquire), 0);
    }

    #[test]
    fn audit_devnet_frame_deadline_covers_prefix_and_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        client.write_all(&1000u32.to_le_bytes()).unwrap();
        let writer = thread::spawn(move || {
            for _ in 0..40 {
                thread::sleep(Duration::from_millis(20));
                if client.write_all(&[1]).is_err() { break; }
            }
            let _ = client.shutdown(Shutdown::Write);
        });
        let result = read_frame_until(&mut server, Instant::now() + Duration::from_millis(300));
        drop(server);
        writer.join().unwrap();
        let error = result.unwrap_err();
        // Linux reports SO_RCVTIMEO as WouldBlock; other platforms use TimedOut.
        assert!(matches!(error.kind(), std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock));
    }

    #[test]
    fn audit_devnet_complete_frame_survives_deadline_enforcement() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        let frame = get_blocks_frame(42);
        write_frame(&mut client, &frame).unwrap();
        assert_eq!(read_frame(&mut server).unwrap(), frame);
    }

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
    /// The wrap that once shed every frame forever is unreachable through the
    /// budget: releases saturate at zero instead of wrapping.
    #[test]
    fn a_release_without_a_reservation_saturates_instead_of_wrapping() {
        let b = QueueBudget::with_caps(4, 1 << 20);
        b.release(&NetEvent::Attestation(sample_attestation(), Origin::none()));
        assert_eq!(b.inflight(), 0);
        assert_eq!(b.inflight_bytes(), 0);
        assert!(
            b.try_reserve(&NetEvent::Attestation(sample_attestation(), Origin::none())),
            "the budget must still admit after a spurious release"
        );
    }

    #[test]
    fn send_to_engine_sheds_above_the_cap_and_delivers_below_it() {
        let (tx, rx) = mpsc::channel::<EngineEvent>();

        let budget = QueueBudget::with_caps(1, 1 << 20);
        assert!(send_to_engine(&tx, &budget, NetEvent::Attestation(sample_attestation(), Origin::none())));
        assert_eq!(budget.inflight(), 1);
        assert!(rx.try_recv().is_ok(), "an event below the cap must reach the engine");

        // At the count cap: shed, and the counters do not move.
        let bytes_before = budget.inflight_bytes();
        assert!(send_to_engine(&tx, &budget, NetEvent::Attestation(sample_attestation(), Origin::none())));
        assert_eq!(budget.inflight(), 1, "shedding must not count");
        assert_eq!(budget.inflight_bytes(), bytes_before, "shedding must not charge bytes");
        assert!(rx.try_recv().is_err(), "an event at the cap must be shed");
        assert_eq!(budget.shed(), (0, 1, 0));
    }

    /// O06 — the invariant `count <= cap` holds under contention. Eight
    /// threads race the reservation with nothing consuming; the old
    /// `load`-then-`fetch_add` could admit up to seven over the cap, the
    /// compare-and-swap cannot admit one.
    #[test]
    fn concurrent_reservations_never_exceed_the_count_cap() {
        let cap = 100usize;
        let budget = Arc::new(QueueBudget::with_caps(cap, usize::MAX));
        let admitted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let budget = budget.clone();
            let admitted = admitted.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..1_000 {
                    if budget.reserve_raw(EventClass::Attestation, 1) {
                        admitted.fetch_add(1, Ordering::Relaxed);
                    }
                    assert!(budget.inflight() <= cap, "count exceeded the cap");
                }
            }));
        }
        for h in handles {
            h.join().expect("racer");
        }
        assert_eq!(admitted.load(Ordering::Relaxed), cap, "exactly cap reservations succeed");
        assert_eq!(budget.inflight(), cap);
    }

    /// O06 — the per-class byte quotas: transactions stop at half the
    /// budget, attestations at three quarters, blocks may use all of it; a
    /// refusal on bytes hands the count back.
    #[test]
    fn byte_quotas_shed_transactions_first_and_blocks_last() {
        let bytes_cap = 1_000usize;
        let b = QueueBudget::with_caps(1_000, bytes_cap);
        // Transactions: admitted while total <= 500.
        assert!(b.reserve_raw(EventClass::Transaction, 400));
        assert!(b.reserve_raw(EventClass::Transaction, 100));
        assert!(!b.reserve_raw(EventClass::Transaction, 1), "transactions stop at half");
        assert_eq!(b.inflight(), 2, "the refused reservation returned its count");
        assert_eq!(b.inflight_bytes(), 500);
        // Attestations may still use up to 750.
        assert!(b.reserve_raw(EventClass::Attestation, 250));
        assert!(!b.reserve_raw(EventClass::Attestation, 1), "attestations stop at three quarters");
        // Blocks may use the whole budget, and not a byte more.
        assert!(b.reserve_raw(EventClass::Block, 250));
        assert!(!b.reserve_raw(EventClass::Block, 1), "blocks stop at the cap");
        assert_eq!(b.inflight_bytes(), bytes_cap);
        assert_eq!(b.inflight(), 4);
        // Releasing the same sizes restores both counters exactly.
        for size in [400, 100, 250, 250] {
            b.release_raw(size);
        }
        assert_eq!((b.inflight(), b.inflight_bytes()), (0, 0));
    }

    /// The size charged at reservation is the size released — the accounting
    /// is a pure function of the event value, so a full cycle is a no-op on
    /// both counters for every event class.
    #[test]
    fn reserve_then_release_is_a_no_op_for_every_class() {
        let b = QueueBudget::with_caps(8, 1 << 24);
        let att = NetEvent::Attestation(sample_attestation(), Origin::none());
        let size = queued_bytes(&att);
        assert!(size > 0);
        assert!(b.try_reserve(&att));
        assert_eq!((b.inflight(), b.inflight_bytes()), (1, size));
        b.release(&att);
        assert_eq!((b.inflight(), b.inflight_bytes()), (0, 0));
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

    // ── R3 M-4 / R1 A3-M2 ────────────────────────────────────────────────────

    /// [`GetBlocksLimiter`] bounds the burst and then the sustained rate,
    /// exactly like `p2p::SyncLimiter` does for the production transport.
    /// Before this fix `serve_get_blocks` had no rate limit of any kind: this
    /// test fails against that code because there was no `GetBlocksLimiter`
    /// to admit or refuse anything, and the equivalent unguarded call would
    /// have served every one of these requests.
    #[test]
    fn get_blocks_limiter_bounds_burst_then_refills() {
        let mut lim = GetBlocksLimiter::new();
        let start = Instant::now();
        let mut admitted = 0u32;
        for _ in 0..(GET_BLOCKS_BURST as u32 + 10) {
            if lim.admit(start) {
                admitted += 1;
            }
        }
        assert_eq!(
            admitted, GET_BLOCKS_BURST as u32,
            "burst must admit exactly GET_BLOCKS_BURST requests at one instant, not more"
        );
        assert!(!lim.admit(start), "past the burst, the same instant must be refused");

        // One second later, exactly GET_BLOCKS_ANSWERS_PER_SEC tokens refill.
        let later = start + Duration::from_secs(1);
        let mut refilled = 0u32;
        loop {
            if lim.admit(later) {
                refilled += 1;
            } else {
                break;
            }
        }
        assert_eq!(refilled as f64, GET_BLOCKS_ANSWERS_PER_SEC, "one second must buy exactly the sustained rate");
    }

    /// R3 M-4 / R1 A3-M2: `DevnetMesh::broadcast`'s outbound queue is bounded.
    /// Simulates a dialer whose connection loop is stalled (never draining
    /// its `Receiver`) by simply never calling `rx.recv()`: on the OLD
    /// unbounded `mpsc::channel()`, every one of these broadcasts would have
    /// been queued forever, one `Vec<u8>` allocation per call, for as long as
    /// the process ran. On the bounded channel, the queue fills at
    /// `OUTBOUND_QUEUE_DEPTH` and every broadcast past that is dropped.
    #[test]
    fn devnet_broadcast_outbound_queue_is_bounded() {
        let (tx, rx): (SyncSender<Vec<u8>>, Receiver<Vec<u8>>) =
            mpsc::sync_channel(OUTBOUND_QUEUE_DEPTH);
        let mesh = DevnetMesh {
            peers: vec![tx],
            inbound: Arc::new(Mutex::new(Vec::new())),
            live: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        };
        // Never drain `rx` — the stalled-dialer scenario — and broadcast well
        // past the bound.
        for i in 0..(OUTBOUND_QUEUE_DEPTH + 50) {
            mesh.broadcast(vec![i as u8]);
        }
        let queued = std::iter::from_fn(|| rx.try_recv().ok()).count();
        assert_eq!(
            queued, OUTBOUND_QUEUE_DEPTH,
            "the outbound queue must cap at OUTBOUND_QUEUE_DEPTH, not grow with every broadcast"
        );
    }

    /// R3 M-4 / R1 A3-M2: the devnet listener accepts at most
    /// `MAX_INBOUND_CONNECTIONS` at once, and a connection past the cap is
    /// closed by the server immediately rather than left half-open. This
    /// transport authenticates nothing, so the cap is the only backstop
    /// against a connection flood on a routable bind.
    #[test]
    fn inbound_connections_are_capped() {
        // Probe a free loopback port, then hand that exact port to `start` —
        // `net::start` takes a fixed port, not an ephemeral-port request it
        // reports back, so this is the standard std::net test pattern. The
        // TOCTOU window is a loopback address in this process's own test
        // run; nothing else in this environment is racing for it.
        let probe = TcpListener::bind(("127.0.0.1", 0)).expect("probe a free port");
        let port = probe.local_addr().expect("local_addr").port();
        drop(probe);

        let (events, _rx) = mpsc::channel::<EngineEvent>();
        let head_slot = Arc::new(AtomicU64::new(0));
        let inflight = QueueBudget::new();
        // Every connection here comes from loopback, so the per-address cap
        // (audit NET-03) would bind at 4 long before the global cap; it is
        // lifted for THIS test only, which is about the global one.
        let mesh = start_with_tuning(
            "127.0.0.1",
            port,
            Vec::new(),
            events,
            std::env::temp_dir(),
            head_slot,
            inflight,
            DevnetTuning { max_inbound_per_ip: usize::MAX, ..DevnetTuning::PRODUCTION },
        )
        .expect("bind the devnet transport");

        // Open more connections than the cap allows and HOLD them open — a
        // dropped `TcpStream` closes the socket, which would silently undo
        // the very thing this test checks.
        let total = MAX_INBOUND_CONNECTIONS + 8;
        let mut conns = Vec::with_capacity(total);
        for _ in 0..total {
            conns.push(TcpStream::connect(("127.0.0.1", port)).expect("connect"));
        }

        // The accept loop runs on its own thread; poll rather than sleep a
        // fixed amount, so this is fast on an idle box and still correct on
        // a loaded one.
        let deadline = Instant::now() + Duration::from_secs(5);
        while mesh.peer_count() < MAX_INBOUND_CONNECTIONS && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(20));
        }
        // One quiet moment so the count has settled — proving it never rises
        // past the cap needs a window, not just a poll exit condition.
        thread::sleep(Duration::from_millis(200));

        assert_eq!(
            mesh.peer_count(),
            MAX_INBOUND_CONNECTIONS,
            "the transport must accept no more than MAX_INBOUND_CONNECTIONS inbound connections"
        );

        // And the excess connections were actually refused, not merely
        // uncounted: the server must have closed them.
        let over_cap = conns.split_off(MAX_INBOUND_CONNECTIONS);
        for mut sock in over_cap {
            sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut buf = [0u8; 1];
            match sock.read(&mut buf) {
                Ok(0) => {} // EOF: the server closed it, as expected
                Ok(n) => panic!("{n} unexpected bytes from a connection past the cap"),
                Err(e) => panic!("a connection past the cap was not closed by the server: {e}"),
            }
        }
        // The connections WITHIN the cap must still be open: draining
        // `conns` here (not `over_cap`, already consumed above) merely drops
        // them at end of scope, which is a normal client-side close and
        // proves nothing was already closed from the server's side.
        drop(conns);
    }

    // ── deep audit 2026-09-16: NET-03, NET-05, NET-09, NET-17 ───────────────

    /// A free loopback port for `start_with_tuning`, which takes a fixed
    /// port (see `inbound_connections_are_capped` for why this is the
    /// standard pattern here).
    fn free_port() -> u16 {
        let probe = TcpListener::bind(("127.0.0.1", 0)).expect("probe a free port");
        let port = probe.local_addr().expect("local_addr").port();
        drop(probe);
        port
    }

    /// Poll `cond` for up to five seconds: fast on an idle box, still
    /// correct on a loaded one.
    fn wait_for(what: &str, cond: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !cond() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            thread::sleep(Duration::from_millis(20));
        }
    }

    /// Accept one connection or fail, rather than block a test forever on a
    /// dialer that never comes.
    fn accept_within(listener: &TcpListener, what: &str) -> TcpStream {
        listener.set_nonblocking(true).expect("nonblocking accept");
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match listener.accept() {
                Ok((sock, _)) => {
                    listener.set_nonblocking(false).expect("blocking accept");
                    sock.set_nonblocking(false).expect("blocking socket");
                    return sock;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "no connection arrived: {what}");
                    thread::sleep(Duration::from_millis(20));
                }
                Err(e) => panic!("accept failed ({what}): {e}"),
            }
        }
    }

    /// The server closed this socket: a read sees EOF, not a timeout.
    fn expect_closed_by_server(sock: &mut TcpStream, what: &str) {
        sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut buf = [0u8; 1];
        match sock.read(&mut buf) {
            Ok(0) => {}
            Ok(n) => panic!("{n} unexpected bytes on a connection the server should have closed ({what})"),
            Err(e) => panic!("the server did not close the connection ({what}): {e}"),
        }
    }

    /// The server is holding this socket open: a short read times out
    /// rather than seeing EOF.
    fn expect_open(sock: &mut TcpStream, what: &str) {
        sock.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
        let mut buf = [0u8; 1];
        match sock.read(&mut buf) {
            Ok(0) => panic!("the server closed a connection it should have kept ({what})"),
            Ok(n) => panic!("{n} unexpected bytes ({what})"),
            Err(e) => assert!(
                matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut),
                "unexpected read error ({what}): {e}"
            ),
        }
    }

    /// audit NET-03 (2026-09-16): one source address holds at most
    /// `max_inbound_per_ip` inbound connections at once. The next one from
    /// that address is closed at accept, exactly like a connection past the
    /// global cap, and the slot comes back the moment one of its
    /// connections ends — so this bounds a host, not a peer for good.
    /// Against the old code every connection below is accepted, since the
    /// only admission decision was the per-process count.
    #[test]
    fn inbound_connections_are_capped_per_source_address() {
        let port = free_port();
        let (events, _rx) = mpsc::channel::<EngineEvent>();
        let mesh = start_with_tuning(
            "127.0.0.1",
            port,
            Vec::new(),
            events,
            std::env::temp_dir(),
            Arc::new(AtomicU64::new(0)),
            QueueBudget::new(),
            DevnetTuning { max_inbound_per_ip: 2, ..DevnetTuning::PRODUCTION },
        )
        .expect("bind the devnet transport");

        let first = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        let mut second = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        wait_for("two connections from loopback", || mesh.peer_count() >= 2);
        thread::sleep(Duration::from_millis(200));
        assert_eq!(mesh.peer_count(), 2);

        // The third from the same address: closed at accept, never counted.
        let mut third = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        expect_closed_by_server(&mut third, "a third connection from one address");
        assert_eq!(mesh.peer_count(), 2, "a refused connection must not be counted");
        expect_open(&mut second, "a connection within the per-address cap");

        // Ending one connection hands the slot back.
        drop(first);
        wait_for("the closed connection's slot to be released", || mesh.peer_count() < 2);
        let mut fourth = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        wait_for("the fourth connection to be accepted", || mesh.peer_count() >= 2);
        expect_open(&mut fourth, "a connection after a slot was released");
        drop(second);
        drop(fourth);
    }

    /// audit NET-03 (2026-09-16): a frame of an unknown type renews nothing.
    /// A peer that sends only such frames — 5 bytes per ~100 s was enough to
    /// hold a slot forever — is closed when a silent peer would be, while a
    /// peer sending decodable frames at the same cadence stays connected.
    /// The `get-blocks` frame is the decodable one here: the empty
    /// per-address table refuses it before the disk is touched, and it still
    /// counts, because `serve_get_blocks` could have used it.
    #[test]
    fn frames_that_decode_to_nothing_do_not_renew_the_inbound_deadline() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let idle = Duration::from_millis(400);
        let by_ip = InboundByIp::new(MAX_INBOUND_PER_IP);
        let (events, _rx) = mpsc::channel::<EngineEvent>();
        let inflight = QueueBudget::new();
        let spawn_reader = |server: TcpStream| {
            let rsock = server.try_clone().expect("clone");
            let wsock = Arc::new(Mutex::new(server));
            let events = events.clone();
            let inflight = inflight.clone();
            let by_ip = by_ip.clone();
            thread::spawn(move || {
                let started = Instant::now();
                run_inbound_reader(
                    rsock,
                    wsock,
                    std::env::temp_dir(),
                    events,
                    inflight,
                    by_ip,
                    addr.ip(),
                    idle,
                );
                started.elapsed()
            })
        };

        // Junk every 100 ms, well inside the deadline, for up to 2 s.
        let mut junk = TcpStream::connect(addr).expect("connect");
        let reader = spawn_reader(listener.accept().expect("accept").0);
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(2) && write_frame(&mut junk, &[0xFF]).is_ok() {
            thread::sleep(Duration::from_millis(100));
        }
        let alive = reader.join().expect("reader thread");
        assert!(alive >= idle, "closed before the deadline: {alive:?}");
        assert!(
            alive < Duration::from_millis(1500),
            "undecodable frames kept the connection alive for {alive:?}; the deadline must \
             be anchored at the last DECODABLE frame"
        );

        // Control: decodable frames at the same cadence keep it open past
        // three deadlines.
        let mut good = TcpStream::connect(addr).expect("connect");
        let reader = spawn_reader(listener.accept().expect("accept").0);
        for _ in 0..13 {
            write_frame(&mut good, &get_blocks_frame(0)).expect("write a decodable frame");
            thread::sleep(Duration::from_millis(100));
        }
        assert!(!reader.is_finished(), "decodable frames must renew the deadline");
        drop(good);
        let _ = reader.join();
    }

    /// audit NET-05 (2026-09-16): the `get-blocks` bucket is per source
    /// address — every connection from one host draws on one burst — and
    /// it outlives the connections, so closing and re-dialing does not hand
    /// out a fresh burst. Refill is still the sustained rate, another
    /// address is unaffected, and an address nobody admitted has no bucket.
    /// Against the old per-connection limiter the two connections below
    /// would have been admitted `2 × GET_BLOCKS_BURST` requests, and the
    /// reconnect another `GET_BLOCKS_BURST`.
    #[test]
    fn get_blocks_budget_is_per_source_address_and_survives_reconnect() {
        let table = InboundByIp::new(4);
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        let t0 = Instant::now();
        assert!(!table.admit_get_blocks(a, t0), "an address never admitted has no budget");

        let slot1 = table.try_admit(a, t0).expect("first slot");
        let slot2 = table.try_admit(a, t0).expect("second slot");
        let admitted = (0..(GET_BLOCKS_BURST as usize * 2))
            .filter(|_| table.admit_get_blocks(a, t0))
            .count();
        assert_eq!(admitted, GET_BLOCKS_BURST as usize, "two connections, one burst");

        let slot_b = table.try_admit(b, t0).expect("another address");
        assert!(table.admit_get_blocks(b, t0), "another address has its own budget");

        drop(slot1);
        drop(slot2);
        let slot3 = table.try_admit(a, t0).expect("re-admitted after closing");
        assert!(!table.admit_get_blocks(a, t0), "a reconnect must not refill the bucket");

        let t1 = t0 + Duration::from_secs(1);
        let refilled = std::iter::from_fn(|| table.admit_get_blocks(a, t1).then_some(()))
            .count();
        assert_eq!(refilled as f64, GET_BLOCKS_ANSWERS_PER_SEC, "one second buys the sustained rate");

        // With no connection and a full bucket, the entry is pruned on the
        // next accept; `b`, still connected, is not.
        drop(slot3);
        let t2 = t1 + Duration::from_secs(60);
        let _slot_b2 = table.try_admit(b, t2).expect("b again");
        let by_ip = table.by_ip.lock().unwrap();
        assert!(!by_ip.contains_key(&a), "a full bucket with no connection must not be retained");
        assert!(by_ip.contains_key(&b));
        drop(by_ip);
        drop(slot_b);
    }

    /// audit NET-17 / NET-05 (2026-09-16): a `get-blocks` page is capped in
    /// bytes as well as blocks, with the libp2p transport's arithmetic —
    /// each block charged its length plus the 4-byte frame prefix, the page
    /// ending at the first block that would take it past `MAX_SYNC_FRAME −
    /// 1 KiB`. Against the old code every block `Store::blocks_after`
    /// returned was written, up to 512 × 8 MiB.
    #[test]
    fn a_get_blocks_page_is_capped_in_bytes_as_well_as_blocks() {
        assert_eq!(SYNC_PAGE_BYTES, crate::p2p::MAX_SYNC_FRAME as usize - 1024);
        // Two of these are exactly the cap once each carries its prefix.
        let half = vec![0u8; SYNC_PAGE_BYTES / 2 - 4];
        let page: Vec<Vec<u8>> =
            page_within_bytes(vec![half.clone(), half.clone(), vec![1], vec![2]]).collect();
        assert_eq!(page.len(), 2, "the page stops at the byte cap, before the block cap");
        assert_eq!(page[0].len(), half.len());
        // Past the cap nothing more is served, however small.
        let over = vec![vec![0u8; SYNC_PAGE_BYTES - 4], vec![0u8; 1]];
        assert_eq!(page_within_bytes(over).count(), 1);
        // A page of small blocks is bounded by the block count alone.
        let small: Vec<Vec<u8>> = (0..SYNC_PAGE_BLOCKS).map(|i| vec![i as u8; 100]).collect();
        assert_eq!(page_within_bytes(small).count(), SYNC_PAGE_BLOCKS);
        // Log order is preserved.
        let ordered: Vec<Vec<u8>> = page_within_bytes(vec![vec![1], vec![2], vec![3]]).collect();
        assert_eq!(ordered, vec![vec![1], vec![2], vec![3]]);
    }

    /// One dialer against a listener the test owns: the mesh dials
    /// `listener`, and whatever it writes is read back here.
    fn dial_from_mesh(tuning: DevnetTuning) -> (TcpListener, DevnetMesh, Receiver<EngineEvent>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind the peer");
        let peer = listener.local_addr().expect("local_addr").to_string();
        let (events, rx) = mpsc::channel::<EngineEvent>();
        let mesh = start_with_tuning(
            "127.0.0.1",
            free_port(),
            vec![peer],
            events,
            std::env::temp_dir(),
            Arc::new(AtomicU64::new(0)),
            QueueBudget::new(),
            tuning,
        )
        .expect("start the dialer");
        (listener, mesh, rx)
    }

    /// Read frames off `sock` until `wanted` arrives; everything before it
    /// must be the dialer's own `get-blocks` (it holds the only sync slot).
    fn expect_frame_then(sock: &mut TcpStream, wanted: &[u8], what: &str) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let frame = read_frame_until(sock, deadline)
                .unwrap_or_else(|e| panic!("the frame never arrived ({what}): {e}"));
            if frame == wanted {
                return;
            }
            assert_eq!(frame.first(), Some(&FRAME_GET_BLOCKS), "unexpected frame ({what}): {frame:?}");
        }
    }

    /// audit NET-09 (2026-09-16): when the peer closes a dialed socket — as
    /// the accepting side does after `DEVNET_IO_TIMEOUT` idle — the dialer
    /// notices through its reader thread, re-dials, and the first broadcast
    /// after the close arrives on the new socket. Against the old code that
    /// broadcast was written into the dead socket (the first write after a
    /// peer's close succeeds locally) and lost; the reconnect came one frame
    /// too late.
    #[test]
    fn a_dialer_whose_peer_closed_the_socket_reconnects_and_loses_no_frame() {
        let (listener, mesh, _rx) = dial_from_mesh(DevnetTuning::PRODUCTION);
        let mut first = accept_within(&listener, "the initial dial");
        let deadline = Instant::now() + Duration::from_secs(5);
        assert_eq!(read_frame_until(&mut first, deadline).expect("sync ask"), get_blocks_frame(0));

        // The peer closes it. Give the dialer's reader a moment to see the
        // FIN — on loopback that is microseconds; this is generous.
        drop(first);
        thread::sleep(Duration::from_millis(500));

        // ONE broadcast, and it must come out of the new socket.
        let frame = att_frame(&sample_attestation());
        mesh.broadcast(frame.clone());
        let mut second = accept_within(&listener, "the re-dial after the peer's close");
        expect_frame_then(&mut second, &frame, "the broadcast after an idle close");
    }

    /// audit NET-09 (2026-09-16): a socket this node has not written to for
    /// `dial_stale_after` is not written to again — the peer's idle close is
    /// due, and racing it loses the frame — so the next broadcast goes out
    /// on a fresh socket, and the stale socket sees nothing further. With
    /// the production value this takes 105 s; the deadline is a tunable so
    /// it takes 300 ms here.
    #[test]
    fn a_dialer_does_not_write_into_a_socket_the_peer_is_about_to_close() {
        let (listener, mesh, _rx) = dial_from_mesh(DevnetTuning {
            dial_stale_after: Duration::from_millis(300),
            ..DevnetTuning::PRODUCTION
        });
        let mut first = accept_within(&listener, "the initial dial");
        let deadline = Instant::now() + Duration::from_secs(5);
        assert_eq!(read_frame_until(&mut first, deadline).expect("sync ask"), get_blocks_frame(0));

        // The peer keeps the socket open and silent; this node writes
        // nothing for longer than the stale deadline (the next sync ask is
        // 5 s away).
        thread::sleep(Duration::from_millis(600));
        let frame = att_frame(&sample_attestation());
        mesh.broadcast(frame.clone());

        let mut second = accept_within(&listener, "the re-dial for a stale socket");
        expect_frame_then(&mut second, &frame, "the broadcast on the fresh socket");
        // Nothing but EOF on the socket the dialer abandoned: the frame was
        // not written there first.
        match read_frame_until(&mut first, Instant::now() + Duration::from_millis(300)) {
            Ok(f) => panic!("a frame was written into the stale socket: {f:?}"),
            Err(_) => {}
        }
    }

    /// The stale deadline must sit under the peer's idle deadline, or it
    /// guards nothing.
    #[test]
    fn the_dial_stale_deadline_is_under_the_inbound_idle_deadline() {
        assert!(DIAL_STALE_AFTER < DEVNET_IO_TIMEOUT);
        assert!(DEVNET_IO_TIMEOUT - DIAL_STALE_AFTER >= Duration::from_secs(10));
    }
}
