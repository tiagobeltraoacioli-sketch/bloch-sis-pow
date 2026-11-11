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
//! **`--mesh-security` (see `mesh_pq.rs`).** With `offer` or `require` a
//! connection first runs a hybrid ML-KEM-768 + X25519 handshake in which
//! each side proves possession of an ML-DSA-65 transport identity, and every
//! frame below then travels as a ChaCha20-Poly1305 record instead of in the
//! clear. That is encryption; it is authentication only when the node was
//! told which identities to expect (`--mesh-allow`, or a pin on the dialed
//! address, `--peers host:port=<identity>`). The default, `plain`, is this
//! paragraph's absence: the wire is byte-for-byte what it was.
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

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
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
mod inbound_slots;
mod source_budget;
pub(crate) mod rejection_log;
pub(crate) use source_budget::Reservation as SourceReservation;
pub(crate) use source_budget::verification_source_for_ip;

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

/// One locally-produced block announcement, encoded together with the exact
/// identity derived from the same borrowed envelope. Fields stay private so
/// the libp2p suppression hint cannot be paired with unrelated wire bytes.
pub(crate) struct PreparedBlockBroadcast {
    payload: Vec<u8>,
    id: [u8; 32],
}

impl PreparedBlockBroadcast {
    fn new(env: &BlockEnvelope) -> Self {
        Self {
            payload: crate::codec::encode_envelope(env),
            id: *env.block_id().as_bytes(),
        }
    }

    fn devnet_frame(&self) -> Vec<u8> {
        let mut frame = Vec::with_capacity(1usize.saturating_add(self.payload.len()));
        frame.push(FRAME_BLOCK);
        frame.extend_from_slice(&self.payload);
        frame
    }

    #[cfg(test)]
    fn payload(&self) -> &[u8] { &self.payload }
    pub(crate) fn id(&self) -> [u8; 32] { self.id }
    pub(crate) fn into_payload(self) -> Vec<u8> { self.payload }
}

/// One canonical transaction payload prepared for transport-specific
/// ownership. Construction copies from the engine's canonical mempool key
/// into a buffer with at least one spare byte, so devnet can prepend its frame
/// tag in place while libp2p can take the untagged payload without a recopy.
pub(crate) struct PreparedTransactionBroadcast {
    payload: Vec<u8>,
}

impl PreparedTransactionBroadcast {
    pub(crate) fn new(canonical: &[u8]) -> Self {
        let mut payload = Vec::with_capacity(canonical.len().saturating_add(1));
        payload.extend_from_slice(canonical);
        Self { payload }
    }

    fn devnet_frame(&self) -> Vec<u8> {
        let mut frame = Vec::with_capacity(self.payload.len().saturating_add(1));
        frame.push(FRAME_TX);
        frame.extend_from_slice(&self.payload);
        frame
    }

    fn into_devnet_frame(mut self) -> Vec<u8> {
        self.payload.insert(0, FRAME_TX);
        self.payload
    }

    #[cfg(test)]
    pub(crate) fn payload(&self) -> &[u8] { &self.payload }
    pub(crate) fn into_payload(self) -> Vec<u8> { self.payload }
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
    /// Publish a locally-produced block without cloning its retained envelope
    /// or making libp2p decode the just-encoded body solely for suppression.
    /// The private prepared value binds the canonical payload and id to one
    /// envelope and lets libp2p take ownership without recopying that payload.
    pub(crate) fn broadcast_block(&self, env: &BlockEnvelope) {
        match self {
            Net::Devnet(m) => m.broadcast(block_frame(env)),
            Net::Libp2p(h) => h.broadcast_block(PreparedBlockBroadcast::new(env)),
            Net::Both(m, h) => {
                let prepared = PreparedBlockBroadcast::new(env);
                m.broadcast(prepared.devnet_frame());
                h.broadcast_block(prepared);
            }
        }
    }

    /// Publish one already-admitted canonical transaction without making the
    /// libp2p command loop copy the complete payload away from a routing tag.
    pub(crate) fn broadcast_transaction(&self, prepared: PreparedTransactionBroadcast) {
        match self {
            Net::Devnet(m) => m.broadcast(prepared.into_devnet_frame()),
            Net::Libp2p(h) => h.broadcast_transaction(prepared),
            Net::Both(m, h) => {
                m.broadcast(prepared.devnet_frame());
                h.broadcast_transaction(prepared);
            }
        }
    }

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
                // another generic raw-frame caller) and each
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

/// Concurrent request leases shared by engine and periodic synchronization.
/// This bounds request issuance, not outstanding responses: the legacy wire
/// has no page-completion marker, and late blocks remain subject to QueueBudget.
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
/// One request per lease; expiration permits another connection's turn even
/// when peers stay silent or the applied head has not moved.
const SYNC_LEASE: Duration = Duration::from_secs(5);
/// Each worker is one thread and one page in memory (at most
/// `codec::MAX_FIELD_LEN` of block bytes), so this is also the memory bound
/// of sync serving: 64 MiB at the very worst.
const MAX_SYNC_SERVING_WORKERS: usize = 8;
/// Workers only the operator's own `--peers` may use. However the rest of
/// the pool is occupied, a configured peer that restarts can still catch up
/// from this node.
const SYNC_SERVING_RESERVED_FOR_CONFIGURED: usize = 2;
/// Serving workers one normalized source address may hold at once. A worker
/// is held for as long as its page takes to write, so without this a single
/// address with a few connections could hold every worker and leave honest
/// peers with silence. Two, not one, so nodes that legitimately share an
/// address (one host, one NAT) do not serialize behind each other. It is a
/// quarter of the pool (a third of what unconfigured sources may use), so no
/// two sources can take every worker.
const MAX_SYNC_SERVING_PER_SOURCE: usize = 2;
/// The share of a source that has not recently been written a whole page
/// (see [`SYNC_SOURCE_PROVEN_FOR`]). An address this node knows nothing about
/// gets one worker; nodes sharing that address are served one after the
/// other until the first page completes, which a reading peer does in
/// seconds, and side by side from then on.
const MAX_SYNC_SERVING_PER_UNPROVEN_SOURCE: usize = 1;
/// How long a completed page vouches for its source.
const SYNC_SOURCE_PROVEN_FOR: Duration = Duration::from_secs(600);
/// A page of at least this many bytes, written in full, is what proves a
/// source reads what it asks for. An empty or tiny page fits in any socket
/// buffer whether or not the peer reads.
const SYNC_PROVING_PAGE_BYTES: usize = 256 * 1024;
/// After a page to a source is cut off for falling below the minimum rate,
/// that source is not served again for this long. Without it a source that
/// never reads gets a new worker the moment the old one is taken away. A
/// peer that honestly cannot read 32 KiB/s loses nothing it could have used.
const SYNC_STALL_COOLDOWN: Duration = Duration::from_secs(60);
/// Sources remembered in each of the two maps above; idle records expire.
const MAX_SYNC_SOURCE_RECORDS: usize = 1024;
/// Slowest sustained read rate at which a peer is still served a whole page:
/// 32 KiB/s (256 kbit/s). A node that cannot receive this fast cannot follow
/// the chain either, since one maximal block body alone is 512 KiB.
const SYNC_PAGE_MIN_BYTES_PER_SEC: u64 = 32 * 1024;
/// Fixed allowance on top of the throughput budget, covering connection
/// latency, frame overhead and broadcasts interleaved on the same socket.
const SYNC_PAGE_WRITE_GRACE: Duration = Duration::from_secs(15);
/// The same allowance for a source that is not proven. Five seconds still
/// covers a slow connection's latency many times over; it is what a peer
/// that reads nothing at all can hold a worker for, beyond the bytes the
/// socket buffer swallows.
const SYNC_PAGE_WRITE_GRACE_UNPROVEN: Duration = Duration::from_secs(5);

/// Whole-page deadline for one `get-blocks` answer of `page_bytes` bytes.
///
/// [`DEVNET_IO_TIMEOUT`] bounds a single stalled write and is renewed by any
/// progress, so a peer reading a few bytes per minute could hold a serving
/// worker indefinitely. This budget is total: `SYNC_PAGE_WRITE_GRACE` plus
/// the time the page takes at `SYNC_PAGE_MIN_BYTES_PER_SEC`. A maximal page
/// (`codec::MAX_FIELD_LEN`, 8 MiB) therefore gets 15 s + 256 s = 271 s, and a
/// peer reading at 32 KiB/s or faster can never reach the deadline.
fn sync_page_deadline(start: Instant, page_bytes: usize) -> Instant {
    PagePace { start, grace: SYNC_PAGE_WRITE_GRACE, bytes_per_sec: SYNC_PAGE_MIN_BYTES_PER_SEC }.deadline(page_bytes)
}

/// The deadline of every block of one page, not only of its last.
///
/// One deadline for the whole page lets a peer that reads nothing hold the
/// worker for the full budget of a page it will never receive. The budget is
/// therefore spent block by block: block `k` must be written by the time the
/// bytes up to and including it take at the minimum rate, plus the grace. A
/// peer that reads at the minimum rate or faster meets every one of these, by
/// the same arithmetic as the whole-page deadline, which is the last of them.
#[derive(Clone, Copy)]
struct PagePace {
    start: Instant,
    grace: Duration,
    bytes_per_sec: u64,
}

impl PagePace {
    fn starting_now(proven: bool) -> Self {
        let grace = if proven { SYNC_PAGE_WRITE_GRACE } else { SYNC_PAGE_WRITE_GRACE_UNPROVEN };
        Self { start: Instant::now(), grace, bytes_per_sec: SYNC_PAGE_MIN_BYTES_PER_SEC }
    }

    /// When the first `bytes` bytes of the page must have been written.
    fn deadline(&self, bytes: usize) -> Instant {
        let millis = (bytes as u128).saturating_mul(1000).div_ceil(u128::from(self.bytes_per_sec.max(1)));
        self.start + self.grace + Duration::from_millis(u64::try_from(millis).unwrap_or(u64::MAX))
    }
}

/// How one page ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PageOutcome {
    /// Every block was written; the count of block bytes.
    Written(usize),
    /// Cut off at a deadline: the peer was not reading fast enough.
    Stalled,
    /// The connection ended for another reason.
    Closed,
}

/// The address form used for per-source accounting: an IPv4-mapped IPv6
/// address counts as its IPv4 address, as in `connection_limit`.
/// The per-source key for sync serving: the same rule as every other
/// per-source limit (IPv4 by address, IPv6 by /64, IPv4-mapped as IPv4), so
/// one IPv6 prefix cannot occupy every serving worker.
fn normalize_source(ip: std::net::IpAddr) -> std::net::IpAddr {
    crate::connection_limit::limit_key(ip)
}

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
/// A pure canonical-size function used at source-free admission and to prove
/// decoded transport bytes are canonical. Transport reservations retain that
/// proved size for later engine-queue reserve/release, avoiding repeated
/// serialization of the same immutable payload.
pub fn queued_bytes(ev: &NetEvent) -> usize {
    match ev {
        // The shared canonical-length authority avoids allocating and copying
        // the complete block body merely to charge its immutable queue entry.
        NetEvent::Block(env, _) => crate::codec::encoded_envelope_len(env),
        // As for blocks, sizing shares the codec's exact length authority and
        // never needs a second owner of the signature bytes.
        NetEvent::Attestation(att, _) => crate::codec::encoded_attestation_len(att),
        NetEvent::Transaction(tx, _) => tx.canonical_bytes().len(),
    }
}

/// Bytes charged to the engine-facing queue. Transport-originated events
/// carry the exact validated wire charge in their private reservation;
/// source-free/local events still compute their canonical size here.
pub(crate) fn charged_bytes(ev: &NetEvent) -> usize {
    let retained = match ev {
        NetEvent::Block(_, origin)
        | NetEvent::Attestation(_, origin)
        | NetEvent::Transaction(_, origin) => origin.reserved_bytes(),
    };
    retained.unwrap_or_else(|| queued_bytes(ev))
}

/// Per-class share of [`ENGINE_QUEUE_BYTES_CAP`] a class may fill.
///
/// The overload policy the audit asked for, stated as three numbers: blocks
/// may use the WHOLE budget (they are what sync progress and control traffic
/// consist of, and a node that sheds blocks while queuing transactions has its
/// priorities inverted); attestations up to three quarters; transactions up to
/// half. So under memory pressure transactions are shed first, attestations
/// second, blocks last. The same shares reserve event-count headroom, so
/// many tiny lower-priority messages cannot consume the block allowance.
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

/// Count thresholds use the byte policy's shares, retaining one usable slot
/// for nonzero tiny test budgets. A zero budget never admits an event.
fn class_count_cap(class: EventClass, count_cap: usize) -> usize {
    class_bytes_cap(class, count_cap).max(usize::from(count_cap != 0))
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
    sources: Arc<Mutex<source_budget::Registry>>,
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
            sources: Arc::new(Mutex::new(source_budget::Registry::default())),
            count: std::sync::atomic::AtomicUsize::new(0),
            bytes: std::sync::atomic::AtomicUsize::new(0),
            count_cap,
            bytes_cap,
            shed_blocks: AtomicU64::new(0),
            shed_attestations: AtomicU64::new(0),
            shed_transactions: AtomicU64::new(0),
        }
    }

    /// Reserve before either transport's first engine-facing channel. The
    /// Origin guard survives forwarding and handling, including error paths.
    fn admit_source(&self, ev: &mut NetEvent, source: source_budget::Source) -> bool {
        let class = class_of(ev);
        let Some(guard) = self.reserve_source_frame(source, class, queued_bytes(ev)) else {
            return false;
        };
        match ev {
            NetEvent::Block(_, origin) | NetEvent::Attestation(_, origin)
                | NetEvent::Transaction(_, origin) => origin.set_reservation(guard),
        }
        true
    }

    pub(crate) fn admit_peer(&self, ev: &mut NetEvent, peer: Vec<u8>) -> bool {
        self.admit_source(ev, source_budget::Source::Peer(peer))
    }

    /// Reserve a libp2p peer's bounded first-hop allowance before parsing its
    /// gossip payload. `size` is the already-bounded gossipsub frame length;
    /// callers must verify that a successfully decoded canonical value has the
    /// same class and encoded size before attaching the returned guard.
    pub(crate) fn reserve_peer_frame(
        &self,
        class: EventClass,
        size: usize,
        peer: Vec<u8>,
    ) -> Option<Arc<SourceReservation>> {
        self.reserve_source_frame(source_budget::Source::Peer(peer), class, size)
    }

    fn reserve_source_frame(
        &self,
        source: source_budget::Source,
        class: EventClass,
        size: usize,
    ) -> Option<Arc<SourceReservation>> {
        let guard = source_budget::Registry::reserve(
            &self.sources,
            source,
            class,
            size,
            self.count_cap,
            self.bytes_cap,
        );
        if guard.is_none() {
            self.shed_counter(class).fetch_add(1, Ordering::Relaxed);
        }
        guard
    }

    /// Reserve room for `ev`, or record a shed and return `false`.
    ///
    /// Count first (cheap, and the invariant everything else already relies
    /// on), then bytes under the class cap; the count is handed back if the
    /// bytes are refused. Both steps are compare-and-swap loops, so the
    /// invariants hold under any interleaving of any number of callers.
    pub fn try_reserve(&self, ev: &NetEvent) -> bool {
        let class = class_of(ev);
        let size = charged_bytes(ev);
        let admitted = self.reserve_raw(class, size);
        if !admitted {
            self.shed_counter(class).fetch_add(1, Ordering::Relaxed);
        }
        admitted
    }

    fn reserve_raw(&self, class: EventClass, size: usize) -> bool {
        let count_cap = class_count_cap(class, self.count_cap);
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

    /// Release the reservation made for `ev` using the same retained charge
    /// as admission. Source-free work falls back to its canonical size.
    pub fn release(&self, ev: &NetEvent) {
        self.release_raw(charged_bytes(ev));
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
/// forever. This ceiling leaves generous headroom over the default configured
/// peer count for inbound connections from peers that dialed first; past it a
/// new connection is closed immediately, before either thread is spawned.
const MAX_INBOUND_CONNECTIONS: usize = 128;
/// Inbound connections one source may hold: an IPv4 address or an IPv6 /64
/// (see [`crate::connection_limit::limit_key`]).
///
/// One eighth of [`MAX_INBOUND_CONNECTIONS`]. This was 32 and keyed by full
/// address, so four IPv4 hosts, or a single IPv6 /64, could hold every slot.
/// At 16 a host can still run sixteen dial-in nodes behind one address, and
/// filling the table takes eight sources that each keep sixteen connections
/// delivering valid frames (see [`INBOUND_IDLE_EVICTION`]). Sources listed in
/// `--peers` are exempt, so a fleet that puts more nodes than this on one
/// host is unaffected as long as its nodes list each other.
const MAX_INBOUND_PER_SOURCE: usize = 16;
/// Inbound connections that have neither completed an authenticated
/// handshake nor delivered a valid frame. They are counted inside
/// [`MAX_INBOUND_CONNECTIONS`] but capped here, so connections that have
/// proven nothing can never hold more than a quarter of the table.
const MAX_PENDING_INBOUND: usize = 32;
/// Share of [`MAX_PENDING_INBOUND`] one source may hold.
const MAX_PENDING_INBOUND_PER_SOURCE: usize = 4;
/// How long an inbound connection may stay pending before it is closed.
///
/// Covers the whole of [`crate::mesh_pq::HANDSHAKE_TIMEOUT`] plus the wait
/// for a first frame. One slot: a dialer that has nothing to say for longer
/// than that is closed and simply dials again.
const PENDING_INBOUND_DEADLINE: Duration = Duration::from_secs(30);
/// Minimum age before a connection that has not yet been useful can be
/// displaced by an unconfigured newcomer. Without it a fast enough flood
/// would evict every honest dialer before its handshake finished.
const INBOUND_EVICTION_GRACE: Duration = Duration::from_secs(5);
/// A useful inbound connection that has delivered no valid frame for this
/// long may be evicted when the table is full and a new connection arrives.
const INBOUND_IDLE_EVICTION: Duration = Duration::from_secs(30);
/// Hard ceiling on inbound connections whose worker threads are still
/// alive. An evicted connection leaves the slot table at once but its two
/// threads take a moment to notice; this bounds how far the real resource
/// count can run ahead of the table under eviction churn.
const MAX_INBOUND_LIVE: usize = MAX_INBOUND_CONNECTIONS * 2;

/// Sources remembered as operator-configured (see `start`).
const MAX_CONFIGURED_SOURCES: usize = 1024;

const INBOUND_POLICY: inbound_slots::Policy = inbound_slots::Policy {
    total: MAX_INBOUND_CONNECTIONS,
    pending: MAX_PENDING_INBOUND,
    per_source: MAX_INBOUND_PER_SOURCE,
    pending_per_source: MAX_PENDING_INBOUND_PER_SOURCE,
    pending_deadline: PENDING_INBOUND_DEADLINE,
    eviction_grace: INBOUND_EVICTION_GRACE,
    idle_eviction: INBOUND_IDLE_EVICTION,
    // Same horizon as the socket timeout, but measured in valid frames: a
    // frame of unknown type resets the socket timer and must not reset this.
    idle_close: DEVNET_IO_TIMEOUT,
};

type InboundSlots = Arc<Mutex<inbound_slots::Slots<TcpStream>>>;
type InboundSlot = inbound_slots::Slot<TcpStream>;

/// Socket read/write timeout for the devnet mesh (R3 M-4 / R1 A3-M2). This
/// transport had none: a peer that stopped reading its socket could stall
/// `write_frame` forever once the kernel send buffer filled (one thread
/// leaked, permanently, per such peer), and a peer that never wrote anything
/// held its reader thread — and its slot under [`MAX_INBOUND_CONNECTIONS`] —
/// open forever.
///
/// An honest peer's connection is never idle anywhere near this long: the
/// dialer side below re-asks for history at least every 5 seconds while it
/// holds a sync slot, and on a live chain a block or attestation broadcast
/// arrives far more often than that. This is a generous multiple of that
/// cadence, not a tight bound tuned to it.
const DEVNET_IO_TIMEOUT: Duration = Duration::from_secs(120);

/// Sustained `get-blocks` answers this transport will build per connection,
/// per second, and the burst above it before the sustained rate binds — same
/// values and the same reasoning as [`crate::p2p::SYNC_ANSWERS_PER_SEC`] /
/// [`crate::p2p::SYNC_ANSWER_BURST`] on the production transport, which this
/// mirrors (R3 M-4 / R1 A3-M2): the devnet serving path had NO rate limit at
/// all, so a connected peer could issue `get-blocks` back to back forever,
/// each one paying a `Store::blocks_after` disk read.
const GET_BLOCKS_ANSWERS_PER_SEC: f64 = 8.0;
const GET_BLOCKS_BURST: f64 = 32.0;

/// One immutable wire frame shared by the bounded devnet writer queues.
/// Conversion happens once before fanout; queue clones only retain the same
/// allocation, including attempts refused because a writer queue is full.
type SharedFrame = Arc<[u8]>;

/// The devnet TCP mesh: one queue per peer we dialed, plus one per peer that
/// dialed us.
pub struct DevnetMesh {
    /// Address selected by the kernel for the inbound listener.  Besides
    /// reporting the configured endpoint, this lets callers request port 0
    /// without probing, dropping and racing to re-bind an ephemeral port.
    listen_addr: SocketAddr,
    /// Bounded per [`OUTBOUND_QUEUE_DEPTH`] (R3 M-4 / R1 A3-M2) — see that
    /// constant's doc for why an unbounded queue here was a memory leak
    /// waiting on a peer that never connects.
    peers: Vec<SyncSender<SharedFrame>>,
    /// One request scheduler for both connection directions and both triggers.
    sync: Arc<SyncScheduler>,
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

#[derive(Clone)]
struct InboundPeer {
    frames: SyncSender<SharedFrame>,
    connection: Weak<Connection>,
}

impl InboundPeer {
    fn is_open(&self) -> bool {
        self.connection.upgrade().is_some_and(|c| !c.closed.load(Ordering::Acquire))
    }
}

/// Both workers share one counted lifetime. Exiting either half shuts down
/// the socket; capacity is released only after BOTH workers have stopped.
struct Connection {
    socket: TcpStream,
    closed: AtomicBool,
    pending_sync: Mutex<Option<(u64, Instant)>>,
    serving_sync: AtomicBool,
    _counts: (ConnCount, Option<ConnCount>),
    /// The inbound slot this connection holds; `None` on a connection this
    /// node dialed.
    slot: Option<InboundSlot>,
}

impl Connection {
    /// Consume one queued authorization only for its matching request. Old
    /// frames left in a dialer's queue cannot bypass a new connection's lease.
    fn take_sync_request(&self, frame: &[u8], now: Instant) -> bool {
        let Ok(mut pending) = self.pending_sync.lock() else { return false };
        let Some((after, at)) = *pending else { return false };
        if frame != get_blocks_frame(after) { return false; }
        *pending = None;
        now.saturating_duration_since(at) < SYNC_LEASE
    }
}

struct ConnectionHalf(Arc<Connection>);

impl Drop for ConnectionHalf {
    fn drop(&mut self) {
        self.0.closed.store(true, Ordering::Release);
        let _ = self.0.socket.shutdown(Shutdown::Both);
    }
}

fn run_inbound_writer(
    rx: Receiver<SharedFrame>,
    socket: Arc<Mutex<MeshWriter>>,
    half: ConnectionHalf,
) {
    run_connection_writer(&rx, socket, half);
}

fn run_connection_writer(rx: &Receiver<SharedFrame>, socket: Arc<Mutex<MeshWriter>>, half: ConnectionHalf) {
    while !half.0.closed.load(Ordering::Acquire) {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(frame) => {
                let Ok(mut writer) = socket.lock() else { return };
                if half.0.closed.load(Ordering::Acquire) { return; }
                if frame.first() == Some(&FRAME_GET_BLOCKS)
                    && !half.0.take_sync_request(frame.as_ref(), Instant::now()) { continue; }
                if writer.write_frame(frame.as_ref()).is_err() { return; }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
        }
    }
}

#[derive(Clone)]
struct SyncResponder {
    socket: Arc<Mutex<MeshWriter>>,
    data_dir: PathBuf,
    budget: Arc<Mutex<SyncBudget>>,
    /// The connection's source is one of the operator's own `--peers`.
    configured: bool,
}

/// Connection, budget, normalized source, whether the source is configured,
/// and whether it was proven when the worker was reserved.
struct SyncServingGuard(Arc<Connection>, Arc<Mutex<SyncBudget>>, std::net::IpAddr, bool, bool);
impl Drop for SyncServingGuard {
    fn drop(&mut self) {
        self.0.serving_sync.store(false, Ordering::Release);
        if let Ok(mut budget) = self.1.lock() {
            budget.serving = budget.serving.saturating_sub(1);
            if !self.3 { budget.serving_unconfigured = budget.serving_unconfigured.saturating_sub(1); }
            if let Some(held) = budget.serving_by_source.get_mut(&self.2) {
                *held = held.saturating_sub(1);
                if *held == 0 { budget.serving_by_source.remove(&self.2); }
            }
        }
    }
}

impl SyncResponder {
    fn reserve(&self, connection: &Arc<Connection>, ip: std::net::IpAddr, limiter: &mut GetBlocksLimiter) -> Option<SyncServingGuard> {
        self.reserve_at(connection, ip, limiter, Instant::now())
    }

    fn reserve_at(&self, connection: &Arc<Connection>, ip: std::net::IpAddr, limiter: &mut GetBlocksLimiter, now: Instant) -> Option<SyncServingGuard> {
        if connection.closed.load(Ordering::Acquire) || !limiter.admit(now) { return None; }
        let mut budget = self.budget.lock().ok()?;
        if !budget.admit(ip, now) || budget.serving >= MAX_SYNC_SERVING_WORKERS { return None; }
        let source = normalize_source(ip);
        if budget.cooling.get(&source).is_some_and(|until| now < *until) { return None; }
        // The workers above the reserve are for every source; the reserve is
        // for configured ones alone.
        if !self.configured
            && budget.serving_unconfigured >= MAX_SYNC_SERVING_WORKERS.saturating_sub(SYNC_SERVING_RESERVED_FOR_CONFIGURED)
        {
            return None;
        }
        let proven = budget.proven.get(&source).is_some_and(|at| now.saturating_duration_since(*at) < SYNC_SOURCE_PROVEN_FOR);
        let share = if proven { MAX_SYNC_SERVING_PER_SOURCE } else { MAX_SYNC_SERVING_PER_UNPROVEN_SOURCE };
        if budget.serving_by_source.get(&source).is_some_and(|held| *held >= share) { return None; }
        if connection.serving_sync.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() { return None; }
        budget.serving = budget.serving.saturating_add(1);
        if !self.configured { budget.serving_unconfigured = budget.serving_unconfigured.saturating_add(1); }
        *budget.serving_by_source.entry(source).or_default() += 1;
        Some(SyncServingGuard(connection.clone(), self.budget.clone(), source, self.configured, proven))
    }

    /// True when a worker took the request. A refused request is answered
    /// with silence and is not activity on the connection.
    fn answer(&self, connection: &Arc<Connection>, ip: std::net::IpAddr, frame: Vec<u8>, limiter: &mut GetBlocksLimiter) -> bool {
        if frame.len() != 9 { return false; }
        let Some(guard) = self.reserve(connection, ip, limiter) else { return false };
        let responder = self.clone();
        // One worker per active connection, with no page queue. Keeping the
        // reader free is necessary when both peers request pages together:
        // synchronous serving on both readers can deadlock their TCP buffers.
        thread::spawn(move || {
            let _guard = guard;
            if !_guard.0.closed.load(Ordering::Acquire) {
                let outcome = serve_get_blocks(&responder.socket, &responder.data_dir, &frame, &_guard.0, PagePace::starting_now(_guard.4));
                if let Ok(mut budget) = _guard.1.lock() { budget.note_page(_guard.2, outcome, Instant::now()); }
            }
        });
        true
    }
}

/// A reader ending for any reason closes both socket halves. In particular,
/// an idle legacy peer can exceed the frame deadline while its TCP connection
/// still accepts writes; retaining that writer would silently lose all inbound
/// data and keep a sync permit occupied until the process restarts.
fn run_outbound_reader(
    mut socket: MeshReader,
    events: Sender<EngineEvent>,
    budget: Arc<QueueBudget>,
    _half: ConnectionHalf,
    responder: SyncResponder,
) {
    let Ok(address) = socket.peer_addr() else { return };
    let mut limiter = GetBlocksLimiter::new();
    loop {
        match socket.read_frame() {
            Ok(frame) => {
                if frame.first() == Some(&FRAME_GET_BLOCKS) {
                    responder.answer(&_half.0, address.ip(), frame, &mut limiter);
                } else if !decode_and_send_from_peer(&events, &budget, address.ip(), &frame, true) {
                    // `true`: this connection was dialled to an address the
                    // operator configured, and it is the one sync is asked on.
                    return;
                }
            }
            Err(_) => return,
        }
    }
}

impl DevnetMesh {
    /// A transport-shaped sink for engine unit tests that do not exercise I/O.
    ///
    /// Using [`start`] for those fixtures leaves its blocking accept thread
    /// alive after the fixture is dropped: the listener owns no shutdown
    /// channel and nobody connects to wake it.  Keep those tests faithful to
    /// the `DevnetMesh` broadcast semantics (zero peers means a no-op) without
    /// opening a socket or spawning either background loop.
    #[cfg(test)]
    pub(crate) fn inert(head: Arc<AtomicU64>, budget: Arc<QueueBudget>) -> Self {
        Self {
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            peers: Vec::new(),
            sync: SyncScheduler::new(head, budget),
            inbound: Arc::new(Mutex::new(Vec::new())),
            live: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    /// TCP connections established right now. See [`DevnetMesh::live`].
    pub fn peer_count(&self) -> usize {
        self.live.load(Ordering::Acquire)
    }

    /// Address actually bound by the inbound listener.
    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    /// Broadcast one frame (type byte + payload, no length prefix) to every
    /// peer, dialed or dialing.
    pub fn broadcast(&self, frame: Vec<u8>) {
        if frame.first() == Some(&FRAME_GET_BLOCKS) {
            if let Some(bytes) = frame.get(1..9).filter(|_| frame.len() == 9) {
                if let Ok(bytes) = bytes.try_into() {
                    self.sync.pump(Instant::now(), Some(u64::from_le_bytes(bytes)));
                }
            }
            return;
        }
        let frame: SharedFrame = frame.into();
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

struct SyncPeer {
    peer: InboundPeer,
    requested_at: Option<Instant>,
}

#[derive(Default)]
struct SyncSchedule {
    peers: std::collections::VecDeque<SyncPeer>,
    requested_after: Option<u64>,
}

/// Shared request leases, not response-completion accounting: the legacy wire
/// has no request ID or end-of-page frame. Late responses remain bounded by
/// QueueBudget admission; expiration never disconnects an honest slow peer.
struct SyncScheduler {
    schedule: Mutex<SyncSchedule>,
    head: Arc<AtomicU64>,
    budget: Arc<QueueBudget>,
}

impl SyncScheduler {
    fn new(head: Arc<AtomicU64>, budget: Arc<QueueBudget>) -> Arc<Self> {
        Arc::new(Self { schedule: Mutex::new(SyncSchedule::default()), head, budget })
    }

    fn register(&self, peer: InboundPeer, now: Instant) {
        if let Ok(mut schedule) = self.schedule.lock() {
            schedule.peers.retain(|p| p.peer.is_open());
            // Existing waiters keep their place; a new connection joins before
            // peers which already consumed this round's lease.
            let waiting = schedule.peers.iter().position(|p| p.requested_at.is_some()).unwrap_or(schedule.peers.len());
            schedule.peers.insert(waiting, SyncPeer { peer, requested_at: None });
        }
        self.pump(now, None);
    }

    fn pump(&self, now: Instant, requested_after: Option<u64>) {
        let Ok(mut schedule) = self.schedule.lock() else { return };
        if let Some(after) = requested_after {
            schedule.requested_after = Some(schedule.requested_after.map_or(after, |old| old.min(after)));
        }
        schedule.peers.retain(|p| p.peer.is_open());
        for peer in &mut schedule.peers {
            if peer.requested_at.is_some_and(|at| now.saturating_duration_since(at) >= SYNC_LEASE) {
                peer.requested_at = None;
            }
        }
        // Slow state application must pause additional fetching, not destroy
        // lease eligibility. Once the consumer drains, FIFO rotation resumes.
        if self.budget.inflight() >= self.budget.count_cap.checked_div(2).unwrap_or(0)
            || self.budget.inflight_bytes() >= self.budget.bytes_cap.checked_div(2).unwrap_or(0) {
            return;
        }
        let mut active = schedule.peers.iter().filter(|p| p.requested_at.is_some()).count();
        let after = schedule.requested_after.unwrap_or_else(|| self.head.load(Ordering::Acquire));
        let frame: SharedFrame = get_blocks_frame(after).into();
        let mut sent = false;
        for _ in 0..schedule.peers.len() {
            if active >= SYNC_FANOUT { break; }
            let Some(mut peer) = schedule.peers.pop_front() else { break };
            if peer.requested_at.is_none() {
                if let Some(connection) = peer.peer.connection.upgrade() {
                    if let Ok(mut pending) = connection.pending_sync.lock() {
                        // Do not pile up requests behind a stalled writer. It
                        // clears the old authorization on send or expiry.
                        if pending.is_none() {
                            *pending = Some((after, now));
                            if peer.peer.frames.try_send(frame.clone()).is_ok() {
                                peer.requested_at = Some(now);
                                active = active.saturating_add(1);
                                sent = true;
                            } else {
                                *pending = None;
                            }
                        }
                    }
                }
            }
            schedule.peers.push_back(peer);
        }
        if sent { schedule.requested_after = None; }
    }

    fn start_timer(scheduler: &Arc<Self>) {
        let weak = Arc::downgrade(scheduler);
        thread::spawn(move || loop {
            thread::sleep(Duration::from_millis(250));
            let Some(scheduler) = weak.upgrade() else { return };
            scheduler.pump(Instant::now(), None);
        });
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
#[cfg(test)]
fn send_from_ip(events: &Sender<EngineEvent>, budget: &QueueBudget, ip: std::net::IpAddr, mut ev: NetEvent) -> bool {
    // One NAT address shares a burst allowance across connections. This is not
    // a validator identity: no score, persistent ban, or disconnect follows.
    if !budget.admit_source(&mut ev, source_budget::Source::ip(ip)) { return true; }
    send_to_engine(events, budget, ev)
}

/// Class and payload bytes available from the fixed one-byte frame tag,
/// before any payload parsing or allocation performed by `decode_event`.
fn framed_event_shape(frame: &[u8]) -> Option<(EventClass, usize)> {
    let class = match frame.first()? {
        &FRAME_BLOCK => EventClass::Block,
        &FRAME_ATT => EventClass::Attestation,
        &FRAME_TX => EventClass::Transaction,
        _ => return None,
    };
    Some((class, frame.len().saturating_sub(1)))
}

/// What one inbound frame turned out to be, for the slot accounting in
/// [`inbound_slots`].
#[derive(Debug, PartialEq, Eq)]
enum FrameOutcome {
    /// A valid frame: it decoded canonically and went to the engine.
    Delivered,
    /// A known type, refused by the queue budget before it was decoded.
    Shed,
    /// Unknown type or malformed. Not activity of any kind.
    Ignored,
    /// The engine is gone; the caller stops its thread.
    EngineGone,
}

/// Admit a legacy devnet frame before decoding it.
fn decode_and_send_from_ip(
    events: &Sender<EngineEvent>,
    budget: &QueueBudget,
    ip: std::net::IpAddr,
    frame: &[u8],
) -> bool {
    decode_and_send_from_peer(events, budget, ip, frame, false)
}

/// [`decode_and_send_from_ip`]; `configured` marks blocks read from a
/// connection this node dialled, so the engine verifies them under the
/// allowance reserved for sync and operator-configured peers.
fn decode_and_send_from_peer(
    events: &Sender<EngineEvent>,
    budget: &QueueBudget,
    ip: std::net::IpAddr,
    frame: &[u8],
    configured: bool,
) -> bool {
    admit_frame_from_ip(events, budget, ip, frame, configured) != FrameOutcome::EngineGone
}

/// The admission core every devnet reader shares. It reports what became of
/// the frame so the inbound slot table can tell a useful peer from an idle
/// one; `configured` is as in [`decode_and_send_from_peer`].
fn admit_frame_from_ip(
    events: &Sender<EngineEvent>,
    budget: &QueueBudget,
    ip: std::net::IpAddr,
    frame: &[u8],
    configured: bool,
) -> FrameOutcome {
    let Some((class, size)) = framed_event_shape(frame) else { return FrameOutcome::Ignored };
    let Some(source_guard) = source_budget::Registry::reserve(
        &budget.sources,
        source_budget::Source::ip(ip),
        class,
        size,
        budget.count_cap,
        budget.bytes_cap,
    ) else {
        budget.shed_counter(class).fetch_add(1, Ordering::Relaxed);
        return FrameOutcome::Shed;
    };
    if !budget.reserve_raw(class, size) {
        budget.shed_counter(class).fetch_add(1, Ordering::Relaxed);
        return FrameOutcome::Shed;
    }

    let Some(mut event) = decode_event(frame) else {
        budget.release_raw(size);
        return FrameOutcome::Ignored;
    };
    // All three decoders are canonical. A future permissive decoder must not
    // release a different byte charge from the one reserved before it ran.
    if class_of(&event) != class || queued_bytes(&event) != size {
        budget.release_raw(size);
        return FrameOutcome::Ignored;
    }
    match &mut event {
        NetEvent::Block(_, origin)
        | NetEvent::Attestation(_, origin)
        | NetEvent::Transaction(_, origin) => origin.set_reservation(source_guard),
    }
    if configured {
        if let NetEvent::Block(_, origin) = &mut event {
            origin.mark_directed_block();
        }
    }
    if events.send(EngineEvent::Net(event)).is_err() {
        budget.release_raw(size);
        return FrameOutcome::EngineGone;
    }
    FrameOutcome::Delivered
}

fn send_to_engine(events: &Sender<EngineEvent>, budget: &QueueBudget, ev: NetEvent) -> bool {
    // Atomic reservation of BOTH the count and the bytes (O06): the old
    // `load >= CAP` followed by `fetch_add` let concurrent readers overshoot
    // the cap, and no byte budget existed at all.
    if !budget.try_reserve(&ev) {
        return true; // shed, but the connection stays healthy
    }
    let size = charged_bytes(&ev);
    if events.send(EngineEvent::Net(ev)).is_err() {
        budget.release_raw(size);
        return false;
    }
    true
}

pub fn block_frame(env: &BlockEnvelope) -> Vec<u8> {
    let frame_len = 1usize.saturating_add(crate::codec::encoded_envelope_len(env));
    let mut f = Vec::with_capacity(frame_len);
    f.push(FRAME_BLOCK);
    crate::codec::write_envelope(&mut f, env).expect("writing to Vec cannot fail");
    debug_assert_eq!(f.len(), frame_len);
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
    write_typed_frame(&mut sock, FRAME_TX, tx_bytes)
}

fn write_frame<W: Write>(writer: &mut W, frame: &[u8]) -> std::io::Result<()> {
    // Keep the prefix and payload under the caller's existing whole-frame
    // lock, but do not allocate and copy the complete payload merely to join
    // these two immutable slices. `write_all` already handles short writes;
    // an error in either phase remains a partial-frame connection failure.
    writer.write_all(&(frame.len() as u32).to_le_bytes())?;
    writer.write_all(frame)
}

fn write_typed_frame<W: Write>(
    writer: &mut W,
    frame_type: u8,
    payload: &[u8],
) -> std::io::Result<()> {
    // Production payloads are bounded by MAX_FIELD_LEN before they reach this
    // sync-serving edge. Keep overflow fail-closed rather than wrapping a
    // length prefix if that invariant ever changes.
    let frame_len = payload.len().checked_add(1).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "frame length overflow")
    })?;
    let frame_len = u32::try_from(frame_len).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "frame length exceeds u32")
    })?;
    writer.write_all(&frame_len.to_le_bytes())?;
    writer.write_all(&[frame_type])?;
    writer.write_all(payload)
}

/// Write half of one mesh connection: length-prefixed plain frames, or
/// sealed records once `--mesh-security` has completed its handshake on the
/// socket (see `mesh_pq.rs`). Callers hand it the same `type ‖ payload` frame
/// either way.
pub(crate) struct MeshWriter {
    sock: TcpStream,
    sealer: Option<crate::mesh_pq::Sealer>,
}

impl MeshWriter {
    #[cfg(test)]
    pub(crate) fn plain(sock: TcpStream) -> Self {
        MeshWriter { sock, sealer: None }
    }

    fn write_frame(&mut self, frame: &[u8]) -> std::io::Result<()> {
        match &mut self.sealer {
            None => write_frame(&mut self.sock, frame),
            Some(sealer) => sealer.write_record(&mut self.sock, &[frame]),
        }
    }

    /// Write a typed frame under a deadline that progress does not renew.
    /// The steady-state write timeout is restored afterwards because
    /// broadcasts share this socket.
    fn write_typed_frame_until(&mut self, frame_type: u8, payload: &[u8], deadline: Instant) -> std::io::Result<()> {
        let mut writer = DeadlineWriter { sock: &self.sock, deadline };
        let result = match &mut self.sealer {
            None => write_typed_frame(&mut writer, frame_type, payload),
            Some(sealer) => sealer.write_record(&mut writer, &[&[frame_type], payload]),
        };
        let restored = self.sock.set_write_timeout(Some(DEVNET_IO_TIMEOUT));
        result.and(restored)
    }
}

/// The write twin of [`read_exact_until`]: every `write` may block only for
/// what is left of one budget (and never longer than [`DEVNET_IO_TIMEOUT`]),
/// so partial progress cannot renew it.
struct DeadlineWriter<'a> {
    sock: &'a TcpStream,
    deadline: Instant,
}

impl Write for DeadlineWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let remaining = self.deadline.checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::TimedOut, "page deadline exceeded"))?;
        self.sock.set_write_timeout(Some(remaining.min(DEVNET_IO_TIMEOUT)))?;
        self.sock.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.sock.flush()
    }
}

/// Read half of one mesh connection; the twin of [`MeshWriter`].
pub(crate) struct MeshReader {
    sock: TcpStream,
    opener: Option<crate::mesh_pq::Opener>,
}

impl MeshReader {
    fn read_frame(&mut self) -> std::io::Result<Vec<u8>> {
        match &mut self.opener {
            None => read_frame(&mut self.sock),
            Some(opener) => {
                let deadline = Instant::now().checked_add(DEVNET_IO_TIMEOUT)
                    .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "frame deadline out of range"))?;
                opener.read_record(&mut self.sock, deadline)
            }
        }
    }

    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        self.sock.peer_addr()
    }
}

/// Split a socket that has been through the handshake step into its two
/// halves. Restores the steady-state write timeout the handshake narrowed.
fn split_session(sock: TcpStream, session: crate::mesh_pq::Session) -> std::io::Result<(MeshReader, MeshWriter)> {
    sock.set_write_timeout(Some(DEVNET_IO_TIMEOUT))?;
    let rsock = sock.try_clone()?;
    Ok(match session {
        crate::mesh_pq::Session::Plain => (
            MeshReader { sock: rsock, opener: None },
            MeshWriter { sock, sealer: None },
        ),
        crate::mesh_pq::Session::Sealed { sealer, opener, .. } => (
            MeshReader { sock: rsock, opener: Some(opener) },
            MeshWriter { sock, sealer: Some(sealer) },
        ),
    })
}

/// Handshake refusals, at most one line per [`REFUSAL_LOG_EVERY`]. A port on
/// a routable address gets scanned; a scanner on a `require` node must not
/// turn into a log flood, and one line is enough to tell an operator that a
/// peer is misconfigured.
const REFUSAL_LOG_EVERY: Duration = Duration::from_secs(10);

fn log_refusal(direction: &str, peer: &str, e: &std::io::Error) {
    static LAST: Mutex<Option<Instant>> = Mutex::new(None);
    let now = Instant::now();
    let Ok(mut last) = LAST.lock() else { return };
    if last.is_some_and(|t| now.saturating_duration_since(t) < REFUSAL_LOG_EVERY) {
        return;
    }
    *last = Some(now);
    eprintln!("net: mesh handshake {direction} {peer} refused: {e}");
}

/// A dialer in `offer` mode met a node that closed on the handshake's first
/// bytes — what a legacy node does when it reads `"BPQ1"` as an 827 MB
/// frame length.
fn closed_on_handshake(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::*;
    matches!(e.kind(), UnexpectedEof | ConnectionReset | ConnectionAborted | BrokenPipe)
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
pub(crate) fn read_exact_until(sock: &mut TcpStream, mut buf: &mut [u8], deadline: Instant) -> std::io::Result<()> {
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

/// Per-connection admission for `get-blocks` on the devnet transport (R3 M-4
/// / R1 A3-M2): a token bucket, same shape and same values as the production
/// transport's [`crate::p2p::SyncLimiter`]. This bucket limits request rate;
/// SyncResponder separately limits serving to one worker per connection and
/// MAX_SYNC_SERVING_WORKERS globally, including disconnected generations.
///
/// Time is a parameter, not a call to `Instant::now()` inside, for the same
/// reason `SyncLimiter` takes one: testable refill arithmetic without
/// sleeping.
struct GetBlocksLimiter {
    tokens: f64,
    last: Instant,
    rate: f64,
    capacity: f64,
}

impl GetBlocksLimiter {
    fn new() -> Self {
        GetBlocksLimiter { tokens: GET_BLOCKS_BURST, last: Instant::now(), rate: GET_BLOCKS_ANSWERS_PER_SEC, capacity: GET_BLOCKS_BURST }
    }

    /// Admit one request now, or refuse. Refusing costs the peer nothing but
    /// silence — no frames are read from the log and none are written back,
    /// so a peer over its budget gets an answer that looks exactly like "the
    /// tip has not moved", which is indistinguishable from the truth and
    /// costs this node one comparison.
    fn admit(&mut self, now: Instant) -> bool {
        let dt = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + dt * self.rate).min(self.capacity);
        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }
}

/// Shared across connections, including reconnects. Idle address records
/// expire and the map itself is bounded, so IP rotation cannot grow memory.
struct SyncBudget {
    addresses: std::collections::BTreeMap<std::net::IpAddr, GetBlocksLimiter>,
    global: GetBlocksLimiter,
    serving: usize,
    /// Workers held per normalized source; entries exist only while nonzero,
    /// so the map never exceeds MAX_SYNC_SERVING_WORKERS entries.
    serving_by_source: std::collections::BTreeMap<std::net::IpAddr, usize>,
    /// Of `serving`, the workers held for sources that are not configured.
    serving_unconfigured: usize,
    /// Normalized source → when a whole page was last written to it.
    proven: std::collections::BTreeMap<std::net::IpAddr, Instant>,
    /// Normalized source → not served before this instant.
    cooling: std::collections::BTreeMap<std::net::IpAddr, Instant>,
}
impl SyncBudget {
    fn new() -> Self { Self { serving: 0, serving_by_source: Default::default(), serving_unconfigured: 0, proven: Default::default(), cooling: Default::default(), addresses: Default::default(), global: GetBlocksLimiter { tokens: 128.0, last: Instant::now(), rate: 64.0, capacity: 128.0 } } }
    /// Record how a page to `source` (already normalized) ended.
    fn note_page(&mut self, source: std::net::IpAddr, outcome: PageOutcome, now: Instant) {
        match outcome {
            PageOutcome::Written(bytes) if bytes >= SYNC_PROVING_PAGE_BYTES => {
                if !self.proven.contains_key(&source) {
                    self.proven.retain(|_, at| now.saturating_duration_since(*at) < SYNC_SOURCE_PROVEN_FOR);
                    if self.proven.len() >= MAX_SYNC_SOURCE_RECORDS { return; }
                }
                self.proven.insert(source, now);
            }
            PageOutcome::Stalled => {
                self.proven.remove(&source);
                if !self.cooling.contains_key(&source) {
                    self.cooling.retain(|_, until| now < *until);
                    if self.cooling.len() >= MAX_SYNC_SOURCE_RECORDS { return; }
                }
                self.cooling.insert(source, now + SYNC_STALL_COOLDOWN);
            }
            PageOutcome::Written(_) | PageOutcome::Closed => {}
        }
    }
    fn admit(&mut self, ip: std::net::IpAddr, now: Instant) -> bool {
        let ip = crate::connection_limit::limit_key(ip);
        if !self.addresses.contains_key(&ip) {
            self.addresses.retain(|_, bucket| now.saturating_duration_since(bucket.last) < Duration::from_secs(60));
            if self.addresses.len() >= 1024 { return false; }
        }
        if !self.addresses.entry(ip).or_insert_with(GetBlocksLimiter::new).admit(now) { return false; }
        self.global.admit(now)
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
fn serve_get_blocks(
    sock: &Arc<Mutex<MeshWriter>>,
    data_dir: &PathBuf,
    frame: &[u8],
    connection: &Connection,
    pace: PagePace,
) -> PageOutcome {
    if frame.len() != 9 || connection.closed.load(Ordering::Acquire) {
        return PageOutcome::Closed;
    }
    // SyncResponder admits rate limits and the per-connection worker permit
    // before this function can touch disk.
    // `frame.len() != 9` already returned above, so `frame[1..9]` is always
    // exactly 8 bytes and the conversion cannot fail; the `else` arm keeps it
    // panic-free by construction rather than by an `unwrap`.
    let Ok(after_bytes) = frame[1..9].try_into() else {
        return PageOutcome::Closed;
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
        // The clock of the page starts after the read from disk: the peer
        // is not charged for this node's storage.
        Ok(blocks) => write_sync_page(sock, &blocks, connection, PagePace { start: Instant::now(), ..pace }),
        Err(e) => {
            eprintln!("net: get-blocks failed: {e}");
            PageOutcome::Closed
        }
    }
}

/// Write one page, giving up and closing the connection as soon as a block
/// misses its deadline under `pace`. The caller's serving worker is therefore
/// held for a bounded time whatever the peer does, including while a
/// broadcast to the same slow peer holds the socket lock, and a peer that
/// reads nothing loses it after the first block the socket buffer refuses.
fn write_sync_page(
    sock: &Arc<Mutex<MeshWriter>>,
    blocks: &[Vec<u8>],
    connection: &Connection,
    pace: PagePace,
) -> PageOutcome {
    let mut written = 0usize;
    for b in blocks {
        let deadline = pace.deadline(written.saturating_add(b.len()));
        let mut w = loop {
            if connection.closed.load(Ordering::Acquire) { return PageOutcome::Closed; }
            match sock.try_lock() {
                Ok(w) => break w,
                Err(std::sync::TryLockError::Poisoned(_)) => return PageOutcome::Closed,
                Err(std::sync::TryLockError::WouldBlock) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(2));
                }
                Err(std::sync::TryLockError::WouldBlock) => {
                    connection.closed.store(true, Ordering::Release);
                    let _ = connection.socket.shutdown(Shutdown::Both);
                    return PageOutcome::Stalled;
                }
            }
        };
        if connection.closed.load(Ordering::Acquire) { return PageOutcome::Closed; }
        if w.write_typed_frame_until(FRAME_BLOCK, b, deadline).is_err() {
            // A partial frame cannot be followed by more framed data.
            connection.closed.store(true, Ordering::Release);
            let _ = connection.socket.shutdown(Shutdown::Both);
            // Past the deadline the peer was too slow; before it, the
            // connection broke, which is nobody's stall.
            return if Instant::now() >= deadline { PageOutcome::Stalled } else { PageOutcome::Closed };
        }
        written = written.saturating_add(b.len());
    }
    PageOutcome::Written(written)
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
/// responsible for restricting the port to known peers at the firewall.
///
/// `security` changes that: under `require` with an allow-list or pinned
/// peers only the expected ML-DSA-65 identities get a connection, and every
/// frame is encrypted and authenticated (`mesh_pq.rs`). Under `require` with
/// neither, frames are encrypted but any identity is accepted, so the
/// paragraph above still holds against anything that can reach the port.
/// Keep the firewall anyway; under `plain` that paragraph is the whole truth.
pub fn start(
    bind_addr: &str,
    listen_port: u16,
    peer_addrs: Vec<String>,
    events: Sender<EngineEvent>,
    data_dir: PathBuf,
    head_slot: Arc<AtomicU64>,
    inflight: Arc<QueueBudget>,
    security: Arc<crate::mesh_pq::MeshSecurity>,
) -> std::io::Result<DevnetMesh> {
    // Inbound: accept, then per-connection: read frames; data frames go to
    // the engine; get-blocks is answered by a globally bounded serving worker.
    let listener = TcpListener::bind((bind_addr, listen_port))?;
    let listen_addr = listener.local_addr()?;
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
    let slots: InboundSlots = Arc::new(Mutex::new(inbound_slots::Slots::new(INBOUND_POLICY)));
    // Sources of the operator's own `--peers`, exempt from the inbound
    // shares, deadlines and eviction. Literal addresses are known now; a peer
    // given by name is learned by its dialer thread on the first connection.
    let configured: Arc<Mutex<std::collections::BTreeSet<std::net::IpAddr>>> = Arc::new(Mutex::new(
        peer_addrs
            .iter()
            .filter_map(|addr| addr.parse::<SocketAddr>().ok())
            .map(|addr| crate::connection_limit::limit_key(addr.ip()))
            .collect(),
    ));
    {
        // Deadlines must not wait for the next accept: a quiet listener would
        // otherwise keep expired connections and their threads.
        let slots = Arc::downgrade(&slots);
        thread::spawn(move || loop {
            thread::sleep(Duration::from_secs(1));
            let Some(slots) = slots.upgrade() else { return };
            if let Ok(mut slots) = slots.lock() { slots.reap(Instant::now()); };
        });
    }
    let sync_budget = Arc::new(Mutex::new(SyncBudget::new()));
    let sync = SyncScheduler::new(head_slot.clone(), inflight.clone());
    SyncScheduler::start_timer(&sync);
    {
        let events = events.clone();
        let data_dir = data_dir.clone();
        let inbound = inbound.clone();
        let inflight = inflight.clone();
        let live = live.clone();
        let inbound_live = inbound_live.clone();
        let scheduler = Arc::downgrade(&sync);
        let sync_budget = sync_budget.clone();
        let security = security.clone();
        let configured = configured.clone();
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
                if inbound_live.load(Ordering::Acquire) >= MAX_INBOUND_LIVE {
                    continue;
                }
                let Ok(address) = sock.peer_addr() else { continue };
                let Ok(evict_handle) = sock.try_clone() else { continue };
                let is_configured = configured
                    .lock()
                    .is_ok_and(|set| set.contains(&crate::connection_limit::limit_key(address.ip())));
                // Shares, the pending pool and eviction are all decided here;
                // see `inbound_slots`. A refusal drops `sock`, closing it.
                let Some(slot) = InboundSlot::admit(&slots, address.ip(), is_configured, Instant::now(), evict_handle) else {
                    continue;
                };
                // R3 M-4 / R1 A3-M2: bounded so a peer that stops reading or
                // never writes cannot hold a thread and a queue open forever.
                if sock.set_read_timeout(Some(DEVNET_IO_TIMEOUT)).is_err()
                    || sock.set_write_timeout(Some(DEVNET_IO_TIMEOUT)).is_err()
                {
                    continue;
                }
                // The inbound slot is taken here, before the handshake, in
                // the pending pool: a flood of half-open handshakes is bounded
                // by `MAX_PENDING_INBOUND` and cannot reach the main pool. The
                // handshake itself runs on the connection's own thread: a slow
                // or silent dialer must not hold up the accept loop.
                let inbound_slot = ConnCount::new(&inbound_live);
                let events = events.clone();
                let data_dir = data_dir.clone();
                let inflight = inflight.clone();
                let inbound = inbound.clone();
                let live = live.clone();
                let scheduler = scheduler.clone();
                let sync_budget = sync_budget.clone();
                let security = security.clone();
                thread::spawn(move || {
                    let mut sock = sock;
                    let session = match crate::mesh_pq::handshake_inbound(&mut sock, &security) {
                        Ok(session) => session,
                        Err(e) => {
                            log_refusal("from", &address.to_string(), &e);
                            return;
                        }
                    };
                    // An authenticated handshake leaves the pending pool. A
                    // plain session has proven nothing yet and stays in it
                    // until its first valid frame.
                    if matches!(session, crate::mesh_pq::Session::Sealed { .. }) && !slot.mark_established() {
                        return;
                    }
                    let Ok(shutdown_socket) = sock.try_clone() else { return };
                    // Reading and writing need separate handles: the reader
                    // blocks in `read_frame` for as long as the peer is quiet,
                    // and a broadcast must not wait behind it.
                    let Ok((mut reader, writer)) = split_session(sock, session) else { return };
                    let connection = Arc::new(Connection {
                        socket: shutdown_socket,
                        closed: AtomicBool::new(false), pending_sync: Mutex::new(None), serving_sync: AtomicBool::new(false),
                        _counts: (ConnCount::new(&live), Some(inbound_slot)),
                        slot: Some(slot),
                    });
                    let wsock = Arc::new(Mutex::new(writer));

                    // One writer thread per connection, fed by a bounded queue,
                    // so a peer that stops reading fills its own queue and is
                    // dropped from there rather than blocking this node's
                    // broadcast loop.
                    let (tx, rx) = mpsc::sync_channel::<SharedFrame>(INBOUND_QUEUE_DEPTH);
                    {
                        let wsock = wsock.clone();
                        let half = ConnectionHalf(connection.clone());
                        thread::spawn(move || {
                            run_inbound_writer(rx, wsock, half);
                        });
                    }
                    let peer = InboundPeer { frames: tx, connection: Arc::downgrade(&connection) };
                    if let Ok(mut reg) = inbound.lock() { reg.push(peer.clone()); }
                    // Not a sync source yet: a connection that has delivered
                    // nothing would take a share of the sync leases and answer
                    // none of them. It is registered on its first valid frame.
                    // A configured source is the operator's own peer and is
                    // asked from the start, as it always was.
                    if is_configured {
                        if let Some(scheduler) = scheduler.upgrade() { scheduler.register(peer.clone(), Instant::now()); }
                    }

                    // Counted from here to wherever this thread leaves. The
                    // guards live in `_half`, so every `return` below and any
                    // unwind releases both.
                    let _half = ConnectionHalf(connection);
                    let responder = SyncResponder { socket: wsock, data_dir: data_dir.clone(), budget: sync_budget, configured: is_configured };
                    // Per-connection (R3 M-4 / R1 A3-M2): see [`GetBlocksLimiter`].
                    let mut get_blocks_limiter = GetBlocksLimiter::new();
                    loop {
                        match reader.read_frame() {
                            Ok(frame) => {
                                let outcome = if frame.first() == Some(&FRAME_GET_BLOCKS) {
                                    let well_formed = frame.len() == 9;
                                    responder.answer(&_half.0, address.ip(), frame, &mut get_blocks_limiter);
                                    if well_formed { FrameOutcome::Delivered } else { FrameOutcome::Ignored }
                                } else {
                                    admit_frame_from_ip(&events, &inflight, address.ip(), &frame, false)
                                };
                                let Some(slot) = _half.0.slot.as_ref() else { return };
                                let now = Instant::now();
                                match outcome {
                                    FrameOutcome::EngineGone => return,
                                    FrameOutcome::Delivered => match slot.mark_valid(now) {
                                        // Expired or evicted while this frame was in flight.
                                        None => return,
                                        Some(true) if !is_configured => {
                                            if let Some(scheduler) = scheduler.upgrade() { scheduler.register(peer.clone(), now); }
                                        }
                                        Some(_) => {}
                                    },
                                    FrameOutcome::Shed => slot.mark_shed(now),
                                    // Unknown or malformed frames are not activity.
                                    FrameOutcome::Ignored => {}
                                }
                            }
                            Err(_) => return,
                        }
                    }
                });
            }
        });
    }

    // Both triggers use the same scheduler. Dialers only write queued frames;
    // they never acquire lifetime sync slots or independently request pages.
    let mut peers = Vec::new();
    for addr in peer_addrs {
        // R3 M-4 / R1 A3-M2: bounded — see [`OUTBOUND_QUEUE_DEPTH`].
        let (tx, rx): (SyncSender<SharedFrame>, Receiver<SharedFrame>) =
            mpsc::sync_channel(OUTBOUND_QUEUE_DEPTH);
        peers.push(tx.clone());
        let scheduler = Arc::downgrade(&sync);
        let data_dir = data_dir.clone();
        let sync_budget = sync_budget.clone();
        let events = events.clone();
        let inflight = inflight.clone();
        let live = live.clone();
        let security = security.clone();
        let configured = configured.clone();
        thread::spawn(move || {
            // `offer` against a legacy peer: a handshake the peer closed on
            // sends the NEXT connection plain; when that plain session ends
            // the handshake is tried again, so an upgraded peer is picked up
            // on its first reconnect with no restart here.
            let mut fallback_plain = false;
            loop {
            let Ok(mut sock) = TcpStream::connect(&addr) else {
                thread::sleep(Duration::from_millis(300));
                continue;
            };
            // Bounded: a name that resolves somewhere new on every dial must
            // not grow this set for the life of the process.
            if let (Ok(address), Ok(mut set)) = (sock.peer_addr(), configured.lock()) {
                if set.len() < MAX_CONFIGURED_SOURCES {
                    set.insert(crate::connection_limit::limit_key(address.ip()));
                }
            }
            let session = if fallback_plain {
                fallback_plain = false;
                Ok(crate::mesh_pq::Session::Plain)
            } else {
                crate::mesh_pq::handshake_outbound(&mut sock, &security, &addr)
            };
            let session = match session {
                Ok(session) => session,
                // Never for a pinned peer: a pin says the peer speaks the
                // handshake, so a close here is not a legacy node, and a
                // plain session would skip the identity check the pin asks for.
                Err(e) if security.mode() == crate::mesh_pq::Mode::Offer
                    && !security.is_pinned(&addr)
                    && closed_on_handshake(&e) => {
                    fallback_plain = true;
                    continue;
                }
                Err(e) => {
                    log_refusal("to", &addr, &e);
                    // Not a busy loop against a peer that will refuse again.
                    thread::sleep(Duration::from_secs(2));
                    continue;
                }
            };
            // Both halves own one connected lifetime. A read timeout must
            // close the writer too: otherwise it can keep sending forever
            // while no worker consumes the peer's blocks or sync replies.
            let Ok(shutdown_socket) = sock.try_clone() else { continue };
            // R3 M-4 / R1 A3-M2: same bound as the inbound side — see
            // [`DEVNET_IO_TIMEOUT`]. Best-effort; a platform that refuses the
            // option gets an unbounded-latency socket, not a broken one.
            let _ = sock.set_read_timeout(Some(DEVNET_IO_TIMEOUT));
            let Ok((reader, writer)) = split_session(sock, session) else { continue };
            let connection = Arc::new(Connection {
                socket: shutdown_socket,
                closed: AtomicBool::new(false), pending_sync: Mutex::new(None), serving_sync: AtomicBool::new(false),
                _counts: (ConnCount::new(&live), None),
                    slot: None,
            });
            if let Some(scheduler) = scheduler.upgrade() {
                scheduler.register(InboundPeer { frames: tx.clone(), connection: Arc::downgrade(&connection) }, Instant::now());
            }
            let writer_half = ConnectionHalf(connection.clone());
            let reader_half = ConnectionHalf(connection);
            let wsock = Arc::new(Mutex::new(writer));
            // Reader half also answers reverse-direction requests, so an
            // inbound-only connection can participate in recovery.
            {
                let events = events.clone();
                let inflight = inflight.clone();
                // A dialled connection goes to an address the operator configured.
                let responder = SyncResponder { socket: wsock.clone(), data_dir: data_dir.clone(), budget: sync_budget.clone(), configured: true };
                thread::spawn(move || {
                    run_outbound_reader(reader, events, inflight, reader_half, responder);
                });
            }
            run_connection_writer(&rx, wsock, writer_half);
            }
        });
    }

    Ok(DevnetMesh { listen_addr, peers, sync, inbound, live })
}

#[cfg(test)]
mod tests {
    #[test]
    fn audit_sync_budget_is_shared_across_reconnections_and_addresses() {
        let mut budget = super::SyncBudget::new();
        let ip = "127.0.0.1".parse().unwrap();
        let now = std::time::Instant::now();
        for _ in 0..super::GET_BLOCKS_BURST as usize { assert!(budget.admit(ip, now)); }
        assert!(!budget.admit(ip, now));
        for host in 2..=4 {
            let other = format!("127.0.0.{host}").parse().unwrap();
            for _ in 0..32 { assert!(budget.admit(other, now)); }
        }
        assert!(!budget.admit("127.0.0.5".parse().unwrap(), now));
        assert!(budget.admit(ip, now + std::time::Duration::from_secs(1)));
    }

    use super::*;

    struct SyncTestPeer {
        peer: InboundPeer,
        received: Receiver<SharedFrame>,
        connection: Arc<Connection>,
        _remote: TcpStream,
    }

    impl SyncTestPeer {
        fn receive(&self) -> Result<SharedFrame, mpsc::TryRecvError> {
            let frame = self.received.try_recv()?;
            if frame.first() == Some(&FRAME_GET_BLOCKS) {
                assert!(self.connection.take_sync_request(frame.as_ref(), Instant::now()));
            }
            Ok(frame)
        }
    }

    fn sync_test_peer() -> SyncTestPeer {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let remote = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (socket, _) = listener.accept().unwrap();
        let live = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let connection = Arc::new(Connection { socket, closed: AtomicBool::new(false), pending_sync: Mutex::new(None), serving_sync: AtomicBool::new(false),
            _counts: (ConnCount::new(&live), None), slot: None });
        let (frames, received) = mpsc::sync_channel(1);
        let peer = InboundPeer { frames, connection: Arc::downgrade(&connection) };
        SyncTestPeer { peer, received, connection, _remote: remote }
    }

    #[test]
    fn shared_sync_leases_rotate_without_head_progress_and_bound_both_triggers() {
        let now = Instant::now();
        let scheduler = SyncScheduler::new(Arc::new(AtomicU64::new(42)), QueueBudget::new());
        let peers: Vec<_> = (0..3).map(|_| sync_test_peer()).collect();
        for peer in &peers { scheduler.register(peer.peer.clone(), now); }
        assert_eq!(peers[0].receive().unwrap().as_ref(), get_blocks_frame(42).as_slice());
        assert_eq!(peers[1].receive().unwrap().as_ref(), get_blocks_frame(42).as_slice());
        assert!(peers[2].receive().is_err());
        for _ in 0..100 {
            scheduler.pump(now, Some(7));
            scheduler.pump(now, None);
        }
        assert!(peers.iter().all(|p| p.receive().is_err()), "engine and timer must share the two leases");
        scheduler.pump(now + SYNC_LEASE, None);
        assert_eq!(peers[2].receive().unwrap().as_ref(), get_blocks_frame(7).as_slice(), "a silent first pair cannot exclude the next peer");
        let mut covered = std::collections::BTreeSet::new();
        for turn in 1..=6u32 {
            scheduler.pump(now + SYNC_LEASE * turn, None);
            for (index, peer) in peers.iter().enumerate() {
                if peer.receive().is_ok() { covered.insert(index); }
                assert!(peer.peer.is_open(), "lease expiration must not disconnect slow honest peers");
            }
            assert!(scheduler.schedule.lock().unwrap().peers.iter().filter(|p| p.requested_at.is_some()).count() <= SYNC_FANOUT);
        }
        assert_eq!(covered.len(), peers.len(), "all connections must reacquire without a head change");
    }

    #[test]
    fn shared_sync_backpressure_disconnect_and_full_queue_preserve_reacquisition() {
        let now = Instant::now();
        let budget = Arc::new(QueueBudget::with_caps(4, 100));
        let scheduler = SyncScheduler::new(Arc::new(AtomicU64::new(42)), budget.clone());
        let first = sync_test_peer();
        let second = sync_test_peer();
        let third = sync_test_peer();
        first.peer.frames.try_send(vec![FRAME_ATT].into()).unwrap(); // saturated writer
        scheduler.register(first.peer.clone(), now);
        scheduler.register(second.peer.clone(), now);
        scheduler.register(third.peer.clone(), now);
        assert_eq!(second.receive().unwrap().as_ref(), get_blocks_frame(42).as_slice());
        assert_eq!(third.receive().unwrap().as_ref(), get_blocks_frame(42).as_slice());
        assert_eq!(first.receive().unwrap().as_ref(), [FRAME_ATT]);
        assert!(budget.reserve_raw(EventClass::Block, 60)); // slow application
        scheduler.pump(now + SYNC_LEASE, Some(3));
        assert!(first.receive().is_err());
        assert!(second.receive().is_err());
        assert!(third.receive().is_err());
        assert!(budget.reserve_raw(EventClass::Block, 40));
        assert!(!budget.reserve_raw(EventClass::Block, 1), "late replies still obey the byte cap");
        budget.release_raw(60);
        budget.release_raw(40);
        scheduler.pump(now + SYNC_LEASE, None);
        assert_eq!(first.receive().unwrap().as_ref(), get_blocks_frame(3).as_slice());
        assert_eq!(second.receive().unwrap().as_ref(), get_blocks_frame(3).as_slice());
        second.connection.closed.store(true, Ordering::Release);
        scheduler.pump(now + SYNC_LEASE, None);
        assert_eq!(third.receive().unwrap().as_ref(), get_blocks_frame(42).as_slice(), "disconnect frees its lease without waiting for expiry");
        let replacement = sync_test_peer();
        scheduler.register(replacement.peer.clone(), now + SYNC_LEASE);
        scheduler.pump(now + SYNC_LEASE * 2, None);
        assert_eq!(replacement.receive().unwrap().as_ref(), get_blocks_frame(42).as_slice(), "reconnection enters the fair queue");
    }

    #[test]
    fn shared_sync_stalled_writer_cannot_accumulate_or_flush_expired_requests() {
        let now = Instant::now();
        let scheduler = SyncScheduler::new(Arc::new(AtomicU64::new(42)), QueueBudget::new());
        let peer = sync_test_peer();
        scheduler.register(peer.peer.clone(), now);
        for turn in 1..=5 { scheduler.pump(now + SYNC_LEASE * turn, Some(3)); }
        let stale = peer.received.try_recv().unwrap();
        assert_eq!(stale.as_ref(), get_blocks_frame(42).as_slice());
        assert!(peer.received.try_recv().is_err(), "only one authorization may wait behind a blocked writer");
        assert!(!peer.connection.take_sync_request(stale.as_ref(), now + SYNC_LEASE * 5));
        scheduler.pump(now + SYNC_LEASE * 5, None);
        let fresh = peer.received.try_recv().unwrap();
        assert_eq!(fresh.as_ref(), get_blocks_frame(3).as_slice());
        assert!(!peer.connection.take_sync_request(stale.as_ref(), now + SYNC_LEASE * 5), "a stale frame must not consume a different request's authorization");
        assert!(peer.connection.take_sync_request(fresh.as_ref(), now + SYNC_LEASE * 5));
        assert!(!peer.connection.take_sync_request(fresh.as_ref(), now + SYNC_LEASE * 5), "authorization is single use");
    }

    fn sync_test_block() -> BlockEnvelope {
        use bloch_pos_committee::header::{BlockHeaderV4, Body, VERSION_G4};
        BlockEnvelope {
            header: BlockHeaderV4 { version: VERSION_G4, parent: [1; 32], state_root: [2; 32],
                body_root: [3; 32], slot: 43, proposer_index: 0, randao_reveal: [4; 32],
                randao_mix: [5; 32], justified_root: [6; 32], finalized_root: [7; 32],
                attestation_root: [8; 32], coherence_root: [9; 32] },
            proposer_sig: vec![0xAA; 32],
            body: Body { transactions: Vec::new(), attestations: Vec::new() },
        }
    }

    #[test]
    fn block_frame_matches_canonical_oracle_for_empty_full_and_large_bodies() {
        let empty = sync_test_block();
        let mut full = sync_test_block();
        full.proposer_sig = vec![0xBB; 4_589];
        full.body.attestations.push(sample_attestation());
        full.body.transactions.push(vec![0xCC; 4_097]);
        let mut large = full.clone();
        large.body.transactions.push(vec![0xA5; 1 << 20]);

        for env in [empty, full, large] {
            let payload = crate::codec::encode_envelope(&env);
            let mut expected = Vec::with_capacity(1usize.saturating_add(payload.len()));
            expected.push(FRAME_BLOCK);
            expected.extend_from_slice(&payload);
            let frame = block_frame(&env);

            assert_eq!(frame, expected);
            assert_eq!(frame.len(), 1usize.saturating_add(crate::codec::encoded_envelope_len(&env)));
            let decoded = crate::codec::decode_envelope(&frame[1..]).expect("canonical payload");
            assert_eq!(decoded.header, env.header);
            assert_eq!(decoded.proposer_sig, env.proposer_sig);
            assert_eq!(decoded.body.transactions, env.body.transactions);
            assert_eq!(decoded.body.attestations.len(), env.body.attestations.len());
        }
    }

    #[test]
    fn block_queue_charge_matches_canonical_length_for_empty_full_and_large_bodies() {
        let empty = sync_test_block();
        let mut full = sync_test_block();
        full.proposer_sig = vec![0xBB; 4_589];
        full.body.attestations.push(sample_attestation());
        full.body.transactions.push(vec![0xCC; 4_097]);
        let mut large = full.clone();
        large.body.transactions.push(vec![0xA5; 1 << 20]);

        for env in [empty, full, large] {
            let canonical_len = crate::codec::encode_envelope(&env).len();
            let calculated_len = crate::codec::encoded_envelope_len(&env);
            let event = NetEvent::Block(env, Origin::none());

            assert_eq!(calculated_len, canonical_len);
            assert_eq!(queued_bytes(&event), canonical_len);
            assert_eq!(charged_bytes(&event), canonical_len);
        }
    }

    #[test]
    fn attestation_queue_charge_matches_canonical_length_without_payload_owner() {
        let mut attestation = sample_attestation();
        for signature_len in [0, 4_589, 1 << 20] {
            attestation.signature.resize(signature_len, 0xA5);
            let mut canonical = Vec::new();
            crate::codec::encode_attestation(&mut canonical, &attestation);
            let event = NetEvent::Attestation(attestation.clone(), Origin::none());

            assert_eq!(
                crate::codec::encoded_attestation_len(&attestation),
                canonical.len(),
            );
            assert_eq!(queued_bytes(&event), canonical.len());
            assert_eq!(charged_bytes(&event), canonical.len());
        }
    }

    #[test]
    fn prepared_block_broadcast_binds_large_wire_bytes_and_exact_id() {
        let mut env = sync_test_block();
        env.body.transactions = vec![vec![0xA5; 1 << 20]];
        let payload = crate::codec::encode_envelope(&env);
        let mut expected_frame = vec![FRAME_BLOCK];
        expected_frame.extend_from_slice(&payload);
        let expected_id = *env.block_id().as_bytes();

        let prepared = PreparedBlockBroadcast::new(&env);
        assert_eq!(prepared.id(), expected_id);
        assert_eq!(prepared.payload(), payload.as_slice());
        assert_eq!(prepared.devnet_frame(), expected_frame);
        assert_eq!(prepared.into_payload(), payload);
    }

    #[test]
    fn prepared_transaction_broadcast_preserves_large_payload_and_transport_bytes() {
        let payload = vec![0xA7; 1 << 20];
        let prepared = PreparedTransactionBroadcast::new(&payload);
        let libp2p_ptr = prepared.payload().as_ptr();
        let devnet = prepared.devnet_frame();
        let libp2p = prepared.into_payload();

        assert_eq!(libp2p.as_ptr(), libp2p_ptr, "libp2p payload was recopied");
        assert_eq!(libp2p, payload);
        assert_eq!(devnet.len(), payload.len() + 1);
        assert_eq!(devnet[0], FRAME_TX);
        assert_eq!(&devnet[1..], payload.as_slice());

        let prepared = PreparedTransactionBroadcast::new(&payload);
        let devnet_ptr = prepared.payload().as_ptr();
        let devnet = prepared.into_devnet_frame();
        assert_eq!(devnet.as_ptr(), devnet_ptr, "devnet tag insertion reallocated");
        assert_eq!(devnet[0], FRAME_TX);
        assert_eq!(&devnet[1..], payload.as_slice());
    }

    #[test]
    fn shared_sync_two_silent_outbound_peers_cannot_starve_responsive_inbound() {
        let silent_a = TcpListener::bind("127.0.0.1:0").unwrap();
        let silent_b = TcpListener::bind("127.0.0.1:0").unwrap();
        let (events, received) = mpsc::channel();
        let mesh = start("127.0.0.1", 0,
            vec![silent_a.local_addr().unwrap().to_string(), silent_b.local_addr().unwrap().to_string()],
            events, std::env::temp_dir(), Arc::new(AtomicU64::new(42)), QueueBudget::new(), Arc::new(crate::mesh_pq::MeshSecurity::plain())).unwrap();
        let port = mesh.listen_addr().port();
        let (mut a, _) = silent_a.accept().unwrap();
        let (mut b, _) = silent_b.accept().unwrap();
        for socket in [&mut a, &mut b] {
            assert_eq!(read_frame_until(socket, Instant::now() + Duration::from_secs(3)).unwrap(), get_blocks_frame(42));
        }
        let mut responder = TcpStream::connect(("127.0.0.1", port)).unwrap();
        for _ in 0..20 { mesh.broadcast(get_blocks_frame(42)); }
        assert_eq!(read_frame_until(&mut responder, Instant::now() + Duration::from_secs(8)).unwrap(), get_blocks_frame(42));
        let block = sync_test_block();
        write_frame(&mut responder, &block_frame(&block)).unwrap();
        match received.recv_timeout(Duration::from_secs(2)).unwrap() {
            EngineEvent::Net(NetEvent::Block(actual, _)) => assert_eq!(actual.block_id(), block.block_id()),
            _ => panic!("responsive peer did not deliver the missing block"),
        }
        assert_eq!(mesh.peer_count(), 3, "rotation must preserve silent and responsive connections");
    }

    #[test]
    fn shared_sync_outbound_reader_serves_reverse_direction_requests() {
        let dir = std::env::temp_dir().join(format!("bloch-reverse-sync-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let block = sync_test_block();
        let mut store = crate::store::Store::open(&dir, &[7; 32]).unwrap();
        store.append(&block).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let (events, _received) = mpsc::channel();
        let _mesh = start("127.0.0.1", 0, vec![listener.local_addr().unwrap().to_string()],
            events, dir.clone(), Arc::new(AtomicU64::new(43)), QueueBudget::new(), Arc::new(crate::mesh_pq::MeshSecurity::plain())).unwrap();
        let (mut remote, _) = listener.accept().unwrap();
        assert_eq!(read_frame_until(&mut remote, Instant::now() + Duration::from_secs(3)).unwrap(), get_blocks_frame(43));
        write_frame(&mut remote, &get_blocks_frame(42)).unwrap();
        assert_eq!(read_frame_until(&mut remote, Instant::now() + Duration::from_secs(3)).unwrap(), block_frame(&block));
        drop(remote);
        drop(store);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn shared_sync_bidirectional_large_pages_keep_both_readers_draining() {
        let base = std::env::temp_dir().join(format!("bloch-duplex-sync-{}-{}", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let left_dir = base.join("left");
        let right_dir = base.join("right");
        let mut block = sync_test_block();
        // Larger than ordinary TCP send buffers: two synchronous serving
        // readers would each block writing before either drained the other.
        block.body.transactions.push(vec![0xA5; 4 * 1024 * 1024]);
        let mut left_store = crate::store::Store::open(&left_dir, &[7; 32]).unwrap();
        let mut right_store = crate::store::Store::open(&right_dir, &[7; 32]).unwrap();
        left_store.append(&block).unwrap();
        right_store.append(&block).unwrap();
        let (left_tx, left_rx) = mpsc::channel();
        let (right_tx, right_rx) = mpsc::channel();
        let left = start("127.0.0.1", 0, Vec::new(), left_tx, left_dir,
            Arc::new(AtomicU64::new(42)), QueueBudget::new(), Arc::new(crate::mesh_pq::MeshSecurity::plain())).unwrap();
        let port = left.listen_addr().port();
        let right = start("127.0.0.1", 0, vec![format!("127.0.0.1:{port}")], right_tx, right_dir,
            Arc::new(AtomicU64::new(42)), QueueBudget::new(), Arc::new(crate::mesh_pq::MeshSecurity::plain())).unwrap();
        for received in [left_rx, right_rx] {
            match received.recv_timeout(Duration::from_secs(8)).unwrap() {
                EngineEvent::Net(NetEvent::Block(actual, _)) => assert_eq!(actual.body.transactions, block.body.transactions),
                _ => panic!("a bidirectional page was not delivered"),
            }
        }
        assert_eq!(left.peer_count(), 1);
        assert_eq!(right.peer_count(), 1);
        drop((left, right, left_store, right_store));
        std::fs::remove_dir_all(base).unwrap();
    }

    /// Two real meshes, right dialling left, each holding one 4 MiB block and
    /// asking the other for it. True when both sides received the other's
    /// page within the timeout.
    fn sync_across(left: crate::mesh_pq::MeshSecurity, right: crate::mesh_pq::MeshSecurity, tag: &str) -> bool {
        sync_across_with(left, |_| right, tag)
    }

    /// [`sync_across`], with the dialing side built once it knows the address
    /// it will dial, so it can pin it.
    fn sync_across_with(
        left: crate::mesh_pq::MeshSecurity,
        right: impl FnOnce(&str) -> crate::mesh_pq::MeshSecurity,
        tag: &str,
    ) -> bool {
        let base = std::env::temp_dir().join(format!("bloch-mesh-pq-{tag}-{}-{}", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let left_dir = base.join("left");
        let right_dir = base.join("right");
        let mut block = sync_test_block();
        block.body.transactions.push(vec![0xA5; 4 * 1024 * 1024]);
        let mut left_store = crate::store::Store::open(&left_dir, &[7; 32]).unwrap();
        let mut right_store = crate::store::Store::open(&right_dir, &[7; 32]).unwrap();
        left_store.append(&block).unwrap();
        right_store.append(&block).unwrap();
        let (left_tx, left_rx) = mpsc::channel();
        let (right_tx, right_rx) = mpsc::channel();
        let left_mesh = start("127.0.0.1", 0, Vec::new(), left_tx, left_dir,
            Arc::new(AtomicU64::new(42)), QueueBudget::new(), Arc::new(left)).unwrap();
        let port = left_mesh.listen_addr().port();
        let dialed = format!("127.0.0.1:{port}");
        let right = right(&dialed);
        let right_mesh = start("127.0.0.1", 0, vec![dialed], right_tx, right_dir,
            Arc::new(AtomicU64::new(42)), QueueBudget::new(), Arc::new(right)).unwrap();
        let delivered = [left_rx, right_rx].into_iter().all(|received| {
            matches!(received.recv_timeout(Duration::from_secs(8)),
                Ok(EngineEvent::Net(NetEvent::Block(actual, _))) if actual.body.transactions == block.body.transactions)
        });
        drop((left_mesh, right_mesh, left_store, right_store));
        let _ = std::fs::remove_dir_all(base);
        delivered
    }

    #[test]
    fn mesh_security_modes_interoperate_as_documented() {
        use crate::mesh_pq::{MeshSecurity, Mode};
        let net = [9; 32];
        let pq = |mode| MeshSecurity::ephemeral(mode, net, None);
        // Sealed end to end, including 4 MiB sync pages in both directions.
        assert!(sync_across(pq(Mode::Require), pq(Mode::Require), "req-req"));
        assert!(sync_across(pq(Mode::Offer), pq(Mode::Require), "offer-req"));
        // `offer` keeps talking to legacy nodes, in either direction.
        assert!(sync_across(pq(Mode::Offer), MeshSecurity::plain(), "offer-plain"));
        assert!(sync_across(MeshSecurity::plain(), pq(Mode::Offer), "plain-offer"));
        // `require` does not, in either direction, and neither does another network.
        assert!(!sync_across(pq(Mode::Require), MeshSecurity::plain(), "req-plain"));
        assert!(!sync_across(MeshSecurity::plain(), pq(Mode::Require), "plain-req"));
        assert!(!sync_across(pq(Mode::Require), MeshSecurity::ephemeral(Mode::Require, [8; 32], None), "other-net"));
    }

    #[test]
    fn mesh_allow_list_admits_only_listed_identities() {
        use crate::mesh_pq::{MeshSecurity, Mode};
        let net = [9; 32];
        let member = MeshSecurity::ephemeral(Mode::Require, net, None);
        let gate = |allowed| MeshSecurity::ephemeral(Mode::Require, net, Some(std::collections::HashSet::from([allowed])));
        let member_id = member.identity_id().unwrap();
        assert!(sync_across(gate(member_id), member, "allow-member"));
        assert!(!sync_across(gate(member_id), MeshSecurity::ephemeral(Mode::Require, net, None), "allow-stranger"));
    }

    #[test]
    fn mesh_pin_binds_the_dialed_address_to_one_identity() {
        use crate::mesh_pq::{MeshSecurity, Mode};
        let net = [9; 32];
        let pq = |mode| MeshSecurity::ephemeral(mode, net, None);
        // The dialer pins the listener's real identity: sealed sync both ways.
        let left = pq(Mode::Require);
        let left_id = left.identity_id().unwrap();
        assert!(sync_across_with(left, |addr| pq(Mode::Require).with_pin(addr, left_id), "pin-match"));
        // The listener holds another key than the pinned one: no session.
        assert!(!sync_across_with(pq(Mode::Require), |addr| pq(Mode::Require).with_pin(addr, [0x11; 32]), "pin-mismatch"));
        // `offer` falls back to plain for an unpinned legacy peer (asserted
        // in `mesh_security_modes_interoperate_as_documented`), but never
        // for a pinned one.
        assert!(!sync_across_with(MeshSecurity::plain(), |addr| pq(Mode::Offer).with_pin(addr, [0x11; 32]), "pin-no-plain"));
    }

    #[test]
    fn shared_sync_serving_cap_survives_reconnect_generations_and_closes_failed_writes() {
        let dir = std::env::temp_dir().join(format!("bloch-sync-workers-{}-{}", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let mut store = crate::store::Store::open(&dir, &[7; 32]).unwrap();
        store.append(&sync_test_block()).unwrap();
        let peers: Vec<_> = (0..=MAX_SYNC_SERVING_WORKERS).map(|_| sync_test_peer()).collect();
        let sockets: Vec<_> = peers.iter().map(|p| Arc::new(Mutex::new(MeshWriter::plain(p.connection.socket.try_clone().unwrap())))).collect();
        let budget = Arc::new(Mutex::new(SyncBudget::new()));
        // Configured, so the whole pool is theirs to fill (see the reserve test).
        let responders: Vec<_> = sockets.iter().map(|s| SyncResponder { socket: s.clone(), data_dir: dir.clone(), budget: budget.clone(), configured: true }).collect();
        let ip = "127.0.0.1".parse().unwrap();
        // Keep the same guards the worker owns alive, modelling outstanding
        // storage work deterministically across disconnected generations.
        // Distinct sources: one source alone is capped below the global limit.
        let guards: Vec<_> = peers.iter().zip(&responders).take(MAX_SYNC_SERVING_WORKERS).enumerate().map(|(i, (peer, responder))| {
            let source = std::net::IpAddr::from([10, 0, 0, i as u8 + 1]);
            responder.reserve(&peer.connection, source, &mut GetBlocksLimiter::new()).unwrap()
        }).collect();
        assert_eq!(budget.lock().unwrap().serving, MAX_SYNC_SERVING_WORKERS);
        for peer in peers.iter().take(MAX_SYNC_SERVING_WORKERS) { peer.connection.closed.store(true, Ordering::Release); }
        let last = peers.last().unwrap();
        let responder = responders.last().unwrap();
        assert!(responder.reserve(&last.connection, ip, &mut GetBlocksLimiter::new()).is_none(), "fresh reconnect generations cannot bypass old serving work");
        drop(guards);
        assert_eq!(budget.lock().unwrap().serving, 0, "worker completion must return capacity");
        let deadline = Instant::now() + Duration::from_secs(3);
        // A response failing after framing begins must close the connection,
        // so the normal writer cannot append frames to a corrupted stream.
        last.connection.socket.shutdown(Shutdown::Write).unwrap();
        responder.answer(&last.connection, ip, get_blocks_frame(42), &mut GetBlocksLimiter::new());
        while !last.connection.closed.load(Ordering::Acquire) || budget.lock().unwrap().serving != 0 {
            assert!(Instant::now() < deadline, "failed response did not close/release its connection");
            thread::sleep(Duration::from_millis(10));
        }
        drop(store);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn one_source_cannot_hold_every_sync_serving_worker() {
        let peers: Vec<_> = (0..=MAX_SYNC_SERVING_PER_SOURCE + 1).map(|_| sync_test_peer()).collect();
        let budget = Arc::new(Mutex::new(SyncBudget::new()));
        let responders: Vec<_> = peers.iter().map(|p| SyncResponder {
            socket: Arc::new(Mutex::new(MeshWriter::plain(p.connection.socket.try_clone().unwrap()))),
            data_dir: std::env::temp_dir(), budget: budget.clone(), configured: false,
        }).collect();
        let reserve = |i: usize, ip: &str| responders[i].reserve(&peers[i].connection, ip.parse().unwrap(), &mut GetBlocksLimiter::new());
        assert!(MAX_SYNC_SERVING_PER_SOURCE < MAX_SYNC_SERVING_WORKERS);
        // The full share belongs to a source that has been written a page.
        budget.lock().unwrap().note_page("192.0.2.1".parse().unwrap(), PageOutcome::Written(SYNC_PROVING_PAGE_BYTES), Instant::now());
        let mut held: Vec<_> = (0..MAX_SYNC_SERVING_PER_SOURCE).map(|i| reserve(i, "192.0.2.1").unwrap()).collect();
        let next = MAX_SYNC_SERVING_PER_SOURCE;
        assert!(reserve(next, "192.0.2.1").is_none(), "one source took more than its share of workers");
        assert!(reserve(next, "::ffff:192.0.2.1").is_none(), "the IPv4-mapped form is the same source");
        assert_eq!(budget.lock().unwrap().serving, MAX_SYNC_SERVING_PER_SOURCE);
        let other = reserve(next + 1, "192.0.2.2").expect("another source must still be served");
        held.pop();
        held.push(reserve(next, "192.0.2.1").expect("a finished worker returns its source's share"));
        drop((held, other));
        let budget = budget.lock().unwrap();
        assert_eq!(budget.serving, 0);
        assert!(budget.serving_by_source.is_empty());
    }

    /// One deadline for every block of the page, as before the pace existed.
    fn fixed_deadline(start: Instant, after: Duration) -> PagePace {
        PagePace { start, grace: after, bytes_per_sec: u64::MAX }
    }

    /// V2-3: two sources, each with its whole share stalled, do not leave a
    /// third without a worker; unconfigured sources together cannot reach the
    /// workers kept for configured peers.
    #[test]
    fn stalled_sources_leave_workers_for_others_and_for_configured_peers() {
        let peers: Vec<_> = (0..MAX_SYNC_SERVING_WORKERS + 2).map(|_| sync_test_peer()).collect();
        let budget = Arc::new(Mutex::new(SyncBudget::new()));
        let responder = |i: usize, configured: bool| SyncResponder {
            socket: Arc::new(Mutex::new(MeshWriter::plain(peers[i].connection.socket.try_clone().unwrap()))),
            data_dir: std::env::temp_dir(), budget: budget.clone(), configured,
        };
        let now = Instant::now();
        let reserve = |i: usize, ip: &str, configured: bool| {
            responder(i, configured).reserve_at(&peers[i].connection, ip.parse().unwrap(), &mut GetBlocksLimiter::new(), now)
        };
        // Both stalling sources have earned the full share beforehand.
        for ip in ["192.0.2.1", "192.0.2.2"] {
            budget.lock().unwrap().note_page(ip.parse().unwrap(), PageOutcome::Written(SYNC_PROVING_PAGE_BYTES), now);
        }
        let mut held = vec![
            reserve(0, "192.0.2.1", false).unwrap(), reserve(1, "192.0.2.1", false).unwrap(),
            reserve(2, "192.0.2.2", false).unwrap(), reserve(3, "192.0.2.2", false).unwrap(),
        ];
        assert!(reserve(4, "192.0.2.2", false).is_none());
        held.push(reserve(4, "192.0.2.3", false).expect("a third source is served"));
        // A source with no completed page holds one worker, not two.
        assert!(reserve(5, "192.0.2.3", false).is_none());
        held.push(reserve(5, "192.0.2.4", false).unwrap());
        assert_eq!(held.len(), MAX_SYNC_SERVING_WORKERS - SYNC_SERVING_RESERVED_FOR_CONFIGURED);
        assert!(reserve(6, "192.0.2.5", false).is_none(), "the reserve is not for unconfigured sources");
        for i in 0..SYNC_SERVING_RESERVED_FOR_CONFIGURED {
            held.push(reserve(6 + i, &format!("198.51.100.{}", i + 1), true).expect("a configured peer is served from the reserve"));
        }
        assert_eq!(budget.lock().unwrap().serving, MAX_SYNC_SERVING_WORKERS);
        drop(held);
        let budget = budget.lock().unwrap();
        assert_eq!((budget.serving, budget.serving_unconfigured), (0, 0));
        assert!(budget.serving_by_source.is_empty());
    }

    /// V2-3: a source whose page was cut off for not reading is not handed
    /// the next worker at once, and loses the share a completed page earned.
    #[test]
    fn a_stalled_source_waits_before_it_is_served_again() {
        let peers: Vec<_> = (0..3).map(|_| sync_test_peer()).collect();
        let budget = Arc::new(Mutex::new(SyncBudget::new()));
        let source: std::net::IpAddr = "192.0.2.1".parse().unwrap();
        let reserve = |i: usize, now: Instant| SyncResponder {
            socket: Arc::new(Mutex::new(MeshWriter::plain(peers[i].connection.socket.try_clone().unwrap()))),
            data_dir: std::env::temp_dir(), budget: budget.clone(), configured: false,
        }.reserve_at(&peers[i].connection, source, &mut GetBlocksLimiter::new(), now);
        let t0 = Instant::now();
        // A page too small to prove anything earns nothing; a real one does.
        budget.lock().unwrap().note_page(source, PageOutcome::Written(SYNC_PROVING_PAGE_BYTES - 1), t0);
        assert!(budget.lock().unwrap().proven.is_empty());
        budget.lock().unwrap().note_page(source, PageOutcome::Written(SYNC_PROVING_PAGE_BYTES), t0);
        // A connection that merely broke is not a stall.
        budget.lock().unwrap().note_page(source, PageOutcome::Closed, t0);
        drop((reserve(0, t0).unwrap(), reserve(1, t0).unwrap()));
        budget.lock().unwrap().note_page(source, PageOutcome::Stalled, t0);
        assert!(reserve(0, t0).is_none());
        assert!(reserve(0, t0 + SYNC_STALL_COOLDOWN - Duration::from_millis(1)).is_none());
        let again = reserve(0, t0 + SYNC_STALL_COOLDOWN).expect("served again after the cooldown");
        assert!(reserve(1, t0 + SYNC_STALL_COOLDOWN).is_none(), "and with the unproven share");
        drop(again);
        // Another source was never affected.
        let other = SyncResponder {
            socket: Arc::new(Mutex::new(MeshWriter::plain(peers[2].connection.socket.try_clone().unwrap()))),
            data_dir: std::env::temp_dir(), budget: budget.clone(), configured: false,
        };
        assert!(other.reserve_at(&peers[2].connection, "192.0.2.2".parse().unwrap(), &mut GetBlocksLimiter::new(), t0).is_some());
    }

    /// V2-3: a peer that reads nothing is cut off when the first block the
    /// socket would not take misses its own deadline, long before the
    /// deadline of the whole page.
    #[test]
    fn a_peer_that_reads_nothing_is_cut_off_long_before_the_page_deadline() {
        let peer = sync_test_peer();
        let socket = Arc::new(Mutex::new(MeshWriter::plain(peer.connection.socket.try_clone().unwrap())));
        // 48 MiB at 2 MiB/s: the page as a whole has 24 s. The remote end
        // never reads, so the socket buffers fill within the first blocks.
        let blocks = vec![vec![0x5A; 1 << 20]; 48];
        let pace = PagePace { start: Instant::now(), grace: Duration::from_millis(300), bytes_per_sec: 2 << 20 };
        let whole_page = pace.deadline(48 << 20);
        let outcome = write_sync_page(&socket, &blocks, &peer.connection, pace);
        let finished = Instant::now();
        assert_eq!(outcome, PageOutcome::Stalled);
        assert!(peer.connection.closed.load(Ordering::Acquire));
        assert!(finished + Duration::from_secs(10) < whole_page, "held for {:?} of a {:?} page budget", finished - pace.start, whole_page - pace.start);
    }

    #[test]
    fn sync_page_deadline_implies_the_documented_minimum_throughput() {
        let start = Instant::now();
        assert_eq!(sync_page_deadline(start, 0), start + SYNC_PAGE_WRITE_GRACE);
        assert_eq!(sync_page_deadline(start, crate::codec::MAX_FIELD_LEN), start + Duration::from_secs(15 + 256));
        // The pace of a page ends at that same instant and never asks for
        // more than the minimum rate on the way there.
        let pace = PagePace { start, grace: SYNC_PAGE_WRITE_GRACE, bytes_per_sec: SYNC_PAGE_MIN_BYTES_PER_SEC };
        assert_eq!(pace.deadline(crate::codec::MAX_FIELD_LEN), sync_page_deadline(start, crate::codec::MAX_FIELD_LEN));
        assert_eq!(pace.deadline(512 * 1024), start + Duration::from_secs(15 + 16));
        assert!(SYNC_SERVING_RESERVED_FOR_CONFIGURED + 2 * MAX_SYNC_SERVING_PER_SOURCE < MAX_SYNC_SERVING_WORKERS);
        // Per-write stalls stay bounded as before; the page budget is separate.
        assert!(SYNC_PAGE_WRITE_GRACE < DEVNET_IO_TIMEOUT);
    }

    #[test]
    fn slow_page_reader_is_cut_off_at_the_deadline_and_frees_its_worker() {
        let peer = sync_test_peer();
        let socket = Arc::new(Mutex::new(MeshWriter::plain(peer.connection.socket.try_clone().unwrap())));
        let budget = Arc::new(Mutex::new(SyncBudget::new()));
        let responder = SyncResponder { socket: socket.clone(), data_dir: std::env::temp_dir(), budget: budget.clone(), configured: false };
        let ip = "192.0.2.1".parse().unwrap();
        let guard = responder.reserve(&peer.connection, ip, &mut GetBlocksLimiter::new()).unwrap();
        // The peer keeps reading, far below the minimum rate. Each read is
        // progress, which is what used to renew the write timeout forever.
        let mut remote = peer._remote.try_clone().unwrap();
        let reader = thread::spawn(move || {
            let mut byte = [0u8; 1];
            while matches!(remote.read(&mut byte), Ok(1)) { thread::sleep(Duration::from_millis(10)); }
        });
        // Larger than any loopback socket buffer, so the write must block.
        let blocks = vec![vec![0x5A; 4 << 20]; 8];
        let started = Instant::now();
        let (done_tx, done_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            let guard = guard;
            let outcome = write_sync_page(&socket, &blocks, &guard.0, fixed_deadline(started, Duration::from_millis(400)));
            assert_eq!(outcome, PageOutcome::Stalled);
            drop(guard);
            done_tx.send(Instant::now()).unwrap();
        });
        let finished = done_rx.recv_timeout(Duration::from_secs(10)).expect("slow reader held its serving worker past the deadline");
        worker.join().unwrap();
        assert!(finished.duration_since(started) >= Duration::from_millis(400), "the page cannot have been written in full");
        assert!(peer.connection.closed.load(Ordering::Acquire), "a page cut off mid-frame must close the connection");
        assert_eq!(budget.lock().unwrap().serving, 0, "the worker slot was not released");
        assert!(budget.lock().unwrap().serving_by_source.is_empty());
        let next = sync_test_peer();
        assert!(responder.reserve(&next.connection, ip, &mut GetBlocksLimiter::new()).is_some());
        let _ = peer._remote.shutdown(Shutdown::Both);
        reader.join().unwrap();
    }

    #[test]
    fn page_deadline_also_bounds_waiting_for_a_stuck_socket_writer() {
        let peer = sync_test_peer();
        let socket = Arc::new(Mutex::new(MeshWriter::plain(peer.connection.socket.try_clone().unwrap())));
        // A broadcast stuck writing to the same slow peer holds this lock.
        let stuck = socket.lock().unwrap();
        let started = Instant::now();
        let outcome = write_sync_page(&socket, &[vec![1; 16]], &peer.connection, fixed_deadline(started, Duration::from_millis(200)));
        assert_eq!(outcome, PageOutcome::Stalled);
        assert!(started.elapsed() >= Duration::from_millis(200));
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(peer.connection.closed.load(Ordering::Acquire));
        drop(stuck);
    }

    #[test]
    fn normal_page_reader_completes_within_the_production_deadline() {
        let peer = sync_test_peer();
        let socket = Arc::new(Mutex::new(MeshWriter::plain(peer.connection.socket.try_clone().unwrap())));
        let blocks: Vec<Vec<u8>> = (0..8u8).map(|i| vec![i; 1 << 20]).collect();
        let expected = blocks.clone();
        let mut remote = peer._remote.try_clone().unwrap();
        let reader = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(20);
            (0..8).map(|_| read_frame_until(&mut remote, deadline).unwrap()).collect::<Vec<_>>()
        });
        let page_bytes: usize = blocks.iter().map(Vec::len).sum();
        let outcome = write_sync_page(&socket, &blocks, &peer.connection, PagePace::starting_now(false));
        assert_eq!(outcome, PageOutcome::Written(page_bytes), "an unproven honest reader is served in full too");
        let received = reader.join().unwrap();
        for (frame, block) in received.iter().zip(&expected) {
            assert_eq!(frame[0], FRAME_BLOCK);
            assert_eq!(&frame[1..], block.as_slice());
        }
        assert!(!peer.connection.closed.load(Ordering::Acquire), "an honest reader must not be disconnected");
        // Broadcasts on this socket get their steady-state timeout back.
        assert_eq!(peer.connection.socket.write_timeout().unwrap(), Some(DEVNET_IO_TIMEOUT));
    }

    #[test]
    fn outbound_reader_failure_reconnects_and_reclaims_sync_permit() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let (events, _received) = mpsc::channel();
        let mesh = start(
            "127.0.0.1", 0, vec![listener.local_addr().unwrap().to_string()],
            events, std::env::temp_dir(), Arc::new(AtomicU64::new(42)), QueueBudget::new(),
            Arc::new(crate::mesh_pq::MeshSecurity::plain()),
        ).unwrap();
        // More reconnects than the sync fanout: a leaked permit would leave
        // the third connection without its initial history request.
        for _ in 0..=SYNC_FANOUT {
            let deadline = Instant::now() + Duration::from_secs(8);
            let mut socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "outbound reader exit did not reconnect");
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("accept failed: {error}"),
                }
            };
            socket.set_nonblocking(false).unwrap();
            assert_eq!(
                read_frame_until(&mut socket, Instant::now() + Duration::from_secs(2)).unwrap(),
                get_blocks_frame(42),
                "each new connection must be able to acquire a sync permit",
            );
            // End the reader with an invalid frame while the peer keeps its
            // TCP read side open. The old writer could keep sending here
            // indefinitely, even though this connection could receive nothing.
            socket.write_all(&0u32.to_le_bytes()).unwrap();
            socket.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            assert_eq!(socket.read(&mut [0; 1]).unwrap(), 0,
                "reader failure left the outbound writer half alive");
            mesh.broadcast(get_blocks_frame(42)); // wake the idle writer promptly
        }
        drop(mesh);
    }

    #[test]
    fn audit_inbound_reader_exit_reclaims_idle_writer_and_capacity() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let _client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (socket, _) = listener.accept().unwrap();
        let live = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let inbound_live = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let connection = Arc::new(Connection {
            socket: socket.try_clone().unwrap(),
            closed: AtomicBool::new(false), pending_sync: Mutex::new(None), serving_sync: AtomicBool::new(false),
            _counts: (ConnCount::new(&live), Some(ConnCount::new(&inbound_live))),
                    slot: None,
        });
        let reader = ConnectionHalf(connection.clone());
        let writer = ConnectionHalf(connection.clone());
        let (frames, rx) = mpsc::sync_channel(INBOUND_QUEUE_DEPTH);
        let peer = InboundPeer { frames, connection: Arc::downgrade(&connection) };
        drop(connection);
        assert!(peer.is_open());
        assert_eq!(inbound_live.load(Ordering::Acquire), 1);
        // Keep the registry's sender alive and never broadcast: the exact
        // condition that previously stranded `for frame in rx` forever.
        let (done_tx, done_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            run_inbound_writer(rx, Arc::new(Mutex::new(MeshWriter::plain(socket))), writer);
            done_tx.send(()).unwrap();
        });
        drop(reader);
        done_rx.recv_timeout(Duration::from_secs(5)).expect("idle writer leaked after reader exit");
        worker.join().unwrap();
        assert!(!peer.is_open());
        assert_eq!(live.load(Ordering::Acquire), 0);
        assert_eq!(inbound_live.load(Ordering::Acquire), 0);
        assert!(matches!(peer.frames.try_send(vec![1].into()), Err(TrySendError::Disconnected(_))));
    }

    #[test]
    fn audit_inbound_writer_exit_interrupts_reader_without_releasing_early() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let _client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut socket, _) = listener.accept().unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let live = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let connection = Arc::new(Connection {
            socket: socket.try_clone().unwrap(),
            closed: AtomicBool::new(false), pending_sync: Mutex::new(None), serving_sync: AtomicBool::new(false),
            _counts: (ConnCount::new(&live), Some(ConnCount::new(&live))),
            slot: None,
        });
        let reader = ConnectionHalf(connection.clone());
        let writer = ConnectionHalf(connection);
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
    fn write_frame_streams_prefix_then_large_payload_across_short_writes() {
        #[derive(Default)]
        struct ShortWriter {
            bytes: Vec<u8>,
            offered: Vec<usize>,
        }

        impl Write for ShortWriter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.offered.push(bytes.len());
                // Split the four-byte prefix twice, then make the large
                // payload cross many writes. `write_all` must preserve both
                // phase order and every byte across those partial accepts.
                let cap = if self.offered.len() <= 2 { 2 } else { 4_093 };
                let accepted = bytes.len().min(cap);
                self.bytes.extend_from_slice(&bytes[..accepted]);
                Ok(accepted)
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let mut payload = vec![0xA5; 1 << 20];
        payload[0] = FRAME_BLOCK;
        let mut writer = ShortWriter::default();
        write_frame(&mut writer, &payload).unwrap();

        assert_eq!(&writer.bytes[..4], &(payload.len() as u32).to_le_bytes());
        assert_eq!(&writer.bytes[4..], payload.as_slice());
        assert_eq!(writer.offered[..3], [4, 2, payload.len()],
            "payload writing must begin only after the complete prefix");
    }

    #[test]
    fn write_typed_frame_streams_length_tag_and_payload_across_short_writes() {
        #[derive(Default)]
        struct ShortWriter {
            bytes: Vec<u8>,
            offered: Vec<usize>,
        }

        impl Write for ShortWriter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.offered.push(bytes.len());
                // Split the prefix, accept the one-byte tag, then split the
                // large payload independently of both preceding phases.
                let cap = if self.offered.len() <= 2 { 2 } else { 4_093 };
                let accepted = bytes.len().min(cap);
                self.bytes.extend_from_slice(&bytes[..accepted]);
                Ok(accepted)
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let payload = vec![0x5A; 1 << 20];
        let mut writer = ShortWriter::default();
        write_typed_frame(&mut writer, FRAME_TX, &payload).unwrap();

        let frame_len = payload.len() + 1;
        assert_eq!(&writer.bytes[..4], &(frame_len as u32).to_le_bytes());
        assert_eq!(writer.bytes[4], FRAME_TX);
        assert_eq!(&writer.bytes[5..], payload.as_slice());
        assert_eq!(writer.offered[..4], [4, 2, 1, payload.len()],
            "payload writing must begin only after the complete prefix and tag");
    }

    #[test]
    fn transaction_typed_frame_matches_legacy_oracle_and_preserves_partial_errors() {
        for payload in [Vec::new(), vec![1, 2, 3], vec![0xA5; 1 << 20]] {
            let mut expected_frame = vec![FRAME_TX];
            expected_frame.extend_from_slice(&payload);
            let mut expected_wire = (expected_frame.len() as u32).to_le_bytes().to_vec();
            expected_wire.extend_from_slice(&expected_frame);

            let mut wire = Vec::new();
            write_typed_frame(&mut wire, FRAME_TX, &payload).unwrap();
            assert_eq!(wire, expected_wire);
        }

        struct PartialThenFail {
            bytes: Vec<u8>,
            remaining: usize,
        }

        impl Write for PartialThenFail {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if self.remaining == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "injected transaction write failure",
                    ));
                }
                let accepted = bytes.len().min(self.remaining);
                self.bytes.extend_from_slice(&bytes[..accepted]);
                self.remaining = self.remaining.saturating_sub(accepted);
                Ok(accepted)
            }

            fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
        }

        let payload = vec![0x6C; 32];
        let mut writer = PartialThenFail { bytes: Vec::new(), remaining: 12 };
        assert_eq!(
            write_typed_frame(&mut writer, FRAME_TX, &payload).unwrap_err().kind(),
            std::io::ErrorKind::BrokenPipe,
        );
        assert_eq!(&writer.bytes[..4], &33u32.to_le_bytes());
        assert_eq!(writer.bytes[4], FRAME_TX);
        assert_eq!(&writer.bytes[5..], &payload[..7]);
    }

    #[test]
    fn send_transaction_writes_exact_wire_then_closes_without_ack() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let reader = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut wire = Vec::new();
            socket.read_to_end(&mut wire).unwrap();
            wire
        });
        let payload = vec![0xA7; 1 << 20];
        send_transaction(&addr.to_string(), &payload).unwrap();
        let wire = reader.join().unwrap();

        let mut expected_frame = vec![FRAME_TX];
        expected_frame.extend_from_slice(&payload);
        let mut expected_wire = (expected_frame.len() as u32).to_le_bytes().to_vec();
        expected_wire.extend_from_slice(&expected_frame);
        assert_eq!(wire, expected_wire);
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

    #[test]
    fn source_admission_lasts_through_processing_and_failed_delivery_releases_it() {
        let (tx, rx) = mpsc::channel::<EngineEvent>();
        let budget = QueueBudget::with_caps(1, 1 << 20);
        let ip = "192.0.2.1".parse().unwrap();
        let event = || NetEvent::Attestation(sample_attestation(), Origin::none());
        assert!(send_from_ip(&tx, &budget, ip, event()));
        let EngineEvent::Net(processing) = rx.recv().unwrap() else { panic!("network event") };
        match &processing {
            NetEvent::Block(_, origin)
            | NetEvent::Attestation(_, origin)
            | NetEvent::Transaction(_, origin) => assert!(
                origin.verification_source().is_some(),
                "the engine must receive the same normalized source carried by its guard",
            ),
        }
        // Match the engine's early release of the legacy queue accounting.
        // The source guard must remain held until processing actually ends.
        budget.release(&processing);
        assert!(send_from_ip(&tx, &budget, ip, event()));
        assert!(rx.try_recv().is_err());
        drop(processing);
        assert!(send_from_ip(&tx, &budget, ip, event()));
        let EngineEvent::Net(next) = rx.recv().unwrap() else { panic!("network event") };
        budget.release(&next);
        drop(next);
        drop(rx);
        assert!(!send_from_ip(&tx, &budget, ip, event()));
        assert_eq!((budget.inflight(), budget.inflight_bytes()), (0, 0));
        // A dead receiver drops both the queue reservation and Origin guard.
        let (live_tx, live_rx) = mpsc::channel();
        assert!(send_from_ip(&live_tx, &budget, ip, event()));
        assert!(live_rx.try_recv().is_ok());
    }

    #[test]
    fn devnet_reserves_before_decode_and_releases_malformed_frames() {
        let (tx, rx) = mpsc::channel::<EngineEvent>();
        let budget = QueueBudget::with_caps(1, 1 << 20);
        let ip = "192.0.2.44".parse().unwrap();
        let malformed = vec![FRAME_ATT, 0xFF];

        // Occupy the aggregate slot first. The malformed payload would fail
        // decoding, but it must be shed on the tag/length reservation before
        // a decoder gets the chance to inspect it.
        assert!(budget.reserve_raw(EventClass::Attestation, 1));
        assert!(decode_and_send_from_ip(&tx, &budget, ip, &malformed));
        assert_eq!(budget.shed(), (0, 1, 0));
        assert_eq!(budget.inflight(), 1);
        assert!(rx.try_recv().is_err());
        assert!(source_budget::Registry::reserve(
            &budget.sources,
            source_budget::Source::ip(ip),
            EventClass::Attestation,
            1,
            1,
            1 << 20,
        ).is_some(), "pre-decode shedding must release the per-IP charge");
        budget.release_raw(1);

        // With capacity available the decoder rejects it, and both the global
        // and per-IP reservations are returned on that path.
        assert!(decode_and_send_from_ip(&tx, &budget, ip, &malformed));
        assert_eq!(budget.inflight(), 0);
        assert_eq!(budget.inflight_bytes(), 0);
        assert!(source_budget::Registry::reserve(
            &budget.sources,
            source_budget::Source::ip(ip),
            EventClass::Attestation,
            1,
            1,
            1 << 20,
        ).is_some(), "decode failure must release the per-IP charge");
    }

    /// Blocks read from a connection this node dialled are marked for the
    /// verification allowance gossip cannot spend; inbound blocks are not.
    #[test]
    fn only_dialled_connections_mark_blocks_as_directed() {
        let (tx, rx) = mpsc::channel::<EngineEvent>();
        let budget = QueueBudget::with_caps(4, 1 << 20);
        let ip = "192.0.2.46".parse().unwrap();
        let frame = block_frame(&sync_test_block());
        assert!(decode_and_send_from_ip(&tx, &budget, ip, &frame));
        assert!(decode_and_send_from_peer(&tx, &budget, ip, &frame, true));
        for directed in [false, true] {
            let EngineEvent::Net(NetEvent::Block(_, origin)) = rx.recv().unwrap() else {
                panic!("block event")
            };
            assert_eq!(origin.directed_block(), directed);
        }
        assert!(!Origin::none().directed_block());
    }

    #[test]
    fn devnet_predecode_charge_matches_the_engine_release_charge() {
        let (tx, rx) = mpsc::channel::<EngineEvent>();
        let budget = QueueBudget::with_caps(4, 1 << 20);
        let ip = "192.0.2.45".parse().unwrap();
        let frame = block_frame(&sync_test_block());
        assert!(decode_and_send_from_ip(&tx, &budget, ip, &frame));
        assert_eq!(budget.inflight(), 1);
        assert_eq!(budget.inflight_bytes(), frame.len() - 1);

        let EngineEvent::Net(mut event) = rx.recv().unwrap() else { panic!("network event") };
        assert_eq!(class_of(&event), EventClass::Block);
        assert_eq!(queued_bytes(&event), frame.len() - 1);
        assert_eq!(charged_bytes(&event), frame.len() - 1);
        match &event {
            NetEvent::Block(_, origin)
            | NetEvent::Attestation(_, origin)
            | NetEvent::Transaction(_, origin) => {
                assert!(origin.verification_source().is_some())
            }
        }
        // Queue consumers do not mutate events, but accounting must remain
        // bound to the bytes that were actually reserved even on an
        // unexpected internal mutation. Re-encoding at release would leak
        // the difference here.
        let NetEvent::Block(env, _) = &mut event else { unreachable!() };
        env.proposer_sig.clear();
        assert_ne!(queued_bytes(&event), frame.len() - 1);
        assert_eq!(charged_bytes(&event), frame.len() - 1);
        budget.release(&event);
        drop(event);
        assert_eq!(budget.inflight(), 0);
        assert_eq!(budget.inflight_bytes(), 0);
        assert!(source_budget::Registry::reserve(
            &budget.sources,
            source_budget::Source::ip(ip),
            EventClass::Attestation,
            1,
            1,
            1 << 20,
        ).is_some(), "event drop must release the per-IP charge");
    }

    #[test]
    fn source_free_queue_events_fall_back_to_canonical_size() {
        let event = NetEvent::Attestation(sample_attestation(), Origin::none());
        assert_eq!(charged_bytes(&event), queued_bytes(&event));
        let budget = QueueBudget::with_caps(1, 1 << 20);
        let expected = queued_bytes(&event);
        assert!(budget.try_reserve(&event));
        assert_eq!(budget.inflight_bytes(), expected);
        budget.release(&event);
        assert_eq!((budget.inflight(), budget.inflight_bytes()), (0, 0));
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
        let attestation_cap = class_count_cap(EventClass::Attestation, cap);
        assert_eq!(admitted.load(Ordering::Relaxed), attestation_cap);
        assert_eq!(budget.inflight(), attestation_cap);
        for _ in attestation_cap..cap {
            assert!(budget.reserve_raw(EventClass::Block, 1));
        }
        assert!(!budget.reserve_raw(EventClass::Block, 1));
        assert_eq!(budget.inflight(), cap);
    }

    #[test]
    fn count_quotas_preserve_block_headroom_and_recover_after_release() {
        let budget = QueueBudget::with_caps(8, 1 << 20);
        for (class, target) in [
            (EventClass::Transaction, 4), (EventClass::Attestation, 6), (EventClass::Block, 8),
        ] {
            while budget.inflight() < target {
                assert!(budget.reserve_raw(class, 1));
            }
            assert!(!budget.reserve_raw(class, 1));
            assert_eq!(budget.inflight_bytes(), target);
        }
        for _ in 0..8 { budget.release_raw(1); }
        assert_eq!((budget.inflight(), budget.inflight_bytes()), (0, 0));
        assert!(budget.reserve_raw(EventClass::Transaction, 1));
        for class in [EventClass::Transaction, EventClass::Attestation, EventClass::Block] {
            assert!(!QueueBudget::with_caps(0, 1024).reserve_raw(class, 1));
            let tiny = QueueBudget::with_caps(1, 1024);
            assert!(tiny.reserve_raw(class, 1));
            assert!(!tiny.reserve_raw(class, 1));
        }
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
        let (tx, rx): (SyncSender<SharedFrame>, Receiver<SharedFrame>) =
            mpsc::sync_channel(OUTBOUND_QUEUE_DEPTH);
        let mesh = DevnetMesh {
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            peers: vec![tx],
            sync: SyncScheduler::new(Arc::new(AtomicU64::new(0)), QueueBudget::new()),
            inbound: Arc::new(Mutex::new(Vec::new())),
            live: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        };
        // Never drain `rx` — the stalled-dialer scenario — and broadcast well
        // past the bound.
        for _ in 0..(OUTBOUND_QUEUE_DEPTH + 50) {
            mesh.broadcast(vec![FRAME_BLOCK]);
        }
        let queued = std::iter::from_fn(|| rx.try_recv().ok()).count();
        assert_eq!(
            queued, OUTBOUND_QUEUE_DEPTH,
            "the outbound queue must cap at OUTBOUND_QUEUE_DEPTH, not grow with every broadcast"
        );
    }

    /// EN-08: fanout retains one immutable wire allocation, rather than one
    /// payload allocation per writer queue. A full queue must still keep its
    /// oldest frame and drop the incoming frame without changing ordering.
    #[test]
    fn devnet_broadcast_shares_wire_bytes_and_full_queues_do_not_displace() {
        let (first_tx, first_rx) = mpsc::sync_channel::<SharedFrame>(1);
        let (second_tx, second_rx) = mpsc::sync_channel::<SharedFrame>(1);
        let mesh = DevnetMesh {
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            peers: vec![first_tx, second_tx],
            sync: SyncScheduler::new(Arc::new(AtomicU64::new(0)), QueueBudget::new()),
            inbound: Arc::new(Mutex::new(Vec::new())),
            live: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        };
        let mut retained = vec![0xA5; 1 << 20];
        retained[0] = FRAME_BLOCK;
        mesh.broadcast(retained.clone());

        // Both queues are now full. This distinct incoming frame is refused;
        // `try_send` does not evict or reorder the already retained frame.
        mesh.broadcast(vec![FRAME_ATT, 0x5A]);

        let first = first_rx.try_recv().unwrap();
        let second = second_rx.try_recv().unwrap();
        assert!(Arc::ptr_eq(&first, &second), "both peers must retain the same allocation");
        assert_eq!(first.as_ref(), retained.as_slice(), "wire bytes must remain exact");
        assert_eq!(second.as_ref(), retained.as_slice(), "wire bytes must remain exact");
        assert!(first_rx.try_recv().is_err(), "full queue must drop, not displace or append");
        assert!(second_rx.try_recv().is_err(), "full queue must drop, not displace or append");
    }

    /// An inbound connection becomes a sync source only once it has delivered
    /// a valid frame. Silence and frames of unknown type earn nothing.
    #[test]
    fn inbound_connection_is_a_sync_source_only_after_a_valid_frame() {
        let (events, _rx) = mpsc::channel::<EngineEvent>();
        let data_dir = std::env::temp_dir().join(format!("bloch-net-useful-{}", std::process::id()));
        let mesh = start(
            "127.0.0.1",
            0,
            Vec::new(),
            events,
            data_dir,
            Arc::new(AtomicU64::new(0)),
            QueueBudget::new(),
            Arc::new(crate::mesh_pq::MeshSecurity::plain()),
        )
        .expect("bind the devnet transport");
        let port = mesh.listen_addr().port();
        let sources = || mesh.sync.schedule.lock().unwrap().peers.len();
        let wait_for = |want: usize| {
            let deadline = Instant::now() + Duration::from_secs(5);
            while sources() != want && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(10));
            }
            sources()
        };

        let _silent = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let mut noisy = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let mut honest = TcpStream::connect(("127.0.0.1", port)).unwrap();
        write_frame(&mut noisy, &[0xEE, 1, 2, 3]).unwrap();
        // Known type, wrong length: malformed, so still nothing.
        write_frame(&mut noisy, &[FRAME_GET_BLOCKS, 1]).unwrap();
        write_frame(&mut honest, &get_blocks_frame(0)).unwrap();
        assert_eq!(wait_for(1), 1);
        // All three are connected and all three receive broadcasts; only the
        // one that delivered a valid frame is asked for blocks.
        let deadline = Instant::now() + Duration::from_secs(5);
        while mesh.peer_count() < 3 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(mesh.peer_count(), 3);
        thread::sleep(Duration::from_millis(300));
        assert_eq!(sources(), 1, "silent and unknown-frame connections must not become sync sources");

        write_frame(&mut noisy, &get_blocks_frame(0)).unwrap();
        assert_eq!(wait_for(2), 2);
    }

    /// R3 M-4 / R1 A3-M2: the devnet listener accepts at most
    /// `MAX_INBOUND_CONNECTIONS` at once, and a connection past the cap is
    /// closed by the server immediately rather than left half-open. This
    /// transport authenticates nothing, so the cap is the only backstop
    /// against a connection flood on a routable bind.
    #[test]
    fn inbound_connections_are_capped() {
        let (events, _rx) = mpsc::channel::<EngineEvent>();
        let head_slot = Arc::new(AtomicU64::new(0));
        let inflight = QueueBudget::new();
        let mesh = start(
            "127.0.0.1",
            0,
            Vec::new(),
            events,
            std::env::temp_dir(),
            head_slot,
            inflight,
            Arc::new(crate::mesh_pq::MeshSecurity::plain()),
        )
        .expect("bind the devnet transport");
        let port = mesh.listen_addr().port();

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
        while mesh.peer_count() < MAX_PENDING_INBOUND_PER_SOURCE && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(20));
        }
        // One quiet moment so the count has settled — proving it never rises
        // past the cap needs a window, not just a poll exit condition.
        thread::sleep(Duration::from_millis(200));

        assert_eq!(
            mesh.peer_count(),
            MAX_PENDING_INBOUND_PER_SOURCE,
            "one unconfigured source that sends nothing holds only its share of the pending pool"
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
}
