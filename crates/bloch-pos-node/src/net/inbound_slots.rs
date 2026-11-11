// SPDX-License-Identifier: AGPL-3.0-or-later
//! Admission, standing and eviction for the mesh's inbound slots.
//!
//! The mesh accepts before it authenticates, so the slot table has to assume
//! that any inbound connection may be worthless. It must also assume the
//! opposite: on mainnet an honest validator says one thing every sixteen
//! minutes (its vote), a dozen of them share one address, and most of them
//! are in nobody's `--peers`. A quiet connection is therefore the normal
//! case, and the table never closes one for being quiet or for being one of
//! many from its address (review W4-1). What it keeps instead is an order:
//! when, and only when, the table is full, it decides who gives way.
//!
//! Every connection is in one of four standings:
//!
//! - **configured**: its source is one of the operator's own `--peers`. Such
//!   a connection is never refused by a share, never expired and never
//!   evicted; only the absolute table size can turn it away, and only when
//!   every slot is already held by another configured source. The standing
//!   is granted by source address at accept, before any handshake, so it is
//!   rationed by the number of peers the operator configured at that address
//!   (see [`Standing::for_source`]).
//! - **vouched**: its source delivered, within [`Policy::vouch_for`], a block
//!   or vote that the engine verified (a signature by a key in the validator
//!   registry), or the connection completed a handshake against an
//!   allow-list or a pin. Only another vouched or configured connection can
//!   take its slot, and only under the fair-share rule below.
//! - **active**: it delivered a frame that decoded, or had a sync request
//!   served. Neither costs a sender anything, so this is not proof.
//! - **silent**: none of the above yet.
//!
//! A source may hold [`Policy::per_source`] unconfigured connections. When
//! the table is full a newcomer is admitted only by displacing a connection:
//!
//! 1. A newcomer displaces connections of a lower standing than its own
//!    source's: a vouched source displaces silent, then active ones.
//! 2. Among equals the rule is fair shares: the source holding the most
//!    connections gives one up, and only if it holds at least two more than
//!    the newcomer's source, so the exchange never leaves it with fewer than
//!    the newcomer's. A newcomer whose source is not vouched has proven
//!    nothing and is everyone's equal at best, so it never displaces a
//!    vouched connection.
//! 3. Where shares are already even, unproven connections take turns: a
//!    newcomer whose source is not vouched may take the slot of the unproven
//!    connection that has held one longest, once that connection has held it
//!    for [`Policy::idle_close`] and its source would not be left with fewer
//!    than the newcomer's. Without this, whoever fills a restarted node's
//!    table first would keep an honest validator out for good, before it
//!    ever had a slot to deliver the vote that proves it.
//!
//! Rules 2 and 3 are what end a chain: a displaced honest peer redials at
//! once, and if it could displace an equal in turn at once, a full table
//! would churn forever. Under rule 3 each unproven connection is replaced at
//! most once per idle deadline, which is how often a quiet connection is
//! replaced anyway.
//!
//! Sources are compared by [`crate::connection_limit::limit_key`]: an IPv4
//! address, or an IPv6 /64.
use std::collections::BTreeMap;
use std::net::{IpAddr, Shutdown, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
pub(super) struct Policy {
    /// Every inbound connection.
    pub(super) total: usize,
    /// Unconfigured connections one source may hold.
    pub(super) per_source: usize,
    /// An unconfigured connection from which no well-formed frame was read
    /// for this long is closed.
    pub(super) idle_close: Duration,
    /// How long one verified block or vote vouches for its source.
    pub(super) vouch_for: Duration,
    /// Sources remembered as vouched; the least recently verified is
    /// forgotten first.
    pub(super) vouched_sources: usize,
}

/// How the table treats a connection, decided when it is accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Standing {
    /// Subject to the per-source share, the idle deadline and eviction.
    Unconfigured,
    /// From a source the operator configured. `may_displace` adds the right
    /// to take the slot of any unconfigured connection when the table is
    /// full.
    Configured { may_displace: bool },
}

impl Standing {
    /// The standing of a new connection from a source at which the operator
    /// configured `peers` peers and which already holds `held` configured
    /// slots.
    ///
    /// Each configured peer needs one inbound connection, and briefly a
    /// second while it replaces a broken one: `2 * peers + 2` configured
    /// slots cover a whole fleet behind one address restarting at once. Past
    /// that a connection is treated like anyone else's. The right to displace
    /// a vouched unconfigured connection is what makes room for a configured
    /// peer in a full table, so it is given to as many connections as there
    /// are configured peers at the address and to none beyond.
    pub(super) fn for_source(peers: usize, held: usize) -> Self {
        if peers == 0 || held >= peers.saturating_mul(2).saturating_add(2) {
            Standing::Unconfigured
        } else {
            Standing::Configured { may_displace: held < peers }
        }
    }

    pub(super) fn is_configured(self) -> bool {
        matches!(self, Standing::Configured { .. })
    }
}

/// What the table does to a connection it expires or evicts.
pub(super) trait Close {
    fn close(&self);
}

impl Close for TcpStream {
    fn close(&self) {
        let _ = self.shutdown(Shutdown::Both);
    }
}

struct Entry<H> {
    source: IpAddr,
    configured: bool,
    /// Completed a handshake against an allow-list or a pin.
    authenticated: bool,
    /// Authenticated, delivered a frame that decoded, or had a request served.
    established: bool,
    /// Delivered a frame that decoded.
    useful: bool,
    accepted: Instant,
    /// Last well-formed frame of any kind; drives the idle deadline only.
    last_heard: Instant,
    /// Last frame that decoded or request that was served.
    last_active: Instant,
    handle: H,
}

/// Standings an eviction compares, lowest first.
const SILENT: u8 = 0;
const ACTIVE: u8 = 1;
const VOUCHED: u8 = 2;

/// What a newcomer to a full table may displace.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Newcomer {
    /// A configured peer with the right to displace: any unconfigured connection.
    Displacing,
    /// Its source is vouched: lower standings, and vouched ones by fair share.
    Vouched,
    /// Nothing is known about its source: fair share and taking turns,
    /// among connections that are not vouched either.
    Unvouched,
}

pub(super) struct Slots<H: Close> {
    policy: Policy,
    next_id: u64,
    entries: BTreeMap<u64, Entry<H>>,
    /// Source → when the engine last verified a block or vote it delivered.
    verified: BTreeMap<IpAddr, Instant>,
}

impl<H: Close> Slots<H> {
    pub(super) fn new(policy: Policy) -> Self {
        Self { policy, next_id: 0, entries: BTreeMap::new(), verified: BTreeMap::new() }
    }

    fn evict(&mut self, id: u64) {
        if let Some(entry) = self.entries.remove(&id) {
            entry.handle.close();
        }
    }

    /// Close every unconfigured connection that is past the idle deadline.
    ///
    /// The deadline is the one the socket read timeout always enforced (a
    /// connection that says nothing for that long is closed and its dialer
    /// dials again), measured in well-formed frames so that bytes of no known
    /// meaning cannot renew it. Nothing else is closed on a timer: a
    /// connection that has proven nothing yet is kept until the table is
    /// full, because an honest validator may have nothing to prove itself
    /// with for a whole epoch.
    pub(super) fn reap(&mut self, now: Instant) {
        let idle_close = self.policy.idle_close;
        let expired: Vec<u64> = self
            .entries
            .iter()
            .filter(|(_, e)| !e.configured && now.saturating_duration_since(e.last_heard) >= idle_close)
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            self.evict(id);
        }
    }

    fn source_vouched(&self, source: IpAddr, now: Instant) -> bool {
        self.verified
            .get(&source)
            .is_some_and(|at| now.saturating_duration_since(*at) < self.policy.vouch_for)
    }

    fn standing_of(&self, entry: &Entry<H>, now: Instant) -> u8 {
        if entry.authenticated || self.source_vouched(entry.source, now) {
            VOUCHED
        } else if entry.established {
            ACTIVE
        } else {
            SILENT
        }
    }

    /// The connection a newcomer from `source`, which already holds `held`
    /// unconfigured connections, takes the slot of; `None` when the rules in
    /// the module header let it displace nobody.
    ///
    /// Order: lowest standing first, then the source holding the most
    /// connections. Inside one source the newest silent or active connection
    /// goes (the older ones have had longer to prove themselves and, in a
    /// flood, the newest are the flood), and the least recently active
    /// vouched one. Only when none of that applies does the longest-held
    /// unproven connection give up its turn (rule 3).
    fn victim(&self, now: Instant, source: IpAddr, held: usize, newcomer: Newcomer) -> Option<u64> {
        let mut by_source: BTreeMap<IpAddr, usize> = BTreeMap::new();
        for e in self.entries.values().filter(|e| !e.configured) {
            let count = by_source.entry(e.source).or_insert(0);
            *count = count.saturating_add(1);
        }
        let fair_from = held.saturating_add(2);
        let tenure = self.policy.idle_close;
        const BY_STANDING: u8 = 0;
        const BY_TURN: u8 = 1;
        self.entries
            .iter()
            .filter(|(_, e)| !e.configured)
            .filter_map(|(id, e)| {
                let standing = self.standing_of(e, now);
                let theirs = by_source.get(&e.source).copied().unwrap_or(0);
                let (lower, fair) = (standing < VOUCHED, theirs >= fair_from);
                let rule = match newcomer {
                    Newcomer::Displacing => BY_STANDING,
                    // Displacing a connection of one's own source gains nothing.
                    _ if e.source == source => return None,
                    Newcomer::Vouched if lower || fair => BY_STANDING,
                    Newcomer::Unvouched if lower && fair => BY_STANDING,
                    Newcomer::Unvouched
                        if lower && theirs > held && now.saturating_duration_since(e.accepted) >= tenure =>
                    {
                        BY_TURN
                    }
                    _ => return None,
                };
                Some((rule, standing, theirs, e, *id))
            })
            .min_by(|a, b| {
                a.0.cmp(&b.0).then_with(|| {
                    if a.0 == BY_TURN {
                        return a.3.accepted.cmp(&b.3.accepted).then(a.4.cmp(&b.4));
                    }
                    a.1.cmp(&b.1)
                        .then(b.2.cmp(&a.2))
                        .then_with(|| {
                            if a.1 == VOUCHED {
                                a.3.last_active.cmp(&b.3.last_active)
                            } else {
                                b.3.accepted.cmp(&a.3.accepted)
                            }
                        })
                        .then(b.4.cmp(&a.4))
                })
            })
            .map(|(.., id)| id)
    }

    /// Take a slot for a connection accepted from `ip`, or refuse it. The
    /// returned id is released with [`Slots::release`].
    #[cfg(test)]
    pub(super) fn admit(&mut self, ip: IpAddr, configured: bool, now: Instant, handle: H) -> Option<u64> {
        let standing = if configured { Standing::Configured { may_displace: true } } else { Standing::Unconfigured };
        self.admit_as(ip, standing, now, handle)
    }

    /// Configured slots currently held by the source of `ip`.
    pub(super) fn configured_held(&self, ip: IpAddr) -> usize {
        let source = crate::connection_limit::limit_key(ip);
        self.entries.values().filter(|e| e.configured && e.source == source).count()
    }

    /// [`Slots::admit`] with the standing spelled out.
    pub(super) fn admit_as(&mut self, ip: IpAddr, standing: Standing, now: Instant, handle: H) -> Option<u64> {
        self.reap(now);
        let policy = self.policy;
        let source = crate::connection_limit::limit_key(ip);
        let configured = standing.is_configured();
        let held = self.entries.values().filter(|e| !e.configured && e.source == source).count();
        if !configured && held >= policy.per_source {
            return None;
        }
        if self.entries.len() >= policy.total {
            let newcomer = match standing {
                Standing::Configured { may_displace: true } => Newcomer::Displacing,
                // A configured address past its displacing connections has
                // the rights of its address and no more (V2-6): whoever else
                // can connect from there must not evict peers at will.
                _ if self.source_vouched(source, now) => Newcomer::Vouched,
                _ => Newcomer::Unvouched,
            };
            let victim = self.victim(now, source, held, newcomer)?;
            self.evict(victim);
        }
        let id = self.next_id;
        self.next_id = self.next_id.checked_add(1)?;
        self.entries.insert(id, Entry {
            source,
            configured,
            authenticated: false,
            // A configured source is the operator's own peer. It still has to
            // deliver a frame to be called useful.
            established: configured,
            useful: false,
            accepted: now,
            last_heard: now,
            last_active: now,
            handle,
        });
        Some(id)
    }

    /// The connection completed a handshake against an allow-list or a pin:
    /// it is vouched for as long as it lives. False when the slot is gone
    /// (expired or evicted).
    pub(super) fn mark_authenticated(&mut self, id: u64) -> bool {
        self.entries
            .get_mut(&id)
            .map(|e| {
                e.authenticated = true;
                e.established = true;
            })
            .is_some()
    }

    /// The connection delivered a frame that decoded. `Some(true)` the first
    /// time, `None` when the slot is gone (expired or evicted).
    pub(super) fn mark_valid(&mut self, id: u64, now: Instant) -> Option<bool> {
        let entry = self.entries.get_mut(&id)?;
        let first = !entry.useful;
        entry.established = true;
        entry.useful = true;
        entry.last_heard = now;
        entry.last_active = now;
        Some(first)
    }

    /// A well-formed frame arrived that this node did not act on: one the
    /// queue budget refused before it could be decoded, or a sync request no
    /// worker took. It proves nothing and promotes nobody, but the peer is
    /// alive and speaking the protocol, so it renews the idle deadline: a
    /// node that is shedding load must not also expire its honest peers.
    pub(super) fn mark_heard(&mut self, id: u64, now: Instant) {
        if let Some(entry) = self.entries.get_mut(&id) {
            entry.last_heard = now;
            if entry.useful {
                entry.last_active = now;
            }
        }
    }

    /// The connection asked for blocks and a serving worker took the request.
    /// That is activity, and it is all a node that is still catching up has
    /// to say. It is not usefulness: nine bytes prove nothing. False when the
    /// slot is gone.
    pub(super) fn mark_requested(&mut self, id: u64, now: Instant) -> bool {
        let Some(entry) = self.entries.get_mut(&id) else { return false };
        entry.established = true;
        entry.last_heard = now;
        entry.last_active = now;
        true
    }

    /// The engine verified a block or vote that a connection from `ip`
    /// delivered: the signature of a key in the validator registry, which is
    /// the one thing on this transport an arbitrary host cannot produce. It
    /// vouches for the source address, not for one connection, because the
    /// proof must outlive the connection it arrived on: connections are
    /// replaced every couple of minutes and a validator votes once an epoch.
    /// Every node behind that address shares the standing, as they share the
    /// per-source share.
    pub(super) fn note_verified(&mut self, ip: IpAddr, now: Instant) {
        let source = crate::connection_limit::limit_key(ip);
        if !self.verified.contains_key(&source) && self.verified.len() >= self.policy.vouched_sources {
            let vouch_for = self.policy.vouch_for;
            self.verified.retain(|_, at| now.saturating_duration_since(*at) < vouch_for);
            if self.verified.len() >= self.policy.vouched_sources {
                let oldest = self.verified.iter().min_by_key(|(_, at)| **at).map(|(source, _)| *source);
                if let Some(oldest) = oldest {
                    self.verified.remove(&oldest);
                }
            }
        }
        self.verified.insert(source, now);
    }

    pub(super) fn release(&mut self, id: u64) {
        self.entries.remove(&id);
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    pub(super) fn is_vouched(&self, ip: IpAddr) -> bool {
        self.source_vouched(crate::connection_limit::limit_key(ip), Instant::now())
    }

    /// Connections that have proven nothing and said nothing useful yet.
    #[cfg(test)]
    pub(super) fn silent(&self) -> usize {
        self.entries.values().filter(|e| !e.established).count()
    }
}

/// One held slot. Dropping it frees the slot on every exit path.
pub(super) struct Slot<H: Close> {
    slots: Arc<Mutex<Slots<H>>>,
    id: u64,
}

impl<H: Close> Slot<H> {
    pub(super) fn admit(
        slots: &Arc<Mutex<Slots<H>>>,
        ip: IpAddr,
        standing: Standing,
        now: Instant,
        handle: H,
    ) -> Option<Self> {
        let id = slots.lock().ok()?.admit_as(ip, standing, now, handle)?;
        Some(Self { slots: slots.clone(), id })
    }

    pub(super) fn mark_requested(&self, now: Instant) -> bool {
        self.slots.lock().is_ok_and(|mut slots| slots.mark_requested(self.id, now))
    }

    pub(super) fn mark_authenticated(&self) -> bool {
        self.slots.lock().is_ok_and(|mut slots| slots.mark_authenticated(self.id))
    }

    pub(super) fn mark_valid(&self, now: Instant) -> Option<bool> {
        self.slots.lock().ok()?.mark_valid(self.id, now)
    }

    pub(super) fn mark_heard(&self, now: Instant) {
        if let Ok(mut slots) = self.slots.lock() {
            slots.mark_heard(self.id, now);
        }
    }

    /// Give the slot back before the connection's threads are gone. The
    /// connection is closed at this point; its dialer may already be dialing
    /// again, and must not be refused for a share its dead connection holds.
    pub(super) fn release(&self) {
        if let Ok(mut slots) = self.slots.lock() {
            slots.release(self.id);
        }
    }
}

impl<H: Close> Drop for Slot<H> {
    fn drop(&mut self) {
        self.release();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[derive(Clone, Default)]
    struct Probe(Arc<AtomicBool>);
    impl Probe {
        fn closed(&self) -> bool {
            self.0.load(Ordering::Acquire)
        }
    }
    impl Close for Probe {
        fn close(&self) {
            self.0.store(true, Ordering::Release);
        }
    }

    const POLICY: Policy = Policy {
        total: 6,
        per_source: 4,
        idle_close: Duration::from_secs(120),
        vouch_for: Duration::from_secs(3600),
        vouched_sources: 4,
    };
    /// The policy the node runs.
    const MAINNET: Policy = super::super::INBOUND_POLICY;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn a_source_at_its_share_is_refused_and_a_64_is_one_source() {
        let mut slots = Slots::new(POLICY);
        let t0 = Instant::now();
        // Four is the share, whether or not anything was said; the fifth is
        // refused, and so is another address inside the same /64.
        for host in ["2001:db8:1:2::1", "2001:db8:1:2:ffff::9", "2001:db8:1:2::3", "2001:db8:1:2::4"] {
            assert!(slots.admit(ip(host), false, t0, Probe::default()).is_some(), "{host}");
        }
        assert_eq!(slots.silent(), 4, "a silent connection is not refused for being one of several");
        assert!(slots.admit(ip("2001:db8:1:2::77"), false, t0, Probe::default()).is_none());
        // A neighbouring /64 is a different source; IPv4 and its mapped form are one.
        assert!(slots.admit(ip("2001:db8:1:3::5"), false, t0, Probe::default()).is_some());
        let mut slots = Slots::new(POLICY);
        for host in ["192.0.2.7", "::ffff:192.0.2.7", "192.0.2.7", "::ffff:192.0.2.7"] {
            assert!(slots.admit(ip(host), false, t0, Probe::default()).is_some());
        }
        assert!(slots.admit(ip("192.0.2.7"), false, t0, Probe::default()).is_none());
        // Being vouched does not widen the share.
        slots.note_verified(ip("192.0.2.7"), t0);
        assert!(slots.admit(ip("192.0.2.7"), false, t0, Probe::default()).is_none());
        // A configured source has no share.
        assert!(slots.admit(ip("192.0.2.7"), true, t0, Probe::default()).is_some());
    }

    /// W4-1: nothing is closed for having proven nothing. The only timer is
    /// the idle deadline the socket timeout always had, and a well-formed
    /// frame of any kind renews it.
    #[test]
    fn a_quiet_connection_is_kept_until_the_idle_deadline_and_no_sooner() {
        let mut slots = Slots::new(POLICY);
        let t0 = Instant::now();
        let silent = Probe::default();
        let asking = Probe::default();
        let voting = Probe::default();
        let configured = Probe::default();
        let silent_id = slots.admit(ip("192.0.2.1"), false, t0, silent.clone()).unwrap();
        let asking_id = slots.admit(ip("192.0.2.2"), false, t0, asking.clone()).unwrap();
        let voting_id = slots.admit(ip("192.0.2.3"), false, t0, voting.clone()).unwrap();
        slots.admit(ip("192.0.2.4"), true, t0, configured.clone()).unwrap();
        assert_eq!(slots.mark_valid(voting_id, t0 + secs(100)), Some(true));
        assert_eq!(slots.mark_valid(voting_id, t0 + secs(100)), Some(false));
        // A request nobody served, and a frame the budget shed: heard, no more.
        slots.mark_heard(asking_id, t0 + secs(90));
        assert_eq!((slots.len(), slots.silent()), (4, 2));

        slots.reap(t0 + secs(119));
        assert!(!silent.closed(), "a silent connection outlives the old thirty-second deadline");
        slots.reap(t0 + secs(120));
        assert!(silent.closed(), "the idle deadline still closes a connection that never spoke");
        assert_eq!(slots.mark_valid(silent_id, t0 + secs(121)), None, "an expired slot cannot come back");
        assert!(!slots.mark_authenticated(silent_id));
        assert!(!asking.closed() && !voting.closed());
        slots.reap(t0 + secs(210));
        assert!(asking.closed(), "ninety seconds plus the deadline");
        assert!(!voting.closed());
        slots.reap(t0 + secs(220));
        assert!(voting.closed());
        assert!(!configured.closed(), "a configured peer is never expired");
        assert_eq!(slots.len(), 1);
    }

    /// The order of the module header, one rule at a time.
    #[test]
    fn a_full_table_gives_way_by_standing_and_then_by_fair_share() {
        let mut slots = Slots::new(POLICY);
        let t0 = Instant::now();
        let configured = Probe::default();
        let vouched = Probe::default();
        let active = Probe::default();
        let older_silent = Probe::default();
        let newer_silent = Probe::default();
        let lone_silent = Probe::default();
        slots.admit(ip("198.51.100.1"), true, t0, configured.clone()).unwrap();
        let vouched_id = slots.admit(ip("192.0.2.1"), false, t0, vouched.clone()).unwrap();
        slots.mark_valid(vouched_id, t0);
        slots.note_verified(ip("192.0.2.1"), t0);
        let active_id = slots.admit(ip("192.0.2.2"), false, t0, active.clone()).unwrap();
        assert!(slots.mark_requested(active_id, t0));
        slots.admit(ip("192.0.2.3"), false, t0 + secs(1), older_silent.clone()).unwrap();
        slots.admit(ip("192.0.2.3"), false, t0 + secs(2), newer_silent.clone()).unwrap();
        slots.admit(ip("192.0.2.4"), false, t0 + secs(3), lone_silent.clone()).unwrap();
        assert_eq!(slots.len(), POLICY.total);
        let now = t0 + secs(10);
        let closed = |probes: &[&Probe]| probes.iter().map(|p| p.closed()).collect::<Vec<_>>();
        let all = [&newer_silent, &older_silent, &lone_silent, &active, &vouched, &configured];

        // A stranger is everyone's equal: it takes a slot only from a source
        // holding two more than its own, and that source's newest goes.
        let stranger = slots.admit(ip("203.0.113.1"), false, now, Probe::default()).unwrap();
        assert_eq!(closed(&all), [true, false, false, false, false, false]);
        // Now every unvouched source holds one. A second stranger displaces
        // nobody, and neither does a second connection of the first.
        assert!(slots.admit(ip("203.0.113.2"), false, now, Probe::default()).is_none());
        assert!(slots.admit(ip("203.0.113.1"), false, now, Probe::default()).is_none());
        assert_eq!(closed(&all), [true, false, false, false, false, false]);

        // A vouched source displaces lower standings: silent before active,
        // newest first, and never a connection of its own.
        assert!(slots.admit(ip("192.0.2.1"), false, now, Probe::default()).is_some());
        assert_eq!(closed(&all), [true, false, false, false, false, false], "the stranger was the newest silent one");
        assert_eq!(slots.mark_valid(stranger, now), None);
        assert!(slots.admit(ip("192.0.2.1"), false, now, Probe::default()).is_some());
        assert_eq!(closed(&all), [true, false, true, false, false, false]);
        assert!(slots.admit(ip("192.0.2.1"), false, now, Probe::default()).is_some());
        assert_eq!(closed(&all), [true, true, true, false, false, false]);
        assert!(slots.admit(ip("192.0.2.1"), false, now, Probe::default()).is_none(), "its share");
        // Another vouched source: the active one goes, then nobody (the
        // vouched source holds four, the newcomer's would hold two: fair
        // share lets it take one more, and no further).
        slots.note_verified(ip("192.0.2.9"), now);
        assert!(slots.admit(ip("192.0.2.9"), false, now, Probe::default()).is_some());
        assert_eq!(closed(&all), [true, true, true, true, false, false]);
        assert!(slots.admit(ip("192.0.2.9"), false, now, Probe::default()).is_some());
        assert!(vouched.closed(), "the larger vouched source gave up its least recently active");
        assert!(slots.admit(ip("192.0.2.9"), false, now, Probe::default()).is_none(), "three against two is fair");
        // A stranger displaces no vouched connection, whatever the shares.
        assert!(slots.admit(ip("203.0.113.9"), false, now, Probe::default()).is_none());

        // A configured newcomer is not refused while an unconfigured
        // connection exists, and still never displaces a configured one.
        for n in 2..=6 {
            assert!(slots.admit(ip(&format!("198.51.100.{n}")), true, now, Probe::default()).is_some());
        }
        assert!(!configured.closed());
        assert!(slots.admit(ip("198.51.100.7"), true, now, Probe::default()).is_none());
        assert!(!configured.closed(), "a configured peer is never evicted");
    }

    /// V2-6: the configured standing follows the source address, so it is
    /// rationed by what the operator configured there.
    #[test]
    fn a_configured_address_gets_bounded_slots_and_bounded_evictions() {
        assert_eq!(Standing::for_source(0, 0), Standing::Unconfigured);
        assert_eq!(Standing::for_source(1, 0), Standing::Configured { may_displace: true });
        assert_eq!(Standing::for_source(1, 1), Standing::Configured { may_displace: false });
        assert_eq!(Standing::for_source(1, 3), Standing::Configured { may_displace: false });
        assert_eq!(Standing::for_source(1, 4), Standing::Unconfigured);
        // Seventeen validators on one host, all listed: every one of them
        // may displace, and all may reconnect at once.
        assert_eq!(Standing::for_source(17, 16), Standing::Configured { may_displace: true });
        assert_eq!(Standing::for_source(17, 35), Standing::Configured { may_displace: false });
        assert_eq!(Standing::for_source(17, 36), Standing::Unconfigured);

        // A full table of useful, unconfigured peers, vouched or not, and a
        // flood of connections from an address at which one peer is
        // configured.
        for vouched in [false, true] {
            let mut slots = Slots::new(POLICY);
            let t0 = Instant::now();
            let honest: Vec<Probe> = (0..POLICY.total).map(|_| Probe::default()).collect();
            for (n, probe) in honest.iter().enumerate() {
                let host = ip(&format!("192.0.2.{}", n + 1));
                let id = slots.admit(host, false, t0, probe.clone()).unwrap();
                slots.mark_valid(id, t0);
                if vouched && n < POLICY.vouched_sources {
                    slots.note_verified(host, t0);
                }
            }
            let shared = ip("198.51.100.1");
            let mut admitted = 0;
            for _ in 0..128 {
                let standing = Standing::for_source(1, slots.configured_held(shared));
                // Past its configured slots the address is an ordinary source.
                if slots.admit_as(shared, standing, t0, Probe::default()).is_some() {
                    admitted += 1;
                }
            }
            assert_eq!(admitted, 1, "one configured peer makes room for one connection");
            assert_eq!(honest.iter().filter(|p| p.closed()).count(), 1);
            assert_eq!(slots.len(), POLICY.total);
        }
    }

    /// V2-7: asking for blocks keeps a connection open but never vouches for
    /// it, so it gives way to any vouched source when the table is full.
    #[test]
    fn a_connection_that_only_asks_for_blocks_is_never_vouched() {
        let mut slots = Slots::new(POLICY);
        let t0 = Instant::now();
        let asker = Probe::default();
        let asker_id = slots.admit(ip("192.0.2.1"), false, t0, asker.clone()).unwrap();
        assert!(slots.mark_requested(asker_id, t0 + secs(1)));
        assert_eq!(slots.silent(), 0, "a served request is activity");
        // Requests are activity: no idle close while they keep coming.
        assert!(slots.mark_requested(asker_id, t0 + secs(100)));
        slots.reap(t0 + secs(200));
        assert!(!asker.closed());
        assert_eq!(slots.mark_valid(asker_id, t0 + secs(200)), Some(true), "its first real frame is still its first");
        slots.release(asker_id);

        // A table full of connections that only ask, however recently: a
        // vouched newcomer always gets in, and a stranger never does.
        let askers: Vec<Probe> = (0..POLICY.total).map(|_| Probe::default()).collect();
        let now = t0 + secs(300);
        for (n, probe) in askers.iter().enumerate() {
            let id = slots.admit(ip(&format!("192.0.2.{}", n + 1)), false, now, probe.clone()).unwrap();
            assert!(slots.mark_requested(id, now));
        }
        assert!(slots.admit(ip("203.0.113.1"), false, now, Probe::default()).is_none());
        slots.note_verified(ip("203.0.113.1"), now);
        assert!(slots.admit(ip("203.0.113.1"), false, now, Probe::default()).is_some());
        assert_eq!(askers.iter().filter(|p| p.closed()).count(), 1);
        assert!(askers[POLICY.total - 1].closed(), "the newest asker made room");
    }

    /// V2-7: sources that keep reopening their whole share do not shut a
    /// newcomer out, and a source never evicts others to add to its own pile.
    #[test]
    fn churning_sources_cannot_hold_the_table_against_a_newcomer() {
        let policy = Policy { total: 4, ..POLICY };
        let mut slots = Slots::new(policy);
        let t0 = Instant::now();
        let pile: Vec<Probe> = (0..3).map(|_| Probe::default()).collect();
        for (n, probe) in pile.iter().enumerate() {
            slots.admit(ip("192.0.2.1"), false, t0 + secs(n as u64), probe.clone()).unwrap();
        }
        slots.admit(ip("192.0.2.2"), false, t0 + secs(2), Probe::default()).unwrap();
        // The table is full of connections a second or two old.
        let newcomer = slots.admit(ip("203.0.113.1"), false, t0 + secs(3), Probe::default());
        assert!(newcomer.is_some(), "an honest dialer was locked out by churn");
        assert_eq!(pile.iter().map(Probe::closed).collect::<Vec<_>>(), [false, false, true], "the source holding the most gave up its newest");
        // It still holds two, and the next newcomer's source holds none.
        assert!(slots.admit(ip("203.0.113.2"), false, t0 + secs(3), Probe::default()).is_some());
        assert_eq!(pile.iter().map(Probe::closed).collect::<Vec<_>>(), [false, true, true]);
        // Now every source holds one, and nobody gives way.
        assert!(slots.admit(ip("203.0.113.3"), false, t0 + secs(3), Probe::default()).is_none());
        assert_eq!(slots.len(), policy.total);
        // Sources with one connection each are equals: nobody gives way,
        // until the one that has held its slot longest has held it for the
        // idle deadline. Then it is the newcomer's turn, once.
        let mut slots = Slots::new(policy);
        let singles: Vec<Probe> = (0..4).map(|_| Probe::default()).collect();
        for (n, probe) in singles.iter().enumerate() {
            slots.admit(ip(&format!("192.0.2.{}", n + 1)), false, t0 + secs(n as u64), probe.clone()).unwrap();
        }
        assert!(slots.admit(ip("203.0.113.1"), false, t0 + secs(119), Probe::default()).is_none());
        for (_, e) in slots.entries.iter_mut() {
            e.last_heard = t0 + secs(119);
        }
        assert!(slots.admit(ip("203.0.113.1"), false, t0 + secs(120), Probe::default()).is_some());
        assert_eq!(singles.iter().map(Probe::closed).collect::<Vec<_>>(), [true, false, false, false]);
        assert!(slots.admit(ip("203.0.113.2"), false, t0 + secs(120), Probe::default()).is_none(), "one turn at a time");
        assert!(slots.admit(ip("203.0.113.1"), false, t0 + secs(122), Probe::default()).is_none(), "and not to add to a pile");
        // A vouched connection has no turn to give up.
        slots.note_verified(ip("192.0.2.2"), t0 + secs(121));
        assert!(slots.admit(ip("203.0.113.2"), false, t0 + secs(121), Probe::default()).is_none());
        assert!(slots.admit(ip("203.0.113.2"), false, t0 + secs(122), Probe::default()).is_some());
        assert_eq!(singles.iter().map(Probe::closed).collect::<Vec<_>>(), [true, false, true, false]);
        // And a source does not evict others to add to its own pile.
        let mut slots = Slots::new(policy);
        slots.admit(ip("192.0.2.1"), false, t0, Probe::default()).unwrap();
        slots.admit(ip("192.0.2.1"), false, t0, Probe::default()).unwrap();
        slots.admit(ip("192.0.2.2"), false, t0, Probe::default()).unwrap();
        slots.admit(ip("192.0.2.3"), false, t0, Probe::default()).unwrap();
        assert!(slots.admit(ip("192.0.2.2"), false, t0 + secs(2), Probe::default()).is_none());
        assert_eq!(slots.len(), policy.total);
    }

    #[test]
    fn vouching_expires_and_its_memory_is_bounded() {
        let mut slots = Slots::new(POLICY);
        let t0 = Instant::now();
        slots.note_verified(ip("::ffff:192.0.2.1"), t0);
        assert!(slots.source_vouched(ip("192.0.2.1"), t0 + secs(3599)));
        assert!(!slots.source_vouched(ip("192.0.2.1"), t0 + secs(3600)));
        // A fifth source displaces the least recently verified record.
        for n in 2..=5 {
            slots.note_verified(ip(&format!("192.0.2.{n}")), t0 + secs(n));
        }
        assert_eq!(slots.verified.len(), POLICY.vouched_sources);
        assert!(!slots.source_vouched(ip("192.0.2.1"), t0 + secs(10)));
        assert!(slots.source_vouched(ip("192.0.2.5"), t0 + secs(10)));
        // An authenticated handshake vouches for its own connection only.
        let pinned = slots.admit(ip("203.0.113.5"), false, t0, Probe::default()).unwrap();
        assert!(slots.mark_authenticated(pinned));
        assert_eq!(slots.standing_of(&slots.entries[&pinned], t0), VOUCHED);
        assert!(!slots.source_vouched(ip("203.0.113.5"), t0));
    }

    #[test]
    fn a_dropped_slot_is_released() {
        let slots = Arc::new(Mutex::new(Slots::new(POLICY)));
        let now = Instant::now();
        let slot = Slot::admit(&slots, ip("192.0.2.1"), Standing::Unconfigured, now, Probe::default()).unwrap();
        assert_eq!(slot.mark_valid(now), Some(true));
        assert_eq!(slots.lock().unwrap().len(), 1);
        // Released early by a closing connection, and again by the drop.
        slot.release();
        assert_eq!(slots.lock().unwrap().len(), 0);
        assert_eq!(slot.mark_valid(now), None);
        drop(slot);
        assert_eq!(slots.lock().unwrap().len(), 0);
    }

    // ── The mainnet shape (W4-1), on the policy the node runs ───────────────

    const EPOCH: u64 = 16 * 60;

    /// One node as both binaries dial: it holds one connection to the
    /// listener and dials again the moment that connection is closed.
    struct Dialer {
        ip: IpAddr,
        /// Seconds into each epoch at which this validator votes; `None` for
        /// a node that never says anything.
        votes_at: Option<u64>,
        slot: Option<(u64, Probe)>,
        last_spoke: Instant,
        refused: usize,
        closed_early: usize,
        delivered: usize,
    }

    impl Dialer {
        fn new(ip: IpAddr, votes_at: Option<u64>, now: Instant) -> Self {
            Self { ip, votes_at, slot: None, last_spoke: now, refused: 0, closed_early: 0, delivered: 0 }
        }

        fn connected(&self) -> bool {
            self.slot.as_ref().is_some_and(|(_, probe)| !probe.closed())
        }

        /// One second of this node's life. `peers` is how many `--peers`
        /// entries the listener has at this node's address.
        fn tick(&mut self, slots: &mut Slots<Probe>, peers: usize, second: u64, now: Instant) {
            if !self.connected() {
                if self.slot.take().is_some() && now.saturating_duration_since(self.last_spoke) < MAINNET.idle_close {
                    self.closed_early += 1;
                }
                let standing = Standing::for_source(peers, slots.configured_held(self.ip));
                let probe = Probe::default();
                match slots.admit_as(self.ip, standing, now, probe.clone()) {
                    Some(id) => {
                        self.slot = Some((id, probe));
                        self.last_spoke = now;
                    }
                    None => self.refused += 1,
                }
            }
            if self.votes_at.is_some_and(|at| second % EPOCH == at) {
                if let Some((id, _)) = self.slot.as_ref().filter(|(_, probe)| !probe.closed()) {
                    // Delivered, and then verified by the engine.
                    if slots.mark_valid(*id, now).is_some() {
                        slots.note_verified(self.ip, now);
                        self.delivered += 1;
                        self.last_spoke = now;
                    }
                }
            }
        }
    }

    fn fleet(ip: IpAddr, validators: usize, now: Instant) -> Vec<Dialer> {
        // Votes spread over the epoch, as committee assignment spreads them.
        (0..validators).map(|n| Dialer::new(ip, Some((n as u64 * 61 + 7) % EPOCH), now)).collect()
    }

    /// The required outcome: up to sixteen validators behind one address,
    /// whatever the listener's `--peers` says about them, are all connected
    /// at every moment, are never refused, are closed only at the idle
    /// deadline both binaries have, and deliver every vote. With the pending
    /// pool this replaced, four of them held a slot and the rest were refused.
    #[test]
    fn sixteen_validators_behind_one_address_all_stay_connected_and_deliver_every_vote() {
        for validators in [11usize, 13, 16] {
            for listed in [0usize, 1, 3, 6] {
                let t0 = Instant::now();
                let mut slots = Slots::new(MAINNET);
                let mut nodes = fleet(ip("100.64.1.52"), validators, t0);
                let epochs = 2;
                for second in 0..epochs * EPOCH {
                    let now = t0 + secs(second);
                    slots.reap(now);
                    for node in nodes.iter_mut() {
                        node.tick(&mut slots, listed, second, now);
                    }
                    assert_eq!(slots.len(), validators, "{validators} validators, {listed} listed, second {second}");
                }
                for node in &nodes {
                    assert_eq!(node.refused, 0, "{validators} validators, {listed} listed");
                    assert_eq!(node.closed_early, 0, "{validators} validators, {listed} listed");
                    assert_eq!(node.delivered as u64, epochs, "{validators} validators, {listed} listed");
                }
            }
        }
    }

    /// One address, a thousand connections that say nothing: it holds its
    /// share and not one more, for the idle deadline and no longer, and the
    /// honest fleet sharing the table never notices.
    #[test]
    fn a_thousand_idle_connections_from_one_address_hold_only_its_share() {
        let t0 = Instant::now();
        let mut slots = Slots::new(MAINNET);
        let mut honest = fleet(ip("100.64.1.52"), 16, t0);
        let flood: Vec<Probe> = (0..1000).map(|_| Probe::default()).collect();
        let mut admitted = 0usize;
        for second in 0..2 * EPOCH {
            let now = t0 + secs(second);
            slots.reap(now);
            for node in honest.iter_mut() {
                node.tick(&mut slots, 0, second, now);
            }
            // Ten new connections a second for the first hundred seconds.
            if second < 100 {
                for probe in &flood[second as usize * 10..][..10] {
                    admitted += usize::from(slots.admit(ip("203.0.113.66"), false, now, probe.clone()).is_some());
                }
            }
            assert!(slots.len() - 16 <= MAINNET.per_source, "second {second}");
            assert_eq!(flood.iter().filter(|p| !p.closed()).count() - (1000 - admitted), slots.len() - 16);
        }
        assert_eq!(admitted, MAINNET.per_source, "the share, once: nothing it held was ever replaced");
        assert_eq!(slots.len(), 16, "every idle connection was closed at the idle deadline");
        for node in &honest {
            assert_eq!((node.refused, node.closed_early, node.delivered), (0, 0, 2));
        }
    }

    fn flood_source(n: usize) -> IpAddr {
        ip(&format!("203.0.{}.{}", 113 + n / 250, n % 250 + 1))
    }

    fn is_flood<H>(entry: &Entry<H>) -> bool {
        matches!(entry.source, IpAddr::V4(v4) if v4.octets()[0] == 203)
    }

    /// The fleet as it is deployed: a listener on one of the three listed
    /// hosts (about 21 `--peers` entries at each), dialed by the 37 other
    /// listed validators, by 13 and 11 validators on two hosts nobody lists,
    /// by two archival nodes and by 44 external validators, some sharing an
    /// address. Then 250 addresses that each open four connections every ten
    /// seconds (a thousand at a time), which say nothing useful and are kept
    /// alive for as long as they can be.
    #[test]
    fn idle_connections_from_250_addresses_are_bounded_and_displace_no_proven_peer() {
        let t0 = Instant::now();
        let mut slots = Slots::new(MAINNET);
        let listed: [(&str, usize); 3] = [("100.64.0.185", 11), ("100.64.0.8", 13), ("100.64.0.251", 13)];
        let mut nodes: Vec<(usize, Dialer)> = Vec::new();
        for (host, validators) in listed {
            nodes.extend(fleet(ip(host), validators, t0).into_iter().map(|node| (21, node)));
        }
        nodes.extend(fleet(ip("100.64.1.52"), 13, t0).into_iter().map(|node| (0, node)));
        nodes.extend(fleet(ip("100.64.1.231"), 11, t0).into_iter().map(|node| (0, node)));
        // 44 external validators: twenty alone, and three operators with
        // eight validators each behind one address.
        for n in 0..20u64 {
            nodes.push((0, Dialer::new(ip(&format!("198.51.100.{}", n + 1)), Some((n * 47 + 3) % EPOCH), t0)));
        }
        for operator in 0..3u64 {
            let host = ip(&format!("198.51.101.{}", operator + 1));
            nodes.extend((0..8u64).map(|n| (0, Dialer::new(host, Some((operator * 300 + n * 31) % EPOCH), t0))));
        }
        // Two archival nodes: they never vote, so nothing ever vouches for them.
        let archival_from = nodes.len();
        nodes.extend((0..2).map(|_| (0, Dialer::new(ip("100.64.2.231"), None, t0))));
        let honest = nodes.len();
        assert_eq!(honest, 107);

        // Runs seconds `from..until`; returns the fullest the table got, the
        // connections the flood tried, and the seconds that ended with an
        // archival node connected.
        let mut run = |nodes: &mut Vec<(usize, Dialer)>, from: u64, until: u64, flood: bool| {
            let (mut worst, mut attempts, mut archival_seconds) = (0usize, 0usize, 0u64);
            for second in from..until {
                let now = t0 + secs(second);
                slots.reap(now);
                for (listed, node) in nodes.iter_mut() {
                    node.tick(&mut slots, *listed, second, now);
                }
                if flood && second % 10 == 0 {
                    for n in 0..250 {
                        for _ in 0..4 {
                            attempts += 1;
                            slots.admit(flood_source(n), false, now, Probe::default());
                        }
                    }
                    // A well-formed frame on each, so the idle deadline never
                    // frees one.
                    let ids: Vec<u64> = slots.entries.iter().filter(|(_, e)| is_flood(e)).map(|(id, _)| *id).collect();
                    for id in ids {
                        slots.mark_heard(id, now);
                    }
                }
                assert!(slots.len() <= MAINNET.total);
                worst = worst.max(slots.len());
                archival_seconds += u64::from(nodes[archival_from..].iter().any(|(_, node)| node.connected()));
            }
            (worst, attempts, slots.entries.values().filter(|e| is_flood(e)).count(), archival_seconds)
        };

        // The first epoch is quiet: everyone connects and votes once.
        let (worst, ..) = run(&mut nodes, 0, EPOCH, false);
        assert_eq!(worst, honest, "the honest fleet alone leaves the table 21 slots short of full");
        assert!(nodes.iter().all(|(_, node)| node.refused == 0 && node.closed_early == 0));

        // An epoch of flood.
        let (worst, attempts, flood_held, archival_seconds) = run(&mut nodes, EPOCH, 2 * EPOCH, true);
        assert!(attempts >= 1000);
        assert_eq!(worst, MAINNET.total, "the flood fills what is free and nothing more");
        assert!(flood_held <= MAINNET.total - (honest - 2), "{flood_held}");
        for (n, (_, node)) in nodes[..archival_from].iter().enumerate() {
            assert_eq!((node.refused, node.closed_early, node.delivered), (0, 0, 2), "validator {n}");
        }
        // The price of having no way to prove itself: the archival address is
        // an equal among the flood's addresses, so it is held to one of its
        // two connections and has to take turns for that one. Listing its
        // address in `--peers` removes even that.
        assert!(archival_seconds >= EPOCH * 9 / 10, "{archival_seconds}");

        // The flood stops; its connections idle out and everyone is back.
        let (.., flood_held, _) = run(&mut nodes, 2 * EPOCH, 2 * EPOCH + 200, false);
        assert_eq!(flood_held, 0);
        assert_eq!(slots.len(), honest);
        assert!(nodes.iter().all(|(_, node)| node.connected()));
    }

    /// The worst moment: the listener has just restarted, so it remembers no
    /// proof, and a flood from twice as many addresses as it has slots got
    /// there first and never lets go. An unlisted fleet is then one unproven
    /// source among equals: it waits for a turn and holds one connection
    /// while its turn lasts. That is enough: the first vote one of those
    /// connections carries is verified, and from then on the whole fleet is
    /// back and stays. (Both older binaries would have refused all thirteen
    /// for as long as the flood lasted.)
    #[test]
    fn a_fleet_caught_unproven_by_a_flood_recovers_with_its_first_verified_vote() {
        let t0 = Instant::now();
        let mut slots = Slots::new(MAINNET);
        for n in 0..MAINNET.total {
            slots.admit(flood_source(n), false, t0, Probe::default()).unwrap();
        }
        let mut nodes = fleet(ip("100.64.1.52"), 13, t0);
        let mut proven_at = None;
        let mut longest_wait = 0u64;
        let mut waiting = 0u64;
        for second in 0..600 {
            let now = t0 + secs(second);
            slots.reap(now);
            // Honest nodes redial at once; which of them gets there first varies.
            let first = (second % 13) as usize;
            for n in (first..13).chain(0..first) {
                nodes[n].tick(&mut slots, 0, second, now);
            }
            // The flood keeps every one of its connections alive and, every
            // five seconds, tries to replace any it lost from all 250 addresses.
            let ids: Vec<u64> = slots.entries.iter().filter(|(_, e)| is_flood(e)).map(|(id, _)| *id).collect();
            for id in ids {
                slots.mark_heard(id, now);
            }
            if second % 5 == 0 {
                for n in 0..250 {
                    slots.admit(flood_source(n), false, now, Probe::default());
                }
            }
            assert!(slots.len() <= MAINNET.total);
            let connected = nodes.iter().filter(|node| node.connected()).count();
            let delivered: usize = nodes.iter().map(|node| node.delivered).sum();
            match proven_at {
                None if delivered > 0 => proven_at = Some(second),
                None => {
                    assert!(connected <= 1, "an unproven source is held to an equal share");
                    waiting = if connected == 0 { waiting + 1 } else { 0 };
                    longest_wait = longest_wait.max(waiting);
                }
                Some(at) if second > at + 1 => assert_eq!(connected, 13, "second {second}, proven at {at}"),
                Some(_) => {}
            }
        }
        let proven_at = proven_at.expect("no vote of the fleet reached the listener");
        assert!(longest_wait <= MAINNET.idle_close.as_secs(), "{longest_wait}");
        assert!(proven_at <= 2 * MAINNET.idle_close.as_secs(), "{proven_at}");
    }
}
