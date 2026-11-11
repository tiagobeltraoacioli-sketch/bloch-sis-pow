// SPDX-License-Identifier: AGPL-3.0-or-later
//! Admission, usefulness and eviction for the devnet mesh's inbound slots.
//!
//! The mesh accepts before it authenticates, so the slot table has to assume
//! that any inbound connection may be worthless. It keeps three facts per
//! connection and derives every decision from them:
//!
//! - **pending**: not yet through an authenticated handshake and no valid
//!   frame delivered. Pending connections live in a small pool of their own
//!   with a short deadline, so they cannot occupy the main pool.
//! - **useful**: delivered at least one valid frame. The caller offers an
//!   unconfigured connection to the sync scheduler only once it is useful.
//! - **configured**: its source is one of the operator's own `--peers`. Such
//!   a connection is never refused by a share, never expired and never
//!   evicted; only the absolute table size can turn it away, and only when
//!   every slot is already held by another configured source. The standing
//!   is granted by source address at accept, before any handshake, so it is
//!   rationed by the number of peers the operator configured at that address
//!   (see [`Standing::for_source`]): whoever else can open connections from
//!   there gets a bounded number of these slots, and no more evictions than
//!   the configured peers themselves could cause.
//!
//! Sources are compared by [`crate::connection_limit::limit_key`]: an IPv4
//! address, or an IPv6 /64.
use std::collections::BTreeMap;
use std::net::{IpAddr, Shutdown, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
pub(super) struct Policy {
    /// Every inbound connection, pending included.
    pub(super) total: usize,
    /// Connections that are still pending, across all sources.
    pub(super) pending: usize,
    /// Connections one source may hold, pending included.
    pub(super) per_source: usize,
    /// Pending connections one source may hold.
    pub(super) pending_per_source: usize,
    /// A pending connection older than this is closed.
    pub(super) pending_deadline: Duration,
    /// A connection younger than this is not evicted to make room for an
    /// unconfigured newcomer: an honest dialer always gets this long to finish
    /// its handshake and send a first frame, however fast others arrive.
    pub(super) eviction_grace: Duration,
    /// A useful connection with no valid frame for this long may be evicted
    /// when the table is full.
    pub(super) idle_eviction: Duration,
    /// A connection with no valid frame for this long is closed outright.
    pub(super) idle_close: Duration,
}

/// How the table treats a connection, decided when it is accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Standing {
    /// Subject to every share, the pending pool and the deadlines.
    Unconfigured,
    /// From a source the operator configured. `may_displace` adds the right
    /// to take the slot of a young or busy unconfigured connection when the
    /// table is full.
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
    /// a busy unconfigured connection is what makes room for a configured
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
    established: bool,
    useful: bool,
    accepted: Instant,
    last_active: Instant,
    handle: H,
}

pub(super) struct Slots<H: Close> {
    policy: Policy,
    next_id: u64,
    entries: BTreeMap<u64, Entry<H>>,
}

impl<H: Close> Slots<H> {
    pub(super) fn new(policy: Policy) -> Self {
        Self { policy, next_id: 0, entries: BTreeMap::new() }
    }

    fn evict(&mut self, id: u64) {
        if let Some(entry) = self.entries.remove(&id) {
            entry.handle.close();
        }
    }

    /// Close every unconfigured connection that is past its deadline.
    pub(super) fn reap(&mut self, now: Instant) {
        let policy = self.policy;
        let expired: Vec<u64> = self
            .entries
            .iter()
            .filter(|(_, e)| {
                !e.configured
                    && if e.established {
                        now.saturating_duration_since(e.last_active) >= policy.idle_close
                    } else {
                        now.saturating_duration_since(e.accepted) >= policy.pending_deadline
                    }
            })
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            self.evict(id);
        }
    }

    /// The connection to give up for a newcomer, if any may be given up.
    ///
    /// Order: pending, then established but never useful, then useful but
    /// idle; oldest first inside each class. A configured newcomer may also
    /// displace a young or busy unconfigured connection, least recently
    /// active first. Configured connections are never candidates.
    fn victim(&self, now: Instant, for_configured: bool) -> Option<u64> {
        let policy = self.policy;
        self.entries
            .iter()
            .filter(|(_, e)| !e.configured)
            .filter_map(|(id, e)| {
                let age = now.saturating_duration_since(e.accepted);
                let idle = now.saturating_duration_since(e.last_active);
                let class = if !e.useful && age >= policy.eviction_grace {
                    if e.established { (1u8, age) } else { (0u8, age) }
                } else if e.useful && idle >= policy.idle_eviction {
                    (2, idle)
                } else if for_configured {
                    (3, idle)
                } else {
                    return None;
                };
                Some((class, *id))
            })
            .min_by(|((class_a, time_a), _), ((class_b, time_b), _)| {
                class_a.cmp(class_b).then(time_b.cmp(time_a))
            })
            .map(|(_, id)| id)
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
        if !configured {
            let mine = self.entries.values().filter(|e| !e.configured && e.source == source);
            let (held, pending) = mine.fold((0usize, 0usize), |(held, pending), e| {
                (held.saturating_add(1), pending.saturating_add(usize::from(!e.established)))
            });
            if held >= policy.per_source || pending >= policy.pending_per_source {
                return None;
            }
            if self.pending() >= policy.pending {
                let oldest = self
                    .entries
                    .iter()
                    .filter(|(_, e)| !e.established)
                    .min_by_key(|(_, e)| e.accepted)
                    .filter(|(_, e)| now.saturating_duration_since(e.accepted) >= policy.eviction_grace)
                    .map(|(id, _)| *id);
                // Nothing is past the grace. The grace protects a dialer
                // that is still shaking hands; it must not let a few sources
                // that keep reopening their whole pending share hold the pool
                // against everyone else. A source that would still hold more
                // pending connections than the newcomer's, after giving one
                // up, gives up its oldest.
                let make_room = oldest.or_else(|| self.most_pending_source_oldest(pending.saturating_add(1)))?;
                self.evict(make_room);
            }
        }
        if self.entries.len() >= policy.total {
            let victim = self.victim(now, matches!(standing, Standing::Configured { may_displace: true }))?;
            self.evict(victim);
        }
        let id = self.next_id;
        self.next_id = self.next_id.checked_add(1)?;
        self.entries.insert(id, Entry {
            source,
            configured,
            // A configured source skips the pending pool: the operator vouched
            // for it. It still has to deliver a frame to be called useful.
            established: configured,
            useful: false,
            accepted: now,
            last_active: now,
            handle,
        });
        Some(id)
    }

    /// The oldest pending connection of the source holding the most pending
    /// connections, if that source holds more than `floor` of them.
    fn most_pending_source_oldest(&self, floor: usize) -> Option<u64> {
        let mut by_source: BTreeMap<IpAddr, (usize, Instant, u64)> = BTreeMap::new();
        for (id, e) in self.entries.iter().filter(|(_, e)| !e.established) {
            let seen = by_source.entry(e.source).or_insert((0, e.accepted, *id));
            seen.0 = seen.0.saturating_add(1);
            if e.accepted < seen.1 {
                (seen.1, seen.2) = (e.accepted, *id);
            }
        }
        by_source
            .values()
            .filter(|(count, _, _)| *count > floor)
            .max_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)))
            .map(|(_, _, id)| *id)
    }

    /// The connection completed an authenticated handshake: it leaves the
    /// pending pool. False when the slot is gone (expired or evicted).
    pub(super) fn mark_established(&mut self, id: u64) -> bool {
        self.entries.get_mut(&id).map(|e| e.established = true).is_some()
    }

    /// The connection delivered a valid frame. `Some(true)` the first time,
    /// `None` when the slot is gone (expired or evicted).
    pub(super) fn mark_valid(&mut self, id: u64, now: Instant) -> Option<bool> {
        let entry = self.entries.get_mut(&id)?;
        let first = !entry.useful;
        entry.established = true;
        entry.useful = true;
        entry.last_active = now;
        Some(first)
    }

    /// A frame of a known type was refused by the queue budget before it
    /// could be decoded. That proves nothing, so it promotes nobody; for a
    /// connection that is already useful it still counts as activity, so a
    /// node that is shedding load does not also expire its honest peers.
    pub(super) fn mark_shed(&mut self, id: u64, now: Instant) {
        if let Some(entry) = self.entries.get_mut(&id).filter(|e| e.useful) {
            entry.last_active = now;
        }
    }

    /// The connection asked for blocks and a serving worker took the request.
    /// That is activity, and it is all a node that is still catching up has
    /// to say, so the connection leaves the pending pool and stays open. It
    /// is not usefulness: nine bytes prove nothing, so the connection remains
    /// the first to go when the table is full. False when the slot is gone.
    pub(super) fn mark_requested(&mut self, id: u64, now: Instant) -> bool {
        let Some(entry) = self.entries.get_mut(&id) else { return false };
        entry.established = true;
        entry.last_active = now;
        true
    }

    pub(super) fn release(&mut self, id: u64) {
        self.entries.remove(&id);
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(super) fn pending(&self) -> usize {
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

    pub(super) fn mark_established(&self) -> bool {
        self.slots.lock().is_ok_and(|mut slots| slots.mark_established(self.id))
    }

    pub(super) fn mark_valid(&self, now: Instant) -> Option<bool> {
        self.slots.lock().ok()?.mark_valid(self.id, now)
    }

    pub(super) fn mark_shed(&self, now: Instant) {
        if let Ok(mut slots) = self.slots.lock() {
            slots.mark_shed(self.id, now);
        }
    }
}

impl<H: Close> Drop for Slot<H> {
    fn drop(&mut self) {
        if let Ok(mut slots) = self.slots.lock() {
            slots.release(self.id);
        }
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
        pending: 3,
        per_source: 4,
        pending_per_source: 2,
        pending_deadline: Duration::from_secs(30),
        eviction_grace: Duration::from_secs(5),
        idle_eviction: Duration::from_secs(30),
        idle_close: Duration::from_secs(120),
    };

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
        // Two pending is the pending share; the third is refused, and so is
        // another address inside the same /64 or the IPv4-mapped form.
        let a = slots.admit(ip("2001:db8:1:2::1"), false, t0, Probe::default()).unwrap();
        let b = slots.admit(ip("2001:db8:1:2:ffff::9"), false, t0, Probe::default()).unwrap();
        assert!(slots.admit(ip("2001:db8:1:2::77"), false, t0, Probe::default()).is_none());
        // Proving useful frees the pending share but not the total share.
        assert_eq!(slots.mark_valid(a, t0), Some(true));
        assert_eq!(slots.mark_valid(b, t0), Some(true));
        let c = slots.admit(ip("192.0.2.7"), false, t0, Probe::default()).unwrap();
        let d = slots.admit(ip("::ffff:192.0.2.7"), false, t0, Probe::default()).unwrap();
        assert!(slots.admit(ip("192.0.2.7"), false, t0, Probe::default()).is_none());
        slots.release(c);
        slots.release(d);
        let c = slots.admit(ip("2001:db8:1:2::3"), false, t0, Probe::default()).unwrap();
        let d = slots.admit(ip("2001:db8:1:2::4"), false, t0, Probe::default()).unwrap();
        assert_eq!(slots.mark_valid(c, t0), Some(true));
        assert_eq!(slots.mark_valid(d, t0), Some(true));
        assert!(slots.admit(ip("2001:db8:1:2::5"), false, t0, Probe::default()).is_none());
        // A neighbouring /64 is a different source.
        assert!(slots.admit(ip("2001:db8:1:3::5"), false, t0, Probe::default()).is_some());
        // A configured source has no share.
        assert!(slots.admit(ip("2001:db8:1:2::6"), true, t0, Probe::default()).is_some());
    }

    #[test]
    fn pending_connections_expire_and_free_their_slot() {
        let mut slots = Slots::new(POLICY);
        let t0 = Instant::now();
        let silent = Probe::default();
        let sealed = Probe::default();
        let proven = Probe::default();
        let configured = Probe::default();
        let silent_id = slots.admit(ip("192.0.2.1"), false, t0, silent.clone()).unwrap();
        let sealed_id = slots.admit(ip("192.0.2.2"), false, t0, sealed.clone()).unwrap();
        let proven_id = slots.admit(ip("192.0.2.3"), false, t0, proven.clone()).unwrap();
        slots.admit(ip("192.0.2.4"), true, t0, configured.clone()).unwrap();
        assert!(slots.mark_established(sealed_id));
        assert_eq!(slots.mark_valid(proven_id, t0), Some(true));
        assert_eq!(slots.mark_valid(proven_id, t0), Some(false));
        assert_eq!((slots.len(), slots.pending()), (4, 1));

        slots.reap(t0 + secs(29));
        assert!(!silent.closed());
        slots.reap(t0 + secs(30));
        assert!(silent.closed(), "a pending connection is closed at its deadline");
        assert_eq!((slots.len(), slots.pending()), (3, 0));
        assert_eq!(slots.mark_valid(silent_id, t0 + secs(31)), None, "an expired slot cannot come back");
        assert!(!slots.mark_established(silent_id));

        // Established connections get the long idle deadline, and a frame the
        // budget shed keeps a useful connection alive without proving a
        // silent one.
        slots.mark_shed(proven_id, t0 + secs(100));
        slots.mark_shed(sealed_id, t0 + secs(100));
        slots.reap(t0 + secs(120));
        assert!(sealed.closed(), "handshake alone does not hold a slot forever");
        assert!(!proven.closed());
        slots.reap(t0 + secs(220));
        assert!(proven.closed());
        assert!(!configured.closed(), "a configured peer is never expired");
        assert_eq!(slots.len(), 1);
    }

    #[test]
    fn a_full_pending_pool_turns_over_only_after_the_grace() {
        let mut slots = Slots::new(POLICY);
        let t0 = Instant::now();
        let first = Probe::default();
        slots.admit(ip("192.0.2.1"), false, t0, first.clone()).unwrap();
        slots.admit(ip("192.0.2.2"), false, t0 + secs(1), Probe::default()).unwrap();
        slots.admit(ip("192.0.2.3"), false, t0 + secs(2), Probe::default()).unwrap();
        assert!(slots.admit(ip("192.0.2.4"), false, t0 + secs(4), Probe::default()).is_none());
        assert!(!first.closed());
        assert!(slots.admit(ip("192.0.2.4"), false, t0 + secs(5), Probe::default()).is_some());
        assert!(first.closed(), "the oldest pending connection makes room");
        assert_eq!((slots.len(), slots.pending()), (3, 3));
    }

    #[test]
    fn eviction_prefers_never_useful_peers_and_spares_configured_ones() {
        let mut slots = Slots::new(POLICY);
        let t0 = Instant::now();
        let configured = Probe::default();
        let busy = Probe::default();
        let idle = Probe::default();
        let older_idle = Probe::default();
        let sealed = Probe::default();
        let pending = Probe::default();
        // A configured peer that never sends anything is the oldest and the
        // least useful entry in the table, and must still survive everything.
        slots.admit(ip("198.51.100.1"), true, t0, configured.clone()).unwrap();
        let older_idle_id = slots.admit(ip("192.0.2.1"), false, t0, older_idle.clone()).unwrap();
        let idle_id = slots.admit(ip("192.0.2.2"), false, t0, idle.clone()).unwrap();
        let busy_id = slots.admit(ip("192.0.2.3"), false, t0, busy.clone()).unwrap();
        slots.mark_valid(older_idle_id, t0 + secs(1));
        slots.mark_valid(idle_id, t0 + secs(2));
        let sealed_id = slots.admit(ip("192.0.2.4"), false, t0 + secs(3), sealed.clone()).unwrap();
        slots.mark_established(sealed_id);
        slots.admit(ip("192.0.2.5"), false, t0 + secs(4), pending.clone()).unwrap();
        assert_eq!(slots.len(), POLICY.total);

        let now = t0 + secs(40);
        slots.mark_valid(busy_id, now);
        let closed = |probes: &[&Probe]| probes.iter().map(|p| p.closed()).collect::<Vec<_>>();
        let all = [&pending, &sealed, &older_idle, &idle, &busy, &configured];

        // The table is full. Each newcomer proves useful at once, so it is
        // never itself the next victim.
        let arrive = |slots: &mut Slots<Probe>, n: u8| {
            let id = slots.admit(ip(&format!("203.0.113.{n}")), false, now, Probe::default());
            if let Some(id) = id {
                slots.mark_valid(id, now);
            }
            id.is_some()
        };
        // The pending one was already past its deadline; `admit` reaps it.
        assert!(arrive(&mut slots, 1));
        assert_eq!(closed(&all), [true, false, false, false, false, false]);
        assert!(arrive(&mut slots, 2));
        assert_eq!(closed(&all), [true, true, false, false, false, false], "never useful goes before idle");
        assert!(arrive(&mut slots, 3));
        assert_eq!(closed(&all), [true, true, true, false, false, false], "longest idle goes first");
        assert!(arrive(&mut slots, 4));
        assert_eq!(closed(&all), [true, true, true, true, false, false]);
        // Only busy and configured connections are left: an unconfigured
        // newcomer is refused rather than displacing either.
        assert!(!arrive(&mut slots, 5));
        assert_eq!(closed(&all), [true, true, true, true, false, false]);
        assert_eq!(slots.len(), POLICY.total);

        // A configured newcomer is not refused while an unconfigured
        // connection exists, and still never displaces a configured one.
        for n in 2..=6 {
            assert!(slots.admit(ip(&format!("198.51.100.{n}")), true, now, Probe::default()).is_some());
        }
        assert!(busy.closed());
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

        // A full table of busy, useful, unconfigured peers, and a flood of
        // connections from an address at which one peer is configured.
        let mut slots = Slots::new(POLICY);
        let t0 = Instant::now();
        let honest: Vec<Probe> = (0..POLICY.total).map(|_| Probe::default()).collect();
        for (n, probe) in honest.iter().enumerate() {
            let id = slots.admit(ip(&format!("192.0.2.{}", n + 1)), false, t0, probe.clone()).unwrap();
            slots.mark_valid(id, t0);
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

    /// V2-7: asking for blocks keeps a connection open but never makes it
    /// useful, so it is the first to go when the table is full.
    #[test]
    fn a_connection_that_only_asks_for_blocks_is_never_useful() {
        let mut slots = Slots::new(POLICY);
        let t0 = Instant::now();
        let asker = Probe::default();
        let asker_id = slots.admit(ip("192.0.2.1"), false, t0, asker.clone()).unwrap();
        assert!(slots.mark_requested(asker_id, t0 + secs(1)));
        assert_eq!(slots.pending(), 0, "an accepted request leaves the pending pool");
        // Requests are activity: no idle close while they keep coming.
        assert!(slots.mark_requested(asker_id, t0 + secs(100)));
        slots.reap(t0 + secs(200));
        assert!(!asker.closed());
        assert_eq!(slots.mark_valid(asker_id, t0 + secs(200)), Some(true), "its first real frame is still its first");
        slots.release(asker_id);

        // A table full of connections that only ask: a newcomer always gets
        // in, at the cost of the oldest of them, however recently it asked.
        let askers: Vec<Probe> = (0..POLICY.total).map(|_| Probe::default()).collect();
        let now = t0 + secs(300);
        for (n, probe) in askers.iter().enumerate() {
            let id = slots.admit(ip(&format!("192.0.2.{}", n + 1)), false, now, probe.clone()).unwrap();
            assert!(slots.mark_requested(id, now));
        }
        let later = now + secs(6);
        for (_, e) in slots.entries.iter_mut() {
            e.last_active = later;
        }
        assert!(slots.admit(ip("203.0.113.1"), false, later, Probe::default()).is_some());
        assert!(askers[0].closed());
        assert_eq!(askers.iter().filter(|p| p.closed()).count(), 1);
        assert!(!slots.mark_requested(asker_id + 1, later), "an evicted slot cannot come back");
    }

    /// V2-7: sources that keep their whole pending share younger than the
    /// grace do not shut a newcomer out of the pending pool.
    #[test]
    fn churning_sources_cannot_hold_the_pending_pool_against_a_newcomer() {
        let policy = Policy { total: 16, pending: 4, ..POLICY };
        let mut slots = Slots::new(policy);
        let t0 = Instant::now();
        let first = Probe::default();
        slots.admit(ip("192.0.2.1"), false, t0, first.clone()).unwrap();
        slots.admit(ip("192.0.2.1"), false, t0 + secs(1), Probe::default()).unwrap();
        slots.admit(ip("192.0.2.2"), false, t0 + secs(1), Probe::default()).unwrap();
        slots.admit(ip("192.0.2.2"), false, t0 + secs(1), Probe::default()).unwrap();
        // The pool is full and nothing in it is past the grace.
        let newcomer = slots.admit(ip("203.0.113.1"), false, t0 + secs(2), Probe::default());
        assert!(newcomer.is_some(), "an honest dialer was locked out by pending churn");
        assert!(first.closed(), "the source holding the most gave up its oldest");
        assert_eq!(slots.pending(), policy.pending);
        // Sources with one pending connection each are equals: the grace
        // holds between them, as before.
        let mut slots = Slots::new(policy);
        let singles: Vec<Probe> = (0..4).map(|_| Probe::default()).collect();
        for (n, probe) in singles.iter().enumerate() {
            slots.admit(ip(&format!("192.0.2.{}", n + 1)), false, t0, probe.clone()).unwrap();
        }
        assert!(slots.admit(ip("203.0.113.1"), false, t0 + secs(2), Probe::default()).is_none());
        // And a source does not evict others to add to its own pile.
        let mut slots = Slots::new(policy);
        slots.admit(ip("192.0.2.1"), false, t0, Probe::default()).unwrap();
        slots.admit(ip("192.0.2.1"), false, t0, Probe::default()).unwrap();
        slots.admit(ip("192.0.2.2"), false, t0, Probe::default()).unwrap();
        slots.admit(ip("192.0.2.3"), false, t0, Probe::default()).unwrap();
        assert!(slots.admit(ip("192.0.2.2"), false, t0 + secs(2), Probe::default()).is_none());
        assert!(singles.iter().all(|p| !p.closed()));
    }

    #[test]
    fn a_dropped_slot_is_released() {
        let slots = Arc::new(Mutex::new(Slots::new(POLICY)));
        let now = Instant::now();
        let slot = Slot::admit(&slots, ip("192.0.2.1"), Standing::Unconfigured, now, Probe::default()).unwrap();
        assert_eq!(slot.mark_valid(now), Some(true));
        assert_eq!(slots.lock().unwrap().len(), 1);
        drop(slot);
        assert_eq!(slots.lock().unwrap().len(), 0);
    }
}
