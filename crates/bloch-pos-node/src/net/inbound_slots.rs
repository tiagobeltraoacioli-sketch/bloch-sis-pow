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
//!   every slot is already held by another configured source.
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
    pub(super) fn admit(&mut self, ip: IpAddr, configured: bool, now: Instant, handle: H) -> Option<u64> {
        self.reap(now);
        let policy = self.policy;
        let source = crate::connection_limit::limit_key(ip);
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
                    .map(|(id, _)| *id)?;
                self.evict(oldest);
            }
        }
        if self.entries.len() >= policy.total {
            let victim = self.victim(now, configured)?;
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
        configured: bool,
        now: Instant,
        handle: H,
    ) -> Option<Self> {
        let id = slots.lock().ok()?.admit(ip, configured, now, handle)?;
        Some(Self { slots: slots.clone(), id })
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

    #[test]
    fn a_dropped_slot_is_released() {
        let slots = Arc::new(Mutex::new(Slots::new(POLICY)));
        let now = Instant::now();
        let slot = Slot::admit(&slots, ip("192.0.2.1"), false, now, Probe::default()).unwrap();
        assert_eq!(slot.mark_valid(now), Some(true));
        assert_eq!(slots.lock().unwrap().len(), 1);
        drop(slot);
        assert_eq!(slots.lock().unwrap().len(), 0);
    }
}
