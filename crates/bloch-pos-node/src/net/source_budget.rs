//! Backlog admission, not identity reputation or a consensus rule.
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use super::{class_bytes_cap, EventClass};

const SOURCE_EVENTS: usize = 256;
const SOURCE_BYTES: usize = 16 * 1024 * 1024;
const MAX_SOURCES: usize = 1024;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(super) enum Source {
    Ip(IpAddr),
    Peer(Vec<u8>),
}

impl Source {
    pub(super) fn ip(ip: IpAddr) -> Self {
        Self::Ip(match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
            _ => ip,
        })
    }
}

#[derive(Debug, Default)]
struct Usage { count: usize, bytes: usize }

#[derive(Debug, Default)]
pub(super) struct Registry {
    sources: HashMap<Source, Usage>,
    total: Usage,
}

/// Shared by Origin clones. The entry disappears when the last message from
/// this source finishes, so reconnects share outstanding work without an
/// ever-growing table of historical IPs or peer identities.
#[derive(Debug)]
pub(crate) struct Reservation {
    registry: Arc<Mutex<Registry>>,
    source: Source,
    bytes: usize,
}

impl Registry {
    pub(super) fn reserve(
        registry: &Arc<Mutex<Self>>, source: Source, class: EventClass,
        bytes: usize, count_cap: usize, bytes_cap: usize,
    ) -> Option<Arc<Reservation>> {
        let mut state = registry.lock().ok()?;
        let usage = state.sources.get(&source);
        let count = usage.map_or(0, |u| u.count);
        let source_bytes = usage.map_or(0, |u| u.bytes).checked_add(bytes)?;
        let total_bytes = state.total.bytes.checked_add(bytes)?;
        if count >= SOURCE_EVENTS || source_bytes > class_bytes_cap(class, SOURCE_BYTES)
            || state.total.count >= count_cap
            || total_bytes > class_bytes_cap(class, bytes_cap)
            || (usage.is_none() && state.sources.len() >= MAX_SOURCES)
        { return None; }
        let usage = state.sources.entry(source.clone()).or_default();
        usage.count = usage.count.saturating_add(1);
        usage.bytes = source_bytes;
        state.total.count = state.total.count.saturating_add(1);
        state.total.bytes = total_bytes;
        Some(Arc::new(Reservation { registry: registry.clone(), source, bytes }))
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        // A panic must not make a reservation permanent.
        let mut state = self.registry.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(usage) = state.sources.get_mut(&self.source) {
            usage.count = usage.count.saturating_sub(1);
            usage.bytes = usage.bytes.saturating_sub(self.bytes);
            if usage.count == 0 { state.sources.remove(&self.source); }
        }
        state.total.count = state.total.count.saturating_sub(1);
        state.total.bytes = state.total.bytes.saturating_sub(self.bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn reserve(registry: &Arc<Mutex<Registry>>, source: Source, class: EventClass, bytes: usize) -> Option<Arc<Reservation>> {
        Registry::reserve(registry, source, class, bytes, 4096, 64 * 1024 * 1024)
    }

    #[test]
    fn source_flood_leaves_room_for_another_peer_and_clone_holds_its_charge() {
        let registry = Arc::new(Mutex::new(Registry::default()));
        let bad = Source::Peer(vec![1]);
        let honest = Source::Peer(vec![2]);
        let mut held = Vec::new();
        for _ in 0..SOURCE_EVENTS {
            held.push(reserve(&registry, bad.clone(), EventClass::Attestation, 512).unwrap());
        }
        assert!(reserve(&registry, bad.clone(), EventClass::Transaction, 1).is_none());
        let last = held.pop().unwrap();
        let clone = last.clone();
        drop(last);
        assert!(reserve(&registry, bad.clone(), EventClass::Block, 1).is_none());
        let honest_guard = reserve(&registry, honest, EventClass::Block, 8 * 1024 * 1024).unwrap();
        drop(clone);
        assert!(reserve(&registry, bad, EventClass::Block, 1).is_some());
        drop(held);
        drop(honest_guard);
        let state = registry.lock().unwrap();
        assert!(state.sources.is_empty());
        assert_eq!((state.total.count, state.total.bytes), (0, 0));
    }

    #[test]
    fn reconnect_and_mapped_ipv6_share_nat_budget_without_historical_entries() {
        let registry = Arc::new(Mutex::new(Registry::default()));
        let v4 = Source::ip("192.0.2.1".parse().unwrap());
        let mapped = Source::ip("::ffff:192.0.2.1".parse().unwrap());
        assert_eq!(v4, mapped);
        let held = reserve(&registry, v4, EventClass::Transaction, SOURCE_BYTES / 2).unwrap();
        assert!(reserve(&registry, mapped.clone(), EventClass::Transaction, 1).is_none());
        // Reserved block headroom remains available behind the same NAT.
        assert!(reserve(&registry, mapped.clone(), EventClass::Block, SOURCE_BYTES / 2).is_some());
        drop(held);
        assert!(reserve(&registry, mapped, EventClass::Transaction, 1).is_some());
        for n in 0u32..4096 {
            assert!(reserve(&registry, Source::Peer(n.to_le_bytes().to_vec()), EventClass::Block, 1).is_some());
        }
        assert!(registry.lock().unwrap().sources.is_empty());
    }

    #[test]
    fn aggregate_first_hop_and_live_identity_tables_are_bounded() {
        let registry = Arc::new(Mutex::new(Registry::default()));
        let mut held = Vec::new();
        for n in 0..MAX_SOURCES {
            held.push(reserve(&registry, Source::Peer(n.to_le_bytes().to_vec()), EventClass::Block, 1).unwrap());
        }
        assert!(reserve(&registry, Source::Peer(vec![255; 32]), EventClass::Block, 1).is_none());
        drop(held);
        let mut all = Vec::new();
        for n in 0u8..4 {
            all.push(reserve(&registry, Source::Peer(vec![n]), EventClass::Block, SOURCE_BYTES).unwrap());
        }
        assert!(reserve(&registry, Source::Peer(vec![5]), EventClass::Block, 1).is_none());
        drop(all);
        assert_eq!(registry.lock().unwrap().total.bytes, 0);
    }
}
