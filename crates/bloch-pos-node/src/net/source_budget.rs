//! Backlog admission, not identity reputation or a consensus rule.
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use sha3::{Digest, Sha3_256};

use super::{class_bytes_cap, class_count_cap, EventClass};

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

    fn verification_key(&self) -> [u8; 32] {
        let mut hash = Sha3_256::new();
        hash.update(b"bloch-node-verification-source-v1");
        match self {
            Source::Ip(IpAddr::V4(ip)) => {
                hash.update([0x04]);
                hash.update(ip.octets());
            }
            Source::Ip(IpAddr::V6(ip)) => {
                hash.update([0x06]);
                hash.update(ip.octets());
            }
            Source::Peer(peer) => {
                hash.update([0x50]);
                hash.update((peer.len() as u64).to_le_bytes());
                hash.update(peer);
            }
        }
        hash.finalize().into()
    }
}

/// Stable admission identity for an RPC/devnet address. Keep this at the
/// transport normalization seam so IPv4 and its mapped IPv6 form cannot buy
/// separate expensive-work allowances.
pub(crate) fn verification_source_for_ip(ip: IpAddr) -> [u8; 32] {
    Source::ip(ip).verification_key()
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

impl Reservation {
    /// Opaque admission identity for expensive-work fairness. Both transports
    /// reuse the normalization that already owns their count/byte reservation.
    pub(crate) fn verification_source(&self) -> [u8; 32] {
        self.source.verification_key()
    }

    /// Exact bounded wire bytes charged when this immutable event entered the
    /// first-hop queue. Receive paths prove the decoded canonical size before
    /// the guarded event reaches later queue accounting.
    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }
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
        if count >= class_count_cap(class, SOURCE_EVENTS) || source_bytes > class_bytes_cap(class, SOURCE_BYTES)
            || state.total.count >= class_count_cap(class, count_cap)
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
        for _ in 0..class_count_cap(EventClass::Attestation, SOURCE_EVENTS) {
            held.push(reserve(&registry, bad.clone(), EventClass::Attestation, 512).unwrap());
        }
        assert!(reserve(&registry, bad.clone(), EventClass::Transaction, 1).is_none());
        let last = held.pop().unwrap();
        let clone = last.clone();
        drop(last);
        assert!(reserve(&registry, bad.clone(), EventClass::Attestation, 1).is_none());
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
    fn verification_identity_normalizes_ipv4_mapped_addresses() {
        let ipv4 = "192.0.2.44".parse().unwrap();
        let mapped = "::ffff:192.0.2.44".parse().unwrap();
        let other = "192.0.2.45".parse().unwrap();
        assert_eq!(verification_source_for_ip(ipv4), verification_source_for_ip(mapped));
        assert_ne!(verification_source_for_ip(ipv4), verification_source_for_ip(other));
    }

    #[test]
    fn tiny_messages_preserve_same_nat_count_headroom_and_release_every_charge() {
        let registry = Arc::new(Mutex::new(Registry::default()));
        let source = Source::ip("192.0.2.19".parse().unwrap());
        let mut held = Vec::new();
        for (class, target) in [
            (EventClass::Transaction, SOURCE_EVENTS / 2),
            (EventClass::Attestation, SOURCE_EVENTS / 4 * 3),
            (EventClass::Block, SOURCE_EVENTS),
        ] {
            while held.len() < target {
                held.push(reserve(&registry, source.clone(), class, 1).unwrap());
            }
            assert!(reserve(&registry, source.clone(), class, 1).is_none());
        }
        assert_eq!(registry.lock().unwrap().total.bytes, SOURCE_EVENTS);
        let clone = held.last().unwrap().clone();
        drop(held);
        assert_eq!(registry.lock().unwrap().total.count, 1);
        assert!(reserve(&registry, source, EventClass::Transaction, 1).is_some());
        drop(clone);
        let state = registry.lock().unwrap();
        assert!(state.sources.is_empty());
        assert_eq!((state.total.count, state.total.bytes), (0, 0));
    }

    #[test]
    fn tiny_messages_preserve_aggregate_count_headroom_across_sources() {
        let registry = Arc::new(Mutex::new(Registry::default()));
        let mut held = Vec::new();
        for (class, target) in [
            (EventClass::Transaction, 4), (EventClass::Attestation, 6), (EventClass::Block, 8),
        ] {
            while held.len() < target {
                let source = Source::Peer(vec![held.len() as u8]);
                held.push(Registry::reserve(&registry, source, class, 1, 8, 1 << 20).unwrap());
            }
            assert!(Registry::reserve(&registry, Source::Peer(vec![99]), class, 1, 8, 1 << 20).is_none());
        }
        drop(held);
        assert_eq!(registry.lock().unwrap().total.count, 0);
        assert!(Registry::reserve(&registry, Source::Peer(vec![99]), EventClass::Transaction, 1, 8, 1 << 20).is_some());
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

    #[test]
    fn verification_source_fingerprint_reuses_normalization_and_separates_peers() {
        let v4 = Source::ip("192.0.2.44".parse().unwrap());
        let mapped = Source::ip("::ffff:192.0.2.44".parse().unwrap());
        assert_eq!(v4.verification_key(), mapped.verification_key());
        assert_ne!(
            Source::Peer(vec![1]).verification_key(),
            Source::Peer(vec![2]).verification_key(),
        );
        assert_ne!(
            v4.verification_key(),
            Source::Peer(vec![192, 0, 2, 44]).verification_key(),
        );
    }
}
