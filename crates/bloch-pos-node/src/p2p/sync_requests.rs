// SPDX-License-Identifier: AGPL-3.0-or-later
//! One shared outgoing response window for connect, timer and page chase.
use super::{request_response::OutboundRequestId, PeerId, SYNC_FANOUT};
use std::collections::{HashMap, VecDeque};

const MAX_WAITING_PEERS: usize = 1024;

#[derive(Default)]
pub(super) struct Requests {
    active: HashMap<PeerId, OutboundRequestId>,
    waiting: VecDeque<(PeerId, u64)>,
}

impl Requests {
    pub(super) fn contains(&self, peer: &PeerId) -> bool { self.active.contains_key(peer) }

    pub(super) fn enqueue(&mut self, peer: PeerId, after_slot: u64) -> bool {
        if self.contains(&peer) { return false; }
        if let Some((_, cursor)) = self.waiting.iter_mut().find(|(p, _)| *p == peer) {
            // A timer asking from a lower applied head must not lose an
            // outstanding gap to a speculative page-chase cursor.
            *cursor = (*cursor).min(after_slot);
            return true;
        }
        if self.waiting.len() >= MAX_WAITING_PEERS { return false; }
        self.waiting.push_back((peer, after_slot));
        true
    }

    pub(super) fn dispatch(&mut self, mut send: impl FnMut(PeerId, u64) -> OutboundRequestId) {
        while self.active.len() < SYNC_FANOUT {
            let Some((peer, after)) = self.waiting.pop_front() else { break };
            self.start(peer, || send(peer, after));
        }
    }

    pub(super) fn start(&mut self, peer: PeerId, send: impl FnOnce() -> OutboundRequestId) -> bool {
        if self.active.len() >= SYNC_FANOUT || self.contains(&peer) { return false; }
        // The swarm is single-threaded. No event can arrive between the send
        // and registration, and the closure is never called on refusal.
        let request = send();
        self.active.insert(peer, request);
        true
    }

    pub(super) fn finish(&mut self, peer: &PeerId, request: OutboundRequestId) -> bool {
        if self.active.get(peer) != Some(&request) { return false; }
        self.active.remove(peer);
        true
    }

    pub(super) fn forget(&mut self, peer: &PeerId) {
        self.active.remove(peer);
        self.waiting.retain(|(p, _)| p != peer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2p::{SyncCodec, SyncRequest, MAX_SYNC_BLOCKS, SYNC_PROTOCOL};
    use libp2p::request_response::{Behaviour, Config, ProtocolSupport};

    fn transport() -> Behaviour<SyncCodec> {
        Behaviour::with_codec(SyncCodec, [(SYNC_PROTOCOL, ProtocolSupport::Full)], Config::default())
    }

    #[test]
    fn outbound_sync_shared_window_refuses_duplicate_and_releases_exact_request() {
        let mut transport = transport();
        let mut requests = Requests::default();
        let peers: Vec<_> = (0..=SYNC_FANOUT).map(|_| PeerId::random()).collect();
        let req = SyncRequest::GetBlocks { after_slot: 0, limit: MAX_SYNC_BLOCKS as u32 };
        for peer in peers.iter().take(SYNC_FANOUT) {
            assert!(requests.start(*peer, || transport.send_request(peer, req.clone())));
        }
        assert!(!requests.start(peers[0], || panic!("duplicate must not enqueue another substream")));
        assert!(!requests.start(peers[SYNC_FANOUT], || panic!("full window must not call send")));
        let first = requests.active[&peers[0]];
        let unrelated = transport.send_request(&peers[0], req.clone());
        assert!(!requests.finish(&peers[0], unrelated));
        assert!(!requests.finish(&peers[1], first));
        assert_eq!(requests.active.len(), SYNC_FANOUT);
        assert!(requests.finish(&peers[0], first));
        assert!(!requests.finish(&peers[0], first));
        assert!(requests.start(peers[SYNC_FANOUT], || transport.send_request(&peers[SYNC_FANOUT], req.clone())));
        assert_eq!(requests.active.len(), SYNC_FANOUT);
    }

    #[test]
    fn outbound_sync_reconnect_late_failure_cannot_release_new_generation() {
        let mut transport = transport();
        let mut requests = Requests::default();
        let peer = PeerId::random();
        let req = SyncRequest::GetBlocks { after_slot: 9, limit: MAX_SYNC_BLOCKS as u32 };
        assert!(requests.start(peer, || transport.send_request(&peer, req.clone())));
        let old = requests.active[&peer];
        requests.forget(&peer);
        assert!(requests.active.is_empty());
        assert!(requests.start(peer, || transport.send_request(&peer, req)));
        let current = requests.active[&peer];
        assert_ne!(current, old);
        assert!(!requests.finish(&peer, old));
        assert!(requests.contains(&peer));
        assert!(requests.finish(&peer, current));
        assert!(requests.active.is_empty());
    }
    #[test]
    fn outbound_sync_fifo_serves_waiting_peer_before_responsive_peer_reacquires() {
        let mut transport = transport();
        let mut requests = Requests::default();
        let peers: Vec<_> = (0..4).map(|_| PeerId::random()).collect();
        for peer in &peers { assert!(requests.enqueue(*peer, 10)); }
        let mut sent = Vec::new();
        requests.dispatch(|peer, after_slot| {
            sent.push((peer, after_slot));
            transport.send_request(&peer, SyncRequest::GetBlocks { after_slot, limit: MAX_SYNC_BLOCKS as u32 })
        });
        assert_eq!(sent, peers[..3].iter().map(|p| (*p, 10)).collect::<Vec<_>>());
        // The first two peers remain silent. The third completes a full page
        // and asks to continue; the fourth has been waiting since connect.
        let done = requests.active[&peers[2]];
        assert!(requests.finish(&peers[2], done));
        assert!(requests.enqueue(peers[2], 138));
        sent.clear();
        requests.dispatch(|peer, after_slot| {
            sent.push((peer, after_slot));
            transport.send_request(&peer, SyncRequest::GetBlocks { after_slot, limit: MAX_SYNC_BLOCKS as u32 })
        });
        assert_eq!(sent, vec![(peers[3], 10)]);
        assert_eq!(requests.waiting.front(), Some(&(peers[2], 138)));
        // A timeout/disconnect frees a silent slot without losing the chase.
        requests.forget(&peers[0]);
        sent.clear();
        requests.dispatch(|peer, after_slot| {
            sent.push((peer, after_slot));
            transport.send_request(&peer, SyncRequest::GetBlocks { after_slot, limit: MAX_SYNC_BLOCKS as u32 })
        });
        assert_eq!(sent, vec![(peers[2], 138)]);
        assert_eq!(requests.active.len(), SYNC_FANOUT);
    }

    #[test]
    fn outbound_sync_waiting_queue_is_unique_bounded_and_forgotten_on_disconnect() {
        let mut requests = Requests::default();
        let peers: Vec<_> = (0..MAX_WAITING_PEERS).map(|_| PeerId::random()).collect();
        for peer in &peers { assert!(requests.enqueue(*peer, 100)); }
        assert!(!requests.enqueue(PeerId::random(), 0));
        assert!(requests.enqueue(peers[0], 50));
        assert!(requests.enqueue(peers[0], 200));
        assert_eq!(requests.waiting.len(), MAX_WAITING_PEERS);
        assert_eq!(requests.waiting.front(), Some(&(peers[0], 50)));
        requests.forget(&peers[0]);
        assert_eq!(requests.waiting.len(), MAX_WAITING_PEERS - 1);
        assert!(requests.enqueue(PeerId::random(), 0));
        for peer in peers.iter().skip(1) { requests.forget(peer); }
        assert_eq!(requests.waiting.len(), 1);
    }

}
