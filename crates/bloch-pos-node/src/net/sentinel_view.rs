// SPDX-License-Identifier: AGPL-3.0-or-later

//! The devnet mesh's [`crate::sentinel::MeshView`]: what the Bloch Sentinel
//! may see (inbound addresses, configured sources) and the one thing it may
//! do (close inbound sessions from a banned, non-configured address).
//!
//! It holds weak/shared handles to the mesh's own registries and adds no
//! state. Registered by [`super::start`] only when the Sentinel is enabled.

use std::collections::BTreeMap;
use std::net::{IpAddr, Shutdown};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, Weak};

use super::InboundPeer;

struct View {
    inbound: Weak<Mutex<Vec<InboundPeer>>>,
    configured: Arc<Mutex<BTreeMap<IpAddr, usize>>>,
}

pub(super) fn register(inbound: &Arc<Mutex<Vec<InboundPeer>>>, configured: &Arc<Mutex<BTreeMap<IpAddr, usize>>>) {
    crate::sentinel::register_mesh(|| {
        Box::new(View { inbound: Arc::downgrade(inbound), configured: configured.clone() })
    });
}

impl View {
    fn is_configured(&self, ip: IpAddr) -> bool {
        let key = crate::connection_limit::limit_key(ip);
        self.configured.lock().map(|c| c.contains_key(&key)).unwrap_or(true)
    }

    /// Open inbound connections with their remote address.
    fn open(&self) -> Vec<(IpAddr, Arc<super::Connection>)> {
        let Some(inbound) = self.inbound.upgrade() else { return Vec::new() };
        let Ok(reg) = inbound.lock() else { return Vec::new() };
        reg.iter()
            .filter_map(|p| p.connection.upgrade())
            .filter(|c| !c.closed.load(Ordering::Acquire))
            .filter_map(|c| c.socket.peer_addr().ok().map(|a| (a.ip(), c)))
            .collect()
    }
}

impl crate::sentinel::MeshView for View {
    fn inbound_addrs(&self) -> Vec<IpAddr> {
        self.open().into_iter().map(|(ip, _)| ip).collect()
    }

    fn configured_sources(&self) -> Vec<IpAddr> {
        self.configured.lock().map(|c| c.keys().copied().collect()).unwrap_or_default()
    }

    fn disconnect(&self, banned: &dyn Fn(IpAddr) -> bool) -> usize {
        let mut closed = 0;
        for (ip, conn) in self.open() {
            if banned(ip) && !self.is_configured(ip) {
                // The reader sees EOF and unwinds through `ConnectionHalf`,
                // which releases the slot exactly as any other close does.
                let _ =conn.socket.shutdown(Shutdown::Both);
                closed += 1;
            }
        }
        closed
    }
}
