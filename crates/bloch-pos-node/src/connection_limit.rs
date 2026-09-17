// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bounded per-address reservations, released on every worker exit path.
use std::{
    collections::BTreeMap,
    net::IpAddr,
    sync::{Arc, Mutex},
};
#[derive(Default)]
pub(crate) struct Limits(Mutex<BTreeMap<IpAddr, usize>>);
pub(crate) struct Permit {
    limits: Arc<Limits>,
    ip: IpAddr,
}
impl Limits {
    pub(crate) fn reserve(self: &Arc<Self>, ip: IpAddr, maximum: usize) -> Option<Permit> {
        let ip = match ip {
            IpAddr::V6(ip) => ip
                .to_ipv4_mapped()
                .map(IpAddr::V4)
                .unwrap_or(IpAddr::V6(ip)),
            ip => ip,
        };
        let mut counts = self.0.lock().ok()?;
        let count = counts.entry(ip).or_default();
        if *count >= maximum {
            return None;
        }
        *count = count.checked_add(1)?;
        Some(Permit {
            limits: self.clone(),
            ip,
        })
    }
}
impl Drop for Permit {
    fn drop(&mut self) {
        if let Ok(mut counts) = self.limits.0.lock() {
            if let Some(count) = counts.get_mut(&self.ip) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    counts.remove(&self.ip);
                }
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn address_limits_release_and_do_not_block_other_addresses() {
        let limits = Arc::new(Limits::default());
        let ip = "127.0.0.1".parse().unwrap();
        let a = limits.reserve(ip, 1).unwrap();
        assert!(limits.reserve(ip, 1).is_none());
        assert!(limits
            .reserve("::ffff:127.0.0.1".parse().unwrap(), 1)
            .is_none());
        assert!(limits.reserve("127.0.0.2".parse().unwrap(), 1).is_some());
        drop(a);
        assert!(limits.reserve(ip, 1).is_some());
        assert!(limits.0.lock().unwrap().is_empty());
    }
}
