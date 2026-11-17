// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded, windowed per-source counters (two counters per source).
//!
//! Memory is capped at [`MAX_SOURCES`] entries no matter how many sources an
//! attacker brings: once the table is full and nothing in it has aged out,
//! new sources are counted in one `overflow` aggregate instead of getting an
//! entry. Each entry is a tumbling window of [`WINDOW`]; a source whose
//! window has passed restarts from zero on its next event and is swept from
//! the table when space is needed.

use std::collections::HashMap;
use std::hash::Hash;
use std::time::{Duration, Instant};

pub(crate) const MAX_SOURCES: usize = 1024;
pub(crate) const WINDOW: Duration = Duration::from_secs(600);
/// Longest top-N list any status answer carries.
pub(crate) const TOP_N: usize = 16;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Counts {
    pub(crate) a: u64,
    pub(crate) b: u64,
}

#[derive(Debug)]
struct Entry {
    since: Instant,
    counts: Counts,
}

#[derive(Debug)]
pub(crate) struct SourceWindow<K> {
    entries: HashMap<K, Entry>,
    overflow: Counts,
    overflow_since: Instant,
    totals: Counts,
    cap: usize,
    window: Duration,
}

impl<K: Hash + Eq + Clone> SourceWindow<K> {
    pub(crate) fn new(now: Instant) -> Self {
        Self::with_bounds(now, MAX_SOURCES, WINDOW)
    }

    pub(crate) fn with_bounds(now: Instant, cap: usize, window: Duration) -> Self {
        SourceWindow { entries: HashMap::new(), overflow: Counts::default(), overflow_since: now, totals: Counts::default(), cap, window }
    }

    /// Add `a` and `b` to `key`'s current window.
    pub(crate) fn add(&mut self, key: &K, a: u64, b: u64, now: Instant) {
        self.totals.a = self.totals.a.saturating_add(a);
        self.totals.b = self.totals.b.saturating_add(b);
        let window = self.window;
        if let Some(e) = self.entries.get_mut(key) {
            if now.saturating_duration_since(e.since) >= window {
                *e = Entry { since: now, counts: Counts::default() };
            }
            e.counts.a = e.counts.a.saturating_add(a);
            e.counts.b = e.counts.b.saturating_add(b);
            return;
        }
        if self.entries.len() >= self.cap {
            // Sweep aged-out entries; O(cap) and only when the table is full.
            self.entries.retain(|_, e| now.saturating_duration_since(e.since) < window);
        }
        if self.entries.len() >= self.cap {
            if now.saturating_duration_since(self.overflow_since) >= window {
                self.overflow = Counts::default();
                self.overflow_since = now;
            }
            self.overflow.a = self.overflow.a.saturating_add(a);
            self.overflow.b = self.overflow.b.saturating_add(b);
            return;
        }
        self.entries.insert(key.clone(), Entry { since: now, counts: Counts { a, b } });
    }

    /// The `n` sources with the most `a + b` in their current window.
    pub(crate) fn top(&self, n: usize, now: Instant) -> Vec<(K, Counts)> {
        let mut live: Vec<(K, Counts)> = self
            .entries
            .iter()
            .filter(|(_, e)| now.saturating_duration_since(e.since) < self.window)
            .map(|(k, e)| (k.clone(), e.counts))
            .collect();
        live.sort_by(|x, y| (y.1.a.saturating_add(y.1.b)).cmp(&x.1.a.saturating_add(x.1.b)));
        live.truncate(n);
        live
    }

    pub(crate) fn tracked(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn overflow(&self, now: Instant) -> Counts {
        if now.saturating_duration_since(self.overflow_since) >= self.window { Counts::default() } else { self.overflow }
    }

    pub(crate) fn totals(&self) -> Counts {
        self.totals
    }

    pub(crate) fn window_secs(&self) -> u64 {
        self.window.as_secs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_is_bounded_and_overflow_aggregates() {
        let now = Instant::now();
        let mut w: SourceWindow<u32> = SourceWindow::with_bounds(now, 8, Duration::from_secs(60));
        for k in 0..10_000u32 {
            w.add(&k, 1, 0, now);
        }
        assert_eq!(w.tracked(), 8);
        assert_eq!(w.overflow(now).a, 10_000 - 8);
        assert_eq!(w.totals().a, 10_000);
        // Aged-out entries make room again.
        let later = now + Duration::from_secs(61);
        w.add(&99_999, 0, 1, later);
        assert_eq!(w.tracked(), 1);
        assert_eq!(w.overflow(later), Counts::default());
    }

    #[test]
    fn top_is_sorted_bounded_and_windowed() {
        let now = Instant::now();
        let mut w: SourceWindow<u32> = SourceWindow::with_bounds(now, 64, Duration::from_secs(60));
        for k in 0..40u32 {
            w.add(&k, u64::from(k), 1, now);
        }
        let top = w.top(TOP_N, now);
        assert_eq!(top.len(), TOP_N);
        assert_eq!(top[0].0, 39);
        assert!(top.windows(2).all(|p| p[0].1.a + p[0].1.b >= p[1].1.a + p[1].1.b));
        assert!(w.top(TOP_N, now + Duration::from_secs(61)).is_empty());
        // A source's window restarts after it ages out.
        w.add(&39, 1, 0, now + Duration::from_secs(61));
        assert_eq!(w.top(1, now + Duration::from_secs(61))[0].1, Counts { a: 1, b: 0 });
    }
}
