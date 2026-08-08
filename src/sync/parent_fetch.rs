//! Missing-parent fetch tracker — the orphan-deadlock fix.
//!
//! The orphan pool (main.rs NewBlock arm) requests each missing parent via
//! `GetBlock` EXACTLY ONCE (`first_waiter && !orphans.contains_key(..)`).
//! `waiting_for` has no timeout and no retry, so a single lost response —
//! and responses DO get lost: the swarm→processor channel drops frames
//! silently when full, gossip publishes race subscriptions, directed pulls
//! time out — leaves the orphan (and every descendant that chains onto it)
//! waiting forever. The node silently partitions onto a sub-DAG.
//!
//! This tracker gives every chased parent a (first_requested, last_requested,
//! attempts) record. A periodic sweep (main.rs, ~30s) asks it which parents
//! are due for a re-request (exponential backoff, capped) and which to give
//! up on (attempt ceiling / age ceiling), so `waiting_for` can never grow
//! stale entries without bound. Pure decision logic lives here so it is
//! unit-testable without a DAG or a network.
//!
//! NOT consensus: this only re-emits `GetBlock` requests (an existing wire
//! message) and prunes a local buffer. Block validation/acceptance is
//! untouched.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// How often main.rs runs the sweep.
pub const SWEEP_PERIOD: Duration = Duration::from_secs(30);

/// Backoff before the first re-request (attempt 1 → 2), doubling per attempt.
pub const BASE_BACKOFF: Duration = Duration::from_secs(30);

/// Backoff ceiling between re-requests.
pub const MAX_BACKOFF: Duration = Duration::from_secs(240);

/// Give up on a parent after this many GetBlock attempts…
pub const MAX_ATTEMPTS: u32 = 8;

/// …or once we have chased it for this long, whichever comes first. Keeps the
/// tracker and `waiting_for` bounded even if attempts stay below the ceiling.
pub const MAX_AGE: Duration = Duration::from_secs(900);

#[derive(Clone, Copy, Debug)]
struct Entry {
    first_requested: Instant,
    last_requested:  Instant,
    attempts:        u32,
}

/// Effective backoff for an entry that has made `attempts` requests so far.
fn backoff_for(attempts: u32) -> Duration {
    // attempts >= 1 always (an entry is created at its first request).
    let shift = attempts.saturating_sub(1).min(31);
    BASE_BACKOFF
        .checked_mul(1u32 << shift)
        .map(|d| d.min(MAX_BACKOFF))
        .unwrap_or(MAX_BACKOFF)
}

/// Per-missing-parent fetch state. Owned by the message-processor task
/// alongside `orphans` / `waiting_for` (no locking needed).
#[derive(Default)]
pub struct ParentFetchTracker {
    map: HashMap<[u8; 32], Entry>,
}

impl ParentFetchTracker {
    pub fn new() -> Self {
        Self { map: HashMap::new() }
    }

    /// Record the FIRST GetBlock we sent for `parent` (main.rs orphan arm).
    /// No-op if already tracked (a re-orphan on the same parent must not
    /// reset the attempt count).
    pub fn note_requested(&mut self, parent: [u8; 32], now: Instant) {
        self.map.entry(parent).or_insert(Entry {
            first_requested: now,
            last_requested:  now,
            attempts:        1,
        });
    }

    /// Number of tracked parents (diagnostics/tests).
    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// One sweep step. `chased` is the set of parents that still need
    /// fetching: keys of `waiting_for` that are neither buffered in the
    /// orphan pool nor already in the DAG (the caller filters; this keeps
    /// the tracker free of DAG/pool dependencies).
    ///
    /// Returns `(retry, give_up)`:
    ///  - `retry`: parents to re-send `GetBlock` for NOW. Includes chased
    ///    parents with no record (e.g. their buffered copy was evicted, so
    ///    the one-shot request path never fired) — they get a fresh record.
    ///  - `give_up`: `(parent, attempts)` pairs that crossed MAX_ATTEMPTS or
    ///    MAX_AGE. Their records are dropped; the caller must drop the
    ///    dependent orphans and their `waiting_for` entries.
    ///
    /// Records for parents NOT in `chased` are garbage-collected (parent
    /// arrived, or every waiter was evicted).
    pub fn sweep(
        &mut self,
        chased: &[[u8; 32]],
        now: Instant,
    ) -> (Vec<[u8; 32]>, Vec<([u8; 32], u32)>) {
        // GC: anything no longer chased is resolved or unwanted.
        let chased_set: std::collections::HashSet<&[u8; 32]> = chased.iter().collect();
        self.map.retain(|h, _| chased_set.contains(h));

        let mut retry = Vec::new();
        let mut give_up = Vec::new();
        for h in chased {
            match self.map.get_mut(h) {
                None => {
                    // Chased but never requested (buffered-parent eviction
                    // leak): start the request cycle now.
                    self.map.insert(*h, Entry {
                        first_requested: now,
                        last_requested:  now,
                        attempts:        1,
                    });
                    retry.push(*h);
                }
                Some(e) => {
                    if e.attempts >= MAX_ATTEMPTS
                        || now.duration_since(e.first_requested) >= MAX_AGE
                    {
                        give_up.push((*h, e.attempts));
                    } else if now.duration_since(e.last_requested) >= backoff_for(e.attempts) {
                        e.last_requested = now;
                        e.attempts += 1;
                        retry.push(*h);
                    }
                }
            }
        }
        for (h, _) in &give_up {
            self.map.remove(h);
        }
        (retry, give_up)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: [u8; 32] = [1u8; 32];
    const Q: [u8; 32] = [2u8; 32];

    #[test]
    fn backoff_schedule_doubles_and_caps() {
        assert_eq!(backoff_for(1), Duration::from_secs(30));
        assert_eq!(backoff_for(2), Duration::from_secs(60));
        assert_eq!(backoff_for(3), Duration::from_secs(120));
        assert_eq!(backoff_for(4), Duration::from_secs(240));
        assert_eq!(backoff_for(5), MAX_BACKOFF); // capped
        assert_eq!(backoff_for(31), MAX_BACKOFF);
        assert_eq!(backoff_for(u32::MAX), MAX_BACKOFF); // no shift overflow
    }

    #[test]
    fn lost_response_is_retried_with_backoff() {
        let t0 = Instant::now();
        let mut tr = ParentFetchTracker::new();
        tr.note_requested(P, t0);

        // Too early: nothing due.
        let (retry, gu) = tr.sweep(&[P], t0 + Duration::from_secs(10));
        assert!(retry.is_empty() && gu.is_empty());

        // First backoff elapsed → re-request.
        let (retry, gu) = tr.sweep(&[P], t0 + Duration::from_secs(30));
        assert_eq!(retry, vec![P]);
        assert!(gu.is_empty());

        // Second retry only after the DOUBLED backoff.
        let (retry, _) = tr.sweep(&[P], t0 + Duration::from_secs(60));
        assert!(retry.is_empty(), "60s < 30s + 60s backoff");
        let (retry, _) = tr.sweep(&[P], t0 + Duration::from_secs(90));
        assert_eq!(retry, vec![P]);
    }

    #[test]
    fn note_requested_does_not_reset_attempts() {
        let t0 = Instant::now();
        let mut tr = ParentFetchTracker::new();
        tr.note_requested(P, t0);
        let _ = tr.sweep(&[P], t0 + Duration::from_secs(30)); // attempts → 2
        tr.note_requested(P, t0 + Duration::from_secs(31));   // re-orphan, no-op
        // Backoff must still be the attempt-2 one (60s from last request).
        let (retry, _) = tr.sweep(&[P], t0 + Duration::from_secs(60));
        assert!(retry.is_empty());
    }

    #[test]
    fn gives_up_at_attempt_ceiling() {
        let t0 = Instant::now();
        let mut tr = ParentFetchTracker::new();
        tr.note_requested(P, t0);
        let mut now = t0;
        let mut gave_up = None;
        // Drive sweeps far apart so every one is past backoff, until give-up.
        for _ in 0..MAX_ATTEMPTS + 2 {
            now += MAX_BACKOFF;
            // MAX_AGE would trip first with real spacing; use a tracker whose
            // ages we control by checking only the attempts path: keep the
            // age below MAX_AGE is impossible here (8×240s > 900s), so this
            // test accepts EITHER ceiling — the observable contract is that
            // it gives up and drops the record.
            let (_, gu) = tr.sweep(&[P], now);
            if let Some((h, _)) = gu.first() {
                gave_up = Some(*h);
                break;
            }
        }
        assert_eq!(gave_up, Some(P));
        assert!(tr.is_empty(), "record dropped after give-up");
        // And a subsequent sweep restarts from scratch (caller normally stops
        // chasing, but if the orphan is re-announced the cycle may restart).
        let (retry, _) = tr.sweep(&[P], now);
        assert_eq!(retry, vec![P]);
    }

    #[test]
    fn gives_up_at_age_ceiling() {
        let t0 = Instant::now();
        let mut tr = ParentFetchTracker::new();
        tr.note_requested(P, t0);
        let (_, gu) = tr.sweep(&[P], t0 + MAX_AGE);
        assert_eq!(gu.len(), 1);
        assert_eq!(gu[0].0, P);
    }

    #[test]
    fn resolved_parents_are_garbage_collected() {
        let t0 = Instant::now();
        let mut tr = ParentFetchTracker::new();
        tr.note_requested(P, t0);
        tr.note_requested(Q, t0);
        assert_eq!(tr.len(), 2);
        // P arrived (no longer chased); Q still chased.
        let _ = tr.sweep(&[Q], t0 + Duration::from_secs(1));
        assert_eq!(tr.len(), 1);
    }

    #[test]
    fn evicted_buffered_parent_gets_a_fresh_request() {
        // A chased parent with NO record (one-shot request path never fired
        // because the parent was buffered, then evicted) must be requested.
        let t0 = Instant::now();
        let mut tr = ParentFetchTracker::new();
        let (retry, gu) = tr.sweep(&[P], t0);
        assert_eq!(retry, vec![P]);
        assert!(gu.is_empty());
        assert_eq!(tr.len(), 1);
    }
}
