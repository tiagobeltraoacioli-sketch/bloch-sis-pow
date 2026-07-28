//! vardiff — the per-worker variable-difficulty engine for the mini-pool.
//!
//! The Sprint-1 `downstream.rs::VardiffController` is inert/passthrough-shaped
//! (keyed off `vardiff_override`); it is left untouched because tests depend on
//! it. This is the purpose-built driver the mini-pool submit path uses.
//!
//! It tracks accepted shares (timestamp + the difficulty each was accepted
//! at) in a sliding window and, every `retarget_shares` accepted shares,
//! retargets toward `target_secs` per share using a WORK-RATE estimate:
//!
//!   est_rate (diff1-units/sec) = Σ share-difficulty / window-span
//!   next = est_rate × target_secs
//!
//! The work-rate form is scale-invariant: it estimates the miner's hashrate
//! correctly no matter which difficulty the shares were mined at, so the
//! stratum "difficulty applies at the NEXT job" lag can never make the
//! controller ladder off into a value the miner will never reach. The step is
//! still clamped (±4×), band-clamped to [min, max], and ±10% hysteresis
//! suppresses `set_difficulty` churn.
//!
//! ## Retarget grace (the raise race)
//!
//! Stratum miners (cpuminer/ccminer/ASIC firmware) apply a pushed
//! `mining.set_difficulty` only when the NEXT `mining.notify` arrives. On a
//! raise, every share the miner finds until then is below the new target;
//! validating them against the new target alone rejects 100% of the miner's
//! work for up to a full notify interval (observed live: 30–60 s of straight
//! error-23). So on every raise the pre-raise difficulty is retained as a
//! GRACE difficulty for `grace_secs` (default 120 s): a share that misses the
//! current target may still be accepted — and PPLNS-credited — at the grace
//! difficulty. Consecutive raises keep the OLDEST still-unexpired grace value
//! (the miner may not have applied the intermediate ones either). Credit is
//! at the difficulty actually met, so grace never over-credits.
//!
//! The proxy serves ITS OWN `set_difficulty` downstream (initial + retarget)
//! instead of relaying the node's per-connection value, so a fleet of ASICs
//! each mine at a locally-sane difficulty while the node still only ever sees
//! network-target-meeting blocks.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::types::ProxyConfig;

/// Per-worker vardiff state machine. Task-local (not shared), so no locking.
#[derive(Clone, Debug)]
pub struct Vardiff {
    current: f64,
    min: f64,
    max: f64,
    target_secs: f64,
    retarget_shares: usize,
    since_retarget: usize,
    /// Accepted shares — (arrival, difficulty credited) — capped at
    /// `retarget_shares + 1`. The difficulty is the one the share was
    /// ACCEPTED at (grace shares carry the grace difficulty), which is what
    /// makes the work-rate estimate scale-invariant.
    window: VecDeque<(Instant, f64)>,
    /// Whether the miner has been told the current value yet.
    announced: bool,
    /// Pre-raise difficulty still honored for shares in flight (see module
    /// docs), with its expiry.
    grace_diff: Option<f64>,
    grace_until: Option<Instant>,
    /// How long a raise keeps the previous difficulty valid.
    grace_secs: Duration,
    /// GENUINE PoW shares that landed BELOW our announced difficulty (a miner
    /// or interposed rig proxy that ignores our `set_difficulty`), carrying the
    /// difficulty each hash actually achieved. Drives the DOWNWARD escape in
    /// [`note_low_share`] so the worker converges to what the miner can do
    /// instead of dead-locking at 100% reject. Cleared the moment a share is
    /// accepted (a healthy miner never triggers the escape).
    low_window: VecDeque<f64>,
}

impl Vardiff {
    /// Build from config (reads the 6 vardiff fields). Clamps the seed into the
    /// [min, max] band and requires retarget_shares >= 1.
    pub fn from_cfg(cfg: &ProxyConfig) -> Self {
        let min = cfg.vardiff_min.max(f64::MIN_POSITIVE);
        let max = cfg.vardiff_max.max(min);
        let current = cfg.vardiff_initial.clamp(min, max);
        let target_secs = if cfg.vardiff_target_secs > 0.0 {
            cfg.vardiff_target_secs
        } else {
            5.0
        };
        let retarget_shares = cfg.vardiff_retarget_shares.max(1);
        let grace_secs = Duration::from_secs(cfg.vardiff_grace_secs.max(1));
        Vardiff {
            current,
            min,
            max,
            target_secs,
            retarget_shares,
            since_retarget: 0,
            window: VecDeque::with_capacity(retarget_shares + 1),
            announced: false,
            grace_diff: None,
            grace_until: None,
            grace_secs,
            low_window: VecDeque::with_capacity(retarget_shares + 1),
        }
    }

    pub fn current(&self) -> f64 {
        self.current
    }

    /// The pre-raise difficulty still honored for in-flight shares, if any.
    /// Expires lazily: past `grace_until` the grace is dropped and `None` is
    /// returned. Only meaningful when BELOW `current` (a raise); a lower
    /// current would already accept everything the grace would.
    pub fn grace(&mut self, now: Instant) -> Option<f64> {
        match (self.grace_diff, self.grace_until) {
            (Some(d), Some(until)) if now < until && d < self.current => Some(d),
            (Some(_), _) => {
                self.grace_diff = None;
                self.grace_until = None;
                None
            }
            _ => None,
        }
    }

    /// Call on every LOCALLY-ACCEPTED share with the difficulty it was
    /// accepted (and PPLNS-credited) at — grace shares pass the GRACE
    /// difficulty. Returns `Some(new_difficulty)` only when a retarget both
    /// FIRED (enough shares) AND moved the value materially (> ±10%),
    /// clamped to [min, max]. Clears the window on a retarget.
    pub fn on_accepted(&mut self, at: Instant, work_diff: f64) -> Option<f64> {
        // A share cleared the announced difficulty: our value is not too high,
        // so any accumulated "too easy" evidence is stale — drop it so a healthy
        // miner (occasional low share amid accepts) never trips the escape.
        self.low_window.clear();
        self.window.push_back((at, work_diff.max(0.0)));
        if self.window.len() > self.retarget_shares + 1 {
            self.window.pop_front();
        }
        self.since_retarget += 1;
        if self.since_retarget < self.retarget_shares {
            return None;
        }
        self.since_retarget = 0;

        let span = self
            .window
            .back()?
            .0
            .duration_since(self.window.front()?.0)
            .as_secs_f64();
        if span <= 0.0 || self.window.len() < 2 {
            return None;
        }
        // Work that ARRIVED during the span: every entry after the first.
        // est_rate is the miner's hashrate in diff1-units/sec, unbiased by
        // WHICH difficulty the shares were mined at (see module docs).
        let work: f64 = self.window.iter().skip(1).map(|(_, d)| d).sum();
        if work <= 0.0 {
            return None;
        }
        let est_rate = work / span;
        let ideal = est_rate * self.target_secs;
        // Per-step clamp: never move faster than ±4× in one retarget.
        let next = ideal
            .clamp(self.current * 0.25, self.current * 4.0)
            .clamp(self.min, self.max);
        // Hysteresis: ignore sub-10% moves to avoid set_difficulty churn.
        if (next - self.current).abs() / self.current < 0.10 {
            return None;
        }
        if next > self.current {
            // A RAISE: keep honoring the difficulty the miner is actually
            // mining at until it demonstrably applies the new one (next
            // notify), bounded by grace_secs. Consecutive raises keep the
            // OLDEST unexpired grace value.
            let now = Instant::now();
            let base = self.grace(now).unwrap_or(self.current).min(self.current);
            self.grace_diff = Some(base);
            self.grace_until = Some(now + self.grace_secs);
        } else if self.grace_diff.map_or(false, |g| next <= g) {
            // Lowered to (or below) the grace value — grace is moot.
            self.grace_diff = None;
            self.grace_until = None;
        }
        self.window.clear();
        self.current = next;
        self.announced = false;
        Some(next)
    }

    /// Record a GENUINE-PoW share that FELL BELOW the announced difficulty
    /// (`achieved_diff` = the difficulty its reconstructed hash actually met,
    /// from [`crate::validator::hash_to_difficulty`]). This is the DOWNWARD
    /// escape from the 100%-reject deadlock: `on_accepted` — the only other
    /// retarget path — never fires when zero shares are accepted, so a fleet
    /// mining below our announced difficulty (e.g. behind a NiceHash/MRR rig
    /// proxy that swallows our `set_difficulty`) would otherwise reject 100%
    /// forever with no way down.
    ///
    /// After `retarget_shares` such observations with no intervening accept, it
    /// lowers `current` to just UNDER the strongest achieved sample (so the next
    /// shares clear it), DOWNWARD-only, clamped to the ±4× step and the
    /// `[min, max]` band. Returns `Some(new)` when it moved (the caller must
    /// re-announce `set_difficulty`), else `None`.
    ///
    /// It is deliberately conservative: it needs a full window of sub-target
    /// shares (one lucky low hash cannot crater difficulty) and only ever
    /// LOWERS, so it can never manufacture the raise-race it exists to escape.
    pub fn note_low_share(&mut self, achieved_diff: f64) -> Option<f64> {
        if !(achieved_diff > 0.0) {
            return None;
        }
        self.low_window.push_back(achieved_diff);
        while self.low_window.len() > self.retarget_shares {
            self.low_window.pop_front();
        }
        if self.low_window.len() < self.retarget_shares {
            return None;
        }
        // Strongest genuine work the miner has shown while stuck below us. Aim a
        // bit under it so the miner's typical share clears the new target.
        let best = self
            .low_window
            .iter()
            .copied()
            .fold(0.0_f64, f64::max);
        let aim = (best * 0.5).clamp(self.min, self.max);
        // Downward-only, and never more than 4× per step.
        let next = aim.max(self.current * 0.25).min(self.current);
        // Hysteresis: only act on a material (>10%) drop.
        if next >= self.current * 0.90 {
            return None;
        }
        self.low_window.clear();
        // A pending raise-grace is moot once we are lowering below it.
        if self.grace_diff.map_or(false, |g| next <= g) {
            self.grace_diff = None;
            self.grace_until = None;
        }
        self.current = next;
        self.announced = false;
        Some(next)
    }

    /// The `mining.set_difficulty` line to inject downstream. Numbers with a
    /// zero fractional part serialize as e.g. `1024` (miners parse either form).
    pub fn set_difficulty_line(&self) -> String {
        format!(
            r#"{{"id":null,"method":"mining.set_difficulty","params":[{}]}}"#,
            fmt_diff(self.current)
        )
    }

    pub fn needs_announce(&self) -> bool {
        !self.announced
    }

    pub fn mark_announced(&mut self) {
        self.announced = true;
    }

    /// Reset the announce flag so a fresh (reconnected) session re-hears our
    /// difficulty before it starts submitting.
    pub fn reset_announced(&mut self) {
        self.announced = false;
    }
}

/// Render a difficulty for the JSON params array without a trailing `.0` when
/// it is integral (matches how pools emit `set_difficulty`).
fn fmt_diff(d: f64) -> String {
    if d.fract() == 0.0 && d.abs() < 1e15 {
        format!("{}", d as i64)
    } else {
        format!("{}", d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn cfg() -> ProxyConfig {
        ProxyConfig {
            vardiff_initial: 1024.0,
            vardiff_min: 16.0,
            vardiff_max: 4_294_967_296.0,
            vardiff_target_secs: 5.0,
            vardiff_retarget_shares: 4,
            ..ProxyConfig::default()
        }
    }

    #[test]
    fn seeds_from_config_and_announces_once() {
        let mut v = Vardiff::from_cfg(&cfg());
        assert_eq!(v.current(), 1024.0);
        assert!(v.needs_announce());
        v.mark_announced();
        assert!(!v.needs_announce());
    }

    #[test]
    fn fast_shares_raise_difficulty() {
        let mut v = Vardiff::from_cfg(&cfg());
        // 4 shares at current diff ~0.1s apart ⇒ rate ≫ target ⇒ raise
        // (clamped 4×).
        let t0 = Instant::now();
        let mut out = None;
        for i in 0..4 {
            out = v.on_accepted(t0 + Duration::from_millis(100 * i), 1024.0);
        }
        let new = out.expect("retarget must fire after 4 shares");
        assert!(new > 1024.0, "fast shares must raise difficulty, got {new}");
        // Per-step clamp caps it at 4× the seed.
        assert!(new <= 1024.0 * 4.0 + 1e-6);
        assert!(v.needs_announce(), "a retarget re-arms the announce flag");
        // A raise arms the grace at the pre-raise difficulty.
        assert_eq!(v.grace(Instant::now()), Some(1024.0));
    }

    #[test]
    fn slow_shares_lower_difficulty_within_band() {
        let mut v = Vardiff::from_cfg(&cfg());
        let t0 = Instant::now();
        let mut out = None;
        for i in 0..4 {
            // 60s apart ⇒ rate ≪ target ⇒ lower (clamped 0.25×).
            out = v.on_accepted(t0 + Duration::from_secs(60 * i), 1024.0);
        }
        let new = out.expect("retarget must fire");
        assert!(new < 1024.0, "slow shares must lower difficulty, got {new}");
        assert!(new >= 16.0, "must not go below the min band");
        // A lower never needs grace.
        assert_eq!(v.grace(Instant::now()), None);
    }

    #[test]
    fn no_retarget_before_enough_shares() {
        let mut v = Vardiff::from_cfg(&cfg());
        let t0 = Instant::now();
        assert!(v.on_accepted(t0, 1024.0).is_none());
        assert!(v.on_accepted(t0 + Duration::from_millis(10), 1024.0).is_none());
        assert!(v.on_accepted(t0 + Duration::from_millis(20), 1024.0).is_none());
        // 4th fires.
        assert!(v.on_accepted(t0 + Duration::from_millis(30), 1024.0).is_some());
    }

    #[test]
    fn work_rate_estimate_is_scale_invariant_no_runaway() {
        // The stratum raise race: the miner keeps mining at the OLD diff until
        // the next job. With interval-based retargeting the controller ladders
        // 4× per window forever; with work-rate it converges to the miner's
        // real hashrate × target and STOPS, even before the miner adopts.
        let mut v = Vardiff::from_cfg(&ProxyConfig {
            vardiff_initial: 0.01,
            vardiff_min: 0.001,
            vardiff_max: 4_294_967_296.0,
            vardiff_target_secs: 10.0,
            vardiff_retarget_shares: 4,
            ..ProxyConfig::default()
        });
        // Miner's true rate: one diff-0.01 share every 100 ms ⇒ 0.1 diff1/s
        // ⇒ ideal diff at 10 s/share = 1.0.
        let t0 = Instant::now();
        let mut t = t0;
        let mut last = v.current();
        for i in 1..=400 {
            t = t0 + Duration::from_millis(100 * i);
            if let Some(d) = v.on_accepted(t, 0.01) {
                last = d;
            }
        }
        assert!(
            (0.5..=2.0).contains(&last),
            "work-rate vardiff must converge near 1.0, got {last}"
        );
        // Grace still honors the ORIGINAL pre-raise diff (miner never adopted).
        assert_eq!(v.grace(t), Some(0.01));
    }

    #[test]
    fn grace_expires() {
        let mut v = Vardiff::from_cfg(&ProxyConfig {
            vardiff_initial: 1.0,
            vardiff_min: 0.001,
            vardiff_max: 1e9,
            vardiff_target_secs: 10.0,
            vardiff_retarget_shares: 4,
            vardiff_grace_secs: 1, // 1s for the test
            ..ProxyConfig::default()
        });
        let t0 = Instant::now();
        for i in 0..4 {
            v.on_accepted(t0 + Duration::from_millis(10 * i), 1.0);
        }
        assert!(v.current() > 1.0);
        assert_eq!(v.grace(Instant::now()), Some(1.0));
        assert_eq!(
            v.grace(Instant::now() + Duration::from_secs(2)),
            None,
            "grace must expire after grace_secs"
        );
        // And it stays cleared.
        assert_eq!(v.grace(Instant::now()), None);
    }

    #[test]
    fn note_low_share_breaks_the_100pct_reject_deadlock() {
        // A worker whose miner submits GENUINE PoW below the announced
        // difficulty (rig proxy ignoring set_difficulty) and NEVER lands an
        // accepted share. Without the downward escape, vardiff is pinned forever
        // and every share rejects. With it, sustained sub-target shares pull the
        // difficulty DOWN toward what the miner can do.
        let mut v = Vardiff::from_cfg(&ProxyConfig {
            vardiff_initial: 1000.0,
            vardiff_min: 0.001,
            vardiff_max: 1e9,
            vardiff_retarget_shares: 3,
            ..ProxyConfig::default()
        });
        assert_eq!(v.current(), 1000.0);

        // Fewer than a full window ⇒ no move (one lucky low hash can't crater it).
        assert!(v.note_low_share(0.5).is_none());
        assert!(v.note_low_share(0.5).is_none());
        // The window completes ⇒ a downward move (step-clamped to ¼×).
        let d1 = v.note_low_share(0.5).expect("full window must retarget down");
        assert!(d1 < 1000.0, "must lower, got {d1}");
        assert!(d1 >= 1000.0 * 0.25 - 1e-9, "never more than 4x per step");
        assert!(v.needs_announce(), "a downward retarget re-arms announce");

        // Keep feeding genuine ~diff-0.5 shares: it must keep descending toward
        // ~0.5 and STOP there (never overshoots below the miner's real work).
        let mut last = d1;
        for _ in 0..40 {
            for _ in 0..3 {
                if let Some(d) = v.note_low_share(0.5) {
                    last = d;
                }
            }
        }
        assert!(
            (0.2..=0.6).contains(&last),
            "must converge near the miner's real difficulty ~0.5, got {last}"
        );
    }

    #[test]
    fn note_low_share_is_downward_only_and_never_raises() {
        let mut v = Vardiff::from_cfg(&ProxyConfig {
            vardiff_initial: 1.0,
            vardiff_min: 0.001,
            vardiff_max: 1e9,
            vardiff_retarget_shares: 2,
            ..ProxyConfig::default()
        });
        // Even huge achieved samples (miner briefly stronger than announced)
        // must NEVER raise from this path — that is on_accepted's job, and a
        // raise here would recreate the reject-race this escape exists to fix.
        assert!(v.note_low_share(1000.0).is_none());
        let out = v.note_low_share(1000.0);
        assert!(out.is_none() || out.unwrap() <= 1.0, "note_low_share must never raise");
        assert!(v.current() <= 1.0);
    }

    #[test]
    fn accepted_share_clears_low_share_evidence() {
        // A healthy miner (accepts interleaved with the odd low share) must
        // never trip the downward escape: an accept clears the evidence window.
        let mut v = Vardiff::from_cfg(&ProxyConfig {
            vardiff_initial: 100.0,
            vardiff_min: 0.001,
            vardiff_max: 1e9,
            vardiff_retarget_shares: 3,
            ..ProxyConfig::default()
        });
        assert!(v.note_low_share(0.5).is_none());
        assert!(v.note_low_share(0.5).is_none());
        // An accept wipes the two pending low observations.
        v.on_accepted(Instant::now(), 100.0);
        // So the next two low shares are only 2/3 of a fresh window ⇒ no move.
        assert!(v.note_low_share(0.5).is_none());
        assert!(v.note_low_share(0.5).is_none());
        assert_eq!(v.current(), 100.0, "healthy miner must not trip the escape");
    }

    #[test]
    fn set_difficulty_line_is_valid_and_integral() {
        let v = Vardiff::from_cfg(&cfg());
        let line = v.set_difficulty_line();
        let framed = crate::codec::classify_server(&line).expect("valid json");
        match framed.parsed {
            crate::types::ServerMsg::SetDifficulty(d) => assert_eq!(d, 1024.0),
            other => panic!("expected SetDifficulty, got {other:?}"),
        }
        assert!(line.contains("1024"), "integral diff has no trailing .0");
    }
}
