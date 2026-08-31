// SPDX-License-Identifier: AGPL-3.0-or-later

//! Clock-versus-peer-time sanity check — the boot gate the weak-subjectivity
//! spec calls for and the 2026-08-31 adversarial audit found missing.
//!
//! ## Why this exists
//!
//! Every weak-subjectivity boot decision pivots on `wall_epoch`, and
//! `wall_epoch` is computed from the host clock — the ONLY
//! attacker-influenceable input to the gate. Roll a fresh node's clock back
//! toward genesis and `anchor_age (== wall_epoch)` drops inside the
//! `WS_PERIOD_EPOCHS` launch trust-once window, so the node boots with **no
//! checkpoint at all** and syncs whatever history its peers offer. One bad
//! boot is permanent: the first finalized epoch on the forged chain flips
//! `has_local_finality`, and every later boot is `Resume`. The same rollback
//! defeats freshness — `anchor_age = wall_epoch.saturating_sub(anchor.epoch)`
//! saturates to 0 below a stale anchor's epoch, so an arbitrarily old
//! checkpoint passes. `bloch_pos_committee::ws` (§1) says the node "SHOULD
//! refuse to start if its clock disagrees grossly with peer time"; this
//! module is that refusal.
//!
//! ## What this is, and is not
//!
//! **Node-local policy.** It changes when a node REFUSES TO START, never what
//! it accepts: no block, attestation or checkpoint becomes valid or invalid
//! because of anything here, so two nodes with different margins cannot fork —
//! the 2026-08-08 `expected_bits` lesson does not apply. It is a screen
//! against the *cheap* clock attack (NTP spoofing, a restored VM snapshot, a
//! mis-set RTC — no peer control needed), not an eclipse defense: the
//! comparison set is the peers this node was configured to dial, so an
//! attacker who already owns that list owns the median too. What the check
//! buys is the upgrade of "flip the victim's clock" into "flip the victim's
//! clock AND control a majority of its chosen peers AND serve a consistent
//! forged history" — the last of which was already the launch-window
//! trust-on-first-use exposure this cannot remove.
//!
//! ## The sample
//!
//! A solicited request/response: each transport asks the peers *this node
//! dialed* for their `now_ms` and records the **skew** — `peer_now_ms −
//! local_now_ms` at receipt — rather than the raw timestamp. Skew is
//! time-invariant while both clocks tick at the same rate, so a sample taken
//! when the connection opened is still meaningful after an hours-long replay,
//! and the boot gate never has to reason about sample age. Inbound peers
//! contribute nothing: they chose us, sybils are free, and a median anyone
//! can join is a median anyone can own.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bloch_pos_committee::params::SLOTS_PER_EPOCH;

/// Unix time in milliseconds — the same clock the engine's `now_ms` reads.
/// Duplicated (three lines) rather than exported from `engine` so the
/// transports do not grow a dependency on the engine module for a timestamp.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// The margin
// ---------------------------------------------------------------------------

/// The tolerated |median skew|, in wall milliseconds: **half an epoch on this
/// network's own slot geometry**.
///
/// The bound is argued from both sides, not guessed:
///
/// - **It must be below one epoch.** The epoch is the coarsest clock-derived
///   unit any consensus-adjacent decision reads: attestation admission
///   accepts only `{wall_epoch, wall_epoch + 1}` (`Engine::on_attestation`),
///   proposals are built for the wall slot, and every weak-subjectivity age
///   is denominated in epochs. A node whose clock is a full epoch wrong is
///   consensus-defective whatever the WS gate says — its attestations are
///   refused network-wide and its proposals land in slots nobody accepts —
///   so any margin ≥ 1 epoch would knowingly boot a broken participant.
/// - **It must be far above honest skew.** Honest error is NTP-scale
///   (milliseconds), plus sampling error (one connection RTT, sub-second),
///   plus the drift of an undisciplined clock between boots (seconds per
///   day — minutes after a month off NTP). On mainnet geometry (32 × 30 s)
///   half an epoch is 8 minutes: every honest source fits with room to
///   spare, and tripping it takes a clock that is *operationally* broken for
///   a slots-based chain, where refusing to start is the correct answer
///   anyway.
///
/// Half an epoch sits at the midpoint of those two failure modes and scales
/// with the manifest (`slot_ms`), so a 500 ms-slot devnet gets 8 s — the
/// same *meaning* on its faster clock. Note the asymmetry of what is being
/// caught: the actual WS exploit needs the clock wrong by hundreds of epochs
/// (to re-enter a 2016-epoch window), so the margin has orders of magnitude
/// of headroom against the attack; the tight side of the argument is epoch-
/// level consensus correctness, and that is the side the bound is set by.
pub fn margin_ms(slot_ms: u64) -> u64 {
    (SLOTS_PER_EPOCH / 2).saturating_mul(slot_ms)
}

/// How long boot will wait for the transports to produce samples before
/// judging with what it has. Devnet TCP answers in milliseconds and libp2p in
/// under a second on a LAN; ten seconds covers a slow WAN dial and is paid
/// only when peers are configured and samples have not yet arrived (a node
/// that spent hours in replay finds its samples already recorded).
pub const SAMPLE_WAIT: Duration = Duration::from_secs(10);

/// How many peer samples the gate would like before judging. More would make
/// the median sturdier; fleets of two or three configured peers are normal,
/// so the wait targets `min(configured_peers, this)` and the gate judges
/// whatever actually answered.
pub const TARGET_SAMPLES: usize = 3;

// ---------------------------------------------------------------------------
// The shared sample registry
// ---------------------------------------------------------------------------

/// Peer clock samples, written by the transports and read once by the boot
/// gate. One slot per peer key (devnet: the configured `host:port`; libp2p:
/// the `PeerId`), latest sample wins — a peer gets one vote however many
/// times it answers, which is the property the median leans on.
#[derive(Default)]
pub struct PeerClock {
    skews: Mutex<HashMap<String, i64>>,
}

impl PeerClock {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one answer: `peer_now_ms` as the peer reported it,
    /// `local_now_ms` read at receipt. Stored as the difference so the
    /// sample never goes stale (see the module header).
    pub fn record(&self, peer: &str, peer_now_ms: u64, local_now_ms: u64) {
        let skew = peer_now_ms as i64 - local_now_ms as i64;
        if let Ok(mut m) = self.skews.lock() {
            m.insert(peer.to_string(), skew);
        }
    }

    /// Every peer's latest skew, unordered.
    pub fn skews(&self) -> Vec<(String, i64)> {
        self.skews
            .lock()
            .map(|m| m.iter().map(|(k, v)| (k.clone(), *v)).collect())
            .unwrap_or_default()
    }

    pub fn len(&self) -> usize {
        self.skews.lock().map(|m| m.len()).unwrap_or(0)
    }

    /// Block until `want` peers have answered or `deadline` passes. Returns
    /// the number of samples present when it stopped waiting.
    pub fn wait_for(&self, want: usize, deadline: Duration) -> usize {
        let start = Instant::now();
        loop {
            let n = self.len();
            if n >= want || start.elapsed() >= deadline {
                return n;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

// ---------------------------------------------------------------------------
// The rule
// ---------------------------------------------------------------------------

/// What the gate concluded about the local clock.
#[derive(Debug, PartialEq, Eq)]
pub enum ClockVerdict {
    /// No peer answered — nothing to compare against. The caller proceeds
    /// (see [`gate`] for why) and must say so loudly.
    NoSamples,
    /// The median peer disagreement is within the margin.
    Ok { median_ms: i64, samples: usize },
    /// The median peer disagreement exceeds the margin: the caller must
    /// refuse to start.
    Refuse { median_ms: i64, samples: usize },
}

/// Median of the skews. Even count averages the two middles; with every
/// honest sample within seconds of zero the average changes nothing, and the
/// breakdown point is the same — an attacker still needs strictly more than
/// half the samples to place the median.
pub fn median_skew(skews: &[i64]) -> Option<i64> {
    if skews.is_empty() {
        return None;
    }
    let mut s = skews.to_vec();
    s.sort_unstable();
    let n = s.len();
    Some(if n % 2 == 1 {
        s[n / 2]
    } else {
        // Midpoint without overflow (skews can be near ±u64 range in theory).
        let a = s[n / 2 - 1];
        let b = s[n / 2];
        a / 2 + b / 2 + (a % 2 + b % 2) / 2
    })
}

/// The refusal rule (§1 of the WS spec, "refuse to start if its clock
/// disagrees grossly with peer time"): refuse iff `|median skew| > margin`.
///
/// **The bootstrap case is a decision, not an accident.** With zero samples
/// this returns [`ClockVerdict::NoSamples`] and the caller PROCEEDS, loudly.
/// The alternative — refuse without corroboration — would make the first
/// node of a network, a deliberately isolated devnet, and every
/// no-peers test harness unstartable, and would hand any attacker who can
/// merely *silence* the probe (drop one frame type; run an old binary) a
/// boot denial-of-service. The cost of proceeding is stated honestly: an
/// attacker who can set the victim's clock AND ensure no configured peer
/// answers keeps the original hole open. That attacker is already most of
/// the way to an eclipse, against which this check never claimed to stand —
/// the answer to eclipse remains the checkpoint, not the clock.
pub fn gate(skews: &[i64], margin_ms: u64) -> ClockVerdict {
    match median_skew(skews) {
        None => ClockVerdict::NoSamples,
        Some(median_ms) => {
            let samples = skews.len();
            if median_ms.unsigned_abs() > margin_ms {
                ClockVerdict::Refuse { median_ms, samples }
            } else {
                ClockVerdict::Ok { median_ms, samples }
            }
        }
    }
}

/// The refusal text: the observed skew, every voter, and both ways out. The
/// refusal is the mechanism working, so the message says so — and it names
/// the second possibility (a lying peer majority) instead of gaslighting an
/// operator whose clock is actually right.
pub fn refusal_message(median_ms: i64, samples: usize, margin_ms: u64, skews: &[(String, i64)]) -> String {
    let mut per_peer = String::new();
    for (peer, skew) in skews {
        per_peer.push_str(&format!("\n    {peer}: {:+.1} s", *skew as f64 / 1000.0));
    }
    format!(
        "ERR_CLOCK_SKEW: this node's clock disagrees with its peers by {:+.1} s \
         (median of {samples} peer sample{}; tolerated margin ±{:.1} s, half an \
         epoch on this network's slot geometry). Refusing to start: every \
         weak-subjectivity boot decision is computed from this clock, and a \
         clock this far off would let the node mis-judge checkpoint freshness \
         and its own place in the slot schedule. Per-peer skew (peer − local):{per_peer}\n\
         This refusal is the mechanism working, not a fault. Either fix this \
         host's clock (chrony/ntpd, then verify with `chronyc tracking` or \
         `ntpq -p`) — or, if the clock is independently verified correct, a \
         majority of the configured peers is lying about the time and they \
         should not be trusted with history either: replace the peer list \
         before syncing anything from it.",
        median_ms as f64 / 1000.0,
        if samples == 1 { "" } else { "s" },
        margin_ms as f64 / 1000.0,
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const MARGIN: u64 = 480_000; // mainnet geometry: 16 slots × 30 s

    #[test]
    fn margin_is_half_an_epoch_of_the_manifest_geometry() {
        // Mainnet: 32 slots × 30 s ⇒ half an epoch is 480 s.
        assert_eq!(margin_ms(30_000), 480_000);
        // A 500 ms-slot devnet gets the same *meaning* on its faster clock.
        assert_eq!(margin_ms(500), 8_000);
        // The margin must stay strictly below one epoch — the coarsest unit
        // consensus reads from the clock — or the gate would knowingly boot
        // a node whose attestations the network refuses.
        assert!(margin_ms(30_000) < SLOTS_PER_EPOCH * 30_000);
    }

    #[test]
    fn median_odd_even_empty() {
        assert_eq!(median_skew(&[]), None);
        assert_eq!(median_skew(&[7]), Some(7));
        assert_eq!(median_skew(&[-5, 100, 3]), Some(3));
        assert_eq!(median_skew(&[2, 4]), Some(3));
        assert_eq!(median_skew(&[-3, -1]), Some(-2));
    }

    #[test]
    fn honest_skew_passes() {
        // Three NTP-disciplined peers: milliseconds of disagreement.
        let v = gate(&[120, -80, 45], MARGIN);
        assert_eq!(v, ClockVerdict::Ok { median_ms: 45, samples: 3 });
    }

    #[test]
    fn boundary_is_refuse_strictly_beyond_the_margin() {
        // Exactly at the margin still boots; one millisecond past does not.
        assert!(matches!(gate(&[MARGIN as i64], MARGIN), ClockVerdict::Ok { .. }));
        assert!(matches!(gate(&[MARGIN as i64 + 1], MARGIN), ClockVerdict::Refuse { .. }));
        assert!(matches!(gate(&[-(MARGIN as i64) - 1], MARGIN), ClockVerdict::Refuse { .. }));
    }

    /// THE audit scenario: the local clock rolled back toward genesis to
    /// re-enter the launch trust-once window. Honest peers report real time,
    /// so every skew is hugely positive (peer − local), and the gate refuses
    /// before the WS gate ever computes its forged `wall_epoch`.
    #[test]
    fn rolled_back_clock_is_refused() {
        let three_days_ms = 3 * 86_400_000_i64;
        let skews = [three_days_ms, three_days_ms + 900, three_days_ms - 1_200];
        match gate(&skews, MARGIN) {
            ClockVerdict::Refuse { median_ms, samples } => {
                assert_eq!(samples, 3);
                assert!(median_ms > MARGIN as i64);
            }
            v => panic!("a clock three days behind its peers booted: {v:?}"),
        }
    }

    /// A clock rolled FORWARD is refused too: it would inflate every anchor's
    /// apparent age (false ERR_WS_STALE) and attest into epochs nobody is in.
    #[test]
    fn rolled_forward_clock_is_refused() {
        let skews = [-3_600_000, -3_601_000, -3_599_000]; // peers an hour "behind" us
        assert!(matches!(gate(&skews, MARGIN), ClockVerdict::Refuse { .. }));
    }

    /// One lying peer among honest ones cannot move the median.
    #[test]
    fn hostile_minority_is_outvoted() {
        let skews = [-(30 * 86_400_000_i64), 40, -15]; // one liar claims we are a month ahead
        assert!(matches!(gate(&skews, MARGIN), ClockVerdict::Ok { .. }));
    }

    /// A hostile MAJORITY owns the median — stated, not hidden. With the
    /// local clock objectively correct, two liars out of three force a
    /// refusal. That is the failure mode this defense accepts: a lying peer
    /// majority can DENY BOOT (loud, operator-visible, recoverable by fixing
    /// the peer list) — a nuisance, not a compromise, because this gate only
    /// ever decides whether to start, never what is valid.
    #[test]
    fn hostile_majority_can_deny_boot_but_only_deny() {
        let lie = 7 * 86_400_000_i64;
        let skews = [lie, lie + 500, 20]; // two liars, one honest peer
        assert!(matches!(gate(&skews, MARGIN), ClockVerdict::Refuse { .. }));
    }

    /// The residual hole, documented as a test: a hostile majority can also
    /// CONFIRM a wrong clock (replay-era peers agreeing with a rolled-back
    /// victim). The gate passes — which is exactly the "attacker controls
    /// the peers" boundary the module header draws. The defense against a
    /// peer set that owns both your history and your time reference is the
    /// signed checkpoint, and was never going to be a clock comparison.
    #[test]
    fn hostile_majority_agreeing_with_a_wrong_clock_passes() {
        let skews = [10, -25, 60]; // liars mirror the victim's rolled-back clock
        assert!(matches!(gate(&skews, MARGIN), ClockVerdict::Ok { .. }));
    }

    #[test]
    fn no_samples_is_its_own_verdict() {
        assert_eq!(gate(&[], MARGIN), ClockVerdict::NoSamples);
    }

    /// A simulated skewed clock through the REGISTRY: samples recorded the
    /// way the transports record them (peer report + local receipt time),
    /// with the local clock two days slow.
    #[test]
    fn peer_clock_records_skew_not_timestamps() {
        let real_now: u64 = 1_790_000_000_000;
        let local_now = real_now - 2 * 86_400_000; // this host is 2 days behind
        let clock = PeerClock::new();
        clock.record("peer-a:19001", real_now, local_now);
        clock.record("peer-b:19002", real_now + 300, local_now);
        let skews: Vec<i64> = clock.skews().into_iter().map(|(_, s)| s).collect();
        assert_eq!(skews.len(), 2);
        let m = median_skew(&skews).unwrap();
        assert!((m - 2 * 86_400_000).abs() <= 300);
        assert!(matches!(gate(&skews, MARGIN), ClockVerdict::Refuse { .. }));
    }

    /// One peer, one vote: re-answering replaces, never accumulates — a
    /// chatty peer cannot stuff the median.
    #[test]
    fn latest_sample_per_peer_wins() {
        let clock = PeerClock::new();
        for i in 0..50 {
            clock.record("noisy:1", 1_000_000 + i, 1_000_000);
        }
        clock.record("quiet:2", 1_000_000, 1_000_000);
        assert_eq!(clock.len(), 2);
    }
}
