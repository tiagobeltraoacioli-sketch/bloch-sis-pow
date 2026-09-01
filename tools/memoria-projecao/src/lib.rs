// SPDX-License-Identifier: AGPL-3.0-or-later
//! # The Genesis-4 fleet memory projection, as a checked artefact
//!
//! There is a date on which 9 validators per Edgevana box exhaust 31,866 MiB.
//! The fleet programme sequences around it. It has been an arithmetic sketch
//! resting partly on numbers with no commit behind them — and every headline
//! number in this programme that lacked a commit behind it has turned out to
//! be wrong.
//!
//! So this crate does three things, and refuses to do a fourth.
//!
//! 1. It states the projection with **every input traceable** to a
//!    measurement, or explicitly marked [`Standing::Modelled`]. See [`INPUTS`].
//! 2. It **recomputes the dates from the live fleet's own numbers**, read out
//!    of `scripts/fleet-memory-observations.tsv`, which
//!    `scripts/fleet-memory-observe.sh` regenerates read-only.
//! 3. Its tests **fail when the fleet stops matching what the projection
//!    assumes** — not when someone edits a constant. A test that re-asserts a
//!    constant proves only that nobody retyped the line.
//!
//! The fourth thing, which it does not do: pretend the growth stops. See
//! [`WHAT_THIS_CANNOT_DO`].
//!
//! ## The denominator is SLOTS, not blocks
//!
//! This is the correction that matters most, and it arrived late enough to
//! have nearly been missed. Interval-by-interval on a real log, growth
//! measured **per block** comes out at 0.005, 0.032 and 0.011 MiB/block — a
//! sixfold disagreement, and any two endpoints would have produced any one of
//! them. The same intervals measured **per slot** are far steadier. Between
//! h=10,000 and h=15,000 the chain burned 21,187 slots to produce 5,000
//! blocks, and memory followed the slots.
//!
//! That matters because slots advance at exactly [`SLOTS_PER_DAY`] on the
//! wall clock whether or not anybody produces a block, while this chain's
//! block cadence has run anywhere from 24% to 100% of slots. Denominating in
//! blocks folds a variable that has moved by 4x into the rate. Denominating
//! in slots removes it, and the date becomes a function of the calendar
//! alone.
//!
//! The block cadence is therefore **no longer an input to the arithmetic** —
//! [`tests::the_date_does_not_move_when_only_the_block_cadence_moves`] proves
//! it is not — but it remains in the snapshot as a **tripwire**, because it
//! is the hidden variable that was hiding. If it moves again,
//! [`tests::the_slot_to_block_relation_is_still_what_the_projection_was_derived_under`]
//! fires, and that is the natural experiment which would confirm or refute
//! the slot hypothesis on live data.
//!
//! ## Peak and steady state are two curves, not one
//!
//! RSS is **not monotone across a replay**. On a real log it climbs while the
//! block map fills, peaks around h≈17,000–20,000, and then *falls* before the
//! replay ends: `VmHWM` 762.0 MiB against `VmRSS` 709.6 at h=20,000 and 675.3
//! at the end. So `/usr/bin/time -v`'s maximum answers a different question
//! from "how much is resident once the chain is loaded", and the two answers
//! enter this projection at different moments:
//!
//! * the **steady curve** is what a box carries between restarts. It grows.
//! * the **peak curve** is what a box must survive *during a replay*. It is
//!   the steady curve plus a premium, and it is paid at **every restart**.
//!
//! A box that survives running can still die in replay. That is why there are
//! two dates below and why the roll date is the earlier one.
//!
//! ## Why VmHWM is free evidence, and why it is only a floor
//!
//! Linux keeps `VmHWM` per process for the process's whole lifetime, so for
//! every validator the fleet is running right now, the boot peak it actually
//! paid is already recorded, kernel-measured, with no experiment. That is why
//! this projection can be checked against reality rather than against a model.
//!
//! It comes with one hard rule: **a mark set days ago was set against a
//! shorter chain, so it is a floor and never headroom.** Reading `MAX_HWM` as
//! spare capacity is the most available way to get this wrong in the
//! dangerous direction, so [`Snapshot::mark_staleness_slots`] surfaces the age
//! of every mark and
//! [`tests::roll_arm_rests_on_marks_that_are_still_informative`] fails when no
//! mark is recent enough to bound a boot today.

use std::collections::BTreeMap;
use std::fmt::Write as _;

// ─────────────────────────────────────────────────────────────── inputs ────

/// How much we are entitled to believe a number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    /// Read off a running kernel, a real chain, or an instrumented run on a
    /// real block log. `source` names where.
    Measured,
    /// Chosen, extrapolated, or assumed. Not wrong — but not evidence, and
    /// the error bars must be read as excluding it.
    Modelled,
    /// Correctly measured, in a denominator that turned out to be the wrong
    /// one. Kept visible because the number is still true of what it measured
    /// and will otherwise be quoted again.
    Superseded,
    /// Was published, was used, and is now known to be wrong. Recorded so it
    /// cannot quietly return. Never read by the arithmetic.
    Discredited,
}

/// One input, with its standing and its provenance.
#[derive(Debug, Clone, Copy)]
pub struct Input {
    pub name: &'static str,
    pub value: f64,
    pub unit: &'static str,
    pub standing: Standing,
    pub source: &'static str,
}

/// Slots per day. Exact, and the reason this projection is a calendar
/// projection: `SLOT_DURATION_SECS` is 30, asserted at
/// `crates/bloch-pos-node/src/main.rs:914`, so 86,400 / 30 = 2,880 slots
/// arrive every day whether or not anyone produces a block in them.
pub const SLOTS_PER_DAY: f64 = 2880.0;

/// Growth of the **steady curve** per validator, in MiB per slot, measured
/// interval by interval on a real log rather than between two endpoints.
///
/// MEASURED, three consecutive intervals, oldest first: 11.9, 21.8 and 27.6
/// MiB/day at [`SLOTS_PER_DAY`]. They are recorded as an array and not
/// averaged, because their disagreement IS the finding: growth is not a
/// single slope, and the same three intervals denominated per block spread
/// over 0.005–0.032 MiB/block, a sixfold range. The spread across these three
/// numbers, not any measurement error, is what sets the width of the dates.
///
/// They are also **rising**. The projection therefore uses the most recent
/// interval as its binding rate and treats the older ones as the optimistic
/// bound — and if the rise continues, even the binding rate is too low and
/// the real date is earlier than the one printed here.
pub const STEADY_MIB_PER_DAY_INTERVALS: [f64; 3] = [11.9, 21.8, 27.6];

/// The binding rate: the most recent measured interval.
pub const STEADY_MIB_PER_DAY_RECENT: f64 = 27.6;
/// The optimistic bound: the oldest measured interval.
pub const STEADY_MIB_PER_DAY_OLDEST: f64 = 11.9;

/// The **peak premium**: how far a boot peak sits above the steady state that
/// follows it. Paid at every restart, and constant rather than growing — the
/// peak is a mid-replay transient, so it carries no growth information of its
/// own and the growth in the peak curve is the steady curve underneath it.
///
/// MEASURED two ways, which do not agree and are not expected to:
///   * 86.7 MiB absolute on an isolated single node (`VmHWM` 762.0 against
///     675.3 MiB at end of replay, h=20,000) — 12.8% of that node.
///   * 13–23% on the live fleet, where each validator also carries a
///     consensus and networking working set the isolated run does not.
///
/// The projection uses the fleet's own per-box `max VmHWM`, which needs no
/// premium constant at all; this is here so the tests can check that the
/// premium still exists and is still not a multiple.
pub const PEAK_PREMIUM_FRACTION_LO: f64 = 1.05;
pub const PEAK_PREMIUM_FRACTION_HI: f64 = 1.60;

/// The **second arm**: what removing signature material from the resident
/// block map buys. Two distinct effects, measured separately, and they must
/// not be conflated.
///
/// A one-off drop in the LEVEL: at end of replay the signature-material
/// saving is 116.8 MiB, 17.5% of resident. (At the *peak* it is only 55.3 MiB
/// / 7.3% — the peak is depressed by allocator arenas, which is a third
/// reason peak and steady are two curves and not one.)
pub const SIG_LEVEL_SAVING_FRACTION: f64 = 0.175;
/// A reduction in the RATE: growth above the 370.0 MiB genesis+carryover
/// plateau falls from 10,579 to 6,410 B per block.
pub const SIG_GROWTH_FACTOR: f64 = 6410.0 / 10579.0;

/// RAM held back from the validators for page cache and the OS.
///
/// MODELLED — a choice, not a measurement, inherited from
/// `scripts/fleet-memory-gate.sh`. The block log is read through the page
/// cache on every boot, so starving it trades RAM for a slower replay. The
/// live boxes were observed holding 5,459–8,136 MiB of page cache, which
/// means 3,072 MiB is if anything *low* — and a low reserve makes these dates
/// **later than they should be**.
pub const RESERVE_MIB_DEFAULT: f64 = 3072.0;

/// The block cadence the projection was derived under, as blocks per slot.
/// Not an input to the arithmetic — a tripwire. See the module header.
pub const BLOCKS_PER_SLOT_AT_DERIVATION: f64 = 0.982;
/// How far the cadence may move before the slot hypothesis becomes testable
/// on live data and every block-denominated figure still in circulation is
/// wrong by a factor of 1/cadence.
pub const BLOCKS_PER_SLOT_TOLERANCE: f64 = 0.15;

/// Every input, with its standing. The report prints this verbatim so nobody
/// has to take the arithmetic on trust.
pub const INPUTS: &[Input] = &[
    Input { name: "box RAM", value: 31866.0, unit: "MiB",
        standing: Standing::Measured,
        source: "/proc/meminfo on all 7 grandes; 31,866 on six, 31,867 on 149.28.180.128" },
    Input { name: "validators per box", value: 9.0, unit: "processes",
        standing: Standing::Measured,
        source: "argv scan of /proc on all 7 boxes: 63 processes carrying both `run` and `--data-dir`" },
    Input { name: "steady resident, per box", value: 11358.8, unit: "MiB",
        standing: Standing::Measured,
        source: "sum of VmRSS, worst box; range across the 7 boxes 10,416-11,359 MiB" },
    Input { name: "boot peak, per validator", value: 1513.1, unit: "MiB",
        standing: Standing::Measured,
        source: "max VmHWM, kernel-retained across the process lifetime; range 1,145-1,513 MiB" },
    Input { name: "slots per day", value: SLOTS_PER_DAY, unit: "slots",
        standing: Standing::Measured,
        source: "SLOT_DURATION_SECS = 30, asserted at crates/bloch-pos-node/src/main.rs:914" },
    Input { name: "steady growth, recent interval", value: STEADY_MIB_PER_DAY_RECENT, unit: "MiB/day/validator",
        standing: Standing::Measured,
        source: "third of three consecutive measured intervals on a real log; the binding rate" },
    Input { name: "steady growth, oldest interval", value: STEADY_MIB_PER_DAY_OLDEST, unit: "MiB/day/validator",
        standing: Standing::Measured,
        source: "first of three consecutive measured intervals; the optimistic bound" },
    Input { name: "peak premium over steady state", value: 86.7, unit: "MiB (12.8% single node; 13-23% on the fleet)",
        standing: Standing::Measured,
        source: "VmHWM 762.0 vs 675.3 MiB end-of-replay at h=20,000; and max VmHWM vs mean VmRSS per box" },
    Input { name: "signature material, level saving", value: SIG_LEVEL_SAVING_FRACTION, unit: "fraction of resident",
        standing: Standing::Measured,
        source: "116.8 MiB / 17.5% at end of replay; only 55.3 MiB / 7.3% at the peak, which allocator arenas depress" },
    Input { name: "signature material, growth-rate factor", value: SIG_GROWTH_FACTOR, unit: "x",
        standing: Standing::Measured,
        source: "per-block growth above the 370.0 MiB genesis+carryover plateau falls 10,579 -> 6,410 B/block" },
    Input { name: "the 17.5% level saving transfers to a fleet validator", value: 1.0, unit: "assumed",
        standing: Standing::Modelled,
        source: "measured on a ~667 MiB isolated node; fleet validators run ~1,200 MiB and carry a consensus working set the isolated run does not" },
    Input { name: "page-cache reserve", value: RESERVE_MIB_DEFAULT, unit: "MiB",
        standing: Standing::Modelled,
        source: "operator choice inherited from fleet-memory-gate.sh; boxes observed holding 5,459-8,136 MiB of cache" },
    Input { name: "the peak premium is constant, not growing", value: 1.0, unit: "assumed",
        standing: Standing::Modelled,
        source: "the peak is a mid-replay transient reached at h~17-20k; whether it grows with a LONGER chain is unmeasured" },
    Input { name: "growth stays linear in slots past today", value: 1.0, unit: "assumed",
        standing: Standing::Modelled,
        source: "MODELLED, and the three measured intervals are RISING (11.9, 21.8, 27.6), so linearity is the optimistic reading" },
    Input { name: "single-node replay rate transfers to a 9-per-box fleet", value: 1.0, unit: "assumed",
        standing: Standing::Modelled,
        source: "NOT MEASURED. See Snapshot::fleet_slope_is_confounded for why the fleet cannot report its own rate" },
    Input { name: "0.01473-0.01719 MiB/block", value: 0.01719, unit: "MiB/block",
        standing: Standing::Superseded,
        source: "correctly measured, wrong denominator: per-block rates fold in a block cadence that has run 24%-100% of slots" },
    Input { name: "2,873 blocks/day", value: 2873.0, unit: "blocks/day",
        standing: Standing::Superseded,
        source: "corroborated on the live chain at 2,827-2,872/day, but blocks are no longer the denominator; slots are" },
    Input { name: "0.0198 MiB/block", value: 0.0198, unit: "MiB/block",
        standing: Standing::Discredited,
        source: "measured on a tree lacking the boot-copy fix; overestimates; behind the retired 'early October' sketch" },
    Input { name: "86.1% of Engine::blocks is signature material", value: 0.861, unit: "fraction",
        standing: Standing::Discredited,
        source: "refuted: the proposer signature is 32.9% of a frame; the ~90% figure counts attestations too" },
];

/// What no arrangement of these numbers can deliver.
pub const WHAT_THIS_CANNOT_DO: &str = "\
WHAT THIS PROJECTION CANNOT DO

  Growth is linear in chain length -- and the three measured intervals are
  RISING, so linear is the optimistic reading. Nothing on the table makes
  memory bounded. Removing the signature term multiplies the date; it does
  not move it to infinity, because what is left is still a line with positive
  slope. Every improvement in flight removes a CONSTANT FACTOR from a curve
  that still rises forever. The date returns.

  A bounded design would be O(unfinalized + state), not O(chain): resident
  cost set by the unfinalized suffix (85 blocks today) plus the state, with
  history paged from the log. No current workstream aims there. Saying so is
  not a criticism of the work in flight, which is real and measured; it is
  the difference between postponing a date and removing one.

  And the irreducible term is not constant either. What survives every
  optimisation is the carryover eUTXO set, and that grows with USAGE, not
  with time. The validator-opening programme exists to add users. The one
  term nobody can optimise away is the one the roadmap is designed to grow.

  Two of the three ways this projection can be wrong point the same way --
  later than the truth. The VmHWM marks it reads are floors; the reserve it
  holds back is smaller than the page cache the boxes actually use; and the
  growth intervals are rising rather than flat. Read the dates as an upper
  bound on the time available, not as a forecast.";

// ──────────────────────────────────────────────────────────── the data ────

/// One validator process as the kernel reported it.
#[derive(Debug, Clone)]
pub struct Observation {
    pub box_ip: String,
    pub box_host: String,
    pub mem_total_mib: f64,
    pub mem_avail_mib: f64,
    pub cached_mib: f64,
    pub nproc: u32,
    pub unit: String,
    pub pid: u32,
    /// Peak resident set, kernel-retained for the process's lifetime.
    pub vmhwm_mib: f64,
    /// Resident set right now.
    pub vmrss_mib: f64,
    pub started_unix: i64,
    pub mark_age_s: i64,
    /// Chain height when this process started, read out of the archive.
    pub boot_height: Option<u64>,
}

/// A box, rolled up.
#[derive(Debug, Clone)]
pub struct BoxRollup {
    pub ip: String,
    pub host: String,
    pub mem_total_mib: f64,
    pub cached_mib: f64,
    pub validators: usize,
    pub sum_rss_mib: f64,
    pub sum_hwm_mib: f64,
    pub max_hwm_mib: f64,
    pub max_hwm_unit: String,
}

/// A kernel-measured reading of the whole fleet at one instant.
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub captured_unix: i64,
    pub chain_height: u64,
    pub chain_slot: u64,
    pub genesis_unix: i64,
    pub slot_secs: f64,
    /// Tripwire, not an input. See the module header.
    pub blocks_per_slot_measured: Option<f64>,
    pub blocks_per_day_measured: Option<f64>,
    pub cadence_window: String,
    pub rows: Vec<Observation>,
}

impl Snapshot {
    /// `BLOCH_FLEET_OBSERVATIONS` overrides the path. That is how
    /// `scripts/memoria-projecao-violacao.sh` proves these checks bite: point
    /// it at a deliberately falsified snapshot and watch them fail.
    pub fn default_path() -> std::path::PathBuf {
        if let Ok(p) = std::env::var("BLOCH_FLEET_OBSERVATIONS") {
            return std::path::PathBuf::from(p);
        }
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../scripts/fleet-memory-observations.tsv")
    }

    pub fn load_default() -> Result<Self, String> {
        let p = Self::default_path();
        let text = std::fs::read_to_string(&p).map_err(|e| {
            format!(
                "cannot read the fleet snapshot at {}: {e}\n\
                 Regenerate it, read-only, with:  scripts/fleet-memory-observe.sh",
                p.display()
            )
        })?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self, String> {
        let mut meta: BTreeMap<&str, &str> = BTreeMap::new();
        let mut rows = Vec::new();
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("# ") {
                let mut it = rest.splitn(2, '\t');
                if let (Some(k), Some(v)) = (it.next(), it.next()) {
                    meta.insert(k.trim(), v.trim());
                }
                continue;
            }
            if line.starts_with('#') || line.trim().is_empty() || line.starts_with("box_ip\t") {
                continue;
            }
            let f: Vec<&str> = line.split('\t').collect();
            if f.len() < 13 {
                return Err(format!(
                    "malformed observation row ({} fields): {line}",
                    f.len()
                ));
            }
            let num = |i: usize| -> Result<f64, String> {
                f[i].parse::<f64>().map_err(|_| {
                    format!(
                        "field {i} of an observation row is not a number: {:?}.\n\
                         A comma decimal separator here means the collector ran under a\n\
                         non-C locale; scripts/fleet-memory-observe.sh pins LC_ALL=C.",
                        f[i]
                    )
                })
            };
            rows.push(Observation {
                box_ip: f[0].to_string(),
                box_host: f[1].to_string(),
                mem_total_mib: num(2)?,
                mem_avail_mib: num(3)?,
                cached_mib: num(4)?,
                nproc: num(5)? as u32,
                unit: f[6].to_string(),
                pid: num(7)? as u32,
                vmhwm_mib: num(8)?,
                vmrss_mib: num(9)?,
                started_unix: num(10)? as i64,
                mark_age_s: num(11)? as i64,
                boot_height: f[12].parse::<u64>().ok(),
            });
        }
        if rows.is_empty() {
            return Err("snapshot carries no validator rows".to_string());
        }
        let need = |k: &str| -> Result<&str, String> {
            meta.get(k)
                .copied()
                .ok_or_else(|| format!("snapshot has no `# {k}` header"))
        };
        let getf = |k: &str| meta.get(k).and_then(|v| v.parse::<f64>().ok());
        Ok(Snapshot {
            captured_unix: need("captured_unix")?
                .parse()
                .map_err(|_| "bad captured_unix")?,
            chain_height: need("chain_height")?
                .parse()
                .map_err(|_| "bad chain_height")?,
            chain_slot: need("chain_slot")?.parse().map_err(|_| "bad chain_slot")?,
            genesis_unix: need("genesis_unix")?
                .parse()
                .map_err(|_| "bad genesis_unix")?,
            slot_secs: getf("slot_secs").unwrap_or(30.0),
            blocks_per_slot_measured: getf("blocks_per_slot_measured"),
            blocks_per_day_measured: getf("blocks_per_day_measured"),
            cadence_window: meta
                .get("blocks_per_day_window")
                .copied()
                .unwrap_or("unrecorded")
                .to_string(),
            rows,
        })
    }

    pub fn boxes(&self) -> Vec<BoxRollup> {
        let mut by: BTreeMap<&str, Vec<&Observation>> = BTreeMap::new();
        for r in &self.rows {
            by.entry(r.box_ip.as_str()).or_default().push(r);
        }
        by.into_iter()
            .map(|(ip, rs)| {
                let top = rs
                    .iter()
                    .max_by(|a, b| a.vmhwm_mib.total_cmp(&b.vmhwm_mib))
                    .expect("non-empty");
                BoxRollup {
                    ip: ip.to_string(),
                    host: rs[0].box_host.clone(),
                    mem_total_mib: rs[0].mem_total_mib,
                    cached_mib: rs[0].cached_mib,
                    validators: rs.len(),
                    sum_rss_mib: rs.iter().map(|r| r.vmrss_mib).sum(),
                    sum_hwm_mib: rs.iter().map(|r| r.vmhwm_mib).sum(),
                    max_hwm_mib: top.vmhwm_mib,
                    max_hwm_unit: top.unit.clone(),
                }
            })
            .collect()
    }

    /// The slot at which a process started. Exact: slots are a fixed
    /// `slot_secs` off genesis, so this is arithmetic on the wall clock and
    /// not an inference from block heights.
    pub fn boot_slot(&self, o: &Observation) -> u64 {
        ((o.started_unix - self.genesis_unix).max(0) as f64 / self.slot_secs) as u64
    }

    /// **Slots** — not blocks — since the most recently booted validator set
    /// its mark. Slots, because that is what the growth follows; measuring
    /// this staleness in blocks would understate it by 1/cadence exactly when
    /// the chain is slow, which is exactly when it matters.
    pub fn mark_staleness_slots(&self) -> u64 {
        let newest = self
            .rows
            .iter()
            .map(|o| self.boot_slot(o))
            .max()
            .unwrap_or(0);
        self.chain_slot.saturating_sub(newest)
    }

    /// **Why the fleet's own VmHWM spread cannot be used as a growth rate.**
    ///
    /// It is tempting: 63 validators booted at 63 different chain lengths, so
    /// regressing VmHWM on boot height looks like a free, kernel-measured
    /// rate. Doing it yields 0.17–0.30 MiB/block within six of the seven
    /// boxes at r = 0.84–0.99 — ten to twenty times any replay-measured rate
    /// — and the seventh box returns a NEGATIVE rate at r = -0.51.
    ///
    /// It is not a rate. The fleet was migrated in batches, so within a box
    /// the k-th validator to boot is *both* the k-th highest boot height *and*
    /// the one that booted with k-1 siblings already resident and competing
    /// for page cache. Boot order and chain length are perfectly collinear
    /// within a box, and the batches interleaved across boxes, so nothing in
    /// this data separates them. The negative box is the tell.
    ///
    /// Recorded here so the next person does not spend the afternoon
    /// rediscovering it and, worse, publishing the answer.
    pub const fn fleet_slope_is_confounded() -> &'static str {
        "boot order and boot height are collinear within a box; not separable from this data"
    }

    /// The box that binds, in each regime. Chosen by days-to-exhaustion, not
    /// by raw headroom: the boxes are the same size today, but a PMO
    /// reservation table may not leave them that way, and a selector that
    /// assumes uniformity would quietly report the wrong box the day it stops
    /// being true.
    fn binding_box(&self, reserve: f64, rate: f64, need: impl Fn(&BoxRollup) -> f64) -> BoxRollup {
        let mut b = self.boxes();
        b.sort_by(|x, y| {
            let d = |c: &BoxRollup| {
                days_until(
                    c.mem_total_mib - reserve - need(c),
                    rate,
                    c.validators as f64,
                )
            };
            d(x).total_cmp(&d(y))
        });
        b.remove(0)
    }
}

// ────────────────────────────────────────────────────────── projection ────

/// Days until a box runs out, given headroom and a **calendar** rate per
/// validator. There is deliberately no block-rate parameter: the denominator
/// is the wall clock.
pub fn days_until(headroom_mib: f64, mib_per_day_per_validator: f64, validators: f64) -> f64 {
    let burn = validators * mib_per_day_per_validator;
    // Order matters, and getting it wrong is not cosmetic. Folding
    // `headroom <= 0` into the same branch as `burn <= 0` returns INFINITY for
    // a box that is ALREADY over capacity, which makes the most endangered box
    // in the fleet sort as the safest and drop out of every "binding box"
    // selection. Exhausted is zero days, not infinite days.
    if headroom_mib <= 0.0 {
        return 0.0;
    }
    if burn <= 0.0 {
        return f64::INFINITY;
    }
    headroom_mib / burn
}

/// A date expressed as a band, because a single date would misrepresent the
/// width of the inputs.
#[derive(Debug, Clone, Copy)]
pub struct Band {
    /// Days from capture at the binding (most recent, fastest) rate.
    pub days_lo: f64,
    /// Days from capture at the optimistic (oldest, slowest) rate.
    pub days_hi: f64,
    pub unix_lo: i64,
    pub unix_hi: i64,
}

impl Band {
    fn new(captured: i64, days_lo: f64, days_hi: f64) -> Self {
        // The optimistic arm can be genuinely infinite, and
        // `captured + (f64::INFINITY * 86400.0) as i64` overflows i64 and
        // panics in a debug build. Saturate.
        let at = |d: f64| -> i64 {
            if !d.is_finite() {
                i64::MAX
            } else {
                captured.saturating_add((d * 86400.0) as i64)
            }
        };
        Band {
            days_lo,
            days_hi,
            unix_lo: at(days_lo),
            unix_hi: at(days_hi),
        }
    }
    pub fn lo_date(&self) -> String {
        ymd(self.unix_lo)
    }
    pub fn hi_date(&self) -> String {
        if self.days_hi.is_finite() {
            ymd(self.unix_hi)
        } else {
            "unbounded".into()
        }
    }
}

#[derive(Debug, Clone)]
pub struct Projection {
    pub captured_unix: i64,
    pub chain_height: u64,
    pub chain_slot: u64,
    pub reserve_mib: f64,
    /// Nine validators booting at once. The earlier date; the one an operator
    /// plans a roll against.
    pub roll: Band,
    /// Nine validators resident, nobody touching them. The later date.
    pub drift: Band,
    /// The same two dates with the signature term removed: a one-off drop in
    /// the level plus a reduced growth rate. Both measured; the transfer of
    /// the level fraction to a fleet validator is the modelled part.
    pub roll_nosig: Band,
    pub drift_nosig: Band,
    pub roll_box: BoxRollup,
    pub drift_box: BoxRollup,
    /// Days the roll date moves if the page-cache reserve is halved.
    pub reserve_sensitivity_days: f64,
    /// Days between the best and the worst box, roll regime.
    pub box_spread_days: f64,
    pub mark_staleness_slots: u64,
}

/// Build the projection **from the snapshot**. Box size, validator count,
/// resident set and boot peaks all come off the live fleet. Only the growth
/// rate is a constant, because it is the one input the fleet cannot report
/// about itself — see [`Snapshot::fleet_slope_is_confounded`]. The block
/// cadence is not read at all.
pub fn project(snap: &Snapshot, reserve_mib: f64) -> Projection {
    let fast = STEADY_MIB_PER_DAY_RECENT;
    let slow = STEADY_MIB_PER_DAY_OLDEST;

    // Nine SIMULTANEOUS peaks is max_hwm x N, not the sum of the nine marks.
    // The nine marks were set minutes-to-days apart, each with a different
    // number of siblings already resident, so their sum is not a picture of
    // nine peaks at once and is systematically too small.
    let roll_need = |b: &BoxRollup| b.max_hwm_mib * b.validators as f64;
    let drift_need = |b: &BoxRollup| b.sum_rss_mib;

    let rbox = snap.binding_box(reserve_mib, fast, roll_need);
    let dbox = snap.binding_box(reserve_mib, fast, drift_need);

    let rn = rbox.validators as f64;
    let rhead = rbox.mem_total_mib - reserve_mib - roll_need(&rbox);
    let dn = dbox.validators as f64;
    let dhead = dbox.mem_total_mib - reserve_mib - drift_need(&dbox);

    let roll = Band::new(
        snap.captured_unix,
        days_until(rhead, fast, rn),
        days_until(rhead, slow, rn),
    );
    let drift = Band::new(
        snap.captured_unix,
        days_until(dhead, fast, dn),
        days_until(dhead, slow, dn),
    );

    let rhead_half = rbox.mem_total_mib - reserve_mib / 2.0 - roll_need(&rbox);
    let best = snap
        .boxes()
        .into_iter()
        .map(|b| {
            days_until(
                b.mem_total_mib - reserve_mib - roll_need(&b),
                fast,
                b.validators as f64,
            )
        })
        .fold(f64::NEG_INFINITY, f64::max);

    // Second arm. The one-off level saving lowers the starting point; the
    // growth factor lowers the slope. Both are needed: the level saving alone
    // buys a fixed number of days and the rate saving alone buys a multiple.
    let rn_need = roll_need(&rbox) * (1.0 - SIG_LEVEL_SAVING_FRACTION);
    let dn_need = drift_need(&dbox) * (1.0 - SIG_LEVEL_SAVING_FRACTION);
    let rhead_ns = rbox.mem_total_mib - reserve_mib - rn_need;
    let dhead_ns = dbox.mem_total_mib - reserve_mib - dn_need;
    let roll_nosig = Band::new(
        snap.captured_unix,
        days_until(rhead_ns, fast * SIG_GROWTH_FACTOR, rn),
        days_until(rhead_ns, slow * SIG_GROWTH_FACTOR, rn),
    );
    let drift_nosig = Band::new(
        snap.captured_unix,
        days_until(dhead_ns, fast * SIG_GROWTH_FACTOR, dn),
        days_until(dhead_ns, slow * SIG_GROWTH_FACTOR, dn),
    );

    Projection {
        roll_nosig,
        drift_nosig,
        captured_unix: snap.captured_unix,
        chain_height: snap.chain_height,
        chain_slot: snap.chain_slot,
        reserve_mib,
        roll,
        drift,
        roll_box: rbox,
        drift_box: dbox,
        reserve_sensitivity_days: days_until(rhead_half, fast, rn) - roll.days_lo,
        box_spread_days: best - roll.days_lo,
        mark_staleness_slots: snap.mark_staleness_slots(),
    }
}

// ─────────────────────────────────────────────────────── documented claim ──

/// The dates this repo publishes, as days from the snapshot that produced
/// them. The tests recompute from a fresh snapshot and fail when reality has
/// moved them by more than [`CLAIM_TOLERANCE_DAYS`]. That is the staleness
/// alarm: nobody has to remember to look.
pub const CLAIMED_ROLL_DAYS: f64 = 61.1;
pub const CLAIMED_DRIFT_DAYS: f64 = 70.2;
/// Seven days: less than that and the programme's sequencing does not change;
/// more and a week of plan rests on a number that no longer holds.
pub const CLAIM_TOLERANCE_DAYS: f64 = 7.0;

/// Snapshot older than this and the projection is not evidence any more.
pub const SNAPSHOT_MAX_AGE_DAYS: f64 = 14.0;

/// If the freshest VmHWM on the fleet was set more slots ago than this, no
/// mark on the fleet bounds a boot today and the roll arm is unsupported.
/// 20,160 slots is exactly seven days on the wall clock.
pub const MARK_MAX_STALENESS_SLOTS: u64 = 20_160;

// ───────────────────────────────────────────────────────────── reporting ───

fn ymd(unix: i64) -> String {
    // civil_from_days, Howard Hinnant. No dependency is worth a date.
    let z = unix.div_euclid(86400) + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    format!("{:04}-{:02}-{:02}", if m <= 2 { y + 1 } else { y }, m, d)
}

impl Projection {
    pub fn report(&self, snap: &Snapshot) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "GENESIS-4 FLEET MEMORY PROJECTION");
        let _ = writeln!(
            s,
            "recomputed from scripts/fleet-memory-observations.tsv, not restated\n"
        );
        let _ = writeln!(
            s,
            "snapshot   {}   chain height {}   slot {}",
            ymd(self.captured_unix),
            self.chain_height,
            self.chain_slot
        );
        let _ = writeln!(
            s,
            "rate       {:.1} MiB/day/validator MEASURED (binding), {:.1} optimistic",
            STEADY_MIB_PER_DAY_RECENT, STEADY_MIB_PER_DAY_OLDEST
        );
        let _ = writeln!(
            s,
            "           denominated in SLOTS ({:.0}/day, wall clock), not in blocks",
            SLOTS_PER_DAY
        );
        let _ = writeln!(
            s,
            "reserve    {:.0} MiB held for page cache (MODELLED)\n",
            self.reserve_mib
        );

        let _ = writeln!(
            s,
            "{:<16} {:>6} {:>7} {:>3} {:>9} {:>9} {:>9}",
            "BOX", "TOTAL", "CACHED", "N", "SUM_RSS", "SUM_HWM", "MAX_HWM"
        );
        for b in snap.boxes() {
            let _ = writeln!(
                s,
                "{:<16} {:>6.0} {:>7.0} {:>3} {:>9.1} {:>9.1} {:>9.1}",
                b.ip,
                b.mem_total_mib,
                b.cached_mib,
                b.validators,
                b.sum_rss_mib,
                b.sum_hwm_mib,
                b.max_hwm_mib
            );
        }

        let _ = writeln!(s, "\nTWO CURVES, TWO DATES. They are not the same risk.\n");
        let _ = writeln!(
            s,
            "  ROLL   nine validators boot at once -- the PEAK curve, paid at every restart\n\
             \x20        {} .. {}   ({:.1}-{:.1} days)   binds on {} ({})\n\
             \x20        need {:.0} MiB = 9 x {:.1} peak against {:.0} MiB of capacity",
            self.roll.lo_date(),
            self.roll.hi_date(),
            self.roll.days_lo,
            self.roll.days_hi,
            self.roll_box.ip,
            self.roll_box.max_hwm_unit,
            self.roll_box.max_hwm_mib * self.roll_box.validators as f64,
            self.roll_box.max_hwm_mib,
            self.roll_box.mem_total_mib - self.reserve_mib
        );
        let _ = writeln!(
            s,
            "\n  DRIFT  nine validators resident, nobody touching them -- the STEADY curve\n\
             \x20        {} .. {}   ({:.1}-{:.1} days)   binds on {}\n\
             \x20        need {:.1} MiB resident against {:.0} MiB of capacity",
            self.drift.lo_date(),
            self.drift.hi_date(),
            self.drift.days_lo,
            self.drift.days_hi,
            self.drift_box.ip,
            self.drift_box.sum_rss_mib,
            self.drift_box.mem_total_mib - self.reserve_mib
        );
        let _ = writeln!(
            s,
            "\n  The roll date is {:.1} days EARLIER than the drift date. Days, not weeks:\n\
             \x20 the boot premium is a constant (86.7 MiB isolated, 13-23% on the fleet),\n\
             \x20 not a multiple, so the two curves run parallel rather than diverging.\n\
             \x20 A box that survives running can still die in replay.",
            self.drift.days_lo - self.roll.days_lo
        );

        let _ = writeln!(
            s,
            "\nSECOND ARM -- signature material removed from the resident block map\n\n\
             \x20 ROLL   {} .. {}   ({:.1}-{:.1} days)\n\
             \x20 DRIFT  {} .. {}   ({:.1}-{:.1} days)\n\n\
             \x20 Two measured effects, and they are not the same thing: a ONE-OFF drop in\n\
             \x20 the level (116.8 MiB, 17.5% of resident at end of replay) and a lower\n\
             \x20 GROWTH RATE (10,579 -> 6,410 B/block above the 370.0 MiB plateau, a factor\n\
             \x20 of {:.3}). The level saving buys a fixed number of days; only the rate\n\
             \x20 saving multiplies the date -- and it multiplies it, it does not remove it.\n\
             \x20 Note the peak sees only 55.3 MiB / 7.3% of that saving, because allocator\n\
             \x20 arenas depress it: a third reason peak and steady are two curves.",
            self.roll_nosig.lo_date(),
            self.roll_nosig.hi_date(),
            self.roll_nosig.days_lo,
            self.roll_nosig.days_hi,
            self.drift_nosig.lo_date(),
            self.drift_nosig.hi_date(),
            self.drift_nosig.days_lo,
            self.drift_nosig.days_hi,
            SIG_GROWTH_FACTOR
        );

        let _ = writeln!(s, "\nWHAT SETS THE WIDTH OF THE RANGE\n");
        let _ = writeln!(
            s,
            "  total width of the ROLL band            {:.1} days\n\
             \x20   of which, the growth curve's own non-linearity   {:.1} days  <- dominates\n\
             \x20   the page-cache reserve, if halved                {:.1} days\n\
             \x20   best box vs worst box                            {:.1} days",
            self.roll.days_hi - self.roll.days_lo,
            self.roll.days_hi - self.roll.days_lo,
            self.reserve_sensitivity_days,
            self.box_spread_days
        );
        let _ = writeln!(
            s,
            "\n  The three measured intervals are {:.1}, {:.1} and {:.1} MiB/day/validator.\n\
             \x20 They differ by {:.1}x and they are RISING. That spread, not measurement\n\
             \x20 error and not the reserve, is essentially the whole width -- and because\n\
             \x20 they rise, the binding arm is a LOWER bound on the rate. Narrowing these\n\
             \x20 dates means a fourth interval, not more arithmetic on these three.",
            STEADY_MIB_PER_DAY_INTERVALS[0],
            STEADY_MIB_PER_DAY_INTERVALS[1],
            STEADY_MIB_PER_DAY_INTERVALS[2],
            STEADY_MIB_PER_DAY_INTERVALS[2] / STEADY_MIB_PER_DAY_INTERVALS[0]
        );

        let _ = writeln!(
            s,
            "\nTHE DENOMINATOR IS SLOTS, AND THE BLOCK CADENCE IS A TRIPWIRE\n\n\
             \x20 Growth follows slots, which arrive at {:.0}/day on the wall clock whether\n\
             \x20 or not anyone produces a block. Measured per BLOCK the same intervals give\n\
             \x20 0.005, 0.032 and 0.011 MiB/block -- a sixfold spread, because a per-block\n\
             \x20 rate folds in a cadence this chain has run at anywhere from 24% to 100%.\n\
             \x20 So the block rate is not an input here. It is recorded ({} blocks/slot over\n\
             \x20 {}) only so that a change in it trips a test: that change would be the\n\
             \x20 natural experiment confirming or refuting the slot hypothesis on live data.",
            SLOTS_PER_DAY,
            snap.blocks_per_slot_measured
                .map(|v| format!("{v:.3}"))
                .unwrap_or("unrecorded".into()),
            snap.cadence_window
        );

        let _ = writeln!(
            s,
            "\nFLOOR, NOT HEADROOM\n\n\
             \x20 The freshest VmHWM on the fleet was set {} slots ago ({:.1} days). Every\n\
             \x20 peak above is therefore a LOWER BOUND on what a boot costs today, and the\n\
             \x20 roll date is optimistic by exactly that much.\n\
             \x20 Do NOT restart a validator to refresh a mark -- that is a double-signing\n\
             \x20 risk for a number. Measure a candidate boot on an IDLE box at tip height\n\
             \x20 and pass it to scripts/fleet-memory-gate.sh as --peak-mib.",
            self.mark_staleness_slots,
            self.mark_staleness_slots as f64 / SLOTS_PER_DAY
        );

        let _ = writeln!(
            s,
            "\nHOW FAR PAST THE EVIDENCE THIS REACHES\n\n\
             \x20 The chain is {} slots old. The binding ROLL date is {:.0} days out, which\n\
             \x20 is slot {:.0} -- {:.1}x the chain that exists today. Every growth rate\n\
             \x20 here was measured on a log of at most ~30,600 blocks. The dates are an\n\
             \x20 extrapolation several times beyond the range of any measurement behind\n\
             \x20 them, and no measurement on this programme has yet covered that range.\n\
             \x20 That is a larger source of error than everything in the width table above\n\
             \x20 and it is not in the band, because a band cannot express it.",
            self.chain_slot,
            self.roll.days_lo,
            self.chain_slot as f64 + self.roll.days_lo * SLOTS_PER_DAY,
            (self.chain_slot as f64 + self.roll.days_lo * SLOTS_PER_DAY) / self.chain_slot as f64
        );

        let _ = writeln!(s, "\nINPUTS\n");
        for i in INPUTS {
            let tag = match i.standing {
                Standing::Measured => "MEASURED   ",
                Standing::Modelled => "MODELLED   ",
                Standing::Superseded => "SUPERSEDED ",
                Standing::Discredited => "DISCREDITED",
            };
            let _ = writeln!(s, "  {tag} {:<44} {:.4} {}", i.name, i.value, i.unit);
            let _ = writeln!(s, "              {}", i.source);
        }
        let _ = writeln!(s, "\n{WHAT_THIS_CANNOT_DO}");
        s
    }
}

#[cfg(test)]
mod tests;
