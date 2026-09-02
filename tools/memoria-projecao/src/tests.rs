// SPDX-License-Identifier: AGPL-3.0-or-later
//! # Tests that fail when the projection goes stale
//!
//! None of these re-assert a constant. A test that reads
//! `STEADY_MIB_PER_DAY_RECENT` and asserts it equals 27.6 proves only that
//! nobody retyped the line; it passes forever while the world moves
//! underneath it, which is exactly how this programme has been burned. Every
//! test below compares a **claim** to a **kernel-measured reading of the live
//! fleet** and, when they part company, names the box that broke it and says
//! what to do next.
//!
//! The reading is `scripts/fleet-memory-observations.tsv`, regenerated
//! read-only by `scripts/fleet-memory-observe.sh`. Point
//! `BLOCH_FLEET_OBSERVATIONS` at another file to check a hypothetical fleet —
//! which is how `scripts/memoria-projecao-violacao.sh` proves these checks
//! actually bite, by falsifying the snapshot on purpose and requiring each
//! named test to go red.
//!
//! Two of these are deliberately time-dependent. That is not an oversight and
//! not a flake: a projection whose inputs are 40 days old IS broken, and a
//! suite that cannot say so leaves the staleness for a human to remember.
//! Nobody remembered last time.

use super::*;

const REDO: &str = "\
    Re-derive the projection: run `scripts/fleet-memory-observe.sh` (read-only,\n\
    touches no validator), then `cargo run -p bloch-memoria-projecao`, then\n\
    update CLAIMED_* in lib.rs and the dates in docs/MEMORY-PROJECTION.md to\n\
    whatever the fresh snapshot says. Do NOT widen the tolerance to make this\n\
    pass -- the tolerance IS the claim.";

fn snap() -> Snapshot {
    match Snapshot::load_default() {
        Ok(s) => s,
        Err(e) => panic!("{e}"),
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock is before 1970")
        .as_secs() as i64
}

// ── the reading itself ────────────────────────────────────────────────────

#[test]
fn snapshot_is_structurally_whole() {
    let s = snap();
    assert!(
        s.rows.len() >= 9,
        "the snapshot carries only {} validator rows. A partial sweep reads exactly\n\
         like a shrinking fleet and would move the date in the SAFE direction, which\n\
         is the dangerous way to be wrong. The collector exits 1 on an unreachable\n\
         box; check its output for UNREACHABLE and re-run.\n{REDO}",
        s.rows.len()
    );
    for r in &s.rows {
        assert!(
            r.vmhwm_mib >= r.vmrss_mib,
            "{} on {}: VmHWM {:.1} < VmRSS {:.1}. A lifetime peak below the current\n\
             resident set is impossible; the snapshot is corrupt, or its columns are\n\
             shifted, or it was assembled from two different readings.",
            r.unit,
            r.box_ip,
            r.vmhwm_mib,
            r.vmrss_mib
        );
        assert!(
            r.vmhwm_mib > 0.0 && r.mem_total_mib > 0.0 && r.nproc > 0,
            "{} on {} has a zero reading (hwm {:.1}, memtotal {:.1}, nproc {}); the\n\
             probe matched a process that is not a validator, or the emitter's column\n\
             indices are off.",
            r.unit,
            r.box_ip,
            r.vmhwm_mib,
            r.mem_total_mib,
            r.nproc
        );
    }
}

#[test]
fn snapshot_has_not_gone_stale() {
    let s = snap();
    let age_days = (now_unix() - s.captured_unix) as f64 / 86400.0;
    assert!(
        age_days <= SNAPSHOT_MAX_AGE_DAYS,
        "the fleet snapshot is {age_days:.1} days old (limit {SNAPSHOT_MAX_AGE_DAYS:.0}).\n\
         At the binding rate the fleet has since put on roughly {:.0} MiB per box, so\n\
         every number the projection rests on is a memory rather than a measurement\n\
         and the published dates are unsupported.\n{REDO}",
        age_days
            * REPLAY_RETENTION_MIB_PER_BLOCK
            * BLOCKS_PER_DAY_AT_DERIVATION
            * EXPECTED_VALIDATORS_PER_BOX as f64
    );
}

// ── the fleet's shape, which the arithmetic assumes ───────────────────────

#[test]
fn every_box_still_has_the_ram_the_projection_assumes() {
    let s = snap();
    for b in s.boxes() {
        assert!(
            (b.mem_total_mib - 31_866.0).abs() <= 64.0,
            "box {} ({}) reports {:.0} MiB of RAM, not ~31,866. The per-validator\n\
             ceiling is (MemTotal - reserve) / N, so a resized box has a different\n\
             date and the published one does not apply to it. A PMO box-reservation\n\
             table is in flight; if the fleet has been re-provisioned, the projection\n\
             must be re-derived per box class rather than fleet-wide.\n{REDO}",
            b.ip,
            b.host,
            b.mem_total_mib
        );
    }
}

#[test]
fn every_box_still_carries_the_validators_the_projection_assumes() {
    let s = snap();
    for b in s.boxes() {
        assert_eq!(
            b.validators, EXPECTED_VALIDATORS_PER_BOX,
            "box {} ({}) is running {} validators, not 9. Both dates scale with N:\n\
             the roll need is N x peak and the drift burn is N x rate, so a box with\n\
             a different tenancy has a different date. Note also that boxes recorded\n\
             as idle have been seen running 9 `bloch` processes at load 9.5 -- a box\n\
             is idle only if /proc says so.\n{REDO}",
            b.ip, b.host, b.validators
        );
    }
}

// ── tenancy: the input a single lens cannot be trusted with ───────────────

#[test]
fn the_four_independent_counts_of_tenancy_agree() {
    // The guard the previous round did not have. Asserting "9 validators" is
    // useless if the collector is the thing that miscounted: an under-count
    // moves the date in the SAFE direction and every check built on it still
    // passes. So the box is enumerated four independent ways -- argv,
    // pgrep, systemd units, distinct --data-dir -- and the projection refuses
    // to run when they disagree, whichever of them is wrong.
    let s = snap();
    for b in s.boxes() {
        let lenses = [b.lens_argv, b.lens_pgrep, b.lens_units, b.lens_datadirs];
        let all_agree = lenses.iter().all(|&v| v == lenses[0]);
        assert!(
            all_agree,
            "box {} ({}): the four independent counts of how many validators it is\n\
             running DISAGREE -- argv={} pgrep={} systemd-units={} data-dirs={}.\n\
             \n\
             Do not pick one. A tenancy claim of 10-per-box reached this programme\n\
             and would have cut the per-validator ceiling from 3,199 to 2,879 MiB;\n\
             it was refuted only because four lenses were read instead of one.\n\
             A disagreement here means either a validator is running that systemd\n\
             does not manage (an orphan from a manual start -- check for a duplicate\n\
             signer before anything else, that is a slashing risk), or a unit is\n\
             enabled with no process behind it, or the argv shape changed.\n{REDO}",
            b.ip, b.host, b.lens_argv, b.lens_pgrep, b.lens_units, b.lens_datadirs
        );
        assert_eq!(
            b.validators, lenses[0] as usize,
            "box {} ({}): the snapshot carries {} validator ROWS but the box reports\n\
             {} running validators. The collector dropped a process it should have\n\
             captured -- and a dropped process is invisible in every downstream\n\
             number, because it makes the box look emptier than it is.\n{REDO}",
            b.ip, b.host, b.validators, lenses[0]
        );
    }
}

// ── the block cadence, which is an input again ────────────────────────────

#[test]
fn the_block_cadence_still_matches_what_the_dates_are_denominated_in() {
    // Reversal from the previous round, and it is decided by mechanism rather
    // than by fit: the dominant term is one envelope per BLOCK, and an empty
    // slot creates no envelope. So cadence is an input, not a tripwire, and a
    // change in it moves the date in direct proportion.
    let s = snap();
    let bpd = s.blocks_per_day_measured.unwrap_or_else(|| {
        panic!("the snapshot records no measured block rate. Re-run the collector.\n{REDO}")
    });
    let drift = (bpd - BLOCKS_PER_DAY_AT_DERIVATION).abs() / BLOCKS_PER_DAY_AT_DERIVATION;
    assert!(
        drift <= BLOCKS_PER_DAY_TOLERANCE,
        "the chain is producing {bpd:.1} blocks/day (measured over {}), against the\n\
         {BLOCKS_PER_DAY_AT_DERIVATION:.0}/day the dates are denominated in -- {:.1}% off,\n\
         limit {:.0}%.\n\
         \n\
         Memory grows per BLOCK, so the date moves in direct proportion: at\n\
         {bpd:.1}/day the roll date moves by about {:.1} days.\n\
         \n\
         Note the cadence is ALSO the experiment that would settle blocks against\n\
         slots. Today it runs at 0.98 blocks/slot, so the two denominators are\n\
         numerically indistinguishable on live data and only the mechanism\n\
         separates them. A cadence far from 1.0 makes them separable: measure the\n\
         growth rate across the change before re-deriving anything.\n{REDO}",
        s.cadence_window,
        drift * 100.0,
        BLOCKS_PER_DAY_TOLERANCE * 100.0,
        CLAIMED_ROLL_DAYS * (1.0 - BLOCKS_PER_DAY_AT_DERIVATION / bpd)
    );
}

#[test]
fn the_date_moves_in_proportion_to_the_block_cadence() {
    // Structural check that the denominator really is the block. The previous
    // model asserted the opposite of this and was wrong; the assertion is kept
    // pointing the other way so the reversal cannot be undone by accident.
    let s = snap();
    let base = project(&s, RESERVE_MIB_DEFAULT);
    let mut faster = s.clone();
    faster.blocks_per_day_measured = Some(base.blocks_per_day * 2.0);
    let p2 = project(&faster, RESERVE_MIB_DEFAULT);
    let ratio = base.roll.days_lo / p2.roll.days_lo;
    assert!(
        (ratio - 2.0).abs() < 1e-6,
        "doubling the block rate should halve the days-to-exhaustion exactly, since\n\
         the dominant term is one envelope per block; got a factor of {ratio}.\n\
         Either project() has stopped reading the cadence -- the retired\n\
         slot-denominated model -- or it has acquired a term that is not linear in\n\
         blocks."
    );
}

// ── the two curves must stay two ──────────────────────────────────────────

// ── model-internal coherence guards ───────────────────────────────────────
//
// The three tests below are NOT reality checks and must not be counted as
// such. They compare a constant to a constant, which clippy correctly notices
// and which is the exact anti-pattern the rest of this file exists to avoid:
// they cannot fail because the fleet moved, only because someone edited a
// number without editing the ones it has to stay consistent with.
//
// They earn their place anyway, because the numbers they relate come from
// four different measuring parties, and a later edit that breaks the
// relationship between them would otherwise land silently. Read them as
// "these constants still describe one system", never as evidence about the
// fleet. The `#[allow]` is a label, not a silencing.

#[test]
#[allow(clippy::assertions_on_constants)]
fn the_peak_curve_still_grows_faster_than_the_steady_curve() {
    assert!(
        PEAK_MIB_PER_BLOCK_BASELINE > REPLAY_RETENTION_MIB_PER_BLOCK,
        "the PEAK rate ({PEAK_MIB_PER_BLOCK_BASELINE}) is no longer above the replay's\n\
         retention rate ({:.5}). If they have converged, the boot premium has stopped\n\
         growing and the roll and drift dates collapse into one.",
        REPLAY_RETENTION_MIB_PER_BLOCK
    );
    assert!(
        REPLAY_RETENTION_MIB_PER_BLOCK > STEADY_MIB_PER_BLOCK_FLEET,
        "the drift band is inverted: its binding end ({:.5}, the replay's retention\n\
         rate) must exceed its optimistic end ({STEADY_MIB_PER_BLOCK_FLEET}, what the\n\
         live fleet is currently adding). The fleet reading is the LOWER bound on\n\
         purpose -- a validator at the tip is filling allocator slack the replay\n\
         transient left behind, so short-run RSS growth understates the durable rate.",
        REPLAY_RETENTION_MIB_PER_BLOCK
    );
}

#[test]
#[allow(clippy::assertions_on_constants)]
fn the_replay_retention_term_still_reconciles_with_the_on_disk_envelope() {
    // Three independent routes to the block-map term must keep agreeing, or
    // the mechanism behind the whole second arm is no longer confirmed.
    let envelope_mib_per_block = ENVELOPE_BYTES_PER_BLOCK / 1_048_576.0;
    let ratio = REPLAY_RETENTION_MIB_PER_BLOCK / envelope_mib_per_block;
    assert!(
        (0.80..=1.20).contains(&ratio),
        "the replay's retention rate ({:.5} MiB/block, from 348.9 MiB over 29,377\n\
         blocks) and the measured on-disk envelope ({:.5} MiB/block) have drifted\n\
         apart -- ratio {ratio:.2}, expected 0.80-1.20.\n\
         Their agreement is what turns the store-backed saving from a claim into a\n\
         confirmed mechanism: the thing removed from RAM is the size of the thing\n\
         that lives on disk. Without it the second arm is an assertion again.",
        REPLAY_RETENTION_MIB_PER_BLOCK,
        envelope_mib_per_block
    );
}

#[test]
#[allow(clippy::assertions_on_constants)]
fn the_refuted_state_footprint_is_nowhere_in_the_arithmetic() {
    // 60 MB per CommittedState was wrong by ~750x: four extra mainnet-sized
    // states measure 320 kB, because EutxoSet.entries is an Arc<BTreeMap> and
    // holding a state is a refcount increment. It is still in the tree at
    // crates/bloch-pos-node/src/engine.rs and it is not this crate's to edit,
    // so the guard here is that nothing in THIS arithmetic is near it.
    assert!(
        MEMO_FOUR_STATES_KIB < 1024.0,
        "four extra states are recorded at {MEMO_FOUR_STATES_KIB} kB. The refuted\n\
         figure was 240 MB for the same four. If this has grown by three orders of\n\
         magnitude, either Arc sharing was lost in EutxoSet or the wrong number\n\
         came back."
    );
    assert!(
        INPUTS
            .iter()
            .any(|i| i.name.contains("60 MB per CommittedState")
                && i.standing == Standing::Discredited),
        "the 60 MB/state figure has left the discredited list. It is wrong by ~750x,\n\
         it is still live in a doc comment at crates/bloch-pos-node/src/engine.rs,\n\
         and the graveyard is the only thing stopping it being quoted again."
    );
}

// ── the term with no plan ─────────────────────────────────────────────────

#[test]
fn the_fork_overhang_has_not_started_running() {
    let s = snap();
    let f = s.fork_overhang_blocks.unwrap_or_else(|| {
        panic!(
            "the snapshot records no fork overhang. It is read straight off the node\n\
             as `blocks_known - height` and it is the ONE growing term here with no\n\
             workstream aimed at it -- store-backing moves the CANONICAL map to disk.\n\
             Re-run the collector.\n{REDO}"
        )
    });
    assert!(
        f <= FORK_OVERHANG_ALARM,
        "the fleet is holding {f} non-canonical blocks whole in RAM, against {}\n\
         when these dates were derived and an alarm at {FORK_OVERHANG_ALARM}.\n\
         That is about {:.0} MiB per validator at the measured envelope, and unlike\n\
         every other term here nothing bounds it and nothing is being done about it.\n\
         A jump this size is more likely to mean the fleet is forking than that the\n\
         term grew: check that the nodes agree on a head before touching memory.\n{REDO}",
        FORK_OVERHANG_AT_DERIVATION,
        f as f64 * ENVELOPE_BYTES_PER_BLOCK / 1_048_576.0
    );
}

// ── the published dates, recomputed from reality ──────────────────────────

#[test]
fn the_published_roll_date_still_follows_from_the_live_fleet() {
    let s = snap();
    let p = project(&s, RESERVE_MIB_DEFAULT);
    let moved = (p.roll.days_lo - CLAIMED_ROLL_DAYS).abs();
    assert!(
        moved <= CLAIM_TOLERANCE_DAYS,
        "the ROLL date recomputed from the live fleet is {:.1} days out, against the\n\
         {CLAIMED_ROLL_DAYS:.1} days this repo publishes -- it has moved {moved:.1}\n\
         days (limit {CLAIM_TOLERANCE_DAYS:.0}).\n\
         \n\
         binding box   {} ({}), {} validators\n\
         boot peak     {:.1} MiB (unit {}), so nine at once need {:.0} MiB\n\
         capacity      {:.0} MiB after a {:.0} MiB page-cache reserve\n\
         headroom      {:.0} MiB at the PEAK rate\n\
         \n\
         The fleet programme is sequencing around the published date, and it is now\n\
         wrong by more than a week.\n{REDO}",
        p.roll.days_lo,
        p.roll_box.ip,
        p.roll_box.host,
        p.roll_box.validators,
        p.roll_box.max_hwm_mib,
        p.roll_box.max_hwm_unit,
        p.roll_box.max_hwm_mib * p.roll_box.validators as f64,
        p.roll_box.mem_total_mib - p.reserve_mib,
        p.reserve_mib,
        p.roll_box.mem_total_mib
            - p.reserve_mib
            - p.roll_box.max_hwm_mib * p.roll_box.validators as f64,
    );
}

#[test]
fn the_published_drift_date_still_follows_from_the_live_fleet() {
    let s = snap();
    let p = project(&s, RESERVE_MIB_DEFAULT);
    let moved = (p.drift.days_lo - CLAIMED_DRIFT_DAYS).abs();
    assert!(
        moved <= CLAIM_TOLERANCE_DAYS,
        "the DRIFT date recomputed from the live fleet is {:.1} days out, against the\n\
         {CLAIMED_DRIFT_DAYS:.1} days this repo publishes -- it has moved {moved:.1}\n\
         days (limit {CLAIM_TOLERANCE_DAYS:.0}).\n\
         \n\
         binding box   {} ({}), {} validators\n\
         resident      {:.1} MiB summed across the box\n\
         capacity      {:.0} MiB after a {:.0} MiB page-cache reserve\n{REDO}",
        p.drift.days_lo,
        p.drift_box.ip,
        p.drift_box.host,
        p.drift_box.validators,
        p.drift_box.sum_rss_mib,
        p.drift_box.mem_total_mib - p.reserve_mib,
        p.reserve_mib,
    );
}

#[test]
fn the_roll_date_is_earlier_than_the_drift_date_but_only_by_days() {
    let s = snap();
    let p = project(&s, RESERVE_MIB_DEFAULT);
    let gap = p.drift.days_lo - p.roll.days_lo;
    assert!(
        gap > 0.0,
        "the recomputed ROLL date ({:.1} d) is not earlier than the DRIFT date\n\
         ({:.1} d). The peak curve must bind before the steady curve does -- a box\n\
         that survives running can still die in replay. If it no longer does, either\n\
         the boot peaks have collapsed into the steady state or the two curves have\n\
         been mixed up in project().",
        p.roll.days_lo,
        p.drift.days_lo
    );
    assert!(
        gap < 45.0,
        "the ROLL date is now {gap:.1} days ahead of the DRIFT date. The programme is\n\
         told these are days apart because the peak premium is a CONSTANT (86.7 MiB\n\
         isolated, 13-23% on the fleet) rather than a multiple, so the two curves run\n\
         curves. The premium DOES grow -- peak 0.01718 against retention 0.01188 --\n\
         so a gap of a few weeks is expected. A gap this wide means the two rates\n\
         have diverged further than any measurement supports.\n{REDO}"
    );
}

#[test]
fn the_projection_has_not_already_expired() {
    let s = snap();
    let p = project(&s, RESERVE_MIB_DEFAULT);
    assert!(
        p.roll.unix_lo > now_unix(),
        "the recomputed roll-exhaustion date ({}) is in the PAST. Either the fleet\n\
         survived it -- in which case a MEASURED input is wrong, and finding out\n\
         which is worth more than any other item on this programme -- or a box has\n\
         already been OOM-killed and nobody connected it to this projection.\n\
         Check `dmesg -T | grep -i oom` on the boxes before touching anything.\n{REDO}",
        p.roll.lo_date()
    );
}

// ── the floor-vs-headroom rule, enforced ──────────────────────────────────

#[test]
fn roll_arm_rests_on_marks_that_are_still_informative() {
    let s = snap();
    let stale = s.mark_staleness_blocks();
    assert!(
        stale <= MARK_MAX_STALENESS_BLOCKS,
        "the FRESHEST VmHWM on the whole fleet was set {stale} blocks ago -- about\n\
         {:.1} days -- against a limit of {MARK_MAX_STALENESS_BLOCKS} slots.\n\
         \n\
         VmHWM is a lifetime high-water mark: a validator that booted that long ago\n\
         recorded what a boot cost against a SHORTER CHAIN. Every peak in the\n\
         snapshot is therefore a FLOOR, never the headroom you have, and the gap\n\
         grows with the calendar. Past this limit no process on the fleet has booted\n\
         recently enough to bound a boot today, and the roll date is optimistic by an\n\
         amount nothing here can measure.\n\
         \n\
         Do NOT restart a validator to refresh a mark -- that is a double-signing\n\
         risk incurred for a number. Measure a candidate boot on an IDLE box against\n\
         a tip-height blocks.log and pass it as `--peak-mib` to\n\
         scripts/fleet-memory-gate.sh, which exists for exactly this.\n{REDO}",
        stale as f64 / BLOCKS_PER_DAY_AT_DERIVATION
    );
}

#[test]
fn the_boot_premium_is_still_a_premium_and_still_not_a_multiple() {
    let s = snap();
    let mut worst = (0.0f64, String::new());
    let mut best = (f64::INFINITY, String::new());
    for b in s.boxes() {
        let steady = b.sum_rss_mib / b.validators as f64;
        let ratio = b.max_hwm_mib / steady;
        if ratio > worst.0 {
            worst = (ratio, b.ip.clone());
        }
        if ratio < best.0 {
            best = (ratio, b.ip.clone());
        }
    }
    assert!(
        best.0 >= PEAK_PREMIUM_FRACTION_LO,
        "on box {} the peak VmHWM is only {:.1}% above the mean resident set. If the\n\
         boot premium has vanished, the PEAK curve is no longer distinct from the\n\
         STEADY one and the two dates collapse into one -- which would be good news,\n\
         and good news is what this programme has previously believed without\n\
         checking. Verify against a real boot before retiring the roll arm.\n{REDO}",
        best.1,
        (best.0 - 1.0) * 100.0
    );
    assert!(
        worst.0 <= PEAK_PREMIUM_FRACTION_HI,
        "on box {} the peak VmHWM is {:.0}% of the mean resident set. The projection\n\
         tells the programme the premium is a constant and therefore moves the date\n\
         by days; at this ratio it moves it by weeks, and a fleet roll -- not the\n\
         drift -- is the near-term risk.\n{REDO}",
        worst.1,
        worst.0 * 100.0
    );
}

// ── provenance, so a number cannot re-enter unattributed ──────────────────

#[test]
fn every_input_carries_a_source_and_a_standing() {
    for i in INPUTS {
        assert!(
            i.source.trim().len() > 20,
            "input {:?} has no usable provenance: {:?}. Every headline number in this\n\
             programme that lacked a commit behind it turned out to be wrong; an input\n\
             with an empty source is one of those waiting to happen.",
            i.name,
            i.source
        );
    }
    assert!(
        INPUTS.iter().any(|i| i.standing == Standing::Modelled),
        "no input is marked Modelled. Several of these are extrapolations, and at\n\
         least two -- that the peak premium stays constant, and that a single-node\n\
         replay rate transfers to a nine-per-box fleet -- have never been measured.\n\
         A table with no modelled entries is a table that stopped being honest."
    );
    assert!(
        INPUTS
            .iter()
            .filter(|i| i.standing == Standing::Discredited)
            .count()
            >= 2,
        "the discredited list shrank. It is a graveyard, not a working set: entries\n\
         go in when a published number is refuted and never come out. 0.0198\n\
         MiB/block and the 86.1% signature fraction both belong there."
    );
    assert!(
        INPUTS.iter().any(|i| i.standing == Standing::Superseded),
        "nothing is marked Superseded. The per-block rates were measured correctly in\n\
         a denominator that turned out to be wrong; deleting them rather than marking\n\
         them is how they get quoted again next month."
    );
}

// ── the arithmetic itself ─────────────────────────────────────────────────

#[test]
fn a_smaller_reserve_pushes_the_date_out_never_in() {
    let s = snap();
    let tight = project(&s, RESERVE_MIB_DEFAULT);
    let loose = project(&s, RESERVE_MIB_DEFAULT / 2.0);
    assert!(
        loose.roll.days_lo > tight.roll.days_lo,
        "halving the page-cache reserve did not push the date out. The reserve is\n\
         subtracted from capacity, so less reserve is strictly more headroom -- and\n\
         that is exactly why a reserve chosen too LOW makes this projection read\n\
         later than the truth. The boxes were observed holding 5,459-8,136 MiB of\n\
         page cache against a 3,072 MiB reserve."
    );
}

#[test]
fn the_binding_box_is_chosen_by_date_and_not_by_size() {
    // Two boxes, identical load, different RAM. The smaller one must bind.
    let s = snap();
    let mut two = s.clone();
    let proto = two.rows[0].clone();
    two.rows = (0..9)
        .map(|i| {
            let mut r = proto.clone();
            r.box_ip = "10.0.0.1".into();
            r.pid = 1000 + i;
            r
        })
        .chain((0..9).map(|i| {
            let mut r = proto.clone();
            r.box_ip = "10.0.0.2".into();
            r.mem_total_mib = proto.mem_total_mib / 2.0;
            r.pid = 2000 + i;
            r
        }))
        .collect();
    let p = project(&two, RESERVE_MIB_DEFAULT);
    assert_eq!(
        p.roll.days_lo, 0.0,
        "a box whose nine boot peaks already exceed its capacity must project ZERO\n\
         days, not infinite days. Returning INFINITY for non-positive headroom makes\n\
         the most endangered box in the fleet sort as the safest and vanish from the\n\
         binding-box selection entirely -- silently, and in the dangerous direction."
    );
    assert_eq!(
        p.roll_box.ip, "10.0.0.2",
        "with two boxes carrying identical load but one at half the RAM, the binding\n\
         box must be the smaller one. A selector that assumes a uniform fleet will\n\
         report the wrong box the day the PMO's reservation table stops making it\n\
         uniform."
    );
}

#[test]
fn the_report_states_what_it_cannot_do() {
    let s = snap();
    let r = project(&s, RESERVE_MIB_DEFAULT).report(&s);
    for must in [
        "MEASURED",
        "MODELLED",
        "SUPERSEDED",
        "DISCREDITED",
        "O(unfinalized + state)",
        "grows with USAGE",
        "FLOOR, NOT HEADROOM",
        "LEVEL, NOT SLOPE",
        "Arc::make_mut",
        "FORK OVERHANG",
        "WALL BEHIND THE WALL",
        "A band cannot express an extrapolation",
    ] {
        assert!(
            r.contains(must),
            "the report no longer contains {must:?}. This projection is read by people\n\
             deciding a schedule; stripping the limits turns a bounded estimate into a\n\
             plan, which is the failure this artefact exists to prevent."
        );
    }
}
