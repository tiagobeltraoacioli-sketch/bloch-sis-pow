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
        age_days * STEADY_MIB_PER_DAY_RECENT * 9.0
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
            b.validators, 9,
            "box {} ({}) is running {} validators, not 9. Both dates scale with N:\n\
             the roll need is N x peak and the drift burn is N x rate, so a box with\n\
             a different tenancy has a different date. Note also that boxes recorded\n\
             as idle have been seen running 9 `bloch` processes at load 9.5 -- a box\n\
             is idle only if /proc says so.\n{REDO}",
            b.ip, b.host, b.validators
        );
    }
}

// ── the hidden variable: slots against blocks ─────────────────────────────

#[test]
fn the_slot_to_block_relation_is_still_what_the_projection_was_derived_under() {
    let s = snap();
    let bps = s.blocks_per_slot_measured.unwrap_or_else(|| {
        panic!(
            "the snapshot records no blocks-per-slot ratio, so the one variable that\n\
             was hiding inside the old per-block rates cannot be watched at all.\n\
             Re-run the collector WITHOUT --fast.\n{REDO}"
        )
    });
    let moved = (bps - BLOCKS_PER_SLOT_AT_DERIVATION).abs();
    assert!(
        moved <= BLOCKS_PER_SLOT_TOLERANCE,
        "the chain is producing {bps:.3} blocks per slot (measured over {}), against\n\
         the {BLOCKS_PER_SLOT_AT_DERIVATION:.3} this projection was derived under --\n\
         a move of {moved:.3}, limit {BLOCKS_PER_SLOT_TOLERANCE:.2}.\n\
         \n\
         This is the tripwire, and tripping it is INFORMATIVE rather than merely\n\
         bad. Growth was found to follow SLOTS, not blocks: between h=10,000 and\n\
         h=15,000 the chain burned 21,187 slots for 5,000 blocks and memory tracked\n\
         the slots. If that is right, the dates here should NOT move now that the\n\
         cadence has -- and this is the live natural experiment that settles it.\n\
         Re-measure the growth rate across this cadence change before touching the\n\
         dates. Separately: every per-BLOCK memory figure still in circulation is\n\
         now wrong by a factor of about {:.2}.\n{REDO}",
        s.cadence_window,
        BLOCKS_PER_SLOT_AT_DERIVATION / bps.max(1e-9)
    );
}

#[test]
fn the_date_does_not_move_when_only_the_block_cadence_moves() {
    // The point of re-denominating in slots is that the block rate stops being
    // an input. This proves it structurally rather than by inspection: halve
    // the cadence and the dates must not budge by a single second.
    let s = snap();
    let base = project(&s, RESERVE_MIB_DEFAULT);
    let mut slower = s.clone();
    slower.blocks_per_slot_measured = slower.blocks_per_slot_measured.map(|v| v / 2.0);
    slower.blocks_per_day_measured = slower.blocks_per_day_measured.map(|v| v / 2.0);
    let p2 = project(&slower, RESERVE_MIB_DEFAULT);
    // The SECOND ARM is included deliberately. SIG_GROWTH_FACTOR is a ratio of
    // two per-BLOCK measurements (6,410 / 10,579 B per block) applied to a
    // per-DAY rate. That is only sound while the cadence of the two
    // measurements matches the cadence of the fleet; it is the one place a
    // block denominator still survives inside the arithmetic instead of in
    // prose, and it was previously unguarded.
    assert_eq!(
        (
            base.roll.unix_lo,
            base.drift.unix_lo,
            base.roll_nosig.unix_lo,
            base.drift_nosig.unix_lo
        ),
        (
            p2.roll.unix_lo,
            p2.drift.unix_lo,
            p2.roll_nosig.unix_lo,
            p2.drift_nosig.unix_lo
        ),
        "halving the block cadence moved the projected dates. It must not: growth is\n\
         denominated in SLOTS, which the wall clock delivers at {SLOTS_PER_DAY:.0}/day\n\
         whether or not blocks are produced in them. If project() has started reading\n\
         a block rate again, the sixfold spread that per-block rates showed across\n\
         three intervals (0.005 / 0.032 / 0.011 MiB/block) is back inside the date."
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
         headroom      {:.0} MiB at {:.1} MiB/day/validator\n\
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
        STEADY_MIB_PER_DAY_RECENT,
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
        gap < 28.0,
        "the ROLL date is now {gap:.1} days ahead of the DRIFT date. The programme is\n\
         told these are days apart because the peak premium is a CONSTANT (86.7 MiB\n\
         isolated, 13-23% on the fleet) rather than a multiple, so the two curves run\n\
         parallel. A gap this wide means the premium has started to grow, which would\n\
         make the peak a second curve with its own slope -- currently unmeasured, and\n\
         the single most valuable thing to measure next.\n{REDO}"
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
    let stale = s.mark_staleness_slots();
    assert!(
        stale <= MARK_MAX_STALENESS_SLOTS,
        "the FRESHEST VmHWM on the whole fleet was set {stale} slots ago -- about\n\
         {:.1} days -- against a limit of {MARK_MAX_STALENESS_SLOTS} slots.\n\
         \n\
         VmHWM is a lifetime high-water mark: a validator that booted that long ago\n\
         recorded what a boot cost against a SHORTER CHAIN. Every peak in the\n\
         snapshot is therefore a FLOOR, never the headroom you have, and the gap\n\
         grows with the calendar. Past this limit no process on the fleet has booted\n\
         recently enough to bound a boot today, and the roll date is optimistic by an\n\
         amount nothing here can measure.\n\
         \n\
         Measured in SLOTS deliberately: counting this staleness in blocks would\n\
         understate it by 1/cadence exactly when the chain is slow, which is exactly\n\
         when it matters.\n\
         \n\
         Do NOT restart a validator to refresh a mark -- that is a double-signing\n\
         risk incurred for a number. Measure a candidate boot on an IDLE box against\n\
         a tip-height blocks.log and pass it as `--peak-mib` to\n\
         scripts/fleet-memory-gate.sh, which exists for exactly this.\n{REDO}",
        stale as f64 / SLOTS_PER_DAY
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
        "O(unfinalized + state)",
        "grows with USAGE",
        "FLOOR, NOT HEADROOM",
        "SLOTS",
        "CONTINGENT ON AN EMPTY CHAIN",
        "REPLAY IS NOT THE REGIME THE FLEET LIVES IN",
        "HOW FAR PAST THE EVIDENCE THIS REACHES",
    ] {
        assert!(
            r.contains(must),
            "the report no longer contains {must:?}. This projection is read by people\n\
             deciding a schedule; stripping the limits turns a bounded estimate into a\n\
             plan, which is the failure this artefact exists to prevent."
        );
    }
}

// ── the contingency: the far date is a claim about an EMPTY chain ─────────

#[test]
fn the_chain_is_still_as_idle_as_the_surviving_eutxo_slope_assumes() {
    // THIS IS THE TEST THAT GUARDS THE 2027 DATE.
    //
    // Serving the block map from the log removes the chain-retention term.
    // What it leaves behind -- ~3,174 B/block -- is almost entirely the eUTXO
    // ledger, and that was measured across a window carrying 1,048
    // transactions in 29,472 blocks. It is not a rate that time drives. It is
    // a rate that USERS drive, and the validator-opening programme exists to
    // add users. So the far date is contingent on the chain staying empty,
    // and this is where that contingency is checked instead of hoped for.
    let s = snap();

    if let Some(bpb) = s.bytes_per_block_measured {
        let moved = (bpb - BYTES_PER_BLOCK_AT_DERIVATION).abs() / BYTES_PER_BLOCK_AT_DERIVATION;
        assert!(
            moved <= BYTES_PER_BLOCK_TOLERANCE_FRACTION,
            "the block log is now carrying {bpb:.0} B/block against the \
             {BYTES_PER_BLOCK_AT_DERIVATION:.0} B/block this projection was derived under \
             -- a move of {:.1}%, limit {:.0}%.\n\
             \n\
             Frame size rises with transaction volume, and the growth term that survives\n\
             every optimisation in flight is the eUTXO ledger, whose slope is a function\n\
             of exactly that. The far dates in docs/MEMORY-PROJECTION.md were computed for\n\
             a chain doing {:.4} tx/block -- essentially nothing. If the chain has started\n\
             being used, those dates are not merely stale, they are the wrong SHAPE:\n\
             memory then grows with adoption rather than with the calendar, and no date\n\
             derived from an idle window bounds it.\n{REDO}",
            moved * 100.0,
            BYTES_PER_BLOCK_TOLERANCE_FRACTION * 100.0,
            TX_PER_BLOCK_AT_DERIVATION
        );
    }

    if let Some(tx) = s.tx_per_block_measured {
        assert!(
            tx <= TX_PER_BLOCK_TOLERANCE,
            "the chain is carrying {tx:.3} transactions per block, against the \
             {:.4} tx/block the surviving eUTXO slope was measured under (limit \
             {TX_PER_BLOCK_TOLERANCE:.2}).\n\
             \n\
             The dates that assume the store-backed block map are the ones this breaks.\n\
             They are not a forecast about time; they are a statement about an empty\n\
             chain. Re-measure the eUTXO slope against a window that carries real\n\
             traffic before quoting any 2027 date again.\n{REDO}",
            TX_PER_BLOCK_AT_DERIVATION
        );
    }
}

#[test]
fn the_fork_overhang_is_still_a_rounding_error_and_not_a_term() {
    // Fork overhang is real -- `blocks_known` exceeds `height` by 226 on every
    // box asked -- and it is the one term here that grows without a bound.
    // It is also, today, 3.0 MiB against a 1,205 MiB validator. Both halves of
    // that sentence matter: recording it keeps the level honest, and refusing
    // to promote it to a dating term keeps the risk in the right place. This
    // test exists to notice if it stops being a rounding error.
    let s = snap();
    let Some(fork) = s.fork_overhang_blocks else {
        return;
    };
    let bpb = s
        .bytes_per_block_measured
        .unwrap_or(BYTES_PER_BLOCK_AT_DERIVATION);
    let mib = fork * bpb / (1024.0 * 1024.0);
    assert!(
        fork <= FORK_OVERHANG_TOLERANCE_BLOCKS,
        "the fleet is holding {fork:.0} non-canonical blocks in RAM ({mib:.1} MiB at \
         {bpb:.0} B/block), against {FORK_OVERHANG_BLOCKS_AT_DERIVATION:.0} when this \
         projection was derived (limit {FORK_OVERHANG_TOLERANCE_BLOCKS:.0}).\n\
         \n\
         At this size it stops being a rounding error and becomes a memory term the\n\
         projection does not model. It is also, at this size, a fork-choice incident\n\
         before it is a memory problem -- look there first.\n{REDO}"
    );
}

#[test]
fn a_replay_slope_is_never_used_to_date_the_live_fleet() {
    // The programme's most expensive confusion, made structural.
    //
    // A static replay grows at 0.01718 MiB/block; a running validator grows at
    // 8,837 B/block, measured two independent ways. The replay figure is 1.99x
    // the live one, so a date computed from replay is roughly HALF the time
    // that actually exists. The binding rate must therefore stay on the live
    // side of that gap.
    let live_mib_per_day = LIVE_B_PER_BLOCK * 2880.0 * 0.982 / (1024.0 * 1024.0);
    let replay_mib_per_day = REPLAY_B_PER_BLOCK * 2880.0 * 0.982 / (1024.0 * 1024.0);
    assert!(
        REPLAY_B_PER_BLOCK > LIVE_B_PER_BLOCK,
        "the replay slope is no longer above the live slope; re-check which regime\n\
         each was measured in before trusting either."
    );
    assert!(
        STEADY_MIB_PER_DAY_RECENT < replay_mib_per_day,
        "the binding rate {STEADY_MIB_PER_DAY_RECENT:.1} MiB/day/validator has reached the\n\
         REPLAY-derived rate of {replay_mib_per_day:.1} MiB/day. Replay is not the regime\n\
         the fleet lives in: a replay pays for the chain in a way a running node does\n\
         not, and dating the fleet from it halves the time that actually exists."
    );
    assert!(
        (STEADY_MIB_PER_DAY_RECENT - live_mib_per_day).abs() < 12.0,
        "the binding rate {STEADY_MIB_PER_DAY_RECENT:.1} MiB/day/validator has drifted away\n\
         from the live per-block lineage ({live_mib_per_day:.1} MiB/day at\n\
         {LIVE_B_PER_BLOCK:.0} B/block). These are two independent routes to the same\n\
         quantity and they agreed to ~6% when the projection was derived; if they no\n\
         longer do, one of them is measuring something else.\n{REDO}"
    );
}
