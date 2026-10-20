"""Validation of the partition model against the Rust fold's own measured
fixtures (crates/bloch-pos-committee/src/finality.rs tests at dd287b6c) and
hand-computed cases.

    python3 tools/partition-model/test_bloch_partition_model.py -v
"""
from __future__ import annotations

import math
import sys
import unittest
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bloch_partition_model as m  # noqa: E402

G = 0  # genesis root id in the bare-fold tests


def bare(stakes: list[int]) -> tuple[m.Roster, m.Finality]:
    return m.Roster(list(range(len(stakes))), stakes), m.Finality.new((0, G), len(stakes))


def votes(n: int, who: list[int], src: tuple[int, int], tgt: int) -> m.Votes:
    v = m.Votes.empty(n)
    mask = np.zeros(n, bool)
    mask[who] = True
    v.add(mask, src[0], src[1], tgt)
    return v


class RustFixtures(unittest.TestCase):
    def test_4_of_64_legacy_false_quorum_epoch_25(self):
        # a_partitioned_minority_finalizes_because_the_leak_shrinks_the_denominator
        # (finality.rs:1072; run_partition_inner :1936): prints "first justified
        # at epoch 25 ... discounted 92.2%" on dd287b6c.
        roster, st = bare([1_000_000_000] * 64)
        got = None
        for e in range(1, 61):
            j, _ = st.process_epoch(e, roster, votes(64, [0, 1, 2, 3], st.cj, 1000 + e), m.LEGACY, m.TODAY)
            if j is not None:
                got = (e, round(int(st.leaked.sum()) / (64 * 1_000_000_000) * 100, 1))
                break
        self.assertEqual(got, (25, 92.2))

    def test_60_40_stall_recovers_at_epoch_12(self):
        # the_leak_still_buys_liveness_back_after_the_fix (finality.rs:1367),
        # epochs < 2880 so Q = 64, no floor, no recovery: prints "recovered at
        # epoch 12; the absent 40% paid 7319440 and 7319440".
        roster, st = bare([60_000_000, 20_000_000, 20_000_000])
        got = None
        for e in range(1, 61):
            _, f = st.process_epoch(e, roster, votes(3, [0], st.cj, 1000 + e), m.MAINNET, m.TODAY)
            if f is not None:
                got = e
                break
        self.assertEqual(got, 12)
        self.assertEqual(st.leaked.tolist(), [0, 7_319_440, 7_319_440])

    def test_disjoint_thirds_finalize_conflicting_roots_at_18(self):
        # disjoint_one_third_partitions_finalize_conflicting_checkpoints_without_equivocation
        # (finality.rs:1504): gates open (floor + recovery), Q = 64, (18, 18).
        roster = m.Roster([0, 1, 2], [1_000_000_000] * 3)
        left, right = m.Finality.new((0, G), 3), m.Finality.new((0, G), 3)
        lf = rf = None
        for e in range(1, 129):
            _, a = left.process_epoch(e, roster, votes(3, [0], left.cj, 1000 + e), m.GATES_OPEN, m.TODAY)
            _, b = right.process_epoch(e, roster, votes(3, [1], right.cj, 2000 + e), m.GATES_OPEN, m.TODAY)
            lf, rf = lf or a, rf or b
            if lf and rf:
                break
        self.assertEqual((lf[0], rf[0]), (18, 18))
        self.assertNotEqual(lf[1], rf[1])

    def test_eth_paced_leak_halves_in_three_weeks(self):
        # the_eth_paced_leak_halves_an_absent_validator_in_about_three_weeks
        # (finality.rs:924): 40/60, no finality for 21 days, >= 99.8% kept after
        # one day, 25M..35M of 60M kept after 21 days.
        roster, st = bare([40_000_000, 60_000_000])
        day = m.EPOCHS_PER_DAY
        kept_day = None
        for e in range(1, 21 * day + 5):
            _, f = st.process_epoch(e, roster, votes(2, [0], (0, G), 1000 + e), m.ETH_REHEARSAL, m.TODAY)
            self.assertIsNone(f)
            if e == day + 4:
                kept_day = 60_000_000 - int(st.leaked[1])
        self.assertGreaterEqual(kept_day * 1000, 60_000_000 * 998)
        self.assertTrue(25_000_000 <= 60_000_000 - int(st.leaked[1]) <= 35_000_000)
        self.assertEqual(int(st.leaked[0]), 0)

    def test_equivocator_counts_for_no_target(self):
        # equivocator_counts_for_no_target_and_is_reported (finality.rs:827):
        # 3 x 100; 0 and 1 vote X, 2 votes X and Y -> 2 dropped, X justified at
        # exactly 200/300, and 2 is absent (it would leak).
        roster, st = bare([100, 100, 100])
        v = votes(3, [0, 1, 2], (0, G), 7)
        v.add(np.array([False, False, True]), 0, G, 8)
        self.assertEqual(v.equiv.tolist(), [False, False, True])
        j, _ = st.process_epoch(1, roster, v, m.MAINNET, m.TODAY)
        self.assertEqual(j, (1, 7))
        self.assertEqual(sorted(st.justified.items()), [(0, G), (1, 7)])

    def test_split_claims_shape(self):
        # Split-claim reproduction: B's blocks carry A's votes; B finalizes A's
        # checkpoint and pays the claim (TODAY). CLAIM refuses it; P2A never lets B
        # count A's votes.
        fleet = m.Fleet.load()
        heavy = ["H1", "H2", "H3", "H4", "X"]  # 90.2%
        sc = m.Scenario("8c73", [heavy, ["H5"]], m.START, None, cross=[(0, 1)], end=m.START + 6)
        today = m.run(fleet, sc, m.TODAY)
        self.assertEqual(today["foreign"], 1)       # B finalizes (S, A_S) at S+1
        self.assertEqual(today["double_pay"], 1)
        self.assertIsNone(today["conflict"])
        self.assertIsNone(m.run(fleet, sc, m.CLAIM)["double_pay"])
        p2a = m.run(fleet, sc, m.P2A)
        self.assertIsNone(p2a["foreign"])
        self.assertIsNone(p2a["double_pay"])

    def test_variant_activation_epoch_override(self):
        # Rules.active_from (sweep --hf-from): a flag day after the run is the
        # TODAY outcome; one at the partition start is the variant's.
        fleet = m.Fleet.load()
        sc = m.Scenario("act", [["H1", "H2", "H3", "H4", "X"], ["H5"]], m.START, None, cross=[(0, 1)],
                        end=m.START + 6)
        late = m.resolve_variants(["BOTH"], m.START + 1000)[0]
        now = m.resolve_variants(["BOTH"], m.START)[0]
        self.assertEqual(m.run(fleet, sc, late), m.run(fleet, sc, m.TODAY))
        self.assertEqual(m.run(fleet, sc, now), m.run(fleet, sc, m.BOTH))


class HandComputed(unittest.TestCase):
    def test_equal_halves_conflict_when_absent_leaks_to_half(self):
        # Two sides of exactly 1/2, mainnet gates (Q = 2_684_355, floor 1/2).
        # Side justifies when 3p >= 2(p + (1-p) r) with p = 1/2, i.e. r <= 1/2.
        # r(T) = prod_{t<=T}(1 - t/Q) ~ exp(-T(T+1)/2Q) = 1/2 at
        # T ~ sqrt(2 Q ln 2) - 1/2 = 1928.6 leak epochs, i.e. justified around
        # epoch 4 + 1929 after the stall began, finalized one epoch later.
        Q = m.INACTIVITY_LEAK_QUOTIENT_ETH_PACED
        T = math.sqrt(2 * Q * math.log(2)) - 0.5
        roster = m.Roster([0, 1], [10**15, 10**15])
        a, b = m.Finality.new((5999, G), 2), m.Finality.new((5999, G), 2)
        fa = fb = None
        for e in range(6000, 6000 + 2200):
            _, x = a.process_epoch(e, roster, votes(2, [0], a.cj, 10_000 + e), m.MAINNET, m.TODAY)
            _, y = b.process_epoch(e, roster, votes(2, [1], b.cj, 20_000 + e), m.MAINNET, m.TODAY)
            fa = fa or (x and e)
            fb = fb or (y and e)
            if fa and fb:
                break
        expect = 6000 + 4 + T + 1
        self.assertEqual(fa, fb)
        self.assertLess(abs(fa - expect), 3, (fa, expect))

    def test_p1a_never_finalizes_either_half(self):
        roster = m.Roster([0, 1], [10**15, 10**15])
        a = m.Finality.new((5999, G), 2)
        for e in range(6000, 6000 + 4000):
            _, x = a.process_epoch(e, roster, votes(2, [0], a.cj, 10_000 + e), m.MAINNET, m.P1A)
            self.assertIsNone(x)

    def test_snapshot_cohort_is_at_its_cap(self):
        # The served weights already sit at the epoch-6016 cohort cap (8780 bps).
        fleet = m.Fleet.load()
        self.assertEqual(m.cohort_cap_bps(6016), 8780)
        raw = fleet.roster.raw
        share = raw[fleet.roster.cohort_mask].sum() / raw.sum()
        self.assertAlmostEqual(float(share), 0.8780, places=4)
        # Re-applying the cap at 6016 moves at most a few parts per million.
        self.assertLess(abs(int(fleet.roster.at(6016).sum()) - int(raw.sum())) / int(raw.sum()), 1e-6)

    def test_heal_copy_equals_direct_run(self):
        fleet = m.Fleet.load()
        sides = [["H1", "H2", "H4"], ["H3", "H5", "X"]]
        H = m.START + 40
        direct = m.run(fleet, m.Scenario("d", sides, m.START, H), m.TODAY)
        via = m.run_heals(fleet, m.Scenario("d", sides, m.START), m.TODAY, [H])[H]
        self.assertEqual(direct, via)


if __name__ == "__main__":
    unittest.main()
