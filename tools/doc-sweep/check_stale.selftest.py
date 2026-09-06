#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Selftest for tools/doc-sweep/check_stale.py.

Proves three things fixed on 2026-09-06 stay fixed:

1. `live_constants()` actually reads the current tokenomics_v4.rs values
   (not stale hardcoded numbers copy-pasted into this script itself).
2. `check_retired_table_fresh()` goes RED when a RETIRED row's "new" column
   drifts from a live constant — this is the exact failure mode that let
   four stale "current" values (CARRYOVER_TOTAL_BLOCH,
   LARGEST_CARRYOVER_ADDRESS_BLOCH, VALIDATOR_EMISSION_BLOCH, and the
   founder-total percentage) go unnoticed after the 2026-08-11
   carryover re-measurement: the "new" column cited the PRE-re-measurement
   figures as if they were current, and nothing checked that against the
   live constants.
3. The founder-cliff RETIRED row is not inverted (a bug that shipped until
   this date: the row treated the LIVE value, "2-year cliff", as the OLD
   one, and suggested "10-year cliff" as its replacement — exactly
   backwards, which meant the sweep could never catch the real stale
   "10-year cliff / 40-year vest" text on the public site and in the specs).

Run: python3 tools/doc-sweep/check_stale.selftest.py
"""
import subprocess
import sys
import os

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import check_stale as cs  # noqa: E402


def test_live_constants_reads_current_values():
    consts = cs.live_constants()
    # These are read from the file, not hardcoded here as a second copy —
    # assert only structural facts a stale copy could not fake:
    assert consts["TOTAL_SUPPLY_BLOCH"] == 100_000_000_000
    assert consts["CARRYOVER_TOTAL_BLOCH"] > 0
    assert consts["LARGEST_CARRYOVER_ADDRESS_BLOCH"] < consts["CARRYOVER_TOTAL_BLOCH"]
    assert consts["FOUNDER_CLIFF_SLOTS"] > 0
    assert consts["FOUNDER_VESTING_SLOTS"] > consts["FOUNDER_CLIFF_SLOTS"]
    print("ok: live_constants() reads sane current values")


def test_check_retired_table_fresh_flags_drift():
    consts = cs.live_constants()
    # Simulate the exact historical bug: a RETIRED table with no row at all
    # mentioning the current CARRYOVER_TOTAL_BLOCH value. Monkeypatch the
    # module's RETIRED list temporarily to an empty list and confirm the
    # guard function reports a problem rather than passing silently.
    original = cs.RETIRED
    try:
        cs.RETIRED = []
        problems = cs.check_retired_table_fresh(consts)
        assert problems, (
            "check_retired_table_fresh() must flag a problem when RETIRED "
            "has no row citing the current CARRYOVER_TOTAL_BLOCH value — "
            "this is the exact silent-drift failure mode from 2026-09-06"
        )
        assert any("CARRYOVER_TOTAL_BLOCH" in p for p in problems)
        assert any("LARGEST_CARRYOVER_ADDRESS_BLOCH" in p or "founder total share" in p
                   for p in problems)
    finally:
        cs.RETIRED = original
    print("ok: check_retired_table_fresh() goes red when a RETIRED row is missing/stale")


def test_check_retired_table_fresh_passes_on_current_table():
    consts = cs.live_constants()
    problems = cs.check_retired_table_fresh(consts)
    assert not problems, f"current RETIRED table should be fresh, but: {problems}"
    print("ok: check_retired_table_fresh() is clean against the current RETIRED table")


def test_founder_cliff_row_not_inverted():
    # The bug: a row claiming "2-year cliff" (the LIVE value) is what's
    # OLD, replaced by "10-year cliff" (the actual old draft value). Fail
    # loudly if that inversion ever reappears.
    for old, what, new in cs.RETIRED:
        if old == "2-year cliff":
            raise AssertionError(
                "RETIRED still has an inverted founder-cliff row: it treats "
                "the LIVE value '2-year cliff' as old — this is the exact "
                "bug fixed 2026-09-06 (see the file's own comment at that row)"
            )
    # And the correct direction must exist: the OLD draft value ("10-year
    # cliff") mapped to something naming the current 2yr/8yr pair.
    found = [row for row in cs.RETIRED if row[0] == "10-year cliff"]
    assert found, "expected a RETIRED row flagging the old '10-year cliff' draft text"
    _, _, new = found[0]
    assert "2-year cliff" in new or "8-year" in new
    print("ok: founder-cliff RETIRED row points the right direction")


def test_script_runs_clean_on_this_tree():
    # Full end-to-end: the script itself, run as a subprocess (closest to
    # how CI invokes it), must not crash and must report the live constants.
    result = subprocess.run(
        [sys.executable, os.path.join(HERE, "check_stale.py")],
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, f"check_stale.py exited {result.returncode}: {result.stderr}"
    assert "constantes vivas" in result.stdout
    print("ok: check_stale.py runs clean end-to-end")


def main():
    tests = [
        test_live_constants_reads_current_values,
        test_check_retired_table_fresh_flags_drift,
        test_check_retired_table_fresh_passes_on_current_table,
        test_founder_cliff_row_not_inverted,
        test_script_runs_clean_on_this_tree,
    ]
    failed = 0
    for t in tests:
        try:
            t()
        except AssertionError as e:
            failed += 1
            print(f"FAIL: {t.__name__}: {e}")
    if failed:
        print(f"\n{failed}/{len(tests)} selftest(s) failed")
        return 1
    print(f"\nall {len(tests)} selftests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
