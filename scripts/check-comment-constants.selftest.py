#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Prove `check-comment-constants.py` fires on lies and stays quiet on honest code.

Why this file exists
--------------------
Three guards audited in this repository were GREEN while the thing they guarded
was broken. One could not detect the change it existed to detect; one went green
when the defect was reopened; one asserted a line count. A guard nobody has
tried to break is a guard nobody knows works.

So this runs the checker against a synthetic repository built in a temporary
directory — never the real tree, so a failed selftest cannot leave the working
copy dirty — and asserts BOTH directions on every case:

  * each lie shape must be caught, and caught by NAME (a checker that fails for
    some other reason would otherwise look like a pass);
  * each honest shape must not fire, including the ones that are one word away
    from a lie — an armed constant documented correctly, a genuinely inert
    sentinel, and a lie described in the past tense;
  * a bind that has stopped matching anything must FAIL rather than go quiet,
    which is the specific way the three audited guards died;
  * and the checker must notice when the CONSTANT moves under honest prose, not
    only when the prose moves under a constant. That is the direction a guard
    usually cannot detect, so it is tested explicitly.

Run: `python3 scripts/check-comment-constants.selftest.py`
Exit 0 = the guard behaves as documented on all cases.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
CHECKER = os.path.join(HERE, "check-comment-constants.py")
REAL_REPO = os.path.dirname(HERE)


class Case:
    def __init__(self, name: str, source: str, *, must_fail: bool,
                 expect: str = "", forbid: str = ""):
        self.name = name
        self.source = source
        self.must_fail = must_fail
        self.expect = expect   # substring the output must contain
        self.forbid = forbid   # substring the output must NOT contain


CASES = [
    # ── lies that must be caught ──────────────────────────────────────────────
    Case(
        "attached: sentinel prose over a bound constant",
        """
/// Flag day for the thing.
///
/// `u64::MAX` means INERT: nothing changes until this is lowered.
pub const ALPHA_ACTIVATION_EPOCH: u64 = 800;
""",
        must_fail=True, expect="ALPHA_ACTIVATION_EPOCH",
    ),
    Case(
        "attached: wrong integer stated as the current value",
        """
/// The height.
///
/// Pinned at 9_999 — chosen for the rollout margin.
pub const BRAVO_FORK_HEIGHT: u64 = 4320;
""",
        must_fail=True, expect="BRAVO_FORK_HEIGHT",
    ),
    Case(
        "named: a claim about a constant declared elsewhere in the file",
        """
pub const CHARLIE_HEIGHT: u64 = 30_030;

fn gate(h: u64) -> bool {
    // Because `CHARLIE_HEIGHT` is 27_600, this is false below the fork.
    h >= CHARLIE_HEIGHT
}
""",
        must_fail=True, expect="CHARLIE_HEIGHT",
    ),
    Case(
        "bound: a prose number the author pinned to a constant",
        """
/// Measured at height 43,172 across the set.
/// prose-guard: bind height=DELTA_MEASURED_HEIGHT
pub const DELTA_MEASURED_HEIGHT: u64 = 39_918;
""",
        must_fail=True, expect="DELTA_MEASURED_HEIGHT",
    ),
    Case(
        "bound: a binding that no longer matches any phrase must FAIL, not go quiet",
        """
/// This paragraph no longer mentions the measurement at all.
/// prose-guard: bind height=ECHO_MEASURED_HEIGHT
pub const ECHO_MEASURED_HEIGHT: u64 = 39_918;
""",
        must_fail=True, expect="dead binding",
    ),
    Case(
        "bound: a binding naming a constant that does not resolve must FAIL",
        """
/// Measured at height 39,918.
/// prose-guard: bind height=FOXTROT_NO_SUCH_CONSTANT
pub const FOXTROT_MEASURED_HEIGHT: u64 = 39_918;
""",
        must_fail=True, expect="not a resolvable workspace constant",
    ),
    Case(
        "the constant moves under honest prose — the direction guards usually miss",
        """
/// The epoch.
///
/// Currently 800, an epoch the chain is past.
pub const GOLF_ACTIVATION_EPOCH: u64 = 1200;
""",
        must_fail=True, expect="GOLF_ACTIVATION_EPOCH",
    ),

    # ── honest code that must NOT fire ────────────────────────────────────────
    Case(
        "honest: a genuinely inert sentinel described as inert",
        """
/// Flag day for the thing.
///
/// `u64::MAX` means INERT: nothing changes until this is lowered.
pub const HOTEL_ACTIVATION_EPOCH: u64 = u64::MAX;
""",
        must_fail=False, forbid="HOTEL_ACTIVATION_EPOCH",
    ),
    Case(
        "honest: a bound constant described with its real value",
        """
/// Flag day for the thing.
///
/// Currently 800, an epoch the chain is long past.
pub const INDIA_ACTIVATION_EPOCH: u64 = 800;
""",
        must_fail=False, forbid="INDIA_ACTIVATION_EPOCH",
    ),
    Case(
        "honest: the old value recounted in the past tense",
        """
/// Flag day for the thing.
///
/// It was `u64::MAX` until 2026-08-24, and it would still be `u64::MAX` if the
/// rollout had not completed. Currently 800.
pub const JULIET_ACTIVATION_EPOCH: u64 = 800;
""",
        must_fail=False, forbid="JULIET_ACTIVATION_EPOCH",
    ),
    Case(
        "honest: a bind whose paragraph agrees with the constant",
        """
/// Measured at height 39,918 across 452,726 outputs.
/// prose-guard: bind height=KILO_MEASURED_HEIGHT, outputs=KILO_MEASURED_UTXOS
pub const KILO_MEASURED_HEIGHT: u64 = 39_918;
/// Count.
pub const KILO_MEASURED_UTXOS: u64 = 452_726;
""",
        must_fail=False, forbid="KILO_MEASURED",
    ),
    Case(
        "honest: a bind must not reach past its own paragraph into a history table",
        """
/// Measured at height 39,918.
/// prose-guard: bind height=LIMA_MEASURED_HEIGHT
///
/// | when | height |
/// |---|---|
/// | superseded | 43,172 |
/// | superseded | 39,328 |
pub const LIMA_MEASURED_HEIGHT: u64 = 39_918;
""",
        must_fail=False, forbid="LIMA_MEASURED_HEIGHT",
    ),
    Case(
        "suppression: an explicit allow silences the block and is counted",
        """
/// Flag day.
///
/// `u64::MAX` means INERT, which is what this WOULD be if the rollout stalled.
/// prose-guard: allow(the sentinel is named to explain the idiom, not this value)
pub const MIKE_ACTIVATION_EPOCH: u64 = 800;
""",
        must_fail=False, forbid="MIKE_ACTIVATION_EPOCH",
    ),
    Case(
        "honest: a constant with no value claim at all in its doc",
        """
/// The number of validators drawn per committee. Sized from the measured
/// signature cost, not chosen for roundness.
pub const NOVEMBER_COMMITTEE_SIZE: u64 = 588;
""",
        must_fail=False, forbid="NOVEMBER_COMMITTEE_SIZE",
    ),
]


def run_checker(repo: str) -> tuple[int, str]:
    checker = os.path.join(repo, "scripts", "check-comment-constants.py")
    p = subprocess.run([sys.executable, checker, "crates"],
                       capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr


def build_fixture(tmp: str, source: str) -> str:
    repo = os.path.join(tmp, "fixture")
    os.makedirs(os.path.join(repo, "scripts"), exist_ok=True)
    os.makedirs(os.path.join(repo, "crates", "probe", "src"), exist_ok=True)
    shutil.copy(CHECKER, os.path.join(repo, "scripts", "check-comment-constants.py"))
    with open(os.path.join(repo, "crates", "probe", "src", "lib.rs"), "w") as fh:
        fh.write("// SPDX-License-Identifier: AGPL-3.0-or-later\n" + source)
    return repo


def main() -> int:
    failures: list[str] = []
    print("check-comment-constants.selftest — proving the guard by breaking it\n")

    for c in CASES:
        with tempfile.TemporaryDirectory() as tmp:
            repo = build_fixture(tmp, c.source)
            rc, out = run_checker(repo)
        verdict = "red" if rc == 1 else ("green" if rc == 0 else f"error(rc={rc})")
        want = "red" if c.must_fail else "green"
        bad = []
        if (rc == 1) != c.must_fail:
            bad.append(f"expected {want}, got {verdict}")
        if c.expect and c.expect not in out:
            bad.append(f"output does not mention {c.expect!r}")
        if c.forbid and c.forbid in out:
            bad.append(f"output wrongly mentions {c.forbid!r}")
        if bad:
            failures.append(f"{c.name}: " + "; ".join(bad))
            print(f"  FAIL  {c.name}\n        " + "\n        ".join(bad))
            print("        --- checker output ---")
            for line in out.strip().splitlines():
                print(f"        {line}")
        else:
            print(f"  ok    [{verdict:5}] {c.name}")

    # The real repository must be green, or the guard cannot be a blocking job.
    rc, out = run_checker(REAL_REPO)
    if rc == 0:
        print(f"\n  ok    [green] the real workspace passes")
    else:
        failures.append("the real workspace does not pass the guard")
        print(f"\n  FAIL  the real workspace does not pass:\n{out}")

    print(f"\n{len(CASES) + 1} cases, {len(failures)} failed")
    for f in failures:
        print(f"  FAIL {f}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
