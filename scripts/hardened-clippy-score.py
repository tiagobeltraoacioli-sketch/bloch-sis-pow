#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Score one crate's hardened-clippy run against its recorded baselines.

Split out of scripts/hardened-clippy.sh for the same reason the fleet gate
sweep is split: the half that runs cargo cannot be exercised without a
toolchain and twenty minutes, so the half that decides pass/fail reads a file
and nothing else. scripts/hardened-clippy.selftest.sh writes those files by
hand and pins the outcomes.

WHY JSON AND NOT `grep ^error`
------------------------------
The ratchet used to count lines matching `^error` in clippy's human output.
That silently discarded an entire signal the profile asks for:
`-W clippy::arithmetic_side_effects` is a WARNING, so every unchecked add,
sub, mul and index offset in consensus and emission code was emitted, printed,
and scored as zero — 199 of them in bloch-pos-committee alone, under a
docstring that said unchecked arithmetic was denied.

Severity is the wrong axis anyway: it is a property of the -W/-D flag, not of
the finding. `--message-format=json` carries the LINT NAME, so each signal is
counted by identity and a reworded diagnostic or a flipped severity cannot
move a count. The three signals are ratcheted separately because they are
separately meaningful, and because conflating them already went wrong once:
the `^error` count for bloch-pos-committee had drifted to 12 against a
baseline of 9, but the 3 extra were `absurd_extreme_comparisons` — deny-level
by default, and not panic sites at all. The panic baseline had been right the
whole time; the counter was measuring something else.

  panics : clippy::unwrap_used, clippy::expect_used — a panic reachable from
           an untrusted block or tx is a remote node-kill.
  arith  : clippy::arithmetic_side_effects — an overflow in emission or stake
           accounting is an inflation / accounting bug.
  other  : anything else clippy or rustc raised at `error` severity. The
           catch-all exists so that no future deny-level lint can be emitted
           and go uncounted, which is the exact bug above.

Usage:
  hardened-clippy-score.py --pkg PKG --panics N --arith N --other N LOGFILE

Exit: 0 at-or-below every baseline, 1 a count rose, 2 the run is void (the
crate never got linted, or it failed to build for a reason that is not a lint).
"""

from __future__ import annotations

import argparse
import json
import sys

PANIC_LINTS = {"clippy::unwrap_used", "clippy::expect_used"}
ARITH_LINTS = {"clippy::arithmetic_side_effects"}

# rustc's own hard errors carry an E-code; lints never do. A crate that fails
# to build for a syntax error or a missing feature must not be scored as
# findings — that reads as "clean" the moment the error count happens to sit
# under a baseline.
def _is_rustc_error_code(code: str | None) -> bool:
    return bool(code) and code[0] == "E" and code[1:].isdigit()


# rustc closes a failed compilation with a codeless `error: aborting due to N
# previous errors`. It is a summary of the findings, not a finding.
_SUMMARY_PREFIXES = ("aborting due to", "could not compile")


def score(path: str) -> dict:
    ran = False
    findings = []  # (level, code, location, text)
    seen = set()
    parse_errors = 0

    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line.startswith("{"):
                continue  # cargo's own chatter on stderr; not a diagnostic
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                parse_errors += 1
                continue
            if not isinstance(rec, dict):
                continue
            if rec.get("reason") == "build-finished":
                ran = True
                continue
            if rec.get("reason") != "compiler-message":
                continue
            msg = rec.get("message") or {}
            level = msg.get("level")
            if level not in ("error", "warning"):
                continue
            text = msg.get("message") or ""
            code = (msg.get("code") or {}).get("code")
            if code is None and text.startswith(_SUMMARY_PREFIXES):
                continue

            loc = "?"
            for span in msg.get("spans") or []:
                if span.get("is_primary"):
                    loc = f"{span.get('file_name')}:{span.get('line_start')}:{span.get('column_start')}"
                    break

            # cargo replays the same diagnostic once per target that shares the
            # source file (lib + test harness). Identity, not emission count.
            key = (code, loc, text)
            if key in seen:
                continue
            seen.add(key)
            findings.append((level, code, loc, text))

    panics = [f for f in findings if f[1] in PANIC_LINTS]
    arith = [f for f in findings if f[1] in ARITH_LINTS]
    broken = [f for f in findings if f[0] == "error" and _is_rustc_error_code(f[1])]
    other = [
        f
        for f in findings
        if f[0] == "error"
        and f[1] not in PANIC_LINTS
        and f[1] not in ARITH_LINTS
        and not _is_rustc_error_code(f[1])
    ]
    return {
        "ran": ran,
        "parse_errors": parse_errors,
        "panics": panics,
        "arith": arith,
        "other": other,
        "broken": broken,
    }


def main() -> int:
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("--pkg", required=True)
    ap.add_argument("--panics", type=int, required=True)
    ap.add_argument("--arith", type=int, required=True)
    ap.add_argument("--other", type=int, required=True)
    ap.add_argument("--show", type=int, default=12, help="max sites to print per signal")
    ap.add_argument("logfile")
    args = ap.parse_args()

    try:
        r = score(args.logfile)
    except OSError as exc:
        print(f"  DID NOT RUN — cannot read the clippy log: {exc}")
        return 2

    # A ratchet that counts findings will read "0 findings, improved!" out of a
    # run that never started: a bad working directory, a renamed package, a
    # cargo that could not resolve the workspace. cargo emits exactly one
    # build-finished record per invocation, success or failure, so its absence
    # means the measurement is void — not clean.
    if not r["ran"]:
        print(f"  DID NOT RUN — no build-finished record for `{args.pkg}`.")
        print("  This is a harness failure, not a clean crate.")
        return 2

    if r["broken"]:
        print("  BUILD FAILURE (not a lint finding):")
        for _lvl, code, loc, text in r["broken"][: args.show]:
            print(f"    {code} {loc}  {text}")
        return 2

    rose = False
    for name, baseline in (
        ("panics", args.panics),
        ("arith", args.arith),
        ("other", args.other),
    ):
        found = r[name]
        n = len(found)
        if n > baseline:
            rose = True
            print(f"  FAIL {name}: {n} findings, baseline {baseline}.")
            print("  Something new tripped the hardened profile. Remove it, or argue")
            print("  for it in review — do not raise the baseline to go green.")
            for _lvl, code, loc, text in found[: args.show]:
                print(f"    {code or '-'} {loc}  {text}")
        elif n < baseline:
            print(f"  IMPROVED {name}: {n} findings, baseline {baseline}.")
            print("  Lower the baseline in scripts/hardened-clippy.sh to lock it in.")
        else:
            print(f"  OK {name}: at baseline ({n}).")

    # Panic sites are the point of the profile; show them even when at baseline
    # so a swap (one removed, one added) is visible in the job log.
    if r["panics"]:
        print("  panic sites:")
        for _lvl, _code, loc, _text in r["panics"][: args.show]:
            print(f"    {loc}")

    return 1 if rose else 0


if __name__ == "__main__":
    sys.exit(main())
