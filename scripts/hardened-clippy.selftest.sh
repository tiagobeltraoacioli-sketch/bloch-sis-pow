#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Self-test for the scoring half of the hardened-clippy ratchet.
#
# The ratchet is a BLOCKING gate on both pipelines, and it is the kind of gate
# that fails silently in the safe-looking direction: when its counter and the
# lint it is counting disagree, the job goes green and nobody learns anything.
# That is exactly what happened — `-W clippy::arithmetic_side_effects` emits at
# warning severity and the ratchet counted `^error`, so 199 unchecked
# arithmetic findings in live consensus scored as zero for as long as the gate
# existed. A green gate is not evidence that a gate works.
#
# So the two halves are separate on purpose: hardened-clippy.sh runs cargo and
# writes a JSON log per crate; hardened-clippy-score.py only reads such a log.
# This test writes those logs BY HAND and pins the outcomes — including the one
# that regressed. It needs no Rust toolchain and no compile.
#
# Usage: bash scripts/hardened-clippy.selftest.sh
set -uo pipefail
cd "$(dirname "$0")/.."
SCORE=scripts/hardened-clippy-score.py

W="$(mktemp -d "${TMPDIR:-/tmp}/hardened-clippy-selftest.XXXXXX")"
trap 'rm -rf "$W"' EXIT
fails=0

# fixture <file> <spec...>  — spec words are lint:count, or a bare literal:
#   nofinish        omit the build-finished record (a void run)
#   dup             repeat the previous finding verbatim
# Everything else is `<lint-or-E-code>:<n>` at the severity clippy really uses.
fixture() {
  local out="$1"; shift
  python3 - "$out" "$@" <<'PY'
import json, sys

out, specs = sys.argv[1], sys.argv[2:]
lines, finish, last = [], True, None

def emit(code, level, text, n):
    global last
    for i in range(n):
        msg = {
            "message": text,
            "code": None if code is None else {"code": code, "explanation": None},
            "level": level,
            "spans": [{
                "file_name": "crates/bloch-pos-committee/src/transition.rs",
                "line_start": 100 + len(lines) + i,
                "column_start": 9,
                "is_primary": True,
            }],
            "rendered": f"{level}: {text}\n",
        }
        last = {"reason": "compiler-message", "message": msg}
        lines.append(json.dumps(last))

SEV = {
    "clippy::unwrap_used": ("error", "used `unwrap()` on a `Result` value"),
    "clippy::expect_used": ("error", "used `expect()` on a `Result` value"),
    # The whole point: requested with -W, so clippy emits it as a WARNING.
    "clippy::arithmetic_side_effects":
        ("warning", "arithmetic operation that can potentially result in unexpected side-effects"),
    "clippy::absurd_extreme_comparisons":
        ("error", "this comparison involving the minimum or maximum element for this type"),
    "clippy::needless_range_loop": ("warning", "the loop variable is only used to index"),
}

for spec in specs:
    if spec == "nofinish":
        finish = False
        continue
    if spec == "dup":
        lines.append(json.dumps(last))
        continue
    head, _, tail = spec.rpartition(":")
    code, n = (head, int(tail)) if tail.isdigit() else (spec, 1)
    if code.startswith("E") and code[1:].isdigit():
        emit(code, "error", "mismatched types", n)
    elif code == "summary":
        emit(None, "error", "aborting due to 12 previous errors", n)
    else:
        lvl, text = SEV[code]
        emit(code, lvl, text, n)

# cargo interleaves its own non-JSON chatter on stderr; the scorer must skip it.
lines.insert(0, "warning: profiles for the non root package will be ignored")
if finish:
    lines.append(json.dumps({"reason": "build-finished", "success": False}))
open(out, "w").write("\n".join(lines) + "\n")
PY
}

# case <name> <expected-exit> <expected-substring> <baselines...> -- <fixture spec...>
case_() {
  local name="$1" want_rc="$2" want_txt="$3" bp="$4" ba="$5" bo="$6"; shift 6
  [ "${1:-}" = "--" ] && shift
  local log="$W/$name.json" outf="$W/$name.out"
  fixture "$log" "$@"
  python3 "$SCORE" --pkg bloch-pos-committee \
    --panics "$bp" --arith "$ba" --other "$bo" "$log" >"$outf" 2>&1
  local rc=$?
  if [ "$rc" -ne "$want_rc" ]; then
    echo "  FAIL $name — exit $rc, expected $want_rc"; sed 's/^/        /' "$outf"
    fails=$((fails + 1)); return
  fi
  if ! grep -qF -- "$want_txt" "$outf"; then
    echo "  FAIL $name — expected to find: $want_txt"; sed 's/^/        /' "$outf"
    fails=$((fails + 1)); return
  fi
  echo "  ok   $name"
}

echo "hardened-clippy self-test"

# ── THE REGRESSION THIS EXISTS FOR ───────────────────────────────────────────
# One unchecked arithmetic op above baseline must fail the gate. Under the old
# `grep -cE '^error'` counter this log scored 0 findings and went green, which
# is how 199 of them accumulated in live consensus behind a passing job.
case_ arith-rises 1 "FAIL arith" \
  0 2 0 -- clippy::arithmetic_side_effects:3

# ...and the same signal must be visible at all: at baseline it reports the
# real number, not zero.
case_ arith-counted 0 "OK arith: at baseline (3)" \
  0 3 0 -- clippy::arithmetic_side_effects:3

# ── THE SIGNALS RATCHET SEPARATELY ───────────────────────────────────────────
# A new panic site fails even while arithmetic sits exactly at baseline.
case_ panic-rises 1 "FAIL panics" \
  1 3 0 -- clippy::unwrap_used:2 clippy::arithmetic_side_effects:3

# A deny-level lint that is neither panic nor arithmetic lands in `other` and
# still fails — the catch-all that makes "emitted but uncounted" unrepeatable.
case_ other-rises 1 "FAIL other" \
  0 0 0 -- clippy::absurd_extreme_comparisons:3

# ...and it does NOT inflate the panic count. This is the conflation that made
# bloch-pos-committee read 12 against a correct baseline of 9.
case_ other-not-panics 0 "OK panics: at baseline (9)" \
  9 0 3 -- clippy::unwrap_used:9 clippy::absurd_extreme_comparisons:3

# Pedantic warnings are requested for the reviewer, not ratcheted; they must
# not be scored into any of the three counts.
case_ pedantic-ignored 0 "OK arith: at baseline (0)" \
  0 0 0 -- clippy::needless_range_loop:5

case_ improved 0 "IMPROVED arith" \
  0 5 0 -- clippy::arithmetic_side_effects:2

case_ at-baseline 0 "OK panics: at baseline (2)" \
  2 0 0 -- clippy::unwrap_used:2

# ── THE MEASUREMENT MUST BE VOID, NOT CLEAN ──────────────────────────────────
# No build-finished record: cargo never linted the crate. A counter alone reads
# that as a perfect score.
case_ did-not-run 2 "DID NOT RUN" \
  9 199 3 -- nofinish

case_ missing-log 2 "DID NOT RUN" 0 0 0 -- nofinish
rm -f "$W/missing-log.json"
python3 "$SCORE" --pkg p --panics 0 --arith 0 --other 0 "$W/missing-log.json" \
  >"$W/missing.out" 2>&1
if [ $? -eq 2 ] && grep -qF "DID NOT RUN" "$W/missing.out"; then
  echo "  ok   absent-log"
else
  echo "  FAIL absent-log — a log that does not exist must be void, not clean"
  fails=$((fails + 1))
fi

# A crate that does not compile must not be scored as findings.
case_ build-failure 2 "BUILD FAILURE" \
  9 199 3 -- E0308:2 clippy::arithmetic_side_effects:400

# rustc's closing `aborting due to N previous errors` is a summary of the
# findings, not a finding.
case_ summary-not-counted 0 "OK other: at baseline (0)" \
  1 0 0 -- clippy::unwrap_used:1 summary:1

# cargo replays a diagnostic once per target sharing the file; identity counts.
case_ duplicates-collapse 0 "OK arith: at baseline (1)" \
  0 1 0 -- clippy::arithmetic_side_effects:1 dup dup

echo
if [ "$fails" -ne 0 ]; then
  echo "hardened-clippy self-test: $fails FAILED"
  exit 1
fi
echo "hardened-clippy self-test: OK"
