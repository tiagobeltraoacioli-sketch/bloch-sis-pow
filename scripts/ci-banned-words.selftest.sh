#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Self-test for ci-banned-words.sh's earned-word negation filter.
#
# WHY THIS EXISTS (Round-1 finding LOW-7)
# ----------------------------------------
# The negation post-filter used to drop a whole LINE if a negation word
# ("not", "no", "never", ...) appeared ANYWHERE on it, regardless of where.
# "Bloch is fully attested; no other chain is." passed the gate: "no" is
# real, but it negates "other chain", not "fully attested" — the sentence
# still reads as an affirmative unearned claim. Fixed by windowing the
# negation check to the ~40 characters immediately BEFORE the matched
# phrase. This test builds a synthetic git repo in a temp dir — never the
# real tree — and proves both directions:
#
#   * the exact bypass sentence from the finding is now caught;
#   * an honest disclaimer with the negation genuinely preceding the phrase
#     still passes;
#   * a bare affirmative claim with no negation anywhere still fails (no
#     regression on the pre-existing behaviour);
#   * the trademark check (which gets NO negation exemption) still fires.
#
# Usage: bash scripts/ci-banned-words.selftest.sh
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CHECKER="$HERE/ci-banned-words.sh"
fails=0

check() {
  local desc="$1" content="$2" want_exit="$3" want_grep="${4:-}"
  local tmp
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/banned-words-selftest.XXXXXX")"
  git -C "$tmp" init -q
  git -C "$tmp" config user.email t@t
  git -C "$tmp" config user.name t
  printf '%s\n' "$content" > "$tmp/DOC.md"
  git -C "$tmp" add -A
  git -C "$tmp" commit -q -m t

  local out rc
  out="$(cd "$tmp" && bash "$CHECKER" 2>&1)"
  rc=$?
  rm -rf "$tmp"

  if [ "$rc" -ne "$want_exit" ]; then
    echo "  FAIL  $desc"
    echo "        expected exit $want_exit, got $rc"
    echo "        output:"
    echo "$out" | sed 's/^/          /'
    fails=$((fails + 1))
    return
  fi
  if [ -n "$want_grep" ] && ! printf '%s' "$out" | grep -qF "$want_grep"; then
    echo "  FAIL  $desc"
    echo "        expected output to contain: $want_grep"
    echo "        output:"
    echo "$out" | sed 's/^/          /'
    fails=$((fails + 1))
    return
  fi
  echo "  ok    $desc"
}

echo "ci-banned-words selftest"
echo

# The exact bypass sentence the finding names: negation is real but does not
# precede the affirmative phrase. MUST now fail.
check "the LOW-7 bypass sentence is caught (negation follows, does not precede)" \
  "Bloch is fully attested; no other chain is." 1 "FAIL"

# Honest disclaimer: the negation word sits immediately before the phrase.
# MUST stay green.
check "a genuine disclaimer (negation precedes the phrase) stays green" \
  "This chain has never been externally audited." 0 "OK"

# Bare affirmative claim, no negation anywhere on the line. MUST fail — this
# is the pre-existing behaviour the rewrite must not regress.
check "a bare affirmative claim with no negation still fails" \
  "The build is fully reproducible." 1 "FAIL"

# Trademark gets no negation exemption at all, windowed or not.
check "trademark violation is refused even when negated" \
  "This is not baba yaga." 1 "TRADEMARK"

# Clean text: neither check should fire.
check "ordinary text stays green" \
  "This is an ordinary sentence about the protocol." 0 "OK"

echo
if [ "$fails" -ne 0 ]; then
  echo "ci-banned-words selftest: FAIL ($fails case(s))"
  exit 1
fi
echo "ci-banned-words selftest: OK — 5 cases behave as documented"
