#!/usr/bin/env bash
# ci-banned-words.sh — BLOCKING trademark + attestation-bleed / earned-word gate.
#
# Roadmap risk R1 (CRITICAL): no trademark / banned-word gate is enforced in the
# bloch-blockchain CI. A green pipeline today proves NOTHING about trademark
# exposure or unearned "attested/audited/reproduced" claims. This script closes
# that: it is wired into .gitlab-ci.yml as a BLOCKING `check`-stage job.
#
# Two independent checks, both case-insensitive, both scanning the TRACKED tree
# (`git grep`, so it matches exactly what a CI checkout carries):
#
#   1. TRADEMARK  — "BABA YAGA" is federally registered (Class 9) and MUST NEVER
#                   ship in any form. Ship as Yagabona / Izbushka. Zero tolerance,
#                   no negation exemption (even "not baba yaga" is a hit — the
#                   string itself must not appear).
#
#   2. EARNED-WORD / attestation-bleed — a curated set of AFFIRMATIVE unearned
#                   claims that the honesty rails forbid until the named artifact
#                   exists. These are high-precision positive constructions
#                   ("fully attested", "externally audited", ...), NOT the bare
#                   words "attested"/"audited"/"reproducible" — those have
#                   legitimate technical uses (Nix `attested-image` attr, the
#                   SEV-SNP attestation subsystem) and honest disclaimers
#                   ("no external audit has been performed", "reproducible-by-
#                   design", "not yet independently verified"), which this gate
#                   deliberately does NOT flag. Honest disclaimers that happen to
#                   contain a banned phrase in a negated form are skipped by the
#                   negation post-filter below.
#
# Portability: matching uses `git grep -iInE` (git's own POSIX-ERE grep, identical
# on macOS/BSD and Linux/GNU runners); no PCRE (-P) is required.
#
# Usage:  scripts/ci-banned-words.sh          # scan the repo (from anywhere in it)
# Exit:   0 = clean, 1 = at least one violation (prints file:line for each).

set -euo pipefail

# Run from the repo root so `git grep` covers the whole tracked tree.
cd "$(git rev-parse --show-toplevel)"

fail=0

# ── 1. TRADEMARK — zero tolerance ────────────────────────────────────────────
# Matches: "baba yaga", "baba-yaga", "baba_yaga", "babayaga" (any case).
TRADEMARK_RE='baba[[:space:]_-]*yaga|babayaga'

tm_hits="$(git grep -iInE -- "$TRADEMARK_RE" -- . ':!scripts/ci-banned-words.sh' || true)"
if [ -n "$tm_hits" ]; then
  echo "❌ TRADEMARK VIOLATION — 'BABA YAGA' (federally registered, Class 9) must NEVER ship."
  echo "   Ship as Yagabona / Izbushka. Offending lines:"
  echo "$tm_hits" | sed 's/^/     /'
  echo
  fail=1
fi

# ── 2. EARNED-WORD / attestation-bleed — affirmative unearned claims ──────────
# Each pattern is an AFFIRMATIVE claim that is only true once a named artifact
# exists (external audit report, two-builder bit-for-bit match, real TEE boot).
# All are currently absent from the tree; this gate keeps them out.
EARNED_RE='fully attested|externally audited|has been audited|security[ -]audited|fully reproducible|independently reproduced|proven[ -]secure|production[ -]ready and secure'

# Negation post-filter: skip lines that are honest DISCLAIMERS (the banned phrase
# appears in a negated context). Trademark above gets no such exemption.
NEGATION_RE='\b(not|no|never|without|nothing|isn.?t|aren.?t|cannot|can.?t)\b'

ew_hits="$(git grep -iInE -- "$EARNED_RE" -- . ':!scripts/ci-banned-words.sh' || true)"
if [ -n "$ew_hits" ]; then
  # Drop disclaimer lines; keep only affirmative unearned claims.
  ew_hits="$(printf '%s\n' "$ew_hits" | grep -viE "$NEGATION_RE" || true)"
fi
if [ -n "$ew_hits" ]; then
  echo "❌ EARNED-WORD / attestation-bleed VIOLATION — an unearned claim is present."
  echo "   The earned word is due only when its artifact exists:"
  echo "   \"reproducible-by-design\" != \"reproduced\"; \"signed\" != \"audited\";"
  echo "   \"built\" != \"booted\". Rephrase to the honest, artifact-gated form."
  echo "   Offending lines:"
  echo "$ew_hits" | sed 's/^/     /'
  echo
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  echo "banned-words gate: FAIL"
  exit 1
fi

echo "banned-words gate: OK — no trademark or attestation-bleed violations."
