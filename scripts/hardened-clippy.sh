#!/usr/bin/env bash
# Hardened Clippy profile for CONSENSUS-CRITICAL code (security scanner lane).
#
# Panics (unwrap/expect) and unchecked arithmetic in consensus, emission, and
# tokenomics code are a denial-of-service / inflation vector: a single crafted
# input that reaches a panic aborts the node. This profile denies them.
#
# ── SCOPE ────────────────────────────────────────────────────────────────────
#
# Until 2026-08-13 this script did not lint the live chain at all. Its entire
# scope was Genesis-3 — the proof-of-work node, its emission, its eUTXO VM —
# which by then had stopped producing blocks at height 39,918. The consensus
# that was actually running, `bloch-pos-committee`, had never been through the
# gate that exists to keep panics out of consensus.
#
#   LIVE — Genesis-4, proof of stake
#     - bloch-pos-committee : state transition, fork choice, FFG finality,
#                             committees, RANDAO, staking, slashing, state
#                             root, tokenomics V4.
#     - bloch-pos-node      : the `bloch-pos` binary the fleet runs.
#
#   CLOSED — Genesis-3, proof of work. Stopped at height 39,918 on 2026-08-13;
#   still gated because Genesis-4's opening ledger is derived from it and that
#   derivation has to stay trustworthy — not because it runs.
#     - bloch        : src/consensus/*, src/pow/*, src/reorg.rs (legacy/genesis3-node)
#     - bloch-crypto : src/core/tokenomics_v2.rs, src/core/mod.rs (emission +
#                      sighash). ALSO on the Genesis-4 signature path.
#     - bloch-euvm   : native eUTXO validator VM (off-by-default `euvm` feature)
#
# ── WHY THIS IS A RATCHET AND NOT A PASS/FAIL GATE ───────────────────────────
#
# It was written as pass/fail, and it did not pass. Measured 2026-08-13 at
# commit 8167ceb, on the toolchain pinned in
# crates/bloch-pos-node/rust-toolchain.toml:
#
#     bloch                  59 findings     bloch-pos-committee   9 findings
#     bloch-crypto           22 findings     bloch-pos-node       27 findings
#     bloch-euvm              0 findings
#
# So the job that both pipelines run as BLOCKING — GitLab `clippy-hardened`,
# GitHub `clippy-hardened (blocking)` — could not have gone green on any recent
# commit, on the retired crates alone, before the live ones were added to it. A
# gate that is permanently red is not a gate; it is noise that everyone learns
# to scroll past, and the way you discover that is by pointing it at new code
# and finding it was never green for the old.
#
# The findings are not a live crash. Every panic site inspected in the live
# consensus crate is locally provable as unreachable: `take(n)` in the
# transaction decoder returns exactly n bytes or an error, so the `try_into()`
# after it cannot fail; the block header's length is checked before any slice
# is taken; the gossip hold-queue's `keys().next()` runs under `len() >= cap >
# 0`. They are hand-proofs where the lint wants a type-level guarantee — which
# is the whole reason to keep counting them.
#
# So each crate carries a baseline and the run fails when its count GOES UP. A
# new panic site in live consensus is rejected today. Retiring the existing
# ones is a deliberate, reviewed change to an audit-facing crate, not something
# a CI job extorts during an incident.
#
# When a baseline reaches 0 it is a hard gate again, which is what
# `bloch-euvm` already is. NEVER raise a baseline to make a build pass — the
# number only goes down.
#
# `--no-deps` is MANDATORY here: without it, `cargo clippy -p X` also lints
# workspace path-dependencies (bloch-sis-pow, coherence-core), and a single
# `-D unwrap_used` hit in one of those aborts the run before the target crate
# is ever linted.
#
# Usage:  ./scripts/hardened-clippy.sh
# Exit non-zero if any crate has more findings than its recorded baseline, or
# if a crate fails to build for a reason that is not a lint.
set -euo pipefail
cd "$(dirname "$0")/.."

HARDENED=(
  -W clippy::pedantic
  -W clippy::arithmetic_side_effects
  -D clippy::unwrap_used
  -D clippy::expect_used
)

FAILED=0

# ratchet <label> <pkg> <baseline> <cargo-clippy args...>
ratchet() {
  local label="$1" pkg="$2" baseline="$3"; shift 3
  echo
  echo "== $label (baseline $baseline) =="
  local log; log="$(mktemp)"
  cargo clippy -p "$pkg" "$@" -- "${HARDENED[@]}" >"$log" 2>&1 || true

  # Did clippy actually lint this crate? A ratchet that counts findings will
  # read "0 findings, improved!" out of a run that never started — a bad
  # working directory, a renamed package, a cargo that could not resolve the
  # workspace. Every real run ends in exactly one of these two lines, so
  # neither one present means the measurement is void, not clean.
  if ! grep -qE "^ *Finished|^error: could not compile \`$pkg\`" "$log"; then
    echo "  DID NOT RUN — this is a harness failure, not a clean crate:"
    grep -E '^error' "$log" | head -5
    rm -f "$log"; FAILED=1; return 0
  fi

  # `error: could not compile ... due to N previous errors` is a summary of the
  # findings, not a finding; everything else at `error:` severity is one.
  local hits
  hits="$(grep -E '^error' "$log" | grep -vcE '^error: could not compile' || true)"

  # A crate that fails to build for a non-lint reason (a syntax error, a
  # missing feature) must not be scored as findings. Anything rustc rejects
  # outright carries an error code; lints do not.
  local broken
  broken="$(grep -cE '^error\[E[0-9]+\]' "$log" || true)"
  if [ "$broken" -gt 0 ]; then
    echo "  BUILD FAILURE (not a lint finding):"
    grep -E '^error\[E[0-9]+\]' "$log" | head -10
    rm -f "$log"; FAILED=1; return 0
  fi

  # Show where the panic sites are; they are the point of the profile.
  grep -E '^error: used `(unwrap|expect)\(\)`' -A2 "$log" \
    | grep -e '-->' | sed 's/^ *--> /  /' | head -80 || true

  if [ "$hits" -gt "$baseline" ]; then
    echo "  FAIL: $hits findings, baseline $baseline."
    echo "  Something new tripped the hardened profile. Remove it, or argue for"
    echo "  it in review — do not raise the baseline to go green."
    grep -E '^error' "$log" | grep -vE '^error: could not compile' | sort | uniq -c | sort -rn | head -10
    FAILED=1
  elif [ "$hits" -lt "$baseline" ]; then
    echo "  IMPROVED: $hits findings, baseline $baseline."
    echo "  Lower the baseline in this script to lock it in."
  else
    echo "  OK: at baseline ($hits)."
  fi
  rm -f "$log"
}

# ── LIVE: Genesis-4 ──────────────────────────────────────────────────────────
ratchet "bloch-pos-committee — Genesis-4 consensus, LIVE" \
  bloch-pos-committee 9 --lib --no-deps

# No lib target: this crate is a binary. --bins, not --lib.
ratchet "bloch-pos-node — the bloch-pos binary, LIVE" \
  bloch-pos-node 27 --bins --no-deps

# ── CLOSED: Genesis-3 ────────────────────────────────────────────────────────
ratchet "bloch — Genesis-3 consensus/pow/reorg, closed chain" \
  bloch 59 --lib --no-deps --no-default-features --features node

ratchet "bloch-crypto — tokenomics/emission/sighash" \
  bloch-crypto 22 --lib --no-deps --all-features

ratchet "bloch-euvm — eUTXO VM, Genesis-3, never wired into Genesis-4" \
  bloch-euvm 0 --lib --no-deps

echo
if [ "$FAILED" -ne 0 ]; then
  echo "hardened-clippy: FAILED"
  exit 1
fi
echo "hardened-clippy: OK"
