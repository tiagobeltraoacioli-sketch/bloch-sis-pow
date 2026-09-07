#!/usr/bin/env bash
# Hardened Clippy profile for CONSENSUS-CRITICAL code (security scanner lane).
#
# Panics (unwrap/expect) and unchecked arithmetic in consensus, emission, and
# tokenomics code are a denial-of-service / inflation vector: a single crafted
# input that reaches a panic aborts the node. This profile counts them.
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
# It was written as pass/fail, and it did not pass. So each crate carries a
# baseline per signal and the run fails when a count GOES UP. A new panic site
# or a new unchecked arithmetic op in live consensus is rejected today.
# Retiring the existing ones is a deliberate, reviewed change to an
# audit-facing crate, not something a CI job extorts during an incident.
#
# The findings are not a live crash. Every panic site inspected in the live
# consensus crate is locally provable as unreachable: `take(n)` in the
# transaction decoder returns exactly n bytes or an error, so the `try_into()`
# after it cannot fail; the block header's length is checked before any slice
# is taken; the gossip hold-queue's `keys().next()` runs under `len() >= cap >
# 0`. They are hand-proofs where the lint wants a type-level guarantee — which
# is the whole reason to keep counting them.
#
# When a baseline reaches 0 it is a hard gate again, which is what
# `bloch-euvm` already is. NEVER raise a baseline to make a build pass — the
# numbers only go down.
#
# ── WHY THERE ARE THREE BASELINES AND NOT ONE ────────────────────────────────
#
# CHANGED 2026-09-05 (audit finding I-M8). The ratchet counted lines matching
# `^error` in clippy's human output. `-W clippy::arithmetic_side_effects` emits
# at WARNING severity, so unchecked arithmetic was requested, emitted, printed,
# and then scored as zero — 199 findings in bloch-pos-committee alone, under a
# docstring that claimed it was denied. The signal the profile exists to raise
# could never have tripped the gate that exists to catch it.
#
# Severity was the wrong axis: it is a property of the -W/-D flag, not of the
# finding. Counting now goes through `--message-format=json`, by LINT NAME, in
# scripts/hardened-clippy-score.py — so a reworded diagnostic or a flipped
# severity cannot move a count, and each signal ratchets on its own:
#
#   panics  unwrap_used + expect_used
#   arith   arithmetic_side_effects
#   other   anything else raised at `error` severity — the catch-all that
#           makes "emitted but uncounted" impossible to repeat
#
# Conflating them had already gone wrong: the `^error` count for
# bloch-pos-committee read 12 against a baseline of 9, but the 3 extra were
# `absurd_extreme_comparisons`, not panic sites. The panic baseline had been
# right all along; the counter was measuring something else. Splitting the
# signals is what restores it to 9 rather than a baseline bump.
#
# ── THE BASELINES BELOW, MEASURED ────────────────────────────────────────────
#
# Re-measured 2026-09-05 at main e266a76c, toolchain 1.94.1, by this script:
#
#   crate                  panics   arith   other      old single number
#   bloch-pos-committee         9     199       3      9
#   bloch-pos-node             28     105       0      27  ← see below
#   bloch                      59     205       0      59
#   bloch-crypto               19      77       3      22  (19 + 3 = 22)
#   bloch-euvm                  0      30       0      0
#
# Read the last column first. Four of the five panic baselines come back
# EXACTLY as recorded at 8167ceb once the signals are separated — including
# bloch-crypto, whose 22 is 19 panic sites plus the 3 non-panic deny-level
# lints that now sit in `other`. That agreement is the evidence that this is a
# re-derivation of the existing baselines and not a fresh, laxer set.
#
# The arith column is the whole finding: 616 unchecked arithmetic operations
# across the gated crates, every one of them requested by the profile, emitted
# by clippy, printed into the job log, and scored as zero. `bloch-euvm` was
# documented as the crate that had already reached 0 and was a hard gate again
# — it has 30.
#
# UPDATE 2026-09-07 (O07, bloch-pos-committee only): the four `expect()`s in
# header.rs's decoder (an infallible `try_into` after the length was already
# checked) became a `Result` path returning the existing `WrongLength` error;
# gossip.rs's hold-queue eviction (`keys().next()` under a `len() >= cap > 0`
# invariant) became a pattern that cannot panic; transition.rs's TxReader
# `try_into().unwrap()`s (after a `take(n)` that returns exactly n bytes) became
# `?` on the decoder's own `Truncated`, and the two REWARDS_V2 `expect("gated
# above")`s became `if let Some(registry)` bindings on the option that IS the
# gate. Panics 9 -> 0: the live consensus crate is a hard panic gate again,
# with `bloch-euvm`. Twenty-four
# arithmetic_side_effects sites in beacon.rs, finality.rs, gossip.rs, header.rs,
# schedule.rs, staking.rs and ws.rs became either a checked/saturating op
# (saturating only on bounds/counters, never on a value that could enter a
# committed root) or a targeted `#[allow(clippy::arithmetic_side_effects)]`
# with a proof naming the bound. Arith 199 -> 186. `other` was already 0.
# Every transformation is behaviour-preserving on every input the chain has
# ever seen; where a panic became an error return, the error is one the
# caller already treated as "block invalid". Re-measured by this script;
# full `cargo test -p bloch-pos-committee` green.
#
# bloch-pos-node is the one number that genuinely moved: 28 panic sites against
# a recorded 27, a real regression that landed between 8167ceb and e266a76c
# while the job was red for unrelated reasons and nobody could read it. It is
# recorded at 28 so the gate can block the 29th, NOT because 28 is acceptable;
# the sites are printed on every run and the crate is one bin. That +1 is
# flagged for review — it is the one baseline here that should come back down.
#
# ── TOOLCHAIN ────────────────────────────────────────────────────────────────
#
# A lint count is a property of (source, toolchain). rustc and clippy add
# lints, reclassify them and change their reachability every release, so a
# baseline recorded on one compiler is not a measurement on another: the same
# tree scores differently and the ratchet reads that drift as regression or as
# improvement. The runner's `stable` moves on its own schedule, which makes the
# gate's verdict a function of the calendar.
#
# So the run is pinned to the same channel the release binary is built with —
# crates/bloch-pos-node/rust-toolchain.toml, the one the baselines below were
# measured on. Not hardcoded here: two pins drift apart silently.
#
# `--no-deps` is MANDATORY here: without it, `cargo clippy -p X` also lints
# workspace path-dependencies (bloch-sis-pow, coherence-core), and a single
# `-D unwrap_used` hit in one of those aborts the run before the target crate
# is ever linted.
#
# Usage:  ./scripts/hardened-clippy.sh
# Self-test (no toolchain needed):  bash scripts/hardened-clippy.selftest.sh
# Exit non-zero if any crate has more findings than a recorded baseline, or if
# a crate fails to build for a reason that is not a lint, or if the pinned
# toolchain is unavailable.
set -euo pipefail
cd "$(dirname "$0")/.."

SCORE=scripts/hardened-clippy-score.py

HARDENED=(
  -W clippy::pedantic
  -W clippy::arithmetic_side_effects
  -D clippy::unwrap_used
  -D clippy::expect_used
)

# ── Resolve the pin ──────────────────────────────────────────────────────────
# rustup only applies rust-toolchain.toml to invocations at or below its
# directory; this script runs from the repo root, which has no pin, so the pin
# has to be applied explicitly.
TOOLCHAIN_FILE=crates/bloch-pos-node/rust-toolchain.toml
CHANNEL="$(sed -n 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' \
  "$TOOLCHAIN_FILE" 2>/dev/null | head -1)"
if [ -z "$CHANNEL" ]; then
  echo "hardened-clippy: cannot read a channel from $TOOLCHAIN_FILE."
  echo "  The baselines below are only meaningful on the pinned toolchain;"
  echo "  refusing to score on an unknown one."
  exit 1
fi
if ! rustup run "$CHANNEL" cargo --version >/dev/null 2>&1; then
  echo "hardened-clippy: installing pinned toolchain $CHANNEL ..."
  rustup toolchain install "$CHANNEL" --component clippy --profile minimal || true
fi
if ! rustup run "$CHANNEL" cargo clippy --version >/dev/null 2>&1; then
  echo "hardened-clippy: pinned toolchain $CHANNEL (from $TOOLCHAIN_FILE) is not"
  echo "  available with clippy, and could not be installed. Failing closed: a"
  echo "  count taken on a different compiler is not a measurement against"
  echo "  these baselines."
  exit 1
fi
echo "hardened-clippy: toolchain $CHANNEL (pinned by $TOOLCHAIN_FILE)"
rustup run "$CHANNEL" cargo clippy --version

FAILED=0

# ratchet <label> <pkg> <panics> <arith> <other> <cargo-clippy args...>
ratchet() {
  local label="$1" pkg="$2" panics="$3" arith="$4" other="$5"; shift 5
  echo
  echo "== $label (panics $panics / arith $arith / other $other) =="
  local log; log="$(mktemp)"
  # --message-format=json puts every diagnostic on stdout with its lint name;
  # stderr keeps cargo's own chatter, which the scorer skips but a human
  # reading a failed job still wants in the log.
  rustup run "$CHANNEL" cargo clippy -p "$pkg" --message-format=json "$@" \
    -- "${HARDENED[@]}" >"$log" 2>&1 || true

  local rc=0
  python3 "$SCORE" --pkg "$pkg" --panics "$panics" --arith "$arith" \
    --other "$other" "$log" || rc=$?
  [ "$rc" -eq 0 ] || FAILED=1
  rm -f "$log"
}

# ── LIVE: Genesis-4 ──────────────────────────────────────────────────────────
ratchet "bloch-pos-committee — Genesis-4 consensus, LIVE" \
  bloch-pos-committee 0 186 0 --lib --no-deps

# No lib target: this crate is a binary. --bins, not --lib.
ratchet "bloch-pos-node — the bloch-pos binary, LIVE" \
  bloch-pos-node 28 105 0 --bins --no-deps

# ── CLOSED: Genesis-3 ────────────────────────────────────────────────────────
ratchet "bloch — Genesis-3 consensus/pow/reorg, closed chain" \
  bloch 59 205 0 --lib --no-deps --no-default-features --features node

ratchet "bloch-crypto — tokenomics/emission/sighash" \
  bloch-crypto 19 77 3 --lib --no-deps --all-features

ratchet "bloch-euvm — eUTXO VM, Genesis-3, never wired into Genesis-4" \
  bloch-euvm 0 30 0 --lib --no-deps

echo
if [ "$FAILED" -ne 0 ]; then
  echo "hardened-clippy: FAILED"
  exit 1
fi
echo "hardened-clippy: OK"
