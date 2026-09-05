#!/usr/bin/env bash
# flake-lock.sh — HUMAN-RUN on the aarch64 Nix host. Agents do NOT run Nix.
#
# Roadmap #2 (pin all Nix inputs). This generates/refreshes flake.lock and prints
# the resolved input revisions so the commit message + os/MOBILE.md can record
# them. It does NOT fabricate any hash — every value printed comes out of Nix.
#
# What the honest claim buys: committing flake.lock makes the build
# "reproducible-by-design" (same inputs -> fixed store hashes). It is NOT
# "reproduced": that word is earned only by a two-builder bit-for-bit /
# diffoscope-clean match (see repro-manifest.sh + repro-compare.sh, REPRO.md §2).
#
# EXPECTED PINS — NOT YET RECORDED.
# These constants used to read `ac62194` (nixpkgs) and `458448d` (mobile-nixos),
# introduced by 93ee0346 whose subject says "flake.lock generated on the aarch64
# host (mobile-nixos@458448d, nixpkgs@ac62194)". That commit did not add
# flake.lock, no commit on main ever has, os/MOBILE.md's "Pinned revisions" block
# still holds its `<from nix flake metadata>` placeholders, and the only
# flake.lock in this repository's history is a 7-line stub on an abandoned branch
# whose `nodes` is `{"root": {}}`. So nothing in the tree corroborates those two
# revs, and comparing against them made this script look like it had verified a
# pin that does not exist. They are kept here only as the historical claim:
#
#   (unverifiable, do NOT restore as expected values)
#     nixpkgs      rev: ac62194   claimed for branch nixos-25.05 at "lock time"
#     mobile-nixos rev: 458448d   claimed; flake=false, its npins nixpkgs is transitive
#
# When you run this on the Nix host it will print the REAL revs. Paste them into
# the two constants below, commit them together with flake.lock, and the drift
# check becomes a comparison against a measured value. scripts/check-repro-inputs.py
# fails the pipeline while they are still UNRECORDED, and fails again if they ever
# disagree with what flake.lock actually pins.
#
# Usage:  scripts/flake-lock.sh
# Requires: a Nix with flakes enabled (aarch64 Linux host). NOT runnable by agents.

set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# Replace both with the revs printed below, once you have run this for real.
EXPECT_NIXPKGS="UNRECORDED"
EXPECT_MOBILE_NIXOS="UNRECORDED"

command -v nix >/dev/null || { echo "nix not found — run this on the aarch64 Nix host."; exit 2; }

# 1. Resolve nixos-25.05 (branch) -> fixed nixpkgs rev, mobile-nixos (branch) ->
#    fixed mobile-nixos rev. Writes flake.lock.
nix flake lock

# 2. Record exactly what got pinned.
meta="$(nix flake metadata --json)"
got_nixpkgs="$(printf '%s' "$meta" | jq -r '.locks.nodes.nixpkgs.locked.rev')"
got_mobile="$(printf '%s' "$meta" | jq -r '.locks.nodes["mobile-nixos"].locked.rev')"

echo "nixpkgs      rev: $got_nixpkgs"
echo "mobile-nixos rev: $got_mobile"

# 3. Drift check against the recorded expected pins (prefix match — the constants
#    above are short revs). A mismatch is not necessarily an error, but it MUST be
#    intentional and re-recorded in this script + os/MOBILE.md + the commit body.
#    UNRECORDED is not a value to match against: it means nobody has ever written
#    down what this repository is supposed to pin, so the check cannot pass.
warn=0
check_rev() {  # <input-name> <recorded> <resolved>
  local name="$1" want="$2" got="$3"
  if [ "$want" = "UNRECORDED" ] || [ -z "$want" ]; then
    echo "⚠ $name: no rev recorded — paste $got into EXPECT_* at the top of this script."
    warn=1
    return
  fi
  case "$got" in
    "$want"*) ;;
    *) echo "⚠ $name rev drifted from expected $want (got $got) — re-record if intentional."; warn=1 ;;
  esac
}
check_rev nixpkgs      "$EXPECT_NIXPKGS"      "$got_nixpkgs"
check_rev mobile-nixos "$EXPECT_MOBILE_NIXOS" "$got_mobile"

echo
echo "Next: paste the revs above into EXPECT_NIXPKGS / EXPECT_MOBILE_NIXOS here, then"
echo "commit flake.lock (+ flake.nix if you pinned the mobile-nixos rev there, and"
echo "os/MOBILE.md 'Pinned revisions'). Verify with:"
echo "    python3 scripts/check-repro-inputs.py"
echo "which is the BLOCKING CI gate and stays red until all of that is true."
exit "$warn"
