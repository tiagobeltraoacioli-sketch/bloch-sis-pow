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
# The committed flake.lock on the aarch64 host resolved these revs (recorded here
# as the EXPECTED pin so drift is visible; regenerating below must reproduce them
# or the drift is intentional and must be re-recorded):
#
#   nixpkgs      rev: ac62194  (branch nixos-25.05 at lock time)
#   mobile-nixos rev: 458448d  (flake=false; its own npins nixpkgs is transitive)
#
# Usage:  scripts/flake-lock.sh
# Requires: a Nix with flakes enabled (aarch64 Linux host). NOT runnable by agents.

set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

EXPECT_NIXPKGS="ac62194"
EXPECT_MOBILE_NIXOS="458448d"

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
warn=0
case "$got_nixpkgs" in
  "$EXPECT_NIXPKGS"*) ;;
  *) echo "⚠ nixpkgs rev drifted from expected $EXPECT_NIXPKGS — re-record if intentional."; warn=1 ;;
esac
case "$got_mobile" in
  "$EXPECT_MOBILE_NIXOS"*) ;;
  *) echo "⚠ mobile-nixos rev drifted from expected $EXPECT_MOBILE_NIXOS — re-record if intentional."; warn=1 ;;
esac

echo
echo "Next: commit flake.lock (+ flake.nix if you pinned the mobile-nixos rev there,"
echo "and os/MOBILE.md 'Pinned revisions'). Then flip the flake-lock-drift CI job"
echo "from allow_failure:true to BLOCKING (see .gitlab-ci.yml)."
exit "$warn"
