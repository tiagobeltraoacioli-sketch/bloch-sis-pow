#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# audit-all-lockfiles.sh — run `cargo audit` on EVERY workspace lockfile in the
# repository, not just the root one.
#
# WHY THIS EXISTS (Round-2 audit finding SC2-sharks-shamir)
# ---------------------------------------------------------
# This repository deliberately hosts several STANDALONE cargo workspaces
# (pool/, pool-proxy/, services/pq-shield-api/, euvm-tooling/, fuzz/,
# spikes/prover-cost/) so that shipping tools cannot link consensus crates.
# The cost of that isolation: `cargo audit` run at the root reads ONLY the
# root Cargo.lock, so a vulnerable dependency pinned in a sub-workspace's
# lockfile was invisible to CI. That is exactly how pool/ shipped sharks
# 0.5.0 (RUSTSEC-2024-0398, biased Shamir coefficients in the M-of-N seed
# recovery tool) through a green pipeline.
#
# CONTRACT
# --------
# * The list below is EXPLICIT, not discovered: a new standalone workspace
#   must be added here. To keep that honest, the script cross-checks the list
#   against `git ls-files '*Cargo.lock'` and FAILS if the repository contains
#   a committed lockfile the list does not cover — a new workspace cannot
#   silently escape the scanner the way pool/ did.
# * Every listed lockfile must exist (standalone workspaces commit their
#   lockfiles — see .gitignore's opening comment). Missing file = red build.
# * Any advisory (including unmaintained/unsound informational ones, via
#   --deny warnings) in ANY lockfile = red build. The shared ignore set with
#   rationale lives in .cargo/audit.toml, same as for the root run.
#
# Run locally: bash scripts/audit-all-lockfiles.sh
set -u -o pipefail

cd "$(dirname "$0")/.."

LOCKFILES=(
  Cargo.lock                      # root (node + consensus) workspace
  pool/Cargo.lock                 # reference mining pool (network-facing; the SC2 lesson)
  pool-proxy/Cargo.lock           # stratum proxy / mini-pool (network-facing)
  services/pq-shield-api/Cargo.lock
  euvm-tooling/Cargo.lock
  crates/coherence-prover/script/Cargo.lock   # SP1 zkVM guest driver (N-3, Round 3:
                                               # added by the P123-sp1-verifier fix
                                               # wave and left off this list)
  crates/coherence-prover/service/Cargo.lock  # SP1 prover HTTP service (same commit)
  fuzz/Cargo.lock
  spikes/prover-cost/Cargo.lock
  spikes/prover-cost/rv32/Cargo.lock  # SP1 guest workspaces (rv32*)
  spikes/prover-cost/rv32f/Cargo.lock
  spikes/prover-cost/rv32h/Cargo.lock
  spikes/prover-cost/rv32k/Cargo.lock
)

# 1) No committed lockfile may be missing from the list above.
missing_from_list=0
while IFS= read -r lock; do
  found=0
  for l in "${LOCKFILES[@]}"; do
    [ "$l" = "$lock" ] && found=1 && break
  done
  if [ "$found" -eq 0 ]; then
    echo "ERROR: committed lockfile '$lock' is NOT in scripts/audit-all-lockfiles.sh —" >&2
    echo "       add it to LOCKFILES so its workspace is scanned (finding SC2)." >&2
    missing_from_list=1
  fi
done < <(git ls-files '*Cargo.lock' 'Cargo.lock')

# 2) Audit every listed lockfile; keep going so ONE run reports ALL failures.
failed=0
for lock in "${LOCKFILES[@]}"; do
  if [ ! -f "$lock" ]; then
    echo "ERROR: expected lockfile '$lock' does not exist (standalone workspaces" >&2
    echo "       commit their lockfiles; run 'cargo generate-lockfile' there)." >&2
    failed=1
    continue
  fi
  echo "== cargo audit: $lock =="
  if ! cargo audit --deny warnings --file "$lock"; then
    echo "ERROR: cargo audit failed for '$lock'" >&2
    failed=1
  fi
done

if [ "$missing_from_list" -ne 0 ] || [ "$failed" -ne 0 ]; then
  exit 1
fi
echo "OK: ${#LOCKFILES[@]} lockfiles audited, list matches committed lockfiles."
