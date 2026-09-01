#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Self-test for the report half of scripts/fleet-gate-sweep.sh.
#
# The sweep is a flag-day gate: an operator reads its verdict and decides
# whether to arm a consensus rule. It therefore has to be trustworthy BEFORE it
# is pointed at production, and it cannot be exercised against production to
# find out — by the time a real disagreement exists, the damage is the thing
# you were trying to prevent.
#
# So the probe layer (ssh) and the report layer (verdicts) are separate on
# purpose: the shell half writes one raw `<label>.out` per host, and the python
# half only reads those files. This test writes those files by hand and pins
# the four outcomes that matter.
#
# Usage: bash scripts/fleet-gate-sweep.selftest.sh
set -uo pipefail
cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"

W="$(mktemp -d "${TMPDIR:-/tmp}/gate-selftest.XXXXXX")"
trap 'rm -rf "$W"' EXIT
fails=0
check() { # $1 = what, $2 = expected substring, $3 = haystack file
  if grep -qF -- "$2" "$3"; then
    echo "  ok   $1"
  else
    echo "  FAIL $1 — expected to find: $2"
    fails=$((fails + 1))
  fi
}

cat > "$W/hosts.tsv" <<'TSV'
ref-node	1.1.1.1	k	/bin/cinco	ref
same	2.2.2.2	k	/bin/cinco	validators
old-quatro	3.3.3.3	k	/bin/quatro	archival
missing-gate	4.4.4.4	k	/bin/tres	validators
inert-differs	5.5.5.5	k	/bin/seis	validators
dead	6.6.6.6	k	/bin/x	validators
TSV

FULL='{"binary":"bloch-pos cinco","gates_digest":"aaaa1111","consensus_gates":[
{"name":"TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH","epoch":800},
{"name":"BLOCK_BYTES_V2_ACTIVATION_EPOCH","epoch":800},
{"name":"LEAKED_ROSTER_ACTIVATION_EPOCH","epoch":1400},
{"name":"ANCESTRY_SEED_ACTIVATION_EPOCH","epoch":null}],"knows_gates_through_epoch":1400}'
printf '%s\n' "$FULL" > "$W/ref-node.out"
printf '%s\n' "$FULL" > "$W/same.out"

# The binary that predates `selfcheck --json`: it accepts the flag, ignores it,
# exits 0. This is the archival case and the whole reason the tool exists.
printf 'self-check passed\n' > "$W/old-quatro.out"

# Knows neither the epoch-1400 roster gate nor the inert one: forks AT 1400.
printf '%s\n' '{"binary":"bloch-pos tres","gates_digest":"bbbb2222","consensus_gates":[
{"name":"TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH","epoch":800},
{"name":"BLOCK_BYTES_V2_ACTIVATION_EPOCH","epoch":800}],"knows_gates_through_epoch":800}' \
  > "$W/missing-gate.out"

# Agrees on everything binding at 1400, but has a gate armed at 9000 that the
# reference ships inert. Safe to arm 1400 today; doomed at 9000.
printf '%s\n' '{"binary":"bloch-pos seis","gates_digest":"cccc3333","consensus_gates":[
{"name":"TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH","epoch":800},
{"name":"BLOCK_BYTES_V2_ACTIVATION_EPOCH","epoch":800},
{"name":"LEAKED_ROSTER_ACTIVATION_EPOCH","epoch":1400},
{"name":"ANCESTRY_SEED_ACTIVATION_EPOCH","epoch":9000}],"knows_gates_through_epoch":9000}' \
  > "$W/inert-differs.out"

printf 'SWEEP-ERROR: ssh/selfcheck failed (rc=255)\n' > "$W/dead.out"

run() { # $1 = epoch ('' for full set) ; writes $W/report, echoes exit code
  WORK="$W" HOSTS_FILE="$W/hosts.tsv" EPOCH="$1" REF_HOST=ref-node \
  REF_JSON= OUT_JSON=0 python3 "$REPO_ROOT/scripts/fleet-gate-sweep.py" \
    > "$W/report" 2>&1
  echo $?
}

echo "case 1: flag day at epoch 1400"
rc="$(run 1400)"
check "identical binary agrees"            "same           OK" "$W/report"
check "binary missing the 1400 gate forks" "LEAKED_ROSTER_ACTIVATION_EPOCH: reference=1400  this node=ABSENT" "$W/report"
check "pre---json binary is UNKNOWN"       "binary predates" "$W/report"
check "unreachable host is UNKNOWN"        "ssh/selfcheck failed" "$W/report"
check "later-only divergence is not a 1400 fork" "fork on a future flag day, not this one" "$W/report"
check "inert-vs-9000 named as the later divergence" "ANCESTRY_SEED_ACTIVATION_EPOCH: reference=inert  this node=9000" "$W/report"
check "overall verdict is NOT READY"       "NOT READY: do not arm." "$W/report"
[ "$rc" = "1" ] && echo "  ok   exit status 1" || { echo "  FAIL exit status $rc, want 1"; fails=$((fails+1)); }

echo "case 2: strict full-set check (no --epoch)"
rc="$(run '')"
check "full set promotes the later divergence to a fork" "inert-differs  FORK" "$W/report"
[ "$rc" = "1" ] && echo "  ok   exit status 1" || { echo "  FAIL exit status $rc, want 1"; fails=$((fails+1)); }

echo "case 3: a fleet that actually agrees"
rm -f "$W/old-quatro.out" "$W/missing-gate.out" "$W/inert-differs.out" "$W/dead.out"
grep -E '^(ref-node|same)' "$W/hosts.tsv" > "$W/hosts2.tsv" && mv "$W/hosts2.tsv" "$W/hosts.tsv"
rc="$(run 1400)"
check "agreeing fleet reports READY" "READY: all 2 probed node(s) agree" "$W/report"
[ "$rc" = "0" ] && echo "  ok   exit status 0" || { echo "  FAIL exit status $rc, want 0"; fails=$((fails+1)); }

echo
if [ "$fails" -eq 0 ]; then
  echo "fleet-gate-sweep selftest: PASS"
  exit 0
fi
echo "fleet-gate-sweep selftest: FAIL ($fails check(s))"
exit 1
