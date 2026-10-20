#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# HF3 KES REHEARSAL ON DEVNET4 — OWNER-RUN ONLY. Written 2026-10-20; NOT run
# by its author (devnet4 is off and agents do not touch it).
#
# devnet4 is a long-running network with real history, so this differs from
# the local rehearsal (kes.py) in three ways: no past flag day moves
# (arm.py --no-past), only the KES constants named in kes-devnet4.conf change
# (--only-listed), and the epochs are FUTURE devnet4 epochs you choose.
#
# Steps (each is a subcommand; nothing happens without one):
#
#   build     DISPOSABLE copy of a ref -> armed devnet4 KES binary under $WORK.
#             REG_EPOCH / ENFORCE_EPOCH must be future devnet4 epochs.
#   preflight read-only: the RPC is devnet4 (network_domain must equal
#             DEVNET4_NETWORK_DOMAIN, and must NOT equal MAINNET_NETWORK_DOMAIN),
#             reports getkes with the expected schedule, and the head is past
#             no gate of this build.
#   plan      print, per validator in $HOSTS, the commands to run ON THAT HOST
#             after the armed binary is installed there: kes keygen and kes
#             register (output file copied back here as v<i>.kes-register.hex).
#   submit    sendrawtransaction of every v<i>.kes-register.hex in $WORK/tx to
#             the devnet4 RPC (preflight first). --apply required; default
#             prints what it would send.
#   monitor   read-only: getkes every 60 s (registered stake, bind epoch,
#             periods remaining, pending rotations) and getchaininfo finality.
#
# Environment:
#   DEVNET4_RPC              http://host:port of a devnet4 RPC (required)
#   DEVNET4_NETWORK_DOMAIN   expected devnet4 network_domain hex (required)
#   MAINNET_NETWORK_DOMAIN   mainnet network_domain hex (required: refuse it)
#   REG_EPOCH ENFORCE_EPOCH  future devnet4 epochs (build)
#   REF                      git ref to build (default codex/hf3-kes-20261020)
#   HOSTS                    file: "<validator index> <ssh host> <data dir>" per line (plan)
#   WORK                     scratch dir (default ./devnet4-kes-work)
#
# Never point any of this at mainnet: the armed binary follows a different
# consensus (KES armed, short periods) and would fork off immediately.
set -euo pipefail

REPO="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
HERE="$REPO/scripts/hf-rehearsal"
WORK="${WORK:-$PWD/devnet4-kes-work}"
REF="${REF:-codex/hf3-kes-20261020}"
APPLY=0
CMD="${1:-}"; shift || true
for a in "$@"; do [ "$a" = "--apply" ] && APPLY=1; done

die() { echo "devnet4-kes: $*" >&2; exit 2; }
rpc() { # method [params-json]
  curl -sS --max-time 10 -X POST -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":${2:-[]}}" "$DEVNET4_RPC"
}
jget() { # [key]  -> JSON of result[key] (or the whole result), "ERROR ..." on an RPC error
  python3 -I -c '
import json,sys
d=json.load(sys.stdin); r=d.get("result")
if r is None: print("ERROR "+json.dumps(d.get("error")))
else: print(json.dumps(r[sys.argv[1]] if len(sys.argv)>1 and sys.argv[1] else r))' "${1:-}"
}

preflight() {
  : "${DEVNET4_RPC:?}" "${DEVNET4_NETWORK_DOMAIN:?}" "${MAINNET_NETWORK_DOMAIN:?}"
  [ "$DEVNET4_NETWORK_DOMAIN" != "$MAINNET_NETWORK_DOMAIN" ] || die "DEVNET4_NETWORK_DOMAIN equals the mainnet one"
  local dom; dom=$(rpc getvalidatoradmission | jget network_domain | tr -d '"')
  [ "$dom" = "$MAINNET_NETWORK_DOMAIN" ] && die "REFUSED: $DEVNET4_RPC is MAINNET"
  [ "$dom" = "$DEVNET4_NETWORK_DOMAIN" ] || die "REFUSED: $DEVNET4_RPC network_domain $dom is not devnet4"
  local kes; kes=$(rpc getkes | jget)
  case "$kes" in ERROR*) die "getkes unavailable: the RPC node does not run the armed KES build ($kes)";; esac
  echo "preflight OK: devnet4 domain $dom"
  echo "getkes: $kes" | cut -c1-600
  rpc getchaininfo | jget finalized
}

case "$CMD" in
  build)
    : "${REG_EPOCH:?future devnet4 epoch}" "${ENFORCE_EPOCH:?future devnet4 epoch}"
    [ "$ENFORCE_EPOCH" -gt "$REG_EPOCH" ] || die "ENFORCE_EPOCH must be after REG_EPOCH"
    mkdir -p "$WORK"; [ -e "$WORK/src" ] && die "$WORK/src exists"
    mkdir -p "$WORK/src"; git -C "$REPO" archive "$REF" | tar -x -C "$WORK/src"
    sed -e "s/__REGISTRATION_EPOCH__/$REG_EPOCH/" -e "s/__ENFORCE_EPOCH__/$ENFORCE_EPOCH/" \
      "$HERE/kes-devnet4.conf" > "$WORK/kes-devnet4.conf"
    python3 -I "$HERE/arm.py" "$WORK/src" --no-past --only-listed --conf "$WORK/kes-devnet4.conf" \
      --report "$WORK/arming.json"
    ( cd "$WORK/src" && CARGO_TARGET_DIR="$WORK/target" cargo build --locked --release -p bloch-pos-node --bin bloch-pos )
    cp "$WORK/target/release/bloch-pos" "$WORK/bloch-pos-devnet4-kes"
    echo "built $WORK/bloch-pos-devnet4-kes (devnet4 ONLY; sha256 $(shasum -a 256 "$WORK/bloch-pos-devnet4-kes" | cut -c1-16))"
    ;;
  preflight) preflight ;;
  plan)
    : "${HOSTS:?file with '<index> <ssh host> <data dir>' lines}"
    echo "# Run on each devnet4 validator host AFTER installing the armed binary and restarting the node."
    echo "# Never copy validator.kes anywhere; it erases its own past on every period."
    while read -r idx host dir; do
      [ -z "${idx:-}" ] && continue; case "$idx" in \#*) continue;; esac
      echo "## v$idx on $host"
      echo "ssh $host 'bloch-pos kes keygen --dir $dir'"
      echo "ssh $host 'bloch-pos kes register --dir $dir --genesis $dir/genesis.bin --out /tmp/v$idx.kes-register.hex --validator $idx'"
      echo "scp $host:/tmp/v$idx.kes-register.hex $WORK/tx/"
    done < "$HOSTS"
    echo "# Then: $0 submit --apply   (registers; bind happens once >= 90% of stake is registered)"
    ;;
  submit)
    preflight
    shopt -s nullglob
    for f in "$WORK"/tx/v*.kes-register.hex; do
      if [ "$APPLY" = 1 ]; then
        echo "$(basename "$f"): $(rpc sendrawtransaction "[\"$(tr -d '\n' < "$f")\"]" | cut -c1-300)"
      else
        echo "would send $(basename "$f") ($(wc -c < "$f") hex chars); add --apply"
      fi
    done
    ;;
  monitor)
    preflight >/dev/null
    while :; do
      date -u +%FT%TZ
      rpc getkes | python3 -I -c '
import json,sys
r=json.load(sys.stdin).get("result") or {}
print(" epoch",r.get("epoch"),"period",r.get("period"),"enforced_from",r.get("enforced_from"),
      "registered_bps",r.get("registered_stake_bps"),"/",r.get("min_registered_stake_bps"))
for e in r.get("registered",[]):
    print("  v%-4s remaining=%-4s start=%-4s end=%-4s pending=%s" % (e["validator"],e["periods_remaining"],
          e["start_period"],e["end_period"],"yes" if e.get("pending_rotation") else "-"))'
      rpc getchaininfo | jget finalized
      sleep 60
    done
    ;;
  *) sed -n '3,38p' "$0"; exit 2;;
esac
