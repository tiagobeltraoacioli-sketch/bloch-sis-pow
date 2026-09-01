#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# blochv-guard.sh — the double-signing gate. Run this BEFORE every `bloch-pos
# run` that carries a validator key, and on a timer afterwards.
#
# ── Why this is the only tool here that can cost you money ──────────────────
#
# Every other failure in this toolkit costs you downtime. This one costs you
# stake, permanently, with no appeal:
#
#   * A slashed validator is removed from every roster immediately and can
#     NEVER rejoin with that key.
#   * The penalty is multiplied 3x (CORRELATION_MULTIPLIER) by the total
#     stake slashed in the surrounding 4,096-epoch (~45 day) window. A single
#     clumsy operator loses little. Anything that looks coordinated — such as
#     a popular start script that gets the safe default wrong — is priced as
#     an attack, for everyone caught in the window. That is why this script
#     refuses rather than warns.
#   * Self-reporting does not help: the whistleblower's 1/32 means reporting
#     your own offence nets you -31/32.
#
# The protocol cannot distinguish a high-availability mistake from an attack.
# There is no failover design that is safe here. One key, one machine, ever.
#
# ── The two mechanisms this script wires you to ─────────────────────────────
#
#   signing_history.bin   In the data dir, beside validator.key. Records the
#                         highest slot ever proposed and the highest
#                         source/target epochs ever attested, fsynced BEFORE
#                         the signature is released (never after), so a crash
#                         loses a duty instead of double-signing. The node
#                         refuses to sign at or below those watermarks, and
#                         refuses to START at all when the file is missing.
#
#                         `--accept-new-signing-history` creates an empty one.
#                         It is a claim, made by you, that this key has never
#                         signed on this network ANYWHERE. An empty history on
#                         a used key is the single most direct route to being
#                         slashed, and this script refuses to bless that claim
#                         when the chain contradicts it.
#
#   doppelganger watch    On each start the node stays SILENT for
#                         --doppelganger-epochs epochs (default 2, ~32 min)
#                         listening for its own validator index signing
#                         elsewhere. If it hears itself, the process exits
#                         rather than completing the equivocation. It is the
#                         last line of defence when step 1 of a migration
#                         silently failed.
#
# ── What this script REFUSES (exit 2) ───────────────────────────────────────
#   1. a keystore with no signing history, when the chain says this validator
#      is already active — the override would be a false claim
#   2. a signing history that binds a DIFFERENT public key than the keystore
#      beside it (the wrong history file carried during a migration)
#   3. a keystore or data dir that is group/world readable, or on shared
#      storage that a second machine could mount
#   4. `--doppelganger-epochs 0` without the explicit coordinated-launch
#      acknowledgement
#   5. a second bloch-pos process already holding this data dir
#
# ── Usage ───────────────────────────────────────────────────────────────────
#   blochv-guard.sh --data-dir DIR [options]
#
#     --data-dir DIR         the node's --data-dir (holds validator.key)
#     --rpc URL              a node to ask whether this validator is already
#                            active on chain (default http://127.0.0.1:16310).
#                            Use ANY synced node, including someone else's,
#                            for this one question — it is a public read.
#     --index N              validator index to check on chain (default: the
#                            index recorded in the keystore)
#     --doppelganger-epochs N
#                            the value you intend to pass to `bloch-pos run`
#                            (default 2). 0 is refused unless the next flag
#                            is also passed.
#     --coordinated-launch-i-am-starting-the-whole-network-at-once
#                            acknowledges that --doppelganger-epochs 0 is a
#                            stated launch-plan decision for a simultaneous
#                            multi-validator start, not a way to skip the
#                            32-minute wait on a solo restart.
#     --migration            you are bringing this key from another machine.
#                            Adds the migration checklist and hard-refuses the
#                            new-history override outright.
#
# Read-only. It never writes to the data dir and never reads secret bytes:
# it parses only the public-key field of each file.

set -u

DATA_DIR=""
RPC="http://127.0.0.1:16310"
INDEX=""
DG_EPOCHS=2
COORDINATED=0
MIGRATION=0

while [ $# -gt 0 ]; do
  case "$1" in
    --data-dir)            DATA_DIR="$2"; shift 2 ;;
    --rpc)                 RPC="$2"; shift 2 ;;
    --index)               INDEX="$2"; shift 2 ;;
    --doppelganger-epochs) DG_EPOCHS="$2"; shift 2 ;;
    --coordinated-launch-i-am-starting-the-whole-network-at-once)
                           COORDINATED=1; shift ;;
    --migration)           MIGRATION=1; shift ;;
    -h|--help)             sed -n '2,88p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "blochv-guard: unknown argument $1 (see --help)" >&2; exit 2 ;;
  esac
done

[ -n "$DATA_DIR" ] || { echo "blochv-guard: --data-dir is required" >&2; exit 2; }

STATUS=0
raise() { [ "$1" -gt "$STATUS" ] && STATUS="$1"; return 0; }
ok()   { printf 'OK      %s\n' "$*"; }
w()    { printf 'WARN    %s\n' "$*"; raise 1; }
refuse(){ printf 'REFUSE  %s\n' "$*"; raise 2; }

KEYSTORE="$DATA_DIR/validator.key"
HISTORY="$DATA_DIR/signing_history.bin"

# ── 0. Is there even a key here? ────────────────────────────────────────────
if [ ! -f "$KEYSTORE" ]; then
  ok "no validator.key in $DATA_DIR — this is an observer. An observer signs \
nothing and cannot be slashed. Nothing to guard; run this again when you move \
the keystore in."
  echo "guard: OK (observer)"
  exit 0
fi
ok "keystore present: $KEYSTORE"

# ── 1. Permissions and storage ──────────────────────────────────────────────
mode_of() { # portable stat
  if stat -f '%Lp' "$1" >/dev/null 2>&1; then stat -f '%Lp' "$1"
  else stat -c '%a' "$1" 2>/dev/null; fi
}
KMODE="$(mode_of "$KEYSTORE")"
DMODE="$(mode_of "$DATA_DIR")"
case "$KMODE" in
  600|400) ok "keystore mode $KMODE" ;;
  *) refuse "keystore mode is $KMODE, not 0600. Anything that can read \
validator.key can sign with your stake, forever, and the key cannot be \
rotated — the registry binds this public key permanently. chmod 600 it, and \
assume it is compromised if it was ever readable by another account." ;;
esac
case "$DMODE" in
  700|750|500) ok "data dir mode $DMODE" ;;
  *) w "data dir mode is $DMODE. Prefer 0700: the data dir holds the keystore \
and the signing history, and the history is as safety-critical as the key." ;;
esac

# Shared storage: a key on a filesystem two machines can mount is a
# doppelganger waiting to happen. NFS/SMB/virtiofs/9p/fuse are the ways a
# data dir ends up mounted twice.
FSTYPE=""
if command -v findmnt >/dev/null 2>&1; then
  FSTYPE="$(findmnt -no FSTYPE --target "$DATA_DIR" 2>/dev/null)"
elif [ "$(uname -s)" = "Darwin" ]; then
  FSTYPE="$(df -P "$DATA_DIR" 2>/dev/null | awk 'NR==2{print $1}' | grep -qE '^//|:' && echo network || echo local)"
fi
case "$FSTYPE" in
  nfs|nfs4|cifs|smbfs|smb3|9p|virtiofs|fuse*|glusterfs|ceph|network)
    refuse "the data dir is on '$FSTYPE' — shared/network storage. Two machines \
that can mount the same key can both run it, and simultaneous signing is \
slashable equivocation that the protocol reads as an attack. Put the keystore \
on local disk that exactly one machine can see." ;;
  "") w "could not determine the filesystem type under $DATA_DIR — verify by \
hand that no second machine can mount it" ;;
  *)  ok "data dir filesystem: $FSTYPE (not shared storage)" ;;
esac

# ── 2. Signing history: present? bound to THIS key? ─────────────────────────
# Parses only the public fields. Layouts (both little-endian):
#   validator.key       "BPOSKEY1" | index u32 | u32 len + pubkey | u32 len + secret | 32B randao seed
#   signing_history.bin "BSIGHIS1" | flags u8 | 32B network digest | u32 len + pubkey | 8B slot | 8B src | 8B tgt
# The secret is never reached: parsing stops after the pubkey field.
read_pub() { # read_pub <file> <magic> <offset-of-len-prefix>
  python3 - "$1" "$2" "$3" <<'PY'
import sys, hashlib
path, magic, off = sys.argv[1], sys.argv[2].encode(), int(sys.argv[3])
b = open(path, "rb").read()
if b[:8] != magic:
    print("BADMAGIC"); raise SystemExit
n = int.from_bytes(b[off:off+4], "little")
if n == 0 or off + 4 + n > len(b):
    print("TRUNCATED"); raise SystemExit
print(hashlib.sha256(b[off+4:off+4+n]).hexdigest())
PY
}
read_hist_meta() {
  python3 - "$1" <<'PY'
import sys
b = open(sys.argv[1], "rb").read()
flags = b[8]
n = int.from_bytes(b[41:45], "little")
p = 45 + n
slot = int.from_bytes(b[p:p+8], "little")
src  = int.from_bytes(b[p+8:p+16], "little")
tgt  = int.from_bytes(b[p+16:p+24], "little")
print("%d %d %d %d %d %d %d" % (
    flags & 1, (flags >> 1) & 1, (flags >> 2) & 1, slot, src, tgt, len(b)))
PY
}

KPUB="$(read_pub "$KEYSTORE" BPOSKEY1 12 2>/dev/null)"
case "$KPUB" in
  BADMAGIC)  refuse "$KEYSTORE is not a bloch-pos keystore (bad magic). Do not \
start a node with it." ;;
  TRUNCATED|"") refuse "$KEYSTORE is truncated or unreadable." ;;
  *) ok "keystore public key fingerprint sha256:${KPUB:0:16}.." ;;
esac

HAVE_HISTORY=0
if [ -f "$HISTORY" ]; then
  HAVE_HISTORY=1
  HPUB="$(read_pub "$HISTORY" BSIGHIS1 41 2>/dev/null)"
  HMODE="$(mode_of "$HISTORY")"
  case "$HPUB" in
    BADMAGIC)  refuse "$HISTORY is not a signing history (bad magic)." ;;
    TRUNCATED|"") refuse "$HISTORY is truncated. A truncated history is worse \
than none: it may read as lower watermarks than the key has actually signed." ;;
    "$KPUB")   ok "signing history binds the SAME public key as the keystore" ;;
    *) refuse "MISMATCH: $HISTORY records the history of a DIFFERENT validator \
(history sha256:${HPUB:0:16}.. vs keystore sha256:${KPUB:0:16}..). This is the \
classic migration error — the right key carried with the wrong history file. \
Starting now would sign below this key's real watermarks. Fetch the correct \
export from the machine this key last ran on." ;;
  esac
  case "$HMODE" in
    600|400) ok "signing history mode $HMODE" ;;
    *) w "signing history mode is $HMODE — anything that can rewrite it can \
lower your watermarks and walk you into a double-sign. chmod 600." ;;
  esac
  if [ "$STATUS" -lt 2 ]; then
    read -r F_NET F_PROP F_ATT H_SLOT H_SRC H_TGT H_LEN <<< "$(read_hist_meta "$HISTORY")"
    [ "${F_NET:-0}" = "1" ] && ok "history is network-bound (it cannot be \
replayed onto a different network)" \
      || w "history is NOT network-bound — it carries no network digest, so \
nothing stops it being used against a different chain"
    if [ "${F_PROP:-0}" = "1" ] || [ "${F_ATT:-0}" = "1" ]; then
      ok "history has watermarks: highest proposed slot ${H_SLOT}, attestation \
source ${H_SRC} / target ${H_TGT} — this key HAS signed before"
      USED_KEY=1
    else
      ok "history exists but carries no watermarks yet (key has not signed)"
      USED_KEY=0
    fi
  fi
else
  w "no $HISTORY. The node will REFUSE TO START without it — that refusal is \
the feature. Read the next check before reaching for --accept-new-signing-history."
  USED_KEY=0
fi

# ── 3. The --accept-new-signing-history decision, checked against the chain ──
# The override is a claim that this key has never signed anywhere. If the
# registry says this validator is already active, the claim is false.
KEY_INDEX="$(python3 - "$KEYSTORE" <<'PY'
import sys
b = open(sys.argv[1], "rb").read()
print(int.from_bytes(b[8:12], "little"))
PY
)"
[ -n "$INDEX" ] || INDEX="$KEY_INDEX"
ok "keystore records validator index $KEY_INDEX; checking index $INDEX on chain"

CHAIN_STATE=""
CHAIN_JSON="$(curl -sS --max-time 10 -X POST "$RPC" \
  -H 'content-type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getvalidator\",\"params\":{\"index\":$INDEX}}" 2>/dev/null)"
if [ -n "$CHAIN_JSON" ]; then
  CHAIN_STATE="$(python3 -c '
import json,sys
try:
    r=json.loads(sys.argv[1])["result"]; print("%s %s %s" % (r.get("state"), r.get("slashed"), r.get("activation_epoch")))
except Exception: print("")' "$CHAIN_JSON")"
fi

if [ -n "$CHAIN_STATE" ]; then
  read -r C_STATE C_SLASHED C_ACT <<< "$CHAIN_STATE"
  ok "chain says validator $INDEX: state=$C_STATE slashed=$C_SLASHED activation_epoch=$C_ACT"
  case "$C_SLASHED" in
    True|true) refuse "validator $INDEX is ALREADY SLASHED. Do not start this \
node. It can never rejoin with this key, and every further signature only adds \
correlation cost to the 4,096-epoch window — for you and for everyone else \
slashed inside it." ;;
  esac
  if [ "$HAVE_HISTORY" -eq 0 ]; then
    case "$C_STATE" in
      active|exiting|exited)
        refuse "validator $INDEX is '$C_STATE' on chain and there is NO signing \
history on this machine. --accept-new-signing-history asserts that this key has \
never signed anywhere; the registry says otherwise. Do NOT pass it. Recover the \
history from the machine this key last ran on:
          old machine:  systemctl disable --now <unit>
                        bloch-pos protection-export --data-dir <old> --out history.txt
          this machine: bloch-pos protection-import --data-dir $DATA_DIR --from history.txt
        If the old machine is unrecoverable, the only safe option is to wait out
        an interval you can prove it was powered off, and even then you are
        betting your whole stake on that proof." ;;
      queued|pending)
        w "validator $INDEX is '$C_STATE' (not yet doing duties) and there is no \
signing history. If this key has genuinely never signed on this network, on any \
machine, --accept-new-signing-history is correct exactly once, now." ;;
      "")
        w "validator $INDEX is not in the registry yet. If this key has never \
signed anywhere, --accept-new-signing-history is correct exactly once, now." ;;
    esac
  fi
else
  w "could not reach $RPC to ask whether validator $INDEX has already signed. \
This is the check that decides whether --accept-new-signing-history is safe. \
Point --rpc at any synced node (it is a public read) and re-run before you use \
that flag."
fi

if [ "$MIGRATION" -eq 1 ] && [ "$HAVE_HISTORY" -eq 0 ]; then
  refuse "--migration was passed and there is no signing history in $DATA_DIR. \
A migration ALWAYS carries the history with the key. Run protection-export on \
the source machine (after disabling its unit, not just stopping it — a reboot \
must not resurrect it) and protection-import here, BEFORE the first run."
fi

# ── 4. Doppelganger default ─────────────────────────────────────────────────
case "$DG_EPOCHS" in (*[!0-9]*|'') refuse "--doppelganger-epochs must be an integer" ;; esac
if [ "$DG_EPOCHS" -eq 0 ]; then
  if [ "$COORDINATED" -eq 1 ]; then
    w "doppelganger watch DISABLED (--doppelganger-epochs 0), acknowledged as a \
coordinated launch. This is only correct when every validator starts at once and \
none of them is already running elsewhere. If even one is, it will double-sign \
and nothing will stop it."
  else
    refuse "--doppelganger-epochs 0 disables the last line of defence against \
running your key on two machines. It costs 2 epochs (~32 min) of duties per \
restart and it is the only thing that catches a migration whose first step \
silently failed. The one legitimate use is a coordinated launch where the whole \
network starts at once (a node booting even a few slots after genesis arms the \
watch and goes silent while everyone waits). If that is what you are doing, say \
so: --coordinated-launch-i-am-starting-the-whole-network-at-once"
  fi
elif [ "$DG_EPOCHS" -lt 2 ]; then
  w "doppelganger watch shortened to $DG_EPOCHS epoch(s). The default 2 exists \
because one epoch can miss a doppelganger that happens not to be drawn for a \
duty in that window. Keep 2 unless you have a reason you can state."
else
  ok "doppelganger watch: $DG_EPOCHS epochs of silence on start (default; ~$((DG_EPOCHS*16)) min of missed duties, which is the premium on the insurance)"
fi

# ── 5. Is something already running this data dir? ──────────────────────────
RUNNING="$(ps -Ao pid=,args= 2>/dev/null | grep -F -- "--data-dir $DATA_DIR" | grep -v grep | grep -v blochv-guard || true)"
if [ -n "$RUNNING" ]; then
  refuse "another process is already using $DATA_DIR:
$RUNNING
  Two nodes on one keystore is the definition of equivocation. Stop and DISABLE \
the existing unit before starting anything else; a plain 'stop' that a reboot \
undoes has slashed validators before."
else
  ok "no other local process is holding $DATA_DIR"
fi
echo
echo "NOTE: this check can only see THIS machine. It cannot prove your key is"
echo "not also running somewhere else. Nothing can, except your own discipline"
echo "about disabling the old unit — and the doppelganger watch, which is why"
echo "check 4 refuses to let you turn it off casually."
echo

case "$STATUS" in
  0) echo "guard: OK — safe to start"; ;;
  1) echo "guard: WARN — read every warning above before starting" ;;
  2) echo "guard: REFUSED — do not start this node" ;;
esac
exit "$STATUS"
