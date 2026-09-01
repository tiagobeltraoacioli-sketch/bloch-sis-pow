#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# blochv-keygen.sh — generate Bloch Genesis-4 validator key material with a
# layout, a permission set, and a set of refusals that a script can actually
# enforce.
#
# ── Two keys, and the difference is the whole point ─────────────────────────
#
#   VALIDATOR HOT KEY  (--role validator, the default)
#     <dir>/keys/validator.key — hybrid ML-DSA-65 ‖ Falcon-1024 secret plus
#     the RANDAO seed. HOT BY CONSTRUCTION: the node must hold it unlocked to
#     attest every epoch and to walk the RANDAO chain when it proposes. Assume
#     that a machine compromise is a compromise of this key.
#
#   WITHDRAWAL CREDENTIALS  (--role withdrawal)
#     A SEPARATE key, generated on a SEPARATE machine, kept cold. Only its
#     32-byte script hash (SHA3-256 of its public key) goes on chain, inside
#     the deposit, where it is IMMUTABLE FOREVER. Nothing about the validator
#     key can change it afterwards.
#
#   That immutability is the security property, and it only holds if the two
#   keys are genuinely different. If you set the withdrawal credentials to the
#   hot key's own script hash, then whoever steals the hot key gets the stake
#   as well as the duties, and the deposit's one-way door protects nobody.
#   This script REFUSES that (check W3 below), which is the one mistake here
#   that cannot be fixed after the fact — not by exiting, not by re-depositing.
#
# ── NO HARDWARE WALLET CAN HOLD EITHER KEY ──────────────────────────────────
#   The suite is hybrid ML-DSA-65 ‖ Falcon-1024 (secret ~6.3 KB, both lattice
#   secrets together). No shipping HSM, Ledger, Trezor, or cloud KMS signs
#   either algorithm. Custody is FILE custody. This layout, these permissions,
#   and the offline backup below are the entire custody story. Plan for that
#   rather than around it.
#
# ── RULE ZERO (docs/specs/BLOCH-GENESIS-KEYS.md) ────────────────────────────
#   No production key may be generated inside an AI-agent session, a shared
#   terminal, a CI job, or any machine whose transcript, shell history, or
#   memory is observable by more than the custodian. A key that has ever
#   existed in an observable context is compromised by definition, and this
#   key cannot be rotated — the registry binds the public key permanently.
#
# ── What this script refuses ────────────────────────────────────────────────
#   E1  running over SSH, under CI, or inside an AI-agent session
#   S1  a target on network/shared storage (nfs, cifs, smb, 9p, virtiofs,
#       fuse): storage two machines can mount is a doppelganger waiting to
#       happen, and one key on two machines is slashable equivocation
#   S2  a target on tmpfs/ramdisk, or under /tmp or /var/tmp: volatile, and
#       world-traversable by default. A validator key that evaporates on
#       reboot has activated stake that can never do duties again
#   S3  a group- or world-writable ancestor directory: anyone who can rename
#       a parent can substitute the whole keystore
#   S4  a umask that would let the key be created group- or world-readable
#   W1  --role withdrawal into the same directory as a validator key
#   W2  a withdrawal credential that is not exactly 32 bytes of hex, or is
#       all zeroes
#   W3  a withdrawal credential equal to the VALIDATOR key's own script hash
#   K1  overwriting an existing keystore, ever
#
# Key material is never printed, never echoed, never stored in a shell
# variable, and never passed as an argument. Only public halves are read back.
#
# ── Usage ───────────────────────────────────────────────────────────────────
#   Step 1, on the COLD machine:
#     blochv-keygen.sh --role withdrawal --dir /media/cold/bloch-withdrawal
#       -> prints the 32-byte credential to carry. Nothing else leaves.
#
#   Step 2, on the VALIDATOR machine (offline, at its console):
#     blochv-keygen.sh --role validator --dir ~/bloch-validator \
#                      --withdrawal-credentials <64-hex from step 1>
#
#   Options:
#     --role validator|withdrawal   which key (default validator)
#     --dir DIR                     target directory
#     --index N                     validator index recorded in the keystore
#                                   (default 0; see the runbook's G6 — a
#                                   deposit-era operator has no index until
#                                   activation assigns one, and nothing yet
#                                   rewrites it)
#     --bloch-pos PATH              the binary
#     --i-accept-observable-risk    override E1 only. Never for a real key.

set -euo pipefail

ROLE=validator
DIR=""
INDEX=0
BLOCH_POS="${BLOCH_POS:-bloch-pos}"
ACCEPT_OBSERVABLE=0
WITHDRAWAL_CREDS=""

while [ $# -gt 0 ]; do
  case "$1" in
    --role)        ROLE="$2"; shift 2 ;;
    --dir)         DIR="$2"; shift 2 ;;
    --index)       INDEX="$2"; shift 2 ;;
    --bloch-pos)   BLOCH_POS="$2"; shift 2 ;;
    --withdrawal-credentials) WITHDRAWAL_CREDS="$2"; shift 2 ;;
    --i-accept-observable-risk) ACCEPT_OBSERVABLE=1; shift ;;
    -h|--help)     sed -n '2,80p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "blochv-keygen: unknown argument $1 (see --help)" >&2; exit 2 ;;
  esac
done

fail() { echo "blochv-keygen: REFUSED — $*" >&2; exit 1; }

case "$ROLE" in
  validator)  : "${DIR:=${HOME}/bloch-validator}" ;;
  withdrawal) : "${DIR:=${HOME}/bloch-withdrawal}" ;;
  *) fail "--role must be 'validator' or 'withdrawal'" ;;
esac

# ── E1. Rule-zero environment refusals ──────────────────────────────────────
if [ "$ACCEPT_OBSERVABLE" -ne 1 ]; then
  if [ -n "${SSH_CONNECTION:-}${SSH_TTY:-}${SSH_CLIENT:-}" ]; then
    fail "running over SSH. This session is observable — terminal scrollback, \
the jump host, session recording, the client's own logs. Generate keys at the \
console of a machine you control. Override only if you fully understand what \
you are accepting: --i-accept-observable-risk"
  fi
  if [ -n "${CI:-}${GITHUB_ACTIONS:-}${GITLAB_CI:-}${BUILDKITE:-}${JENKINS_URL:-}" ]; then
    fail "running under CI. A key generated in CI is public by definition — it \
is in the runner image, the logs, and the artifact store. There is no \
legitimate override for a real key."
  fi
  if [ -n "${CLAUDECODE:-}${CLAUDE_CODE:-}${AGENT_SESSION:-}${ANTHROPIC_API_KEY:-}" ]; then
    fail "running inside an AI-agent session. Rule zero exists precisely for \
this case: the transcript is retained and leaves this machine. Run this \
yourself, at a console, with no agent attached."
  fi
fi

command -v "$BLOCH_POS" >/dev/null 2>&1 || fail "bloch-pos binary not found \
(looked for '$BLOCH_POS'). Build it per the runbook §3 and pass --bloch-pos, \
or set BLOCH_POS."

case "$INDEX" in (*[!0-9]*|'') fail "--index must be a non-negative integer" ;; esac

# ── S1-S4. The key must not land on storage that leaks or evaporates ────────
# Resolve the nearest existing ancestor: the target itself may not exist yet.
PROBE="$DIR"
while [ ! -d "$PROBE" ] && [ "$PROBE" != "/" ] && [ -n "$PROBE" ]; do
  PARENT="$(dirname "$PROBE")"
  [ "$PARENT" = "$PROBE" ] && break
  PROBE="$PARENT"
done
[ -d "$PROBE" ] || fail "cannot resolve any existing parent of $DIR"
ABS="$(cd "$PROBE" && pwd -P)"

FSTYPE=""
if command -v findmnt >/dev/null 2>&1; then
  FSTYPE="$(findmnt -no FSTYPE --target "$ABS" 2>/dev/null || true)"
elif command -v stat >/dev/null 2>&1 && stat -f '%T' "$ABS" >/dev/null 2>&1; then
  FSTYPE="$(stat -f '%T' "$ABS" 2>/dev/null || true)"     # BSD/macOS
fi
case "$FSTYPE" in
  nfs|nfs4|cifs|smbfs|smb3|9p|virtiofs|fuse*|glusterfs|ceph|afs|autofs)
    fail "S1: $ABS is on '$FSTYPE' — network or shared storage. Two machines \
that can mount the same key can both run it, and simultaneous signing is \
slashable equivocation the protocol reads as an attack. Put the keystore on \
local disk that exactly one machine can see." ;;
  tmpfs|ramfs|devtmpfs)
    fail "S2: $ABS is on '$FSTYPE' — a RAM filesystem. The key would not \
survive a reboot, and stake whose key is gone is stake that can never do \
duties and (today) can never be withdrawn either." ;;
esac
case "$ABS" in
  /tmp|/tmp/*|/var/tmp|/var/tmp/*|/dev/shm|/dev/shm/*|/private/tmp|/private/tmp/*|/private/var/tmp|/private/var/tmp/*)
    fail "S2: $ABS is under a temporary directory. It is world-traversable by \
default and it is cleaned without asking. This is not where a key that cannot \
be rotated lives." ;;
esac
[ -n "$FSTYPE" ] || echo "blochv-keygen: NOTE — could not determine the \
filesystem type under $ABS. Verify by hand that no second machine can mount it." >&2

# Ancestor permissions: anyone who can write a parent directory can rename it
# and substitute the whole keystore, permissions on the file notwithstanding.
mode_of() {
  if stat -f '%Lp' "$1" >/dev/null 2>&1; then stat -f '%Lp' "$1"
  else stat -c '%a' "$1" 2>/dev/null; fi
}
P="$ABS"
while : ; do
  M="$(mode_of "$P" || echo '')"
  if [ -n "$M" ]; then
    OTHER="${M#??}"; GROUP="${M#?}"; GROUP="${GROUP%?}"
    case "$OTHER" in *[2367]*) 
      # world-writable is only acceptable with the sticky bit (e.g. /tmp),
      # and we already refused /tmp outright above.
      if [ "${#M}" -lt 4 ]; then
        fail "S3: ancestor directory $P is world-writable (mode $M). Anyone \
who can write it can rename it and put their own keystore in its place."
      fi ;;
    esac
    case "$GROUP" in *[2367]*)
      echo "blochv-keygen: WARNING — ancestor $P is group-writable (mode $M). \
Every member of that group can substitute your keystore directory." >&2 ;;
    esac
  fi
  [ "$P" = "/" ] && break
  P="$(dirname "$P")"
done

# S4: a permissive umask would create the directory readable by others before
# we ever get to chmod it.
UM="$(umask)"
case "$UM" in
  0077|077|0177|177) : ;;
  *) echo "blochv-keygen: NOTE — umask is $UM; forcing 077 for this run." >&2 ;;
esac
umask 077

# ── W2. Validate the withdrawal credentials BEFORE generating anything ──────
# Checked here, not after, so a missing or malformed credential costs nothing
# and leaves no key material behind to clean up.
if [ "$ROLE" = validator ]; then
  if [ -z "$WITHDRAWAL_CREDS" ]; then
    fail "W2: --withdrawal-credentials is required for a validator key.

    The deposit commits 32 bytes saying where the stake returns, and they can
    never be changed afterwards — not by exiting, not by re-depositing. Deciding
    them at deposit time, from whatever is at hand, is how operators end up with
    stake payable to a key they no longer control.

    Generate them FIRST, on a separate cold machine:
        blochv-keygen.sh --role withdrawal --dir /media/cold/bloch-withdrawal
    then re-run this with the 64 hex characters it prints.

    (The keystore was NOT created; nothing has been written that you have to
    clean up. Re-run this command when you have the credentials.)"
  fi
  case "$WITHDRAWAL_CREDS" in
    *[!0-9a-fA-F]*) fail "W2: --withdrawal-credentials must be hexadecimal" ;;
  esac
  [ "${#WITHDRAWAL_CREDS}" -eq 64 ] || fail "W2: --withdrawal-credentials must be \
  exactly 64 hex characters (32 bytes); got ${#WITHDRAWAL_CREDS}"
  case "$WITHDRAWAL_CREDS" in
    0000000000000000000000000000000000000000000000000000000000000000)
      fail "W2: the withdrawal credentials are all zeroes. Nothing can ever spend \
  that, and the deposit is one-way." ;;
  esac
fi

# ── K1 / W1. Never overwrite; never mix the two roles in one directory ──────
[ -e "$DIR/keys/validator.key" ] && fail "K1: $DIR/keys/validator.key already \
exists. This script never overwrites a keystore — a validator key exists \
exactly once, and an overwrite is indistinguishable from losing it. Move the \
old directory aside yourself if you truly mean to."

if [ "$ROLE" = withdrawal ] && [ -e "$DIR/ROLE" ] && [ "$(cat "$DIR/ROLE" 2>/dev/null)" = validator ]; then
  fail "W1: $DIR already holds a VALIDATOR key. The withdrawal key must live \
on different storage, ideally a different machine, or a single compromise \
takes both the duties and the stake."
fi
if [ "$ROLE" = validator ] && [ -e "$DIR/ROLE" ] && [ "$(cat "$DIR/ROLE" 2>/dev/null)" = withdrawal ]; then
  fail "W1: $DIR already holds a WITHDRAWAL key. Keep them apart."
fi

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

# ── Layout ──────────────────────────────────────────────────────────────────
mkdir -p "$DIR/keys" "$DIR/public"
[ "$ROLE" = validator ] && mkdir -p "$DIR/data"
chmod 700 "$DIR" "$DIR/keys"
printf '%s\n' "$ROLE" > "$DIR/ROLE"

# ── Generate ────────────────────────────────────────────────────────────────
# The node's keygen writes <dir>/validator.key at mode 0600 and never prints
# secret bytes. That property is preserved here by never reading the file:
# no `cat`, no command substitution, no variable ever holds key material.
"$BLOCH_POS" keygen --dir "$DIR/keys" --index "$INDEX" >/dev/null \
  || fail "bloch-pos keygen failed"
[ -f "$DIR/keys/validator.key" ] || fail "keygen reported success but \
$DIR/keys/validator.key does not exist"
chmod 600 "$DIR/keys/validator.key"

# The public halves are the ONLY bytes that may leave this machine.
"$BLOCH_POS" keygen-public --dir "$DIR/keys" > "$DIR/public/pubkey.tsv" \
  || fail "bloch-pos keygen-public failed"
# public/ is meant to be carried off this machine; the umask above made it
# 0700. Relax the PUBLIC half only - keys/ stays 0700 and the keystore 0600.
chmod 755 "$DIR/public"; chmod 644 "$DIR/public/pubkey.tsv"

# script_hash = SHA3-256(pubkey) — the 32 bytes that identify where value can
# be paid. For the withdrawal role this IS the credential.
SCRIPT_HASH="$("$BLOCH_POS" spendkey --dir "$DIR/keys" 2>/dev/null \
  | awk '$1=="script_hash"{print $2}')"
[ -n "$SCRIPT_HASH" ] || fail "could not derive the script hash from the new keystore"

if [ "$ROLE" = withdrawal ]; then
  cat > "$DIR/public/WITHDRAWAL-CREDENTIALS" <<EOF
# Bloch Genesis-4 withdrawal credentials
# Generated $(date -u +%Y-%m-%dT%H:%M:%SZ)
#
# These 32 bytes go into the deposit and are IMMUTABLE FOREVER after it.
# They are PUBLIC: carry this file to the validator machine freely. The key
# that controls them must never follow it.
withdrawal_credentials	$SCRIPT_HASH
EOF
  chmod 644 "$DIR/public/WITHDRAWAL-CREDENTIALS"
  {
    echo "created_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "role: withdrawal"
    echo "host: $(hostname 2>/dev/null || echo unknown)"
    echo "bloch_pos_version: $("$BLOCH_POS" --version 2>/dev/null | head -1)"
    echo "withdrawal_credentials: $SCRIPT_HASH"
    echo "key_sha256: $(sha256 "$DIR/keys/validator.key")"
  } > "$DIR/public/MANIFEST"
  echo
  echo "blochv-keygen: WITHDRAWAL key written."
  echo
  echo "  keystore     $DIR/keys/validator.key   (0600 — this NEVER goes online)"
  echo "  credentials  $DIR/public/WITHDRAWAL-CREDENTIALS"
  echo
  echo "  withdrawal_credentials = $SCRIPT_HASH"
  echo
  echo "CARRY ONLY THE 64 HEX CHARACTERS ABOVE to the validator machine."
  echo "Then, there:"
  echo "  blochv-keygen.sh --role validator --dir ~/bloch-validator \\"
  echo "                   --withdrawal-credentials $SCRIPT_HASH"
  echo
  echo "Back this keystore up to two offline media in two places and verify"
  echo "each copy against key_sha256 in $DIR/public/MANIFEST. Losing it means"
  echo "losing the stake it is the only route back to."
  exit 0
fi

# ── Validator role: bind the withdrawal credentials, and check them ─────────
WC_LOWER="$(printf '%s' "$WITHDRAWAL_CREDS" | tr 'A-F' 'a-f')"
SH_LOWER="$(printf '%s' "$SCRIPT_HASH" | tr 'A-F' 'a-f')"
if [ "$WC_LOWER" = "$SH_LOWER" ]; then
  fail "W3: the withdrawal credentials you passed are THIS VALIDATOR KEY's own
  script hash.

  That makes the hot key and the withdrawal path the same secret. The hot key
  is unlocked on a networked machine every epoch; whoever takes it would then
  take the stake as well, and the deposit's immutability — the property that
  is supposed to protect you — would be protecting them instead.

  The withdrawal credentials must come from a DIFFERENT key, generated on a
  DIFFERENT machine, that never goes online:
      blochv-keygen.sh --role withdrawal --dir /media/cold/bloch-withdrawal

  A keystore WAS created at $DIR/keys/validator.key before this could be
  checked (the script hash is only knowable after generation). It has NOT been
  deleted: silently destroying key material is its own way to lose a stake, and
  an unlinked file is not securely erased anyway. Move the whole directory
  aside and start again with real cold credentials:
      mv $DIR $DIR.rejected-\$(date -u +%Y%m%dT%H%M%SZ)

  Nothing was submitted anywhere. This key has never signed and never will."
fi

cat > "$DIR/public/DEPOSIT-FIELDS" <<EOF
# Bloch Genesis-4 deposit fields — PUBLIC, safe to copy off this machine.
#
# withdrawal_credentials is immutable once the deposit is included. Check it
# character by character against the WITHDRAWAL-CREDENTIALS file produced on
# the cold machine before you submit anything.
validator_script_hash	$SCRIPT_HASH
withdrawal_credentials	$WC_LOWER
index_recorded_in_keystore	$INDEX
EOF
chmod 644 "$DIR/public/DEPOSIT-FIELDS"

{
  echo "created_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "role: validator"
  echo "host: $(hostname 2>/dev/null || echo unknown)"
  echo "bloch_pos_version: $("$BLOCH_POS" --version 2>/dev/null | head -1)"
  echo "index_recorded_in_keystore: $INDEX"
  echo "validator_script_hash: $SCRIPT_HASH"
  echo "withdrawal_credentials: $WC_LOWER"
  echo "validator_key_sha256: $(sha256 "$DIR/keys/validator.key")"
  echo "pubkey_tsv_sha256: $(sha256 "$DIR/public/pubkey.tsv")"
} > "$DIR/public/MANIFEST"
chmod 644 "$DIR/public/MANIFEST"

echo
echo "blochv-keygen: VALIDATOR keystore written."
echo
echo "  keystore   $DIR/keys/validator.key   (0600 — offline backup only)"
echo "  public     $DIR/public/              (safe to publish)"
echo "  manifest   $DIR/public/MANIFEST      (verify any restored backup against validator_key_sha256)"
echo
echo "  validator script hash   $SCRIPT_HASH"
echo "  withdrawal credentials  $WC_LOWER   <- different key, as it must be"
echo
echo "DO NOW, in this order:"
echo "  1. Back up $DIR/keys/validator.key to two offline media in two places."
echo "     Verify each copy: its sha256 must equal validator_key_sha256 in the"
echo "     MANIFEST. There is no hardware wallet and no recovery phrase; this"
echo "     backup is the entire custody plan."
echo "  2. Re-read the withdrawal credentials above against the cold machine's"
echo "     WITHDRAWAL-CREDENTIALS file. After the deposit they are permanent."
echo "  3. Move the keystore to the node's --data-dir only when you are ready"
echo "     to start, and run blochv-guard.sh --data-dir <dir> FIRST. The first"
echo "     start of a brand-new key needs --accept-new-signing-history exactly"
echo "     once; the guard checks the chain before it lets you believe that."
echo "  4. Never run two nodes with this keystore. Ever. Simultaneous signing"
echo "     is slashable equivocation, and the protocol cannot tell an HA"
echo "     mistake from an attack."
