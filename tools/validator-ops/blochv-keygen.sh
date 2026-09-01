#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# blochv-keygen.sh — generate a Bloch Genesis-4 validator keystore with a safe
# default layout, enforcing BLOCH-GENESIS-KEYS.md rule zero as far as a script
# can.
#
# RULE ZERO (docs/specs/BLOCH-GENESIS-KEYS.md): no production key may be
# generated inside an AI-agent session, a shared terminal, a CI job, or any
# machine whose transcript, shell history, or memory is observable by more
# than the custodian. This script REFUSES to run under SSH or CI unless
# explicitly overridden, because a key that has ever existed in an observable
# context is compromised by definition.
#
# NO HARDWARE WALLET CAN HOLD THIS KEY. The validator key is hybrid
# ML-DSA-65 ‖ Falcon-1024 (secret ≈ 6.3 KB, both lattice secrets together).
# No shipping HSM, Ledger, Trezor, or cloud KMS signs either algorithm. The
# custody plan is therefore FILE custody: this script's layout, permissions,
# and the backup it tells you to make are the whole story. Plan accordingly.
#
# What it produces, under --dir (default ~/bloch-validator):
#
#   <dir>/                       mode 0700
#     keys/                      mode 0700
#       validator.key            mode 0600  — BPOSKEY1 keystore: hybrid secret
#                                            key + RANDAO seed. THE key. Hot by
#                                            construction (the node walks the
#                                            RANDAO chain to propose).
#     public/                    safe to copy off this machine
#       validator.pub.tsv        the public TSV row (`bloch-pos keygen-public`)
#       MANIFEST                 sha256 of validator.key + metadata, so a
#                                restored backup can be verified byte-for-byte
#     data/                      empty; becomes the node's --data-dir
#
# Only public/ may ever leave the custodian's control. keys/ leaves only as an
# offline backup (two media, two places — losing validator.key before your
# first proposal means the stake activates and can never do duties; losing it
# after exit still lets the withdrawal complete, because withdrawal needs no
# validator signature, but you can no longer exit if you haven't already).
#
# Usage:
#   blochv-keygen.sh [--dir DIR] [--index N] [--bloch-pos PATH]
#                    [--i-accept-observable-risk]
#
# --index is the validator index recorded inside the keystore. Genesis-cohort
# operators know theirs; a DEPOSIT-ERA operator does NOT have an index until
# activation assigns one. Generate with the default (0), and see the runbook
# (docs/VALIDATOR-RUNBOOK.md §8) for the index-binding gap and how it will be
# resolved — the keystore's key material is index-independent, only the 4-byte
# index field would need rewriting.

set -euo pipefail

DIR="${HOME}/bloch-validator"
INDEX=0
BLOCH_POS="${BLOCH_POS:-bloch-pos}"
ACCEPT_OBSERVABLE=0

while [ $# -gt 0 ]; do
  case "$1" in
    --dir)        DIR="$2"; shift 2 ;;
    --index)      INDEX="$2"; shift 2 ;;
    --bloch-pos)  BLOCH_POS="$2"; shift 2 ;;
    --i-accept-observable-risk) ACCEPT_OBSERVABLE=1; shift ;;
    -h|--help)    sed -n '2,55p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "blochv-keygen: unknown argument $1 (see --help)" >&2; exit 2 ;;
  esac
done

fail() { echo "blochv-keygen: FAIL — $*" >&2; exit 1; }

# ── Rule-zero environment refusals ──────────────────────────────────────────
if [ "$ACCEPT_OBSERVABLE" -ne 1 ]; then
  if [ -n "${SSH_CONNECTION:-}${SSH_TTY:-}${SSH_CLIENT:-}" ]; then
    fail "running over SSH. The transcript of this session is observable \
(terminal, jump host, session recording). Generate keys at the console of an \
air-gapped machine. Override only if you fully understand the consequence: \
--i-accept-observable-risk"
  fi
  if [ -n "${CI:-}${GITHUB_ACTIONS:-}${GITLAB_CI:-}" ]; then
    fail "running under CI. A key generated in CI is public by definition. \
There is no legitimate reason to override this for a mainnet key."
  fi
  if [ -n "${CLAUDECODE:-}${CLAUDE_CODE:-}${AGENT_SESSION:-}" ]; then
    fail "running inside an AI-agent session. Rule zero exists precisely for \
this case: the transcript is retained. Run this yourself, at a console."
  fi
fi

command -v "$BLOCH_POS" >/dev/null 2>&1 || fail "bloch-pos binary not found \
(looked for '$BLOCH_POS'). Build it per docs/VALIDATOR-RUNBOOK.md §3 and pass \
--bloch-pos or set BLOCH_POS."

case "$INDEX" in (*[!0-9]*|'') fail "--index must be a non-negative integer";; esac

[ -e "$DIR/keys/validator.key" ] && fail "$DIR/keys/validator.key already \
exists. This script never overwrites a keystore — a validator key exists \
exactly once. Move the old directory aside yourself if you truly mean to."

# ── Layout ──────────────────────────────────────────────────────────────────
umask 077
mkdir -p "$DIR/keys" "$DIR/public" "$DIR/data"
chmod 700 "$DIR" "$DIR/keys"

# ── Generate ────────────────────────────────────────────────────────────────
# The node's keygen writes <dir>/validator.key mode 0600 and never prints
# secret bytes; we keep that property by never reading the file into a
# variable here.
"$BLOCH_POS" keygen --dir "$DIR/keys" --index "$INDEX" \
  || fail "bloch-pos keygen failed"
[ -f "$DIR/keys/validator.key" ] || fail "keygen reported success but \
$DIR/keys/validator.key does not exist"
chmod 600 "$DIR/keys/validator.key"

# ── Public halves — the only bytes that leave this machine ──────────────────
"$BLOCH_POS" keygen-public --dir "$DIR/keys" > "$DIR/public/validator.pub.tsv" \
  || fail "bloch-pos keygen-public failed"

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1;
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

{
  echo "created_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "host: $(hostname 2>/dev/null || echo unknown)"
  echo "bloch_pos_version: $("$BLOCH_POS" --version 2>/dev/null | head -1)"
  echo "index_recorded_in_keystore: $INDEX"
  echo "validator_key_sha256: $(sha256 "$DIR/keys/validator.key")"
  echo "validator_pub_tsv_sha256: $(sha256 "$DIR/public/validator.pub.tsv")"
} > "$DIR/public/MANIFEST"

echo
echo "blochv-keygen: keystore written."
echo
echo "  keystore   $DIR/keys/validator.key   (0600 — never copy off-machine except as offline backup)"
echo "  public     $DIR/public/              (safe to publish; carry THIS to the online machine)"
echo "  manifest   $DIR/public/MANIFEST      (verify any restored backup against validator_key_sha256)"
echo
echo "DO NOW, before anything else:"
echo "  1. Back up $DIR/keys/validator.key to two offline media, two places."
echo "     Verify each copy: sha256 must equal the MANIFEST value."
echo "  2. Your WITHDRAWAL key is a SEPARATE key this script does not make —"
echo "     it is a cold spending key whose 32-byte address goes into the"
echo "     deposit and can never be changed afterwards. Custody it colder"
echo "     than this one. (No hardware wallet can hold it either.)"
echo "  3. Never run two nodes with this keystore. Ever. Simultaneous"
echo "     signing is slashable equivocation and the protocol cannot tell"
echo "     an HA mistake from an attack."
