#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Genesis-4 validator key ceremony — run this on an AIR-GAPPED machine.
#
# Generates the 64 genesis validator keystores and emits ONLY their public
# halves, as a cohort TSV to carry back out. Secret material never leaves the
# machine, is never printed, and is never written anywhere but a 0600 file.
#
# Why a script instead of a runbook someone follows by hand: a ceremony
# performed differently twice has been performed wrong at least once. This is
# the same commands in the same order every time, and it refuses to run in the
# conditions that make a ceremony worthless.
#
#   usage:  ./genesis4-key-ceremony.sh <bloch-pos-binary> <output-dir> [count]
#
# What to carry OUT (safe, public):   cohort.tsv, DIGESTS.txt
# What NEVER leaves (secret):         */validator.key
#
# The keystores are SEALED (Argon2id + XChaCha20-Poly1305) under a passphrase
# this script asks for at the tty — see the block below. The passphrase is a
# separate carry-out from the keystores and from this machine: without it the
# 64 files are unopenable, including by you.
set -euo pipefail

BIN="${1:?usage: $0 <bloch-pos-binary> <output-dir> [count]}"
OUT="${2:?usage: $0 <bloch-pos-binary> <output-dir> [count]}"
COUNT="${3:-64}"

[ -x "$BIN" ] || { echo "FATAL: $BIN is not executable"; exit 1; }

# ── Refuse to run networked ────────────────────────────────────────────────
#
# Not theatre. A ceremony on a machine that can reach the internet has the one
# property it was supposed to eliminate. Checked rather than trusted, because
# "I disconnected it" is exactly the kind of thing people are sure about and
# wrong about.
if ping -c1 -W2 1.1.1.1 >/dev/null 2>&1 || ping -c1 -t2 1.1.1.1 >/dev/null 2>&1; then
    echo "FATAL: this machine has network access."
    echo "       The whole point of the ceremony is that it does not."
    echo "       Disconnect it — physically, not by disabling an interface — and re-run."
    exit 1
fi

# ── Refuse to overwrite ────────────────────────────────────────────────────
#
# Re-running over an existing set would silently replace keys that may already
# be committed to in a published manifest.
if [ -e "$OUT" ]; then
    echo "FATAL: $OUT already exists. Choose a new directory."
    echo "       Overwriting a ceremony's output destroys keys that a manifest"
    echo "       may already commit to, and there is no way to tell from here."
    exit 1
fi

mkdir -p "$OUT"
chmod 700 "$OUT"
umask 077

echo "Bloch Genesis-4 key ceremony"
echo "  binary : $BIN"
echo "  output : $OUT"
echo "  count  : $COUNT"
echo "  host   : $(hostname) — confirm this is the air-gapped machine"
echo

# ── The keystore passphrase ────────────────────────────────────────────────
#
# Every validator.key this ceremony writes is SEALED (Argon2id +
# XChaCha20-Poly1305) under this one passphrase — audit I-H1. Before that, the
# ceremony's output was 64 files with the secret key in the clear behind
# nothing but mode 0600, which is not a confidentiality boundary the moment a
# file is backed up, imaged, or copied to a host.
#
# Read from the tty and never echoed, never passed as an argument (argv is
# world-readable in /proc), never written to disk by this script. Confirmed
# twice, because a typo here does not fail now — it fails when 64 keystores
# cannot be opened and there is nothing left to open them with.
#
# CARRY THIS PASSPHRASE OUT SEPARATELY FROM THE KEYSTORES, on paper, split if
# your policy says so. It is not in cohort.tsv and it is not in DIGESTS.txt.
# Lose it and the 64 genesis validators are gone with it.
read -r -s -p "  keystore passphrase: " KEYPASS; echo
read -r -s -p "  confirm            : " KEYPASS2; echo
[ -n "$KEYPASS" ] || { echo "FATAL: an empty passphrase is not a passphrase."; exit 1; }
[ "$KEYPASS" = "$KEYPASS2" ] || { echo "FATAL: the two passphrases differ. Nothing was written."; exit 1; }
unset KEYPASS2
export BLOCH_KEYSTORE_PASSPHRASE="$KEYPASS"
unset KEYPASS
echo

for i in $(seq 0 $((COUNT - 1))); do
    n=$(printf "%02d" "$i")
    "$BIN" keygen --dir "$OUT/v$n" --index "$i" >/dev/null
    printf "\r  generated %d/%d" "$((i + 1))" "$COUNT"
done
echo
echo

# ── Verify before trusting ─────────────────────────────────────────────────
missing=0
for i in $(seq 0 $((COUNT - 1))); do
    n=$(printf "%02d" "$i")
    f="$OUT/v$n/validator.key"
    [ -f "$f" ] || { echo "  MISSING: $f"; missing=$((missing + 1)); continue; }
    perms=$(stat -c '%a' "$f" 2>/dev/null || stat -f '%Lp' "$f")
    [ "$perms" = "600" ] || { echo "  BAD PERMS on $f: $perms"; missing=$((missing + 1)); }
    # Checked, not assumed: BPOSKEY2 is the sealed format, BPOSKEY1 is the
    # plaintext one. A ceremony that silently produced 64 plaintext keys
    # because someone had BLOCH_KEYSTORE_ALLOW_PLAINTEXT set in their profile
    # would look identical to a correct one right up to the breach.
    magic=$(head -c 8 "$f")
    [ "$magic" = "BPOSKEY2" ] || {
        echo "  NOT SEALED: $f is '$magic', expected BPOSKEY2"
        missing=$((missing + 1))
    }
done
[ "$missing" -eq 0 ] || { echo "FATAL: $missing keystore(s) bad. Nothing is trustworthy here; start over."; exit 1; }
echo "  all $COUNT keystores present, sealed (BPOSKEY2), mode 0600"

# ── The public halves, and only those ──────────────────────────────────────
#
# Fill stake_sat / withdrawal_credentials / commission_bps before assembling
# the manifest. They are left explicit rather than defaulted so that nobody
# launches a network having never decided them.
{
    echo -e "index\tpubkey_hex\trandao_commitment_hex\tstake_sat\twithdrawal_credentials_hex\tcommission_bps"
    for i in $(seq 0 $((COUNT - 1))); do
        n=$(printf "%02d" "$i")
        "$BIN" keygen-public --dir "$OUT/v$n" 2>/dev/null \
            || echo -e "$i\tTODO_RUN_keygen-public\tTODO\t\tTODO\t"
    done
} > "$OUT/cohort.tsv"

# ── Digests, so the carry-out can be checked on arrival ────────────────────
{
    echo "Bloch Genesis-4 ceremony digests"
    echo "date(UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "count    : $COUNT"
    echo
    echo "sha256(cohort.tsv):"
    (sha256sum "$OUT/cohort.tsv" 2>/dev/null || shasum -a 256 "$OUT/cohort.tsv") | awk '{print "  "$1}'
} > "$OUT/DIGESTS.txt"

echo
echo "DONE."
echo
echo "  CARRY OUT (public, safe):"
echo "    $OUT/cohort.tsv"
echo "    $OUT/DIGESTS.txt"
echo
echo "  NEVER LEAVES THIS MACHINE:"
echo "    $OUT/v*/validator.key"
echo
echo "  Next: shard the keystores per BLOCH-GENESIS-KEYS.md §3.2 (Shamir 3-of-5,"
echo "  shares geographically separated), then move each validator's keystore to"
echo "  its own box by sealed transfer. Verify DIGESTS.txt on arrival — a cohort"
echo "  file that changed in transit is a different validator set."
