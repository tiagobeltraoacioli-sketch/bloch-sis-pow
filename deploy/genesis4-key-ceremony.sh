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

# MED-10: COUNT must be a plain positive decimal integer, checked before it
# drives `seq`/array sizing below. An unvalidated COUNT accepts things like
# "64; rm -rf /" nowhere here (there is no eval), but it also accepted
# "0", "-1", "abc", or a huge number silently misbehaving in `seq` — a
# ceremony that silently generates 0 or the wrong number of keys is exactly
# the "ran differently and wrong" failure mode this script exists to prevent.
case "$COUNT" in
    ''|*[!0-9]*)
        echo "FATAL: count must be a positive integer (got: '$COUNT')"
        exit 1
        ;;
esac
if [ "$COUNT" -lt 1 ] || [ "$COUNT" -gt 9999 ]; then
    echo "FATAL: count out of sane range (got: $COUNT, expected 1-9999)"
    exit 1
fi

# ── Refuse to run networked ────────────────────────────────────────────────
#
# Not theatre. A ceremony on a machine that can reach the internet has the one
# property it was supposed to eliminate. Checked rather than trusted, because
# "I disconnected it" is exactly the kind of thing people are sure about and
# wrong about. Layered, because any single probe is defeatable: ICMP alone
# misses a network that blocks ping but permits TCP/DNS; a TCP-connect probe
# alone misses one that blocks that port but resolves DNS; and a machine with
# no default route can still have live link-local/LAN reachability that a
# probe to a public IP never exercises, so the route table is checked too.
NET_SIGNS=""

if ping -c1 -W2 1.1.1.1 >/dev/null 2>&1 || ping -c1 -t2 1.1.1.1 >/dev/null 2>&1; then
    NET_SIGNS="${NET_SIGNS}ICMP to 1.1.1.1 answered. "
fi

# TCP-connect probe, no external tool required: bash's /dev/tcp pseudo-device.
# Short timeout — this must fail FAST on a truly air-gapped host, not hang.
if timeout 3 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443' 2>/dev/null; then
    NET_SIGNS="${NET_SIGNS}TCP connect to 1.1.1.1:443 succeeded. "
fi

# DNS resolution probe — a host can be air-gapped from the wider internet but
# still reach an internal resolver that leaks the ceremony's activity/timing;
# any answer at all here is a signal this host is not isolated.
if command -v getent >/dev/null 2>&1 && getent hosts cloudflare.com >/dev/null 2>&1; then
    NET_SIGNS="${NET_SIGNS}DNS resolution of cloudflare.com succeeded. "
elif command -v host >/dev/null 2>&1 && host -W2 cloudflare.com >/dev/null 2>&1; then
    NET_SIGNS="${NET_SIGNS}DNS resolution of cloudflare.com succeeded. "
fi

# No-default-route assertion: a host with no default route cannot reach the
# public internet at all regardless of what any single probe above measured
# at this instant (a probe result is a point-in-time sample; the absence of a
# route is closer to a structural guarantee against the same host reaching
# out a minute later). This is a POSITIVE check (must show NO route), unlike
# the three probes above (must show no answer) — record it separately so a
# platform where `ip`/`route` are unavailable does not silently pass by
# omission.
ROUTE_CHECK="not performed (neither 'ip' nor 'route' available)"
if command -v ip >/dev/null 2>&1; then
    if ip route show default 2>/dev/null | grep -q .; then
        NET_SIGNS="${NET_SIGNS}A default route exists (ip route show default). "
    fi
    ROUTE_CHECK="performed via 'ip route'"
elif command -v route >/dev/null 2>&1; then
    if route -n 2>/dev/null | awk '$1=="0.0.0.0"{f=1} END{exit !f}'; then
        NET_SIGNS="${NET_SIGNS}A default route exists (route -n). "
    fi
    ROUTE_CHECK="performed via 'route -n'"
fi

if [ -n "$NET_SIGNS" ]; then
    echo "FATAL: this machine has network access."
    echo "       Signal(s): $NET_SIGNS"
    echo "       The whole point of the ceremony is that it does not."
    echo "       Disconnect it — physically, not by disabling an interface — and re-run."
    exit 1
fi
echo "  network isolation: ICMP/TCP/DNS probes clean; no-default-route check $ROUTE_CHECK"
if [ "$ROUTE_CHECK" = "not performed (neither 'ip' nor 'route' available)" ]; then
    echo "  WARNING: could not check for a default route on this host (no 'ip' or 'route')."
    echo "           The three probes above are the only isolation evidence this run has."
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

# Portable sha256 of a FILE. Prefers sha256sum, falls back to shasum (macOS
# has no sha256sum by default), falls back to openssl. Prints the hex digest
# alone.
sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        openssl dgst -sha256 "$1" | awk '{print $NF}'
    fi
}

# Portable sha256 of STDIN, for the per-row digests below (no temp file).
sha256_stdin() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 | awk '{print $1}'
    else
        openssl dgst -sha256 | awk '{print $NF}'
    fi
}

# ── Digests, so the carry-out can be checked on arrival ────────────────────
#
# A single whole-file digest tells you the file changed; it does not tell you
# WHICH row, so a corrupted or tampered single validator entry is indistin-
# guishable from a clean transfer gone wrong until every row is hand-diffed
# against a second copy. A per-row digest, over that row's own bytes, means a
# single bad entry is caught and named without needing a second reference
# copy of the whole file to diff against.
{
    echo "Bloch Genesis-4 ceremony digests"
    echo "date(UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "count    : $COUNT"
    echo
    echo "sha256(cohort.tsv):"
    echo "  $(sha256_file "$OUT/cohort.tsv")"
    echo
    echo "per-keystore public digest (sha256 of that index's cohort.tsv row, tab-separated fields, exact bytes):"
    tail -n +2 "$OUT/cohort.tsv" | while IFS= read -r row; do
        idx=$(printf '%s' "$row" | cut -f1)
        rowdigest=$(printf '%s' "$row" | sha256_stdin)
        printf '  v%02d  %s\n' "$idx" "$rowdigest"
    done
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
