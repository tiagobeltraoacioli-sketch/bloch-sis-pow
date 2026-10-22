#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Mainnet L2 attestor keys (policy approved 2026-10-14: 3-of-5 hybrid
# ML-DSA-65 + Falcon-1024, the scheme the chain already uses for admission,
# weak-subjectivity signers and L2 attestations; set fixed at activation).
#
# PREPARED, NOT RUN. Nothing in this repository has generated mainnet
# attestor keys. Read docs/L2-MAINNET-ACTIVATION.md ("Attestor keys") first.
#
# Key generation is `bloch-pos ws-keygen --out <prefix>`: it writes
# <prefix>.pk (enveloped public key, hex) and <prefix>.sk (secret, hex,
# created 0600 from the first byte, refuses to overwrite) and prints only the
# paths. This script never reads, prints or copies a .sk file.
#
# Modes:
#   --index I     generate ONLY attestor-I (0..4). The intended ceremony: each
#                 of the five operators runs this on their own (ideally
#                 air-gapped) machine and hands back only attestor-I.pk.
#   --all         generate attestor-0..4 on THIS machine (a weaker ceremony:
#                 one machine holds all five secrets; move each .sk to its
#                 operator and delete it here before the set is used).
#   --assemble    build attestors.set (threshold 3 + the five .pk in order)
#                 with `bloch-pos l2-claim attestor-set` and print its set
#                 hash. Needs attestor-0..4.pk in --out-dir; no secrets.
#
# Options:
#   --binary PATH      bloch-pos (default: target/release/bloch-pos)
#   --out-dir DIR      default: ~/Desktop/L2-MAINNET-ATESTADORES
#   --age-recipient R  after generating, encrypt each .sk to R with `age`
#                      (attestor-I.sk.age) and delete the plaintext. Without
#                      it the .sk stays plaintext hex, mode 0600, dir 0700.
#
# The resulting attestors.set is what goes into the code, set once:
#   l2_settlement::mainnet::ATTESTOR_SET = Some(include_str!(".../attestors.set"))
set -euo pipefail

BIN="target/release/bloch-pos"
OUT="$HOME/Desktop/L2-MAINNET-ATESTADORES"
MODE=""
INDEX=""
AGE_RECIPIENT=""
THRESHOLD=3
COUNT=5

die() { echo "error: $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --index) MODE=index; INDEX="${2:?--index needs a value}"; shift 2 ;;
        --all) MODE=all; shift ;;
        --assemble) MODE=assemble; shift ;;
        --binary) BIN="${2:?}"; shift 2 ;;
        --out-dir) OUT="${2:?}"; shift 2 ;;
        --age-recipient) AGE_RECIPIENT="${2:?}"; shift 2 ;;
        -h|--help) sed -n '2,36p' "$0"; exit 0 ;;
        *) die "unknown argument $1" ;;
    esac
done
[[ -n "$MODE" ]] || die "choose --index I, --all or --assemble"
[[ -x "$BIN" ]] || die "$BIN is not an executable bloch-pos (cargo build --release -p bloch-pos-node)"
if [[ -n "$AGE_RECIPIENT" ]]; then command -v age >/dev/null || die "age not found"; fi

# Every file created from here on is private by default.
umask 077
mkdir -p "$OUT"
chmod 700 "$OUT"

gen_one() {
    local i="$1" prefix="$OUT/attestor-$1"
    [[ "$i" =~ ^[0-4]$ ]] || die "index must be 0..4"
    for f in "$prefix.pk" "$prefix.sk" "$prefix.sk.age"; do
        [[ -e "$f" ]] && die "$f already exists; refusing to overwrite an attestor key"
    done
    "$BIN" ws-keygen --out "$prefix" >/dev/null
    [[ -f "$prefix.sk" && -f "$prefix.pk" ]] || die "ws-keygen did not write $prefix.{pk,sk}"
    chmod 600 "$prefix.sk"
    chmod 644 "$prefix.pk"
    if [[ -n "$AGE_RECIPIENT" ]]; then
        age -r "$AGE_RECIPIENT" -o "$prefix.sk.age" "$prefix.sk"
        chmod 600 "$prefix.sk.age"
        rm -f "$prefix.sk"
        echo "attestor-$i: $prefix.pk (public), $prefix.sk.age (secret, encrypted, 0600)"
    else
        echo "attestor-$i: $prefix.pk (public), $prefix.sk (SECRET, 0600, never leaves its operator)"
    fi
    echo "  sha3-256(pk file): $(python3 -I -c 'import hashlib,sys; print(hashlib.sha3_256(open(sys.argv[1],"rb").read()).hexdigest())' "$prefix.pk")"
}

case "$MODE" in
    index) gen_one "$INDEX" ;;
    all)
        echo "WARNING: all five secrets on one machine; hand each .sk to its operator and delete it here."
        for i in $(seq 0 $((COUNT - 1))); do gen_one "$i"; done ;;
    assemble)
        args=()
        for i in $(seq 0 $((COUNT - 1))); do
            [[ -f "$OUT/attestor-$i.pk" ]] || die "missing $OUT/attestor-$i.pk"
            args+=(--pubkey "$OUT/attestor-$i.pk")
        done
        [[ -e "$OUT/attestors.set" ]] && die "$OUT/attestors.set already exists"
        "$BIN" l2-claim attestor-set --threshold "$THRESHOLD" "${args[@]}" --out "$OUT/attestors.set"
        chmod 644 "$OUT/attestors.set"
        echo "next: copy attestors.set into the tree and set l2_settlement::mainnet::ATTESTOR_SET (one commit, reviewed)"
        ;;
esac
