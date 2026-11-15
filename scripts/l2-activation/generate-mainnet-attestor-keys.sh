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
#   --age-recipient R  generate each key in a RAM-backed staging directory,
#                      encrypt its .sk to R with `age` (attestor-I.sk.age in
#                      --out-dir), then overwrite and delete the staged
#                      plaintext. The plaintext .sk never touches --out-dir.
#   --ram-dir DIR      RAM-backed directory for that staging (tmpfs/ramfs on
#                      Linux, a RAM disk on macOS, e.g.
#                      `diskutil erasevolume HFS+ ATTRAM $(hdiutil attach -nomount ram://16384)`
#                      then --ram-dir /Volumes/ATTRAM). Default on Linux:
#                      /dev/shm. Verified on both systems (statfs type on
#                      Linux; on macOS the volume must be an attached ram://
#                      image per `hdiutil info`); anything else is refused.
#                      Because it is RAM, the overwrite-then-unlink of the
#                      staged plaintext is meaningful there (on APFS an
#                      in-place overwrite is not, which is why plaintext is
#                      never staged on disk).
#   --plaintext-on-unencrypted-disk
#                      without --age-recipient the .sk stays plaintext hex
#                      (0600, dir 0700) in --out-dir, which is refused unless
#                      that directory is on an encrypted volume (FileVault on
#                      macOS, dm-crypt on Linux). This flag overrides the
#                      check; do not use it for mainnet keys.
#
# L1M-09 (2026-11-14): previously --age-recipient ran ws-keygen into
# --out-dir and removed the plaintext with `rm -f`, leaving it recoverable on
# an unencrypted disk or in an APFS/Time Machine snapshot.
#
# The resulting attestors.set is what goes into the code, set once:
#   l2_settlement::mainnet::ATTESTOR_SET = Some(include_str!(".../attestors.set"))
set -euo pipefail

BIN="target/release/bloch-pos"
OUT="$HOME/Desktop/L2-MAINNET-ATESTADORES"
MODE=""
INDEX=""
AGE_RECIPIENT=""
RAM_DIR=""
PLAINTEXT_OK=0
STAGE=""
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
        --ram-dir) RAM_DIR="${2:?}"; shift 2 ;;
        --plaintext-on-unencrypted-disk) PLAINTEXT_OK=1; shift ;;
        -h|--help) sed -n '2,57p' "$0"; exit 0 ;;
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

# Overwrite then unlink (best effort: on a RAM-backed staging dir the data
# never reached persistent storage in the first place).
wipe() {
    local f="$1" size
    [[ -f "$f" ]] || return 0
    size=$(wc -c <"$f" | tr -d ' ')
    if command -v shred >/dev/null; then
        shred -u -z "$f"
    else
        dd if=/dev/zero of="$f" bs="$size" count=1 conv=notrunc 2>/dev/null || true
        rm -f "$f"
    fi
}

cleanup() {
    if [[ -n "$STAGE" && -d "$STAGE" ]]; then
        for f in "$STAGE"/*; do [[ -e "$f" ]] && wipe "$f"; done
        rmdir "$STAGE" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

# The block device DIR is mounted from (e.g. /dev/disk3s1).
mount_device() { df -P "$1" 2>/dev/null | awk 'NR==2 {print $1}'; }

# Is DIR on a RAM-backed filesystem? Linux: tmpfs/ramfs by statfs type.
# macOS: the volume's device must belong to an attached `ram://` disk image
# (`hdiutil info`), so a USB stick or a folder on the boot disk is refused.
# Anything else: fail closed.
ram_backed() {
    local d="$1" t dev
    case "$(uname -s)" in
        Linux)
            t=$(stat -f -c %T "$d" 2>/dev/null) || return 1
            [[ "$t" == tmpfs || "$t" == ramfs ]] ;;
        Darwin)
            dev=$(mount_device "$d"); [[ "$dev" == /dev/disk* ]] || return 1
            hdiutil info 2>/dev/null | awk -v dev="$dev" '
                /^=+$/ { ram = 0 }
                /^image-path[[:space:]]*:/ { ram = ($NF ~ /^ram:\/\//) }
                ram && $1 == dev { found = 1 }
                END { exit found ? 0 : 1 }' ;;
        *) return 1 ;;
    esac
}

# Is DIR on an encrypted volume? macOS: the volume DIR itself lives on must
# report FileVault/encryption in `diskutil info` (not merely the boot volume,
# which is all `fdesetup isactive` looks at); Linux: a dm-crypt device under
# the mount. Anything undetectable counts as "no" (fail closed).
encrypted_volume() {
    local d="$1" src
    case "$(uname -s)" in
        Darwin)
            src=$(mount_device "$d"); [[ "$src" == /dev/disk* ]] || return 1
            diskutil info "$src" 2>/dev/null | grep -Eq '^[[:space:]]*(FileVault|Encrypted):[[:space:]]*Yes' ;;
        Linux)
            command -v findmnt >/dev/null && command -v lsblk >/dev/null || return 1
            src=$(findmnt -no SOURCE --target "$d" 2>/dev/null) || return 1
            lsblk -s -no TYPE "$src" 2>/dev/null | grep -qx crypt ;;
        *) return 1 ;;
    esac
}

if [[ "$MODE" != assemble ]]; then
    if [[ -n "$AGE_RECIPIENT" ]]; then
        if [[ -z "$RAM_DIR" ]]; then
            [[ "$(uname -s)" == Linux ]] || die "--age-recipient needs --ram-dir (a RAM disk) on $(uname -s) (see --help)"
            RAM_DIR=/dev/shm
        fi
        [[ -d "$RAM_DIR" ]] || die "--ram-dir $RAM_DIR is not a directory"
        ram_backed "$RAM_DIR" || die "$RAM_DIR is not RAM-backed (tmpfs/ramfs); refusing to stage secrets there"
        STAGE=$(mktemp -d "$RAM_DIR/attestor-stage.XXXXXX")
        chmod 700 "$STAGE"
    elif [[ "$PLAINTEXT_OK" != 1 ]]; then
        encrypted_volume "$OUT" || die "$OUT is not on a detectably encrypted volume and the .sk would be \
written there in plaintext; use --age-recipient (with a RAM --ram-dir) or an encrypted disk \
(override: --plaintext-on-unencrypted-disk)"
    fi
fi

gen_one() {
    local i="$1" prefix="$OUT/attestor-$1" gen
    [[ "$i" =~ ^[0-4]$ ]] || die "index must be 0..4"
    for f in "$prefix.pk" "$prefix.sk" "$prefix.sk.age"; do
        [[ -e "$f" ]] && die "$f already exists; refusing to overwrite an attestor key"
    done
    # With age, the plaintext secret is only ever written to the RAM stage.
    if [[ -n "$AGE_RECIPIENT" ]]; then gen="$STAGE/attestor-$i"; else gen="$prefix"; fi
    "$BIN" ws-keygen --out "$gen" >/dev/null
    [[ -f "$gen.sk" && -f "$gen.pk" ]] || die "ws-keygen did not write $gen.{pk,sk}"
    chmod 600 "$gen.sk"
    if [[ -n "$AGE_RECIPIENT" ]]; then
        age -r "$AGE_RECIPIENT" -o "$prefix.sk.age" "$gen.sk"
        chmod 600 "$prefix.sk.age"
        wipe "$gen.sk"
        mv "$gen.pk" "$prefix.pk"
        chmod 644 "$prefix.pk"
        echo "attestor-$i: $prefix.pk (public), $prefix.sk.age (secret, encrypted, 0600; plaintext only ever in RAM)"
    else
        chmod 644 "$prefix.pk"
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
