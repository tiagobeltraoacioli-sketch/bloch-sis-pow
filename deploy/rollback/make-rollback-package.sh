#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# make-rollback-package.sh — assemble the G8 rollback package for bloch-pos
# (docs/specs/BLOCH-POS-SHA3-LATTICE-MIGRATION.md §11, gate G8: "rollback
# package staged and tested"; full spec in deploy/RELEASE-INTEGRITY.md §5).
#
# A rollback package is the LAST KNOWN-GOOD release, frozen as a self-
# contained tarball that a tired operator can apply at 03:00 without a Rust
# toolchain, without network access to the repo, and without reading anything
# but the README inside it. It is assembled at RELEASE TIME (when the
# known-good binary is provably known-good), not at incident time.
#
# Usage:
#   deploy/rollback/make-rollback-package.sh <bloch-pos-binary> <stamp> [outdir]
#     <binary>  path to the known-good bloch-pos (the previous release's
#               canonical /build container binary — NOT a box's local build)
#     <stamp>   its identity, e.g. "0.0.1-skeleton (f3842923e068)" — must be
#               exactly what `<binary> --version` prints (verified when the
#               package is applied on a Linux host, and at assembly time too
#               when the binary is runnable here)
#     [outdir]  default: deploy/rollback/dist/
#
#   Required environment:
#     BLOCH_ROLLBACK_SECKEY  path to the minisign SECRET key of the release
#                            signing keypair. Assembly FAILS CLOSED without
#                            it — see "why" below.
#   Optional:
#     BLOCH_ROLLBACK_PUBKEY  its public key file; derived from the secret key
#                            with `minisign -R` when unset.
#
# WHY THE SIGNATURE (audit I-H3): SHA256SUMS travels INSIDE the tarball and
# `install.sh` runs as root. A hash manifest that ships next to the bytes it
# describes proves only that the tarball is internally consistent — anyone who
# can rewrite the tarball (mirror, R2 bucket, USB stick, MITM on the fetch)
# rewrites the manifest with it and `sha256sum -c` still passes. So the
# manifest carries a DETACHED minisign signature, verified by install.sh
# against a public key pinned OUT OF BAND on the box (/etc/bloch/…), BEFORE
# any hash check and long before anything is executed or installed. The
# manifest also covers install.sh, the drop-in and the README — not just the
# binary — because all of them reach root.
#
# This script only ASSEMBLES. It never touches a service, a box, or the fleet.
set -euo pipefail

# NOTE: no apostrophes and no nested quotes inside ${..:?..}/${..:-..} — the
# macOS /bin/bash 3.2 parser trips on both (measured while testing this file).
BIN="${1:?usage: make-rollback-package.sh <bloch-pos-binary> <stamp> [outdir]}"
STAMP="${2:?missing <stamp> (the --version identity of the binary)}"
OUTDIR="${3:-}"
if [ -z "$OUTDIR" ]; then OUTDIR="$(cd "$(dirname "$0")" && pwd)/dist"; fi

[ -f "$BIN" ] || { echo "no such binary: $BIN" >&2; exit 1; }

sha() {
  if command -v sha256sum >/dev/null; then sha256sum "$1" | awk '{print $1}';
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}
HASH="$(sha "$BIN")"

# ── signing key, resolved BEFORE anything is assembled ───────────────────────
# Fail closed and fail early: an unsigned rollback package must not exist even
# transiently, because a tarball on disk is indistinguishable from a released
# one once it leaves this directory. There is deliberately no --unsigned flag.
command -v minisign >/dev/null || {
  echo "FAIL: minisign not installed — the rollback manifest must be signed." >&2
  echo "  macOS: brew install minisign   Debian/Ubuntu: apt install minisign" >&2
  exit 1
}
SECKEY="${BLOCH_ROLLBACK_SECKEY:-}"
[ -n "$SECKEY" ] || {
  echo "FAIL: BLOCH_ROLLBACK_SECKEY is unset — refusing to assemble an unsigned" >&2
  echo "rollback package (audit I-H3; deploy/RELEASE-INTEGRITY.md §5.4)." >&2
  echo "  one-time:  minisign -G -p rollback-signing.pub -s rollback-signing.key" >&2
  echo "  then:      BLOCH_ROLLBACK_SECKEY=…/rollback-signing.key $0 …" >&2
  echo "The public half is pinned on every box at /etc/bloch/rollback-signing.pub." >&2
  exit 1
}
[ -f "$SECKEY" ] || { echo "FAIL: no such minisign secret key: $SECKEY" >&2; exit 1; }

# Short id for filenames: the parenthesised commit if present, else the hash.
ID="$(printf '%s' "$STAMP" | sed -n 's/.*(\([0-9a-f]\{7,\}\)).*/\1/p')"
ID="${ID:-${HASH:0:12}}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/bloch-pos-rollback.XXXXXX")"
PKGDIR="$WORK/bloch-pos-rollback-$ID"
mkdir -p "$PKGDIR" "$OUTDIR"

PUBFILE="${BLOCH_ROLLBACK_PUBKEY:-}"
if [ -z "$PUBFILE" ]; then
  PUBFILE="$WORK/derived.pub"
  minisign -R -s "$SECKEY" -p "$PUBFILE" >/dev/null
fi
[ -f "$PUBFILE" ] || { echo "FAIL: no such minisign public key: $PUBFILE" >&2; exit 1; }
# Line 1 of a minisign .pub is an untrusted comment; line 2 is the key.
PUBLINE="$(grep -v '^untrusted comment:' "$PUBFILE" | tr -d '[:space:]')"
[ -n "$PUBLINE" ] || { echo "FAIL: $PUBFILE holds no minisign public key line" >&2; exit 1; }

# If the binary runs on this host, refuse a stamp that contradicts it — a
# rollback package whose label lies is worse than none.
if V="$("$BIN" --version 2>/dev/null)"; then
  case "$V" in
    *"$STAMP"*) : ;;
    *) echo "STAMP MISMATCH: --version says '$V', you said '$STAMP'." >&2; exit 1 ;;
  esac
fi

cp "$BIN" "$PKGDIR/bloch-pos"
chmod 0755 "$PKGDIR/bloch-pos"

printf 'stamp: %s\n' "$STAMP" > "$PKGDIR/STAMP"

# ── the drop-in ──────────────────────────────────────────────────────────────
# 99- so it sorts LAST: systemd merges up to N drop-ins and for ExecStart the
# last-read file wins (after the reset line). The 2026-08-11 fleet survey found
# up to 16 stacked drop-ins; reading the unit's base ExecStart tells you
# nothing about what runs. This name guarantees the rollback wins them all.
cat > "$PKGDIR/99-rollback.conf" <<EOF
# Installed by bloch-pos-rollback-$ID — REMOVE this file to leave rollback.
[Service]
ExecStart=
ExecStart=/opt/bloch/releases/rollback-$ID/bloch-pos
EOF

# ── install.sh (runs ON the box, BY the operator, never by CI) ───────────────
# The two constants are baked at assembly time. They are NOT a trust root —
# they live inside the tarball like everything else. They exist so that a
# package signed by the wrong key, or carrying a signature over some other
# package, fails with a sentence an operator can act on at 03:00 instead of a
# bare cryptographic error. The trust root is the out-of-band public key.
{
  printf '#!/usr/bin/env bash\n'
  printf '# Generated by make-rollback-package.sh for bloch-pos-rollback-%s.\n' "$ID"
  printf 'PACKAGE_SIGNING_PUBKEY=%s\n' "$PUBLINE"
  printf 'PACKAGE_BINARY_SHA256=%s\n' "$HASH"
  cat <<'INSTALL'
# Apply the bloch-pos rollback on THIS box. Run as root (or sudo).
#   ./install.sh [service-name]        default service: bloch-pos.service
#   ./install.sh --verify-only         verify signature + manifest, change nothing
#
# Order of operations is the security property (audit I-H3): the DETACHED
# signature over SHA256SUMS is checked against a public key pinned on this box
# — never one shipped in the package — BEFORE `sha256sum -c`, because a
# tampered tarball carries a matching manifest. Only then is anything staged.
# Refuses to finish silently either: the last step PROVES what runs via /proc.
set -euo pipefail
cd "$(dirname "$0")"

VERIFY_ONLY=0
if [ "${1:-}" = "--verify-only" ]; then VERIFY_ONLY=1; shift; fi
SVC="${1:-bloch-pos.service}"
ID="$(basename "$(pwd)" | sed 's/^bloch-pos-rollback-//')"
DEST="/opt/bloch/releases/rollback-$ID"

echo "== verify the detached signature over SHA256SUMS (before any hash check) =="
command -v minisign >/dev/null || {
  echo "FAIL: minisign is not installed on this box, so this package cannot be" >&2
  echo "authenticated. Install it (apt install minisign) and re-run. Refusing to" >&2
  echo "fall back to an unauthenticated hash check." >&2
  exit 1
}
[ -f SHA256SUMS.minisig ] || {
  echo "FAIL: no SHA256SUMS.minisig in this package — it is unsigned or was" >&2
  echo "stripped. An unsigned rollback package is not applied. Re-fetch it." >&2
  exit 1
}
TRUSTED_PUB="${BLOCH_ROLLBACK_PUBKEY:-/etc/bloch/rollback-signing.pub}"
[ -f "$TRUSTED_PUB" ] || {
  echo "FAIL: no trusted signing key at $TRUSTED_PUB." >&2
  echo "Pin the release public key on this box (out of band — NOT from this" >&2
  echo "tarball), or point BLOCH_ROLLBACK_PUBKEY at it, then re-run." >&2
  exit 1
}
TRUSTED_LINE="$(grep -v '^untrusted comment:' "$TRUSTED_PUB" | tr -d '[:space:]')"
[ -n "$TRUSTED_LINE" ] || { echo "FAIL: $TRUSTED_PUB holds no minisign key line" >&2; exit 1; }
if [ "$TRUSTED_LINE" != "$PACKAGE_SIGNING_PUBKEY" ]; then
  echo "FAIL: this package was signed by a key this box does not trust." >&2
  echo "  package signed by: $PACKAGE_SIGNING_PUBKEY" >&2
  echo "  box trusts:        $TRUSTED_LINE  ($TRUSTED_PUB)" >&2
  exit 1
fi
SIGNED_STATEMENT="$(minisign -V -Q -p "$TRUSTED_PUB" -x SHA256SUMS.minisig -m SHA256SUMS)" || {
  echo "FAIL: SHA256SUMS does not carry a valid signature from $TRUSTED_PUB." >&2
  echo "Do not apply this package. Re-fetch it from the release store." >&2
  exit 1
}
case "$SIGNED_STATEMENT" in
  *"$PACKAGE_BINARY_SHA256"*) : ;;
  *) echo "FAIL: the signed statement does not name this package's binary hash." >&2
     echo "  signed: $SIGNED_STATEMENT" >&2
     echo "  packaged bloch-pos: $PACKAGE_BINARY_SHA256" >&2
     echo "A signature from another package was pasted onto this one." >&2
     exit 1 ;;
esac
echo "signature OK — signed statement: $SIGNED_STATEMENT"

echo "== verify package contents against the SIGNED manifest =="
sha256sum -c SHA256SUMS
echo "packaged stamp: $(cat STAMP)"

if [ "$VERIFY_ONLY" = 1 ]; then
  echo "PACKAGE VERIFIED (signature + manifest). Nothing was installed (--verify-only)."
  exit 0
fi

echo "== stage binary =="
mkdir -p "$DEST"
install -m 0755 bloch-pos "$DEST/bloch-pos"
"$DEST/bloch-pos" --version

echo "== record what was running (for the incident log) =="
OLDPID="$(systemctl show "$SVC" -p ExecMainPID --value || true)"
if [ -n "${OLDPID:-}" ] && [ "$OLDPID" != "0" ] && [ -e "/proc/$OLDPID/exe" ]; then
  echo "was: $(readlink "/proc/$OLDPID/exe")  sha256=$(sha256sum "/proc/$OLDPID/exe" | awk '{print $1}')"
else
  echo "was: $SVC not running"
fi

echo "== install drop-in (wins over every stacked drop-in: sorts last) =="
mkdir -p "/etc/systemd/system/$SVC.d"
install -m 0644 99-rollback.conf "/etc/systemd/system/$SVC.d/99-rollback.conf"
systemctl daemon-reload
systemctl restart "$SVC"

echo "== PROVE it (the authoritative check: /proc, never the unit file) =="
sleep 2
PID="$(systemctl show "$SVC" -p ExecMainPID --value)"
[ -n "$PID" ] && [ "$PID" != "0" ] || { echo "FAIL: $SVC has no main PID after restart"; exit 1; }
RUN_HASH="$(sha256sum "/proc/$PID/exe" | awk '{print $1}')"
# The bloch-pos row of the SIGNED manifest — not the whole file: it now covers
# install.sh, the drop-in and the README too.
PKG_HASH="$(awk '$2 == "bloch-pos" { print $1 }' SHA256SUMS)"
echo "running: $(readlink "/proc/$PID/exe")  sha256=$RUN_HASH"
if [ "$RUN_HASH" != "$PKG_HASH" ]; then
  echo "FAIL: the service restarted onto a DIFFERENT binary than this package."
  echo "Another drop-in or unit generator is overriding ExecStart — inspect:"
  echo "  systemd-delta --type=extended | grep $SVC ; systemctl cat $SVC"
  exit 1
fi
echo "ROLLBACK APPLIED AND VERIFIED: $SVC runs the packaged binary."
echo "To leave rollback later: rm /etc/systemd/system/$SVC.d/99-rollback.conf && systemctl daemon-reload && systemctl restart $SVC"
INSTALL
} > "$PKGDIR/install.sh"
chmod 0755 "$PKGDIR/install.sh"

cat > "$PKGDIR/README" <<EOF
bloch-pos rollback package — $STAMP
sha256(bloch-pos) = $HASH
signed by         = $PUBLINE

Verify BEFORE you trust it (the signature is what makes SHA256SUMS mean
anything — the manifest ships inside this tarball and a tampered tarball
carries a tampered manifest):

  minisign -Vm SHA256SUMS -p /etc/bloch/rollback-signing.pub   # or your pinned copy
  sha256sum -c SHA256SUMS                                      # covers install.sh too
  ./install.sh --verify-only                                   # both of the above

The public key is NOT in this tarball on purpose. Pin it on the box out of
band (/etc/bloch/rollback-signing.pub) or pass BLOCH_ROLLBACK_PUBKEY=<file>.
install.sh refuses to run without it — it will not fall back to an
unauthenticated hash check.

Apply on a box:   sudo ./install.sh [service-name]     (default bloch-pos.service)
Leave rollback:   rm /etc/systemd/system/<svc>.d/99-rollback.conf
                  systemctl daemon-reload && systemctl restart <svc>

This package must have been TESTED on a scratch host before it counts for
gate G8 — the procedure is deploy/RELEASE-INTEGRITY.md §5.3. Applying it to
the live fleet is an operator decision, never automation.
EOF

# ── the manifest: every file that reaches root, not just the binary ──────────
: > "$PKGDIR/SHA256SUMS"
for f in bloch-pos STAMP 99-rollback.conf install.sh README; do
  printf '%s  %s\n' "$(sha "$PKGDIR/$f")" "$f" >> "$PKGDIR/SHA256SUMS"
done

# ── the detached signature (audit I-H3) ─────────────────────────────────────
# The trusted comment is signed too, so the signature itself names the release
# and the binary hash it stands for; install.sh cross-checks it, which is what
# stops a valid signature from another package being pasted onto this one.
minisign -S -s "$SECKEY" -m "$PKGDIR/SHA256SUMS" -x "$PKGDIR/SHA256SUMS.minisig" \
  -c "detached signature over the bloch-pos rollback manifest" \
  -t "bloch-pos rollback $ID stamp=$STAMP sha256(bloch-pos)=$HASH" >/dev/null
# Never emit a package whose own signature does not verify.
minisign -V -q -p "$PUBFILE" -x "$PKGDIR/SHA256SUMS.minisig" -m "$PKGDIR/SHA256SUMS" >/dev/null || {
  echo "FAIL: the signature just produced does not verify against $PUBFILE" >&2
  exit 1
}

TARBALL="$OUTDIR/bloch-pos-rollback-$ID.tar.gz"
# Deterministic-ish tar: sorted names, fixed owner. (GNU tar options guarded
# for bsdtar on macOS; the tarball hash is recorded either way.)
if tar --version 2>/dev/null | grep -q GNU; then
  tar --sort=name --owner=0 --group=0 --numeric-owner \
      -C "$(dirname "$PKGDIR")" -czf "$TARBALL" "$(basename "$PKGDIR")"
else
  ( cd "$(dirname "$PKGDIR")" && find "$(basename "$PKGDIR")" | sort \
    | tar -czf "$TARBALL" -T - )
fi

# The public key is published BESIDE the tarball, never inside it: a key that
# travels with the bytes it authenticates authenticates nothing.
cp "$PUBFILE" "$OUTDIR/bloch-pos-rollback-$ID.pub"

echo "rollback package: $TARBALL"
echo "sha256(package):  $(sha "$TARBALL")"
echo "signing pubkey:   $PUBLINE"
echo "                  (also written to $OUTDIR/bloch-pos-rollback-$ID.pub)"
echo
echo "Next (G8): test it on a SCRATCH host per deploy/RELEASE-INTEGRITY.md §5.3,"
echo "then stage it in the release store alongside the release it protects."
echo "Every box that may apply it needs the public key pinned at"
echo "/etc/bloch/rollback-signing.pub — install.sh fails closed without it."
