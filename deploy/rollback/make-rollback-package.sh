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

# If the binary runs on this host, refuse a stamp that contradicts it — a
# rollback package whose label lies is worse than none.
if V="$("$BIN" --version 2>/dev/null)"; then
  case "$V" in
    *"$STAMP"*) : ;;
    *) echo "STAMP MISMATCH: --version says '$V', you said '$STAMP'." >&2; exit 1 ;;
  esac
fi

# Short id for filenames: the parenthesised commit if present, else the hash.
ID="$(printf '%s' "$STAMP" | sed -n 's/.*(\([0-9a-f]\{7,\}\)).*/\1/p')"
ID="${ID:-${HASH:0:12}}"
PKGDIR="$(mktemp -d "${TMPDIR:-/tmp}/bloch-pos-rollback.XXXXXX")/bloch-pos-rollback-$ID"
mkdir -p "$PKGDIR" "$OUTDIR"

cp "$BIN" "$PKGDIR/bloch-pos"
chmod 0755 "$PKGDIR/bloch-pos"

printf '%s  bloch-pos\n' "$HASH" > "$PKGDIR/SHA256SUMS"
printf 'stamp: %s\n' "$STAMP"    > "$PKGDIR/STAMP"

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
cat > "$PKGDIR/install.sh" <<'INSTALL'
#!/usr/bin/env bash
# Apply the bloch-pos rollback on THIS box. Run as root (or sudo).
#   ./install.sh [service-name]        default service: bloch-pos.service
# Refuses to proceed if the packaged binary fails its hash check, and refuses
# to finish silently: the last step PROVES what is running via /proc.
set -euo pipefail
cd "$(dirname "$0")"
SVC="${1:-bloch-pos.service}"
ID="$(basename "$(pwd)" | sed 's/^bloch-pos-rollback-//')"
DEST="/opt/bloch/releases/rollback-$ID"

echo "== verify package integrity =="
sha256sum -c SHA256SUMS
echo "packaged stamp: $(cat STAMP)"

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
PKG_HASH="$(awk '{print $1}' SHA256SUMS)"
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
chmod 0755 "$PKGDIR/install.sh"

cat > "$PKGDIR/README" <<EOF
bloch-pos rollback package — $STAMP
sha256(bloch-pos) = $HASH

Apply on a box:   sudo ./install.sh [service-name]     (default bloch-pos.service)
Leave rollback:   rm /etc/systemd/system/<svc>.d/99-rollback.conf
                  systemctl daemon-reload && systemctl restart <svc>

This package must have been TESTED on a scratch host before it counts for
gate G8 — the procedure is deploy/RELEASE-INTEGRITY.md §5.3. Applying it to
the live fleet is an operator decision, never automation.
EOF

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

echo "rollback package: $TARBALL"
echo "sha256(package):  $(sha "$TARBALL")"
echo
echo "Next (G8): test it on a SCRATCH host per deploy/RELEASE-INTEGRITY.md §5.3,"
echo "then stage it in the release store alongside the release it protects."
