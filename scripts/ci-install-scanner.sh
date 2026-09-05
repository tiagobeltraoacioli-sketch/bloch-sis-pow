#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Install a security scanner for CI, or FAIL. Never "skip".
#
# WHY THIS EXISTS
# ---------------
# Both scanner jobs used to open with the same shape:
#
#     if ! command -v <tool> >/dev/null; then echo "skipping"; exit 0; fi
#
# on a job that was ALSO `allow_failure: true`. That is two independent ways to
# be green while scanning nothing, and one of them is silent: a runner that
# never had the tool produced a green job whose log said "skipping
# (informational)". osv-scanner is the only tool in this repository that sees
# GHSA-only advisories — GHSA-vxx9-2994-q338 (yamux 0.12.1, CVSS 8.7) is
# invisible to cargo-audit's RustSec feed — so "osv-scanner did not run" and
# "osv-scanner found nothing" printed the same colour.
#
# This script inverts that: it installs the tool, and if it cannot, it exits
# NON-ZERO. A scanner that is absent is a failed scan, not a passed one.
#
# Usage:  bash scripts/ci-install-scanner.sh <osv-scanner|gitleaks>
# Prints the directory the binary lands in; callers put it on PATH.
#
# Pinned versions, not @latest: an unpinned installer is a supply-chain hole in
# the job that exists to close supply-chain holes, and a floating scanner
# version makes the gate's verdict irreproducible.
set -euo pipefail

OSV_VERSION="v1.9.2"        # matches google/osv-scanner-action@v1.9.2 in .github/workflows/security.yml
GITLEAKS_VERSION="8.18.4"   # without the leading v; the release assets embed it bare

BIN_DIR="${CI_TOOLS_BIN:-$HOME/.local/bin}"
mkdir -p "$BIN_DIR"
export PATH="$BIN_DIR:$PATH"

tool="${1:-}"
case "$tool" in
  osv-scanner|gitleaks) ;;
  *) echo "usage: $0 <osv-scanner|gitleaks>" >&2; exit 2 ;;
esac

log() { echo "[ci-install-scanner] $*" >&2; }

if command -v "$tool" >/dev/null 2>&1; then
  log "$tool already present: $(command -v "$tool")"
  echo "$BIN_DIR"
  exit 0
fi

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
# Two naming schemes for the same machine: osv-scanner ships Go's GOARCH
# (amd64/arm64), gitleaks' goreleaser config renames 64-bit x86 to `x64`.
# Verified against the published asset lists for the pinned versions.
case "$(uname -m)" in
  x86_64|amd64)  arch="amd64"; gl_arch="x64" ;;
  aarch64|arm64) arch="arm64"; gl_arch="arm64" ;;
  *) log "FAIL: unsupported architecture $(uname -m)"; exit 1 ;;
esac

# sha256 of $1, portable across the Linux runner and a macOS workstation.
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

# Verify $1 against the sha256 listed for $2 in the checksums file $3.
# Be precise about what this proves: it catches a truncated or corrupted
# download, NOT a compromised release — the checksums come from the same host
# as the artifact. The real supply-chain control here is the PIN, so an
# unexpected build cannot arrive under a version this repository already ran.
verify_sha256() {
  local file="$1" name="$2" sums="$3" want got
  want="$(awk -v n="$name" '$2 == n || $2 == "*" n {print $1}' "$sums" | head -1)"
  [ -n "$want" ] || { log "FAIL: $name is not listed in the release checksums file"; exit 1; }
  got="$(sha256_of "$file")"
  [ "$want" = "$got" ] || { log "FAIL: sha256 mismatch for $name (want $want, got $got)"; exit 1; }
  log "sha256 ok: $name"
}

install_osv_scanner() {
  # Go toolchain first (the upstream-documented install path). No `|| true`:
  # if this is the only route and it fails, the job must fail.
  if command -v go >/dev/null 2>&1; then
    log "installing osv-scanner $OSV_VERSION via go install"
    GOBIN="$BIN_DIR" go install "github.com/google/osv-scanner/cmd/osv-scanner@$OSV_VERSION" && return 0
    log "go install failed; falling back to the release binary"
  fi
  local asset="osv-scanner_${os}_${arch}"
  local base="https://github.com/google/osv-scanner/releases/download/${OSV_VERSION}"
  local tmp
  tmp="$(mktemp -d)"
  log "downloading $base/$asset"
  curl -fsSL --retry 3 -o "$tmp/$asset" "$base/$asset"
  curl -fsSL --retry 3 -o "$tmp/SHA256SUMS" "$base/osv-scanner_SHA256SUMS" \
    || { log "FAIL: could not fetch osv-scanner_SHA256SUMS"; exit 1; }
  verify_sha256 "$tmp/$asset" "$asset" "$tmp/SHA256SUMS"
  install -m 0755 "$tmp/$asset" "$BIN_DIR/osv-scanner"
  rm -rf "$tmp"
}

install_gitleaks() {
  local tgz="gitleaks_${GITLEAKS_VERSION}_${os}_${gl_arch}.tar.gz"
  local base="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}"
  local tmp
  tmp="$(mktemp -d)"
  log "downloading $base/$tgz"
  curl -fsSL --retry 3 -o "$tmp/$tgz" "$base/$tgz"
  curl -fsSL --retry 3 -o "$tmp/checksums.txt" "$base/gitleaks_${GITLEAKS_VERSION}_checksums.txt" \
    || { log "FAIL: could not fetch the gitleaks release checksums file"; exit 1; }
  verify_sha256 "$tmp/$tgz" "$tgz" "$tmp/checksums.txt"
  tar -xzf "$tmp/$tgz" -C "$tmp" gitleaks
  install -m 0755 "$tmp/gitleaks" "$BIN_DIR/gitleaks"
  rm -rf "$tmp"
}

case "$tool" in
  osv-scanner) install_osv_scanner ;;
  gitleaks)    install_gitleaks ;;
esac

# Fail-closed verification. Everything above may have printed reassuring text;
# only this decides.
if ! command -v "$tool" >/dev/null 2>&1; then
  log "FAIL: $tool is still not on PATH after install — refusing to report a scan that did not run"
  exit 1
fi
# `osv-scanner --version` vs `gitleaks version`: print whichever the tool answers.
ver="$("$tool" --version 2>/dev/null | head -1 || true)"
[ -n "$ver" ] || ver="$("$tool" version 2>/dev/null | tail -1 || true)"
log "$tool ready: $(command -v "$tool") (${ver:-version unknown})"
echo "$BIN_DIR"
