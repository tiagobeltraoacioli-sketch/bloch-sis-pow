#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Install only repository-pinned scanner bytes. Never execute/trust a binary
# merely because it already exists on a self-hosted runner's PATH.
# Usage: bash scripts/ci-install-scanner.sh <osv-scanner|gitleaks>
set -euo pipefail
OSV_VERSION="v1.9.2"
GITLEAKS_VERSION="8.18.4"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PINS="$SCRIPT_DIR/ci-scanner-checksums.txt"
BIN_DIR="${CI_TOOLS_BIN:-$HOME/.local/bin}"
log() { echo "[ci-install-scanner] $*" >&2; }
tool="${1:-}"
case "$tool" in osv-scanner|gitleaks) ;; *) log "expected osv-scanner or gitleaks"; exit 2 ;; esac
os="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$os" in linux|darwin) ;; *) log "unsupported OS: $os"; exit 1 ;; esac
case "$(uname -m)" in
  x86_64|amd64) arch=amd64; gl_arch=x64 ;;
  aarch64|arm64) arch=arm64; gl_arch=arm64 ;;
  *) log "unsupported architecture"; exit 1 ;;
esac
case "$tool" in
  osv-scanner)
    version="$OSV_VERSION"
    asset="osv-scanner_${os}_${arch}"
    url="https://github.com/google/osv-scanner/releases/download/${version}/${asset}"
    ;;
  gitleaks)
    version="$GITLEAKS_VERSION"
    asset="gitleaks_${version}_${os}_${gl_arch}.tar.gz"
    url="https://github.com/gitleaks/gitleaks/releases/download/v${version}/${asset}"
    ;;
esac
# Exactly one committed pin must match. No same-download-host checksum fallback
# and no Go build fallback that bypasses the reviewed release asset identity.
want="$(awk -v t="$tool" -v v="$version" -v a="$asset" '$1==t && $2==v && $3==a {print $4}' "$PINS")"
if [ "${#want}" -ne 64 ] || [[ "$want" == *[!0-9a-f]* ]]; then
  log "missing, duplicate or malformed committed checksum for $asset"; exit 1
fi
umask 077
tmp="$(mktemp -d "${TMPDIR:-/tmp}/bloch-scanner.XXXXXX")"
staged=""
cleanup() {
  if [ -n "$staged" ]; then rm -f -- "$staged"; fi
  rm -rf -- "$tmp"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
log "downloading pinned $asset"
curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL --retry 3 --connect-timeout 15 --max-time 180 -o "$tmp/asset" "$url"
if command -v sha256sum >/dev/null 2>&1; then got="$(sha256sum "$tmp/asset" | awk '{print $1}')"
else got="$(shasum -a 256 "$tmp/asset" | awk '{print $1}')"; fi
[ "$got" = "$want" ] || { log "sha256 mismatch for $asset"; exit 1; }
case "$tool" in
  osv-scanner) source="$tmp/asset" ;;
  gitleaks) tar -xzf "$tmp/asset" -C "$tmp" gitleaks; source="$tmp/gitleaks" ;;
esac
[ -f "$source" ] && [ ! -L "$source" ] || { log "release artifact is not a regular binary"; exit 1; }
mkdir -p "$BIN_DIR"
staged="$(mktemp "$BIN_DIR/.${tool}.verified.XXXXXX")"
install -m 0755 "$source" "$staged"
# Atomic replacement avoids following an existing executable symlink.
[ ! -d "$BIN_DIR/$tool" ] || { log "refusing a directory at the executable path"; exit 1; }
mv -f -- "$staged" "$BIN_DIR/$tool"
staged=""
log "$tool installed from committed checksum $want"
echo "$BIN_DIR"
